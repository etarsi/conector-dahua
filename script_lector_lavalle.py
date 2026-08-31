# -*- coding: utf-8 -*-
"""
Conector de asistencias de LAVALLE (lector ZKTeco) -> Odoo

Es el equivalente de script_lector_sdk.py, que atiende el DEPOSITO (lectores
Dahua). Va aparte a proposito: son protocolos distintos, sedes distintas, y si
una falla la otra tiene que seguir andando.

Como funciona:
  1) Escucha las marcas en vivo (live capture del protocolo ZKTeco).
  2) Si la escucha se cae, releva el historial del equipo para no perder nada.
  3) Toda marca se guarda en SQLite ANTES de mandarla a Odoo.
  4) Si Odoo no responde, queda pendiente y se reintenta sola.

    python script_lector_lavalle.py

Configuracion: la seccion "lavalle" de config.json.
"""

import json
import logging
import os
import queue
import sqlite3
import ssl
import sys
import threading
import time
import unicodedata
import xmlrpc.client
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from struct import unpack

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULT_LAVALLE = {
    "enabled": True,
    "sede": "Lavalle",
    "devices": [{"ip": "192.168.0.80", "puerto": 4370, "password": 0, "nombre": "Horus"}],
    # Cada cuanto se hace un relevamiento completo por si la escucha en vivo
    # se perdio alguna marca (0 lo desactiva)
    "barrido_minutos": 30,
    "dias_primera_carga": 7,
    "timeout_seconds": 30,
    "reconnect_seconds": 15,
    "heartbeat_minutes": 30,
    "resend_interval_seconds": 60,
    "normalize_name_ascii": True,
    "status_file": "logs/estado_lavalle.json",
}


def _deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


with open(CONFIG_PATH, "r", encoding="utf-8") as _fh:
    CFG = json.load(_fh)
LAV = _deep_merge(DEFAULT_LAVALLE, CFG.get("lavalle", {}))
EQUIPOS = LAV.get("devices") or []

# =========================
# LOGGING
# =========================
logs_dir = os.path.join(BASE_DIR, "logs")
os.makedirs(logs_dir, exist_ok=True)
_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s: %(message)s")
root = logging.getLogger()
root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
root.handlers.clear()
_fh_log = RotatingFileHandler(os.path.join(logs_dir, "lavalle.log"),
                              maxBytes=5_242_880, backupCount=5, encoding="utf-8")
_fh_log.setFormatter(_fmt)
root.addHandler(_fh_log)
_sh = logging.StreamHandler(sys.stdout)
_sh.setFormatter(_fmt)
root.addHandler(_sh)

try:
    from zk import ZK, const
except ImportError:
    logging.error("Falta la libreria pyzk. Instalar con:  python -m pip install pyzk")
    sys.exit(1)

STOP = threading.Event()
COLA = queue.Queue(maxsize=5000)
HAY_TRABAJO = threading.Event()

data_dir = os.path.join(BASE_DIR, "data")
os.makedirs(data_dir, exist_ok=True)
DB_PATH = os.path.join(data_dir, "lavalle.sqlite3")
DB_LOCK = threading.Lock()
ZK_LOCK = threading.Lock()          # el equipo acepta una conexion por vez

ESTADO = {"conectado": False, "desde": None, "ultima_marca": None, "modo": "iniciando"}
ESTADO_LOCK = threading.Lock()
STATS = {"en_vivo": 0, "por_barrido": 0, "duplicadas": 0, "enviadas": 0, "rechazadas": 0}
STATS_LOCK = threading.Lock()

PENDIENTE, ENVIADO, DESCARTADO = 0, 1, 2

# Hasta donde mirar hacia atras la primera vez, si la base esta vacia.
# Se calcula una sola vez para que no se corra en cada barrido.
CORTE_PRIMERA_CARGA = datetime.now() - timedelta(days=int(LAV["dias_primera_carga"]))


def ahora_txt():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def bump(k, n=1):
    with STATS_LOCK:
        STATS[k] = STATS.get(k, 0) + n


def poner_estado(**campos):
    with ESTADO_LOCK:
        ESTADO.update(campos)
        ESTADO["actualizado"] = ahora_txt()


def a_ascii(s):
    s = unicodedata.normalize("NFKD", s or "")
    return "".join(c for c in s if not unicodedata.combining(c)).encode("ascii", "ignore").decode("ascii")


# =========================
# LECTURA DE MARCAS DEL EQUIPO
# =========================
def _fecha_zk(valor):
    """El entero de 4 bytes que usa ZKTeco -> fecha y hora."""
    t = valor
    seg = t % 60; t //= 60
    mi = t % 60;  t //= 60
    ho = t % 24;  t //= 24
    di = t % 31 + 1; t //= 31
    me = t % 12 + 1; t //= 12
    try:
        return datetime(t + 2000, me, di, ho, mi, seg)
    except ValueError:
        return None


def leer_historial(conn):
    """
    Trae todas las marcas guardadas en el equipo.

    Ojo: pyzk supone registros de 8, 16 o 40 bytes y este Horus usa 49
    (2.792.804 / 56.996 = 49 exacto). Si se usa get_attendance() devuelve
    basura: fechas del 2133 y miles de usuarios que no existen. Por eso se
    calcula el tamaño real y se parsea aca.
    """
    datos, size = conn.read_with_buffer(const.CMD_ATTLOG_RRQ)
    if size < 4:
        return [], 0
    total = unpack("I", datos[:4])[0]
    cuerpo = datos[4:]
    cantidad = int(getattr(conn, "records", 0) or 0)
    tam = (total // cantidad) if cantidad and total % cantidad == 0 else 0
    if not tam:
        for c in (49, 40, 32, 16, 8):
            if len(cuerpo) % c == 0:
                tam = c
                break
    if tam < 8:
        logging.error("No pude deducir el tamaño de registro del historial")
        return [], 0

    marcas, malas = [], 0
    for i in range(0, len(cuerpo) - tam + 1, tam):
        r = cuerpo[i:i + tam]
        if tam == 8:
            uid, estado, crudo, punch = unpack("<HB4sB", r[:8])
            user_id = str(uid)
        elif tam == 16:
            num, crudo, estado, punch, _ = unpack("<I4sBB6s", r[:16])
            user_id = str(num)
        else:
            _uid, ubytes, estado, crudo, punch = unpack("<H24sB4sB", r[:32])
            user_id = ubytes.split(b"\x00", 1)[0].decode("ascii", "ignore").strip()
        f = _fecha_zk(unpack("<I", crudo)[0])
        if f is None or not user_id:
            malas += 1
            continue
        marcas.append({"user_id": user_id, "fecha": f, "estado": estado, "punch": punch})
    return marcas, malas


# =========================
# SQLITE
# =========================
def conectar_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db():
    with DB_LOCK:
        conn = conectar_db()
        try:
            cr = conn.cursor()
            cr.execute("PRAGMA journal_mode = WAL")
            cr.execute("""
                CREATE TABLE IF NOT EXISTS marcas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sede TEXT,
                    equipo TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    nombre TEXT,
                    fecha TEXT NOT NULL,
                    estado INTEGER,
                    punch INTEGER,
                    origen TEXT,                    -- vivo | barrido
                    payload_json TEXT,
                    enviado INTEGER DEFAULT 0,      -- 0 pendiente, 1 enviado, 2 descartado
                    enviado_at TEXT,
                    intentos INTEGER DEFAULT 0,
                    ultimo_error TEXT,
                    creado TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (equipo, user_id, fecha)
                )
            """)
            cr.execute("CREATE INDEX IF NOT EXISTS idx_marcas_pend ON marcas (enviado, id)")
            conn.commit()
            logging.info(f"Base de Lavalle lista: {DB_PATH}")
        finally:
            conn.close()


def guardar_marca(m):
    """Devuelve True si es nueva."""
    payload = {
        "check_time": m["fecha"],
        "EventType": "ZKTECO",
        "eventSubType": "ENTRY" if not m.get("punch") else f"PUNCH_{m['punch']}",
        "deviceTime": m["fecha"],
        "eventId": 0,
        "dni": m["user_id"],
        "name": m.get("nombre") or "",
        "openMethod": "FACE_RECOGNITION",
        "status": "Exito",
        "cardType": "",
        "deviceIp": m["equipo"],
        "sede": LAV.get("sede", "Lavalle"),
    }
    with DB_LOCK:
        conn = conectar_db()
        try:
            cr = conn.cursor()
            cr.execute("""
                INSERT OR IGNORE INTO marcas
                    (sede, equipo, user_id, nombre, fecha, estado, punch, origen, payload_json, enviado)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (LAV.get("sede", "Lavalle"), m["equipo"], m["user_id"], m.get("nombre") or "",
                  m["fecha"], m.get("estado"), m.get("punch"), m.get("origen", "vivo"),
                  json.dumps(payload, ensure_ascii=False), PENDIENTE))
            nueva = cr.rowcount > 0
            conn.commit()
            return nueva
        finally:
            conn.close()


def pendientes(limite=50):
    with DB_LOCK:
        conn = conectar_db()
        try:
            return [dict(r) for r in conn.execute("""
                SELECT id, payload_json, intentos, user_id, fecha FROM marcas
                WHERE enviado = ? ORDER BY id LIMIT ?
            """, (PENDIENTE, limite)).fetchall()]
        finally:
            conn.close()


def contar_pendientes():
    with DB_LOCK:
        conn = conectar_db()
        try:
            return conn.execute("SELECT COUNT(*) FROM marcas WHERE enviado = ?", (PENDIENTE,)).fetchone()[0]
        finally:
            conn.close()


def marcar_resultado(id_, ok, error="", descartar=False):
    with DB_LOCK:
        conn = conectar_db()
        try:
            if ok:
                conn.execute("UPDATE marcas SET enviado = ?, enviado_at = ?, ultimo_error = NULL WHERE id = ?",
                             (ENVIADO, ahora_txt(), id_))
            else:
                conn.execute("""
                    UPDATE marcas SET intentos = intentos + 1, ultimo_error = ?,
                        enviado = CASE WHEN ? = 1 THEN ? ELSE enviado END
                    WHERE id = ?
                """, (error[:300], 1 if descartar else 0, DESCARTADO, id_))
            conn.commit()
        finally:
            conn.close()


def ultima_fecha_guardada(ip):
    with DB_LOCK:
        conn = conectar_db()
        try:
            r = conn.execute("SELECT MAX(fecha) FROM marcas WHERE equipo = ?", (ip,)).fetchone()
            return r[0] if r and r[0] else None
        finally:
            conn.close()


# =========================
# ODOO
# =========================
class _TransporteTimeout(xmlrpc.client.SafeTransport):
    def __init__(self, timeout, *a, **kw):
        super().__init__(*a, **kw)
        self._timeout = timeout

    def make_connection(self, host):
        c = super().make_connection(host)
        c.timeout = self._timeout
        return c


class Odoo:
    def __init__(self, cfg):
        self.enabled = bool(cfg.get("enabled")) and bool(cfg.get("url"))
        self.url = (cfg.get("url") or "").rstrip("/")
        self.db = cfg.get("db") or ""
        self.usuario = cfg.get("user") or ""
        self.clave = cfg.get("api_key") or ""
        self.modelo = cfg.get("model") or "hr.enhancement.api"
        self.metodo = cfg.get("method") or "attendance_webhook"
        self.timeout = int(cfg.get("timeout_seconds", 20))
        self.max_reintentos = int(cfg.get("max_app_retries", 5))
        self._uid = None
        self._models = None
        self._lock = threading.Lock()

    def _conectar(self):
        t = _TransporteTimeout(self.timeout) if self.url.lower().startswith("https") else None
        common = xmlrpc.client.ServerProxy(f"{self.url}/xmlrpc/2/common", transport=t, allow_none=True)
        uid = common.authenticate(self.db, self.usuario, self.clave, {})
        if not uid:
            raise PermissionError("Odoo rechazo el usuario o la api key")
        self._uid = uid
        t2 = _TransporteTimeout(self.timeout) if self.url.lower().startswith("https") else None
        self._models = xmlrpc.client.ServerProxy(f"{self.url}/xmlrpc/2/object", transport=t2, allow_none=True)
        logging.info(f"Conectado a Odoo {self.url} (uid={uid})")

    def enviar(self, payload):
        """(ok, transitorio, mensaje)"""
        if not self.enabled:
            return True, False, "Odoo deshabilitado"
        with self._lock:
            for intento in (1, 2):
                try:
                    if self._models is None:
                        self._conectar()
                    r = self._models.execute_kw(self.db, self._uid, self.clave,
                                                self.modelo, self.metodo, [payload], {})
                    if isinstance(r, dict):
                        if r.get("success"):
                            return True, False, str(r.get("message", ""))[:200]
                        return False, False, str(r.get("error") or r.get("message") or r)[:200]
                    return (True, False, "") if r in (True, 1) else (False, False, str(r)[:200])
                except PermissionError as e:
                    self._models = None
                    return False, True, str(e)
                except xmlrpc.client.Fault as e:
                    self._models = None
                    if intento == 1:
                        continue
                    return False, False, f"Fault: {e.faultString[:200]}"
                except Exception as e:
                    self._models = None
                    if intento == 1:
                        continue
                    return False, True, f"Red/Odoo: {e}"
        return False, True, "sin respuesta"


ODOO = Odoo(CFG.get("odoo") or {})


# =========================
# ESCUCHA DEL LECTOR
# =========================
def abrir(equipo):
    zk = ZK(equipo["ip"], port=int(equipo.get("puerto", 4370)),
            timeout=int(LAV["timeout_seconds"]), password=int(equipo.get("password", 0)),
            ommit_ping=True)
    return zk.connect()


def barrido(conn, equipo, nombres, primera_vez=False):
    """Releva el historial del equipo y encola lo que falte."""
    marcas, malas = leer_historial(conn)
    desde_txt = ultima_fecha_guardada(equipo["ip"])
    if desde_txt:
        corte = datetime.strptime(desde_txt, "%Y-%m-%d %H:%M:%S")
    else:
        # Se usa el corte calculado al arrancar, NO datetime.now(). Si se
        # recalculara en cada barrido y todavia no hay ninguna marca guardada,
        # el corte se correria solo y las marcas de una desconexion larga
        # quedarian afuera para siempre.
        corte = CORTE_PRIMERA_CARGA
    nuevas = 0
    for m in marcas:
        if m["fecha"] < corte:
            continue
        item = {"equipo": equipo["ip"], "user_id": m["user_id"],
                "nombre": nombres.get(m["user_id"], ""),
                "fecha": m["fecha"].strftime("%Y-%m-%d %H:%M:%S"),
                "estado": m["estado"], "punch": m["punch"], "origen": "barrido"}
        try:
            COLA.put(item, timeout=5)
            nuevas += 1
        except queue.Full:
            logging.error("Cola llena durante el barrido")
            break
    logging.info(f"Barrido: {len(marcas)} marcas en el equipo, {nuevas} a revisar"
                 + (f", {malas} con fecha invalida" if malas else "")
                 + (" (primera carga)" if primera_vez else ""))
    return nuevas


def hilo_lector(equipo):
    """Escucha en vivo, con barrido periodico y reconexion."""
    ip = equipo["ip"]
    barrido_cada = int(LAV["barrido_minutos"]) * 60
    primera = True

    while not STOP.is_set():
        conn = None
        try:
            with ZK_LOCK:
                conn = abrir(equipo)
                usuarios = conn.get_users()
                nombres = {str(u.user_id): u.name for u in usuarios}
                try:
                    conn.read_sizes()
                except Exception:
                    pass
                barrido(conn, equipo, nombres, primera)

            poner_estado(conectado=True, desde=ahora_txt(), modo="escuchando",
                         equipo=ip, usuarios=len(nombres))
            logging.info(f"Escuchando marcas en vivo de {ip} ({len(nombres)} usuarios)")
            primera = False
            ultimo_barrido = time.time()

            for marca in conn.live_capture(new_timeout=10):
                if STOP.is_set():
                    break
                if marca is None:
                    # sin novedades; aprovecha para el barrido periodico
                    if barrido_cada and time.time() - ultimo_barrido > barrido_cada:
                        try:
                            conn.cancel_capture()
                            with ZK_LOCK:
                                conn.read_sizes()
                                barrido(conn, equipo, nombres)
                        except Exception:
                            logging.debug("Barrido periodico fallo", exc_info=True)
                        ultimo_barrido = time.time()
                        break   # se reabre la escucha limpia
                    continue

                nombre = nombres.get(str(marca.user_id), "")
                item = {"equipo": ip, "user_id": str(marca.user_id), "nombre": nombre,
                        "fecha": marca.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "estado": marca.status, "punch": marca.punch, "origen": "vivo"}
                try:
                    COLA.put_nowait(item)
                    bump("en_vivo")
                    poner_estado(ultima_marca=item["fecha"])
                except queue.Full:
                    logging.error("Cola llena: se perdio una marca en vivo")

        except Exception as exc:
            logging.warning(f"Escucha de {ip} interrumpida: {exc}")
            poner_estado(conectado=False, modo="reconectando", error=str(exc))
        finally:
            if conn:
                try:
                    conn.cancel_capture()
                except Exception:
                    pass
                try:
                    conn.disconnect()
                except Exception:
                    pass
            if not STOP.is_set():
                STOP.wait(int(LAV["reconnect_seconds"]))

    logging.info(f"Hilo de {ip} finalizado")


# =========================
# WORKERS
# =========================
def worker_guardado():
    while not STOP.is_set() or not COLA.empty():
        try:
            m = COLA.get(timeout=1)
        except queue.Empty:
            continue
        try:
            if LAV.get("normalize_name_ascii", True):
                m["nombre"] = a_ascii(m.get("nombre"))
            if guardar_marca(m):
                bump("por_barrido" if m.get("origen") == "barrido" else "en_vivo", 0)
                logging.info(f"MARCA {m['origen']:<7} | {m['fecha']} | ID={m['user_id']} "
                             f"{m['nombre'] or '?'}")
                HAY_TRABAJO.set()
            else:
                bump("duplicadas")
        except Exception:
            logging.exception("Error guardando la marca")
        finally:
            COLA.task_done()
    logging.info("Worker de guardado finalizado")


def worker_odoo():
    espera = int(LAV["resend_interval_seconds"])
    backoff = 0
    if not ODOO.enabled:
        logging.warning("Envio a Odoo DESHABILITADO: las marcas solo se guardan localmente")
    while not STOP.is_set():
        if not ODOO.enabled:
            STOP.wait(espera)
            continue
        filas = pendientes()
        if not filas:
            HAY_TRABAJO.wait(timeout=espera)
            HAY_TRABAJO.clear()
            backoff = 0
            continue
        corte = False
        for f in filas:
            if STOP.is_set():
                break
            try:
                payload = json.loads(f["payload_json"])
            except Exception:
                marcar_resultado(f["id"], False, "payload invalido", descartar=True)
                continue
            ok, transitorio, msg = ODOO.enviar(payload)
            if ok:
                marcar_resultado(f["id"], True)
                bump("enviadas")
                logging.info(f"Odoo OK | ID={f['user_id']} | {f['fecha']} | {msg}")
                backoff = 0
            elif transitorio:
                marcar_resultado(f["id"], False, msg)
                logging.warning(f"Odoo no disponible ({msg}); las marcas quedan pendientes")
                corte = True
                break
            else:
                descartar = (f["intentos"] + 1) >= ODOO.max_reintentos
                marcar_resultado(f["id"], False, msg, descartar)
                if descartar:
                    bump("rechazadas")
                logging.log(logging.ERROR if descartar else logging.WARNING,
                            f"Odoo rechazo | ID={f['user_id']} | {f['fecha']} | {msg}"
                            + (" | DESCARTADA" if descartar else ""))
        if corte:
            backoff = min(backoff * 2 if backoff else espera, 300)
            STOP.wait(backoff)
    logging.info("Worker de Odoo finalizado")


def escribir_estado():
    ruta = os.path.join(BASE_DIR, LAV.get("status_file", "logs/estado_lavalle.json"))
    try:
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        with ESTADO_LOCK:
            est = dict(ESTADO)
        with STATS_LOCK:
            est["stats"] = dict(STATS)
        est.update({"ts": ahora_txt(), "pid": os.getpid(),
                    "pendientes_odoo": contar_pendientes(), "cola": COLA.qsize()})
        tmp = ruta + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(est, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, ruta)
    except Exception:
        logging.debug("No se pudo escribir el estado", exc_info=True)


# =========================
# MAIN
# =========================
def main():
    if not EQUIPOS:
        logging.error("No hay equipos configurados en config.json ('lavalle.devices')")
        sys.exit(1)

    init_db()
    hilos = [threading.Thread(target=worker_guardado, name="Guardado", daemon=True),
             threading.Thread(target=worker_odoo, name="Odoo", daemon=True)]
    for eq in EQUIPOS:
        hilos.append(threading.Thread(target=hilo_lector, args=(eq,),
                                      name=f"Lector-{eq['ip']}", daemon=True))
    for h in hilos:
        h.start()

    logging.info(f"Conector de {LAV.get('sede','Lavalle')} en marcha "
                 f"({', '.join(e['ip'] for e in EQUIPOS)}) — Ctrl+C para salir")

    latido = int(LAV["heartbeat_minutes"]) * 60
    ultimo = time.time()
    try:
        while True:
            if time.time() - ultimo >= latido:
                with STATS_LOCK:
                    s = dict(STATS)
                with ESTADO_LOCK:
                    e = dict(ESTADO)
                logging.info("-------------------------------")
                logging.info(f"Activo a las {ahora_txt()} | {e.get('modo')} | "
                             f"conectado={e.get('conectado')}")
                logging.info(f"Marcas en vivo={s['en_vivo']} duplicadas={s['duplicadas']} "
                             f"enviadas={s['enviadas']} rechazadas={s['rechazadas']} | "
                             f"pendientes={contar_pendientes()}")
                logging.info("-------------------------------")
                ultimo = time.time()
            escribir_estado()
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("Deteniendo...")
    finally:
        STOP.set()
        HAY_TRABAJO.set()
        for h in hilos:
            h.join(timeout=8)
        logging.info(f"Quedaron {contar_pendientes()} marcas pendientes de enviar")
        logging.info("Listo.")


if __name__ == "__main__":
    main()
