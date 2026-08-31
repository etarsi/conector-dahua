# -*- coding: utf-8 -*-
"""
Panel ZKTeco — lector Horus (192.168.0.80)

Panel aparte del de los lectores Dahua, a proposito: son protocolos distintos y
no conviene mezclarlos hasta que este andando. Mas adelante se unifican.

Diferencias con el panel Dahua:
  - ZKTeco habla su propio protocolo por el puerto 4370 (libreria pyzk),
    nada que ver con el SDK de Dahua.
  - El equipo acepta UNA conexion por vez, asi que aca se conecta, se hace lo
    que haya que hacer, y se desconecta enseguida.
  - NUNCA se llama a disable_device(): eso dejaria al lector sin aceptar
    marcas mientras estamos conectados.

    python panel_zkteco.py

Configuracion: la seccion "zkteco" de config.json.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta
from struct import unpack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULT_ZK = {
    "enabled": True,
    "host": "0.0.0.0",
    "port": 8081,
    "password": "",
    "session_hours": 12,
    # Equipos ZKTeco
    "devices": [
        {"ip": "192.168.0.80", "puerto": 4370, "password": 0, "nombre": "Horus"}
    ],
    # Cada cuanto se traen las marcas nuevas
    "poll_seconds": 120,
    "timeout_seconds": 30,
    # Cuantos dias de marcas se guardan la primera vez
    "dias_primera_carga": 7,
}


def _deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


with open(CONFIG_PATH, "r", encoding="utf-8") as _fh:
    CFG = json.load(_fh)
ZKCFG = _deep_merge(DEFAULT_ZK, CFG.get("zkteco", {}))
EQUIPOS = ZKCFG.get("devices") or []

# =========================
# LOGGING
# =========================
logs_dir = os.path.join(BASE_DIR, "logs")
os.makedirs(logs_dir, exist_ok=True)
_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s: %(message)s")
root = logging.getLogger()
root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
root.handlers.clear()
_fh_log = RotatingFileHandler(os.path.join(logs_dir, "panel_zkteco.log"),
                              maxBytes=5_242_880, backupCount=3, encoding="utf-8")
_fh_log.setFormatter(_fmt)
root.addHandler(_fh_log)
_sh = logging.StreamHandler(sys.stdout)
_sh.setFormatter(_fmt)
root.addHandler(_sh)

try:
    from zk import ZK, const
    from zk.base import ZK as ZKBase
except ImportError:
    logging.error("Falta la libreria pyzk. Instalar con:  python -m pip install pyzk")
    sys.exit(1)

# El equipo tiene registros con fechas corruptas que rompen la libreria al
# decodificarlos. Se los marca con una fecha centinela y despues se descartan,
# en vez de perder toda la lectura por un registro malo.
FECHA_INVALIDA = datetime(1900, 1, 1)
_decode_original = ZKBase._ZK__decode_time
_corruptas = {"n": 0}


def _decode_tolerante(self, t):
    try:
        return _decode_original(self, t)
    except Exception:
        _corruptas["n"] += 1
        return FECHA_INVALIDA


ZKBase._ZK__decode_time = _decode_tolerante

def _decodificar_fecha_zk(valor):
    """Convierte el entero de 4 bytes que usa ZKTeco en fecha y hora."""
    t = valor
    segundo = t % 60; t //= 60
    minuto = t % 60;  t //= 60
    hora = t % 24;    t //= 24
    dia = t % 31 + 1; t //= 31
    mes = t % 12 + 1; t //= 12
    anio = t + 2000
    try:
        return datetime(anio, mes, dia, hora, minuto, segundo)
    except ValueError:
        return None


def leer_marcas_crudo(conn):
    """
    Lee las marcas del equipo interpretando bien el tamaño de registro.

    pyzk asume registros de 8, 16 o 40 bytes, pero este Horus usa **49**
    (2.792.804 bytes / 56.996 marcas = 49 exacto). Al no contemplarlo, pyzk
    lo lee como 40 y devuelve basura: fechas del año 2133 y miles de usuarios
    inexistentes. Aca se calcula el tamaño real y se parsea con la estructura
    uid(2) + user_id(24) + estado(1) + fecha(4) + punch(1) + relleno.

    Devuelve (marcas, corruptas) donde cada marca es un dict.
    """
    datos, size = conn.read_with_buffer(const.CMD_ATTLOG_RRQ)
    if size < 4:
        return [], 0

    total = unpack("I", datos[:4])[0]
    cuerpo = datos[4:]
    cantidad = int(getattr(conn, "records", 0) or 0)
    tam = (total // cantidad) if cantidad else 0
    if tam <= 0 or total % (cantidad or 1) != 0:
        # Si la division no da exacta se prueban los tamaños conocidos
        for candidato in (49, 40, 32, 16, 8):
            if len(cuerpo) % candidato == 0:
                tam = candidato
                break
    if tam < 8:
        logging.error(f"No pude deducir el tamaño de registro (total={total}, marcas={cantidad})")
        return [], 0

    logging.info(f"Marcas: {len(cuerpo)} bytes, registros de {tam} bytes -> {len(cuerpo) // tam} marcas")

    marcas, corruptas = [], 0
    for i in range(0, len(cuerpo) - tam + 1, tam):
        r = cuerpo[i:i + tam]
        if tam == 8:
            uid, estado, crudo, punch = unpack("<HB4sB", r[:8])
            user_id = str(uid)
        elif tam == 16:
            user_id_num, crudo, estado, punch, _ = unpack("<I4sBB6s", r[:16])
            uid = user_id_num
            user_id = str(user_id_num)
        else:
            # 40, 49 y variantes: mismo comienzo, cambia el relleno del final
            uid, uid_bytes, estado, crudo, punch = unpack("<H24sB4sB", r[:32])
            user_id = uid_bytes.split(b"\x00", 1)[0].decode("ascii", "ignore").strip()
        fecha = _decodificar_fecha_zk(unpack("<I", crudo)[0])
        if fecha is None or not user_id:
            corruptas += 1
            continue
        marcas.append({"uid": uid, "user_id": user_id, "fecha": fecha,
                       "estado": estado, "punch": punch})
    return marcas, corruptas


STOP = threading.Event()
DB_PATH = os.path.join(BASE_DIR, "data", "panel_zkteco.sqlite3")
DB_LOCK = threading.Lock()
ZK_LOCK = threading.Lock()          # el equipo acepta una conexion por vez
SESIONES = {}
SESIONES_LOCK = threading.Lock()

ESTADO = {}                         # ip -> ultimo estado conocido del equipo
ESTADO_LOCK = threading.Lock()


def ahora_txt():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =========================
# BASE DE DATOS
# =========================
def conectar_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
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
                CREATE TABLE IF NOT EXISTS zk_usuarios (
                    equipo TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    uid INTEGER,
                    nombre TEXT,
                    privilegio INTEGER,
                    tarjeta TEXT,
                    actualizado TEXT,
                    PRIMARY KEY (equipo, user_id)
                )
            """)
            cr.execute("""
                CREATE TABLE IF NOT EXISTS zk_marcas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    equipo TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    nombre TEXT,
                    fecha TEXT NOT NULL,
                    estado INTEGER,
                    punch INTEGER,
                    creado TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (equipo, user_id, fecha)
                )
            """)
            cr.execute("CREATE INDEX IF NOT EXISTS idx_zk_marcas_fecha ON zk_marcas (fecha)")
            conn.commit()
            logging.info(f"Base del panel ZKTeco lista: {DB_PATH}")
        finally:
            conn.close()


def guardar_usuarios(ip, usuarios):
    with DB_LOCK:
        conn = conectar_db()
        try:
            cr = conn.cursor()
            for u in usuarios:
                cr.execute("""
                    INSERT INTO zk_usuarios (equipo, user_id, uid, nombre, privilegio, tarjeta, actualizado)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(equipo, user_id) DO UPDATE SET
                        uid = excluded.uid, nombre = excluded.nombre,
                        privilegio = excluded.privilegio, tarjeta = excluded.tarjeta,
                        actualizado = excluded.actualizado
                """, (ip, str(u.user_id), u.uid, u.name, u.privilege, str(u.card), ahora_txt()))
            conn.commit()
        finally:
            conn.close()


def guardar_marcas(ip, marcas, nombres):
    """Devuelve cuantas marcas nuevas se guardaron."""
    nuevas = 0
    with DB_LOCK:
        conn = conectar_db()
        try:
            cr = conn.cursor()
            for m in marcas:
                uid = str(m["user_id"])
                cr.execute("""
                    INSERT OR IGNORE INTO zk_marcas (equipo, user_id, nombre, fecha, estado, punch)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (ip, uid, nombres.get(uid, ""),
                      m["fecha"].strftime("%Y-%m-%d %H:%M:%S"), m["estado"], m["punch"]))
                nuevas += cr.rowcount
            conn.commit()
        finally:
            conn.close()
    return nuevas


def ultima_marca(ip):
    with DB_LOCK:
        conn = conectar_db()
        try:
            r = conn.execute("SELECT MAX(fecha) FROM zk_marcas WHERE equipo = ?", (ip,)).fetchone()
            return r[0] if r and r[0] else None
        finally:
            conn.close()


def listar_usuarios(ip=None, busqueda=""):
    with DB_LOCK:
        conn = conectar_db()
        try:
            sql = """
                SELECT u.equipo, u.user_id, u.nombre, u.privilegio, u.actualizado,
                       (SELECT COUNT(*) FROM zk_marcas m
                         WHERE m.equipo = u.equipo AND m.user_id = u.user_id) AS marcas,
                       (SELECT MAX(fecha) FROM zk_marcas m
                         WHERE m.equipo = u.equipo AND m.user_id = u.user_id) AS ultima
                FROM zk_usuarios u WHERE 1=1
            """
            args = []
            if ip:
                sql += " AND u.equipo = ? "
                args.append(ip)
            if busqueda:
                sql += " AND (u.nombre LIKE ? OR u.user_id LIKE ?) "
                args += [f"%{busqueda}%", f"%{busqueda}%"]
            sql += " ORDER BY u.nombre"
            return [dict(r) for r in conn.execute(sql, args).fetchall()]
        finally:
            conn.close()


def listar_marcas(limite=60):
    with DB_LOCK:
        conn = conectar_db()
        try:
            return [dict(r) for r in conn.execute("""
                SELECT equipo, user_id, nombre, fecha, estado, punch
                FROM zk_marcas ORDER BY fecha DESC LIMIT ?
            """, (limite,)).fetchall()]
        finally:
            conn.close()


def resumen_db():
    with DB_LOCK:
        conn = conectar_db()
        try:
            return {
                "usuarios": conn.execute("SELECT COUNT(*) FROM zk_usuarios").fetchone()[0],
                "marcas": conn.execute("SELECT COUNT(*) FROM zk_marcas").fetchone()[0],
                "hoy": conn.execute("SELECT COUNT(*) FROM zk_marcas WHERE fecha >= ?",
                                    (datetime.now().strftime("%Y-%m-%d 00:00:00"),)).fetchone()[0],
            }
        finally:
            conn.close()


# =========================
# CONEXION AL LECTOR
# =========================
def conectar(equipo):
    """Abre una conexion al lector. Hay que cerrarla siempre."""
    zk = ZK(equipo["ip"], port=int(equipo.get("puerto", 4370)),
            timeout=int(ZKCFG["timeout_seconds"]),
            password=int(equipo.get("password", 0)),
            ommit_ping=True)
    return zk.connect()


def poner_estado(ip, **campos):
    with ESTADO_LOCK:
        e = ESTADO.setdefault(ip, {"ip": ip})
        e.update(campos)
        e["actualizado"] = ahora_txt()


def leer_equipo(equipo, traer_marcas=True):
    """
    Se conecta, lee informacion, usuarios y marcas nuevas, y se desconecta.
    Nunca deshabilita el lector: la gente puede seguir marcando mientras tanto.
    """
    ip = equipo["ip"]
    conn = None
    with ZK_LOCK:
        try:
            conn = conectar(equipo)
            info = {
                "conectado": True,
                "nombre": equipo.get("nombre") or conn.get_device_name(),
                "firmware": conn.get_firmware_version(),
                "serie": conn.get_serialnumber(),
                "hora_equipo": conn.get_time().strftime("%Y-%m-%d %H:%M:%S"),
                "error": "",
            }
            try:
                conn.read_sizes()
                info.update({"usuarios": conn.users, "rostros": conn.faces,
                             "huellas": conn.fingers, "marcas_equipo": conn.records})
            except Exception:
                logging.debug("No se pudieron leer los contadores", exc_info=True)

            usuarios = conn.get_users()
            guardar_usuarios(ip, usuarios)
            nombres = {str(u.user_id): u.name for u in usuarios}

            nuevas = 0
            if traer_marcas:
                validas, corruptas = leer_marcas_crudo(conn)

                desde = ultima_marca(ip)
                if desde:
                    corte = datetime.strptime(desde, "%Y-%m-%d %H:%M:%S")
                else:
                    corte = datetime.now() - timedelta(days=int(ZKCFG["dias_primera_carga"]))
                recientes = [m for m in validas if m["fecha"] >= corte]

                nuevas = guardar_marcas(ip, recientes, nombres)
                info["marcas_corruptas"] = corruptas
                info["marcas_leidas"] = len(validas)
                if nuevas:
                    logging.info(f"{ip}: {nuevas} marcas nuevas guardadas")

            info["ultimas_nuevas"] = nuevas
            poner_estado(ip, **info)
            return True, info

        except Exception as exc:
            logging.warning(f"No se pudo leer {ip}: {exc}")
            poner_estado(ip, conectado=False, error=str(exc), nombre=equipo.get("nombre") or ip)
            return False, {"error": str(exc)}
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass


def worker_lectura():
    """Cada tanto se conecta a cada equipo y trae lo nuevo."""
    intervalo = int(ZKCFG["poll_seconds"])
    primera = True
    while not STOP.is_set():
        for equipo in EQUIPOS:
            if STOP.is_set():
                break
            ok, info = leer_equipo(equipo)
            if ok and primera:
                logging.info(f"{equipo['ip']}: {info.get('usuarios','?')} usuarios, "
                             f"{info.get('marcas_equipo','?')} marcas en el equipo")
        primera = False
        STOP.wait(intervalo)
    logging.info("Worker de lectura finalizado")


# =========================
# SESIONES
# =========================
def nueva_sesion():
    token = secrets.token_urlsafe(32)
    with SESIONES_LOCK:
        SESIONES[token] = time.time() + int(ZKCFG["session_hours"]) * 3600
    return token


def sesion_valida(token):
    if not token:
        return False
    with SESIONES_LOCK:
        vence = SESIONES.get(token)
        if not vence:
            return False
        if time.time() > vence:
            SESIONES.pop(token, None)
            return False
        return True


# =========================
# SERVIDOR WEB
# =========================
class Handler(BaseHTTPRequestHandler):
    server_version = "PanelZKTeco"

    def log_message(self, formato, *args):
        logging.debug("%s - %s" % (self.address_string(), formato % args))

    def _json(self, datos, codigo=200):
        cuerpo = json.dumps(datos, ensure_ascii=False).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(cuerpo)

    def _leer_json(self):
        largo = int(self.headers.get("Content-Length") or 0)
        if largo <= 0 or largo > 1024 * 1024:
            return {}
        try:
            return json.loads(self.rfile.read(largo).decode("utf-8"))
        except Exception:
            return {}

    def _autorizado(self):
        return sesion_valida(self.headers.get("X-Panel-Token"))

    def do_GET(self):
        ruta = urlparse(self.path).path
        if ruta == "/":
            cuerpo = PAGINA.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers()
            self.wfile.write(cuerpo)
            return

        if not self._autorizado():
            return self._json({"error": "no autorizado"}, 401)

        if ruta == "/api/estado":
            with ESTADO_LOCK:
                equipos = [dict(v) for v in ESTADO.values()]
            if not equipos:
                equipos = [{"ip": e["ip"], "nombre": e.get("nombre") or e["ip"], "conectado": False}
                           for e in EQUIPOS]
            return self._json({"equipos": equipos, "resumen": resumen_db()})

        if ruta == "/api/usuarios":
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            return self._json({"usuarios": listar_usuarios(busqueda=q)})

        if ruta == "/api/marcas":
            return self._json({"marcas": listar_marcas()})

        self._json({"error": "no encontrado"}, 404)

    def do_POST(self):
        ruta = urlparse(self.path).path
        datos = self._leer_json()

        if ruta == "/api/login":
            esperada = str(ZKCFG.get("password", ""))
            if not esperada:
                return self._json({"error": "El panel no tiene clave configurada en config.json"}, 500)
            time.sleep(0.4)
            if hmac.compare_digest(str(datos.get("password", "")), esperada):
                logging.info(f"Ingreso al panel ZKTeco desde {self.address_string()}")
                return self._json({"token": nueva_sesion()})
            logging.warning(f"Intento de acceso fallido desde {self.address_string()}")
            return self._json({"error": "Clave incorrecta"}, 401)

        if not self._autorizado():
            return self._json({"error": "no autorizado"}, 401)

        if ruta == "/api/leer_ahora":
            def tarea():
                for equipo in EQUIPOS:
                    leer_equipo(equipo)
            threading.Thread(target=tarea, name="LecturaManual", daemon=True).start()
            return self._json({"ok": True, "detalle": "Leyendo el lector, mira en unos segundos."})

        self._json({"error": "no encontrado"}, 404)


PAGINA = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#1e5f8f">
<title>ZKTeco — Horus</title>
<style>
  :root {
    --acento:#155e8a; --acento-fuerte:#0f4a6e; --acento-suave:#e2eef6; --acento-borde:#b3d3e6;
    --fondo:#f2f4f6; --tarjeta:#fff; --tarjeta-alt:#f8fafb; --borde:#dfe4e8;
    --texto:#16202a; --texto-2:#5b6771; --texto-3:#8b969f;
    --ok:#0f7a52; --ok-fondo:#e2f2ea; --alerta:#b23c17; --alerta-fondo:#fbe9e2;
    --sombra:0 1px 2px rgba(16,28,40,.05), 0 6px 20px -12px rgba(16,28,40,.35);
    --radio:14px; --radio-chico:10px;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --acento:#5aaede; --acento-fuerte:#7cc2ea; --acento-suave:#12283a; --acento-borde:#1f4460;
      --fondo:#0e1418; --tarjeta:#161f26; --tarjeta-alt:#1c262d; --borde:#26323b;
      --texto:#e8eef2; --texto-2:#9aa8b2; --texto-3:#6d7b85;
      --ok:#4ec596; --ok-fondo:#12302a; --alerta:#f08b62; --alerta-fondo:#33201a;
      --sombra:0 1px 2px rgba(0,0,0,.4), 0 6px 20px -12px rgba(0,0,0,.7);
    }
  }
  * { box-sizing:border-box; -webkit-tap-highlight-color:transparent; }
  body { margin:0; background:var(--fondo); color:var(--texto); font-size:16px; line-height:1.5;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; -webkit-font-smoothing:antialiased; }
  #login { max-width:380px; margin:12vh auto; padding:0 20px; }
  header { position:sticky; top:0; z-index:20; background:var(--tarjeta); border-bottom:1px solid var(--borde);
           padding:max(12px,env(safe-area-inset-top)) 16px 12px; }
  .header-fila { display:flex; align-items:center; gap:12px; max-width:960px; margin:0 auto; }
  .header-fila h1 { font-size:17px; margin:0; font-weight:650; letter-spacing:-.02em; flex:1; }
  main { max-width:960px; margin:0 auto; padding:16px 16px 60px; }
  .tarjeta { background:var(--tarjeta); border:1px solid var(--borde); border-radius:var(--radio);
             box-shadow:var(--sombra); padding:20px 18px; margin-bottom:16px; }
  .tarjeta > h2 { font-size:12px; text-transform:uppercase; letter-spacing:.09em; color:var(--texto-3);
                  margin:0 0 16px; font-weight:650; }
  label { display:block; font-size:13px; font-weight:600; color:var(--texto-2); margin-bottom:7px; }
  input { width:100%; padding:13px 14px; font:inherit; border:1.5px solid var(--borde);
          border-radius:var(--radio-chico); background:var(--tarjeta-alt); color:var(--texto); }
  input:focus { outline:none; border-color:var(--acento); box-shadow:0 0 0 3px color-mix(in srgb,var(--acento) 18%,transparent); }
  button { font:inherit; font-weight:600; cursor:pointer; border-radius:var(--radio-chico);
           border:1.5px solid transparent; padding:13px 18px; min-height:48px;
           display:inline-flex; align-items:center; justify-content:center; gap:8px; transition:transform .12s,filter .15s; }
  button:active { transform:scale(.975); }
  .btn-principal { background:var(--acento); color:#fff; width:100%; }
  .btn-2 { background:var(--tarjeta-alt); color:var(--texto); border-color:var(--borde); }
  .btn-chico { padding:9px 14px; min-height:42px; font-size:14px; }
  .estado-equipo { display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
  .punto { width:11px; height:11px; border-radius:50%; flex:none; }
  .punto.on { background:var(--ok); box-shadow:0 0 0 4px var(--ok-fondo); }
  .punto.off { background:var(--alerta); box-shadow:0 0 0 4px var(--alerta-fondo); }
  .metricas { display:grid; grid-template-columns:repeat(auto-fit,minmax(96px,1fr)); gap:10px; margin-top:16px; }
  .metrica { background:var(--tarjeta-alt); border:1px solid var(--borde); border-radius:var(--radio-chico); padding:12px; }
  .metrica strong { display:block; font-size:21px; font-weight:650; font-variant-numeric:tabular-nums; letter-spacing:-.02em; }
  .metrica span { font-size:11.5px; text-transform:uppercase; letter-spacing:.06em; color:var(--texto-3); font-weight:600; }
  .pestanas { display:flex; gap:8px; margin-bottom:16px; }
  .pestanas button { flex:1; }
  .pestanas button.activa { background:var(--acento-suave); border-color:var(--acento); color:var(--acento-fuerte); }
  .filas { display:grid; gap:8px; }
  .fila { display:flex; align-items:center; gap:12px; padding:12px 14px; background:var(--tarjeta-alt);
          border:1px solid var(--borde); border-radius:var(--radio-chico); }
  .fila-datos { min-width:0; flex:1; }
  .fila-nombre { font-weight:650; font-size:15px; }
  .fila-sub { font-size:13px; color:var(--texto-2); font-variant-numeric:tabular-nums; }
  .fila-der { text-align:right; font-size:13px; color:var(--texto-2); font-variant-numeric:tabular-nums; flex:none; }
  .tag { display:inline-block; font-size:11.5px; font-weight:600; padding:3px 9px; border-radius:20px;
         background:var(--acento-suave); color:var(--acento-fuerte); border:1px solid var(--acento-borde); }
  .vacio { text-align:center; padding:32px 16px; color:var(--texto-3); font-size:14.5px; }
  .barra { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:16px; }
  .barra input { flex:1; min-width:170px; }
  #aviso { position:fixed; left:50%; transform:translateX(-50%) translateY(-120%); top:max(14px,env(safe-area-inset-top));
           z-index:60; background:var(--texto); color:var(--fondo); padding:13px 18px; border-radius:12px;
           font-size:14.5px; font-weight:600; transition:transform .34s cubic-bezier(.16,1,.3,1); max-width:92vw; }
  #aviso.visible { transform:translateX(-50%) translateY(0); }
  .oculto { display:none !important; }
  @media (prefers-reduced-motion: reduce) { * { animation:none !important; transition:none !important; } }
</style>
</head>
<body>

<div id="login">
  <div class="tarjeta">
    <h2>Panel ZKTeco</h2>
    <div id="loginError" class="tag oculto" style="background:var(--alerta-fondo);color:var(--alerta);border:none;display:block;margin-bottom:14px;padding:10px 12px"></div>
    <label for="clave">Clave de acceso</label>
    <input id="clave" type="password" autocomplete="current-password">
    <div style="margin-top:16px"><button class="btn-principal" onclick="entrar()">Entrar</button></div>
  </div>
</div>

<div id="app" class="oculto">
  <header>
    <div class="header-fila">
      <h1>ZKTeco</h1>
      <button class="btn-2 btn-chico" onclick="leerAhora()">Leer ahora</button>
    </div>
  </header>
  <main>
    <section class="tarjeta" id="equipos"></section>

    <section class="tarjeta">
      <div class="pestanas">
        <button class="btn-2 activa" id="tabUsuarios" onclick="verPestana('usuarios')">Usuarios</button>
        <button class="btn-2" id="tabMarcas" onclick="verPestana('marcas')">Marcas</button>
      </div>
      <div class="barra" id="barraBuscar">
        <input id="buscar" type="search" placeholder="Buscar por nombre o ID" oninput="cargarUsuarios()">
      </div>
      <div class="filas" id="contenido"></div>
    </section>
  </main>
</div>

<div id="aviso"></div>

<script>
let TOKEN = sessionStorage.getItem("zkToken") || "";
let PESTANA = "usuarios";
let TIMERS = [];

function api(ruta, opciones) {
  opciones = opciones || {};
  opciones.headers = Object.assign({"Content-Type": "application/json", "X-Panel-Token": TOKEN},
                                   opciones.headers || {});
  return fetch(ruta, opciones).then(function (r) {
    if (r.status === 401) { salir(); throw new Error("La sesión venció"); }
    return r.json().then(function (j) {
      if (!r.ok) throw new Error(j.error || "Algo salió mal");
      return j;
    });
  });
}

function escapar(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c];
  });
}

let avisoTimer = null;
function avisar(t, mal) {
  var d = document.getElementById("aviso");
  d.textContent = t;
  d.className = "visible";
  if (mal) { d.style.background = "var(--alerta)"; d.style.color = "#fff"; }
  else { d.style.background = ""; d.style.color = ""; }
  clearTimeout(avisoTimer);
  avisoTimer = setTimeout(function () { d.className = ""; }, 4500);
}

function entrar() {
  fetch("/api/login", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({password: document.getElementById("clave").value})
  })
    .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error); return j; }); })
    .then(function (j) { TOKEN = j.token; sessionStorage.setItem("zkToken", TOKEN); mostrarApp(); })
    .catch(function (e) {
      var d = document.getElementById("loginError");
      d.textContent = e.message; d.classList.remove("oculto");
    });
}

function salir() {
  TOKEN = ""; sessionStorage.removeItem("zkToken");
  TIMERS.forEach(clearInterval); TIMERS = [];
  document.getElementById("app").classList.add("oculto");
  document.getElementById("login").classList.remove("oculto");
}

function mostrarApp() {
  document.getElementById("login").classList.add("oculto");
  document.getElementById("app").classList.remove("oculto");
  cargarEstado(); verPestana("usuarios");
  TIMERS.forEach(clearInterval);
  TIMERS = [setInterval(cargarEstado, 15000)];
}

function cargarEstado() {
  api("/api/estado").then(function (j) {
    var r = j.resumen;
    document.getElementById("equipos").innerHTML = j.equipos.map(function (e) {
      var m = [["usuarios", e.usuarios], ["rostros", e.rostros], ["huellas", e.huellas],
               ["marcas equipo", e.marcas_equipo]].filter(function (x) { return x[1] != null; });
      return '<div class="estado-equipo">' +
          '<span class="punto ' + (e.conectado ? "on" : "off") + '"></span>' +
          '<div style="flex:1;min-width:0">' +
            '<div class="fila-nombre">' + escapar(e.nombre || e.ip) + "</div>" +
            '<div class="fila-sub">' + escapar(e.ip) +
              (e.firmware ? " · " + escapar(e.firmware) : "") +
              (e.hora_equipo ? " · hora " + escapar(e.hora_equipo.slice(11)) : "") + "</div>" +
            (e.error ? '<div class="fila-sub" style="color:var(--alerta)">' + escapar(e.error) + "</div>" : "") +
          "</div></div>" +
        '<div class="metricas">' +
          m.map(function (x) {
            return '<div class="metrica"><strong>' + x[1] + "</strong><span>" + x[0] + "</span></div>";
          }).join("") +
          '<div class="metrica"><strong>' + r.marcas + "</strong><span>guardadas</span></div>" +
          '<div class="metrica"><strong>' + r.hoy + "</strong><span>hoy</span></div>" +
        "</div>";
    }).join("");
  }).catch(function () {});
}

function verPestana(cual) {
  PESTANA = cual;
  document.getElementById("tabUsuarios").classList.toggle("activa", cual === "usuarios");
  document.getElementById("tabMarcas").classList.toggle("activa", cual === "marcas");
  document.getElementById("barraBuscar").classList.toggle("oculto", cual !== "usuarios");
  if (cual === "usuarios") cargarUsuarios(); else cargarMarcas();
}

function cargarUsuarios() {
  var q = document.getElementById("buscar").value;
  api("/api/usuarios?q=" + encodeURIComponent(q)).then(function (j) {
    if (PESTANA !== "usuarios") return;
    document.getElementById("contenido").innerHTML = j.usuarios.map(function (u) {
      return '<div class="fila"><div class="fila-datos">' +
          '<div class="fila-nombre">' + escapar(u.nombre || "(sin nombre)") + "</div>" +
          '<div class="fila-sub">ID ' + escapar(u.user_id) +
            (u.privilegio ? ' · <span class="tag">admin</span>' : "") + "</div>" +
        "</div><div class=\"fila-der\">" + (u.marcas || 0) + " marcas<br>" +
          (u.ultima ? escapar(u.ultima.slice(0, 16)) : "sin marcas") + "</div></div>";
    }).join("") || '<div class="vacio">Todavía no se leyeron usuarios.<br>Probá <strong>Leer ahora</strong>.</div>';
  }).catch(function () {});
}

function cargarMarcas() {
  api("/api/marcas").then(function (j) {
    if (PESTANA !== "marcas") return;
    document.getElementById("contenido").innerHTML = j.marcas.map(function (m) {
      return '<div class="fila"><div class="fila-datos">' +
          '<div class="fila-nombre">' + escapar(m.nombre || ("ID " + m.user_id)) + "</div>" +
          '<div class="fila-sub">ID ' + escapar(m.user_id) + "</div>" +
        "</div><div class=\"fila-der\">" + escapar(m.fecha) + "</div></div>";
    }).join("") || '<div class="vacio">Todavía no hay marcas guardadas.</div>';
  }).catch(function () {});
}

function leerAhora() {
  api("/api/leer_ahora", {method: "POST", body: "{}"})
    .then(function (j) {
      avisar(j.detalle);
      setTimeout(function () { cargarEstado(); verPestana(PESTANA); }, 8000);
    })
    .catch(function (e) { avisar(e.message, true); });
}

document.getElementById("clave").addEventListener("keydown", function (e) {
  if (e.key === "Enter") entrar();
});

if (TOKEN) {
  fetch("/api/estado", {headers: {"X-Panel-Token": TOKEN}})
    .then(function (r) { if (r.ok) { mostrarApp(); } else { salir(); } })
    .catch(function () { salir(); });
}
</script>
</body>
</html>
"""


# =========================
# MAIN
# =========================
def main():
    if not EQUIPOS:
        logging.error("No hay equipos ZKTeco configurados en config.json ('zkteco.devices')")
        sys.exit(1)
    if not ZKCFG.get("password"):
        logging.error('Falta la clave del panel: config.json -> "zkteco" -> "password"')
        sys.exit(1)

    init_db()

    hilo = threading.Thread(target=worker_lectura, name="Lectura", daemon=True)
    hilo.start()

    servidor = ThreadingHTTPServer((ZKCFG["host"], int(ZKCFG["port"])), Handler)
    servidor.daemon_threads = True
    logging.info(f"Panel ZKTeco en http://{ZKCFG['host']}:{ZKCFG['port']}/  (Ctrl+C para salir)")
    logging.info(f"Equipos: {', '.join(e['ip'] for e in EQUIPOS)}")

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        logging.info("Cerrando...")
    finally:
        STOP.set()
        servidor.shutdown()
        hilo.join(timeout=10)
        logging.info("Listo.")


if __name__ == "__main__":
    main()
