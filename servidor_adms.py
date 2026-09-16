# -*- coding: utf-8 -*-
"""
Servidor ADMS (push) para los lectores ZKTeco — sede Lavalle

Por que existe: el protocolo del puerto 4370 sirve para leer usuarios, marcas y
huellas, pero NO permite cargar una foto. Las fotos (BIOPHOTO) solo viajan por
el protocolo push, donde el lector es el que llama al servidor.

O sea que se da vuelta la relacion: en vez de que nosotros llamemos al lector,
el lector nos llama a nosotros cada pocos segundos y nos:
  - deja las marcas en el momento en que ocurren (tiempo real de verdad)
  - pregunta si tenemos comandos para el (alta de gente, foto, baja)

Endpoints que usa el equipo:
  GET  /iclock/cdata?SN=..&options=all   -> le devolvemos su configuracion
  POST /iclock/cdata?SN=..&table=ATTLOG  -> nos deja las marcas
  GET  /iclock/getrequest?SN=..          -> nos pide comandos
  POST /iclock/devicecmd?SN=..           -> nos dice como le fue con cada comando

    python servidor_adms.py

Configuracion: la seccion "adms" de config.json.
"""

import base64
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULT_ADMS = {
    "enabled": True,
    "host": "0.0.0.0",
    "port": 8082,
    # Cada cuanto el lector nos pregunta si hay comandos (segundos)
    "delay": 10,
    "error_delay": 30,
    # Zona horaria que se le informa al equipo
    "timezone": -3,
    # Equipos autorizados: numero de serie -> nombre. Vacio = se acepta cualquiera
    "equipos": {"CL3S211160720": "Horus (Lavalle)"},
    "sede": "lavalle",
}


def _deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


with open(CONFIG_PATH, "r", encoding="utf-8") as _fh:
    CFG = json.load(_fh)
ADMS = _deep_merge(DEFAULT_ADMS, CFG.get("adms", {}))

# =========================
# LOGGING
# =========================
logs_dir = os.path.join(BASE_DIR, "logs")
os.makedirs(logs_dir, exist_ok=True)


def configurar_logging():
    """Deja el log de este servidor en logs/adms.log.

    OJO: solo se llama cuando este archivo se ejecuta directamente. El panel lo
    importa como modulo, y antes esta configuracion corria en el import: hacia
    root.handlers.clear() y se llevaba TODO el logging del panel a adms.log,
    dejando panel_personas.log vacio. Costo horas de diagnostico a ciegas.
    """
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
    root.handlers.clear()
    fh = RotatingFileHandler(os.path.join(logs_dir, "adms.log"),
                             maxBytes=5_242_880, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    # Con pythonw.exe no hay consola y sys.stdout es None.
    if sys.stdout is not None:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        root.addHandler(sh)

DB_PATH = os.path.join(BASE_DIR, "data", "adms.sqlite3")
DB_LOCK = threading.Lock()
EQUIPOS_VISTOS = {}
VISTOS_LOCK = threading.Lock()


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
                CREATE TABLE IF NOT EXISTS marcas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serie TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    fecha TEXT NOT NULL,
                    estado TEXT,
                    verificacion TEXT,
                    crudo TEXT,
                    recibido TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (serie, user_id, fecha)
                )
            """)
            cr.execute("""
                CREATE TABLE IF NOT EXISTS comandos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serie TEXT NOT NULL,
                    comando TEXT NOT NULL,
                    descripcion TEXT,
                    estado TEXT DEFAULT 'pendiente',   -- pendiente | entregado | ok | error
                    respuesta TEXT,
                    creado TEXT DEFAULT CURRENT_TIMESTAMP,
                    entregado_at TEXT,
                    respondido_at TEXT
                )
            """)
            cr.execute("CREATE INDEX IF NOT EXISTS idx_cmd_pend ON comandos (serie, estado, id)")
            conn.commit()
            logging.info(f"Base del servidor ADMS lista: {DB_PATH}")
        finally:
            conn.close()


def guardar_marca(serie, user_id, fecha, estado, verificacion, crudo):
    with DB_LOCK:
        conn = conectar_db()
        try:
            cr = conn.cursor()
            cr.execute("""
                INSERT OR IGNORE INTO marcas (serie, user_id, fecha, estado, verificacion, crudo)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (serie, user_id, fecha, estado, verificacion, crudo))
            nueva = cr.rowcount > 0
            conn.commit()
            return nueva
        finally:
            conn.close()


def encolar_comando(serie, comando, descripcion=""):
    """Deja un comando esperando a que el lector lo venga a buscar."""
    with DB_LOCK:
        conn = conectar_db()
        try:
            cr = conn.cursor()
            cr.execute("INSERT INTO comandos (serie, comando, descripcion) VALUES (?, ?, ?)",
                       (serie, comando, descripcion))
            conn.commit()
            logging.info(f"Comando encolado para {serie}: {descripcion or comando[:60]}")
            return cr.lastrowid
        finally:
            conn.close()


def comandos_pendientes(serie, limite=3):
    with DB_LOCK:
        conn = conectar_db()
        try:
            return [dict(r) for r in conn.execute("""
                SELECT id, comando, descripcion FROM comandos
                WHERE serie = ? AND estado = 'pendiente' ORDER BY id LIMIT ?
            """, (serie, limite)).fetchall()]
        finally:
            conn.close()


def marcar_entregado(ids):
    if not ids:
        return
    with DB_LOCK:
        conn = conectar_db()
        try:
            conn.executemany("UPDATE comandos SET estado='entregado', entregado_at=? WHERE id=?",
                             [(ahora_txt(), i) for i in ids])
            conn.commit()
        finally:
            conn.close()


def marcar_respuesta(id_, retorno):
    ok = str(retorno).strip() in ("0", "OK")
    with DB_LOCK:
        conn = conectar_db()
        try:
            conn.execute("UPDATE comandos SET estado=?, respuesta=?, respondido_at=? WHERE id=?",
                         ("ok" if ok else "error", str(retorno), ahora_txt(), id_))
            conn.commit()
        finally:
            conn.close()
    return ok


# =========================
# COMANDOS QUE ENTIENDE EL LECTOR
# =========================
def cmd_alta_persona(serie, user_id, nombre, privilegio=0, tarjeta="", clave=""):
    """Crea o actualiza a la persona en el lector."""
    campos = "\t".join([
        f"PIN={user_id}", f"Name={nombre[:24]}", f"Pri={privilegio}",
        f"Passwd={clave}", f"Card={tarjeta}", "Grp=1", "TZ=0000000000000000",
    ])
    return encolar_comando(serie, f"DATA UPDATE USERINFO {campos}",
                           f"alta/edicion de {user_id} {nombre}")


def cmd_baja_persona(serie, user_id):
    return encolar_comando(serie, f"DATA DELETE USERINFO PIN={user_id}",
                           f"baja de {user_id}")


def cmd_foto(serie, user_id, jpg_bytes, biometrica=True):
    """
    Manda la foto de la persona.

    Con biometrica=True va como BIOPHOTO: el lector le extrae el rostro y arma
    la plantilla, o sea que la persona queda habilitada a marcar con la cara sin
    tener que pararse frente al equipo.
    Con biometrica=False va como USERPIC: es solo la foto que se muestra en
    pantalla, no sirve para reconocer.
    """
    contenido = base64.b64encode(jpg_bytes).decode("ascii")
    tabla = "BIOPHOTO" if biometrica else "USERPIC"
    campos = "\t".join([
        f"PIN={user_id}", f"FileName={user_id}.jpg", "Type=9", "Index=0",
        "Format=0", f"Size={len(jpg_bytes)}", f"Content={contenido}",
    ])
    return encolar_comando(serie, f"DATA UPDATE {tabla} {campos}",
                           f"foto de {user_id} ({len(jpg_bytes) // 1024} KB, "
                           f"{'biometrica' if biometrica else 'solo pantalla'})")


# =========================
# SERVIDOR
# =========================
class Handler(BaseHTTPRequestHandler):
    server_version = "ADMS"
    protocol_version = "HTTP/1.1"

    def log_message(self, formato, *args):
        logging.debug("%s - %s" % (self.address_string(), formato % args))

    def _texto(self, cuerpo, codigo=200):
        datos = cuerpo.encode("utf-8") if isinstance(cuerpo, str) else cuerpo
        self.send_response(codigo)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)

    def _serie(self, params):
        return (params.get("SN", [""])[0] or "").strip()

    def _autorizado(self, serie):
        permitidos = ADMS.get("equipos") or {}
        if not permitidos:
            return True
        return serie in permitidos

    def _visto(self, serie, que):
        with VISTOS_LOCK:
            e = EQUIPOS_VISTOS.setdefault(serie, {"serie": serie})
            e["ultimo_contacto"] = ahora_txt()
            e["ultima_accion"] = que
            e["nombre"] = (ADMS.get("equipos") or {}).get(serie, serie)

    # ---------- el lector nos pide su configuracion ----------
    def do_GET(self):
        u = urlparse(self.path)
        params = parse_qs(u.query)
        serie = self._serie(params)

        if u.path.startswith("/iclock/cdata"):
            if not self._autorizado(serie):
                logging.warning(f"Equipo no autorizado: {serie}")
                return self._texto("UNAUTHORIZED", 401)
            self._visto(serie, "pidio configuracion")
            logging.info(f"Equipo {serie} conectado, pidiendo configuracion")
            # TransFlag le dice al equipo QUE cosas nos tiene que mandar
            conf = "\n".join([
                f"GET OPTION FROM: {serie}",
                "Stamp=9999",
                "OpStamp=9999",
                f"ErrorDelay={ADMS['error_delay']}",
                f"Delay={ADMS['delay']}",
                "TransTimes=00:00;14:00",
                "TransInterval=1",
                "TransFlag=TransData AttLog OpLog AttPhoto EnrollUser ChgUser "
                "EnrollFP ChgFP FPImag UserPic FACE BioPhoto",
                f"TimeZone={ADMS['timezone']}",
                "Realtime=1",
                "Encrypt=0",
                "ServerVer=2.4.1",
                "PushProtVer=2.4.1",
            ])
            return self._texto(conf + "\n")

        if u.path.startswith("/iclock/getrequest"):
            if not self._autorizado(serie):
                return self._texto("UNAUTHORIZED", 401)
            self._visto(serie, "pidio comandos")
            pendientes = comandos_pendientes(serie)
            if not pendientes:
                return self._texto("OK\n")
            lineas, ids = [], []
            for c in pendientes:
                lineas.append(f"C:{c['id']}:{c['comando']}")
                ids.append(c["id"])
                logging.info(f"Entregando comando {c['id']} a {serie}: {c['descripcion']}")
            marcar_entregado(ids)
            return self._texto("\n".join(lineas) + "\n")

        if u.path.startswith("/iclock/ping"):
            return self._texto("OK\n")

        logging.debug(f"GET no contemplado: {self.path}")
        self._texto("OK\n")

    # ---------- el lector nos manda datos ----------
    def do_POST(self):
        u = urlparse(self.path)
        params = parse_qs(u.query)
        serie = self._serie(params)
        largo = int(self.headers.get("Content-Length") or 0)
        cuerpo = self.rfile.read(largo) if largo else b""

        if not self._autorizado(serie):
            return self._texto("UNAUTHORIZED", 401)

        if u.path.startswith("/iclock/cdata"):
            tabla = (params.get("table", [""])[0] or "").upper()
            self._visto(serie, f"envio {tabla or 'datos'}")

            if tabla == "ATTLOG":
                nuevas = self._procesar_marcas(serie, cuerpo)
                return self._texto(f"OK: {nuevas}\n")

            if tabla == "OPERLOG":
                logging.info(f"{serie}: registro de operaciones ({largo} bytes)")
                return self._texto("OK\n")

            logging.info(f"{serie}: datos tabla={tabla or '?'} ({largo} bytes)")
            return self._texto("OK\n")

        if u.path.startswith("/iclock/devicecmd"):
            self._visto(serie, "respondio comandos")
            for linea in cuerpo.decode("utf-8", "ignore").splitlines():
                datos = dict(p.split("=", 1) for p in linea.split("&") if "=" in p)
                if "ID" in datos:
                    ok = marcar_respuesta(datos["ID"], datos.get("Return", "?"))
                    nivel = logging.INFO if ok else logging.WARNING
                    logging.log(nivel, f"{serie}: comando {datos['ID']} -> "
                                       f"Return={datos.get('Return')} {datos.get('CMD','')}")
            return self._texto("OK\n")

        logging.debug(f"POST no contemplado: {self.path}")
        self._texto("OK\n")

    def _procesar_marcas(self, serie, cuerpo):
        """
        Cada linea es una marca:  PIN <tab> fecha <tab> estado <tab> verificacion ...
        """
        nuevas = 0
        for linea in cuerpo.decode("utf-8", "ignore").splitlines():
            if not linea.strip():
                continue
            campos = linea.split("\t")
            if len(campos) < 2:
                continue
            user_id = campos[0].strip()
            fecha = campos[1].strip()
            estado = campos[2].strip() if len(campos) > 2 else ""
            verif = campos[3].strip() if len(campos) > 3 else ""
            if guardar_marca(serie, user_id, fecha, estado, verif, linea):
                nuevas += 1
                logging.info(f"MARCA | {fecha} | ID={user_id} | equipo={serie}")
        return nuevas


def estado_equipos():
    with VISTOS_LOCK:
        return [dict(v) for v in EQUIPOS_VISTOS.values()]


def main():
    configurar_logging()
    if not ADMS.get("enabled", True):
        logging.error("El servidor ADMS esta deshabilitado en config.json")
        sys.exit(1)

    init_db()
    servidor = ThreadingHTTPServer((ADMS["host"], int(ADMS["port"])), Handler)
    servidor.daemon_threads = True

    logging.info(f"Servidor ADMS escuchando en http://{ADMS['host']}:{ADMS['port']}/")
    logging.info("Para que el lector reporte aca, en su menu de red hay que poner:")
    logging.info(f"   Servidor / ADMS -> direccion del servidor, puerto {ADMS['port']}")
    permitidos = ADMS.get("equipos") or {}
    if permitidos:
        for s, n in permitidos.items():
            logging.info(f"   equipo autorizado: {s} ({n})")
    else:
        logging.warning("   sin lista de equipos: se acepta cualquier lector que se conecte")

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        logging.info("Cerrando...")
    finally:
        servidor.shutdown()
        logging.info("Listo.")


if __name__ == "__main__":
    main()
