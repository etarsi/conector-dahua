# -*- coding: utf-8 -*-
"""
Panel de personas — alta y baja de gente en los lectores Dahua.

Es un panel web local: corre en el servidor del deposito (el SDK necesita
alcanzar a los lectores por la red interna) y se abre desde cualquier PC de la
red. No usa librerias externas, solo la biblioteca estandar de Python.

Corre en un proceso APARTE del conector de asistencias: si algo falla aca, la
captura de marcas sigue funcionando igual.

Idea central: la base local es la fuente de verdad. Das de alta a la persona
una vez y el panel la empuja a todos los lectores; si uno esta caido, queda
pendiente y se sincroniza solo cuando vuelve.

    python panel_personas.py

Configuracion: la seccion "panel" de config.json (reusa los mismos lectores).
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import queue
import secrets
import sqlite3
import ssl
import sys
import threading
import time
import re
import unicodedata
import urllib.request
import xmlrpc.client
from ctypes import (POINTER, Structure, addressof, cast, create_string_buffer, pointer, sizeof,
                    c_char, c_int, c_ubyte, c_void_p)
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULT_PANEL = {
    "enabled": True,
    "host": "0.0.0.0",
    # El navegador solo habilita la camara en sitios seguros, asi que sin
    # https no se puede sacar la foto de rostro desde el panel.
    "https": {
        "enabled": True,
        # 8443 y no 443: en este servidor el 443 lo tiene tomado HTTP.sys
        # (el driver que usan IIS y otros servicios) y no responde. El puerto
        # 80 redirige aca, asi que la URL que se escribe no cambia.
        "port": 8443,
        "cert": "certs/panel.crt",
        "key": "certs/panel.key",
    },
    "port": 8080,
    # Clave para entrar al panel. CAMBIALA: esta pagina da acceso a puertas.
    "password": "",
    # Tipos de persona. Cada tipo define en que lectores va.
    # Los 3 lectores de fijos tienen que tener SIEMPRE la misma gente; el panel
    # se encarga de eso. El de eventuales lleva su propio registro aparte.
    "grupos": {
        "fijo": {
            "nombre": "Personal fijo",
            "lectores": ["192.168.88.245", "192.168.88.252", "192.168.88.253"],
            "vigencia_dias": 3650,
        },
        "eventual": {
            "nombre": "Eventual",
            "lectores": ["192.168.88.254"],
            "vigencia_dias": 90,
        },
    },
    # Puerta del lector a la que se le da permiso (equipos de una puerta: 0)
    "doors": [0],
    # Franja horaria del equipo. 0 suele ser "todo el dia".
    "time_section": 0,
    # Vigencia por defecto de una persona nueva
    "validity_years": 10,
    # Cuantos dias de historial del lector se miran al importar
    "import_days": 30,
    "sync_interval_seconds": 30,
    "session_hours": 12,
    "max_foto_kb": 100,
    "sdk_timeout_ms": 8000,
}


def _deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


with open(CONFIG_PATH, "r", encoding="utf-8") as _fh:
    CFG = json.load(_fh)
PANEL = _deep_merge(DEFAULT_PANEL, CFG.get("panel", {}))
DEVICES = CFG.get("devices", [])
# Sedes: Deposito (lectores Dahua) y Lavalle (ZKTeco)
SEDES = CFG.get("sedes") or {}
SEDE_POR_DEFECTO = next(iter(SEDES), "deposito")

# =========================
# LOGGING
# =========================
logs_dir = os.path.join(BASE_DIR, "logs")
os.makedirs(logs_dir, exist_ok=True)
_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s: %(message)s")
root = logging.getLogger()
root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
root.handlers.clear()
_fh_log = RotatingFileHandler(os.path.join(logs_dir, "panel_personas.log"),
                              maxBytes=5_242_880, backupCount=3, encoding="utf-8")
_fh_log.setFormatter(_fmt)
root.addHandler(_fh_log)
# Corriendo como tarea programada con pythonw.exe no hay consola y sys.stdout
# es None; un StreamHandler sobre eso falla en cada linea que se loguea.
if sys.stdout is not None:
    _sh = logging.StreamHandler(sys.stdout)
    _sh.setFormatter(_fmt)
    root.addHandler(_sh)

try:
    from SDK_Struct import (
        C_BOOL, C_DWORD, C_ENUM, C_LDWORD, C_LLONG,
        NET_TIME, NET_ERROR_DETAIL,
        NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
        NETSDK_INIT_PARAM,
        NET_ACCESS_USER_INFO,
        NET_IN_ACCESS_USER_SERVICE_GET, NET_OUT_ACCESS_USER_SERVICE_GET,
        NET_IN_ACCESS_USER_SERVICE_INSERT, NET_OUT_ACCESS_USER_SERVICE_INSERT,
        NET_IN_ACCESS_USER_SERVICE_REMOVE, NET_OUT_ACCESS_USER_SERVICE_REMOVE,
        NET_ACCESS_FACE_INFO,
        NET_IN_ACCESS_FACE_SERVICE_INSERT, NET_OUT_ACCESS_FACE_SERVICE_INSERT,
        # Historial del lector: sirve para saber que personas tiene cargadas
        NET_IN_FIND_RECORD_PARAM, NET_OUT_FIND_RECORD_PARAM,
        NET_IN_FIND_NEXT_RECORD_PARAM, NET_OUT_FIND_NEXT_RECORD_PARAM,
        NET_FIND_RECORD_ACCESSCTLCARDREC_CONDITION_EX, NET_RECORDSET_ACCESS_CTL_CARDREC,
    )
    from SDK_Enum import (
        EM_LOGIN_SPAC_CAP_TYPE,
        EM_A_NET_EM_ACCESS_CTL_USER_SERVICE,
        EM_A_NET_EM_ACCESS_CTL_FACE_SERVICE,
        EM_A_NET_ENUM_USER_TYPE,
        EM_NET_RECORD_TYPE, EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD, EM_RECORD_ORDER_TYPE,
    )
    from SDK_Callback import fDisConnect
    from NetSDK import NetClient
except ImportError as exc:
    logging.error(f"Error importando el SDK: {exc}")
    sys.exit(1)

client = NetClient()
STOP = threading.Event()

# Lavalle usa lectores ZKTeco, otro protocolo. Si falta la libreria el panel
# igual arranca: simplemente esa sede queda deshabilitada.
try:
    import lector_zkteco
    ZKTECO_OK = True
except Exception as _exc_zk:
    lector_zkteco = None
    ZKTECO_OK = False
    logging.warning(f"Lavalle deshabilitado: {_exc_zk}")

DEV_STATE = {}          # ip -> {conectado, login_id, disconnect}
MAP_LOCK = threading.Lock()
LOGIN_TO_IP = {}
SDK_LOCK = threading.Lock()     # el SDK se llama de a una operacion por vez

DB_PATH = os.path.join(BASE_DIR, "data", "panel_personas.sqlite3")
ASISTENCIAS_DB = os.path.join(BASE_DIR, "data", "attendance_backup.sqlite3")
DB_LOCK = threading.Lock()

SESIONES = {}           # token -> vence (timestamp)
SESIONES_LOCK = threading.Lock()

HAY_TRABAJO = threading.Event()

ESTADO_PENDIENTE = "pendiente"
ESTADO_OK = "ok"
ESTADO_ERROR = "error"
ESTADO_AUSENTE = "ausente"   # no esta en ese lector y no corresponde que este

ACCION_ALTA = "alta"
ACCION_BAJA = "baja"


# =========================
# UTILES
# =========================
def ahora_txt():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def decode_sdk(raw) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw.split("\x00", 1)[0].strip()
    data = bytes(raw).split(b"\x00", 1)[0]
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return data.decode(enc).strip()
        except Exception:
            continue
    return data.decode("utf-8", errors="replace").strip()


def a_ascii(s: str) -> str:
    s = unicodedata.normalize("NFKD", s or "")
    return "".join(c for c in s if not unicodedata.combining(c)).encode("ascii", "ignore").decode("ascii")


def poner_net_time(net_time, dt):
    net_time.dwYear, net_time.dwMonth, net_time.dwDay = dt.year, dt.month, dt.day
    net_time.dwHour, net_time.dwMinute, net_time.dwSecond = dt.hour, dt.minute, dt.second


def solo_digitos(s):
    return "".join(c for c in (s or "") if c.isdigit())


def ips_configuradas():
    """Todas las IPs de lectores, de cualquier sede."""
    ips = [d["ip"] for d in DEVICES]
    for sede in SEDES.values():
        ips += [d["ip"] for d in (sede.get("devices") or [])]
    return ips


def sede_de(clave):
    return SEDES.get(clave) or {}


def es_zkteco(clave):
    return sede_de(clave).get("tecnologia") == "zkteco"


def capacidades(clave):
    return sede_de(clave).get("capacidades") or {}


def lectores_de_sede(clave):
    """Los lectores de una sede (para Lavalle, que no maneja tipos)."""
    return [d["ip"] for d in (sede_de(clave).get("devices") or [])]


def equipo_zk(ip):
    for sede in SEDES.values():
        for d in (sede.get("devices") or []):
            if d["ip"] == ip:
                return d
    return None


def usa_grupos(clave):
    """La sede reparte su gente entre lectores segun el tipo (fijo / eventual).

    Antes esto se deducia de la tecnologia -si era ZKTeco, todos al mismo
    lector-, pero eso dejo de servir cuando Lavalle paso de ZKTeco a Dahua. Lo
    que define el reparto es si la sede maneja tipos, no con que protocolo
    habla el equipo.
    """
    return bool(capacidades(clave).get("tipos", True))


def ips_de_sede(clave):
    """Todos los lectores que pertenecen a esa sede.

    Cada lector declara su sede en config.json. Los que no la declaran son de
    la sede por defecto, que es como venia cuando todos eran del Deposito.
    """
    nombre = (sede_de(clave).get("nombre") or clave).strip().lower()
    ips = {d["ip"] for d in (sede_de(clave).get("devices") or [])}
    for d in DEVICES:
        suya = (d.get("sede") or "").strip().lower()
        if suya == nombre or (not suya and clave == SEDE_POR_DEFECTO):
            ips.add(d["ip"])
    return sorted(ips)


def ips_de_sede_persona(sede):
    """Todos los lectores de esa sede, para poder marcar los que no le tocan."""
    if not usa_grupos(sede):
        return lectores_de_sede(sede)
    return ips_de_sede(sede)


def sede_de_lector(ip):
    """A que sede pertenece un lector."""
    for clave, sede in SEDES.items():
        if ip in [d["ip"] for d in (sede.get("devices") or [])]:
            return clave
    return SEDE_POR_DEFECTO


def lectores_para(sede, tipo):
    """En que lectores va una persona, segun su sede y (si aplica) su tipo."""
    if not usa_grupos(sede):
        return lectores_de_sede(sede)
    return lectores_de_tipo(tipo)


def lectores_de_tipo(tipo):
    """En que lectores tiene que estar una persona de ese tipo."""
    grupo = (PANEL.get("grupos") or {}).get(tipo) or {}
    validas = ips_configuradas()
    return [ip for ip in grupo.get("lectores", []) if ip in validas]


def tipo_de_lector(ip):
    """A que tipo pertenece un lector (fijo / eventual)."""
    for tipo, grupo in (PANEL.get("grupos") or {}).items():
        if ip in (grupo.get("lectores") or []):
            return tipo
    return None


def siguiente_id_de_sede(sede):
    """Proximo identificador libre en una sede que no pide DNI.

    Se toma el mas alto que conoce el panel y se suma uno, y despues se
    comprueba contra el lector que no este ocupado. No se reusan los huecos:
    un numero liberado puede volver a usarse desde el equipo y terminar con
    dos personas distintas compartiendo ID.

    Antes esto se le preguntaba al ZKTeco con pyzk. Dejo de servir cuando
    Lavalle paso a Dahua, asi que ahora se resuelve sin depender del protocolo
    y solo se consulta al equipo para confirmar.
    """
    with DB_LOCK:
        conn = conectar_db()
        try:
            filas = conn.execute("SELECT dni FROM personas WHERE sede = ?", (sede,)).fetchall()
        finally:
            conn.close()
    numeros = [int(f["dni"]) for f in filas if str(f["dni"]).isdigit()]
    candidato = (max(numeros) + 1) if numeros else 1

    ip = next(iter(lectores_para(sede, None)), None)
    if not ip:
        return str(candidato)

    # Hasta 50 intentos: si el equipo tiene gente que el panel no conoce, se
    # sigue subiendo hasta encontrar uno libre de verdad.
    for _ in range(50):
        if not _id_ocupado_en_lector(ip, str(candidato), sede):
            return str(candidato)
        candidato += 1
    return str(candidato)


def _id_ocupado_en_lector(ip, dni, sede):
    """True si ese ID ya existe en el lector. None-safe: ante la duda, libre."""
    try:
        if es_zkteco(sede):
            equipo = equipo_zk(ip)
            return bool(equipo and lector_zkteco.existe_persona(equipo, dni))
        login_id = _login_de(ip)
        if not login_id:
            return False
        return sdk_consultar(login_id, dni) is not None
    except Exception:
        logging.debug(f"No se pudo consultar {dni} en {ip}", exc_info=True)
        return False


def vigencia_por_defecto(tipo=None):
    """
    Desde hoy hasta hoy + 10 años, igual para todas las sedes y tipos.
    (Antes cada grupo tenia su propia duracion; se unifico a pedido.)
    """
    anios = int(PANEL.get("validity_years", 10))
    hoy = datetime.now()
    return hoy, hoy.replace(year=hoy.year + anios)


# =========================
# BASE DE DATOS
# =========================
def conectar_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def _necesita_migrar(cr):
    """
    Las bases viejas usaban solo el DNI como clave. Eso hacia que una persona de
    Lavalle con el mismo ID que una del Deposito pisara a la otra, sin aviso.
    Ahora la clave es (sede, dni).
    """
    try:
        cols = list(cr.execute("PRAGMA table_info(personas)"))
    except Exception:
        return False
    if not cols:
        return False
    clave = [c[1] for c in cols if c[5]]     # c[5] = forma parte de la clave primaria
    return clave == ["dni"]


def _migrar_a_clave_sede(cr):
    """Copia los datos de las tablas viejas a las nuevas, deduciendo la sede."""
    equipos_sede = {}
    for clave, sd in SEDES.items():
        for ip in ips_de_sede_persona(clave):
            equipos_sede[ip] = clave

    cols_viejas = [c[1] for c in cr.execute("PRAGMA table_info(personas_vieja)")]
    comunes = [c for c in cols_viejas if c in
               [x[1] for x in cr.execute("PRAGMA table_info(personas)")]]
    lista = ", ".join(comunes)
    cr.execute(f"INSERT OR IGNORE INTO personas ({lista}) SELECT {lista} FROM personas_vieja")
    personas = cr.rowcount

    # A la sincronizacion vieja le falta la sede: se deduce del equipo
    filas = list(cr.execute("SELECT * FROM sincronizacion_vieja"))
    nombres = [d[0] for d in cr.description]
    sincro = 0
    for f in filas:
        d = dict(zip(nombres, f))
        sede = equipos_sede.get(d.get("equipo"))
        if not sede:
            continue
        d["sede"] = sede
        campos = [k for k in d if k in [x[1] for x in cr.execute("PRAGMA table_info(sincronizacion)")]]
        marcas = ", ".join("?" for _ in campos)
        cr.execute(f"INSERT OR IGNORE INTO sincronizacion ({', '.join(campos)}) VALUES ({marcas})",
                   [d[k] for k in campos])
        sincro += cr.rowcount

    cr.execute("DROP TABLE personas_vieja")
    cr.execute("DROP TABLE sincronizacion_vieja")
    logging.warning(f"Migracion terminada: {personas} personas y {sincro} filas de sincronizacion")


def init_db():
    with DB_LOCK:
        conn = conectar_db()
        try:
            cr = conn.cursor()
            cr.execute("PRAGMA journal_mode = WAL")

            migrar = _necesita_migrar(cr)
            if migrar:
                logging.warning("Base con clave vieja (solo DNI): se migra a (sede, dni)")
                cr.execute("ALTER TABLE personas RENAME TO personas_vieja")
                cr.execute("ALTER TABLE sincronizacion RENAME TO sincronizacion_vieja")
            cr.execute("""
                CREATE TABLE IF NOT EXISTS personas (
                    dni TEXT NOT NULL,
                    nombre TEXT NOT NULL,
                    vigencia_desde TEXT,
                    vigencia_hasta TEXT,
                    foto BLOB,
                    foto_hash TEXT,
                    huella BLOB,                   -- plantillas respaldadas del lector
                    huella_cantidad INTEGER,
                    huella_packet_len INTEGER,
                    huella_duress INTEGER,
                    huella_hash TEXT,
                    huella_actualizada TEXT,
                    activo INTEGER DEFAULT 1,
                    sede TEXT,                     -- deposito | lavalle
                    tipo TEXT,                     -- fijo | eventual (solo Deposito)
                    turno TEXT,                    -- day | night
                    lectores TEXT,                 -- JSON: lectores que le tocan segun el tipo
                    observaciones TEXT,
                    creado TEXT DEFAULT CURRENT_TIMESTAMP,
                    actualizado TEXT,
                    -- La clave es (sede, dni): los IDs de un lector pueden
                    -- repetirse en otra sede y son personas distintas.
                    PRIMARY KEY (sede, dni)
                )
            """)
            cr.execute("""
                CREATE TABLE IF NOT EXISTS sincronizacion (
                    sede TEXT NOT NULL,
                    dni TEXT NOT NULL,
                    equipo TEXT NOT NULL,
                    accion TEXT NOT NULL,          -- alta | baja
                    estado TEXT NOT NULL,          -- pendiente | ok | error
                    intentos INTEGER DEFAULT 0,
                    ultimo_error TEXT,
                    foto_hash TEXT,                -- que foto quedo puesta en ese equipo
                    actualizado TEXT,
                    PRIMARY KEY (sede, dni, equipo)
                )
            """)
            cr.execute("CREATE INDEX IF NOT EXISTS idx_sync_estado ON sincronizacion (estado)")

            if migrar:
                _migrar_a_clave_sede(cr)
            # Migracion para bases creadas antes de tener la columna
            columnas = [c[1] for c in cr.execute("PRAGMA table_info(personas)")]
            if "lectores" not in columnas:
                cr.execute("ALTER TABLE personas ADD COLUMN lectores TEXT")
            if "tipo" not in columnas:
                cr.execute("ALTER TABLE personas ADD COLUMN tipo TEXT")
            if "turno" not in columnas:
                cr.execute("ALTER TABLE personas ADD COLUMN turno TEXT")
            if "sede" not in columnas:
                cr.execute("ALTER TABLE personas ADD COLUMN sede TEXT")
                # lo que ya estaba cargado es del Deposito
                cr.execute("UPDATE personas SET sede = ? WHERE sede IS NULL", (SEDE_POR_DEFECTO,))
            if "odoo_id" not in columnas:
                cr.execute("ALTER TABLE personas ADD COLUMN odoo_id INTEGER")
            for col, tipo_col in (("huella", "BLOB"), ("huella_cantidad", "INTEGER"),
                                  ("huella_packet_len", "INTEGER"), ("huella_duress", "INTEGER"),
                                  ("huella_hash", "TEXT"), ("huella_actualizada", "TEXT")):
                if col not in columnas:
                    cr.execute(f"ALTER TABLE personas ADD COLUMN {col} {tipo_col}")

            cols_sync = [c[1] for c in cr.execute("PRAGMA table_info(sincronizacion)")]
            if "huella_hash" not in cols_sync:
                cr.execute("ALTER TABLE sincronizacion ADD COLUMN huella_hash TEXT")
            conn.commit()
            logging.info(f"Base del panel lista: {DB_PATH}")
        finally:
            conn.close()


def persona_por_dni(dni, sede):
    """La persona de esa sede con ese DNI, o None."""
    with DB_LOCK:
        conn = conectar_db()
        try:
            f = conn.execute(
                "SELECT dni, nombre, tipo, activo FROM personas WHERE sede = ? AND dni = ?",
                (sede, dni)).fetchone()
            return dict(f) if f else None
        finally:
            conn.close()


def guardar_persona(dni, nombre, sede, tipo, turno, desde, hasta, foto_bytes,
                    observaciones="", forzar_foto=False):
    """
    Crea o actualiza la persona.

    El tipo define los lectores: 'fijo' va a los 3 equipos de personal fijo
    (que tienen que quedar identicos) y 'eventual' va solo al suyo. Si a alguien
    le cambias el tipo, se lo da de alta en los lectores nuevos y de baja en los
    del tipo anterior, en una sola operacion.
    """
    foto_hash = hashlib.sha1(foto_bytes).hexdigest() if foto_bytes else None
    lectores = lectores_para(sede, tipo)

    with DB_LOCK:
        conn = conectar_db()
        try:
            cr = conn.cursor()
            previa = cr.execute("SELECT foto, foto_hash FROM personas WHERE sede = ? AND dni = ?",
                                (sede, dni)).fetchone()
            if previa and foto_bytes is None:
                foto_bytes, foto_hash = previa["foto"], previa["foto_hash"]

            cr.execute("""
                INSERT INTO personas (dni, nombre, vigencia_desde, vigencia_hasta, foto,
                                      foto_hash, activo, sede, tipo, turno, lectores,
                                      observaciones, actualizado)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sede, dni) DO UPDATE SET
                    nombre = excluded.nombre,
                    vigencia_desde = excluded.vigencia_desde,
                    vigencia_hasta = excluded.vigencia_hasta,
                    foto = excluded.foto,
                    foto_hash = excluded.foto_hash,
                    activo = 1,
                    sede = excluded.sede,
                    tipo = excluded.tipo,
                    turno = excluded.turno,
                    lectores = excluded.lectores,
                    observaciones = excluded.observaciones,
                    actualizado = excluded.actualizado
            """, (dni, nombre, desde, hasta, foto_bytes, foto_hash,
                  sede, tipo, turno, json.dumps(lectores), observaciones, ahora_txt()))

            for ip in (lectores + [i for i in ips_de_sede_persona(sede) if i not in lectores]):
                actual = cr.execute(
                    "SELECT estado FROM sincronizacion WHERE sede = ? AND dni = ? AND equipo = ?",
                    (sede, dni, ip)
                ).fetchone()
                estaba = actual and actual["estado"] == ESTADO_OK

                if ip in lectores:
                    accion, estado = ACCION_ALTA, ESTADO_PENDIENTE
                elif estaba:
                    accion, estado = ACCION_BAJA, ESTADO_PENDIENTE   # se le saca el acceso ahi
                else:
                    accion, estado = ACCION_ALTA, ESTADO_AUSENTE     # nunca estuvo: no se toca

                cr.execute("""
                    INSERT INTO sincronizacion (sede, dni, equipo, accion, estado, intentos, actualizado)
                    VALUES (?, ?, ?, ?, ?, 0, ?)
                    ON CONFLICT(sede, dni, equipo) DO UPDATE SET
                        accion = ?, estado = ?, intentos = 0, ultimo_error = NULL, actualizado = ?
                """, (sede, dni, ip, accion, estado, ahora_txt(), accion, estado, ahora_txt()))

                # Si el operador adjunto una foto, se sube si o si. Normalmente
                # solo se manda cuando cambia respecto de la que el lector ya
                # tiene, pero si vuelve a elegir el mismo archivo los bytes son
                # identicos, el hash da igual y no se subia nada: desde el panel
                # parecia que "editar no manda la foto". Olvidando lo que se
                # creia puesto, la proxima sincronizacion la sube de nuevo.
                if forzar_foto and ip in lectores:
                    cr.execute(
                        "UPDATE sincronizacion SET foto_hash = NULL "
                        "WHERE sede = ? AND dni = ? AND equipo = ?", (sede, dni, ip))
            conn.commit()
        finally:
            conn.close()
    HAY_TRABAJO.set()


def marcar_baja(dni, sede):
    with DB_LOCK:
        conn = conectar_db()
        try:
            cr = conn.cursor()
            cr.execute("UPDATE personas SET activo = 0, lectores = '[]', actualizado = ? "
                       "WHERE sede = ? AND dni = ?", (ahora_txt(), sede, dni))
            # Solo se pide la baja donde la persona realmente esta cargada,
            # y en los lectores de SU sede (no siempre son los del Deposito)
            for ip in ips_de_sede_persona(sede):
                actual = cr.execute(
                    "SELECT estado FROM sincronizacion WHERE sede = ? AND dni = ? AND equipo = ?",
                    (sede, dni, ip)
                ).fetchone()
                if not actual or actual["estado"] != ESTADO_OK:
                    continue
                cr.execute("""
                    UPDATE sincronizacion
                    SET accion = ?, estado = ?, intentos = 0, ultimo_error = NULL, actualizado = ?
                    WHERE sede = ? AND dni = ? AND equipo = ?
                """, (ACCION_BAJA, ESTADO_PENDIENTE, ahora_txt(), sede, dni, ip))
            conn.commit()
        finally:
            conn.close()
    HAY_TRABAJO.set()


def listar_personas(busqueda="", sede=None):
    with DB_LOCK:
        conn = conectar_db()
        try:
            sql = """
                SELECT p.dni, p.nombre, p.vigencia_desde, p.vigencia_hasta, p.activo,
                       p.foto_hash IS NOT NULL AS tiene_foto, p.foto_hash,
                       p.actualizado, p.observaciones,
                       p.sede, p.tipo, p.turno, p.odoo_id, p.lectores, p.huella_cantidad, p.huella_actualizada
                FROM personas p
            """
            args, condiciones = [], []
            if sede:
                condiciones.append("COALESCE(p.sede, ?) = ?")
                args += [SEDE_POR_DEFECTO, sede]
            if busqueda:
                condiciones.append("(p.dni LIKE ? OR p.nombre LIKE ?)")
                args += [f"%{busqueda}%", f"%{busqueda}%"]
            if condiciones:
                sql += " WHERE " + " AND ".join(condiciones)
            sql += " ORDER BY p.activo DESC, p.nombre"
            personas = [dict(r) for r in conn.execute(sql, args).fetchall()]

            sync = {}
            # La clave es (sede, dni) y no solo el dni: la misma persona puede
            # estar en las dos sedes con el mismo documento, y mezclando las
            # filas se mostraban los lectores de una en la ficha de la otra.
            for r in conn.execute("SELECT sede, dni, equipo, accion, estado, ultimo_error, "
                                  "foto_hash FROM sincronizacion"):
                sync.setdefault((r["sede"], r["dni"]), {})[r["equipo"]] = {
                    "accion": r["accion"], "estado": r["estado"], "error": r["ultimo_error"],
                    "foto": r["foto_hash"],
                }
            for p in personas:
                p["sync"] = sync.get((p["sede"] or SEDE_POR_DEFECTO, p["dni"]), {})
                try:
                    p["lectores"] = json.loads(p["lectores"]) if p["lectores"] else []
                except Exception:
                    p["lectores"] = []
                # Si el lector ya tiene ESTA foto. Sirve para distinguir en la
                # lista "tiene foto cargada en el panel" de "la foto ya esta en
                # el equipo", que es lo unico que le permite fichar.
                p["foto_en_lector"] = bool(p["foto_hash"]) and bool(p["lectores"]) and all(
                    p["sync"].get(ip, {}).get("foto") == p["foto_hash"] for ip in p["lectores"])
            return personas
        finally:
            conn.close()


def obtener_foto(dni, sede):
    with DB_LOCK:
        conn = conectar_db()
        try:
            row = conn.execute("SELECT foto FROM personas WHERE sede = ? AND dni = ?",
                               (sede, dni)).fetchone()
            return row["foto"] if row else None
        finally:
            conn.close()


def tareas_pendientes(equipo=None, limite=25):
    with DB_LOCK:
        conn = conectar_db()
        try:
            sql = """
                SELECT s.dni, s.sede, s.equipo, s.accion, s.intentos,
                       s.foto_hash AS foto_puesta, s.huella_hash AS huella_puesta,
                       p.nombre, p.vigencia_desde, p.vigencia_hasta, p.foto, p.foto_hash,
                       p.huella, p.huella_cantidad, p.huella_packet_len, p.huella_duress, p.huella_hash
                FROM sincronizacion s
                LEFT JOIN personas p ON p.dni = s.dni AND p.sede = s.sede
                WHERE s.estado = ?
            """
            args = [ESTADO_PENDIENTE]
            if equipo:
                sql += " AND s.equipo = ? "
                args.append(equipo)
            sql += " ORDER BY s.intentos, s.actualizado LIMIT ?"
            args.append(limite)
            return [dict(r) for r in conn.execute(sql, args).fetchall()]
        finally:
            conn.close()


def actualizar_sync(dni, sede, equipo, estado, error=None, foto_hash=None, huella_hash=None):
    with DB_LOCK:
        conn = conectar_db()
        try:
            if estado == ESTADO_OK:
                conn.execute("""
                    UPDATE sincronizacion
                    SET estado = ?, ultimo_error = NULL, foto_hash = ?, huella_hash = ?,
                        actualizado = ?
                    WHERE sede = ? AND dni = ? AND equipo = ?
                """, (estado, foto_hash, huella_hash, ahora_txt(), sede, dni, equipo))
            else:
                conn.execute("""
                    UPDATE sincronizacion
                    SET estado = ?, intentos = intentos + 1, ultimo_error = ?, actualizado = ?
                    WHERE sede = ? AND dni = ? AND equipo = ?
                """, (estado, (error or "")[:300], ahora_txt(), sede, dni, equipo))
            conn.commit()
        finally:
            conn.close()


def resumen():
    with DB_LOCK:
        conn = conectar_db()
        try:
            total = conn.execute("SELECT COUNT(*) FROM personas WHERE activo = 1").fetchone()[0]
            pend = conn.execute("SELECT COUNT(*) FROM sincronizacion WHERE estado = ?",
                                (ESTADO_PENDIENTE,)).fetchone()[0]
            err = conn.execute("SELECT COUNT(*) FROM sincronizacion WHERE estado = ?",
                               (ESTADO_ERROR,)).fetchone()[0]
            return {"personas": total, "pendientes": pend, "errores": err}
        finally:
            conn.close()


# =========================
# OPERACIONES CONTRA EL LECTOR
# =========================
def _login_de(ip):
    st = DEV_STATE.get(ip) or {}
    return st.get("login_id")


def sdk_consultar(login_id, dni):
    """Devuelve el nombre si la persona existe en ese lector, o None."""
    try:
        ent = NET_IN_ACCESS_USER_SERVICE_GET()
        ent.dwSize = sizeof(NET_IN_ACCESS_USER_SERVICE_GET)
        ent.nUserNum = 1
        ent.szUserID = dni.encode("utf-8")[:3199]
        ent.bUserIDEx = 0

        sal = NET_OUT_ACCESS_USER_SERVICE_GET()
        sal.dwSize = sizeof(NET_OUT_ACCESS_USER_SERVICE_GET)
        sal.nMaxRetNum = 1
        infos = (NET_ACCESS_USER_INFO * 1)()
        fallos = (C_ENUM * 1)()
        sal.pUserInfo = cast(infos, POINTER(NET_ACCESS_USER_INFO))
        sal.pFailCode = cast(fallos, POINTER(C_ENUM))

        with SDK_LOCK:
            ok = client.OperateAccessUserService(
                int(login_id),
                EM_A_NET_EM_ACCESS_CTL_USER_SERVICE.NET_EM_ACCESS_CTL_USER_SERVICE_GET,
                ent, sal, int(PANEL["sdk_timeout_ms"]))
        if not ok or int(sal.nMaxRetNum) < 1 or int(fallos[0]) != 0:
            return None
        u = infos[0]
        nombre = decode_sdk(u.szNameEx) if bool(u.bUseNameEx) else ""
        return nombre or decode_sdk(u.szName) or ""
    except Exception:
        logging.exception(f"Error consultando {dni}")
        return None


def sdk_alta(login_id, dni, nombre, desde, hasta):
    """Crea o actualiza la persona en el lector."""
    try:
        u = NET_ACCESS_USER_INFO()
        u.szUserID = dni.encode("utf-8")[:31]
        nombre_ascii = a_ascii(nombre)
        if len(nombre_ascii.encode("utf-8")) > 31:
            u.bUseNameEx = 1
            u.szNameEx = nombre_ascii.encode("utf-8")[:127]
            u.szName = nombre_ascii.encode("utf-8")[:31]
        else:
            u.szName = nombre_ascii.encode("utf-8")
        u.emUserType = EM_A_NET_ENUM_USER_TYPE.NET_ENUM_USER_TYPE_NORMAL
        u.nUserStatus = 0

        puertas = PANEL["doors"] or [0]
        u.nDoorNum = len(puertas)
        for i, p in enumerate(puertas[:32]):
            u.nDoors[i] = int(p)
        u.nTimeSectionNum = len(puertas)
        for i in range(len(puertas[:32])):
            u.nTimeSectionNo[i] = int(PANEL["time_section"])

        poner_net_time(u.stuValidBeginTime, desde)
        poner_net_time(u.stuValidEndTime, hasta)

        ent = NET_IN_ACCESS_USER_SERVICE_INSERT()
        ent.dwSize = sizeof(NET_IN_ACCESS_USER_SERVICE_INSERT)
        ent.nInfoNum = 1
        ent.pUserInfo = pointer(u)

        sal = NET_OUT_ACCESS_USER_SERVICE_INSERT()
        sal.dwSize = sizeof(NET_OUT_ACCESS_USER_SERVICE_INSERT)
        sal.nMaxRetNum = 1
        fallos = (C_ENUM * 1)()
        sal.pFailCode = cast(fallos, POINTER(C_ENUM))

        with SDK_LOCK:
            ok = client.OperateAccessUserService(
                int(login_id),
                EM_A_NET_EM_ACCESS_CTL_USER_SERVICE.NET_EM_ACCESS_CTL_USER_SERVICE_INSERT,
                ent, sal, int(PANEL["sdk_timeout_ms"]))
        if not ok:
            return False, f"{client.GetLastErrorMessage()} (codigo interno {int(fallos[0])})"
        return True, ""
    except Exception as exc:
        logging.exception(f"Error dando de alta a {dni}")
        return False, str(exc)


def sdk_baja(login_id, dni):
    try:
        ent = NET_IN_ACCESS_USER_SERVICE_REMOVE()
        ent.dwSize = sizeof(NET_IN_ACCESS_USER_SERVICE_REMOVE)
        ent.nUserNum = 1
        ent.szUserID = dni.encode("utf-8")[:3199]
        ent.bUserIDEx = 0

        sal = NET_OUT_ACCESS_USER_SERVICE_REMOVE()
        sal.dwSize = sizeof(NET_OUT_ACCESS_USER_SERVICE_REMOVE)
        sal.nMaxRetNum = 1
        fallos = (C_ENUM * 1)()
        sal.pFailCode = cast(fallos, POINTER(C_ENUM))

        with SDK_LOCK:
            ok = client.OperateAccessUserService(
                int(login_id),
                EM_A_NET_EM_ACCESS_CTL_USER_SERVICE.NET_EM_ACCESS_CTL_USER_SERVICE_REMOVE,
                ent, sal, int(PANEL["sdk_timeout_ms"]))
        if not ok:
            return False, client.GetLastErrorMessage()
        return True, ""
    except Exception as exc:
        logging.exception(f"Error dando de baja a {dni}")
        return False, str(exc)


# =========================
# HUELLAS
# =========================
# El binding de Python de Dahua no expone el servicio de huellas en ninguna
# version, asi que las estructuras estan transcritas del header oficial
# dhnetsdk.h V3.061 (linea 103909 y siguientes). No estan adivinadas.
#
# Ojo con lo que NO se puede: estos lectores no aceptan la captura remota
# (probado: CaptureAccessPersonCollectionCmd y GetAccessPersonCollectionCaps
# devuelven "device does not support current operation"). El dedo se apoya en
# el equipo; desde aca se lee, se respalda y se copia a otros lectores.

class NET_ACCESS_FINGERPRINT_INFO(Structure):
    _fields_ = [
        ("szUserID", c_char * 32),
        ("nPacketLen", c_int),                    # largo de una huella
        ("nPacketNum", c_int),                    # cuantas huellas
        ("szFingerPrintInfo", POINTER(c_char)),   # nPacketLen * nPacketNum
        ("nDuressIndex", c_int),                  # cual es la huella de coaccion
        ("szUserIDEx", c_char * 128),
        ("bUserIDEx", C_BOOL),
        ("szFingerPrintName", (c_char * 32) * 3),
        ("byReserved", c_ubyte * 3868),
    ]


class NET_IN_FINGERPRINT_INSERT(Structure):
    _fields_ = [("dwSize", C_DWORD), ("nFpNum", c_int),
                ("pFingerPrintInfo", POINTER(NET_ACCESS_FINGERPRINT_INFO))]


class NET_OUT_FINGERPRINT_INSERT(Structure):
    _fields_ = [("dwSize", C_DWORD), ("nMaxRetNum", c_int),
                ("pFailCode", POINTER(C_ENUM)), ("stuDetail", NET_ERROR_DETAIL)]


class NET_IN_FINGERPRINT_GET(Structure):
    _fields_ = [("dwSize", C_DWORD), ("szUserID", c_char * 32),
                ("szUserIDEx", c_char * 128), ("bUserIDEx", C_BOOL)]


class NET_OUT_FINGERPRINT_GET(Structure):
    _fields_ = [
        ("dwSize", C_DWORD),
        ("nRetFingerPrintCount", c_int),
        ("nSinglePacketLength", c_int),
        ("nDuressIndex", c_int),
        ("nMaxFingerDataLength", c_int),
        ("nRetFingerDataLength", c_int),
        ("pbyFingerData", POINTER(c_ubyte)),
        ("stuUpdateTime", NET_TIME),
        ("szFingerPrintName", (c_char * 32) * 3),
    ]


FP_INSERT, FP_GET, FP_UPDATE, FP_REMOVE, FP_CLEAR = 0, 1, 2, 3, 4
FP_MAX_HUELLAS = 10
FP_BUFFER = FP_MAX_HUELLAS * 4096

_fn_huella = client.sdk.CLIENT_OperateAccessFingerprintService
_fn_huella.argtypes = [C_LLONG, c_int, c_void_p, c_void_p, c_int]
_fn_huella.restype = C_BOOL


def _llamar_huella(login_id, operacion, entrada, salida):
    with SDK_LOCK:
        return bool(_fn_huella(
            C_LLONG(int(login_id)), c_int(operacion),
            cast(pointer(entrada), c_void_p), cast(pointer(salida), c_void_p),
            c_int(int(PANEL["sdk_timeout_ms"])),
        ))


def sdk_huella_leer(login_id, dni):
    """
    Trae las huellas que el lector tiene guardadas de esa persona.
    Devuelve dict con los datos crudos, o None si no tiene / no se pudo.
    """
    try:
        ent = NET_IN_FINGERPRINT_GET()
        ent.dwSize = sizeof(NET_IN_FINGERPRINT_GET)
        ent.szUserID = dni.encode("utf-8")[:31]
        ent.bUserIDEx = 0

        sal = NET_OUT_FINGERPRINT_GET()
        sal.dwSize = sizeof(NET_OUT_FINGERPRINT_GET)
        buf = create_string_buffer(FP_BUFFER)
        sal.pbyFingerData = cast(buf, POINTER(c_ubyte))
        sal.nMaxFingerDataLength = FP_BUFFER

        if not _llamar_huella(login_id, FP_GET, ent, sal):
            return None

        cantidad = int(sal.nRetFingerPrintCount)
        largo = int(sal.nRetFingerDataLength)
        if cantidad < 1 or largo < 1:
            return None
        return {
            "cantidad": cantidad,
            "packet_len": int(sal.nSinglePacketLength),
            "duress": int(sal.nDuressIndex),
            "datos": bytes(buf.raw[:largo]),
        }
    except Exception:
        logging.exception(f"Error leyendo la huella de {dni}")
        return None


def sdk_huella_escribir(login_id, dni, huella: dict):
    """Escribe las huellas en el lector. Si ya tiene, las reemplaza."""
    try:
        datos = huella["datos"]
        ultimo = ""
        for operacion, etiqueta in ((FP_INSERT, "alta"), (FP_UPDATE, "reemplazo")):
            info = NET_ACCESS_FINGERPRINT_INFO()
            info.szUserID = dni.encode("utf-8")[:31]
            info.nPacketLen = int(huella["packet_len"])
            info.nPacketNum = int(huella["cantidad"])
            info.nDuressIndex = int(huella.get("duress") or 0)
            buf = create_string_buffer(datos, len(datos))
            info.szFingerPrintInfo = cast(buf, POINTER(c_char))

            ent = NET_IN_FINGERPRINT_INSERT()
            ent.dwSize = sizeof(NET_IN_FINGERPRINT_INSERT)
            ent.nFpNum = 1
            ent.pFingerPrintInfo = pointer(info)

            sal = NET_OUT_FINGERPRINT_INSERT()
            sal.dwSize = sizeof(NET_OUT_FINGERPRINT_INSERT)
            sal.nMaxRetNum = 1
            fallos = (C_ENUM * 1)()
            sal.pFailCode = cast(fallos, POINTER(C_ENUM))

            if _llamar_huella(login_id, operacion, ent, sal):
                return True, ""

            codigo = int(fallos[0])
            ultimo = FALLOS.get(codigo) or f"el lector la rechazo (codigo {codigo})"
            if codigo not in (24, 29):   # ya existe -> se reintenta con reemplazo
                break
            logging.info(f"{dni}: ya tenia huella, se reemplaza ({etiqueta})")
        return False, ultimo
    except Exception as exc:
        logging.exception(f"Error escribiendo la huella de {dni}")
        return False, str(exc)


# Motivos por los que el lector rechaza una foto, en castellano. Son los que le
# van a aparecer a quien carga la gente, asi que conviene que se entiendan.
FALLOS = {
    21: "la foto pesa mas de lo que acepta el lector",
    22: "el usuario no existe en el lector",
    23: "no se pudo extraer el rostro de la foto",
    24: "el usuario ya tiene una foto cargada",
    29: "el usuario ya tiene esa huella cargada",
    25: "el usuario ya llego al maximo de fotos",
    26: "formato de foto invalido (tiene que ser JPG)",
    32: "no se detecto ninguna cara en la foto",
    33: "hay mas de una cara en la foto",
    34: "no se pudo leer la imagen (archivo dañado)",
    35: "la calidad de la foto es muy baja",
    36: "el lector no recomienda esta foto para reconocer",
    37: "la cara esta muy de costado, tiene que ser de frente",
    38: "la cara ocupa demasiado o muy poco: que entre entre 1/3 y 2/3 de la foto",
    39: "la foto esta quemada de luz",
}
FALLO_FOTO_YA_EXISTE = 24


def _armar_face_info(dni, jpg):
    """Prepara la estructura de foto. Devuelve (info, buffer) — hay que mantener
    vivo el buffer mientras dure la llamada al SDK."""
    info = NET_ACCESS_FACE_INFO()
    info.szUserID = dni.encode("utf-8")[:31]
    info.nFacePhoto = 1
    buffer_foto = create_string_buffer(jpg, len(jpg))
    info.nInFacePhotoLen[0] = len(jpg)
    # Sin nOutFacePhotoLen el SDK rechaza la llamada antes de mandarla al equipo
    # (devuelve un error generico y la foto nunca sale del servidor).
    info.nOutFacePhotoLen[0] = len(jpg)
    info.pFacePhoto[0] = addressof(buffer_foto)
    return info, buffer_foto


def sdk_foto(login_id, dni, jpg):
    """Sube la foto de rostro. La persona ya tiene que existir en el lector."""
    try:
        ultimo = ""
        # Primero INSERT (alta). Si el lector avisa que ya tiene foto, se
        # reemplaza con UPDATE.
        operaciones = [
            (EM_A_NET_EM_ACCESS_CTL_FACE_SERVICE.NET_EM_ACCESS_CTL_FACE_SERVICE_INSERT, "alta"),
            (EM_A_NET_EM_ACCESS_CTL_FACE_SERVICE.NET_EM_ACCESS_CTL_FACE_SERVICE_UPDATE, "reemplazo"),
        ]
        for operacion, etiqueta in operaciones:
            info, _buffer = _armar_face_info(dni, jpg)
            ent = NET_IN_ACCESS_FACE_SERVICE_INSERT()
            ent.dwSize = sizeof(NET_IN_ACCESS_FACE_SERVICE_INSERT)
            ent.nFaceInfoNum = 1
            ent.pFaceInfo = pointer(info)

            sal = NET_OUT_ACCESS_FACE_SERVICE_INSERT()
            sal.dwSize = sizeof(NET_OUT_ACCESS_FACE_SERVICE_INSERT)
            sal.nMaxRetNum = 1
            fallos = (C_ENUM * 1)()
            sal.pFailCode = cast(fallos, POINTER(C_ENUM))

            with SDK_LOCK:
                ok = client.OperateAccessFaceService(
                    int(login_id), operacion, ent, sal, int(PANEL["sdk_timeout_ms"]))
            if ok:
                return True, ""

            codigo = int(fallos[0])
            ultimo = FALLOS.get(codigo) or f"el lector la rechazo (codigo {codigo})"
            if codigo != FALLO_FOTO_YA_EXISTE:
                break   # no tiene sentido reintentar con UPDATE
            logging.info(f"{dni}: ya tenia foto, se reemplaza ({etiqueta})")

        return False, ultimo
    except Exception as exc:
        logging.exception(f"Error subiendo la foto de {dni}")
        return False, str(exc)


# =========================
# SINCRONIZACION
# =========================
def aplicar_tarea(t):
    ip = t["equipo"]

    # Lavalle habla ZKTeco: otro protocolo, y sin foto ni huella
    if es_zkteco(sede_de_lector(ip)):
        return aplicar_tarea_zkteco(t, ip)

    login_id = _login_de(ip)
    if not login_id:
        return False, "lector desconectado"

    dni = t["dni"]
    if t["accion"] == ACCION_BAJA:
        ok, msg = sdk_baja(login_id, dni)
        return ok, msg

    if not t.get("nombre"):
        return False, "la persona ya no existe en el panel"

    try:
        desde = datetime.strptime(t["vigencia_desde"], "%Y-%m-%d")
    except Exception:
        desde = datetime.now()
    try:
        hasta = datetime.strptime(t["vigencia_hasta"], "%Y-%m-%d")
    except Exception:
        hasta = datetime.now() + timedelta(days=365 * int(PANEL["validity_years"]))

    ok, msg = sdk_alta(login_id, dni, t["nombre"], desde, hasta)
    if not ok:
        return False, msg

    # La foto va despues del alta, y solo si cambio respecto de lo que ya tiene
    if t["foto"] and t["foto_hash"] != t.get("foto_puesta"):
        foto = bytes(t["foto"])
        ok_foto, msg_foto = sdk_foto(login_id, dni, foto)
        if not ok_foto:
            return False, f"persona creada, pero la foto fallo: {msg_foto}"
        # Se loguea el exito, no solo el fallo: sin esta linea, mirando el log
        # no habia forma de saber si una foto habia salido o si se habia
        # salteado por estar ya puesta.
        logging.info(f"Foto subida | {dni} -> {ip} ({len(foto)} bytes)")

    # La huella respaldada se copia al lector si ahi no esta o si cambio.
    # Asi un eventual que pasa a fijo no tiene que volver a apoyar el dedo.
    if t["huella"] and t["huella_hash"] != t.get("huella_puesta"):
        huella = {
            "datos": bytes(t["huella"]),
            "cantidad": t["huella_cantidad"] or 1,
            "packet_len": t["huella_packet_len"] or 0,
            "duress": t["huella_duress"] or 0,
        }
        ok_h, msg_h = sdk_huella_escribir(login_id, dni, huella)
        if not ok_h:
            return False, f"persona creada, pero la huella fallo: {msg_h}"

    return True, ""


# =========================
# ALTA DEL EMPLEADO EN ODOO
# =========================
# La misma alta que carga a la persona en los lectores la crea en Odoo, para no
# cargar los datos dos veces y que el DNI sea el mismo de los dos lados.
#
# Como mapea:
#   tipo fijo      -> employee_type = 'employee'
#   tipo eventual  -> employee_type = 'eventual'
#   turno dia/noche-> type_shift = 'day' / 'night'

TURNOS = {"day": "Turno Dia", "night": "Turno Noche"}


class EmpleadosOdoo:
    def __init__(self, cfg, cfg_emp):
        self.enabled = bool(cfg_emp.get("enabled")) and bool(cfg.get("url"))
        self.url = (cfg.get("url") or "").rstrip("/")
        self.db = cfg.get("db") or ""
        self.usuario = cfg.get("user") or ""
        self.clave = cfg.get("api_key") or ""
        self.timeout = int(cfg.get("timeout_seconds", 20))
        self.tipo_a_odoo = cfg_emp.get("employee_type_por_tipo") or {
            "fijo": "employee", "eventual": "eventual"}
        self.horario_por_tipo = cfg_emp.get("work_schedule_por_tipo") or {}
        self._uid = None
        self._models = None
        self._lock = threading.Lock()

    def _conectar(self):
        common = xmlrpc.client.ServerProxy(f"{self.url}/xmlrpc/2/common", allow_none=True)
        uid = common.authenticate(self.db, self.usuario, self.clave, {})
        if not uid:
            raise PermissionError("Odoo rechazo el usuario o la api key")
        self._uid = uid
        self._models = xmlrpc.client.ServerProxy(f"{self.url}/xmlrpc/2/object", allow_none=True)

    def _eje(self, modelo, metodo, args, kw=None):
        if self._models is None:
            self._conectar()
        return self._models.execute_kw(self.db, self._uid, self.clave, modelo, metodo, args, kw or {})

    def guardar_empleado(self, dni, nombre, tipo, turno):
        """Crea el empleado en Odoo, o lo actualiza si ya existe ese DNI."""
        if not self.enabled:
            return True, None, "alta en Odoo desactivada"

        with self._lock:
            try:
                valores = {
                    "name": nombre,
                    "dni": dni,
                    "employee_type": self.tipo_a_odoo.get(tipo, "employee"),
                }
                if turno in TURNOS:
                    valores["type_shift"] = turno
                horario = self.horario_por_tipo.get(tipo)
                if horario:
                    valores["work_schedule_id"] = int(horario)

                # active_test False a proposito: por defecto Odoo no devuelve los
                # empleados archivados, y sin esto un reingreso creaba una ficha
                # nueva con un DNI que ya existia. Hay que encontrarlo aunque
                # este de baja, justamente para no duplicarlo.
                existente = self._eje("hr.employee", "search",
                                      [[("dni", "=", dni)]],
                                      {"limit": 1, "context": {"active_test": False}})
                if existente:
                    ficha = self._eje("hr.employee", "read", [existente],
                                      {"fields": ["name", "active"],
                                       "context": {"active_test": False}})
                    archivado = ficha and not ficha[0].get("active")
                    self._eje("hr.employee", "write", [existente, valores])
                    estado = " (estaba archivado)" if archivado else ""
                    logging.info(f"Odoo: empleado actualizado | DNI={dni} {nombre} "
                                 f"(id={existente[0]}){estado}")
                    detalle = "ya existia en Odoo, se actualizo"
                    if archivado:
                        detalle += ". La ficha estaba archivada: revisala en Odoo"
                    return True, existente[0], detalle

                nuevo = self._eje("hr.employee", "create", [valores])
                logging.info(f"Odoo: empleado creado | DNI={dni} {nombre} (id={nuevo})")
                return True, nuevo, "creado en Odoo"

            except PermissionError as exc:
                self._models = None
                return False, None, str(exc)
            except xmlrpc.client.Fault as exc:
                self._models = None
                return False, None, f"Odoo rechazo el alta: {exc.faultString.strip().splitlines()[-1][:200]}"
            except Exception as exc:
                self._models = None
                return False, None, f"no se pudo conectar con Odoo: {exc}"


ODOO_EMPLEADOS = EmpleadosOdoo(CFG.get("odoo") or {}, PANEL.get("odoo_empleados") or {})

# La foto en los ZKTeco no se puede mandar por el protocolo directo: hay que
# encolarla como comando y el lector la retira cuando se conecta al servidor
# ADMS. Se importa aparte para no acoplar los dos paneles.
try:
    import servidor_adms
    ADMS_OK = True
except Exception as _exc_adms:
    servidor_adms = None
    ADMS_OK = False
    logging.warning(f"Sin servidor ADMS, la foto de Lavalle no se va a poder encolar: {_exc_adms}")


def encolar_foto_zkteco(sede, dni, jpg):
    """
    Deja la foto esperando a que el lector la venga a buscar.

    Devuelve (ok, mensaje). Que devuelva True significa que quedo encolada,
    no que el lector ya la tenga: eso pasa cuando el equipo se conecta.
    """
    if not ADMS_OK:
        return False, "el servidor ADMS no esta disponible"
    series = [s for s in (CFG.get("adms", {}).get("equipos") or {})]
    if not series:
        return False, "no hay ningun lector ZKTeco declarado en la seccion adms"
    for serie in series:
        servidor_adms.cmd_foto(serie, dni, jpg, biometrica=True)
    return True, f"foto encolada para {len(series)} lector(es)"


# =========================
# CAPTURA DE HUELLA NUEVA (RPC2)
# =========================
# El SDK no permite pedirle al lector que tome una huella: estos equipos
# responden "operation not supported". Pero la propia web del lector si puede,
# usando su interfaz interna RPC2. Esto reproduce ese mismo flujo:
#
#   1. login RPC2 (desafio MD5)
#   2. eventManager.attach(["Fingerprint"])   -> se suscribe
#   3. GET /SubscribeNotify.cgi                -> canal por donde llegan eventos
#   4. accessControl.captureFingerprint()      -> el lector espera el dedo
#   5. llega el evento con la plantilla
#
# Ojo: RPC2 es la interfaz interna del equipo, no documentada por Dahua. Anda
# (verificado contra los lectores), pero una actualizacion de firmware podria
# cambiarla. Todo lo demas del panel usa el SDK oficial.

CAPTURAS = {}                      # dni -> estado de la captura en curso
CAPTURAS_LOCK = threading.Lock()


def estado_captura(dni, **campos):
    with CAPTURAS_LOCK:
        actual = CAPTURAS.setdefault(dni, {})
        actual.update(campos)
        actual["actualizado"] = ahora_txt()
        return dict(actual)


def ver_captura(dni):
    with CAPTURAS_LOCK:
        return dict(CAPTURAS.get(dni) or {})


class ClienteRPC2:
    """Cliente minimo de la interfaz RPC2 del lector."""

    def __init__(self, ip, usuario, clave):
        self.ip = ip
        self.usuario = usuario
        self.clave = clave
        self.sesion = None
        self._id = 0

    def _post(self, ruta, cuerpo, timeout=20):
        datos = json.dumps(cuerpo).encode()
        req = urllib.request.Request(f"http://{self.ip}{ruta}", method="POST", data=datos)
        req.add_header("Content-Type", "application/json")
        if self.sesion:
            req.add_header("Cookie", f"DhWebClientSessionID={self.sesion}")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())

    def login(self):
        d = self._post("/RPC2_Login", {
            "method": "global.login",
            "params": {"userName": self.usuario, "password": "", "clientType": "Web3.0"},
            "id": 1,
        })
        p = d.get("params") or {}
        self.sesion = d.get("session")
        if not p.get("realm"):
            raise RuntimeError("el lector no devolvio el desafio de login")

        h1 = hashlib.md5(f"{self.usuario}:{p['realm']}:{self.clave}".encode()).hexdigest().upper()
        h2 = hashlib.md5(f"{self.usuario}:{p['random']}:{h1}".encode()).hexdigest().upper()
        r = self._post("/RPC2_Login", {
            "method": "global.login",
            "params": {"userName": self.usuario, "password": h2, "clientType": "Web3.0",
                       "loginType": "Direct", "authorityType": "Default", "passwordType": "Default"},
            "id": 2, "session": self.sesion,
        })
        if not r.get("result"):
            raise RuntimeError(f"el lector rechazo el usuario o la clave: {r.get('error')}")
        return self

    def llamar(self, metodo, params=None, objeto=None, timeout=20):
        self._id += 1
        cuerpo = {"method": metodo, "params": params, "id": self._id, "session": self.sesion}
        if objeto is not None:
            cuerpo["object"] = objeto
        return self._post("/RPC2", cuerpo, timeout)

    def logout(self):
        try:
            self.llamar("global.logout", timeout=5)
        except Exception:
            pass


def _objeto_json_alrededor(texto, pos):
    """El objeto JSON completo que contiene la posicion dada, contando llaves.

    Hace falta contar y no usar una expresion regular porque el Data del evento
    de huella trae objetos anidados: cualquier `.*?\}` corta en la primera llave
    que cierra, que es la de adentro, y el json queda invalido.
    """
    ini = texto.rfind("{", 0, pos)
    while ini != -1:
        nivel, en_texto, escapa = 0, False, False
        for i in range(ini, len(texto)):
            c = texto[i]
            if escapa:
                escapa = False
                continue
            if c == "\\":
                escapa = True
            elif c == '"':
                en_texto = not en_texto
            elif not en_texto:
                if c == "{":
                    nivel += 1
                elif c == "}":
                    nivel -= 1
                    if nivel == 0:
                        return texto[ini:i + 1]
        # objeto incompleto: puede que todavia no haya llegado entero
        ini = texto.rfind("{", 0, ini)
    return None


def _extraer_huella_del_evento(texto):
    """
    Saca la plantilla del evento Fingerprint que emite /SubscribeNotify.cgi.

    Devuelve None mientras no haya un evento completo y parseable. Es importante
    que sea None y no un crudo: quien llama sigue escuchando mientras esto de
    None, y antes se devolvia el texto recibido hasta el momento, que al ser un
    valor verdadero cortaba la espera a los pocos segundos -con el preambulo que
    manda el lector al abrir el canal- sin haber visto ninguna huella.
    """
    if '"Fingerprint"' not in texto:
        return None
    for m in re.finditer(r'"Code"\s*:\s*"Fingerprint"', texto):
        crudo = _objeto_json_alrededor(texto, m.start())
        if not crudo:
            continue
        try:
            ev = json.loads(crudo)
        except Exception:
            continue
        datos = ev.get("Data")
        if datos:
            return datos
    return None


def capturar_huella_en_lector(ip, dni, segundos=60):
    """
    Le pide al lector que tome una huella y espera a que la persona apoye el dedo.
    Devuelve (ok, datos_o_None, mensaje).
    """
    dev = next((d for d in DEVICES if d["ip"] == ip), None)
    if not dev:
        return False, None, f"el lector {ip} no esta configurado"

    cliente = ClienteRPC2(ip, dev["user"], dev["password"])
    obj_em = None
    recibido = {}

    try:
        cliente.login()

        obj_em = cliente.llamar("eventManager.factory.instance").get("result")
        if not obj_em:
            return False, None, "el lector no acepto la suscripcion a eventos"
        att = cliente.llamar("eventManager.attach", {"codes": ["Fingerprint"]}, objeto=obj_em)
        if not att.get("result"):
            return False, None, "no se pudo suscribir al evento de huella"

        # Canal de notificaciones abierto en paralelo: el lector va escribiendo
        # ahi los eventos a medida que ocurren.
        def escuchar():
            try:
                req = urllib.request.Request(f"http://{ip}/SubscribeNotify.cgi")
                req.add_header("Cookie", f"DhWebClientSessionID={cliente.sesion}")
                with urllib.request.urlopen(req, timeout=segundos + 10) as r:
                    acumulado = ""
                    fin = time.time() + segundos
                    while time.time() < fin and not STOP.is_set():
                        # read1 y no read: la respuesta no trae Content-Length, y
                        # read(4096) se queda bloqueado hasta juntar los 4096 bytes.
                        # El lector manda ~1 KB de preambulo y despues se calla
                        # hasta que hay un evento, asi que read() no volvia nunca
                        # y el hilo moria en el timeout sin haber leido nada.
                        trozo = r.read1(4096)
                        if not trozo:
                            break
                        acumulado += trozo.decode("utf-8", errors="ignore")
                        # Se guarda lo recibido aunque no se reconozca: si la
                        # captura falla, es lo unico que permite ver si el lector
                        # mando algo y en que formato.
                        recibido["crudo"] = acumulado
                        datos = _extraer_huella_del_evento(acumulado)
                        if datos:
                            recibido["datos"] = datos
                            return
            except Exception as exc:
                recibido["error"] = str(exc)

        hilo = threading.Thread(target=escuchar, name=f"Huella-{dni}", daemon=True)
        hilo.start()
        time.sleep(1)   # que el canal quede abierto antes de pedir la captura

        obj_ac = cliente.llamar("accessControl.factory.instance", {"channel": 0}).get("result")
        if not obj_ac:
            return False, None, "el lector no acepto la orden de captura"
        cap = cliente.llamar("accessControl.captureFingerprint",
                             {"info": {"ReaderID": "1"}}, objeto=obj_ac)
        if not cap.get("result"):
            return False, None, f"el lector rechazo la captura: {cap.get('error')}"

        logging.info(f"Captura de huella iniciada en {ip} para {dni}: esperando el dedo")
        estado_captura(dni, estado="esperando",
                       mensaje="Apoya el dedo en el lector, tres veces si te lo pide")

        hilo.join(timeout=segundos + 5)

        if recibido.get("datos"):
            logging.info(f"Huella recibida de {ip} para {dni}")
            return True, recibido["datos"], ""
        if recibido.get("error"):
            logging.warning(f"Captura de {dni} en {ip}: se corto el canal de "
                            f"notificaciones -> {recibido['error']}")
            return False, None, f"se corto la escucha: {recibido['error']}"
        crudo = (recibido.get("crudo") or "").strip()
        # El lector manda ~1 KB de preambulo js al abrir el canal. Si aparece la
        # palabra Fingerprint es que hubo evento pero no se pudo interpretar, que
        # es un problema distinto de que no haya llegado nada.
        hubo_evento = '"Fingerprint"' in crudo
        logging.warning(
            f"Captura de {dni} en {ip}: pasaron {segundos}s sin la huella. "
            f"Por el canal llegaron {len(crudo)} caracteres"
            + (" -- HUBO evento de huella pero no se pudo interpretar" if hubo_evento
               else " (solo el preambulo: el lector no mando ningun evento)"))
        if hubo_evento:
            corte = crudo.find('"Fingerprint"')
            logging.warning(f"Evento sin interpretar: {crudo[max(0, corte - 200):corte + 1800]}")
        return False, None, ("El lector no aviso de la huella. "
                             "Puede que no se haya apoyado el dedo, o que este "
                             "modelo no reporte la captura por este canal.")

    except Exception as exc:
        logging.exception(f"Error capturando huella en {ip}")
        return False, None, str(exc)
    finally:
        try:
            if obj_em:
                cliente.llamar("eventManager.detach", {"codes": ["Fingerprint"]}, objeto=obj_em, timeout=5)
        except Exception:
            pass
        cliente.logout()


def tomar_huella(dni):
    """Trabajo de fondo: captura la huella y la guarda."""
    try:
        with DB_LOCK:
            conn = conectar_db()
            try:
                fila = conn.execute(
                    "SELECT nombre, tipo, sede FROM personas WHERE dni = ? AND activo = 1", (dni,)
                ).fetchone()
            finally:
                conn.close()
        if not fila:
            estado_captura(dni, estado="error", mensaje="la persona no esta en el panel")
            return

        lectores = [ip for ip in lectores_para(fila["sede"], fila["tipo"])
                    if (DEV_STATE.get(ip) or {}).get("conectado")]
        if not lectores:
            logging.warning(f"Captura de huella de {dni}: ningun lector conectado para "
                            f"tipo '{fila['tipo']}' en {fila['sede']}")
            estado_captura(dni, estado="error",
                           mensaje="no hay ningun lector conectado para ese tipo de persona")
            return

        # No todos los equipos tienen sensor de huella: el ASI6213S no lo trae y
        # rechaza la orden con "Unknown error". Por eso, si uno la rechaza de
        # entrada, se prueba con el siguiente en vez de darse por vencido.
        ok = False
        for n, ip in enumerate(lectores, start=1):
            estado_captura(dni, estado="iniciando", lector=ip,
                           mensaje=f"Preparando el lector {ip}...")
            ok, datos, msg = capturar_huella_en_lector(ip, dni)
            if ok:
                break
            logging.warning(f"Captura de huella FALLIDA | {dni} {fila['nombre']} "
                            f"en {ip}: {msg}")
            if "rechazo la captura" not in msg or n == len(lectores):
                break
            logging.info(f"{ip} no acepta capturar huella; pruebo con el siguiente")

        if not ok:
            estado_captura(dni, estado="error", mensaje=msg)
            return

        # El evento trae la plantilla; se guarda para que la sincronizacion la
        # replique a los demas lectores del tipo.
        logging.info(f"Evento de huella de {dni}: {_describir_evento(datos)}")

        # Si el lector dice para quien es la huella, tiene que coincidir: hubo
        # casos en que el evento llegaba con otro ID y la plantilla terminaba
        # guardada en la persona equivocada.
        if isinstance(datos, dict):
            del_evento = str(datos.get("UserID") or datos.get("UserId")
                             or datos.get("szUserID") or "").strip()
            if del_evento and del_evento != str(dni):
                logging.error(f"El evento de huella vino con UserID={del_evento} pero se "
                              f"habia pedido para {dni}. No se guarda, para no asignarsela "
                              f"a la persona equivocada.")
                estado_captura(dni, estado="error",
                               mensaje=f"El lector devolvio la huella del usuario {del_evento}, "
                                       f"no la de {dni}. Volve a intentar.")
                return

        plantilla = _plantilla_desde_evento(datos)
        if not plantilla:
            logging.error(f"El evento de {dni} no traia una plantilla usable. "
                          f"Contenido: {_describir_evento(datos)}")
            estado_captura(dni, estado="error",
                           mensaje="El lector aviso de la huella pero no mando la plantilla. "
                                   "Quedo el detalle en el log.")
            return

        guardar_huella(dni, fila["sede"], plantilla)
        marcar_pendiente_huella(dni, fila["sede"])
        estado_captura(dni, estado="ok",
                       mensaje=f"Huella tomada y guardada ({plantilla['cantidad']} dedo/s)")
        logging.info(f"Huella nueva | {dni} {fila['nombre']} | {len(plantilla['datos'])} bytes")
        HAY_TRABAJO.set()

    except Exception as exc:
        logging.exception(f"Error en la captura de huella de {dni}")
        estado_captura(dni, estado="error", mensaje=str(exc))


def _describir_evento(datos):
    """Resumen legible del evento, para el log. No vuelca la plantilla entera."""
    if isinstance(datos, dict):
        partes = []
        for k, v in datos.items():
            if isinstance(v, str) and len(v) > 60:
                partes.append("%s=<texto de %d caracteres>" % (k, len(v)))
            elif isinstance(v, (dict, list)):
                partes.append("%s=%s" % (k, str(v)[:80]))
            else:
                partes.append("%s=%r" % (k, v))
        return "{" + ", ".join(partes) + "}"
    return "%s: %s" % (type(datos).__name__, str(datos)[:200])


def _buscar_plantilla(datos, profundidad=0):
    """Busca, dentro del evento, una cadena que sea una plantilla en base64.

    Se recorre en profundidad porque el nombre de la clave cambia segun el
    modelo y a veces viene anidada. Se acepta solo lo que decodifique a 100
    bytes o mas, para no confundirla con un nombre o un identificador.
    """
    if profundidad > 4:
        return None
    if isinstance(datos, str):
        if len(datos) < 130:
            return None
        try:
            if len(base64.b64decode(datos, validate=True)) >= 100:
                return datos
        except Exception:
            return None
        return None
    if isinstance(datos, dict):
        for v in datos.values():
            r = _buscar_plantilla(v, profundidad + 1)
            if r:
                return r
    elif isinstance(datos, (list, tuple)):
        for v in datos:
            r = _buscar_plantilla(v, profundidad + 1)
            if r:
                return r
    return None


def _plantilla_desde_evento(datos):
    """Arma el dict de plantilla a partir de lo que manda el evento."""
    if isinstance(datos, (bytes, bytearray)):
        crudo = bytes(datos)
    elif isinstance(datos, str):
        try:
            crudo = base64.b64decode(datos)
        except Exception:
            crudo = datos.encode()
    elif isinstance(datos, dict):
        texto = datos.get("Fingerprint") or datos.get("Data") or datos.get("Packet")
        if not texto:
            # Cada modelo nombra la clave a su manera y puede venir anidada, asi
            # que si los nombres conocidos no estan se busca dentro: cualquier
            # cadena que decodifique en base64 a algo del tamano de una
            # plantilla sirve. Es mas robusto que mantener una lista de nombres.
            texto = _buscar_plantilla(datos)
        if not texto:
            return None
        try:
            crudo = base64.b64decode(texto)
        except Exception:
            crudo = str(texto).encode()
    else:
        return None

    if len(crudo) < 100:
        return None
    packet = 810 if len(crudo) % 810 == 0 else len(crudo)
    return {"datos": crudo, "cantidad": max(1, len(crudo) // packet),
            "packet_len": packet, "duress": 0}


def marcar_pendiente_huella(dni, sede):
    """Deja los lectores del tipo listos para recibir la huella nueva."""
    with DB_LOCK:
        conn = conectar_db()
        try:
            conn.execute("""
                UPDATE sincronizacion SET huella_hash = NULL, estado = ?, actualizado = ?
                WHERE sede = ? AND dni = ? AND estado = ?
            """, (ESTADO_PENDIENTE, ahora_txt(), sede, dni, ESTADO_OK))
            conn.commit()
        finally:
            conn.close()


def guardar_huella(dni, sede, huella):
    """Guarda en la base la huella leida de un lector."""
    datos = huella["datos"]
    h = hashlib.sha1(datos).hexdigest()
    with DB_LOCK:
        conn = conectar_db()
        try:
            conn.execute("""
                UPDATE personas
                SET huella = ?, huella_cantidad = ?, huella_packet_len = ?,
                    huella_duress = ?, huella_hash = ?, huella_actualizada = ?
                WHERE sede = ? AND dni = ?
            """, (datos, huella["cantidad"], huella["packet_len"],
                  huella.get("duress") or 0, h, ahora_txt(), sede, dni))
            conn.commit()
        finally:
            conn.close()
    return h


def respaldar_huellas(solo_dni=None):
    """
    Recorre las personas y se trae del lector las huellas que tengan cargadas.
    Es solo lectura sobre los equipos: no modifica nada.
    """
    with DB_LOCK:
        conn = conectar_db()
        try:
            sql = """
                SELECT p.dni, p.sede, p.nombre, s.equipo
                FROM personas p
                JOIN sincronizacion s ON s.dni = p.dni AND s.sede = p.sede AND s.estado = ?
                WHERE p.activo = 1
            """
            args = [ESTADO_OK]
            if solo_dni:
                sql += " AND p.dni = ? "
                args.append(solo_dni)
            filas = conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    # Por persona, los equipos donde esta cargada
    donde = {}
    nombres = {}
    sedes_de = {}
    for f in filas:
        donde.setdefault(f["dni"], []).append(f["equipo"])
        nombres[f["dni"]] = f["nombre"]
        sedes_de[f["dni"]] = f["sede"]

    con_huella = 0
    sin_huella = 0
    for dni, equipos in donde.items():
        if STOP.is_set():
            break
        huella = None
        for ip in equipos:
            login_id = _login_de(ip)
            if not login_id:
                continue
            huella = sdk_huella_leer(login_id, dni)
            if huella:
                break
        if huella:
            guardar_huella(dni, sedes_de.get(dni, SEDE_POR_DEFECTO), huella)
            con_huella += 1
            logging.info(
                f"Huella respaldada | {dni} {nombres.get(dni, '')} | "
                f"{huella['cantidad']} huella(s), {len(huella['datos'])} bytes"
            )
        else:
            sin_huella += 1

    detalle = (f"Se respaldaron las huellas de {con_huella} personas. "
               f"{sin_huella} no tienen huella cargada en los lectores.")
    logging.info(detalle)
    return {"con_huella": con_huella, "sin_huella": sin_huella, "detalle": detalle}


def aplicar_tarea_zkteco(t, ip):
    """Alta o baja en un lector de Lavalle."""
    if not ZKTECO_OK:
        return False, "falta la libreria pyzk para operar Lavalle"
    equipo = equipo_zk(ip)
    if not equipo:
        return False, f"el lector {ip} no esta configurado"

    dni = t["dni"]
    if t["accion"] == ACCION_BAJA:
        return lector_zkteco.baja_persona(equipo, dni)

    if not t.get("nombre"):
        return False, "la persona ya no existe en el panel"
    return lector_zkteco.alta_persona(equipo, dni, t["nombre"])


def reconciliar_lectores():
    """Le da una fila de sincronizacion a cada persona por cada lector que le toca.

    Los lectores de una persona salen de config.json, y hasta ahora eso se
    miraba solo al darla de alta. Si despues se agregaba un equipo al grupo,
    los que ya estaban cargados no subian nunca a ese equipo: no habia nada
    que volviera a comparar la configuracion contra lo sincronizado.

    Corre al arrancar el panel y solo agrega trabajo, nunca lo quita. Una fila
    marcada 'ausente' -no le tocaba ese lector- pasa a pendiente si ahora si le
    toca. Lo que ya estaba en ok o en error se deja como esta, para no rehacer
    altas que ya funcionaron ni pisar un error que hay que mirar.
    """
    agregadas = 0
    with DB_LOCK:
        conn = conectar_db()
        try:
            cr = conn.cursor()
            personas = cr.execute(
                "SELECT dni, nombre, sede, tipo FROM personas WHERE activo = 1").fetchall()
            existentes = {(r["sede"], r["dni"], r["equipo"]): r["estado"]
                          for r in cr.execute(
                              "SELECT sede, dni, equipo, estado FROM sincronizacion")}

            for per in personas:
                for ip in lectores_para(per["sede"], per["tipo"]):
                    clave = (per["sede"], per["dni"], ip)
                    estado = existentes.get(clave)
                    if estado in (ESTADO_OK, ESTADO_ERROR, ESTADO_PENDIENTE):
                        continue
                    cr.execute("""
                        INSERT INTO sincronizacion
                            (sede, dni, equipo, accion, estado, actualizado)
                        VALUES (?, ?, ?, 'alta', ?, ?)
                        ON CONFLICT(sede, dni, equipo) DO UPDATE SET
                            accion = 'alta',
                            estado = excluded.estado,
                            actualizado = excluded.actualizado
                    """, (per["sede"], per["dni"], ip, ESTADO_PENDIENTE, ahora_txt()))
                    agregadas += 1
            conn.commit()
        finally:
            conn.close()

    if agregadas:
        logging.info(f"Reconciliacion: {agregadas} altas pendientes por lectores "
                     f"que se agregaron a la configuracion")
        HAY_TRABAJO.set()
    else:
        logging.info("Reconciliacion: todos ya estan en los lectores que les tocan")
    return agregadas


def worker_sincronizacion():
    intervalo = int(PANEL["sync_interval_seconds"])
    while not STOP.is_set():
        try:
            tareas = tareas_pendientes()
        except Exception:
            logging.exception("Error leyendo tareas pendientes")
            tareas = []

        if not tareas:
            HAY_TRABAJO.wait(timeout=intervalo)
            HAY_TRABAJO.clear()
            continue

        for t in tareas:
            if STOP.is_set():
                break
            ok, msg = aplicar_tarea(t)
            if ok:
                actualizar_sync(t["dni"], t["sede"], t["equipo"], ESTADO_OK,
                                foto_hash=t["foto_hash"], huella_hash=t["huella_hash"])
                logging.info(f"{t['accion'].upper()} OK | {t['dni']} {t.get('nombre','')} -> {t['equipo']}")
            else:
                # Si el lector esta caido no se cuenta como error: se reintenta igual
                estado = ESTADO_PENDIENTE if "desconectado" in msg else ESTADO_ERROR
                actualizar_sync(t["dni"], t["sede"], t["equipo"], estado, error=msg)
                nivel = logging.INFO if estado == ESTADO_PENDIENTE else logging.WARNING
                logging.log(nivel, f"{t['accion']} {t['dni']} -> {t['equipo']}: {msg}")

        STOP.wait(2)

    logging.info("Worker de sincronizacion finalizado")


def _candidatos_de_lector(login_id, ip, dias):
    """
    Lee el historial de marcas guardado en el propio lector para saber que
    personas tiene cargadas (ID y nombre). Es solo lectura.
    """
    encontrados = {}
    try:
        cond = NET_FIND_RECORD_ACCESSCTLCARDREC_CONDITION_EX()
        cond.dwSize = sizeof(cond)
        cond.bCardNoEnable = 0
        # Por timestamp UTC real: el rango con NET_TIME se interpreta en hora
        # local del equipo y los registros vuelven en UTC.
        cond.bTimeEnable = 0
        cond.bRealUTCTimeEnable = 1
        desde = datetime.now() - timedelta(days=dias)
        hasta = datetime.now() + timedelta(hours=6)
        cond.nStartRealUTCTime = int(desde.timestamp())
        cond.nEndRealUTCTime = int(hasta.timestamp())
        poner_net_time(cond.stStartTime, desde)
        poner_net_time(cond.stEndTime, hasta)
        cond.nOrderNum = 1
        cond.stuOrders[0].emField = \
            EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD.EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD_CREATETIME
        cond.stuOrders[0].emOrderType = EM_RECORD_ORDER_TYPE.EM_RECORD_ORDER_TYPE_DESCENT

        ent = NET_IN_FIND_RECORD_PARAM()
        ent.dwSize = sizeof(ent)
        ent.emType = EM_NET_RECORD_TYPE.ACCESSCTLCARDREC_EX
        ent.pQueryCondition = cast(pointer(cond), c_void_p)
        sal = NET_OUT_FIND_RECORD_PARAM()
        sal.dwSize = sizeof(sal)

        with SDK_LOCK:
            ok = client.FindRecord(int(login_id), ent, sal, 8000)
        if not ok:
            logging.warning(f"No se pudo leer el historial de {ip}")
            return encontrados

        handle = sal.lFindeHandle
        pagina = 200
        try:
            while not STOP.is_set():
                arr = (NET_RECORDSET_ACCESS_CTL_CARDREC * pagina)()
                for r in arr:
                    r.dwSize = sizeof(NET_RECORDSET_ACCESS_CTL_CARDREC)
                sig = NET_IN_FIND_NEXT_RECORD_PARAM()
                sig.dwSize = sizeof(sig)
                sig.lFindeHandle = handle
                sig.nFileCount = pagina
                res = NET_OUT_FIND_NEXT_RECORD_PARAM()
                res.dwSize = sizeof(res)
                res.pRecordList = cast(arr, c_void_p)
                res.nMaxRecordNum = pagina

                with SDK_LOCK:
                    ok = client.FindNextRecord(sig, res, 10000)
                if not ok:
                    break
                devueltos = int(res.nRetRecordNum)
                for i in range(devueltos):
                    rec = arr[i]
                    dni = decode_sdk(getattr(rec, "szUserIDEx", b"")) or decode_sdk(rec.szUserID)
                    if not dni:
                        continue
                    nombre = decode_sdk(rec.szCardNameEx) if bool(rec.bUseCardNameEx) else ""
                    nombre = nombre or decode_sdk(rec.szCardName)
                    if dni not in encontrados or (nombre and not encontrados[dni]):
                        encontrados[dni] = nombre
                if devueltos < pagina:
                    break
        finally:
            try:
                with SDK_LOCK:
                    client.FindRecordClose(handle)
            except Exception:
                pass
    except Exception:
        logging.exception(f"Error leyendo el historial de {ip}")
    return encontrados


def importar_zkteco(clave_sede):
    """
    Trae las personas cargadas en los lectores de una sede ZKTeco.

    Es mucho mas simple que en Dahua: el equipo devuelve la lista completa de
    usuarios de una, no hace falta ir preguntando de a uno.
    """
    if not ZKTECO_OK:
        return 0, "falta la libreria pyzk"

    importados = 0
    lectores = lectores_de_sede(clave_sede)
    for ip in lectores:
        equipo = equipo_zk(ip)
        if not equipo:
            continue
        try:
            personas = lector_zkteco.listar_personas(equipo)
        except Exception as exc:
            logging.warning(f"No se pudo leer el lector {ip}: {exc}")
            continue

        logging.info(f"{ip}: {len(personas)} personas cargadas en el lector")
        for p in personas:
            dni = str(p["user_id"]).strip()
            if not dni:
                continue
            nombre = a_ascii(p["nombre"] or "") or dni
            with DB_LOCK:
                conn = conectar_db()
                try:
                    cr = conn.cursor()
                    cr.execute("""
                        INSERT INTO personas (dni, nombre, activo, sede, tipo, turno,
                                              lectores, observaciones, actualizado)
                        VALUES (?, ?, 1, ?, '', 'day', ?, ?, ?)
                        ON CONFLICT(sede, dni) DO UPDATE SET
                            -- En ZKTeco el lector es la fuente de verdad de
                            -- quien esta cargado, asi que el nombre se toma de ahi
                            nombre = excluded.nombre,
                            lectores = excluded.lectores,
                            actualizado = excluded.actualizado
                    """, (dni, nombre, clave_sede, json.dumps(lectores),
                          "importado del lector", ahora_txt()))
                    # Esta cargada en este lector; en los demas de la sede se
                    # marca ausente hasta que se compruebe.
                    for otro in lectores:
                        estado = ESTADO_OK if otro == ip else ESTADO_AUSENTE
                        cr.execute("""
                            INSERT INTO sincronizacion (sede, dni, equipo, accion, estado, actualizado)
                            VALUES (?, ?, ?, ?, ?, ?)
                            ON CONFLICT(sede, dni, equipo) DO UPDATE SET
                                estado = excluded.estado, actualizado = excluded.actualizado
                        """, (clave_sede, dni, otro, ACCION_ALTA, estado, ahora_txt()))
                    conn.commit()
                finally:
                    conn.close()
            importados += 1

    return importados, f"Se importaron {importados} personas de los lectores de la sede."


def importar_de_lectores(sede=None):
    """
    Arma el inventario de personas.

    Cada sede se importa distinto segun su tecnologia:
      - ZKTeco (Lavalle): el equipo devuelve la lista completa de una.
      - Dahua (Deposito): hay que deducir los IDs del historial de marcas y
        despues preguntar equipo por equipo si cada persona esta cargada.

    Todo es solo lectura sobre los lectores.
    """
    # Si la sede pedida es ZKTeco, se resuelve por ese camino
    if sede and es_zkteco(sede):
        n, detalle = importar_zkteco(sede)
        return {"revisados": n, "importados": n, "diferencias": 0, "detalle": detalle}

    candidatos = {}
    dias = int(PANEL.get("import_days", 30))

    if os.path.exists(ASISTENCIAS_DB):
        try:
            c = sqlite3.connect(ASISTENCIAS_DB)
            c.row_factory = sqlite3.Row
            for r in c.execute("""
                SELECT dni, employee_name FROM attendance_events WHERE dni <> '' GROUP BY dni
            """):
                candidatos[r["dni"]] = r["employee_name"] or ""
            c.close()
        except Exception:
            logging.info("El conector de asistencias todavia no genero historial; se leen los lectores")

    for ip, st in DEV_STATE.items():
        if not st.get("conectado") or not st.get("login_id"):
            continue
        del_lector = _candidatos_de_lector(st["login_id"], ip, dias)
        logging.info(f"{ip}: {len(del_lector)} personas distintas en los ultimos {dias} dias")
        for dni, nombre in del_lector.items():
            if dni not in candidatos or (nombre and not candidatos[dni]):
                candidatos[dni] = nombre

    if not candidatos:
        return {"revisados": 0, "importados": 0,
                "detalle": "No se encontraron personas en el historial de los lectores."}

    importados = 0
    faltantes = []          # personas a las que les falta un lector de su tipo
    conectados = [ip for ip, st in DEV_STATE.items() if st.get("conectado")]
    logging.info(f"Importando: {len(candidatos)} personas a revisar en {len(conectados)} lectores")

    for dni, nombre_hist in candidatos.items():
        if STOP.is_set():
            break
        presencias = {}
        nombre_real = ""
        for ip in conectados:
            login_id = _login_de(ip)
            if not login_id:
                continue
            nombre = sdk_consultar(login_id, dni)
            presencias[ip] = nombre is not None
            if nombre:
                nombre_real = nombre_real or nombre

        if not any(presencias.values()):
            continue

        nombre_final = a_ascii(nombre_real or nombre_hist) or dni
        donde_esta = sorted([ip for ip, existe in presencias.items() if existe])

        # De que tipo es: se deduce de en que grupo de lectores esta cargada
        tipos = {tipo_de_lector(ip) for ip in donde_esta} - {None}
        if len(tipos) == 1:
            tipo = tipos.pop()
            nota = "importado del lector"
        else:
            # Aparece en los dos grupos (o en ninguno conocido): no se toca nada
            tipo = None
            nota = "REVISAR: aparece en fijos y en eventuales"
            logging.warning(f"{dni} {nombre_final}: aparece en los dos grupos, queda para revisar")

        with DB_LOCK:
            conn = conectar_db()
            try:
                cr = conn.cursor()
                cr.execute("""
                    INSERT INTO personas (dni, nombre, vigencia_desde, vigencia_hasta, activo,
                                          sede, tipo, lectores, observaciones, actualizado)
                    VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                    ON CONFLICT(sede, dni) DO UPDATE SET
                        nombre = CASE WHEN personas.nombre = '' THEN excluded.nombre ELSE personas.nombre END,
                        -- Si el lector no permite deducir el tipo se conserva el
                        -- que ya tenia. Antes se pisaba con NULL, y desde que la
                        -- misma persona puede estar cargada en todos los equipos
                        -- eso dejaba sin tipo a todo el padron de una sola pasada.
                        tipo = CASE WHEN excluded.tipo IS NULL THEN personas.tipo ELSE excluded.tipo END,
                        lectores = excluded.lectores,
                        observaciones = excluded.observaciones,
                        actualizado = excluded.actualizado
                """, (dni, nombre_final, None, None, SEDE_POR_DEFECTO, tipo,
                      json.dumps(lectores_de_tipo(tipo) if tipo else donde_esta), nota, ahora_txt()))

                # Donde le toca estar segun su tipo pero no esta -> pendiente
                # (es justamente la diferencia entre los 3 lectores de fijos).
                # Donde no le toca -> ausente, no se toca el equipo.
                le_tocan = lectores_de_tipo(tipo) if tipo else []
                for ip, existe in presencias.items():
                    if existe:
                        estado = ESTADO_OK
                    elif ip in le_tocan:
                        estado = ESTADO_PENDIENTE
                        faltantes.append((dni, nombre_final, ip))
                    else:
                        estado = ESTADO_AUSENTE
                    cr.execute("""
                        INSERT INTO sincronizacion (sede, dni, equipo, accion, estado, actualizado)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(sede, dni, equipo) DO UPDATE SET estado = ?, actualizado = ?
                    """, (SEDE_POR_DEFECTO, dni, ip, ACCION_ALTA, estado, ahora_txt(),
                          estado, ahora_txt()))
                conn.commit()
            finally:
                conn.close()
        importados += 1

    logging.info(f"Importacion terminada: {importados} personas, {len(faltantes)} diferencias entre lectores")
    for dni, nombre, ip in faltantes:
        logging.warning(f"Diferencia: {dni} {nombre} deberia estar en {ip} y no esta")

    detalle = f"Se encontraron {importados} personas cargadas en los lectores."
    if faltantes:
        detalle += f" Hay {len(faltantes)} diferencias entre equipos del mismo tipo: se van a corregir solas."
    else:
        detalle += " Los lectores de cada tipo estan iguales, no hay nada que corregir."
    return {"revisados": len(candidatos), "importados": importados,
            "diferencias": len(faltantes), "detalle": detalle}


# =========================
# CONEXION A LOS LECTORES
# =========================
@fDisConnect
def CallbackDesconexion(lLoginID, pchDVRIP, nDVRPort, dwUser):
    try:
        with MAP_LOCK:
            ip = LOGIN_TO_IP.get(int(lLoginID))
        if ip and ip in DEV_STATE:
            logging.warning(f"Lector desconectado: {ip}")
            DEV_STATE[ip]["conectado"] = False
            DEV_STATE[ip]["disconnect"].set()
    except Exception:
        logging.exception("Error en el callback de desconexion")


def hilo_lector(dev):
    ip = dev["ip"]
    st = DEV_STATE[ip]
    while not STOP.is_set():
        login_id = 0
        st["disconnect"].clear()
        try:
            ent = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY()
            ent.dwSize = sizeof(ent)
            ent.szIP = ip.encode()
            ent.nPort = int(dev["port"])
            ent.szUserName = dev["user"].encode()
            ent.szPassword = dev["password"].encode()
            ent.emSpecCap = EM_LOGIN_SPAC_CAP_TYPE.TCP
            ent.pCapParam = None
            sal = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY()
            sal.dwSize = sizeof(sal)

            login_id, _, err = client.LoginWithHighLevelSecurity(ent, sal)
            if login_id == 0:
                logging.error(f"Login {ip} fallo: {err}")
                STOP.wait(10)
                continue

            with MAP_LOCK:
                LOGIN_TO_IP[int(login_id)] = ip
            st["login_id"] = int(login_id)
            st["conectado"] = True
            logging.info(f"Conectado a {ip}")
            HAY_TRABAJO.set()

            while not STOP.is_set() and not st["disconnect"].is_set():
                st["disconnect"].wait(timeout=1)

        except Exception:
            logging.exception(f"Error en el hilo de {ip}")
        finally:
            st["conectado"] = False
            st["login_id"] = None
            if login_id:
                try:
                    client.Logout(int(login_id))
                except Exception:
                    pass
                with MAP_LOCK:
                    LOGIN_TO_IP.pop(int(login_id), None)
            if not STOP.is_set():
                STOP.wait(10)


# =========================
# SESIONES
# =========================
def nueva_sesion():
    token = secrets.token_urlsafe(32)
    with SESIONES_LOCK:
        SESIONES[token] = time.time() + int(PANEL["session_hours"]) * 3600
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
    server_version = "PanelPersonas"

    def log_message(self, formato, *args):
        logging.debug("%s - %s" % (self.address_string(), formato % args))

    # -- utilidades --
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
        if largo <= 0 or largo > 12 * 1024 * 1024:
            return {}
        try:
            return json.loads(self.rfile.read(largo).decode("utf-8"))
        except Exception:
            return {}

    def _autorizado(self):
        return sesion_valida(self.headers.get("X-Panel-Token"))

    # -- rutas --
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

        if ruta == "/api/equipos":
            if not self._autorizado():
                return self._json({"error": "no autorizado"}, 401)
            equipos = [{"ip": ip, "conectado": bool(st.get("conectado"))} for ip, st in DEV_STATE.items()]
            if not equipos:
                equipos = [{"ip": d["ip"], "conectado": False} for d in DEVICES]
            grupos = {}
            for t, g in (PANEL.get("grupos") or {}).items():
                grupos[t] = {"nombre": g.get("nombre", t), "lectores": lectores_de_tipo(t)}

            sedes = {}
            for clave, sd in SEDES.items():
                sedes[clave] = {
                    "nombre": sd.get("nombre", clave),
                    "tecnologia": sd.get("tecnologia"),
                    "capacidades": sd.get("capacidades") or {},
                    "lectores": ips_de_sede_persona(clave),
                    "disponible": True if sd.get("tecnologia") != "zkteco" else ZKTECO_OK,
                }
            return self._json({"equipos": equipos, "grupos": grupos, "sedes": sedes,
                               "sede_por_defecto": SEDE_POR_DEFECTO, "resumen": resumen()})

        if ruta == "/api/personas":
            if not self._autorizado():
                return self._json({"error": "no autorizado"}, 401)
            params = parse_qs(urlparse(self.path).query)
            q = params.get("q", [""])[0]
            sede = params.get("sede", [""])[0] or None
            return self._json({"personas": listar_personas(q, sede)})

        if ruta.startswith("/api/foto/"):
            if not self._autorizado():
                return self._json({"error": "no autorizado"}, 401)
            partes = ruta.split("/")          # /api/foto/<sede>/<dni>
            if len(partes) >= 5:
                foto = obtener_foto(partes[4], partes[3])
            else:
                foto = obtener_foto(partes[-1], SEDE_POR_DEFECTO)
            if not foto:
                return self._json({"error": "sin foto"}, 404)
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(foto)))
            self.end_headers()
            self.wfile.write(foto)
            return

        self._json({"error": "no encontrado"}, 404)

    def do_POST(self):
        ruta = urlparse(self.path).path
        datos = self._leer_json()

        if ruta == "/api/login":
            clave = str(datos.get("password", ""))
            esperada = str(PANEL.get("password", ""))
            if not esperada:
                return self._json({"error": "El panel no tiene clave configurada en config.json"}, 500)
            time.sleep(0.4)  # freno simple contra fuerza bruta
            if hmac.compare_digest(clave, esperada):
                logging.info(f"Ingreso al panel desde {self.address_string()}")
                return self._json({"token": nueva_sesion()})
            logging.warning(f"Intento de acceso fallido desde {self.address_string()}")
            return self._json({"error": "Clave incorrecta"}, 401)

        if not self._autorizado():
            return self._json({"error": "no autorizado"}, 401)

        if ruta == "/api/personas":
            dni_crudo = (datos.get("dni") or "").strip()
            dni = solo_digitos(dni_crudo)
            nombre = (datos.get("nombre") or "").strip()
            if not nombre:
                return self._json({"error": "Falta el nombre"}, 400)

            d_def, h_def = vigencia_por_defecto((datos.get("tipo") or "").strip())
            desde = datos.get("desde") or d_def.strftime("%Y-%m-%d")
            hasta = datos.get("hasta") or h_def.strftime("%Y-%m-%d")

            foto = None
            if datos.get("foto_base64"):
                try:
                    foto = base64.b64decode(datos["foto_base64"].split(",")[-1])
                except Exception:
                    return self._json({"error": "La foto no se pudo leer"}, 400)
                tope = int(PANEL.get("max_foto_kb", 100)) * 1024
                if len(foto) > tope:
                    return self._json(
                        {"error": f"La foto supera los {tope // 1024} KB que acepta el lector"}, 400)

            sede = (datos.get("sede") or SEDE_POR_DEFECTO).strip()
            if sede not in SEDES:
                return self._json({"error": "Elegi una sede valida"}, 400)
            caps = capacidades(sede)

            tipo = (datos.get("tipo") or "").strip()
            if caps.get("tipos"):
                if tipo not in (PANEL.get("grupos") or {}):
                    return self._json({"error": "Elegi si la persona es de planta fija o eventual"}, 400)
            else:
                tipo = ""   # Lavalle no maneja tipos
            if not lectores_para(sede, tipo):
                return self._json({"error": f"La sede '{sede}' no tiene lectores configurados"}, 400)

            # En Lavalle el identificador es interno del lector y correlativo:
            # no se pide ni se edita, se asigna solo al dar de alta.
            if not caps.get("dni", True):
                if not dni:
                    try:
                        dni = siguiente_id_de_sede(sede)
                        logging.info(f"ID asignado automaticamente en {sede}: {dni}")
                    except Exception as exc:
                        return self._json(
                            {"error": f"No se pudo asignar el ID: {exc}"}, 502)
            elif not dni:
                # Se distingue "escribio letras" de "no escribio nada": antes
                # las dos daban el mismo mensaje sobre numeros, y encima saltaba
                # por largo -pedia 3 digitos- cuando hay identificadores de uno
                # o dos, tanto en Lavalle como en Deposito. Con esa regla 55
                # personas no se podian ni editar.
                if dni_crudo:
                    return self._json(
                        {"error": "El DNI solo puede tener numeros, sin puntos ni letras"}, 400)
                return self._json({"error": "Falta el DNI"}, 400)

            # Un DNI repetido no puede crear una persona nueva: la clave es
            # (sede, dni), asi que el alta pisaria en silencio a la que ya
            # estaba. Al editar se manda el DNI original y ahi si se permite.
            editando = (datos.get("editando") or "").strip()
            if dni != editando:
                ya = persona_por_dni(dni, sede)
                if ya:
                    return self._json({"error":
                        f"Ya hay una persona con el DNI {dni}: {ya['nombre']}. "
                        f"Si querés modificarla, buscala en la lista y usá Editar."}, 409)

            if foto and not caps.get("foto"):
                return self._json(
                    {"error": "El lector de esa sede no acepta foto desde el panel."}, 400)

            turno = (datos.get("turno") or "").strip()
            if not caps.get("turnos", True):
                turno = "day"       # Lavalle no tiene turno noche
            if turno and turno not in TURNOS:
                return self._json({"error": "El turno tiene que ser dia o noche"}, 400)

            guardar_persona(dni, nombre, sede, tipo, turno, desde, hasta, foto,
                            (datos.get("observaciones") or "").strip(),
                            forzar_foto=bool(foto))
            logging.info(f"Alta/edicion desde el panel: {dni} {nombre} "
                         f"(sede {sede}, {tipo or 'sin tipo'}, turno {turno or '-'})")

            # Alta en Odoo: si falla, la persona igual queda cargada en los
            # lectores y el aviso dice que reviso Odoo.
            # Odoo solo para las sedes que lo tengan habilitado. Lavalle todavia
            # no se configura del lado de Odoo, pero si se carga en el lector.
            aviso_odoo = ""
            if sede_de(sede).get("odoo", True):
                ok_odoo, odoo_id, msg_odoo = ODOO_EMPLEADOS.guardar_empleado(dni, nombre, tipo, turno)
            else:
                ok_odoo, odoo_id, msg_odoo = True, None, ""
            if ok_odoo and odoo_id:
                with DB_LOCK:
                    conn = conectar_db()
                    try:
                        conn.execute("UPDATE personas SET odoo_id = ? WHERE sede = ? AND dni = ?",
                                     (odoo_id, sede, dni))
                        conn.commit()
                    finally:
                        conn.close()
            elif not ok_odoo:
                aviso_odoo = msg_odoo
                logging.warning(f"Odoo: no se pudo dar de alta a {dni}: {msg_odoo}")

            # En Lavalle la foto viaja como comando: el lector la retira cuando
            # se conecta al servidor ADMS.
            aviso_foto = ""
            if foto and es_zkteco(sede):
                ok_foto, msg_foto = encolar_foto_zkteco(sede, dni, foto)
                if ok_foto:
                    aviso_foto = ("La foto quedo encolada y se va a cargar en cuanto "
                                  "el lector se conecte al servidor.")
                    logging.info(f"Foto encolada para {dni} en {sede}")
                else:
                    aviso_foto = f"No se pudo encolar la foto: {msg_foto}"
                    logging.warning(aviso_foto)

            ficha = next((p for p in listar_personas(dni) if p["dni"] == dni), None)
            return self._json({"ok": True, "persona": ficha,
                               "odoo": msg_odoo if ok_odoo else "",
                               "aviso": aviso_odoo, "foto": aviso_foto})

        if ruta == "/api/baja":
            dni = solo_digitos(datos.get("dni"))
            if not dni:
                return self._json({"error": "Falta el DNI"}, 400)
            marcar_baja(dni, (datos.get("sede") or SEDE_POR_DEFECTO).strip())
            logging.info(f"Baja desde el panel: {dni}")
            return self._json({"ok": True})

        if ruta == "/api/reintentar":
            with DB_LOCK:
                conn = conectar_db()
                try:
                    conn.execute("UPDATE sincronizacion SET estado = ?, intentos = 0 WHERE estado = ?",
                                 (ESTADO_PENDIENTE, ESTADO_ERROR))
                    conn.commit()
                finally:
                    conn.close()
            HAY_TRABAJO.set()
            return self._json({"ok": True})

        if ruta == "/api/tomar_huella":
            dni = solo_digitos(datos.get("dni"))
            if not dni:
                return self._json({"error": "Falta el DNI"}, 400)
            actual = ver_captura(dni)
            if actual.get("estado") in ("iniciando", "esperando"):
                return self._json({"ok": True, "estado": actual})
            estado_captura(dni, estado="iniciando", mensaje="Preparando el lector...")
            threading.Thread(target=tomar_huella, args=(dni,),
                             name=f"TomarHuella-{dni}", daemon=True).start()
            return self._json({"ok": True, "estado": ver_captura(dni)})

        if ruta == "/api/estado_captura":
            dni = solo_digitos(datos.get("dni"))
            return self._json({"estado": ver_captura(dni)})

        if ruta == "/api/respaldar_huellas":
            hilo = threading.Thread(target=respaldar_huellas, name="RespaldarHuellas", daemon=True)
            hilo.start()
            return self._json({"ok": True,
                               "detalle": "Leyendo las huellas de los lectores, mira el listado en unos segundos."})

        if ruta == "/api/importar":
            sede = (datos.get("sede") or SEDE_POR_DEFECTO).strip()
            hilo = threading.Thread(target=importar_de_lectores, args=(sede,),
                                    name="Importar", daemon=True)
            hilo.start()
            return self._json({"ok": True, "detalle": "Importacion en curso, mira el listado en unos segundos."})

        self._json({"error": "no encontrado"}, 404)


PAGINA = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0f766e">
<title>Personas — Lectores Dahua</title>
<style>
  :root {
    --acento:        #0d7a63;
    --acento-fuerte: #0a6353;
    --acento-suave:  #e3f3ee;
    --acento-borde:  #b4ddd0;
    --fondo:         #f2f4f3;
    --tarjeta:       #ffffff;
    --tarjeta-alt:   #f8faf9;
    --borde:         #dfe4e2;
    --texto:         #16211d;
    --texto-2:       #5b6a64;
    --texto-3:       #8b9a94;
    --ok:            #0d7a63;
    --ok-fondo:      #e3f3ee;
    --alerta:        #b23c17;
    --alerta-fondo:  #fbe9e2;
    --peligro-texto: #ffffff;
    --espera:        #96690a;
    --espera-fondo:  #fbf1d8;
    --sombra:        0 1px 2px rgba(16,32,28,.05), 0 6px 20px -12px rgba(16,32,28,.35);
    --sombra-alta:   0 2px 6px rgba(16,32,28,.08), 0 24px 48px -24px rgba(16,32,28,.45);
    --radio:         14px;
    --radio-chico:   10px;
  }

  @media (prefers-color-scheme: dark) {
    :root {
      --acento:        #45c4a5;
      --acento-fuerte: #5fd8ba;
      --acento-suave:  #12302a;
      --acento-borde:  #1f4d43;
      --fondo:         #0e1513;
      --tarjeta:       #16201d;
      --tarjeta-alt:   #1c2724;
      --borde:         #26332f;
      --texto:         #e8eeec;
      --texto-2:       #9aaaa4;
      --texto-3:       #6d7d77;
      --ok:            #45c4a5;
      --ok-fondo:      #12302a;
      --alerta:        #f08b62;
      --alerta-fondo:  #33201a;
      --peligro-texto: #0e1513;
      --espera:        #d9ac47;
      --espera-fondo:  #2e2718;
      --sombra:        0 1px 2px rgba(0,0,0,.4), 0 6px 20px -12px rgba(0,0,0,.7);
      --sombra-alta:   0 2px 6px rgba(0,0,0,.5), 0 24px 48px -24px rgba(0,0,0,.8);
    }
  }

  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }

  body {
    margin: 0;
    background: var(--fondo);
    color: var(--texto);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
    font-size: 16px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    padding-bottom: env(safe-area-inset-bottom);
  }

  /* ---------- Login ---------- */
  #login {
    max-width: 380px;
    margin: 12vh auto;
    padding: 0 20px;
  }
  #login .tarjeta { padding: 28px 24px; }
  .marca {
    display: flex; align-items: center; gap: 12px;
    margin-bottom: 22px;
  }
  .marca svg { width: 34px; height: 34px; color: var(--acento); flex: none; }
  .marca h1 { font-size: 19px; margin: 0; font-weight: 650; letter-spacing: -.02em; }
  .marca p { margin: 1px 0 0; font-size: 13px; color: var(--texto-2); }

  /* ---------- Estructura ---------- */
  header {
    position: sticky; top: 0; z-index: 20;
    background: color-mix(in srgb, var(--tarjeta) 88%, transparent);
    backdrop-filter: saturate(180%) blur(12px);
    -webkit-backdrop-filter: saturate(180%) blur(12px);
    border-bottom: 1px solid var(--borde);
    padding: 12px 16px calc(12px + env(safe-area-inset-top));
    padding-top: max(12px, env(safe-area-inset-top));
  }
  .header-fila { display: flex; align-items: center; gap: 12px; max-width: 960px; margin: 0 auto; }
  .header-fila h1 { font-size: 17px; margin: 0; font-weight: 650; letter-spacing: -.02em; flex: 1; }
  .equipos { display: flex; gap: 5px; flex-wrap: wrap; justify-content: flex-end; }
  .chip {
    font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 20px;
    border: 1px solid var(--borde); color: var(--texto-3);
    font-variant-numeric: tabular-nums;
  }
  .chip.on  { background: var(--ok-fondo); color: var(--ok); border-color: var(--acento-borde); }
  .chip.off { background: var(--alerta-fondo); color: var(--alerta); border-color: transparent; }

  main { max-width: 960px; margin: 0 auto; padding: 16px 16px 60px; }

  .tarjeta {
    background: var(--tarjeta);
    border: 1px solid var(--borde);
    border-radius: var(--radio);
    box-shadow: var(--sombra);
    padding: 20px 18px;
    margin-bottom: 16px;
  }
  .tarjeta > h2 {
    font-size: 12px; text-transform: uppercase; letter-spacing: .09em;
    color: var(--texto-3); margin: 0 0 16px; font-weight: 650;
  }

  /* ---------- Formulario ---------- */
  label {
    display: block; font-size: 13px; font-weight: 600;
    color: var(--texto-2); margin-bottom: 7px;
  }
  input[type=text], input[type=date], input[type=password], input[type=search] {
    width: 100%; padding: 13px 14px; font: inherit;
    border: 1.5px solid var(--borde); border-radius: var(--radio-chico);
    background: var(--tarjeta-alt); color: var(--texto);
    transition: border-color .15s, box-shadow .15s;
  }
  input:focus {
    outline: none; border-color: var(--acento);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--acento) 18%, transparent);
  }
  .campos { display: grid; gap: 16px; margin-bottom: 16px; }
  @media (min-width: 620px) { .campos.dos { grid-template-columns: 1fr 1fr; } }

  /* ---------- Selector segmentado ---------- */
  .segmentado { display: grid; grid-auto-flow: column; gap: 8px; }
  .segmentado input { position: absolute; opacity: 0; pointer-events: none; }
  .segmentado label {
    margin: 0; display: flex; align-items: center; justify-content: center; gap: 8px;
    padding: 14px 10px; border: 1.5px solid var(--borde); border-radius: var(--radio-chico);
    background: var(--tarjeta-alt); color: var(--texto-2);
    font-size: 15px; font-weight: 600; cursor: pointer;
    transition: all .18s cubic-bezier(.4,0,.2,1);
    min-height: 52px; text-align: center;
  }
  .segmentado label svg { width: 19px; height: 19px; flex: none; }
  .segmentado input:checked + label {
    background: var(--acento-suave); border-color: var(--acento);
    color: var(--acento-fuerte); box-shadow: 0 0 0 1px var(--acento);
  }
  .segmentado input:focus-visible + label {
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--acento) 25%, transparent);
  }
  .ayuda { font-size: 12.5px; color: var(--texto-3); margin: 8px 0 0; }
  .enlace {
    background: none; border: none; padding: 0 0 0 6px; min-height: 0;
    font: inherit; font-weight: 600; color: var(--acento);
    text-decoration: underline; text-underline-offset: 2px; cursor: pointer;
  }

  /* ---------- Botones ---------- */
  button {
    font: inherit; font-weight: 600; cursor: pointer;
    border-radius: var(--radio-chico); border: 1.5px solid transparent;
    padding: 14px 20px; min-height: 50px;
    display: inline-flex; align-items: center; justify-content: center; gap: 9px;
    transition: transform .12s, filter .15s, background .15s;
  }
  button:active { transform: scale(.975); }
  button:disabled { opacity: .5; cursor: default; transform: none; }
  button svg { width: 19px; height: 19px; flex: none; }
  .btn-principal { background: var(--acento); color: #fff; width: 100%; }
  .btn-principal:hover:not(:disabled) { filter: brightness(1.08); }
  .btn-2 { background: var(--tarjeta-alt); color: var(--texto); border-color: var(--borde); }
  .btn-2:hover:not(:disabled) { background: var(--acento-suave); border-color: var(--acento-borde); }
  .btn-chico { padding: 9px 14px; min-height: 42px; font-size: 14px; }
  .acciones { display: flex; gap: 10px; flex-wrap: wrap; }
  .acciones .btn-principal { width: auto; flex: 1; min-width: 180px; }

  /* ---------- Foto ---------- */
  .foto-fila { display: flex; gap: 16px; align-items: center; }
  .foto-preview {
    width: 76px; height: 76px; border-radius: 50%; object-fit: cover; flex: none;
    background: var(--tarjeta-alt); border: 2px solid var(--borde);
    display: grid; place-items: center; color: var(--texto-3);
  }
  input[type=file] { font-size: 13px; color: var(--texto-2); width: 100%; }
  input[type=file]::file-selector-button {
    font: inherit; font-weight: 600; padding: 9px 14px; margin-right: 10px;
    border: 1.5px solid var(--borde); border-radius: 8px;
    background: var(--tarjeta-alt); color: var(--texto); cursor: pointer;
  }

  /* ---------- Ficha de la persona recien creada ---------- */
  #ficha { display: none; }
  #ficha.visible { display: block; animation: entrar .32s cubic-bezier(.16,1,.3,1); }
  @keyframes entrar { from { opacity: 0; transform: translateY(10px); } }
  .ficha-cab { display: flex; align-items: center; gap: 15px; margin-bottom: 18px; }
  .ficha-cab .foto-preview { width: 62px; height: 62px; }
  .ficha-datos { min-width: 0; flex: 1; }
  .ficha-datos strong { display: block; font-size: 19px; font-weight: 650; letter-spacing: -.02em; }
  .ficha-datos span { font-size: 14px; color: var(--texto-2); font-variant-numeric: tabular-nums; }
  .ficha-tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 7px; }
  .exito {
    display: flex; align-items: center; gap: 9px;
    background: var(--ok-fondo); color: var(--ok);
    padding: 11px 14px; border-radius: var(--radio-chico);
    font-size: 14px; font-weight: 600; margin-bottom: 16px;
  }
  .exito svg { width: 19px; height: 19px; flex: none; }

  /* ---------- Etiquetas ---------- */
  .tag {
    display: inline-flex; align-items: center; gap: 5px;
    font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 20px;
    background: var(--tarjeta-alt); color: var(--texto-2); border: 1px solid var(--borde);
  }
  .tag.ok    { background: var(--ok-fondo); color: var(--ok); border-color: var(--acento-borde); }
  .tag.mal   { background: var(--alerta-fondo); color: var(--alerta); border-color: transparent; }
  .tag.espera{ background: var(--espera-fondo); color: var(--espera); border-color: transparent; }
  .tag.gris  { color: var(--texto-3); border-style: dashed; }

  /* ---------- Camara ---------- */
  .foto-botones { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .camara { margin-top: 14px; }
  .camara video {
    width: 100%; max-width: 360px; border-radius: var(--radio-chico);
    background: #000; display: block; margin-bottom: 10px;
    transform: scaleX(-1);          /* espejo: es como uno se ve, cuesta menos encuadrar */
  }

  /* ---------- Lista de personas ---------- */
  .barra { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 16px; }
  .barra input { flex: 1; min-width: 180px; }
  .resumen {
    font-size: 13px; color: var(--texto-3); font-variant-numeric: tabular-nums;
    width: 100%; padding-top: 2px;
  }
  .personas { display: grid; gap: 10px; }
  .persona {
    display: grid; grid-template-columns: 48px 1fr; gap: 14px;
    padding: 14px; border: 1px solid var(--borde); border-radius: var(--radio);
    background: var(--tarjeta-alt);
    transition: border-color .15s, box-shadow .15s;
  }
  .persona:hover { border-color: var(--acento-borde); box-shadow: var(--sombra); }
  .persona .foto-preview { width: 48px; height: 48px; border-width: 1.5px; }
  .persona-datos { min-width: 0; }
  .persona-nombre { font-weight: 650; font-size: 16px; letter-spacing: -.01em; }
  .persona-dni { font-size: 13.5px; color: var(--texto-2); font-variant-numeric: tabular-nums; }
  .persona-tags { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 8px; }
  .persona-acciones { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
  .vacio { text-align: center; padding: 34px 16px; color: var(--texto-3); font-size: 14.5px; }

  /* ---------- Overlay de captura de huella ---------- */
  #captura {
    position: fixed; inset: 0; z-index: 50; display: none;
    background: color-mix(in srgb, var(--fondo) 82%, transparent);
    backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
    place-items: center; padding: 20px;
  }
  #captura.visible { display: grid; animation: aparecer .2s ease-out; }
  @keyframes aparecer { from { opacity: 0; } }
  .captura-caja {
    background: var(--tarjeta); border: 1px solid var(--borde);
    border-radius: 20px; box-shadow: var(--sombra-alta);
    padding: 32px 26px; max-width: 340px; width: 100%; text-align: center;
    animation: subir .3s cubic-bezier(.16,1,.3,1);
  }
  @keyframes subir { from { transform: translateY(16px) scale(.97); opacity: 0; } }
  .huella-icono { width: 108px; height: 108px; margin: 0 auto 20px; position: relative; }
  .huella-icono svg { width: 100%; height: 100%; color: var(--acento); }
  .huella-icono svg path, .huella-icono svg circle { transition: opacity .3s; }

  /* animacion: las lineas de la huella se dibujan una tras otra */
  .escaneando svg path {
    stroke-dasharray: 120;
    animation: dibujar 2.1s ease-in-out infinite;
  }
  .escaneando svg path:nth-child(1) { animation-delay: 0s; }
  .escaneando svg path:nth-child(2) { animation-delay: .13s; }
  .escaneando svg path:nth-child(3) { animation-delay: .26s; }
  .escaneando svg path:nth-child(4) { animation-delay: .39s; }
  .escaneando svg path:nth-child(5) { animation-delay: .52s; }
  .escaneando svg path:nth-child(6) { animation-delay: .65s; }
  @keyframes dibujar {
    0%   { stroke-dashoffset: 120; opacity: .18; }
    45%  { stroke-dashoffset: 0;   opacity: 1; }
    100% { stroke-dashoffset: 0;   opacity: .18; }
  }
  /* linea de escaneo que barre de arriba a abajo */
  .escaneando::after {
    content: ""; position: absolute; left: 6%; right: 6%; height: 2px;
    background: linear-gradient(90deg, transparent, var(--acento), transparent);
    border-radius: 2px; box-shadow: 0 0 12px var(--acento);
    animation: barrer 2.1s cubic-bezier(.5,0,.5,1) infinite;
  }
  @keyframes barrer { 0%,100% { top: 8%; } 50% { top: 88%; } }

  .huella-icono.logrado svg { color: var(--ok); animation: latir .5s cubic-bezier(.34,1.56,.64,1); }
  .huella-icono.fallo svg   { color: var(--alerta); animation: sacudir .4s; }
  @keyframes latir  { 0% { transform: scale(.82); } 60% { transform: scale(1.07); } 100% { transform: scale(1); } }
  @keyframes sacudir{ 0%,100% { transform: translateX(0); } 25% { transform: translateX(-7px); } 75% { transform: translateX(7px); } }

  .captura-titulo { font-size: 18px; font-weight: 650; margin: 0 0 7px; letter-spacing: -.02em; }
  .captura-texto { font-size: 14.5px; color: var(--texto-2); margin: 0 0 22px; min-height: 44px; }
  .captura-persona { font-size: 13px; color: var(--texto-3); margin: -3px 0 16px; font-variant-numeric: tabular-nums; }

  /* ---------- Avisos ---------- */
  #aviso {
    position: fixed; left: 50%; transform: translateX(-50%) translateY(-120%);
    top: max(14px, env(safe-area-inset-top)); z-index: 60;
    background: var(--texto); color: var(--fondo);
    padding: 13px 18px; border-radius: 12px; box-shadow: var(--sombra-alta);
    font-size: 14.5px; font-weight: 600; max-width: min(92vw, 460px);
    transition: transform .34s cubic-bezier(.16,1,.3,1);
  }
  #aviso.visible { transform: translateX(-50%) translateY(0); }
  #aviso.mal { background: var(--alerta); color: #fff; }
  #aviso.bien { background: var(--acento); color: #fff; }

  /* ---------- Confirmaciones ----------
     Reemplazan al confirm() del navegador, que mostraba "192.168.1.100 dice"
     arriba de todo y a la gente le parecia un mensaje raro o sospechoso. */
  #velo {
    position: fixed; inset: 0; z-index: 70;
    display: flex; align-items: center; justify-content: center;
    padding: 20px;
    background: rgba(8, 18, 15, .5);
    backdrop-filter: blur(4px); -webkit-backdrop-filter: blur(4px);
    opacity: 0; pointer-events: none;
    transition: opacity .2s ease;
  }
  #velo.visible { opacity: 1; pointer-events: auto; }

  #velo .cuadro {
    background: var(--tarjeta); color: var(--texto);
    border: 1px solid var(--borde); border-radius: var(--radio);
    box-shadow: var(--sombra-alta);
    width: min(100%, 430px); padding: 26px 26px 22px;
    transform: translateY(10px) scale(.97);
    transition: transform .24s cubic-bezier(.16,1,.3,1);
  }
  #velo.visible .cuadro { transform: none; }

  #velo .simbolo {
    width: 46px; height: 46px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    margin-bottom: 15px; font-size: 22px;
    background: var(--acento-suave); color: var(--acento);
  }
  #velo.peligro .simbolo { background: var(--alerta-fondo); color: var(--alerta); }

  #velo h3 {
    margin: 0 0 8px; font-size: 18.5px; font-weight: 700;
    letter-spacing: -.01em; line-height: 1.3;
  }
  #velo p {
    margin: 0 0 22px; font-size: 14.5px; line-height: 1.55;
    color: var(--texto-2);
  }
  #velo .botones { display: flex; gap: 10px; justify-content: flex-end; }
  #velo .botones button { min-width: 116px; }
  #velo .btn-peligro { background: var(--alerta); color: var(--peligro-texto); border-color: transparent; }
  #velo .btn-peligro:hover:not(:disabled) { filter: brightness(1.08); }

  @media (max-width: 480px) {
    #velo .botones { flex-direction: column-reverse; }
    #velo .botones button { width: 100%; }
  }
  @media (prefers-reduced-motion: reduce) {
    #velo, #velo .cuadro { transition: none; }
  }

  .oculto { display: none !important; }

  @media (prefers-reduced-motion: reduce) {
    *, *::after { animation: none !important; transition: none !important; }
  }
</style>
</head>
<body>

<!-- ============ LOGIN ============ -->
<div id="login">
  <div class="tarjeta">
    <div class="marca">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round">
        <path d="M12 2a9 9 0 0 0-9 9c0 3 1 5 1 7"/>
        <path d="M12 6a5 5 0 0 0-5 5c0 3 .5 4.5.5 7"/>
        <path d="M12 10a1.5 1.5 0 0 0-1.5 1.5c0 3 .3 5 .3 7"/>
        <path d="M12 6a5 5 0 0 1 5 5c0 3-.6 5-1 6.5"/>
        <path d="M21 11a9 9 0 0 0-4.5-7.8"/>
      </svg>
      <div>
        <h1>Personas</h1>
        <p>Lectores de acceso</p>
      </div>
    </div>
    <div id="loginError" class="exito oculto" style="background:var(--alerta-fondo);color:var(--alerta)"></div>
    <label for="clave">Clave de acceso</label>
    <input id="clave" type="password" autocomplete="current-password" inputmode="text">
    <div style="margin-top:18px"><button class="btn-principal" onclick="entrar()">Entrar</button></div>
  </div>
</div>

<!-- ============ APLICACION ============ -->
<div id="app" class="oculto">
  <header>
    <div class="header-fila">
      <h1>Personas</h1>
      <div class="equipos" id="equipos"></div>
    </div>
    <div class="segmentado" id="sedes" style="margin-top:12px;max-width:960px;margin-left:auto;margin-right:auto"></div>
  </header>

  <main>
    <!-- Ficha de la persona recien guardada -->
    <section id="ficha" class="tarjeta">
      <div class="exito">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
          <path d="M20 6 9 17l-5-5"/>
        </svg>
        <span id="fichaMensaje">Persona guardada</span>
      </div>
      <div class="ficha-cab">
        <img id="fichaFoto" class="foto-preview" alt="">
        <div class="ficha-datos">
          <strong id="fichaNombre"></strong>
          <span id="fichaDni"></span>
          <div class="ficha-tags" id="fichaTags"></div>
        </div>
      </div>
      <div class="acciones">
        <button class="btn-principal" id="fichaHuella">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
            <path d="M12 2a9 9 0 0 0-9 9c0 3 1 5 1 7"/>
            <path d="M12 6a5 5 0 0 0-5 5c0 3 .5 4.5.5 7"/>
            <path d="M12 10a1.5 1.5 0 0 0-1.5 1.5c0 3 .3 5 .3 7"/>
            <path d="M12 6a5 5 0 0 1 5 5c0 3-.6 5-1 6.5"/>
          </svg>
          Tomar huella ahora
        </button>
        <button class="btn-2" onclick="nuevaPersona()">Cargar otra persona</button>
      </div>
    </section>

    <!-- Alta -->
    <section id="alta" class="tarjeta">
      <h2 id="tituloForm">Nueva persona</h2>

      <div class="campos dos" id="filaIdentidad">
        <div id="bloqueDni">
          <label for="dni">DNI</label>
          <input id="dni" type="text" inputmode="numeric" pattern="[0-9]*" autocomplete="off"
                 maxlength="12" placeholder="Solo numeros, sin puntos" oninput="soloNumeros(this)">
        </div>
        <div>
          <label for="nombre">Nombre y apellido</label>
          <input id="nombre" type="text" autocomplete="off" placeholder="Como figura en el legajo">
        </div>
      </div>

      <div class="campos" id="bloqueTipo">
        <div>
          <label>Tipo de persona</label>
          <div class="segmentado" id="tipos"></div>
          <p class="ayuda" id="tipoDetalle">Define en qué lectores queda cargada.</p>
        </div>
      </div>

      <div class="campos" id="bloqueTurno">
        <div>
          <label>Turno</label>
          <div class="segmentado">
            <input type="radio" name="turno" id="turno-day" class="rbTurno" value="day" checked>
            <label for="turno-day">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round">
                <circle cx="12" cy="12" r="4.2"/>
                <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>
              </svg>
              Día
            </label>
            <input type="radio" name="turno" id="turno-night" class="rbTurno" value="night">
            <label for="turno-night">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/>
              </svg>
              Noche
            </label>
          </div>
          <p class="ayuda">Se guarda en el legajo de Odoo.</p>
        </div>
      </div>

      <p class="ayuda" id="vigenciaResumen" style="margin:-4px 0 14px">
        <span id="vigenciaTexto"></span>
        <button type="button" class="enlace" onclick="verVigencia()">cambiar</button>
      </p>
      <div class="campos dos oculto" id="bloqueVigencia">
        <div>
          <label for="desde">Vigente desde</label>
          <input id="desde" type="date" onchange="textoVigencia()">
        </div>
        <div>
          <label for="hasta">Vigente hasta</label>
          <input id="hasta" type="date" onchange="textoVigencia()">
        </div>
      </div>

      <div class="campos" id="bloqueFoto">
        <div>
          <label for="foto">Foto de rostro</label>
          <div class="foto-fila">
            <img id="preview" class="foto-preview" alt="">
            <div style="flex:1;min-width:0">
              <div class="foto-botones">
                <button type="button" class="btn-2 btn-chico oculto" id="btnCamara"
                        onclick="abrirCamara()">Sacar foto</button>
                <input id="foto" type="file" accept="image/*" capture="user" onchange="prepararFoto(event)">
              </div>
              <p class="ayuda" id="fotoInfo">De frente y con buena luz. Se achica sola.</p>
            </div>
          </div>
          <div id="camara" class="camara oculto">
            <video id="video" autoplay playsinline muted></video>
            <div class="foto-botones">
              <button type="button" class="btn-principal btn-chico" onclick="capturarFoto()">Capturar</button>
              <button type="button" class="btn-2 btn-chico" onclick="cerrarCamara()">Cancelar</button>
            </div>
          </div>
        </div>
      </div>

      <div class="acciones">
        <button class="btn-principal" onclick="guardar()" id="btnGuardar">Guardar</button>
        <button class="btn-2" onclick="limpiar()">Limpiar</button>
      </div>
    </section>

    <!-- Listado -->
    <section class="tarjeta">
      <div class="barra">
        <input id="buscar" type="search" placeholder="Buscar por nombre o DNI" oninput="cargar()">
        <button class="btn-2 btn-chico" onclick="importar()">Importar</button>
        <button class="btn-2 btn-chico" id="btnHuellas" onclick="respaldarHuellas()">Respaldar huellas</button>
        <button class="btn-2 btn-chico" onclick="reintentar()">Reintentar</button>
        <div class="resumen" id="resumen"></div>
      </div>
      <div class="personas" id="lista"></div>
    </section>
  </main>
</div>

<!-- ============ CAPTURA DE HUELLA ============ -->
<div id="captura">
  <div class="captura-caja">
    <div class="huella-icono" id="huellaIcono">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
        <path d="M12 2a9 9 0 0 0-9 9c0 3 1 5 1 7"/>
        <path d="M12 6a5 5 0 0 0-5 5c0 3 .5 4.5.5 7"/>
        <path d="M12 10a1.5 1.5 0 0 0-1.5 1.5c0 3 .3 5 .3 7"/>
        <path d="M12 6a5 5 0 0 1 5 5c0 3-.6 5-1 6.5"/>
        <path d="M21 11a9 9 0 0 0-4.5-7.8"/>
        <path d="M7.5 3.2A9 9 0 0 0 3.4 8"/>
      </svg>
    </div>
    <p class="captura-titulo" id="capturaTitulo">Apoyá el dedo</p>
    <p class="captura-persona" id="capturaPersona"></p>
    <p class="captura-texto" id="capturaTexto">Preparando el lector…</p>
    <button class="btn-2" id="capturaCerrar" onclick="cerrarCaptura()">Cancelar</button>
  </div>
</div>

<div id="aviso"></div>

<div id="velo" role="dialog" aria-modal="true" aria-labelledby="velo-titulo">
  <div class="cuadro">
    <div class="simbolo" id="velo-simbolo" aria-hidden="true">?</div>
    <h3 id="velo-titulo"></h3>
    <p id="velo-texto"></p>
    <div class="botones">
      <button type="button" class="btn btn-2" id="velo-no">Cancelar</button>
      <button type="button" class="btn btn-principal" id="velo-si">Aceptar</button>
    </div>
  </div>
</div>

<script>
// El monitoreo embebe este panel (iframe) sin volver a pedir la clave: entra
// por su cuenta y pasa un token ya valido por la URL (?panelToken=...). Se
// guarda y se limpia de la barra para no dejarlo a la vista. Sin ese parametro,
// el panel funciona como siempre (pide la clave).
let TOKEN = (function () {
  try {
    var t = new URLSearchParams(location.search).get("panelToken");
    if (t) {
      sessionStorage.setItem("panelToken", t);
      history.replaceState(null, "", location.pathname);
      return t;
    }
  } catch (e) {}
  return sessionStorage.getItem("panelToken") || "";
})();
let FOTO = null;
let GRUPOS = {};
let SEDES = {};
let SEDE = sessionStorage.getItem("sede") || "";
let TIMERS = [];
let CAPTURA_ACTIVA = null;
let DNI_EDITANDO = null;

/* ---------- infraestructura ---------- */
function api(ruta, opciones) {
  opciones = opciones || {};
  opciones.headers = Object.assign({"Content-Type": "application/json", "X-Panel-Token": TOKEN},
                                   opciones.headers || {});
  return fetch(ruta, opciones).then(function (r) {
    if (r.status === 401) { salir(); throw new Error("La sesión venció, entrá de nuevo"); }
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
function avisar(texto, mal) {
  var d = document.getElementById("aviso");
  d.textContent = texto;
  d.className = "visible " + (mal ? "mal" : "bien");
  clearTimeout(avisoTimer);
  avisoTimer = setTimeout(function () { d.className = ""; }, 4500);
}

/* ---------- Confirmaciones ----------
   Devuelve una promesa con true o false. Reemplaza al confirm() del navegador,
   que anunciaba "192.168.1.100 dice" y a la gente le resultaba sospechoso.
   Enter NO se intercepta a proposito: lo maneja el boton que tenga el foco, y
   en lo destructivo el foco arranca en Cancelar. */
function preguntar(op) {
  var velo = document.getElementById("velo");
  var si = document.getElementById("velo-si");
  var no = document.getElementById("velo-no");
  var previo = document.activeElement;

  document.getElementById("velo-titulo").textContent = op.titulo;
  document.getElementById("velo-texto").textContent = op.texto;
  document.getElementById("velo-simbolo").textContent = op.peligro ? "!" : "?";
  si.textContent = op.ok || "Aceptar";
  no.textContent = op.cancelar || "Cancelar";
  si.className = "btn " + (op.peligro ? "btn-peligro" : "btn-principal");
  velo.className = "visible" + (op.peligro ? " peligro" : "");

  return new Promise(function (resolver) {
    function cerrar(respuesta) {
      velo.className = "";
      si.onclick = null;
      no.onclick = null;
      velo.onmousedown = null;
      document.removeEventListener("keydown", teclas, true);
      if (previo && previo.focus) { try { previo.focus(); } catch (e) {} }
      resolver(respuesta);
    }
    function teclas(ev) {
      if (ev.key === "Escape") { ev.preventDefault(); cerrar(false); return; }
      // el foco no tiene que poder irse a la pagina de atras
      if (ev.key === "Tab") {
        ev.preventDefault();
        (document.activeElement === si ? no : si).focus();
      }
    }
    si.onclick = function () { cerrar(true); };
    no.onclick = function () { cerrar(false); };
    velo.onmousedown = function (ev) { if (ev.target === velo) cerrar(false); };
    document.addEventListener("keydown", teclas, true);
    setTimeout(function () { (op.peligro ? no : si).focus(); }, 40);
  });
}

/* ---------- sesión ---------- */
function entrar() {
  var clave = document.getElementById("clave").value;
  fetch("/api/login", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({password: clave})
  })
    .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error); return j; }); })
    .then(function (j) {
      TOKEN = j.token;
      sessionStorage.setItem("panelToken", TOKEN);
      mostrarApp();
    })
    .catch(function (e) {
      var d = document.getElementById("loginError");
      d.textContent = e.message;
      d.classList.remove("oculto");
    });
}

function salir() {
  TOKEN = "";
  sessionStorage.removeItem("panelToken");
  TIMERS.forEach(clearInterval);
  TIMERS = [];
  document.getElementById("app").classList.add("oculto");
  document.getElementById("login").classList.remove("oculto");
}

function mostrarApp() {
  document.getElementById("login").classList.add("oculto");
  document.getElementById("app").classList.remove("oculto");
  // Primero las sedes: si se pide el listado antes de saber en cual estamos,
  // la primera vista muestra las dos mezcladas.
  vigenciaPorDefecto();
  cargarEquipos().then(cargar).catch(cargar);
  TIMERS.forEach(clearInterval);
  TIMERS = [setInterval(cargarEquipos, 10000), setInterval(cargar, 20000)];
}

/* ---------- equipos y tipos ---------- */
function cargarEquipos() {
  return api("/api/equipos").then(function (j) {
    document.getElementById("equipos").innerHTML = j.equipos.map(function (e) {
      return '<span class="chip ' + (e.conectado ? "on" : "off") + '">.' +
             escapar(e.ip.split(".").pop()) + "</span>";
    }).join("");

    SEDES = j.sedes || {};
    if (!SEDE || !SEDES[SEDE]) SEDE = j.sede_por_defecto || Object.keys(SEDES)[0] || "";
    pintarSedes();
    GRUPOS = j.grupos || {};
    var cont = document.getElementById("tipos");
    if (!cont.children.length) {
      cont.innerHTML = Object.keys(GRUPOS).map(function (t, i) {
        var icono = t === "eventual"
          ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>'
          : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21V9l9-6 9 6v12"/><path d="M9 21v-7h6v7"/></svg>';
        return '<input type="radio" name="tipo" class="rbTipo" id="tipo-' + escapar(t) + '" value="' + escapar(t) + '" onchange="mostrarTipo()">' +
               '<label for="tipo-' + escapar(t) + '">' + icono + escapar(GRUPOS[t].nombre) + "</label>";
      }).join("");
    }

    var r = j.resumen;
    document.getElementById("resumen").textContent =
      r.personas + " personas · " + r.pendientes + " pendientes · " + r.errores + " con error";
  }).catch(function () {});
}

function pintarSedes() {
  var cont = document.getElementById("sedes");
  var claves = Object.keys(SEDES);
  if (claves.length < 2) { cont.style.display = "none"; return; }
  if (!cont.children.length) {
    cont.innerHTML = claves.map(function (k) {
      var s = SEDES[k];
      var icono = s.tecnologia === "zkteco"
        ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="12" cy="11" r="2.6"/><path d="M7.5 17a5 5 0 0 1 9 0"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21V8l9-5 9 5v13"/><path d="M9 21v-6h6v6"/></svg>';
      return '<input type="radio" name="sede" class="rbSede" id="sede-' + escapar(k) + '" value="' + escapar(k) + '"' +
             (k === SEDE ? " checked" : "") + (s.disponible ? "" : " disabled") + ' onchange="cambiarSede()">' +
             '<label for="sede-' + escapar(k) + '"' + (s.disponible ? "" : ' style="opacity:.45"') + ">" +
             icono + escapar(s.nombre) + "</label>";
    }).join("");
  }
  aplicarCapacidades();
}

function cambiarSede() {
  var r = document.querySelector(".rbSede:checked");
  SEDE = r ? r.value : SEDE;
  sessionStorage.setItem("sede", SEDE);
  aplicarCapacidades();
  limpiar();
  document.getElementById("ficha").classList.remove("visible");
  document.getElementById("alta").classList.remove("oculto");
  cargar();
}

function capacidadesSede() {
  return (SEDES[SEDE] && SEDES[SEDE].capacidades) || {};
}

function aplicarCapacidades() {
  var c = capacidadesSede();
  var bt = document.getElementById("bloqueTipo"), bf = document.getElementById("bloqueFoto");
  if (bt) bt.classList.toggle("oculto", !c.tipos);
  if (bf) bf.classList.toggle("oculto", !c.foto);
  // La camara solo existe si el panel se abrio por https. Cuando no, en vez
  // de un boton muerto se explica por que no esta.
  var bc = document.getElementById("btnCamara");
  if (bc) bc.classList.toggle("oculto", !(c.foto && hayCamara()));
  var info = document.getElementById("fotoInfo");
  var prev = document.getElementById("preview");
  if (info && !FOTO && !(prev && prev.getAttribute("src"))) info.textContent = textoAyudaFoto();
  var bh = document.getElementById("btnHuellas");
  if (bh) bh.classList.toggle("oculto", !c.huella);
  // Lavalle no tiene turno noche: se oculta el selector y queda en dia
  var btu = document.getElementById("bloqueTurno");
  if (btu) btu.classList.toggle("oculto", c.turnos === false);
  if (c.turnos === false) document.getElementById("turno-day").checked = true;
  // Donde el ID lo asigna el lector, no se pide ni se edita
  var bd = document.getElementById("bloqueDni");
  if (bd) bd.classList.toggle("oculto", c.dni === false);
  var fi = document.getElementById("filaIdentidad");
  if (fi) fi.classList.toggle("dos", c.dni !== false);
  if (c.dni === false) document.getElementById("dni").value = "";
  var s = SEDES[SEDE] || {};
  var ayuda = document.getElementById("tipoDetalle");
  if (ayuda && !c.tipos) {
    ayuda.textContent = "En " + (s.nombre || "esta sede") + " la persona va a " +
      (s.lectores || []).join(", ");
  }
}

function soloNumeros(campo) {
  var limpio = campo.value.replace(/[^0-9]/g, "");
  if (campo.value !== limpio) campo.value = limpio;
}

function fechaISO(d) {
  return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") +
         "-" + String(d.getDate()).padStart(2, "0");
}

function vigenciaPorDefecto() {
  var hoy = new Date();
  var hasta = new Date(hoy.getFullYear() + 10, hoy.getMonth(), hoy.getDate());
  document.getElementById("desde").value = fechaISO(hoy);
  document.getElementById("hasta").value = fechaISO(hasta);
  document.getElementById("bloqueVigencia").classList.add("oculto");
  textoVigencia();
}

function textoVigencia() {
  var d = document.getElementById("desde").value, h = document.getElementById("hasta").value;
  document.getElementById("vigenciaTexto").textContent =
    d && h ? "Vigencia " + d + " a " + h : "Sin vigencia definida";
}

function verVigencia() {
  document.getElementById("bloqueVigencia").classList.remove("oculto");
}

function tipoElegido() {
  var r = document.querySelector(".rbTipo:checked");
  return r ? r.value : "";
}

function turnoElegido() {
  var r = document.querySelector(".rbTurno:checked");
  return r ? r.value : "day";
}

function mostrarTipo() {
  var t = tipoElegido(), d = document.getElementById("tipoDetalle");
  d.textContent = (t && GRUPOS[t])
    ? "Va a los lectores " + GRUPOS[t].lectores.map(function (i) { return "." + i.split(".").pop(); }).join(", ")
    : "Define en qué lectores queda cargada.";
}

/* ---------- foto ---------- */
/* Achica la imagen y la deja lista para mandar. La usan tanto el archivo
   como la foto sacada con la camara, asi que el limite de tamano y la
   calidad se tocan en un solo lugar. */
function usarImagen(fuente, anchoFuente, altoFuente) {
  var max = 800, ancho = anchoFuente, alto = altoFuente;
  if (ancho > max || alto > max) {
    var f = Math.min(max / ancho, max / alto);
    ancho = Math.round(ancho * f);
    alto = Math.round(alto * f);
  }
  var lienzo = document.createElement("canvas");
  lienzo.width = ancho; lienzo.height = alto;
  lienzo.getContext("2d").drawImage(fuente, 0, 0, ancho, alto);
  var calidad = 0.9, datos;
  do {
    datos = lienzo.toDataURL("image/jpeg", calidad);
    calidad -= 0.1;
  } while (datos.length * 0.75 > 95 * 1024 && calidad > 0.25);
  FOTO = datos;
  document.getElementById("preview").src = datos;
  document.getElementById("fotoInfo").textContent =
    ancho + "×" + alto + " · " + Math.round(datos.length * 0.75 / 1024) + " KB";
}

function prepararFoto(ev) {
  var archivo = ev.target.files[0];
  if (!archivo) return;
  var lector = new FileReader();
  lector.onload = function (e) {
    var img = new Image();
    img.onload = function () { usarImagen(img, img.width, img.height); };
    img.src = e.target.result;
  };
  lector.readAsDataURL(archivo);
}

/* ---------- camara ----------
   El navegador solo entrega la camara en un sitio seguro. Si el panel se
   abre por http el boton ni se muestra, con una explicacion, para que nadie
   apriete algo que no puede funcionar. */
let CAMARA = null;

function hayCamara() {
  return !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
}

function abrirCamara() {
  if (!hayCamara()) { avisar("Este navegador no da acceso a la camara", true); return; }
  navigator.mediaDevices.getUserMedia({
    video: {facingMode: "user", width: {ideal: 1280}, height: {ideal: 720}},
    audio: false
  }).then(function (flujo) {
    CAMARA = flujo;
    var v = document.getElementById("video");
    v.srcObject = flujo;
    document.getElementById("camara").classList.remove("oculto");
    document.getElementById("btnCamara").classList.add("oculto");
  }).catch(function (e) {
    var motivo = (e && e.name === "NotAllowedError")
      ? "Hay que permitir la camara en el navegador"
      : (e && e.name === "NotFoundError") ? "No se encontro ninguna camara" : e.message;
    avisar("No se pudo abrir la camara: " + motivo, true);
  });
}

function capturarFoto() {
  var v = document.getElementById("video");
  if (!v.videoWidth) { avisar("La camara todavia no esta lista", true); return; }
  usarImagen(v, v.videoWidth, v.videoHeight);
  cerrarCamara();
}

function cerrarCamara() {
  if (CAMARA) {
    CAMARA.getTracks().forEach(function (t) { t.stop(); });
    CAMARA = null;
  }
  var v = document.getElementById("video");
  if (v) v.srcObject = null;
  document.getElementById("camara").classList.add("oculto");
  if (hayCamara()) document.getElementById("btnCamara").classList.remove("oculto");
}

var AYUDA_FOTO = "De frente y con buena luz. Se achica sola.";

function textoAyudaFoto() {
  if (capacidadesSede().foto && !hayCamara()) {
    return AYUDA_FOTO + " Para sacar la foto desde acá hay que entrar por https://"
           + location.host + "/";
  }
  return AYUDA_FOTO;
}

// Las fotos NO se pueden pedir como <img src="/api/foto/...">: ese pedido lo
// hace el navegador sin el header X-Panel-Token y el panel contesta 401, asi
// que se veian todas rotas. Se traen con fetch y se muestran como blob.
function ponerFoto(img, sede, dni) {
  if (!img) return;
  fetch("/api/foto/" + encodeURIComponent(sede) + "/" + encodeURIComponent(dni),
        {headers: {"X-Panel-Token": TOKEN}})
    .then(function (r) { return r.ok ? r.blob() : null; })
    .then(function (b) {
      if (!b) { img.removeAttribute("src"); return; }
      var url = URL.createObjectURL(b);
      img.onload = function () { URL.revokeObjectURL(url); };
      img.src = url;
    })
    .catch(function () { img.removeAttribute("src"); });
}

// Deja el bloque de la foto como recien abierto. Antes esto estaba suelto
// adentro de limpiar(), y editar() solo hacia FOTO = null: la miniatura y el
// input con el archivo quedaban con lo del empleado anterior, asi que al
// editar a un segundo empleado se veia la foto del primero.
function limpiarFoto(texto) {
  FOTO = null;
  document.getElementById("foto").value = "";
  document.getElementById("preview").removeAttribute("src");
  document.getElementById("fotoInfo").textContent = texto || textoAyudaFoto();
  cerrarCamara();
}

/* ---------- alta ---------- */
function guardar() {
  var cuerpo = {
    dni: capacidadesSede().dni === false ? (DNI_EDITANDO || "")
                                        : document.getElementById("dni").value,
    nombre: document.getElementById("nombre").value,
    desde: document.getElementById("desde").value,
    hasta: document.getElementById("hasta").value,
    foto_base64: FOTO,
    tipo: tipoElegido(),
    turno: turnoElegido(),
    sede: SEDE,
    // Sin esto el backend no puede distinguir un alta con DNI repetido
    // de la edicion de esa misma persona.
    editando: DNI_EDITANDO || ""
  };
  var btn = document.getElementById("btnGuardar");
  btn.disabled = true;
  btn.textContent = "Guardando…";
  api("/api/personas", {method: "POST", body: JSON.stringify(cuerpo)})
    .then(function (j) {
      if (j.aviso) avisar("Cargada en los lectores, pero Odoo falló: " + j.aviso, true);
      else if (j.foto) avisar(j.foto);
      else if (j.persona && !capacidadesSede().dni) avisar("Guardada con el ID " + j.persona.dni);
      mostrarFicha(j.persona, j.odoo);
      cargar();
    })
    .catch(function (e) { avisar(e.message, true); })
    .then(function () { btn.disabled = false; btn.textContent = "Guardar"; });
}

function mostrarFicha(p, msgOdoo) {
  if (!p) { limpiar(); return; }
  document.getElementById("alta").classList.add("oculto");
  document.getElementById("fichaMensaje").textContent =
    "Guardada" + (msgOdoo ? " y " + msgOdoo : "");
  document.getElementById("fichaNombre").textContent = p.nombre;
  document.getElementById("fichaDni").textContent =
    (capacidadesSede().dni === false ? "ID en el lector " : "DNI ") + p.dni;
  var foto = document.getElementById("fichaFoto");
  foto.removeAttribute("src");
  if (p.tiene_foto) ponerFoto(foto, SEDE, p.dni);
  document.getElementById("fichaTags").innerHTML =
    tagTipo(p) + tagTurno(p) + tagHuella(p) + tagsLectores(p);
  var bfh = document.getElementById("fichaHuella");
  bfh.classList.toggle("oculto", !capacidadesSede().huella);
  bfh.onclick = function () { tomarHuella(p.dni, p.nombre); };
  document.getElementById("ficha").classList.add("visible");
  window.scrollTo({top: 0, behavior: "smooth"});
}

function nuevaPersona() {
  document.getElementById("ficha").classList.remove("visible");
  document.getElementById("alta").classList.remove("oculto");
  limpiar();
  document.getElementById("dni").focus();
}

function limpiar() {
  ["dni", "nombre", "desde", "hasta"].forEach(function (id) { document.getElementById(id).value = ""; });
  limpiarFoto();
  document.getElementById("tituloForm").textContent = "Nueva persona";
  document.querySelectorAll(".rbTipo").forEach(function (c) { c.checked = false; });
  DNI_EDITANDO = null;
  document.getElementById("turno-day").checked = true;
  vigenciaPorDefecto();
  mostrarTipo();
}

/* ---------- listado ---------- */
function tagTipo(p) {
  // En Lavalle no hay tipos: no tiene sentido marcar "sin tipo"
  if (!capacidadesSede().tipos) return "";
  if (!p.tipo) return '<span class="tag mal">sin tipo</span>';
  var nombre = (GRUPOS[p.tipo] && GRUPOS[p.tipo].nombre) || p.tipo;
  return '<span class="tag">' + escapar(nombre) + "</span>";
}
function tagTurno(p) {
  if (!p.turno) return "";
  return '<span class="tag">' + (p.turno === "night" ? "Turno noche" : "Turno día") + "</span>";
}
function tagHuella(p) {
  // Solo donde la huella sigue en uso. En Deposito se apago: ahora todos
  // fichan con rostro y la huella dejo de pedirse.
  if (!capacidadesSede().huella) return "";
  var n = p.huella_cantidad || 0;
  if (n > 0) return '<span class="tag ok">' + n + (n === 1 ? " huella" : " huellas") + "</span>";
  return '<span class="tag gris">sin huella</span>';
}

function tagFoto(p) {
  // Sin rostro cargado la persona no puede fichar, asi que conviene que se
  // vea en la lista y no haya que abrir la ficha para darse cuenta.
  if (!capacidadesSede().foto) return "";
  if (!p.tiene_foto) return '<span class="tag mal">sin foto</span>';
  return p.foto_en_lector ? '<span class="tag ok">con foto</span>'
                          : '<span class="tag espera">foto sin subir</span>';
}
function tagsLectores(p) {
  var s = p.sync || {};
  return Object.keys(s).sort().map(function (ip) {
    var e = s[ip].estado;
    if (e === "ausente") return "";
    var clase = e === "ok" ? "ok" : (e === "error" ? "mal" : "espera");
    return '<span class="tag ' + clase + '" title="' + escapar(ip + ": " + (s[ip].error || e)) + '">.' +
           escapar(ip.split(".").pop()) + "</span>";
  }).join("");
}

function cargar() {
  var q = document.getElementById("buscar").value;
  api("/api/personas?sede=" + encodeURIComponent(SEDE) + "&q=" + encodeURIComponent(q)).then(function (j) {
    var html = j.personas.map(function (p) {
      var foto = p.tiene_foto
        ? '<img class="foto-preview" data-foto="' + escapar(p.dni) + '" alt="">'
        : '<span class="foto-preview"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="8" r="3.6"/><path d="M5 20a7 7 0 0 1 14 0"/></svg></span>';
      return '<article class="persona">' + foto +
        '<div class="persona-datos">' +
          '<div class="persona-nombre">' + escapar(p.nombre) +
            (p.activo ? "" : ' <span class="tag mal">baja</span>') + "</div>" +
          '<div class="persona-dni">' + (capacidadesSede().dni === false ? "ID " : "DNI ") +
            escapar(p.dni) + "</div>" +
          '<div class="persona-tags">' + tagTipo(p) + tagTurno(p) + tagFoto(p) + tagHuella(p) + tagsLectores(p) + "</div>" +
          '<div class="persona-acciones">' +
            (capacidadesSede().huella
               ? '<button class="btn-2 btn-chico" data-accion="huella" data-dni="' + escapar(p.dni) + '" data-nombre="' + escapar(p.nombre) + '">Tomar huella</button>'
               : "") +
            '<button class="btn-2 btn-chico" data-accion="editar" data-dni="' + escapar(p.dni) + '">Editar</button>' +
            '<button class="btn-2 btn-chico" data-accion="baja" data-dni="' + escapar(p.dni) + '" data-nombre="' + escapar(p.nombre) + '">Baja</button>' +
          "</div>" +
        "</div></article>";
    }).join("");
    document.getElementById("lista").innerHTML = html ||
      '<div class="vacio">No hay personas todavía.<br>Probá el botón <strong>Importar</strong> para traer las que ya están en los lectores.</div>';
    document.querySelectorAll("#lista img[data-foto]").forEach(function (img) {
      ponerFoto(img, SEDE, img.getAttribute("data-foto"));
    });
  }).catch(function () {});
}

function editar(dni) {
  api("/api/personas?q=" + encodeURIComponent(dni)).then(function (j) {
    var p = j.personas.filter(function (x) { return x.dni === dni; })[0];
    if (!p) return;
    document.getElementById("ficha").classList.remove("visible");
    document.getElementById("alta").classList.remove("oculto");
    document.getElementById("dni").value = p.dni;
    document.getElementById("nombre").value = p.nombre;
    DNI_EDITANDO = p.dni;
    vigenciaPorDefecto();
    if (p.vigencia_desde) document.getElementById("desde").value = p.vigencia_desde;
    if (p.vigencia_hasta) document.getElementById("hasta").value = p.vigencia_hasta;
    textoVigencia();
    document.getElementById("tituloForm").textContent = "Editando a " + p.nombre;
    document.querySelectorAll(".rbTipo").forEach(function (c) { c.checked = (c.value === p.tipo); });
    document.getElementById("turno-night").checked = (p.turno === "night");
    document.getElementById("turno-day").checked = (p.turno !== "night");
    mostrarTipo();
    // Se muestra la foto de ESTA persona, no la que hubiera quedado antes.
    // FOTO sigue en null a proposito: si no se elige una nueva, no se reenvia
    // nada al lector y la que ya tiene queda como esta.
    limpiarFoto();
    if (p.tiene_foto) {
      ponerFoto(document.getElementById("preview"), SEDE, p.dni);
      document.getElementById("fotoInfo").textContent =
        "Ya tiene foto cargada. Si elegís otra, la reemplaza.";
    }
    window.scrollTo({top: 0, behavior: "smooth"});
  });
}

function baja(dni, nombre) {
  var quien = nombre ? nombre : "esta persona";
  var donde = (SEDES[SEDE] || {}).nombre || "la sede";
  preguntar({
    titulo: "Dar de baja a " + quien,
    texto: "Se la quita de los lectores de " + donde + " y deja de poder entrar. "
         + "Sus marcas anteriores no se borran. Si vuelve, hay que darla de alta otra vez.",
    ok: "Dar de baja",
    peligro: true
  }).then(function (si) {
    if (!si) return;
    api("/api/baja", {method: "POST", body: JSON.stringify({dni: dni, sede: SEDE})})
      .then(function () { avisar("Baja pedida, se está aplicando"); cargar(); })
      .catch(function (e) { avisar(e.message, true); });
  });
}

function importar() {
  var s = (SEDES[SEDE] || {}).nombre || "esta sede";
  preguntar({
    titulo: "Traer la gente de " + s,
    texto: "Lee los lectores de " + s + " y suma al listado a quienes ya estén cargados ahí. "
         + "No da de alta ni de baja a nadie en los lectores.",
    ok: "Traer"
  }).then(function (si) {
    if (!si) return;
    api("/api/importar", {method: "POST", body: JSON.stringify({sede: SEDE})})
      .then(function (j) { avisar(j.detalle); setTimeout(cargar, 4000); })
      .catch(function (e) { avisar(e.message, true); });
  });
}

function respaldarHuellas() {
  preguntar({
    titulo: "Respaldar las huellas",
    texto: "Lee las huellas guardadas en los lectores y las copia acá, para poder recuperarlas "
         + "si algún equipo se borra o se cambia. No modifica nada en los lectores.",
    ok: "Respaldar"
  }).then(function (si) {
    if (!si) return;
    api("/api/respaldar_huellas", {method: "POST", body: "{}"})
      .then(function (j) { avisar(j.detalle); setTimeout(cargar, 6000); })
      .catch(function (e) { avisar(e.message, true); });
  });
}

function reintentar() {
  api("/api/reintentar", {method: "POST", body: "{}"})
    .then(function () { avisar("Reintentando los que fallaron"); cargar(); })
    .catch(function (e) { avisar(e.message, true); });
}

/* ---------- captura de huella ---------- */
function tomarHuella(dni, nombre) {
  CAPTURA_ACTIVA = dni;
  abrirCaptura(nombre || "", dni);
  api("/api/tomar_huella", {method: "POST", body: JSON.stringify({dni: dni})})
    .then(function () { seguirCaptura(dni); })
    .catch(function (e) { capturaFallo(e.message); });
}

function abrirCaptura(nombre, dni) {
  document.getElementById("capturaPersona").textContent = nombre ? nombre + " · DNI " + dni : "DNI " + dni;
  document.getElementById("capturaTitulo").textContent = "Preparando el lector";
  document.getElementById("capturaTexto").textContent = "Esperá unos segundos…";
  var icono = document.getElementById("huellaIcono");
  icono.className = "huella-icono escaneando";
  document.getElementById("capturaCerrar").textContent = "Cancelar";
  document.getElementById("captura").classList.add("visible");
}

function capturaLogro(msg) {
  document.getElementById("huellaIcono").className = "huella-icono logrado";
  document.getElementById("capturaTitulo").textContent = "¡Huella tomada!";
  document.getElementById("capturaTexto").textContent = msg || "Ya quedó guardada.";
  document.getElementById("capturaCerrar").textContent = "Listo";
  cargar();
}

function capturaFallo(msg) {
  document.getElementById("huellaIcono").className = "huella-icono fallo";
  document.getElementById("capturaTitulo").textContent = "No se pudo";
  document.getElementById("capturaTexto").textContent = msg || "Intentá de nuevo.";
  document.getElementById("capturaCerrar").textContent = "Cerrar";
}

function cerrarCaptura() {
  CAPTURA_ACTIVA = null;
  document.getElementById("captura").classList.remove("visible");
  document.getElementById("huellaIcono").className = "huella-icono";
}

function seguirCaptura(dni) {
  var hasta = Date.now() + 95000;
  (function mirar() {
    if (CAPTURA_ACTIVA !== dni) return;
    api("/api/estado_captura", {method: "POST", body: JSON.stringify({dni: dni})})
      .then(function (j) {
        if (CAPTURA_ACTIVA !== dni) return;
        var e = j.estado || {};
        if (e.estado === "ok") { capturaLogro(e.mensaje); return; }
        if (e.estado === "error") { capturaFallo(e.mensaje); return; }
        if (e.estado === "esperando") {
          document.getElementById("capturaTitulo").textContent = "Apoyá el dedo";
          document.getElementById("capturaTexto").textContent =
            e.mensaje || "Poné el dedo en el lector, puede pedirte que lo repitas.";
        }
        if (Date.now() < hasta) setTimeout(mirar, 1500);
        else capturaFallo("Se agotó el tiempo de espera");
      })
      .catch(function (e) { capturaFallo(e.message); });
  })();
}

/* ---------- eventos ---------- */
document.getElementById("lista").addEventListener("click", function (ev) {
  var b = ev.target.closest("button[data-accion]");
  if (!b) return;
  var a = b.dataset.accion;
  if (a === "editar") editar(b.dataset.dni);
  else if (a === "baja") baja(b.dataset.dni, b.dataset.nombre);
  else if (a === "huella") tomarHuella(b.dataset.dni, b.dataset.nombre);
});

document.getElementById("clave").addEventListener("keydown", function (e) {
  if (e.key === "Enter") entrar();
});

if (TOKEN) {
  fetch("/api/equipos", {headers: {"X-Panel-Token": TOKEN}})
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
class ServidorExclusivo(ThreadingHTTPServer):
    """Servidor que falla si el puerto ya tiene dueno.

    ThreadingHTTPServer trae allow_reuse_address = 1, y en Windows eso NO
    significa lo mismo que en Linux: ahi permite bindear un puerto que YA esta
    en uso en vez de dar error. Quedan dos procesos escuchando lo mismo y las
    conexiones caen en cualquiera de los dos, asi que el sitio "esta arriba"
    pero corta la mitad de las conexiones sin responder.

    Apagandolo, si el puerto esta ocupado el bind falla, lo vemos en el log y
    podemos seguir en http en vez de quedar a medias.
    """

    allow_reuse_address = False


class RedirectorHTTPS(BaseHTTPRequestHandler):
    """Manda a https cualquier cosa que llegue por http.

    Se deja el puerto 80 escuchando para que quien escriba la direccion sin
    protocolo -que es lo que hace todo el mundo- termine igual en el panel.
    """

    protocol_version = "HTTP/1.1"

    def _redirigir(self):
        host = (self.headers.get("Host") or PANEL["host"]).split(":")[0]
        puerto = int(PANEL["https"]["port"])
        destino = f"https://{host}" + ("" if puerto == 443 else f":{puerto}") + self.path
        self.send_response(301)
        self.send_header("Location", destino)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = do_HEAD = _redirigir

    def log_message(self, *a):
        pass


def armar_servidores():
    """Levanta el panel y, si hay certificado, lo deja en https.

    El https no es un lujo: el navegador solo habilita la camara en un sitio
    seguro, asi que sin esto la foto de rostro no se puede sacar desde el
    panel. De paso, la clave y el token de sesion dejan de viajar en claro.

    Si falta el certificado se sigue en http, avisando: es preferible un panel
    andando sin camara que un panel que no arranca.
    """
    cfg = PANEL.get("https") or {}
    cert = os.path.join(BASE_DIR, cfg.get("cert", ""))
    clave = os.path.join(BASE_DIR, cfg.get("key", ""))
    usar_https = bool(cfg.get("enabled")) and os.path.exists(cert) and os.path.exists(clave)

    if bool(cfg.get("enabled")) and not usar_https:
        logging.warning(f"https pedido pero falta el certificado ({cert}). "
                        f"Se sigue en http y la camara del panel no va a funcionar.")

    if not usar_https:
        srv = ThreadingHTTPServer((PANEL["host"], int(PANEL["port"])), Handler)
        srv.daemon_threads = True
        logging.info(f"Panel en http://{PANEL['host']}:{PANEL['port']}/  (Ctrl+C para salir)")
        return srv, None

    puerto = int(cfg.get("port", 443))
    try:
        # Un reinicio rapido puede encontrar el puerto todavia cerrandose, asi
        # que se reintenta un par de veces antes de dar por ocupado.
        ultimo = None
        srv = None
        for intento in range(3):
            try:
                srv = ServidorExclusivo((PANEL["host"], puerto), Handler)
                break
            except OSError as exc:
                ultimo = exc
                if intento < 2:
                    time.sleep(2)
        if srv is None:
            raise ultimo
        srv.daemon_threads = True
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        contexto.load_cert_chain(cert, clave)
        srv.socket = contexto.wrap_socket(srv.socket, server_side=True)
    except Exception as exc:
        # Que el puerto este ocupado o el certificado mal no puede dejar sin
        # panel a RRHH. Se avisa fuerte y se sigue en http: se pierde la camara,
        # no el panel. Antes esto tiraba la excepcion, la tarea reiniciaba el
        # proceso y quedaba en un loop de arranques sin servidor web.
        logging.error(f"No se pudo levantar https en el puerto {puerto}: {exc}")
        logging.error("Se sigue en http. La camara del panel NO va a funcionar. "
                      "Ver que ocupa el puerto con:  netstat -ano | findstr :%d" % puerto)
        srv = ThreadingHTTPServer((PANEL["host"], int(PANEL["port"])), Handler)
        srv.daemon_threads = True
        logging.info(f"Panel en http://{PANEL['host']}:{PANEL['port']}/  (Ctrl+C para salir)")
        return srv, None
    logging.info(f"Panel en https://{PANEL['host']}:{puerto}/  (Ctrl+C para salir)")

    # El puerto de siempre queda redirigiendo, no sirviendo el panel.
    redirector = None
    if int(PANEL["port"]) != puerto:
        try:
            redirector = ServidorExclusivo((PANEL["host"], int(PANEL["port"])), RedirectorHTTPS)
            redirector.daemon_threads = True
            threading.Thread(target=redirector.serve_forever,
                             name="RedirHTTP", daemon=True).start()
            logging.info(f"El puerto {PANEL['port']} redirige a https")
        except OSError as exc:
            logging.warning(f"No se pudo abrir el puerto {PANEL['port']} para redirigir: {exc}")

    if PANEL["host"] == "0.0.0.0":
        logging.info("Escucha en toda la red: limita el acceso con el firewall de Windows")
    return srv, redirector


def main():
    if not DEVICES:
        logging.error("No hay lectores configurados en config.json")
        sys.exit(1)
    if not PANEL.get("password"):
        logging.error('Falta la clave del panel. Agregala en config.json, seccion "panel" -> "password".')
        sys.exit(1)

    init_param = NETSDK_INIT_PARAM()
    init_param.nThreadNum = 0
    if not client.InitEx(CallbackDesconexion, C_LDWORD(0), init_param):
        logging.error(f"No se pudo inicializar el SDK: {client.GetLastErrorMessage()}")
        sys.exit(1)
    logging.info("SDK inicializado")

    init_db()

    reconciliar_lectores()

    hilos = [threading.Thread(target=worker_sincronizacion, name="Sync", daemon=True)]
    for dev in DEVICES:
        DEV_STATE[dev["ip"]] = {"conectado": False, "login_id": None, "disconnect": threading.Event()}
        hilos.append(threading.Thread(target=hilo_lector, args=(dev,), name=f"Lector-{dev['ip']}", daemon=True))
    for h in hilos:
        h.start()

    servidor, redirector = armar_servidores()

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        logging.info("Cerrando...")
    finally:
        STOP.set()
        HAY_TRABAJO.set()
        for st in DEV_STATE.values():
            st["disconnect"].set()
        servidor.shutdown()
        if redirector:
            redirector.shutdown()
        for h in hilos:
            h.join(timeout=5)
        try:
            client.Cleanup()
        except Exception:
            pass
        logging.info("Listo.")


if __name__ == "__main__":
    main()
