# -*- coding: utf-8 -*-
"""
Conector Dahua (NetSDK) -> Odoo

Escucha eventos de control de acceso de varios equipos en paralelo, los guarda
en SQLite y los envia a Odoo.

Principios de diseno:
  1) El callback del SDK NUNCA bloquea: copia el evento y lo encola.
  2) Todo evento se persiste en SQLite ANTES de intentar enviarlo a Odoo.
  3) Si Odoo no responde, los eventos quedan pendientes y se reintentan solos.
  4) Si un equipo se desconecta, el hilo lo detecta y vuelve a loguear/suscribir.

Configuracion: config.json (junto a este archivo) o variables de entorno.
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
from ctypes import POINTER, byref, cast, sizeof, string_at, c_int, c_void_p
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

# =========================
# CONFIGURACION
# =========================
DEFAULT_CONFIG = {
    "log_level": "INFO",

    # Equipos a escuchar en paralelo
    "devices": [],

    "odoo": {
        "enabled": True,
        "url": "",
        "db": "",
        "user": "",
        "api_key": "",
        "model": "hr.enhancement.api",
        "method": "attendance_webhook",
        "timeout_seconds": 20,
        "verify_ssl": True,
        # Cuantas veces reintentar cuando Odoo responde pero rechaza el evento
        "max_app_retries": 5,
    },

    # True  -> el campo UTC del equipo viene en UTC y se convierte a hora local
    # False -> el equipo ya envia hora local
    "device_time_is_utc": True,

    # Ventana para considerar que las marcas pertenecen a la misma asistencia
    # (sirve para turno dia y turno noche)
    "attendance_window_hours": 18,

    # Quitar acentos/caracteres especiales del nombre antes de mandarlo a Odoo
    "normalize_name_ascii": True,

    # Carpeta donde guardar la foto que el fichador saca al marcar (la lee el
    # panel de asistencias). Se organiza igual que el equipo: <fecha>/hh/mm/archivo.jpg.
    # "" o null = no guardar fotos.
    "capturas_dir": r"C:\Lector\Capturas",

    "user_cache_minutes": 60,
    "resend_interval_seconds": 60,
    "heartbeat_minutes": 30,
    "reconnect_seconds": 5,
    "sdk_query_timeout_ms": 5000,

    # Registrar en el log los intentos de acceso denegados (no se envian a Odoo)
    "log_denied_events": True,

    # Avisar si la hora del evento difiere mucho de la hora del PC
    "clock_drift_warn_minutes": 10,
    # Pasado este desfase la marca NO se manda a Odoo: queda guardada en SQLite
    # con el motivo. Una hora es muchisimo mas de lo que puede tardar un evento
    # en llegar, asi que si se supera es que el reloj del equipo esta mal.
    "clock_drift_max_minutes": 60,

    # --- Recuperacion de marcas desde la memoria del lector ---
    # Cubre los cortes de luz del servidor: los lectores siguen guardando
    # internamente y al arrancar se traen las marcas que faltan.
    "backfill": {
        "enabled": True,
        # Cuanto mirar hacia atras la primera vez (sin datos previos de ese
        # equipo). Conservador a proposito: solo aplica con la base vacia, para
        # no inundar Odoo con marcas viejas en el primer arranque. Para los
        # cortes de luz no se usa: ahi se parte de la ultima marca guardada.
        "days_on_first_run": 1,
        # Se relee un rato antes de la ultima marca conocida, por las dudas
        "overlap_minutes": 15,
        # Tope de dias hacia atras en cualquier recuperacion
        "max_days": 30,
        "page_size": 200,
        "max_records": 50000,
        # Tambien recuperar cada vez que un lector se reconecta
        "on_reconnect": True,
        # Si el lector no informa timestamp UTC real, ajustar stuTime (en minutos)
        "record_time_offset_minutes": 0,
    },

    # --- Watchdog: si el proceso se cuelga, salir para que el servicio reinicie ---
    "watchdog": {
        "enabled": True,
        "check_seconds": 30,
        # El hilo principal no marca señal de vida hace tanto -> colgado
        "main_stall_seconds": 180,
        # El worker de eventos no avanza hace tanto -> colgado (SDK trabado)
        "worker_stall_seconds": 300,
        # Todos los lectores caidos tanto tiempo (habiendo estado conectados) -> reiniciar
        "all_devices_down_minutes": 15,
        # Archivo de estado para vigilancia externa
        "status_file": "logs/estado.json",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    problems = []

    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                cfg = _deep_merge(cfg, json.load(fh))
        except Exception as exc:
            problems.append(f"No se pudo leer {CONFIG_PATH}: {exc}")
    else:
        problems.append(f"No existe {CONFIG_PATH} (copiar config.example.json y completarlo)")

    # Las variables de entorno pisan al archivo (util para el servicio NSSM)
    env_map = {
        "LOG_LEVEL": ("log_level",),
        "ODOO_URL": ("odoo", "url"),
        "ODOO_DB": ("odoo", "db"),
        "ODOO_USER": ("odoo", "user"),
        "ODOO_API_KEY": ("odoo", "api_key"),
    }
    for env_name, path in env_map.items():
        val = os.getenv(env_name)
        if not val:
            continue
        node = cfg
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = val

    cfg["_problems"] = problems
    return cfg


CFG = load_config()
SEDE_POR_DEFECTO = CFG.get("sede_por_defecto", "Deposito")

# =========================
# LOGGING (consola + archivo rotativo)
# =========================
LOG_LEVEL = str(CFG.get("log_level", "INFO")).upper()
logs_dir = os.path.join(BASE_DIR, "logs")
os.makedirs(logs_dir, exist_ok=True)

formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s %(name)s: %(message)s")

root = logging.getLogger()
root.setLevel(LOG_LEVEL)
root.handlers.clear()

file_handler = RotatingFileHandler(
    os.path.join(logs_dir, "dahua_sdk.log"),
    maxBytes=5_242_880,  # 5 MB
    backupCount=5,
    encoding="utf-8",
)
file_handler.setLevel(LOG_LEVEL)
file_handler.setFormatter(formatter)
root.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(LOG_LEVEL)
console_handler.setFormatter(formatter)
root.addHandler(console_handler)

for _p in CFG.get("_problems", []):
    logging.warning(_p)

try:
    from SDK_Struct import (
        C_BOOL, C_ENUM, C_DWORD, C_LDWORD, C_LLONG,
        NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
        NETSDK_INIT_PARAM,
        DEV_EVENT_ACCESS_CTL_INFO,
        NET_ACCESS_USER_INFO, NET_IN_ACCESS_USER_SERVICE_GET, NET_OUT_ACCESS_USER_SERVICE_GET,
        # Consulta de registros historicos guardados en el lector
        NET_IN_FIND_RECORD_PARAM, NET_OUT_FIND_RECORD_PARAM,
        NET_IN_FIND_NEXT_RECORD_PARAM, NET_OUT_FIND_NEXT_RECORD_PARAM,
        NET_FIND_RECORD_ACCESSCTLCARDREC_CONDITION_EX, NET_RECORDSET_ACCESS_CTL_CARDREC,
    )
    from SDK_Enum import (
        EM_LOGIN_SPAC_CAP_TYPE, EM_EVENT_IVS_TYPE,
        NET_ACCESS_DOOROPEN_METHOD, NET_ACCESSCTLCARD_TYPE,
        NET_ACCESS_CTL_EVENT_TYPE,
        EM_A_NET_EM_ACCESS_CTL_USER_SERVICE,
        EM_NET_RECORD_TYPE, EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD, EM_RECORD_ORDER_TYPE,
    )
    from SDK_Callback import fAnalyzerDataCallBack, fDisConnect
    from NetSDK import NetClient
    logging.info("SDK importado (SDK_Struct / SDK_Enum / SDK_Callback / NetSDK)")
except ImportError as exc:
    logging.error(f"Error importando SDK: {exc}")
    sys.exit(1)

# Suscribirse solo a ACCESS_CTL (para probar todo: EM_EVENT_IVS_TYPE.ALL)
SUBSCRIBE_TYPES = EM_EVENT_IVS_TYPE.ACCESS_CTL

# Codigos de error de apertura (nErrorCode del evento)
ACCESS_ERROR_CODES = {
    0x00: "Sin error",
    0x10: "No autorizado",
    0x11: "Tarjeta dada de baja",
    0x12: "Sin permiso en esa puerta",
    0x13: "Modo de apertura incorrecto",
    0x14: "Fuera de vigencia",
    0x15: "Anti-passback",
    0x16: "Alarma de coaccion no habilitada",
    0x17: "Puerta en modo cerrado",
    0x18: "Bloqueo AB",
    0x19: "Tarjeta de ronda",
    0x1A: "Equipo en alarma de intrusion",
    0x20: "Fuera de horario",
    0x21: "Fuera de horario (feriado)",
    0x30: "Requiere primera tarjeta",
    0x40: "Clave incorrecta",
    0x41: "Tiempo de espera de clave agotado",
    0x50: "Secuencia de apertura combinada incorrecta",
    0x51: "Apertura combinada: falta validacion",
    0x60: "Validado pero sin autorizacion de la central",
    0x61: "Rostro incorrecto",
    0x62: "Tiempo de espera de rostro agotado",
    0x63: "Reingreso repetido",
    0x64: "No autorizado (requiere validacion de plataforma)",
    0x65: "Temperatura corporal alta",
    0x66: "Sin barbijo",
}

# =========================
# ESTADO GLOBAL
# =========================
client = NetClient()

STOP = threading.Event()
EVENT_QUEUE = queue.Queue(maxsize=10000)
NEW_EVENT = threading.Event()          # despierta al hilo que envia a Odoo

HANDLE_TO_DEV = {}                     # handle suscripcion -> ip
LOGIN_TO_IP = {}                       # login_id           -> ip
DEV_STATE = {}                         # ip -> {connected, login_id, disconnect, ...}
MAP_LOCK = threading.Lock()

USER_CACHE = {}                        # (ip, user_id) -> (nombre, ts, ttl)
USER_CACHE_LOCK = threading.Lock()

STATS = {"recibidos": 0, "duplicados": 0, "descartados": 0,
         "guardados": 0, "enviados": 0, "denegados": 0, "recuperados": 0}
STATS_LOCK = threading.Lock()

# Señales de vida para el watchdog
WATCHDOG_TICKS = {"main": time.time(), "worker": time.time()}
SALUD = {"hubo_conexion": False, "todos_caidos_desde": None}

data_dir = os.path.join(BASE_DIR, "data")
os.makedirs(data_dir, exist_ok=True)
SQLITE_DB_PATH = os.path.join(data_dir, "attendance_backup.sqlite3")
DB_LOCK = threading.Lock()

ATTENDANCE_WINDOW_HOURS = int(CFG["attendance_window_hours"])

# Estado de envio a Odoo
SENT_PENDING = 0
SENT_OK = 1
SENT_DISCARDED = 2


def bump(key, n=1):
    with STATS_LOCK:
        STATS[key] = STATS.get(key, 0) + n


# =========================
# UTILS
# =========================
def decode_sdk_str(raw) -> str:
    """Decodifica un char[] del SDK probando varias codificaciones."""
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


def strip_accents(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in s if not unicodedata.combining(ch))


def to_ascii_simple(s: str) -> str:
    return strip_accents(s or "").encode("ascii", "ignore").decode("ascii")


def sdk_time_to_datetime(sdk_time_obj):
    """NET_TIME_EX -> datetime (o None si la fecha es invalida)."""
    if not sdk_time_obj or int(sdk_time_obj.dwYear) == 0:
        return None
    try:
        return datetime(
            int(sdk_time_obj.dwYear), int(sdk_time_obj.dwMonth), int(sdk_time_obj.dwDay),
            int(sdk_time_obj.dwHour), int(sdk_time_obj.dwMinute), int(sdk_time_obj.dwSecond),
        )
    except ValueError:
        return None


def device_dt_to_local(dt):
    """Convierte la hora del equipo a hora local del PC segun configuracion.

    Los lectores informan siempre lo que ELLOS creen que es UTC, sin importar el
    huso que muestre la pantalla: se comprobo en un equipo puesto en huso +8 y en
    otro puesto en Buenos Aires, y los dos entregan UTC real. Por eso la
    conversion es una sola para todos, y cuando una marca llega corrida el
    problema es el reloj del equipo, no esta cuenta.
    """
    if dt is None:
        return None
    if CFG.get("device_time_is_utc", True):
        return dt.replace(tzinfo=timezone.utc).astimezone().replace(tzinfo=None)
    return dt


def fmt_dt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""


# =========================
# SQLITE
# =========================
def get_db_connection():
    conn = sqlite3.connect(SQLITE_DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db():
    with DB_LOCK:
        conn = get_db_connection()
        try:
            cr = conn.cursor()
            cr.execute("PRAGMA journal_mode = WAL")

            # 1) Log crudo de marcas: es la fuente de verdad para enviar a Odoo
            cr.execute("""
                CREATE TABLE IF NOT EXISTS attendance_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    dni TEXT NOT NULL,
                    employee_name TEXT,
                    check_time TEXT NOT NULL,      -- hora local de la marca
                    device_time TEXT,              -- hora cruda del equipo
                    received_at TEXT,              -- hora en que la recibio este PC

                    device_ip TEXT,
                    event_id TEXT,
                    event_type TEXT,
                    event_subtype TEXT,
                    open_method TEXT,
                    card_no TEXT,
                    card_type TEXT,
                    status TEXT,
                    error_code INTEGER,

                    payload_json TEXT,

                    sent_to_odoo INTEGER DEFAULT 0,   -- 0 pendiente, 1 enviado, 2 descartado
                    sent_at TEXT,
                    retry_count INTEGER DEFAULT 0,
                    last_error TEXT,

                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                    UNIQUE (device_ip, dni, check_time)
                )
            """)
            cr.execute("""
                CREATE INDEX IF NOT EXISTS idx_attendance_events_pendientes
                ON attendance_events (sent_to_odoo, id)
            """)

            # 2) Vista tipo hr.attendance (check_in / check_out) para consulta local
            cr.execute("""
                CREATE TABLE IF NOT EXISTS hr_attendance_backup (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    dni TEXT NOT NULL,
                    employee_name TEXT,

                    check_in TEXT NOT NULL,
                    check_out TEXT,

                    device_ip TEXT,
                    event_id TEXT,
                    event_type TEXT,
                    event_subtype TEXT,
                    open_method TEXT,
                    status TEXT,
                    card_type TEXT,

                    sent_to_odoo INTEGER DEFAULT 0,
                    sent_at TEXT,
                    retry_count INTEGER DEFAULT 0,
                    last_error TEXT,

                    payload_json TEXT,

                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT
                )
            """)
            cr.execute("""
                CREATE INDEX IF NOT EXISTS idx_hr_attendance_backup_dni_check_in
                ON hr_attendance_backup (dni, check_in)
            """)
            cr.execute("""
                CREATE INDEX IF NOT EXISTS idx_hr_attendance_backup_sent
                ON hr_attendance_backup (sent_to_odoo)
            """)

            conn.commit()
            logging.info(f"SQLite inicializado: {SQLITE_DB_PATH}")
        finally:
            conn.close()


def save_event(mark: dict, payload: dict):
    """
    Inserta la marca cruda. Devuelve (event_id, es_nueva).
    El UNIQUE (equipo, dni, hora) descarta repetidos: el equipo reenvia eventos
    al reconectar y no queremos duplicar asistencias.
    """
    payload_json = json.dumps(payload, ensure_ascii=False)
    with DB_LOCK:
        conn = get_db_connection()
        try:
            cr = conn.cursor()
            cr.execute("""
                INSERT OR IGNORE INTO attendance_events (
                    dni, employee_name, check_time, device_time, received_at,
                    device_ip, event_id, event_type, event_subtype,
                    open_method, card_no, card_type, status, error_code,
                    payload_json, sent_to_odoo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mark["dni"], mark["name"], mark["check_time"], mark["device_time"], mark["received_at"],
                mark["device_ip"], str(mark["event_id"]), mark["event_type"], mark["event_subtype"],
                mark["open_method"], mark["card_no"], mark["card_type"], mark["status"], mark["error_code"],
                payload_json, SENT_PENDING,
            ))
            is_new = cr.rowcount > 0
            event_id = cr.lastrowid if is_new else None
            conn.commit()
            return event_id, is_new
        except Exception:
            conn.rollback()
            logging.exception("Error guardando evento crudo")
            return None, False
        finally:
            conn.close()


def guardar_foto_captura(snap_url, foto_bytes):
    """Guarda la foto que el fichador saca al marcar, con la MISMA ruta/nombre que
    reporta el equipo (szSnapURL / campo URL del historial), para que el panel de
    asistencias la encuentre. Best-effort: si algo falla, la marca ya quedo guardada
    y enviada a Odoo igual (esto no debe romper nunca el flujo)."""
    base_dir = CFG.get("capturas_dir")
    if not base_dir or not foto_bytes or not snap_url:
        return
    rel = snap_url.split("/SnapShotFilePath/", 1)[-1].lstrip("/\\")
    if not rel:
        return
    destino = os.path.join(base_dir, *rel.replace("\\", "/").split("/"))
    try:
        os.makedirs(os.path.dirname(destino), exist_ok=True)
        if not os.path.exists(destino):
            with open(destino, "wb") as fh:
                fh.write(foto_bytes)
    except OSError as exc:
        logging.debug(f"No se pudo guardar la foto de captura ({rel}): {exc}")


def upsert_attendance(mark: dict, payload: dict):
    """
    Mantiene la tabla tipo hr.attendance:
      - si no hay asistencia reciente para ese DNI, crea el check_in
      - si hay una dentro de la ventana, actualiza el check_out
    """
    dni = mark["dni"]
    check_time = mark["check_time"]
    try:
        mark_dt = datetime.strptime(check_time, "%Y-%m-%d %H:%M:%S")
    except Exception:
        logging.warning(f"Fecha invalida para backup: {check_time}")
        return

    min_check_in = (mark_dt - timedelta(hours=ATTENDANCE_WINDOW_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
    payload_json = json.dumps(payload, ensure_ascii=False)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with DB_LOCK:
        conn = get_db_connection()
        try:
            cr = conn.cursor()
            existing = cr.execute("""
                SELECT id, check_in, check_out
                FROM hr_attendance_backup
                WHERE dni = ? AND check_in >= ? AND check_in <= ?
                ORDER BY check_in DESC
                LIMIT 1
            """, (dni, min_check_in, check_time)).fetchone()

            if not existing:
                cr.execute("""
                    INSERT INTO hr_attendance_backup (
                        dni, employee_name, check_in, check_out,
                        device_ip, event_id, event_type, event_subtype,
                        open_method, status, card_type,
                        payload_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    dni, mark["name"], check_time, None,
                    mark["device_ip"], str(mark["event_id"]), mark["event_type"], mark["event_subtype"],
                    mark["open_method"], mark["status"], mark["card_type"],
                    payload_json, now,
                ))
                logging.info(f"CHECK_IN  | DNI={dni} | {check_time} | equipo={mark['device_ip']}")

            elif existing["check_in"] == check_time:
                logging.info(f"Marca duplicada ignorada | DNI={dni} | {check_time}")

            else:
                cr.execute("""
                    UPDATE hr_attendance_backup
                    SET check_out = ?,
                        employee_name = COALESCE(NULLIF(?, ''), employee_name),
                        device_ip = ?, event_id = ?, event_type = ?, event_subtype = ?,
                        open_method = ?, status = ?, card_type = ?,
                        payload_json = ?, updated_at = ?
                    WHERE id = ?
                """, (
                    check_time, mark["name"],
                    mark["device_ip"], str(mark["event_id"]), mark["event_type"], mark["event_subtype"],
                    mark["open_method"], mark["status"], mark["card_type"],
                    payload_json, now, existing["id"],
                ))
                logging.info(f"CHECK_OUT | DNI={dni} | {check_time} | asistencia_id={existing['id']}")

            conn.commit()
        except Exception:
            conn.rollback()
            logging.exception("Error guardando backup local de asistencia")
        finally:
            conn.close()


def fetch_pending(limit=50):
    with DB_LOCK:
        conn = get_db_connection()
        try:
            return conn.execute("""
                SELECT id, payload_json, retry_count, dni, check_time
                FROM attendance_events
                WHERE sent_to_odoo = ?
                ORDER BY id
                LIMIT ?
            """, (SENT_PENDING, limit)).fetchall()
        finally:
            conn.close()


def count_pending() -> int:
    with DB_LOCK:
        conn = get_db_connection()
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM attendance_events WHERE sent_to_odoo = ?", (SENT_PENDING,)
            ).fetchone()[0]
        finally:
            conn.close()


def mark_event_sent(event_id: int, message: str = ""):
    with DB_LOCK:
        conn = get_db_connection()
        try:
            conn.execute("""
                UPDATE attendance_events
                SET sent_to_odoo = ?, sent_at = ?, last_error = ?
                WHERE id = ?
            """, (SENT_OK, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), (message or "")[:500], event_id))
            conn.commit()
        finally:
            conn.close()


def mark_event_error(event_id: int, error: str, discard: bool = False):
    with DB_LOCK:
        conn = get_db_connection()
        try:
            conn.execute("""
                UPDATE attendance_events
                SET retry_count = retry_count + 1,
                    last_error = ?,
                    sent_to_odoo = CASE WHEN ? = 1 THEN ? ELSE sent_to_odoo END
                WHERE id = ?
            """, ((error or "")[:500], 1 if discard else 0, SENT_DISCARDED, event_id))
            conn.commit()
        finally:
            conn.close()


# =========================
# ODOO (XML-RPC con timeout y sesion reusada)
# =========================
class _TimeoutTransport(xmlrpc.client.Transport):
    def __init__(self, timeout, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._timeout = timeout

    def make_connection(self, host):
        conn = super().make_connection(host)
        conn.timeout = self._timeout
        return conn


class _TimeoutSafeTransport(xmlrpc.client.SafeTransport):
    def __init__(self, timeout, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._timeout = timeout

    def make_connection(self, host):
        conn = super().make_connection(host)
        conn.timeout = self._timeout
        return conn


class OdooClient:
    """
    Mantiene la sesion (uid) entre eventos en vez de autenticar en cada envio.
    send() devuelve (ok, transitorio, mensaje):
      ok=True                      -> enviado y aceptado
      ok=False, transitorio=True   -> problema de red/servidor, hay que reintentar
      ok=False, transitorio=False  -> Odoo respondio pero rechazo el evento
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.enabled = bool(cfg.get("enabled"))
        self.url = (cfg.get("url") or "").rstrip("/")
        self.db = cfg.get("db") or ""
        self.user = cfg.get("user") or ""
        self.api_key = cfg.get("api_key") or ""
        self.model = cfg.get("model") or "hr.enhancement.api"
        self.method = cfg.get("method") or "attendance_webhook"
        self.timeout = int(cfg.get("timeout_seconds", 20))
        self.verify_ssl = bool(cfg.get("verify_ssl", True))
        self._uid = None
        self._models = None
        self._lock = threading.Lock()

        if self.enabled and not (self.url and self.db and self.user and self.api_key):
            logging.error("Odoo habilitado pero faltan datos de conexion en config.json")
            self.enabled = False

    def _transport(self):
        if self.url.lower().startswith("https"):
            ctx = None if self.verify_ssl else ssl._create_unverified_context()
            return _TimeoutSafeTransport(self.timeout, context=ctx)
        return _TimeoutTransport(self.timeout)

    def _connect(self):
        common = xmlrpc.client.ServerProxy(
            f"{self.url}/xmlrpc/2/common", transport=self._transport(), allow_none=True
        )
        uid = common.authenticate(self.db, self.user, self.api_key, {})
        if not uid:
            raise PermissionError("Autenticacion rechazada por Odoo (usuario / api key)")
        self._uid = uid
        self._models = xmlrpc.client.ServerProxy(
            f"{self.url}/xmlrpc/2/object", transport=self._transport(), allow_none=True
        )
        logging.info(f"Conectado a Odoo {self.url} (uid={uid})")

    def send(self, payload: dict):
        if not self.enabled:
            return True, False, "Odoo deshabilitado"

        with self._lock:
            for intento in (1, 2):  # el 2do intento es despues de re-autenticar
                try:
                    if self._models is None or self._uid is None:
                        self._connect()
                    resp = self._models.execute_kw(
                        self.db, self._uid, self.api_key, self.model, self.method, [payload], {}
                    )
                    return self._interpret(resp)

                except PermissionError as exc:
                    self._uid, self._models = None, None
                    return False, True, str(exc)

                except xmlrpc.client.Fault as exc:
                    # Error de aplicacion en Odoo (metodo inexistente, permisos, etc.)
                    self._uid, self._models = None, None
                    if intento == 1:
                        continue
                    return False, False, f"Fault: {exc.faultString[:300]}"

                except (xmlrpc.client.ProtocolError, OSError, EOFError, TimeoutError) as exc:
                    self._uid, self._models = None, None
                    if intento == 1:
                        continue
                    return False, True, f"Red/Odoo: {exc}"

                except Exception as exc:
                    self._uid, self._models = None, None
                    return False, True, f"Inesperado: {exc}"

        return False, True, "Sin respuesta"

    @staticmethod
    def _interpret(resp):
        """attendance_webhook devuelve {'success': bool, 'message'|'error': str}."""
        if isinstance(resp, dict):
            if resp.get("success"):
                return True, False, str(resp.get("message", ""))[:300]
            return False, False, str(resp.get("error") or resp.get("message") or resp)[:300]
        if resp in (True, 1):
            return True, False, ""
        return False, False, str(resp)[:300]


ODOO = OdooClient(CFG["odoo"])


# =========================
# CONSULTA DE PERSONA AL EQUIPO
# =========================
def _sdk_get_user_name(login_id: int, user_id: str) -> str:
    """OperateAccessUserService(GET): trae el nombre de la persona que marco."""
    try:
        in_param = NET_IN_ACCESS_USER_SERVICE_GET()
        in_param.dwSize = sizeof(NET_IN_ACCESS_USER_SERVICE_GET)
        in_param.nUserNum = 1
        in_param.szUserID = user_id.encode("utf-8")[:3199]
        in_param.bUserIDEx = 0

        out_param = NET_OUT_ACCESS_USER_SERVICE_GET()
        out_param.dwSize = sizeof(NET_OUT_ACCESS_USER_SERVICE_GET)
        out_param.nMaxRetNum = 1

        user_info_array = (NET_ACCESS_USER_INFO * 1)()
        fail_code_array = (C_ENUM * 1)()
        out_param.pUserInfo = cast(user_info_array, POINTER(NET_ACCESS_USER_INFO))
        out_param.pFailCode = cast(fail_code_array, POINTER(C_ENUM))

        ok = client.OperateAccessUserService(
            int(login_id),
            EM_A_NET_EM_ACCESS_CTL_USER_SERVICE.NET_EM_ACCESS_CTL_USER_SERVICE_GET,
            in_param, out_param, int(CFG["sdk_query_timeout_ms"]),
        )
        if not ok:
            logging.warning(f"No se pudo consultar al usuario {user_id}: {client.GetLastErrorMessage()}")
            return ""
        if int(out_param.nMaxRetNum) < 1:
            logging.debug(f"El equipo no devolvio datos del usuario {user_id}")
            return ""
        if int(fail_code_array[0]) != 0:
            logging.debug(f"Usuario {user_id} no encontrado (failcode={int(fail_code_array[0])})")
            return ""

        u = user_info_array[0]
        # szName es char[32]; los nombres largos vienen en szNameEx (char[128])
        name = ""
        if bool(u.bUseNameEx):
            name = decode_sdk_str(u.szNameEx)
        if not name:
            name = decode_sdk_str(u.szName)
        return name

    except Exception:
        logging.exception(f"Excepcion consultando al usuario {user_id}")
        return ""


def sede_del_lector(dev_ip):
    """Sede a la que pertenece un lector, segun config.json.

    Se lee del propio device: {"ip": ..., "sede": "Lavalle"}. Si no lo trae, se
    asume la sede por defecto, que es como venia funcionando cuando todos los
    lectores eran del Deposito.
    """
    for d in CFG.get("devices", []):
        if d.get("ip") == dev_ip:
            return d.get("sede") or SEDE_POR_DEFECTO
    return SEDE_POR_DEFECTO


def resolve_user_name(login_id, dev_ip: str, user_id: str) -> str:
    """Igual que _sdk_get_user_name pero con cache, para no consultar en cada marca."""
    if not user_id or not login_id:
        return ""

    key = (dev_ip, user_id)
    now = time.time()
    with USER_CACHE_LOCK:
        hit = USER_CACHE.get(key)
        if hit and now - hit[1] < hit[2]:
            return hit[0]

    name = _sdk_get_user_name(login_id, user_id)
    ttl = int(CFG["user_cache_minutes"]) * 60 if name else 300  # si no resolvio, reintenta en 5 min
    with USER_CACHE_LOCK:
        USER_CACHE[key] = (name, now, ttl)
    return name


# =========================
# RECUPERACION DE MARCAS DESDE LA MEMORIA DEL LECTOR
# =========================
# Cuando se corta la luz del servidor (o se cuelga el servicio), los lectores
# siguen registrando internamente. Al conectar les pedimos las marcas del
# periodo que nos falta y las metemos por el mismo camino que las de tiempo
# real: el UNIQUE (equipo, dni, hora) evita duplicar lo que ya teniamos.

def _fill_net_time(net_time, dt: datetime):
    net_time.dwYear = dt.year
    net_time.dwMonth = dt.month
    net_time.dwDay = dt.day
    net_time.dwHour = dt.hour
    net_time.dwMinute = dt.minute
    net_time.dwSecond = dt.second


def last_event_time_for_device(dev_ip: str):
    """Ultima marca que tenemos guardada de ese equipo."""
    with DB_LOCK:
        conn = get_db_connection()
        try:
            row = conn.execute(
                "SELECT MAX(check_time) FROM attendance_events WHERE device_ip = ?", (dev_ip,)
            ).fetchone()
        except Exception:
            logging.exception("Error consultando la ultima marca guardada")
            return None
        finally:
            conn.close()
    if row and row[0]:
        try:
            return datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return None


def record_to_mark(rec, dev_ip: str):
    """NET_RECORDSET_ACCESS_CTL_CARDREC -> el mismo dict que produce el callback."""
    offset = int(CFG["backfill"].get("record_time_offset_minutes", 0))

    # nCreateTimeRealUTC es el timestamp UTC real de la marca: es la fuente mas
    # confiable porque no depende del huso ni del horario de verano del equipo.
    # (Verificado en los lectores: stuTime viene en UTC, igual que el campo UTC
    #  de los eventos en vivo, mientras que el rango de busqueda por NET_TIME se
    #  interpreta en hora local. Por eso se consulta y se lee todo por UTC real.)
    ts = int(getattr(rec, "nCreateTimeRealUTC", 0) or 0)
    if ts > 0:
        local_dt = datetime.fromtimestamp(ts)
    else:
        local_dt = device_dt_to_local(sdk_time_to_datetime(rec.stuTime))
        if local_dt and offset:
            local_dt += timedelta(minutes=offset)
    if local_dt is None:
        return None

    try:
        subtype = NET_ACCESS_CTL_EVENT_TYPE(rec.emDirection).name
    except Exception:
        subtype = "UNKNOWN"
    try:
        open_method = NET_ACCESS_DOOROPEN_METHOD(rec.emMethod).name
    except Exception:
        open_method = str(rec.emMethod)
    try:
        card_type = NET_ACCESSCTLCARD_TYPE(rec.emCardType).name
    except Exception:
        card_type = str(rec.emCardType)

    user_id = decode_sdk_str(getattr(rec, "szUserIDEx", b"")) or decode_sdk_str(rec.szUserID)
    nombre = decode_sdk_str(rec.szCardNameEx) if bool(rec.bUseCardNameEx) else ""
    if not nombre:
        nombre = decode_sdk_str(rec.szCardName)

    return {
        "device_ip": dev_ip,
        "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "device_time": fmt_dt(sdk_time_to_datetime(rec.stuTime)),
        "check_time": fmt_dt(local_dt),
        "event_id": int(rec.nRecNo),
        "channel": int(rec.nDoor),
        "dni": user_id,
        "card_no": decode_sdk_str(rec.szCardNo),
        "status_ok": bool(rec.bStatus),
        "error_code": int(rec.nErrorCode),
        "event_type": "ACCESS_CTL",
        "event_subtype": subtype,
        "open_method": open_method,
        "card_type": card_type,
        "offline": True,
        "name_hint": nombre,
    }


def backfill_device(dev_ip: str, login_id: int, motivo: str = "arranque") -> int:
    """Trae del lector las marcas posteriores a la ultima que tenemos guardada."""
    cfg = CFG["backfill"]
    if not cfg.get("enabled", True) or not login_id:
        return 0

    ahora = datetime.now()
    ultima = last_event_time_for_device(dev_ip)
    if ultima:
        desde = ultima - timedelta(minutes=int(cfg["overlap_minutes"]))
    else:
        desde = ahora - timedelta(days=int(cfg["days_on_first_run"]))
    tope = ahora - timedelta(days=int(cfg["max_days"]))
    if desde < tope:
        desde = tope
    # El equipo puede tener el reloj adelantado: pedimos un margen hacia adelante
    hasta = ahora + timedelta(hours=6)

    logging.info(
        f"Recuperando marcas de {dev_ip} ({motivo}) desde {fmt_dt(desde)} "
        f"(ultima guardada: {fmt_dt(ultima) or 'ninguna'})"
    )

    cond = NET_FIND_RECORD_ACCESSCTLCARDREC_CONDITION_EX()
    cond.dwSize = sizeof(cond)
    cond.bCardNoEnable = 0
    # Se busca por timestamp UTC real: el rango con NET_TIME se interpreta en
    # hora local del equipo y los registros vuelven en UTC, asi que mezclarlos
    # deja marcas afuera. Igual se completa stStartTime/stEndTime por si algun
    # modelo viejo ignora bRealUTCTimeEnable.
    cond.bTimeEnable = 0
    cond.bRealUTCTimeEnable = 1
    cond.nStartRealUTCTime = int(desde.timestamp())
    cond.nEndRealUTCTime = int(hasta.timestamp())
    _fill_net_time(cond.stStartTime, desde)
    _fill_net_time(cond.stEndTime, hasta)
    cond.nOrderNum = 1
    cond.stuOrders[0].emField = \
        EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD.EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD_CREATETIME
    cond.stuOrders[0].emOrderType = EM_RECORD_ORDER_TYPE.EM_RECORD_ORDER_TYPE_ASCENT

    in_find = NET_IN_FIND_RECORD_PARAM()
    in_find.dwSize = sizeof(in_find)
    in_find.emType = EM_NET_RECORD_TYPE.ACCESSCTLCARDREC_EX
    in_find.pQueryCondition = cast(byref(cond), c_void_p)
    out_find = NET_OUT_FIND_RECORD_PARAM()
    out_find.dwSize = sizeof(out_find)

    if not client.FindRecord(int(login_id), in_find, out_find, 8000):
        logging.error(f"No se pudo consultar el historial de {dev_ip}: {client.GetLastErrorMessage()}")
        return 0

    find_handle = out_find.lFindeHandle
    page = int(cfg["page_size"])
    max_records = int(cfg["max_records"])
    total = 0
    encolados = 0

    try:
        while not STOP.is_set() and total < max_records:
            arr = (NET_RECORDSET_ACCESS_CTL_CARDREC * page)()
            for r in arr:
                r.dwSize = sizeof(NET_RECORDSET_ACCESS_CTL_CARDREC)

            in_next = NET_IN_FIND_NEXT_RECORD_PARAM()
            in_next.dwSize = sizeof(in_next)
            in_next.lFindeHandle = find_handle
            in_next.nFileCount = page
            out_next = NET_OUT_FIND_NEXT_RECORD_PARAM()
            out_next.dwSize = sizeof(out_next)
            out_next.pRecordList = cast(arr, c_void_p)
            out_next.nMaxRecordNum = page

            if not client.FindNextRecord(in_next, out_next, 10000):
                logging.warning(f"Corte al leer el historial de {dev_ip}: {client.GetLastErrorMessage()}")
                break

            devueltos = int(out_next.nRetRecordNum)
            for i in range(devueltos):
                mark = record_to_mark(arr[i], dev_ip)
                if not mark:
                    continue
                try:
                    EVENT_QUEUE.put(mark, timeout=5)
                    encolados += 1
                except queue.Full:
                    logging.error(f"Cola llena recuperando historial de {dev_ip}, se corta")
                    devueltos = 0
                    break

            total += devueltos
            if devueltos < page:  # se acabaron los registros del periodo
                break
    finally:
        try:
            client.FindRecordClose(find_handle)
        except Exception:
            logging.debug("FindRecordClose fallo", exc_info=True)

    logging.info(f"Historial de {dev_ip}: {total} registros leidos, {encolados} para procesar")
    return encolados


# =========================
# CALLBACKS DEL SDK
# =========================
@fDisConnect
def DisconnectCallBack(lLoginID, pchDVRIP, nDVRPort, dwUser):
    """El SDK avisa que se cayo la conexion: marcamos el equipo para re-loguear."""
    try:
        login_id = int(lLoginID)
        with MAP_LOCK:
            ip = LOGIN_TO_IP.get(login_id)
        if not ip:
            ip = pchDVRIP.decode(errors="replace") if pchDVRIP else "?"
        logging.warning(f"DESCONECTADO {ip}:{nDVRPort} (LoginID={login_id})")
        state = DEV_STATE.get(ip)
        if state:
            state["connected"] = False
            state["disconnect"].set()
    except Exception:
        logging.exception("Error en el callback de desconexion")


@fAnalyzerDataCallBack
def AnalyzerDataCallBack(lAnalyzerHandle, dwAlarmType, pAlarmInfo, pBuffer, dwBufSize, dwUser, nSequence, reserved):
    """
    Se ejecuta en un hilo del SDK: solo copia el evento y lo encola.
    Nada de red ni de base de datos aca adentro.
    """
    try:
        if dwAlarmType != EM_EVENT_IVS_TYPE.ACCESS_CTL or not pAlarmInfo:
            return

        with MAP_LOCK:
            dev_ip = HANDLE_TO_DEV.get(int(lAnalyzerHandle), "?")

        ev = cast(pAlarmInfo, POINTER(DEV_EVENT_ACCESS_CTL_INFO)).contents

        try:
            subtype = NET_ACCESS_CTL_EVENT_TYPE(ev.emEventType).name
        except Exception:
            subtype = str(ev.emEventType)
        try:
            open_method = NET_ACCESS_DOOROPEN_METHOD(ev.emOpenMethod).name
        except Exception:
            open_method = str(ev.emOpenMethod)
        try:
            card_type = NET_ACCESSCTLCARD_TYPE(ev.emCardType).name
        except Exception:
            card_type = str(ev.emCardType)

        device_dt = sdk_time_to_datetime(ev.UTC)
        mark = {
            "device_ip": dev_ip,
            "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device_time": fmt_dt(device_dt),
            "check_time": fmt_dt(device_dt_to_local(device_dt)),
            "event_id": int(ev.nEventID),
            "channel": int(ev.nChannelID),
            "dni": decode_sdk_str(ev.szUserID),
            "card_no": decode_sdk_str(ev.szCardNo),
            "status_ok": bool(ev.bStatus),
            "error_code": int(ev.nErrorCode),
            "event_type": "ACCESS_CTL",
            "event_subtype": subtype,
            "open_method": open_method,
            "card_type": card_type,
            # nState = 1 -> evento historico que el equipo reenvia tras reconectar
            "offline": bool(isinstance(reserved, int) and reserved == 1),
        }

        # Foto de captura: con bNeedPicFile=1 el SDK la manda en pBuffer. El puntero
        # solo vale durante el callback, asi que se copia aca; el archivo se escribe
        # en el worker (nada de I/O en este hilo). szSnapURL es la MISMA ruta que
        # despues aparece en el historial, para que el panel case foto <-> marca.
        mark["snap_url"] = decode_sdk_str(ev.szSnapURL)
        mark["foto_bytes"] = b""
        try:
            n = int(dwBufSize)
            if n > 0 and pBuffer:
                datos = string_at(pBuffer, n)
                if datos[:2] == b"\xff\xd8" and datos[-2:] == b"\xff\xd9":   # JPEG completo
                    mark["foto_bytes"] = datos
        except Exception:
            pass

        EVENT_QUEUE.put_nowait(mark)
        bump("recibidos")

    except queue.Full:
        bump("descartados")
        logging.error("Cola de eventos llena: se descarto un evento")
    except Exception:
        logging.exception("Error en el callback de eventos")


# =========================
# WORKERS
# =========================
def event_worker():
    """Consume la cola: resuelve el nombre, guarda en SQLite y avisa al enviador."""
    drift_limit = int(CFG.get("clock_drift_warn_minutes", 10)) * 60
    drift_max = int(CFG.get("clock_drift_max_minutes", 60)) * 60

    while not STOP.is_set() or not EVENT_QUEUE.empty():
        WATCHDOG_TICKS["worker"] = time.time()
        try:
            mark = EVENT_QUEUE.get(timeout=1)
        except queue.Empty:
            continue

        try:
            dev_ip = mark["device_ip"]
            mark["status"] = "Exito" if mark["status_ok"] else "Fallo"

            if not mark["status_ok"]:
                bump("denegados")
                if CFG.get("log_denied_events", True):
                    motivo = ACCESS_ERROR_CODES.get(mark["error_code"], f"codigo 0x{mark['error_code']:02X}")
                    logging.info(
                        f"ACCESO DENEGADO | equipo={dev_ip} | usuario={mark['dni'] or '?'} | "
                        f"metodo={mark['open_method']} | motivo={motivo}"
                    )
                continue

            if not mark["dni"] or not mark["check_time"]:
                logging.warning(f"Evento sin usuario o sin fecha valida, se ignora: {mark}")
                continue

            # Aviso si el reloj del equipo esta corrido (solo para eventos en vivo)
            reloj_corrido = None
            if not mark["offline"] and drift_limit:
                try:
                    delta = abs((
                        datetime.strptime(mark["check_time"], "%Y-%m-%d %H:%M:%S")
                        - datetime.strptime(mark["received_at"], "%Y-%m-%d %H:%M:%S")
                    ).total_seconds())
                    if delta > drift_limit:
                        logging.warning(
                            f"Hora del equipo {dev_ip} corrida {int(delta / 60)} min respecto del PC "
                            f"(evento={mark['check_time']}, pc={mark['received_at']}). "
                            f"Revisar el reloj del equipo."
                        )
                    # Avisar no alcanzaba: el 9/9/2026 el lector de Lavalle quedo
                    # 11 horas atrasado, el aviso salio 20 veces en el log y las
                    # marcas igual entraron a Odoo con la fecha del dia anterior,
                    # cerrando asistencias ajenas. Una marca con esta diferencia
                    # es basura: se guarda, pero no se manda.
                    if drift_max and delta > drift_max:
                        reloj_corrido = (
                            f"No se envio: el reloj de {dev_ip} esta corrido "
                            f"{int(delta / 60)} min (evento={mark['check_time']}, "
                            f"pc={mark['received_at']})"
                        )
                except Exception:
                    pass

            state = DEV_STATE.get(dev_ip) or {}
            state["last_event"] = datetime.now()

            # Los registros historicos ya traen el nombre; los eventos en vivo no
            nombre = mark.get("name_hint") or resolve_user_name(state.get("login_id"), dev_ip, mark["dni"])
            if CFG.get("normalize_name_ascii", True):
                nombre = to_ascii_simple(nombre)
            mark["name"] = nombre

            payload = {
                "check_time": mark["check_time"],
                "EventType": mark["event_type"],
                "eventSubType": mark["event_subtype"],
                "deviceTime": mark["device_time"],
                "eventId": mark["event_id"],
                "dni": mark["dni"],
                "name": mark["name"],
                "openMethod": mark["open_method"],
                "status": mark["status"],
                "cardType": mark["card_type"],
                "deviceIp": dev_ip,
                # De que sede es el lector. Odoo lo usa para saber en que campo
                # buscar al empleado: id_lavalle o id_deposito. Cada padron es
                # independiente y un mismo numero puede ser de otra persona en
                # la otra sede, asi que mandarlo mal le asigna la marca a alguien
                # que no es.
                "sede": sede_del_lector(dev_ip),
            }

            _event_id, es_nueva = save_event(mark, payload)
            if not es_nueva:
                bump("duplicados")
                logging.info(
                    f"Evento repetido ignorado | DNI={mark['dni']} | {mark['check_time']} | equipo={dev_ip}"
                )
                continue

            bump("guardados")
            logging.info(
                f"MARCA | equipo={dev_ip} | DNI={mark['dni']} | nombre={mark['name'] or '?'} | "
                f"{mark['check_time']} | metodo={mark['open_method']} | {mark['event_subtype']}"
                + (" | (historico)" if mark["offline"] else "")
            )

            # Guardar la foto de captura en disco (solo la traen los eventos en vivo).
            if mark.get("foto_bytes"):
                guardar_foto_captura(mark.get("snap_url"), mark["foto_bytes"])

            if reloj_corrido:
                # Queda en SQLite con el motivo, sin tocar el backup de
                # asistencias: cuando se arregle el reloj, el backfill la vuelve
                # a traer con la hora buena.
                mark_event_error(_event_id, reloj_corrido, discard=True)
                bump("descartados_por_reloj")
                logging.error(f"{reloj_corrido} | DNI={mark['dni']}")
                continue

            upsert_attendance(mark, payload)
            NEW_EVENT.set()

        except Exception:
            logging.exception("Error procesando evento")
        finally:
            EVENT_QUEUE.task_done()

    logging.info("Worker de eventos finalizado")


def odoo_sender():
    """
    Envia a Odoo todo lo que este pendiente en SQLite (nuevo o de reintentos).
    Si Odoo no responde espera con backoff y vuelve a intentar: nada se pierde.
    """
    base_wait = int(CFG["resend_interval_seconds"])
    max_app_retries = int(CFG["odoo"].get("max_app_retries", 5))
    backoff = 0

    if not ODOO.enabled:
        logging.warning("Envio a Odoo DESHABILITADO: los eventos solo se guardan en SQLite")

    while not STOP.is_set():
        if not ODOO.enabled:
            STOP.wait(base_wait)
            continue

        try:
            pendientes = fetch_pending(limit=50)
        except Exception:
            logging.exception("Error leyendo eventos pendientes")
            pendientes = []

        if not pendientes:
            NEW_EVENT.wait(timeout=base_wait)
            NEW_EVENT.clear()
            backoff = 0
            continue

        corte = False
        for row in pendientes:
            if STOP.is_set():
                break
            try:
                payload = json.loads(row["payload_json"])
            except Exception:
                mark_event_error(row["id"], "payload_json invalido", discard=True)
                continue

            ok, transitorio, msg = ODOO.send(payload)

            if ok:
                mark_event_sent(row["id"], msg)
                bump("enviados")
                logging.info(f"Odoo OK | DNI={row['dni']} | {row['check_time']} | {msg}")
                backoff = 0

            elif transitorio:
                mark_event_error(row["id"], msg)
                logging.warning(f"Odoo no disponible ({msg}). Los eventos quedan pendientes.")
                corte = True
                break

            else:
                descartar = (row["retry_count"] + 1) >= max_app_retries
                mark_event_error(row["id"], msg, discard=descartar)
                logging.log(
                    logging.ERROR if descartar else logging.WARNING,
                    f"Odoo rechazo el evento | DNI={row['dni']} | {row['check_time']} | {msg}"
                    + (" | DESCARTADO tras varios intentos" if descartar else ""),
                )

        if corte:
            backoff = min(backoff * 2 if backoff else base_wait, 300)
            STOP.wait(backoff)

    logging.info("Worker de envio a Odoo finalizado")


# =========================
# WATCHDOG
# =========================
# Si el proceso queda colgado (SDK trabado, hilo muerto, todos los lectores
# caidos), no sirve de nada seguir vivo: se registra el motivo y se sale con
# codigo != 0 para que el servicio de Windows lo reinicie. Como todo evento se
# guarda en SQLite y al arrancar se recupera el historial del lector, reiniciar
# es barato y no se pierde ninguna marca.

def estado_actual() -> dict:
    equipos = {}
    for ip, st in DEV_STATE.items():
        equipos[ip] = {
            "conectado": bool(st.get("connected")),
            "conectado_desde": fmt_dt(st.get("since")),
            "ultimo_evento": fmt_dt(st.get("last_event")),
        }
    with STATS_LOCK:
        resumen = dict(STATS)
    try:
        pendientes = count_pending()
    except Exception:
        pendientes = -1
    return {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pid": os.getpid(),
        "equipos": equipos,
        "conectados": sum(1 for e in equipos.values() if e["conectado"]),
        "total_equipos": len(equipos),
        "cola": EVENT_QUEUE.qsize(),
        "pendientes_odoo": pendientes,
        "odoo_habilitado": ODOO.enabled,
        "stats": resumen,
    }


def escribir_estado():
    """Deja logs/estado.json para que una tarea programada pueda vigilar el servicio."""
    ruta = os.path.join(BASE_DIR, CFG["watchdog"].get("status_file", "logs/estado.json"))
    try:
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        tmp = ruta + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(estado_actual(), fh, ensure_ascii=False, indent=2)
        os.replace(tmp, ruta)
    except Exception:
        logging.debug("No se pudo escribir el archivo de estado", exc_info=True)


def _reiniciar(motivos):
    logging.critical("WATCHDOG: " + " | ".join(motivos))
    logging.critical("WATCHDOG: se reinicia el proceso para que el servicio lo levante de nuevo")
    for h in logging.getLogger().handlers:
        try:
            h.flush()
        except Exception:
            pass
    os._exit(2)


def watchdog_loop():
    cfg = CFG["watchdog"]
    if not cfg.get("enabled", True):
        logging.warning("Watchdog deshabilitado")
        return

    intervalo = int(cfg["check_seconds"])
    main_max = int(cfg["main_stall_seconds"])
    worker_max = int(cfg["worker_stall_seconds"])
    caidos_max = int(cfg["all_devices_down_minutes"]) * 60

    while not STOP.wait(intervalo):
        ahora = time.time()
        motivos = []

        if ahora - WATCHDOG_TICKS["main"] > main_max:
            motivos.append(f"el hilo principal no responde hace {int(ahora - WATCHDOG_TICKS['main'])}s")

        if ahora - WATCHDOG_TICKS["worker"] > worker_max:
            motivos.append(
                f"el worker de eventos esta trabado hace {int(ahora - WATCHDOG_TICKS['worker'])}s "
                f"(cola={EVENT_QUEUE.qsize()})"
            )

        for t in threading.enumerate():
            if t.name in ("EventWorker", "OdooSender") and not t.is_alive():
                motivos.append(f"el hilo {t.name} murio")

        conectados = [ip for ip, st in DEV_STATE.items() if st.get("connected")]
        if conectados:
            SALUD["hubo_conexion"] = True
            SALUD["todos_caidos_desde"] = None
        elif SALUD["hubo_conexion"]:
            if SALUD["todos_caidos_desde"] is None:
                SALUD["todos_caidos_desde"] = ahora
                logging.warning("WATCHDOG: se cayeron todos los lectores")
            elif ahora - SALUD["todos_caidos_desde"] > caidos_max:
                motivos.append(
                    f"todos los lectores caidos hace {int((ahora - SALUD['todos_caidos_desde']) / 60)} min"
                )

        escribir_estado()

        if motivos:
            _reiniciar(motivos)


# =========================
# HILO POR DISPOSITIVO
# =========================
def device_loop(dev: dict):
    ip_str = dev["ip"]
    ip_bytes = ip_str.encode()
    state = DEV_STATE[ip_str]
    reconnect_seconds = int(CFG["reconnect_seconds"])

    while not STOP.is_set():
        login_id = 0
        handle = 0
        state["disconnect"].clear()

        try:
            in_login = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY()
            in_login.dwSize = sizeof(in_login)
            in_login.szIP = ip_bytes
            in_login.nPort = int(dev["port"])
            in_login.szUserName = dev["user"].encode()
            in_login.szPassword = dev["password"].encode()
            in_login.emSpecCap = EM_LOGIN_SPAC_CAP_TYPE.TCP
            in_login.pCapParam = None
            out_login = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY()
            out_login.dwSize = sizeof(out_login)

            login_id, _, err = client.LoginWithHighLevelSecurity(in_login, out_login)
            if login_id == 0:
                logging.error(f"Login {ip_str} fallo: {err} | {client.GetLastErrorMessage()}")
                STOP.wait(reconnect_seconds)
                continue

            with MAP_LOCK:
                LOGIN_TO_IP[int(login_id)] = ip_str
            state["login_id"] = int(login_id)
            logging.info(f"Login OK {ip_str} | LoginID={login_id}")

            # bNeedPicFile=1: ademas del evento, el SDK entrega la FOTO de captura
            # (pBuffer) para guardarla. Antes era 0 (sin foto). No cambia las marcas
            # ni el envio a Odoo: solo suma la imagen en el callback.
            need_pic = 1 if CFG.get("capturas_dir") else 0
            handle = client.sdk.CLIENT_RealLoadPictureEx(
                C_LLONG(login_id), 0, SUBSCRIBE_TYPES, need_pic, AnalyzerDataCallBack, C_LDWORD(0), None
            )
            # Si el equipo no soporta suscribir la foto, NO perder el en-vivo:
            # reintentar sin foto (comportamiento original).
            if handle == 0 and need_pic:
                logging.warning(f"Suscripcion con foto fallo en {ip_str}; reintento sin foto")
                handle = client.sdk.CLIENT_RealLoadPictureEx(
                    C_LLONG(login_id), 0, SUBSCRIBE_TYPES, 0, AnalyzerDataCallBack, C_LDWORD(0), None
                )
            if handle == 0:
                logging.error(
                    f"Suscripcion {ip_str} fallo: {client.GetLastError()} - {client.GetLastErrorMessage()}"
                )
                client.Logout(int(login_id))
                with MAP_LOCK:
                    LOGIN_TO_IP.pop(int(login_id), None)
                login_id = 0
                STOP.wait(reconnect_seconds)
                continue

            with MAP_LOCK:
                HANDLE_TO_DEV[int(handle)] = ip_str
            state["connected"] = True
            state["since"] = datetime.now()
            logging.info(f"Suscripto {ip_str} | Handle={handle}")

            # Recuperar las marcas que el lector guardo mientras el servidor
            # estuvo apagado, colgado o sin red.
            primera_vez = not state.get("backfill_hecho")
            bf = CFG["backfill"]
            if bf.get("enabled", True) and (primera_vez or bf.get("on_reconnect", True)):
                try:
                    n = backfill_device(ip_str, int(login_id), "arranque" if primera_vez else "reconexion")
                    if n:
                        bump("recuperados", n)
                except Exception:
                    logging.exception(f"Error recuperando el historial de {ip_str}")
                state["backfill_hecho"] = True

            # Espera hasta que se pida parar o el SDK avise desconexion
            while not STOP.is_set() and not state["disconnect"].is_set():
                state["disconnect"].wait(timeout=1)

        except Exception:
            logging.exception(f"Error en el hilo de {ip_str}")

        finally:
            state["connected"] = False
            state["login_id"] = None
            if handle:
                try:
                    client.sdk.CLIENT_StopLoadPic(C_LLONG(handle))
                except Exception:
                    logging.debug(f"StopLoadPic fallo en {ip_str}", exc_info=True)
                with MAP_LOCK:
                    HANDLE_TO_DEV.pop(int(handle), None)
            if login_id:
                try:
                    client.Logout(int(login_id))
                except Exception:
                    logging.debug(f"Logout fallo en {ip_str}", exc_info=True)
                with MAP_LOCK:
                    LOGIN_TO_IP.pop(int(login_id), None)

            if not STOP.is_set():
                logging.info(f"Reintentando {ip_str} en {reconnect_seconds}s...")
                STOP.wait(reconnect_seconds)

    logging.info(f"Hilo de {ip_str} finalizado")


# =========================
# MAIN
# =========================
def heartbeat():
    conectados = [ip for ip, st in DEV_STATE.items() if st.get("connected")]
    caidos = [ip for ip in DEV_STATE if ip not in conectados]
    try:
        pendientes = count_pending()
    except Exception:
        pendientes = -1

    with STATS_LOCK:
        resumen = dict(STATS)

    logging.info("-------------------------------")
    logging.info(f"Servicio activo a las {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info(f"Equipos conectados ({len(conectados)}): {', '.join(conectados) or '-'}")
    if caidos:
        logging.warning(f"Equipos CAIDOS ({len(caidos)}): {', '.join(caidos)}")
    logging.info(
        f"Eventos: recibidos={resumen['recibidos']} recuperados={resumen['recuperados']} "
        f"guardados={resumen['guardados']} enviados={resumen['enviados']} "
        f"duplicados={resumen['duplicados']} denegados={resumen['denegados']} "
        f"descartados={resumen['descartados']} | pendientes de envio={pendientes} | "
        f"cola={EVENT_QUEUE.qsize()}"
    )
    logging.info("-------------------------------")
    escribir_estado()


def main():
    devices = CFG.get("devices") or []
    if not devices:
        logging.error("No hay equipos configurados en config.json ('devices'). Nada que hacer.")
        sys.exit(1)

    logging.info("Inicializando SDK...")
    init_param = NETSDK_INIT_PARAM()
    init_param.nThreadNum = 0
    if not client.InitEx(DisconnectCallBack, C_LDWORD(0), init_param):
        logging.error(f"SDK Init Error: {client.GetLastErrorMessage()}")
        sys.exit(1)
    logging.info("SDK inicializado (con callback de desconexion)")

    # argtypes una sola vez, antes de arrancar los hilos
    client.sdk.CLIENT_RealLoadPictureEx.argtypes = [
        C_LLONG, c_int, C_DWORD, c_int, fAnalyzerDataCallBack, C_LDWORD, c_void_p
    ]
    client.sdk.CLIENT_RealLoadPictureEx.restype = C_LLONG
    client.sdk.CLIENT_StopLoadPic.argtypes = [C_LLONG]
    client.sdk.CLIENT_StopLoadPic.restype = C_BOOL

    init_db()

    modo_hora = "UTC -> hora local" if CFG.get("device_time_is_utc", True) else "hora local del equipo"
    logging.info(f"Hora de los eventos: {modo_hora}")

    threads = [
        threading.Thread(target=event_worker, name="EventWorker", daemon=True),
        threading.Thread(target=odoo_sender, name="OdooSender", daemon=True),
        threading.Thread(target=watchdog_loop, name="Watchdog", daemon=True),
    ]
    for dev in devices:
        ip = dev["ip"]
        DEV_STATE[ip] = {
            "connected": False,
            "login_id": None,
            "disconnect": threading.Event(),
            "last_event": None,
            "since": None,
        }
        threads.append(threading.Thread(target=device_loop, args=(dev,), name=f"Dev-{ip}", daemon=True))

    for t in threads:
        t.start()

    logging.info(f"Escuchando eventos de: {', '.join(d['ip'] for d in devices)} (Ctrl+C para salir)")

    heartbeat_seconds = int(CFG["heartbeat_minutes"]) * 60
    last_heartbeat = time.time()
    try:
        while True:
            WATCHDOG_TICKS["main"] = time.time()
            if time.time() - last_heartbeat >= heartbeat_seconds:
                heartbeat()
                last_heartbeat = time.time()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Deteniendo...")
    finally:
        STOP.set()
        NEW_EVENT.set()
        for st in DEV_STATE.values():
            st["disconnect"].set()
        for t in threads:
            t.join(timeout=5)
        try:
            client.Cleanup()
        except Exception:
            logging.debug("Cleanup fallo", exc_info=True)
        try:
            logging.info(f"Quedaron {count_pending()} eventos pendientes de enviar a Odoo")
        except Exception:
            pass
        logging.info("Listo.")


if __name__ == "__main__":
    main()
