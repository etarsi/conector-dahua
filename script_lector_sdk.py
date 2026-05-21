import json, os, sys, time, threading, requests, sqlite3, unicodedata, io, traceback, logging, xmlrpc.client 
from ctypes import (POINTER, sizeof, cast, c_void_p, c_int)
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler




# Configuracion de logging
# === Config de logging (consola + archivo rotativo) ===
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logs_dir = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(logs_dir, exist_ok=True)

formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(threadName)s %(name)s: %(message)s"
)

# Limpia handlers previos (por si el script se recarga)
root = logging.getLogger()
root.setLevel(LOG_LEVEL)
root.handlers.clear()

# -> a archivo rotativo
file_handler = RotatingFileHandler(
    os.path.join(logs_dir, "dahua_sdk.log"),
    maxBytes=5_242_880,  # 5 MB
    backupCount=5,
    encoding="utf-8"
)
file_handler.setLevel(LOG_LEVEL)
file_handler.setFormatter(formatter)
root.addHandler(file_handler)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(LOG_LEVEL)
console_handler.setFormatter(formatter)
root.addHandler(console_handler)

try:
    from SDK_Struct import (
        C_DWORD, C_BOOL, C_LLONG, C_ENUM, C_LDWORD,
        NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
        NETSDK_INIT_PARAM,
        DEV_EVENT_ACCESS_CTL_INFO, DEV_EVENT_FACERECOGNITION_INFO,
        NET_ACCESS_USER_INFO, NET_IN_ACCESS_USER_SERVICE_GET, NET_OUT_ACCESS_USER_SERVICE_GET,
        NET_TIME, NET_TIME_EX
    )
    logging.info("INFO: Estructuras importadas de SDK_Struct.py")

    from SDK_Enum import (
        EM_LOGIN_SPAC_CAP_TYPE, EM_EVENT_IVS_TYPE,
        NET_ACCESS_DOOROPEN_METHOD, NET_ACCESSCTLCARD_TYPE,
        NET_ACCESS_CTL_EVENT_TYPE,
        EM_A_NET_EM_ACCESS_CTL_USER_SERVICE
    )
    logging.info("INFO: Enums importados de SDK_Enum.py.")

    from SDK_Callback import fAnalyzerDataCallBack
    logging.info("INFO: Tipo de Callback fAnalyzerDataCallBack importado.")

    from NetSDK import NetClient
    logging.info("INFO: NetClient importado de NetSDK.py")

except ImportError as e:
    logging.error(f"Error importando SDK: {e}")
    sys.exit(1)

# =========================
# CONFIG
# =========================
CSV_FIELDNAMES = [
    "Timestamp", "DeviceIP", "EventType", "EventSubType", "DeviceTime", "ChannelID_Evento", "ChannelID_Puerta",
    "EventID", "CardNo", "UserID", "UserName", "OpenMethod", "Status", "ErrorCode", "CardType",
    "Recog_UserName", "Recog_Similarity", "Recog_UID"
]
if "ChannelID_Puerta" not in CSV_FIELDNAMES:
    CSV_FIELDNAMES.insert(5, "ChannelID_Puerta")

# Equipos a escuchar en paralelo:
DEVICES = [
    {"ip": b"192.168.88.254", "port": 37777, "user": b"admin", "pwd": b"Sebigus2025*$"},
    {"ip": b"192.168.88.253", "port": 37777, "user": b"admin", "pwd": b"Sebigus2025*$"},
    {"ip": b"192.168.88.252", "port": 37777, "user": b"admin", "pwd": b"Sebigus2025*$"},
    {"ip": b"192.168.88.245", "port": 37777, "user": b"admin", "pwd": b"Sebigus2025*$"},
]

# Enviar a tu endpoint (Odoo) — pon en False si no querés enviar
# Apa, te encontré usando esto Tito (Lauta)
POST_TO_ODOO = True
URL = "https://one.sebigus.com.ar"
DB = "one"
USER = "rrhh@sebigus.com.ar"
API_KEY = "123"

# Suscribirse sólo a ACCESS_CTL (recomendado) o a todo:
SUBSCRIBE_TYPES = EM_EVENT_IVS_TYPE.ACCESS_CTL
# Si querés probar todo: SUBSCRIBE_TYPES = EM_EVENT_IVS_TYPE.ALL

# =========================
# BACKUP LOCAL SQLITE
# =========================
data_dir = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(data_dir, exist_ok=True)

SQLITE_DB_PATH = os.path.join(data_dir, "attendance_backup.sqlite3")
DB_LOCK = threading.Lock()

# Ventana para considerar que las marcas pertenecen a la misma asistencia
# Sirve para turno día y turno noche.
ATTENDANCE_WINDOW_HOURS = 18

# =========================
# CLIENTE SDK + ESTADO
# =========================
client = NetClient()

# Mapeo: handle -> {ip, login_id}
HANDLE_TO_DEV = {}
MAP_LOCK = threading.Lock()

g_null_term_str = b'\x00'.decode()

# =========================
# UTILS
# =========================

def get_db_connection():
    conn = sqlite3.connect(SQLITE_DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_attendance_backup_db():
    with DB_LOCK:
        conn = get_db_connection()
        try:
            cr = conn.cursor()
            cr.execute("""
                CREATE TABLE IF NOT EXISTS hr_attendance_backup (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    -- En vez de employee_id
                    dni TEXT NOT NULL,
                    employee_name TEXT,

                    -- Igual concepto que hr.attendance
                    check_in TEXT NOT NULL,
                    check_out TEXT,

                    -- Datos del lector
                    device_ip TEXT,
                    event_id TEXT,
                    event_type TEXT,
                    event_subtype TEXT,
                    open_method TEXT,
                    status TEXT,
                    card_type TEXT,

                    -- Control de envío a Odoo
                    sent_to_odoo INTEGER DEFAULT 0,
                    sent_at TEXT,
                    retry_count INTEGER DEFAULT 0,
                    last_error TEXT,

                    -- Payload completo por seguridad
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
            logging.info(f"Backup SQLite inicializado: {SQLITE_DB_PATH}")

        finally:
            conn.close()

def normalize_datetime_str(dt_str):
    """
    Deja la fecha en formato YYYY-MM-DD HH:MM:SS.
    Si viene con milisegundos, los corta.
    """
    if not dt_str:
        return None
    return str(dt_str)[:19]

def format_sdk_time(sdk_time_obj):
    if not sdk_time_obj or int(sdk_time_obj.dwYear) == 0:
        return "Fecha/Hora Inválida"
    try:
        return datetime(
            int(sdk_time_obj.dwYear), int(sdk_time_obj.dwMonth), int(sdk_time_obj.dwDay),
            int(sdk_time_obj.dwHour), int(sdk_time_obj.dwMinute), int(sdk_time_obj.dwSecond)
        ).strftime('%Y-%m-%d %H:%M:%S') + f".{int(getattr(sdk_time_obj, 'dwMillisecond', 0)):03d}"
    except ValueError as e:
        return f"Error Fecha: {e}"

def strip_accents(s):
    s = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in s if not unicodedata.combining(ch))

def to_ascii_simple(s):
    s = strip_accents(s)
    return s.encode("ascii", "ignore").decode("ascii")


def post_to_odoo(payload: dict):
    if not POST_TO_ODOO:
        return
    try:
        common = xmlrpc.client.ServerProxy(f"{URL}/xmlrpc/2/common")
        uid = common.authenticate(DB, USER, API_KEY, {})
        assert uid, "Autenticación falló"
        models = xmlrpc.client.ServerProxy(f"{URL}/xmlrpc/2/object")
        logging.info(f"UID: {uid}")
        resp = models.execute_kw(DB, uid, API_KEY, 'hr.enhancement.api', 'attendance_webhook', [payload], {})
        logging.info(resp)
        if resp.status_code == 200:
            logging.info(f"Evento enviado a Odoo OK. Respuesta: {resp.json() if resp.text else ''}")
        else:
            logging.warning(f"Odoo respondió {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        logging.error(f"Error enviando a Odoo: {e}")

def get_devinfo_from_handle(lAnalyzerHandle):
    with MAP_LOCK:
        return HANDLE_TO_DEV.get(int(lAnalyzerHandle))

def resolve_user_info_by_id(login_id: int, user_id_str: str):
    """
    Usa OperateAccessUserService(GET) para traer NET_ACCESS_USER_INFO del que marcó.
    Devuelve dict {'name': str, 'id': str} con lo que se pueda resolver.
    """
    try:
        in_param = NET_IN_ACCESS_USER_SERVICE_GET()
        in_param.dwSize = sizeof(NET_IN_ACCESS_USER_SERVICE_GET)
        in_param.nUserNum = 1

        # szUserID es un char[3200]. Escribimos el ID + zeros.
        uid = (user_id_str or "").encode("utf-8")
        if len(uid) > 3199:
            uid = uid[:3199]
        in_param.szUserID = uid + b"\x00" * (3200 - len(uid))
        in_param.bUserIDEx = C_BOOL(False)

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
            in_param,
            out_param,
            5000
        )
        if not ok:
            logging.error(f"OperateAccessUserService(GET) falló: {client.GetLastErrorMessage()}")
            return {"name": "", "id": user_id_str}

        # OJO: algunos equipos no devuelven nMaxRetNum real aquí; tomamos el primer slot
        u = user_info_array[0]
        # Campos típicos que suelen existir en NET_ACCESS_USER_INFO (revisa tu SDK_Struct):
        # p.ej. u.szName (char[64/128/256]), u.szUserID, etc.
        try:
            name = getattr(u, "szName").decode("utf-8", errors="ignore").strip("\x00")
        except Exception:
            name = ""
        try:
            back_id = getattr(u, "szUserID").decode("utf-8", errors="ignore").strip("\x00")
        except Exception:
            back_id = user_id_str

        return {"name": name, "id": back_id or user_id_str}
    except Exception as e:
        logging.error(f"Excepción resolviendo usuario: {e}")
        return {"name": "", "id": user_id_str}

# =========================
# CALLBACK
# =========================
@fAnalyzerDataCallBack
def AnalyzerDataCallBack(lAnalyzerHandle, dwAlarmType, pAlarmInfo, pBuffer, dwBufSize, dwUser, nSequence, reserved):
    devinfo = get_devinfo_from_handle(lAnalyzerHandle)
    dev_ip = devinfo["ip"] if devinfo else "?"
    dev_login = devinfo["login_id"] if devinfo else 0
    g_login_id = dev_login
    try:
        event_type_name = EM_EVENT_IVS_TYPE(dwAlarmType).name
    except ValueError:
        event_type_name = f"Desconocido (0x{dwAlarmType:X})"

    logging.info(f"\n[Evento desde {dev_ip}] Handle={lAnalyzerHandle}  Tipo={event_type_name} ({dwAlarmType})")

    # Base de log
    log_data = {key: "" for key in CSV_FIELDNAMES}
    log_data["Timestamp"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    log_data["DeviceIP"] = dev_ip
    log_data["EventType"] = event_type_name

    # ====== ACCESS_CTL ======
    if dwAlarmType == EM_EVENT_IVS_TYPE.ACCESS_CTL:
        if pAlarmInfo:
            try:
                access_event = cast(pAlarmInfo, POINTER(DEV_EVENT_ACCESS_CTL_INFO)).contents
                if access_event.bStatus:
                    # --- 1. Obtener el UserID del evento (quien marcó) ---
                    user_id_bytes = access_event.szUserID
                    user_id_str = user_id_bytes.decode(errors='replace').strip('\x00')
                    # --- 2. Preparar structs de entrada y salida ---
                    in_param = NET_IN_ACCESS_USER_SERVICE_GET()
                    in_param.dwSize = sizeof(NET_IN_ACCESS_USER_SERVICE_GET)
                    in_param.nUserNum = 1
                    # Asumimos que el ID cabe en 3200 bytes (si no, ajustalo)
                    in_param.szUserID = (user_id_str + '\x00' * (3200 - len(user_id_str))).encode('utf-8')
                    # OJO: Algunos SDK requieren codificar como ascii, chequeá tu equipo
                    out_param = NET_OUT_ACCESS_USER_SERVICE_GET()
                    out_param.dwSize = sizeof(NET_OUT_ACCESS_USER_SERVICE_GET)
                    out_param.nMaxRetNum = 1
                    # Reservar memoria para el resultado:
                    user_info_array = (NET_ACCESS_USER_INFO * 1)()
                    fail_code_array = (C_ENUM * 1)()
                    out_param.pUserInfo = cast(user_info_array, POINTER(NET_ACCESS_USER_INFO))
                    out_param.pFailCode = cast(fail_code_array, POINTER(C_ENUM))
                    # --- 3. Llamar a la función ---
                    liste_user = client.OperateAccessUserService(
                        g_login_id,
                        EM_A_NET_EM_ACCESS_CTL_USER_SERVICE.NET_EM_ACCESS_CTL_USER_SERVICE_GET,
                        in_param, out_param, 5000
                    )
                    # --- 4. Procesar respuesta ---
                    if liste_user and out_param.nMaxRetNum > 0:
                        personal = user_info_array[0]
                        logging.info(f"personal data {personal}")
                    # Subtipo
                    try:
                        event_subtype_name_access = NET_ACCESS_CTL_EVENT_TYPE(access_event.emEventType).name
                    except Exception:
                        event_subtype_name_access = str(getattr(access_event, "emEventType", ""))
                    log_data["EventSubType"] = event_subtype_name_access

                    # Canal
                    log_data["ChannelID_Evento"] = access_event.nChannelID
                    log_data["ChannelID_Puerta"] = access_event.nChannelID

                    # Campos directos del evento
                    card_no_str = access_event.szCardNo.decode(errors='replace').strip('\x00')
                    user_id_str = access_event.szUserID.decode(errors='replace').strip('\x00')
                    open_method_name = str(access_event.emOpenMethod)
                    card_type_name = str(access_event.emCardType)
                    try:
                        open_method_name = NET_ACCESS_DOOROPEN_METHOD(access_event.emOpenMethod).name
                    except Exception:
                        pass
                    try:
                        card_type_name = NET_ACCESSCTLCARD_TYPE(access_event.emCardType).name
                    except Exception:
                        pass

                    # Resolver nombre de la persona (si el equipo lo soporta)
                    resolved = {"name": "", "id": user_id_str}
                    personal_name = personal.szName.decode(errors='replace').strip('\x00') if personal else resolved.get("name", "")
                    if dev_login and user_id_str:
                        resolved = resolve_user_info_by_id(dev_login, user_id_str)
                    # Armar log
                    log_data["DeviceTime"]  = format_sdk_time(access_event.UTC)
                    log_data["EventID"]     = access_event.nEventID
                    log_data["CardNo"]      = card_no_str
                    log_data["UserID"]      = resolved.get("id", user_id_str)
                    log_data["UserName"]    = to_ascii_simple(personal_name)
                    log_data["OpenMethod"]  = open_method_name
                    log_data["Status"]      = 'Exito' if access_event.bStatus else 'Fallo'
                    log_data["ErrorCode"]   = access_event.nErrorCode if not access_event.bStatus else 0
                    log_data["CardType"]    = card_type_name
                    # POST (opcional)
                    payload = {
                        "check_time": log_data["Timestamp"],
                        "EventType": log_data["EventType"],
                        "eventSubType": log_data["EventSubType"],
                        "deviceTime": log_data["DeviceTime"],
                        "eventId": log_data["EventID"],
                        "dni": log_data["UserID"],
                        "name": log_data["UserName"],
                        "openMethod": log_data["OpenMethod"],
                        "status": log_data["Status"],
                        "cardType": log_data["CardType"],
                        "deviceIp": dev_ip
                    }
                    payload_backup = {
                        "check_time": log_data["DeviceTime"],
                        "received_at": log_data["Timestamp"],
                        "EventType": log_data["EventType"],
                        "eventSubType": log_data["EventSubType"],
                        "deviceTime": log_data["DeviceTime"],
                        "eventId": log_data["EventID"],
                        "dni": log_data["UserID"],
                        "name": log_data["UserName"],
                        "openMethod": log_data["OpenMethod"],
                        "status": log_data["Status"],
                        "cardType": log_data["CardType"],
                        "deviceIp": dev_ip
                    }
                    # Primero backup local
                    save_hr_attendance_backup(payload_backup)
                    # Envio a Odoo
                    post_to_odoo(payload)

            except Exception as e:
                logging.error(f"Error procesando ACCESS_CTL: {e}")
                traceback.print_exc()
        else:
            logging.error("pAlarmInfo es NULL para ACCESS_CTL")


def save_hr_attendance_backup(payload: dict):
    """
    Guarda la asistencia localmente con lógica parecida a hr.attendance.

    Regla:
    - Si no existe una asistencia reciente para ese DNI, crea check_in.
    - Si existe una asistencia reciente dentro de ATTENDANCE_WINDOW_HOURS,
      actualiza check_out con la última marca.
    """

    dni = payload.get("dni")
    employee_name = payload.get("name")
    check_time = normalize_datetime_str(
        payload.get("check_time") or payload.get("deviceTime")
    )

    if not dni or not check_time:
        logging.warning(f"No se guarda backup: falta dni o check_time. Payload={payload}")
        return

    try:
        mark_dt = datetime.strptime(check_time, "%Y-%m-%d %H:%M:%S")
    except Exception:
        logging.warning(f"Fecha inválida para backup: {check_time}. Payload={payload}")
        return

    min_check_in_dt = mark_dt - timedelta(hours=ATTENDANCE_WINDOW_HOURS)
    min_check_in = min_check_in_dt.strftime("%Y-%m-%d %H:%M:%S")

    payload_json = json.dumps(payload, ensure_ascii=False)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with DB_LOCK:
        conn = get_db_connection()
        try:
            cr = conn.cursor()

            # Buscar última asistencia del DNI dentro de la ventana
            existing = cr.execute("""
                SELECT id, check_in, check_out
                FROM hr_attendance_backup
                WHERE dni = ?
                  AND check_in >= ?
                  AND check_in <= ?
                ORDER BY check_in DESC
                LIMIT 1
            """, (
                dni,
                min_check_in,
                check_time,
            )).fetchone()

            if not existing:
                # Primera marca: crear check_in
                cr.execute("""
                    INSERT INTO hr_attendance_backup (
                        dni,
                        employee_name,
                        check_in,
                        check_out,

                        device_ip,
                        event_id,
                        event_type,
                        event_subtype,
                        open_method,
                        status,
                        card_type,

                        payload_json,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    dni,
                    employee_name,
                    check_time,
                    None,

                    payload.get("deviceIp"),
                    str(payload.get("eventId")),
                    payload.get("EventType"),
                    payload.get("eventSubType"),
                    payload.get("openMethod"),
                    payload.get("status"),
                    payload.get("cardType"),

                    payload_json,
                    now,
                ))

                logging.info(
                    f"Backup creado CHECK_IN | DNI={dni} | check_in={check_time} | equipo={payload.get('deviceIp')}"
                )

            else:
                attendance_id = existing["id"]
                current_check_in = existing["check_in"]

                # Si la marca es igual al check_in, no tiene sentido actualizar check_out
                if check_time == current_check_in:
                    logging.info(
                        f"Marca duplicada ignorada | DNI={dni} | check_time={check_time}"
                    )
                else:
                    # Siguiente marca: actualizar check_out
                    cr.execute("""
                        UPDATE hr_attendance_backup
                        SET check_out = ?,
                            employee_name = COALESCE(?, employee_name),
                            device_ip = ?,
                            event_id = ?,
                            event_type = ?,
                            event_subtype = ?,
                            open_method = ?,
                            status = ?,
                            card_type = ?,
                            payload_json = ?,
                            updated_at = ?
                        WHERE id = ?
                    """, (
                        check_time,
                        employee_name,
                        payload.get("deviceIp"),
                        str(payload.get("eventId")),
                        payload.get("EventType"),
                        payload.get("eventSubType"),
                        payload.get("openMethod"),
                        payload.get("status"),
                        payload.get("cardType"),
                        payload_json,
                        now,
                        attendance_id,
                    ))

                    logging.info(
                        f"Backup actualizado CHECK_OUT | DNI={dni} | check_out={check_time} | asistencia_id={attendance_id}"
                    )

            conn.commit()
        except Exception:
            conn.rollback()
            logging.exception("Error guardando backup local de asistencia")
        finally:
            conn.close()

# =========================
# HILO POR DISPOSITIVO
# =========================
def login_and_subscribe_loop(dev: dict, stop_event: threading.Event):
    # Definir argtypes/restype una vez aquí (por si el hilo arranca primero)
    client.sdk.CLIENT_RealLoadPictureEx.argtypes = [C_LLONG, c_int, C_DWORD, c_int, fAnalyzerDataCallBack, C_LDWORD, c_void_p]
    client.sdk.CLIENT_RealLoadPictureEx.restype = C_LLONG
    client.sdk.CLIENT_StopLoadPic.argtypes = [C_LLONG]
    client.sdk.CLIENT_StopLoadPic.restype = C_BOOL

    while not stop_event.is_set():
        login_id = 0
        handle = 0
        ip_str = dev["ip"].decode()
        try:
            # Login
            in_login = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY(); in_login.dwSize = sizeof(in_login)
            in_login.szIP = dev["ip"]; in_login.nPort = dev["port"]
            in_login.szUserName = dev["user"]; in_login.szPassword = dev["pwd"]
            in_login.emSpecCap = EM_LOGIN_SPAC_CAP_TYPE.TCP; in_login.pCapParam = None
            out_login = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY(); out_login.dwSize = sizeof(out_login)

            login_id, _, err = client.LoginWithHighLevelSecurity(in_login, out_login)
            if login_id == 0:
                logging.error(f"Login {ip_str} falló: {err} | {client.GetLastErrorMessage()}")
                time.sleep(3); continue

            logging.info(f"Login OK {ip_str} | LoginID={login_id}")
            # Suscribirse (canal 0; ajusta si tu puerta es otra)
            dwUserCallback = C_LDWORD(12345)
            b_need_pic_file = 0
            handle = client.sdk.CLIENT_RealLoadPictureEx(
                C_LLONG(login_id), 0, SUBSCRIBE_TYPES, b_need_pic_file, AnalyzerDataCallBack, dwUserCallback, None
            )
            if handle == 0:
                logging.error(f"Subscribe {ip_str} falló: {client.GetLastError()} - {client.GetLastErrorMessage()}")
                client.Logout(C_LLONG(login_id))
                time.sleep(3); continue

            with MAP_LOCK:
                HANDLE_TO_DEV[int(handle)] = {"ip": ip_str, "login_id": int(login_id)}
            logging.info(f"Suscripto {ip_str} | Handle={handle}")

            # Mantener vivo
            while not stop_event.is_set():
                time.sleep(1)

        except Exception as e:
            logging.error(f"Hilo {ip_str}: {e}")

        finally:
            # Cleanup
            if handle:
                try:
                    client.sdk.CLIENT_StopLoadPic(C_LLONG(handle))
                except: pass
                with MAP_LOCK:
                    HANDLE_TO_DEV.pop(int(handle), None)
            if login_id:
                try:
                    client.Logout(C_LLONG(login_id))
                except: pass

            if not stop_event.is_set():
                logging.info(f"Reintentando {ip_str} en 3s…")
                time.sleep(3)

# =========================
# MAIN
# =========================
def main():
    logging.info("Inicializando SDK…")
    init_param_instance = NETSDK_INIT_PARAM(); init_param_instance.nThreadNum = 0
    user_data_param_init = C_LDWORD(0)
    if not client.InitEx(None, user_data_param_init, init_param_instance):
        logging.error(f"SDK Init Error: {client.GetLastErrorMessage()}")
        sys.exit(1)

    logging.info("SDK Inicializado.")
    stop_event = threading.Event()
    threads = []
    init_attendance_backup_db()
    for dev in DEVICES:
        t = threading.Thread(target=login_and_subscribe_loop, args=(dev, stop_event), daemon=True)
        t.start()
        threads.append(t)

    logging.info("Escuchando eventos de 254/253/252 (Ctrl+C para salir)…")
    # --- Latido cada 30 minutos ---
    last_heartbeat = time.time()
    try:
        while True:
            # Si pasaron 1800 segundos (30 min), logueamos el latido
            if time.time() - last_heartbeat >= 1800:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.info("-------------------------------")
                logging.info(f"Servicio activo a las {now}")
                logging.info("-------------------------------")
                last_heartbeat = time.time()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Deteniendo…")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=3)
        client.Cleanup()
        logging.info("Listo.")

if __name__ == "__main__":
    main()
