import csv, json, os, sys, time, threading, requests
from ctypes import (POINTER, sizeof, cast, c_void_p, c_int)
from datetime import datetime
import traceback

# =========================
# IMPORTS DEL SDK (tus módulos)
# =========================
try:
    from SDK_Struct import (
        C_DWORD, C_BOOL, C_LLONG, C_ENUM, C_LDWORD,
        NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
        NETSDK_INIT_PARAM,
        DEV_EVENT_ACCESS_CTL_INFO, DEV_EVENT_FACERECOGNITION_INFO,
        NET_ACCESS_USER_INFO, NET_IN_ACCESS_USER_SERVICE_GET, NET_OUT_ACCESS_USER_SERVICE_GET,
        NET_TIME, NET_TIME_EX
    )
    print("INFO: Estructuras importadas de SDK_Struct.py")

    from SDK_Enum import (
        EM_LOGIN_SPAC_CAP_TYPE, EM_EVENT_IVS_TYPE,
        NET_ACCESS_DOOROPEN_METHOD, NET_ACCESSCTLCARD_TYPE,
        NET_ACCESS_CTL_EVENT_TYPE,
        EM_A_NET_EM_ACCESS_CTL_USER_SERVICE
    )
    print("INFO: Enums importados de SDK_Enum.py.")

    from SDK_Callback import fAnalyzerDataCallBack
    print("INFO: Tipo de Callback fAnalyzerDataCallBack importado.")

    from NetSDK import NetClient
    print("INFO: NetClient importado de NetSDK.py")

except ImportError as e:
    print(f"❌ Error importando SDK: {e}")
    sys.exit(1)

# =========================
# CONFIG
# =========================
CSV_PATH = r"C:\Users\Usuario\Downloads\eventos_tiempo_real.csv"
CSV_FIELDNAMES = [
    "Timestamp", "DeviceIP", "EventType", "EventSubType", "DeviceTime", "ChannelID_Evento", "ChannelID_Puerta",
    "EventID", "CardNo", "UserID", "UserName", "OpenMethod", "Status", "ErrorCode", "CardType",
    "Recog_UserName", "Recog_Similarity", "Recog_UID"
]
if "ChannelID_Puerta" not in CSV_FIELDNAMES:
    CSV_FIELDNAMES.insert(5, "ChannelID_Puerta")

# Equipos a escuchar en paralelo:
DEVICES = [
    {"ip": b"192.168.88.254", "port": 37777, "user": b"admin", "pwd": b"Sebigus123"},
    {"ip": b"192.168.88.253", "port": 37777, "user": b"admin", "pwd": b"Sebigus123"},
    {"ip": b"192.168.88.252", "port": 37777, "user": b"admin", "pwd": b"Sebigus123"},
]

# Enviar a tu endpoint (Odoo) — pon en False si no querés enviar
POST_TO_ODOO = True
ODOO_URL = "https://test.sebigus.com.ar/hr_enhancement/attendance"

# Suscribirse sólo a ACCESS_CTL (recomendado) o a todo:
SUBSCRIBE_TYPES = EM_EVENT_IVS_TYPE.ACCESS_CTL
# Si querés probar todo: SUBSCRIBE_TYPES = EM_EVENT_IVS_TYPE.ALL

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

def write_csv_row(row: dict):
    try:
        file_exists = os.path.isfile(CSV_PATH)
        with open(CSV_PATH, "a", newline='', encoding='utf-8') as f_csv:
            writer = csv.DictWriter(f_csv, fieldnames=CSV_FIELDNAMES)
            if not file_exists or os.path.getsize(CSV_PATH) == 0:
                writer.writeheader()
            writer.writerow(row)
    except Exception as e:
        print(f"  Error escribiendo a CSV: {e}")

def post_to_odoo(payload: dict):
    if not POST_TO_ODOO:
        return
    try:
        resp = requests.post(
            ODOO_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
            verify=False
        )
        if resp.status_code == 200:
            print("✅ Evento enviado a Odoo OK.", resp.json() if resp.text else "")
        else:
            print(f"⚠️ Odoo respondió {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"⚠️ Error enviando a Odoo: {e}")

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
            C_LLONG(login_id),
            EM_A_NET_EM_ACCESS_CTL_USER_SERVICE.NET_EM_ACCESS_CTL_USER_SERVICE_GET,
            in_param,
            out_param,
            5000
        )
        if not ok:
            print("OperateAccessUserService(GET) falló:", client.GetLastErrorMessage())
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
        print("Excepción resolviendo usuario:", e)
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

    print(f"\n[Evento desde {dev_ip}] Handle={lAnalyzerHandle}  Tipo={event_type_name} ({dwAlarmType})")

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
                print("  Procesando ACCESS_CTL evento...")
                print(f"  Evento ID: {access_event.nEventID}, Canal: {access_event.nChannelID}, "
                      f"Estado: {'OK' if access_event.bStatus else 'Fallo'}, Error: {access_event.nErrorCode}")
                if access_event.bStatus:
                    # --- 1. Obtener el UserID del evento (quien marcó) ---
                    user_id_bytes = access_event.szUserID
                    user_id_str = user_id_bytes.decode(errors='replace').strip('\x00')
                    print("UserID del que marcó:", user_id_str)
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
                    if dev_login and user_id_str:
                        resolved = resolve_user_info_by_id(dev_login, user_id_str)

                    # Imprimir por consola
                    print(f"  UserID={user_id_str}  Name={resolved.get('name','')}  Card={card_no_str}  "
                        f"Method={open_method_name}  Status={'OK' if access_event.bStatus else 'FAIL'}  "
                        f"SubType={event_subtype_name_access}")

                    # Armar log
                    log_data["DeviceTime"]  = format_sdk_time(access_event.UTC)
                    log_data["EventID"]     = access_event.nEventID
                    log_data["CardNo"]      = card_no_str
                    log_data["UserID"]      = resolved.get("id", user_id_str)
                    log_data["UserName"]    = personal.szName.decode(errors='replace').strip('\x00') if personal else resolved.get("name", "")
                    log_data["OpenMethod"]  = open_method_name
                    log_data["Status"]      = 'Exito' if access_event.bStatus else 'Fallo'
                    log_data["ErrorCode"]   = access_event.nErrorCode if not access_event.bStatus else 0
                    log_data["CardType"]    = card_type_name

                    # CSV
                    write_csv_row(log_data)
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
                    post_to_odoo(payload)

            except Exception as e:
                print("    Error procesando ACCESS_CTL:", e)
                traceback.print_exc()
        else:
            print("    pAlarmInfo es NULL para ACCESS_CTL")

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
                print(f"❌ Login {ip_str} falló: {err} | {client.GetLastErrorMessage()}")
                time.sleep(3); continue

            print(f"✅ Login OK {ip_str} | LoginID={login_id}")

            # Suscribirse (canal 0; ajusta si tu puerta es otra)
            dwUserCallback = C_LDWORD(12345)
            b_need_pic_file = 0
            handle = client.sdk.CLIENT_RealLoadPictureEx(
                C_LLONG(login_id), 0, SUBSCRIBE_TYPES, b_need_pic_file, AnalyzerDataCallBack, dwUserCallback, None
            )
            if handle == 0:
                print(f"❌ Subscribe {ip_str} falló: {client.GetLastError()} - {client.GetLastErrorMessage()}")
                client.Logout(C_LLONG(login_id))
                time.sleep(3); continue

            with MAP_LOCK:
                HANDLE_TO_DEV[int(handle)] = {"ip": ip_str, "login_id": int(login_id)}
            print(f"📡 Suscripto {ip_str} | Handle={handle}")

            # Mantener vivo
            while not stop_event.is_set():
                time.sleep(1)

        except Exception as e:
            print(f"⚠️ Hilo {ip_str}: {e}")

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
                print(f"🔁 Reintentando {ip_str} en 3s…")
                time.sleep(3)

# =========================
# MAIN
# =========================
def main():
    print("🚀 Inicializando SDK…")
    init_param_instance = NETSDK_INIT_PARAM(); init_param_instance.nThreadNum = 0
    user_data_param_init = C_LDWORD(0)
    if not client.InitEx(None, user_data_param_init, init_param_instance):
        print(f"❌ SDK Init Error: {client.GetLastErrorMessage()}")
        sys.exit(1)
    print("✅ SDK Inicializado.")

    # Asegurar CSV con header
    try:
        file_is_new = not os.path.exists(CSV_PATH) or os.path.getsize(CSV_PATH) == 0
        with open(CSV_PATH, "a", newline='', encoding='utf-8') as f_csv:
            writer = csv.DictWriter(f_csv, fieldnames=CSV_FIELDNAMES)
            if file_is_new:
                writer.writeheader()
    except IOError as e:
        print(f"❌ Error CSV: {e}")
        client.Cleanup()
        sys.exit(1)

    stop_event = threading.Event()
    threads = []
    for dev in DEVICES:
        t = threading.Thread(target=login_and_subscribe_loop, args=(dev, stop_event), daemon=True)
        t.start()
        threads.append(t)

    print("⏳ Escuchando eventos de 254/253/252 (Ctrl+C para salir)…")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Deteniendo…")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=3)
        client.Cleanup()
        print("🏁 Listo.")

if __name__ == "__main__":
    main()
