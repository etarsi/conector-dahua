import csv, json, os, time, requests
from ctypes import (POINTER, sizeof, cast, c_void_p, c_int)
from datetime import datetime
import traceback

try:
    from SDK_Struct import (
        C_DWORD, C_BOOL, C_LLONG, C_ENUM, C_LDWORD,
        NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
        NETSDK_INIT_PARAM, DEV_EVENT_ACCESS_CTL_INFO, NET_ACCESS_USER_INFO, NET_IN_ACCESS_USER_SERVICE_GET,
        NET_OUT_ACCESS_USER_SERVICE_GET
    )
    print("INFO: Estructuras base importadas de SDK_Struct.py")

    from SDK_Enum import (
        EM_LOGIN_SPAC_CAP_TYPE, EM_EVENT_IVS_TYPE,
        NET_ACCESS_DOOROPEN_METHOD, NET_ACCESSCTLCARD_TYPE,
        NET_ACCESS_CTL_EVENT_TYPE, EM_A_NET_EM_ACCESS_CTL_USER_SERVICE
    )
    print("INFO: Enums principales (incluyendo de acceso) importados de SDK_Enum.py.")

    from SDK_Callback import fAnalyzerDataCallBack
    print("INFO: Tipo de Callback fAnalyzerDataCallBack importado.")

    from NetSDK import NetClient
    print("INFO: NetClient importado de NetSDK.py")

except ImportError as e:
    print(f"❌ Error importando desde los módulos del SDK: {e}"); exit()

CSV_PATH = r"C:\Users\Usuario\Downloads\eventos_tiempo_real.csv"
CSV_FIELDNAMES = [
    "Timestamp", "EventType", "EventSubType", "DeviceTime", "ChannelID_Evento", "ChannelID_Puerta", "EventID",
    "CardNo", "UserID", "UserName", "OpenMethod", "Status", "ErrorCode", "CardType",
    "Recog_UserName", "Recog_Similarity", "Recog_UID"
]
# Asegurar que los nombres de las columnas están actualizados
if "ChannelID_Puerta" not in CSV_FIELDNAMES: CSV_FIELDNAMES.insert(5, "ChannelID_Puerta")


client = NetClient()
g_login_id = 0
g_event_analyzer_handle = 0
g_null_term_str = b'\x00'.decode()

@fAnalyzerDataCallBack
def AnalyzerDataCallBack(lAnalyzerHandle, dwAlarmType, pAlarmInfo, pBuffer, dwBufSize, dwUser, nSequence, reserved):
    event_type_name = "Desconocido"
    try:
        event_type_name = EM_EVENT_IVS_TYPE(dwAlarmType).name
    except ValueError:
        event_type_name = f"Desconocido (0x{dwAlarmType:X})"

    log_data = {}
    log_data["check_time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    log_data["EventType"] = event_type_name

    if dwAlarmType == EM_EVENT_IVS_TYPE.ACCESS_CTL:
        if pAlarmInfo:
            try:
                access_event = cast(pAlarmInfo, POINTER(DEV_EVENT_ACCESS_CTL_INFO)).contents
                print(f"acceso event: {access_event.bStatus}, pAlarmInfo ptr: {pAlarmInfo}, size: {dwBufSize}")
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
                    event_subtype_name_access = "N/A"
                    if hasattr(access_event, 'emEventType'):
                        try:
                            event_subtype_name_access = NET_ACCESS_CTL_EVENT_TYPE(access_event.emEventType).name
                            print(f"    Subtipo de Evento de Acceso (emEventType): {event_subtype_name_access} (Valor: {access_event.emEventType})")
                        except (ValueError, AttributeError) as e_enum_subtype:
                            event_subtype_name_access = f"ValorNum {access_event.emEventType} (Err: {e_enum_subtype})"
                            print(f"    Subtipo de Evento de Acceso (emEventType): {event_subtype_name_access}")
                    else:
                        print("    ADVERTENCIA: access_event no tiene 'emEventType'.")
                    open_method_name = NET_ACCESS_DOOROPEN_METHOD(access_event.emOpenMethod).name if hasattr(NET_ACCESS_DOOROPEN_METHOD(access_event.emOpenMethod), 'name') else str(access_event.emOpenMethod)
                    card_type_name = NET_ACCESSCTLCARD_TYPE(access_event.emCardType).name if hasattr(NET_ACCESSCTLCARD_TYPE(access_event.emCardType), 'name') else str(access_event.emCardType)
                    log_data["status"] = True
                    log_data["eventSubType"] = event_subtype_name_access
                    log_data["deviceTime"] = format_sdk_time(access_event.UTC) # UTC es NET_TIME_EX
                    log_data["eventId"] = access_event.nEventID
                    log_data["dni"] = user_id_str
                    log_data["name"] = personal.szName.decode('utf-8', errors='ignore') if hasattr(personal, 'szName') else "Desconocido"    
                    log_data["openMethod"] = open_method_name
                    log_data["status"] = 'Exito' if access_event.bStatus else 'Fallo'
                    log_data["cardType"] = card_type_name
                    print(f"    ver los logs registrados: {log_data}")
                else:
                    log_data["status"] = False
            except Exception as e:
                print(f"    Error procesando evento ACCESS_CTL: {e}")
                traceback.print_exc()
        else: print("    pAlarmInfo es NULL para ACCESS_CTL")

    try:
        if log_data["status"]:
            response = requests.post("https://test.sebigus.com.ar/hr_enhancement/attendance", json=log_data, timeout=10, verify=False)
            if response.status_code == 200:
                print(f"    Evento registrado exitosamente: {log_data}")
                print(f"Respuesta del servidor: {response.json()}")
            else:
                print(f"    Error al registrar evento: {log_data}, Código de estado: {response.status_code}, Respuesta: {response.text}")
    except Exception as e:
        print(f"  Error al momento de enviar datos a Odoo: {e}")
    return

def format_sdk_time(sdk_time_obj):
    if not sdk_time_obj or int(sdk_time_obj.dwYear) == 0: return "Fecha/Hora Inválida"
    try:
        return datetime(int(sdk_time_obj.dwYear), int(sdk_time_obj.dwMonth), int(sdk_time_obj.dwDay),
                        int(sdk_time_obj.dwHour), int(sdk_time_obj.dwMinute), int(sdk_time_obj.dwSecond)
                       ).strftime('%Y-%m-%d %H:%M:%S') + f".{int(getattr(sdk_time_obj, 'dwMillisecond', 0)):03d}" # getattr para dwMillisecond
    except ValueError as e: return f"Error Fecha: {e}"

# ... (resto del script: InitEx, login, RealLoadPictureEx, bucle principal, cleanup) ...
print("🚀 Inicializando SDK...");
init_param_instance = NETSDK_INIT_PARAM(); init_param_instance.nThreadNum = 0
user_data_param_init = C_LDWORD(0)
if not client.InitEx(None, user_data_param_init, init_param_instance):
    print(f"❌ SDK Init Error: {client.GetLastErrorMessage()}"); exit()
print("✅ SDK Inicializado.")
try:
    file_is_new = not os.path.exists(CSV_PATH) or os.path.getsize(CSV_PATH) == 0
    with open(CSV_PATH, "a", newline='', encoding='utf-8') as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=CSV_FIELDNAMES)
        if file_is_new: writer.writeheader()
except IOError as e: print(f"❌ Error CSV: {e}"); client.Cleanup(); exit()

print("🔒 Intentando conectar al dispositivo...")
in_login = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY(); in_login.dwSize = sizeof(in_login)
in_login.szIP = b"192.168.88.253"; in_login.nPort = 37777
in_login.szUserName = b"admin"; in_login.szPassword = b"Sebigus123"
in_login.emSpecCap = EM_LOGIN_SPAC_CAP_TYPE.TCP; in_login.pCapParam = None
out_login = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY(); out_login.dwSize = sizeof(out_login)
g_login_id, _, error_msg_login = client.LoginWithHighLevelSecurity(in_login, out_login)

if g_login_id == 0:
    print(f"❌ Error Conexión: {error_msg_login} (Cod: {client.GetLastError()})"); client.Cleanup(); exit()
print(f"✅ Conectado. Login ID: {g_login_id}")

dwUserCallback = C_LDWORD(12345)
# dwAlarmTypeSubscription = EM_EVENT_IVS_TYPE.ACCESS_CTL | EM_EVENT_IVS_TYPE.FACERECOGNITION
# O EM_EVENT_IVS_TYPE.ALL si quieres probar todo primero
dwAlarmTypeSubscription = EM_EVENT_IVS_TYPE.ALL
b_need_pic_file = 0

print(f"📡 Suscribiéndose a eventos (Tipo: {dwAlarmTypeSubscription})...")

client.sdk.CLIENT_RealLoadPictureEx.argtypes = [C_LLONG, c_int, C_DWORD, c_int, fAnalyzerDataCallBack, C_LDWORD, c_void_p]
client.sdk.CLIENT_RealLoadPictureEx.restype = C_LLONG
g_event_analyzer_handle = client.sdk.CLIENT_RealLoadPictureEx(g_login_id, 0, dwAlarmTypeSubscription, b_need_pic_file, AnalyzerDataCallBack, dwUserCallback, None)

if g_event_analyzer_handle == 0:
    print(f"❌ Error al suscribirse a eventos. Código: {client.GetLastError()} - {client.GetLastErrorMessage()}")
    client.Logout(g_login_id); client.Cleanup(); exit()

print(f"✅ Suscrito a eventos con éxito. Handle: {g_event_analyzer_handle}. Esperando eventos...")
print("Presiona Ctrl+C para detener.")

try:
    while True: time.sleep(1)
except KeyboardInterrupt: print("\n🛑 Deteniendo script por el usuario...")
finally:
    if g_event_analyzer_handle != 0:
        print(f"🔌 Cancelando suscripción a eventos (Handle: {g_event_analyzer_handle})...")
        client.sdk.CLIENT_StopLoadPic.argtypes = [C_LLONG]; client.sdk.CLIENT_StopLoadPic.restype = C_BOOL
        if not client.sdk.CLIENT_StopLoadPic(g_event_analyzer_handle): print(f"⚠️ Error al cancelar suscripción. (Cod: {client.GetLastError()})")
        else: print("✅ Suscripción cancelada.")
    if g_login_id != 0:
        print("🚪 Desconectando...");
        if not client.Logout(g_login_id): print(f"⚠️ Error al desconectar. (Cod: {client.GetLastError()})")
        else: print("✅ Desconectado.")
    print("🧹 Limpiando SDK...");
    if not client.Cleanup(): print(f"⚠️ Error al limpiar SDK. (Cod: {client.GetLastError()})")
    else: print("✅ SDK Limpiado.")
    print("🏁 Script finalizado.")