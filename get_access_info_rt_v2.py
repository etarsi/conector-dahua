import csv
import os
import sys
import time
from ctypes import (
    Structure, POINTER, byref, sizeof, cast, c_void_p,
    c_char, c_int, c_longlong, c_ubyte, c_uint, c_short, c_char_p
)
from datetime import datetime
import traceback # Para depuración más detallada

try:
    from SDK_Struct import (
        C_DWORD, C_BOOL, C_LLONG, C_ENUM, C_BYTE, C_UINT, POINTERSIZE, C_LDWORD,
        NET_TIME, NET_TIME_EX,
        NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
        NETSDK_INIT_PARAM,
        DEV_EVENT_ACCESS_CTL_INFO, DEV_EVENT_FACERECOGNITION_INFO,
        SDK_MSG_OBJECT, CANDIDATE_INFO,
        SDK_EVENT_FILE_INFO, SDK_PIC_INFO,
    )
    print("INFO: Estructuras base importadas de SDK_Struct.py")

    from SDK_Enum import (
        EM_LOGIN_SPAC_CAP_TYPE, EM_EVENT_IVS_TYPE,
        NET_ACCESS_DOOROPEN_METHOD, NET_ACCESSCTLCARD_TYPE,
        NET_ACCESS_CTL_EVENT_TYPE
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
    "CardNo", "UserID", "OpenMethod", "Status", "ErrorCode", "CardType",
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

    print(f"\n--- Nuevo Evento Recibido ---")
    print(f"  Handle: {lAnalyzerHandle}")
    print(f"  Tipo de Evento (dwAlarmType): {event_type_name} (Valor: {dwAlarmType})")

    log_data = {key: "" for key in CSV_FIELDNAMES}
    log_data["Timestamp"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    log_data["EventType"] = event_type_name

    if dwAlarmType == EM_EVENT_IVS_TYPE.ACCESS_CTL:
        if pAlarmInfo:
            try:
                access_event = cast(pAlarmInfo, POINTER(DEV_EVENT_ACCESS_CTL_INFO)).contents
                print(f"  Evento de Control de Acceso (ACCESS_CTL):")
                
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
                log_data["EventSubType"] = event_subtype_name_access

                # Usar nChannelID como el identificador de "Puerta" o canal de acceso
                # nChannelID es el primer campo en DEV_EVENT_ACCESS_CTL_INFO, así que debería existir.
                log_data["ChannelID_Evento"] = access_event.nChannelID # ID del canal que reporta el evento
                log_data["ChannelID_Puerta"] = access_event.nChannelID # Asumiendo que es el mismo para la puerta
                print(f"    ChannelID_Evento (Puerta): {access_event.nChannelID}")
                
                card_no_str = access_event.szCardNo.decode(errors='replace').strip(g_null_term_str)
                user_id_str = access_event.szUserID.decode(errors='replace').strip(g_null_term_str)
                open_method_name = NET_ACCESS_DOOROPEN_METHOD(access_event.emOpenMethod).name if hasattr(NET_ACCESS_DOOROPEN_METHOD(access_event.emOpenMethod), 'name') else str(access_event.emOpenMethod)
                card_type_name = NET_ACCESSCTLCARD_TYPE(access_event.emCardType).name if hasattr(NET_ACCESSCTLCARD_TYPE(access_event.emCardType), 'name') else str(access_event.emCardType)

                print(f"    Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
                print(f"    Tarjeta: {card_no_str}")
                print(f"    UserID: {user_id_str}")
                print(f"    Método: {open_method_name}")
                print(f"    Estado: {'Éxito' if access_event.bStatus else 'Fallo'}")
                if not access_event.bStatus: print(f"    ErrorCode: {access_event.nErrorCode}")

                log_data["DeviceTime"] = format_sdk_time(access_event.UTC) # UTC es NET_TIME_EX
                log_data["EventID"] = access_event.nEventID
                log_data["CardNo"] = card_no_str
                log_data["UserID"] = user_id_str
                log_data["OpenMethod"] = open_method_name
                log_data["Status"] = 'Exito' if access_event.bStatus else 'Fallo'
                log_data["ErrorCode"] = access_event.nErrorCode if not access_event.bStatus else 0
                log_data["CardType"] = card_type_name

            except Exception as e:
                print(f"    Error procesando evento ACCESS_CTL: {e}")
                traceback.print_exc()
        else: print("    pAlarmInfo es NULL para ACCESS_CTL")

    elif dwAlarmType == EM_EVENT_IVS_TYPE.FACERECOGNITION:
        if pAlarmInfo:
            try:
                face_event = cast(pAlarmInfo, POINTER(DEV_EVENT_FACERECOGNITION_INFO)).contents
                print(f"  Evento de Reconocimiento Facial (FACERECOGNITION):")
                log_data["DeviceTime"] = format_sdk_time(face_event.UTC)
                log_data["ChannelID_Evento"] = face_event.nChannelID
                log_data["EventID"] = face_event.nEventID

                if face_event.nCandidateNum > 0:
                    candidate = face_event.stuCandidates[0]
                    user_name = candidate.szPersonName.decode(errors='replace').strip(g_null_term_str)
                    similarity = int(candidate.bySimilarity)
                    uid = candidate.szUID.decode(errors='replace').strip(g_null_term_str)
                    print(f"    Candidato: Nombre='{user_name}', Similitud={similarity}%, UID='{uid}'")
                    log_data["Recog_UserName"] = user_name
                    log_data["Recog_Similarity"] = similarity
                    log_data["Recog_UID"] = uid
                else:
                    print("    Sin candidatos en el evento de reconocimiento facial.")
            except Exception as e:
                print(f"    Error procesando evento FACERECOGNITION: {e}")
                traceback.print_exc()
        else: print("    pAlarmInfo es NULL para FACERECOGNITION")

    try:
        file_exists = os.path.isfile(CSV_PATH)
        with open(CSV_PATH, "a", newline='', encoding='utf-8') as f_csv:
            writer = csv.DictWriter(f_csv, fieldnames=CSV_FIELDNAMES)
            if not file_exists or os.path.getsize(CSV_PATH) == 0: writer.writeheader()
            writer.writerow(log_data)
        print(f"  Evento guardado en {CSV_PATH}")
    except Exception as e:
        print(f"  Error escribiendo a CSV: {e}")
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
in_login.szIP = b"192.168.88.254"; in_login.nPort = 37777
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