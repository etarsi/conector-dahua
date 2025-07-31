import csv
import os
import sys
from ctypes import (
    Structure, POINTER, byref, sizeof, cast, c_void_p,
    c_char, c_int, c_longlong, c_ubyte, c_uint, c_short, c_char_p
)
from datetime import datetime

# --- Importar desde tus archivos de wrapper ---
try:
    from SDK_Struct import (
        C_DWORD, C_BOOL, C_LLONG, C_ENUM, C_BYTE, C_UINT, POINTERSIZE, C_LDWORD,
        NET_TIME, NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
        NETSDK_INIT_PARAM,
        NET_IN_FIND_RECORD_PARAM, NET_OUT_FIND_RECORD_PARAM,
        NET_IN_FIND_NEXT_RECORD_PARAM, NET_OUT_FIND_NEXT_RECORD_PARAM,
        NET_RECORDSET_ACCESS_CTL_CARDREC, # Usaremos esta como estructura de resultado
    )
    print("INFO: Estructuras base importadas de SDK_Struct.py")

    from SDK_Enum import (
        EM_LOGIN_SPAC_CAP_TYPE,
        EM_NET_RECORD_TYPE,
        NET_ACCESS_DOOROPEN_METHOD,
        NET_ACCESSCTLCARD_TYPE
    )
    print("INFO: Enums principales importados de SDK_Enum.py.")

    from NetSDK import NetClient
    print("INFO: NetClient importado de NetSDK.py")

except ImportError as e:
    print(f"❌ Error importando desde los módulos del SDK: {e}")
    exit()

# === Configuración ===
CSV_PATH = r"C:\Users\Ezequiel Tarsitano\Desktop\logs_acceso_findrecord_nullcond.csv"
RECORDS_PER_PAGE = 10 # Reducido para pruebas
TIMEOUT_GENERAL = 5000
TIMEOUT_FIND_RECORD = 10000

client = NetClient()

# ... (Funciones auxiliares format_sdk_time, etc. sin cambios) ...
def format_sdk_time(sdk_time_obj):
    if not sdk_time_obj or int(sdk_time_obj.dwYear) == 0:
        return "Fecha/Hora Inválida"
    try:
        dt_obj = datetime(
            int(sdk_time_obj.dwYear), int(sdk_time_obj.dwMonth), int(sdk_time_obj.dwDay),
            int(sdk_time_obj.dwHour), int(sdk_time_obj.dwMinute), int(sdk_time_obj.dwSecond)
        )
        return dt_obj.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError as e:
        return f"Error Fecha (Y{sdk_time_obj.dwYear}M{sdk_time_obj.dwMonth}D{sdk_time_obj.dwDay}): {e}"

def get_door_open_method_name(method_val):
    try: return NET_ACCESS_DOOROPEN_METHOD(method_val).name
    except: return f"Desconocido ({method_val})"

def get_card_type_name(card_type_val):
    try: return NET_ACCESSCTLCARD_TYPE(card_type_val).name
    except: return f"Desconocido ({card_type_val})"

# === Inicio del script ===
print("🚀 Inicializando SDK...")
init_param_instance = NETSDK_INIT_PARAM()
init_param_instance.nThreadNum = 0
user_data_for_init = C_LDWORD(0)
try: from SDK_Callback import fDisConnect as CB_fDisConnectType
except ImportError: CB_fDisConnectType = c_void_p

if not client.InitEx(None, user_data_for_init, init_param_instance):
    print(f"❌ Error al inicializar SDK. Código: {client.GetLastError()} - {client.GetLastErrorMessage()}"); exit()
print("✅ SDK Inicializado.")

if not os.path.exists(CSV_PATH):
    try:
        with open(CSV_PATH, "w", newline='', encoding='utf-8') as f_csv:
            fieldnames = ["RecNo", "Fecha y Hora", "Tarjeta", "UsuarioID", "MetodoApertura", "Puerta", "Estado", "TipoTarjeta", "Error"]
            writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
            writer.writeheader()
    except IOError as e: print(f"❌ Error CSV: {e}"); client.Cleanup(); exit()

print("🔒 Intentando conectar al dispositivo...")
in_login = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY(); in_login.dwSize = sizeof(in_login)
in_login.szIP = b"192.168.88.254"; in_login.nPort = 37777
in_login.szUserName = b"admin"; in_login.szPassword = b"Sebigus123"
in_login.emSpecCap = EM_LOGIN_SPAC_CAP_TYPE.TCP; in_login.pCapParam = None
out_login = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY(); out_login.dwSize = sizeof(out_login)
login_id, _, error_msg_login = client.LoginWithHighLevelSecurity(in_login, out_login)

if login_id == 0:
    print(f"❌ Error al conectar: {error_msg_login} (Cod: {client.GetLastError()} - {client.GetLastErrorMessage()})")
    client.Cleanup(); exit()
print(f"✅ Conectado. Login ID: {login_id}")

print("📁 Consultando logs de acceso (ACCESSCTLCARDREC, sin filtro de condición específico)...")

in_find_rec = NET_IN_FIND_RECORD_PARAM()
in_find_rec.dwSize = sizeof(in_find_rec)
# *** PRUEBA: Usar ACCESSCTLCARDREC (valor 6) y pQueryCondition = NULL ***
in_find_rec.emType = EM_NET_RECORD_TYPE.ACCESSCTLCARDREC
in_find_rec.pQueryCondition = c_void_p(0) # Pasar NULL como condición (buscar todo de este tipo)
print(f"INFO: Usando emType = {EM_NET_RECORD_TYPE(in_find_rec.emType).name if hasattr(EM_NET_RECORD_TYPE(in_find_rec.emType),'name') else in_find_rec.emType}, pQueryCondition = NULL")

out_find_rec = NET_OUT_FIND_RECORD_PARAM()
out_find_rec.dwSize = sizeof(out_find_rec)

client.sdk.CLIENT_FindRecord.argtypes = [C_LLONG, POINTER(NET_IN_FIND_RECORD_PARAM), POINTER(NET_OUT_FIND_RECORD_PARAM), c_int]
client.sdk.CLIENT_FindRecord.restype = C_BOOL

find_record_successful = client.sdk.CLIENT_FindRecord(login_id, byref(in_find_rec), byref(out_find_rec), TIMEOUT_FIND_RECORD)
find_rec_handle_val = 0

if not find_record_successful:
    print(f"❌ No se pudo iniciar búsqueda (CLIENT_FindRecord). Código: {client.GetLastError()} - {client.GetLastErrorMessage()}")
else:
    find_rec_handle_val = out_find_rec.lFindeHandle
    if find_rec_handle_val == 0:
        print(f"❌ Error al iniciar búsqueda, handle inválido (0). Código: {client.GetLastError()} - {client.GetLastErrorMessage()}")
    else:
        print(f"🔎 Búsqueda de records iniciada. Handle: {find_rec_handle_val}")
        record_buffer_type = NET_RECORDSET_ACCESS_CTL_CARDREC * RECORDS_PER_PAGE
        record_buffer = record_buffer_type()
        in_do_rec = NET_IN_FIND_NEXT_RECORD_PARAM(); in_do_rec.dwSize = sizeof(in_do_rec)
        in_do_rec.lFindeHandle = find_rec_handle_val; in_do_rec.nFileCount = RECORDS_PER_PAGE
        out_do_rec = NET_OUT_FIND_NEXT_RECORD_PARAM(); out_do_rec.dwSize = sizeof(out_do_rec)
        out_do_rec.pRecordList = cast(record_buffer, c_void_p); out_do_rec.nMaxRecordNum = RECORDS_PER_PAGE

        client.sdk.CLIENT_FindNextRecord.argtypes = [POINTER(NET_IN_FIND_NEXT_RECORD_PARAM), POINTER(NET_OUT_FIND_NEXT_RECORD_PARAM), c_int]
        client.sdk.CLIENT_FindNextRecord.restype = C_BOOL
        total_logs_exportados = 0
        while True:
            print(f"📄 Solicitando {in_do_rec.nFileCount} logs...")
            if not client.sdk.CLIENT_FindNextRecord(byref(in_do_rec), byref(out_do_rec), TIMEOUT_FIND_RECORD):
                print(f"❌ Error FindNextRecord o no más logs. Código: {client.GetLastError()} - {client.GetLastErrorMessage()}"); break
            if out_do_rec.nRetRecordNum == 0: print("ℹ️ No más registros."); break
            
            print(f"🔍 Recibidos {out_do_rec.nRetRecordNum} logs.")
            for i in range(out_do_rec.nRetRecordNum):
                log_entry = record_buffer[i]
                print(f"\n--- LOG ENTRY {total_logs_exportados + 1} ---")
                print(f"  dwSize: {log_entry.dwSize}, nRecNo: {log_entry.nRecNo}")
                print(f"  Raw stuTime: Y{log_entry.stuTime.dwYear} M{log_entry.stuTime.dwMonth} D{log_entry.stuTime.dwDay}")
                print(f"  Raw szCardNo: {bytes(log_entry.szCardNo)[:10].hex(' ')}")
                print(f"  Raw bStatus: {log_entry.bStatus}, Raw nErrorCode: {log_entry.nErrorCode}")
                
                fecha_hora_str = format_sdk_time(log_entry.stuTime)
                tarjeta_str = log_entry.szCardNo.decode('utf-8', errors='replace').strip('\x00').strip()
                usuario_id_str = log_entry.szUserID.decode('utf-8', errors='replace').strip('\x00').strip()
                metodo_str = get_door_open_method_name(log_entry.emMethod)
                puerta_str = str(log_entry.nDoor)
                estado_str = "Éxito" if log_entry.bStatus else f"Fallo (Cod:{log_entry.nErrorCode})"
                tipo_tarjeta_str = get_card_type_name(log_entry.emCardType)
                
                with open(CSV_PATH, "a", newline='', encoding='utf-8') as f_csv_write:
                    writer = csv.DictWriter(f_csv_write, fieldnames=["RecNo", "Fecha y Hora", "Tarjeta", "UsuarioID", "MetodoApertura", "Puerta", "Estado", "TipoTarjeta", "Error"])
                    writer.writerow({"RecNo": log_entry.nRecNo, "Fecha y Hora": fecha_hora_str, "Tarjeta": tarjeta_str, "UsuarioID": usuario_id_str, "MetodoApertura": metodo_str, "Puerta": puerta_str, "Estado": estado_str, "TipoTarjeta": tipo_tarjeta_str, "Error": log_entry.nErrorCode if not log_entry.bStatus else 0})
                total_logs_exportados += 1
            if out_do_rec.nRetRecordNum < RECORDS_PER_PAGE: print("ℹ️ Fin de datos (menos que página completa)."); break
        print(f"✅ Exportados {total_logs_exportados} logs.")
        if find_rec_handle_val != 0:
            client.sdk.CLIENT_FindRecordClose.argtypes = [C_LLONG]; client.sdk.CLIENT_FindRecordClose.restype = C_BOOL
            if not client.sdk.CLIENT_FindRecordClose(find_rec_handle_val): print(f"⚠️ No se pudo cerrar búsqueda. Código: {client.GetLastError()} - {client.GetLastErrorMessage()}")
            else: print("✅ Búsqueda cerrada.")

print("🚪 Desconectando...");
if login_id != 0:
    if not client.Logout(login_id): print(f"⚠️ Error al desconectar. Código: {client.GetLastError()} - {client.GetLastErrorMessage()}")
    else: print("✅ Desconectado.")
print("🧹 Limpiando SDK...");
if not client.Cleanup(): print(f"⚠️ Error al limpiar SDK. Código: {client.GetLastError()} - {client.GetLastErrorMessage()}")
else: print("✅ SDK Limpiado.")
print("🏁 Script finalizado.")
print("🧹 Limpiando SDK...")