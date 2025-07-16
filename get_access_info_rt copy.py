# Script: Captura en Tiempo Real + Consulta Histórica Dahua
import os
import csv
from datetime import datetime
from NetSDK.NetSDK import NetClient
from NetSDK.SDK_Enum import EM_EVENT_IVS_TYPE
from NetSDK.SDK_Struct import (
    DEV_EVENT_FACERECOGNITION_INFO, CANDIDATE_INFO, NET_TIME,
    NET_IN_STARTFIND_FACERECONGNITION, NET_OUT_STARTFIND_FACERECONGNITION,
    NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY
)
from ctypes import POINTER, cast, c_void_p, c_ubyte, sizeof, Structure, c_int, byref, CFUNCTYPE
import time

sdk = NetClient()
sdk.InitEx(None)
sdk.SetAutoReconnect(None)

# Configuración de login
in_param = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY()
in_param.dwSize = sizeof(NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY)
in_param.szIP = b"192.168.88.254"
in_param.nPort = 37777
in_param.szUserName = b"admin"
in_param.szPassword = b"Sebigus123"
in_param.emSpecCap = 0
in_param.pCapParam = None

out_param = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY()
out_param.dwSize = sizeof(NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY)

loginID, device_info, err_msg = sdk.LoginWithHighLevelSecurity(in_param, out_param)

if loginID == 0:
    print(f"❌ Error al conectar: {err_msg}")
    exit()
print("✅ Conectado con éxito")

# === Parte 1: Captura de eventos en tiempo real ===
csv_path_live = r"C:\Users\Ezequiel Tarsitano\Desktop\eventos_facial_tiempo_real.csv"
registros = []

CALLBACK_FUNC_TYPE = CFUNCTYPE(None, c_int, c_int, c_void_p, POINTER(c_ubyte), c_int, c_int, c_int, c_void_p)

@CALLBACK_FUNC_TYPE
def callback(handle, dwType, pAlarmInfo, pBuffer, dwBufSize, user, seq, reserved):
    if dwType == EM_EVENT_IVS_TYPE.FACERECOGNITION:
        evento = cast(pAlarmInfo, POINTER(DEV_EVENT_FACERECOGNITION_INFO)).contents

        fecha = f"{evento.UTC.dwYear}-{evento.UTC.dwMonth:02d}-{evento.UTC.dwDay:02d} {evento.UTC.dwHour:02d}:{evento.UTC.dwMinute:02d}:{evento.UTC.dwSecond:02d}"
        simil = evento.stuCandidates[0].bySimilarity
        nombre = evento.stuCandidates[0].stPersonInfo.szPersonNameEx.decode('utf-8', errors='ignore').strip()
        uid = evento.stuCandidates[0].stPersonInfo.szID.decode('utf-8', errors='ignore').strip()

        print(f"🧍‍♂️ {fecha} | {nombre} ({uid}) | {simil}%")
        registros.append({
            "Fecha y Hora": fecha,
            "Nombre": nombre,
            "Usuario": uid,
            "Similitud": simil
        })

        with open(csv_path_live, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=registros[0].keys())
            writer.writeheader()
            writer.writerows(registros)

canal = 0
handle = sdk.RealLoadPictureEx(loginID, canal, EM_EVENT_IVS_TYPE.FACERECOGNITION, True, callback)

if handle:
    print("📡 Escuchando eventos faciales en tiempo real. Presioná Ctrl+C para detener.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("🛑 Detenido por el usuario.")
    sdk.StopLoadPic(handle)
else:
    print("❌ Error al iniciar suscripción a eventos")
    print("Código:", sdk.GetLastErrorMessage())

sdk.Logout(loginID)
sdk.Cleanup()