# -*- coding: utf-8 -*-
"""
Respalda la biometria de un lector y despues lo vacia.

El respaldo va SIEMPRE antes del borrado, y si el respaldo falla no se borra
nada. Se aprendio por las malas: borrar primero y descubrir despues que las
huellas no estaban en ningun lado no tiene vuelta atras.

Que hace:
  1. Arma la lista de usuarios del equipo cruzando su historial con lo que sabe
     el panel, y confirma uno por uno contra el propio lector.
  2. Lee la huella de cada uno y guarda todo en un .json con la plantilla en
     base64, mas un Excel para mirarlo.
  3. Recien entonces, y solo con --aplicar, los borra del equipo.

    python instalacion\\respaldar_y_vaciar_lector.py --ip 192.168.88.252
    python instalacion\\respaldar_y_vaciar_lector.py --ip 192.168.88.252 --aplicar
"""

import argparse
import base64
import json
import logging
import os
import sqlite3
import sys
from ctypes import byref, c_void_p, cast, sizeof
from datetime import datetime, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stderr)
import panel_personas as P  # noqa: E402
import script_lector_sdk as C  # noqa: E402
logging.getLogger().handlers = [logging.StreamHandler(sys.stderr)]
logging.getLogger().setLevel(logging.WARNING)

from SDK_Struct import (  # noqa: E402
    NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
    NET_FIND_RECORD_ACCESSCTLCARDREC_CONDITION_EX, NET_RECORDSET_ACCESS_CTL_CARDREC,
    NET_IN_FIND_RECORD_PARAM, NET_OUT_FIND_RECORD_PARAM,
    NET_IN_FIND_NEXT_RECORD_PARAM, NET_OUT_FIND_NEXT_RECORD_PARAM,
)
from SDK_Enum import (  # noqa: E402
    EM_LOGIN_SPAC_CAP_TYPE, EM_NET_RECORD_TYPE,
    EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD, EM_RECORD_ORDER_TYPE,
)


def entrar(ip):
    dev = next((d for d in P.DEVICES if d["ip"] == ip), None)
    if not dev:
        raise SystemExit("El lector %s no esta en config.json" % ip)
    ent = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY()
    ent.dwSize = sizeof(ent)
    ent.szIP = ip.encode()
    ent.nPort = int(dev.get("port", 37777))
    ent.szUserName = str(dev["user"]).encode()
    ent.szPassword = str(dev["password"]).encode()
    ent.emSpecCap = EM_LOGIN_SPAC_CAP_TYPE.TCP
    sal = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY()
    sal.dwSize = sizeof(sal)
    login_id, _i, err = P.client.LoginWithHighLevelSecurity(ent, sal)
    if not login_id:
        raise SystemExit("No pude entrar a %s: %s" % (ip, err))
    return int(login_id)


def ids_del_historial(login_id, ip, anios=3):
    """IDs que aparecen en el historial del equipo, con su nombre."""
    ahora = datetime.now()
    desde = ahora - timedelta(days=365 * anios)
    hasta = ahora + timedelta(hours=6)
    cond = NET_FIND_RECORD_ACCESSCTLCARDREC_CONDITION_EX()
    cond.dwSize = sizeof(cond)
    cond.bCardNoEnable = 0
    cond.bTimeEnable = 0
    cond.bRealUTCTimeEnable = 1
    cond.nStartRealUTCTime = int(desde.timestamp())
    cond.nEndRealUTCTime = int(hasta.timestamp())
    C._fill_net_time(cond.stStartTime, desde)
    C._fill_net_time(cond.stEndTime, hasta)
    cond.nOrderNum = 1
    cond.stuOrders[0].emField = \
        EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD.EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD_CREATETIME
    cond.stuOrders[0].emOrderType = EM_RECORD_ORDER_TYPE.EM_RECORD_ORDER_TYPE_ASCENT

    ini = NET_IN_FIND_RECORD_PARAM()
    ini.dwSize = sizeof(ini)
    ini.emType = EM_NET_RECORD_TYPE.ACCESSCTLCARDREC_EX
    ini.pQueryCondition = cast(byref(cond), c_void_p)
    fin = NET_OUT_FIND_RECORD_PARAM()
    fin.dwSize = sizeof(fin)
    if not P.client.FindRecord(login_id, ini, fin, 10000):
        return {}

    handle = fin.lFindeHandle
    pagina, encontrados = 200, {}
    while True:
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
        if not P.client.FindNextRecord(sig, res, 15000):
            break
        n = int(res.nRetRecordNum)
        if n <= 0:
            break
        for i in range(n):
            rec = arr[i]
            uid = C.decode_sdk_str(getattr(rec, "szUserIDEx", b"")) or C.decode_sdk_str(rec.szUserID)
            if not uid:
                continue
            nom = C.decode_sdk_str(rec.szCardNameEx) if bool(rec.bUseCardNameEx) else ""
            nom = nom or C.decode_sdk_str(rec.szCardName)
            if uid not in encontrados or (nom and not encontrados[uid]):
                encontrados[uid] = nom
        if n < pagina:
            break
    return encontrados


def ids_del_panel():
    conn = sqlite3.connect(P.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        return {str(r["dni"]): r["nombre"] for r in
                conn.execute("SELECT dni, nombre FROM personas")}
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="Respalda y vacia un lector")
    ap.add_argument("--ip", required=True)
    ap.add_argument("--aplicar", action="store_true", help="sin esto solo respalda y simula")
    args = ap.parse_args()

    sello = datetime.now().strftime("%Y%m%d-%H%M")
    carpeta = os.path.join(BASE, "respaldos")
    os.makedirs(carpeta, exist_ok=True)
    destino = os.path.join(carpeta, "lector_%s_%s.json" % (args.ip.replace(".", "_"), sello))

    P.client.InitEx(None)
    print("=" * 74)
    print("  %s   lector %s" % ("RESPALDO Y VACIADO" if args.aplicar
                                else "RESPALDO + SIMULACION del vaciado", args.ip))
    print("=" * 74)

    login_id = entrar(args.ip)
    try:
        print("\n1) armando la lista de usuarios del equipo...")
        candidatos = ids_del_historial(login_id, args.ip)
        print("   del historial              : %d" % len(candidatos))
        del_panel = ids_del_panel()
        for k, v in del_panel.items():
            candidatos.setdefault(k, v)
        print("   sumando los del panel      : %d candidatos" % len(candidatos))

        presentes = []
        for n, (uid, nom) in enumerate(sorted(candidatos.items()), start=1):
            en_equipo = P.sdk_consultar(login_id, uid)
            if en_equipo is None:
                continue
            presentes.append({"dni": uid, "nombre": en_equipo or nom or ""})
            if n % 100 == 0:
                print("   revisados %d, en el equipo %d" % (n, len(presentes)))
        print("   CARGADOS EN EL EQUIPO      : %d" % len(presentes))

        print("\n2) respaldando la biometria...")
        con_huella = 0
        for f in presentes:
            h = P.sdk_huella_leer(login_id, f["dni"])
            if h and h.get("datos"):
                f["huella_b64"] = base64.b64encode(bytes(h["datos"])).decode()
                f["huella_cantidad"] = h.get("cantidad")
                f["huella_packet_len"] = h.get("packet_len")
                f["huella_duress"] = h.get("duress", 0)
                con_huella += 1
        print("   con huella respaldada      : %d de %d" % (con_huella, len(presentes)))
    finally:
        try:
            P.client.Logout(login_id)
        except Exception:
            pass

    with open(destino, "w", encoding="utf-8") as fh:
        json.dump({"ip": args.ip, "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   "usuarios": presentes}, fh, ensure_ascii=False)
    print("\n   respaldo guardado en: %s" % destino)
    print("   tamano: %.1f KB" % (os.path.getsize(destino) / 1024))

    if not presentes:
        print("\n  El equipo ya esta vacio. Nada que borrar.")
        P.client.Cleanup()
        return 0

    if not args.aplicar:
        print("\n3) SIMULACION del vaciado")
        print("   se borrarian %d usuarios. Primeros 10:" % len(presentes))
        for f in presentes[:10]:
            print("      %-12s %-30s %s" % (f["dni"], (f["nombre"] or "")[:30],
                                            "con huella" if f.get("huella_b64") else "sin huella"))
        print("\n" + "-" * 74)
        print("  No se borro nada. El respaldo YA quedo hecho.")
        print("  Para vaciar de verdad, repetir con  --aplicar")
        P.client.Cleanup()
        return 0

    print("\n3) vaciando el equipo...")
    login_id = entrar(args.ip)
    borrados, fallaron = 0, []
    try:
        for n, f in enumerate(presentes, start=1):
            ok, msg = P.sdk_baja(login_id, f["dni"])
            if ok:
                borrados += 1
            else:
                fallaron.append((f["dni"], msg))
            if n % 25 == 0:
                print("   %d/%d borrados %d" % (n, len(presentes), borrados))
    finally:
        try:
            P.client.Logout(login_id)
        except Exception:
            pass

    print("\n   borrados: %d   fallaron: %d" % (borrados, len(fallaron)))
    for uid, msg in fallaron[:10]:
        print("      %-12s %s" % (uid, str(msg)[:50]))

    print("\n   verificando que quedo vacio...")
    login_id = entrar(args.ip)
    quedan = []
    try:
        for f in presentes:
            if P.sdk_consultar(login_id, f["dni"]) is not None:
                quedan.append(f["dni"])
    finally:
        try:
            P.client.Logout(login_id)
        except Exception:
            pass
    P.client.Cleanup()

    if quedan:
        print("   ATENCION: siguen %d en el equipo: %s" % (len(quedan), ", ".join(quedan[:15])))
    else:
        print("   verificado: el lector %s quedo vacio." % args.ip)
    print("\n   El respaldo esta en %s" % destino)
    return 0


if __name__ == "__main__":
    sys.exit(main())
