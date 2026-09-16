# -*- coding: utf-8 -*-
"""
Mira como viene la hora de un lector y que hora terminaria mandando a Odoo.

Odoo espera hora local de Argentina: el modulo hace `_ar_local_to_utc` sobre lo
que recibe. Si el equipo tiene mal el huso, o si informa la hora local en el
campo que el conector lee como UTC, la marca entra corrida y no hay forma de
darse cuenta mirando el log.

Esta herramienta no cambia nada. Compara, para las ultimas marcas del equipo,
las dos lecturas posibles del mismo dato y dice cual da una hora creible.

    python instalacion\\revisar_hora_lector.py --ip 192.168.31.200
    python instalacion\\revisar_hora_lector.py --ip 192.168.88.245 --marcas 10

Lo mas practico es marcar en el lector y correrlo enseguida: la lectura
correcta es la que dice "hace unos minutos".
"""

import argparse
import logging
import os
import sys
from ctypes import byref, c_void_p, cast, sizeof
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stderr)
import script_lector_sdk as C  # noqa: E402
logging.getLogger().handlers = [logging.StreamHandler(sys.stderr)]
logging.getLogger().setLevel(logging.WARNING)

from SDK_Struct import (  # noqa: E402
    NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
    NET_TIME_EX, NET_FIND_RECORD_ACCESSCTLCARDREC_CONDITION_EX,
    NET_RECORDSET_ACCESS_CTL_CARDREC, NET_IN_FIND_RECORD_PARAM, NET_OUT_FIND_RECORD_PARAM,
    NET_IN_FIND_NEXT_RECORD_PARAM, NET_OUT_FIND_NEXT_RECORD_PARAM)
from SDK_Enum import (  # noqa: E402
    EM_LOGIN_SPAC_CAP_TYPE, EM_NET_RECORD_TYPE,
    EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD, EM_RECORD_ORDER_TYPE)


def entrar(ip):
    dev = next((d for d in C.CFG["devices"] if d["ip"] == ip), None)
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
    login_id, _i, err = C.client.LoginWithHighLevelSecurity(ent, sal)
    if not login_id:
        raise SystemExit("No pude entrar a %s: %s" % (ip, err))
    return int(login_id)


def reloj_del_equipo(login_id):
    t = NET_TIME_EX()
    if not C.client.QueryDeviceTimeEx(login_id, t, 5000):
        return None, None
    try:
        return datetime(t.dwYear, t.dwMonth, t.dwDay, t.dwHour, t.dwMinute, t.dwSecond), int(t.dwUTC)
    except ValueError:
        return None, None


def ultimas_marcas(login_id, ip, dias, cuantas):
    ahora = datetime.now()
    desde = ahora - timedelta(days=dias)
    hasta = ahora + timedelta(hours=12)

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
    if not C.client.FindRecord(login_id, ini, fin, 10000):
        return []

    handle = fin.lFindeHandle
    pagina, encontradas = 200, []
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
        if not C.client.FindNextRecord(sig, res, 15000):
            break
        n = int(res.nRetRecordNum)
        if n <= 0:
            break
        for i in range(n):
            rec = arr[i]
            encontradas.append({
                "usuario": C.decode_sdk_str(getattr(rec, "szUserIDEx", b"")) or C.decode_sdk_str(rec.szUserID),
                "stu": C.sdk_time_to_datetime(rec.stuTime),
                "epoch": int(getattr(rec, "nCreateTimeRealUTC", 0) or 0),
                "mark": C.record_to_mark(rec, ip),
            })
        if n < pagina:
            break
    return encontradas[-cuantas:]


def hace(dt, ahora):
    if dt is None:
        return "-"
    seg = (ahora - dt).total_seconds()
    signo = "hace" if seg >= 0 else "dentro de"
    seg = abs(seg)
    if seg < 90:
        return "%s %d s" % (signo, seg)
    if seg < 5400:
        return "%s %d min" % (signo, round(seg / 60))
    return "%s %d h %d min" % (signo, int(seg // 3600), round((seg % 3600) / 60))


def main():
    ap = argparse.ArgumentParser(description="Revisa la hora de un lector")
    ap.add_argument("--ip", required=True)
    ap.add_argument("--marcas", type=int, default=5, help="cuantas marcas mostrar (default 5)")
    ap.add_argument("--dias", type=int, default=2, help="cuantos dias hacia atras buscar")
    args = ap.parse_args()

    ahora = datetime.now()
    ahora_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    desfase = round((ahora - ahora_utc).total_seconds() / 3600)

    print("=" * 92)
    print("  Hora del lector %s   y que hora terminaria en Odoo" % args.ip)
    print("=" * 92)
    print("  Esta PC        local %s    UTC %s    (UTC%+d)"
          % (ahora.strftime("%Y-%m-%d %H:%M:%S"), ahora_utc.strftime("%Y-%m-%d %H:%M:%S"), desfase))
    print("  device_time_is_utc en config.json: %s" % C.CFG.get("device_time_is_utc", True))

    C.client.InitEx(None)
    login_id = entrar(args.ip)
    try:
        reloj, marca_utc = reloj_del_equipo(login_id)
        if reloj is None:
            print("  El equipo no contesto que hora tiene.")
        else:
            dif_local = (reloj - ahora).total_seconds()
            dif_utc = (reloj - ahora_utc).total_seconds()
            print("  El lector dice: %s" % reloj.strftime("%Y-%m-%d %H:%M:%S"))
            if abs(dif_local) < 120:
                print("      -> coincide con la hora LOCAL de Argentina (%+d s)" % dif_local)
            elif abs(dif_utc) < 120:
                print("      -> coincide con UTC (%+d s): el equipo esta puesto en huso 0" % dif_utc)
            else:
                print("      -> no coincide ni con la local (%+.1f h) ni con UTC (%+.1f h)"
                      % (dif_local / 3600, dif_utc / 3600))
            # dwUTC viene con el instante real en formato epoch: es lo unico que
            # no depende de como este configurado el huso del equipo.
            if marca_utc and marca_utc > 1000000000:
                real = datetime.utcfromtimestamp(marca_utc)
                error = (real - ahora_utc).total_seconds()
                print("  Instante real del equipo (campo UTC): %s UTC   error %+d s"
                      % (real.strftime("%Y-%m-%d %H:%M:%S"), error))
                if abs(error) > 120:
                    print("      -> ATENCION: el reloj del equipo esta corrido %.1f h contra la realidad"
                          % (error / 3600))

        marcas = ultimas_marcas(login_id, args.ip, args.dias, args.marcas)
    finally:
        try:
            C.client.Logout(login_id)
        except Exception:
            pass
        C.client.Cleanup()

    if not marcas:
        print("\n  El equipo no devolvio marcas en los ultimos %d dias." % args.dias)
        print("  Marca una vez en el lector y volve a correr esto.")
        return 0

    print("\n  Ultimas %d marcas, leidas de las dos formas posibles:" % len(marcas))
    print("  %-10s %-20s %-20s %-20s" % ("usuario", "stuTime (crudo)", "epoch como UTC", "epoch como ya-local"))
    print("  " + "-" * 88)
    for m in marcas:
        como_utc = datetime.fromtimestamp(m["epoch"]) if m["epoch"] else None
        como_local = datetime.utcfromtimestamp(m["epoch"]) if m["epoch"] else None
        print("  %-10s %-20s %-20s %-20s"
              % (m["usuario"][:10],
                 m["stu"].strftime("%Y-%m-%d %H:%M:%S") if m["stu"] else "-",
                 como_utc.strftime("%Y-%m-%d %H:%M:%S") if como_utc else "-",
                 como_local.strftime("%Y-%m-%d %H:%M:%S") if como_local else "-"))

    u = marcas[-1]
    enviado = (u["mark"] or {}).get("check_time")
    como_utc = datetime.fromtimestamp(u["epoch"]) if u["epoch"] else None
    como_local = datetime.utcfromtimestamp(u["epoch"]) if u["epoch"] else None
    print("\n  " + "-" * 88)
    print("  La MAS NUEVA (usuario %s):" % u["usuario"])
    print("     como la lee hoy el conector : %-22s %s" % (enviado or "-", hace(como_utc, ahora)))
    print("     si el equipo informara local: %-22s %s"
          % (como_local.strftime("%Y-%m-%d %H:%M:%S") if como_local else "-", hace(como_local, ahora)))
    if como_utc and como_local:
        print("     diferencia entre las dos    : %d horas" % round(
            (como_local - como_utc).total_seconds() / 3600))
    print()
    print("  Eso es lo que se manda en 'check_time', y Odoo lo toma como hora local de")
    print("  Argentina. Si acabas de marcar, la linea correcta es la que dice 'hace' pocos")
    print("  minutos; si la correcta es la segunda, el conector esta restando de mas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
