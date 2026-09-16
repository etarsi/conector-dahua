# -*- coding: utf-8 -*-
"""
Borra del lector los usuarios marcados en un Excel de revision.

Lee el archivo que genera la revision de inactivos y saca del equipo a los que
tengan SI en la columna "Borrar". Los que digan NO -o cualquier otra cosa- se
dejan como estan.

Va contra el lector por SDK, no por el panel: son usuarios que fueron cargados
directamente en el equipo y el panel no los conoce.

Simula por defecto. Para que borre de verdad hay que agregar --aplicar.

    python instalacion\\borrar_usuarios_lector.py --excel usuarios_a_borrar_254.xlsx --ip 192.168.88.254
    python instalacion\\borrar_usuarios_lector.py --excel usuarios_a_borrar_254.xlsx --ip 192.168.88.254 --aplicar
"""

import argparse
import logging
import os
import sys
from ctypes import sizeof
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stderr)
import panel_personas as P  # noqa: E402
logging.getLogger().handlers = [logging.StreamHandler(sys.stderr)]
logging.getLogger().setLevel(logging.WARNING)

from openpyxl import load_workbook  # noqa: E402
from SDK_Struct import (NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY,  # noqa: E402
                        NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY)
from SDK_Enum import EM_LOGIN_SPAC_CAP_TYPE  # noqa: E402


def leer_excel(ruta):
    """Filas con Borrar = SI. Devuelve [(id, nombre, ultima)]."""
    wb = load_workbook(ruta, read_only=True)
    ws = wb[wb.sheetnames[0]]
    filas = list(ws.values)
    cab = [str(c or "").strip().lower() for c in filas[0]]
    try:
        i_id = cab.index("id en el lector")
        i_nom = cab.index("nombre en el lector")
        i_ult = cab.index("ultima marca")
        i_bor = cab.index("borrar")
    except ValueError:
        raise SystemExit("El Excel no tiene las columnas esperadas: %s" % cab)

    elegidos, salteados = [], []
    for f in filas[1:]:
        if not f or f[i_id] is None:
            continue
        marca = str(f[i_bor] or "").strip().upper()
        item = (str(f[i_id]).strip(), str(f[i_nom] or ""), str(f[i_ult] or ""))
        (elegidos if marca == "SI" else salteados).append(item)
    return elegidos, salteados


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
    P.client.InitEx(None)
    login_id, _i, err = P.client.LoginWithHighLevelSecurity(ent, sal)
    if not login_id:
        raise SystemExit("No pude entrar a %s: %s" % (ip, err))
    return int(login_id)


def main():
    ap = argparse.ArgumentParser(description="Borra usuarios de un lector segun un Excel")
    ap.add_argument("--excel", required=True)
    ap.add_argument("--ip", required=True)
    ap.add_argument("--aplicar", action="store_true", help="sin esto solo simula")
    args = ap.parse_args()

    elegidos, salteados = leer_excel(args.excel)
    print("=" * 74)
    print("  %s   lector %s" % ("BORRANDO" if args.aplicar else "SIMULACION - no toca nada", args.ip))
    print("=" * 74)
    print("  marcados para borrar : %d" % len(elegidos))
    print("  se conservan         : %d" % len(salteados))
    if salteados:
        print("\n  se conservan estos:")
        for i, n, u in salteados[:20]:
            print("     %-12s %-30s ultima: %s" % (i, n[:30], u))
        if len(salteados) > 20:
            print("     ... y %d mas" % (len(salteados) - 20))

    if not elegidos:
        print("\n  No hay nadie marcado con SI. No hay nada que hacer.")
        return 0

    if not args.aplicar:
        print("\n  primeros 10 de los que se borrarian:")
        for i, n, u in elegidos[:10]:
            print("     %-12s %-30s ultima: %s" % (i, n[:30], u))
        print("\n" + "-" * 74)
        print("  SIMULACION. No se borro nada. Para hacerlo, agregar  --aplicar")
        return 0

    login_id = entrar(args.ip)
    borrados, no_estaban, fallaron = [], [], []
    try:
        for n, (uid, nombre, ult) in enumerate(elegidos, start=1):
            existia = P.sdk_consultar(login_id, uid) is not None
            if not existia:
                no_estaban.append((uid, nombre))
                continue
            ok, msg = P.sdk_baja(login_id, uid)
            if ok:
                borrados.append((uid, nombre))
            else:
                fallaron.append((uid, nombre, msg))
            if n % 25 == 0:
                print("   %d/%d  (borrados %d, fallaron %d)"
                      % (n, len(elegidos), len(borrados), len(fallaron)))
    finally:
        try:
            P.client.Logout(login_id)
        except Exception:
            pass

    print("\n" + "-" * 74)
    print("  borrados       : %d" % len(borrados))
    print("  ya no estaban  : %d" % len(no_estaban))
    print("  fallaron       : %d" % len(fallaron))
    for uid, nombre, msg in fallaron[:15]:
        print("     %-12s %-28s %s" % (uid, nombre[:28], msg[:40]))

    # --- verificacion: volver a preguntarle al equipo ---
    print("\n  verificando contra el lector...")
    login_id = entrar(args.ip)
    quedan = []
    try:
        for uid, nombre in borrados:
            if P.sdk_consultar(login_id, uid) is not None:
                quedan.append((uid, nombre))
    finally:
        try:
            P.client.Logout(login_id)
        except Exception:
            pass
    if quedan:
        print("  ATENCION: %d siguen en el equipo pese a la baja:" % len(quedan))
        for uid, nombre in quedan[:15]:
            print("     %-12s %s" % (uid, nombre[:35]))
    else:
        print("  verificado: ninguno de los %d borrados sigue en el equipo." % len(borrados))
    return 0


if __name__ == "__main__":
    sys.exit(main())
