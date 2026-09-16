# -*- coding: utf-8 -*-
"""
Le pregunta al lector si de verdad tiene el rostro de cada persona.

El panel guarda la foto y anota que la subio, pero hasta ahora nadie le
preguntaba al equipo si la tiene. Esta herramienta compara las dos cosas y, si
se le pide, vuelve a subir las que falten.

    python instalacion\\revisar_foto_lector.py --sede lavalle
    python instalacion\\revisar_foto_lector.py --sede lavalle --reenviar
    python instalacion\\revisar_foto_lector.py --ip 192.168.88.245 --id 41304964

Sin --reenviar no toca nada: solo mira.
"""

import argparse
import logging
import os
import sys
from ctypes import POINTER, addressof, cast, create_string_buffer, memmove, sizeof

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

from SDK_Struct import (  # noqa: E402
    NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
    NET_IN_ACCESS_FACE_SERVICE_GET, NET_OUT_ACCESS_FACE_SERVICE_GET, NET_ACCESS_FACE_INFO)
from SDK_Enum import EM_LOGIN_SPAC_CAP_TYPE, EM_A_NET_EM_ACCESS_CTL_FACE_SERVICE  # noqa: E402
from SDK_Callback import C_ENUM  # noqa: E402


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


def rostro_en_el_lector(login_id, dni):
    """(plantillas, bytes_de_foto). None si el equipo no contesta la consulta."""
    ent = NET_IN_ACCESS_FACE_SERVICE_GET()
    ent.dwSize = sizeof(ent)
    ent.nUserNum = 1
    crudo = dni.encode("utf-8")[:31]
    # szUserID es un bloque plano de 100 IDs de 32 bytes: el primero va al inicio
    memmove(addressof(ent) + NET_IN_ACCESS_FACE_SERVICE_GET.szUserID.offset, crudo, len(crudo))

    infos = (NET_ACCESS_FACE_INFO * 1)()
    buffers = [create_string_buffer(300 * 1024) for _ in range(5)]
    for k in range(5):
        infos[0].nInFacePhotoLen[k] = 300 * 1024
        infos[0].pFacePhoto[k] = addressof(buffers[k])

    sal = NET_OUT_ACCESS_FACE_SERVICE_GET()
    sal.dwSize = sizeof(sal)
    sal.nMaxRetNum = 1
    sal.pFaceInfo = cast(infos, POINTER(NET_ACCESS_FACE_INFO))
    fallos = (C_ENUM * 1)()
    sal.pFailCode = cast(fallos, POINTER(C_ENUM))

    with P.SDK_LOCK:
        ok = P.client.OperateAccessFaceService(
            login_id, EM_A_NET_EM_ACCESS_CTL_FACE_SERVICE.NET_EM_ACCESS_CTL_FACE_SERVICE_GET,
            ent, sal, int(P.PANEL["sdk_timeout_ms"]))
    if not ok:
        return None
    i = infos[0]
    fotos = [i.nOutFacePhotoLen[k] for k in range(min(int(i.nFacePhoto), 5))]
    return int(i.nFaceData), sum(x for x in fotos if x > 0)


def main():
    ap = argparse.ArgumentParser(description="Compara las fotos del panel contra las del lector")
    ap.add_argument("--sede", help="revisa todos los lectores de esa sede")
    ap.add_argument("--ip", help="revisa solo ese lector")
    ap.add_argument("--id", action="append", default=[], help="solo estos IDs (se puede repetir)")
    ap.add_argument("--reenviar", action="store_true",
                    help="vuelve a subir la foto de quienes no la tengan en el equipo")
    args = ap.parse_args()

    if not args.sede and not args.ip:
        raise SystemExit("Hace falta --sede o --ip")

    sede = args.sede or P.sede_de_lector(args.ip) or P.SEDE_POR_DEFECTO
    ips = [args.ip] if args.ip else P.ips_de_sede_persona(sede)

    gente = [p for p in P.listar_personas("", sede) if p["tiene_foto"]]
    if args.id:
        gente = [p for p in gente if p["dni"] in args.id]

    print("=" * 78)
    print("  Fotos del panel vs. fotos en el lector   |   sede %s" % sede)
    print("=" * 78)
    print("  personas con foto en el panel : %d" % len(gente))
    print("  lectores a revisar            : %s" % ", ".join(ips))
    if not gente:
        print("\n  No hay a quien revisar.")
        return 0

    P.client.InitEx(None)
    faltan = []
    try:
        for ip in ips:
            print("\n" + "-" * 78)
            print("  LECTOR %s" % ip)
            print("-" * 78)
            print("  %-12s %-26s %-11s %-9s %s"
                  % ("ID", "nombre", "en el panel", "usuario", "rostro en el equipo"))
            login_id = entrar(ip)
            try:
                for p in gente:
                    if ip not in (p["lectores"] or []):
                        continue
                    usuario = P.sdk_consultar(login_id, p["dni"])
                    dato = rostro_en_el_lector(login_id, p["dni"])
                    if dato is None:
                        estado = "no contesta la consulta"
                    elif dato[0] > 0 or dato[1] > 0:
                        estado = "SI  (%d plantilla/s, %d bytes)" % dato
                    else:
                        estado = "NO TIENE ROSTRO"
                        faltan.append((ip, p))
                    print("  %-12s %-26s %-11s %-9s %s"
                          % (p["dni"], (p["nombre"] or "")[:26],
                             "si" if p["foto_en_lector"] else "sin subir",
                             "si" if usuario is not None else "NO ESTA", estado))
            finally:
                try:
                    P.client.Logout(login_id)
                except Exception:
                    pass

        print("\n" + "=" * 78)
        if not faltan:
            print("  Todas las fotos estan en los lectores.")
            return 0
        print("  Sin rostro en el equipo: %d" % len(faltan))
        if not args.reenviar:
            print("  Para subirlas, repetir el comando agregando  --reenviar")
            return 0

        print("\n  subiendo las que faltan...")
        por_lector = {}
        for ip, p in faltan:
            por_lector.setdefault(ip, []).append(p)
        subidas, fallaron = 0, []
        for ip, personas in por_lector.items():
            login_id = entrar(ip)
            try:
                for p in personas:
                    foto = P.obtener_foto(p["dni"], p["sede"] or P.SEDE_POR_DEFECTO)
                    if not foto:
                        fallaron.append((p["dni"], "el panel no tiene la foto"))
                        continue
                    ok, msg = P.sdk_foto(login_id, p["dni"], bytes(foto))
                    if not ok:
                        fallaron.append((p["dni"], msg))
                        continue
                    subidas += 1
                    dato = rostro_en_el_lector(login_id, p["dni"])
                    print("     %-12s %-26s subida, el equipo ahora dice: %s"
                          % (p["dni"], (p["nombre"] or "")[:26], dato))
            finally:
                try:
                    P.client.Logout(login_id)
                except Exception:
                    pass
        print("\n  subidas: %d   fallaron: %d" % (subidas, len(fallaron)))
        for dni, msg in fallaron:
            print("     %-12s %s" % (dni, msg))
    finally:
        P.client.Cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
