# -*- coding: utf-8 -*-
"""
Deshace una baja en lote y deja los lectores igual a lo que dice la configuracion.

Hace dos cosas, las dos con simulacion por defecto:

  1. REACTIVAR: vuelve a poner activas a las personas que se dieron de baja en un
     lote concreto, identificado por la hora exacta en que se hizo. Se usa la hora
     y no la fecha a proposito: asi no se revierten bajas que alguien haya hecho
     a mano el mismo dia.

  2. LIMPIAR LECTORES: pide la baja de quien este cargado en un lector que, segun
     la configuracion actual, ya no le corresponde. Es lo que hace falta despues
     de volver atras un cambio de grupos, porque la reconciliacion del panel solo
     agrega, nunca saca.

Las altas de los reactivados NO se encolan aca: las arma sola la reconciliacion
del panel al arrancar, leyendo la configuracion. Por eso el orden es:
reactivar -> reiniciar el panel.

Uso, desde C:\\proyectos\\conector-dahua:

    # ver los lotes de baja que hay
    python instalacion\\restaurar_lectores.py --listar-lotes

    # simular
    python instalacion\\restaurar_lectores.py --reactivar-lote "2026-09-01 10:53:46" --limpiar-lectores

    # hacerlo
    python instalacion\\restaurar_lectores.py --reactivar-lote "2026-09-01 10:53:46" --limpiar-lectores --aplicar
"""

import argparse
import logging
import os
import sqlite3
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.chdir(BASE)

logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stderr)
import panel_personas as P  # noqa: E402
logging.getLogger().handlers = [logging.StreamHandler(sys.stderr)]
logging.getLogger().setLevel(logging.WARNING)


def conectar():
    c = sqlite3.connect(P.DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout = 30000")
    return c


def listar_lotes(sede):
    conn = conectar()
    try:
        print("=== lotes de baja en %s ===" % sede)
        for r in conn.execute("""
                SELECT actualizado, COUNT(*) n
                FROM personas WHERE sede = ? AND activo = 0
                GROUP BY actualizado HAVING n > 1
                ORDER BY actualizado DESC LIMIT 15""", (sede,)):
            print("   %s   %3d personas" % (r["actualizado"], r["n"]))
        print("\n(los lotes son los que comparten la hora exacta: los hizo una herramienta,")
        print(" no una persona clickeando de a una)")
    finally:
        conn.close()


def a_reactivar(sede, lote):
    conn = conectar()
    try:
        return [dict(r) for r in conn.execute("""
            SELECT dni, nombre, tipo, huella_cantidad FROM personas
            WHERE sede = ? AND activo = 0 AND actualizado = ?
            ORDER BY nombre""", (sede, lote))]
    finally:
        conn.close()


def sobrantes_en_lectores(sede):
    """Quien esta cargado donde ya no le toca, segun la config de ahora."""
    conn = conectar()
    try:
        fuera = []
        for p in conn.execute(
                "SELECT dni, nombre, tipo FROM personas WHERE sede = ? AND activo = 1", (sede,)):
            le_tocan = set(P.lectores_para(sede, p["tipo"]))
            for s in conn.execute("""
                    SELECT equipo FROM sincronizacion
                    WHERE sede = ? AND dni = ? AND estado = 'ok'""", (sede, p["dni"])):
                if s["equipo"] not in le_tocan:
                    fuera.append({"dni": p["dni"], "nombre": p["nombre"],
                                  "tipo": p["tipo"], "equipo": s["equipo"]})
        return fuera
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="Restaura personas y lectores")
    ap.add_argument("--sede", default="deposito")
    ap.add_argument("--listar-lotes", action="store_true")
    ap.add_argument("--reactivar-lote", default=None,
                    help='hora exacta del lote, ej "2026-09-01 10:53:46"')
    ap.add_argument("--limpiar-lectores", action="store_true",
                    help="pide la baja de quien este en un lector que ya no le toca")
    ap.add_argument("--aplicar", action="store_true", help="sin esto solo simula")
    args = ap.parse_args()

    if args.listar_lotes:
        listar_lotes(args.sede)
        return 0

    if not args.reactivar_lote and not args.limpiar_lectores:
        ap.error("hay que pedir --reactivar-lote, --limpiar-lectores o --listar-lotes")

    print("=" * 70)
    print("  %s   (sede %s)" % ("APLICANDO" if args.aplicar else "SIMULACION - no toca nada",
                                args.sede))
    print("=" * 70)

    gente = a_reactivar(args.sede, args.reactivar_lote) if args.reactivar_lote else []
    if args.reactivar_lote:
        print("\n1) REACTIVAR el lote de las %s: %d personas" % (args.reactivar_lote, len(gente)))
        for p in gente:
            print("     %-12s %-30s %-9s huellas=%s"
                  % (p["dni"], (p["nombre"] or "")[:30], p["tipo"] or "?",
                     p["huella_cantidad"] or 0))
        if not gente:
            print("     (ninguna: revisar la hora con --listar-lotes)")

    fuera = sobrantes_en_lectores(args.sede) if args.limpiar_lectores else []
    if args.limpiar_lectores:
        print("\n2) SACAR de lectores que ya no les corresponden: %d bajas" % len(fuera))
        porequipo = {}
        for f in fuera:
            porequipo.setdefault(f["equipo"], []).append(f)
        for eq, lista in sorted(porequipo.items()):
            print("     %-16s %3d personas (%s)"
                  % (eq, len(lista), ", ".join(sorted({x["tipo"] or "?" for x in lista}))))

    if not args.aplicar:
        print("\n" + "-" * 70)
        print("  SIMULACION. No se modifico nada. Para hacerlo, agregar  --aplicar")
        return 0

    conn = conectar()
    try:
        cr = conn.cursor()
        for p in gente:
            cr.execute("UPDATE personas SET activo = 1, actualizado = ? WHERE sede = ? AND dni = ?",
                       (P.ahora_txt(), args.sede, p["dni"]))
        for f in fuera:
            cr.execute("""
                UPDATE sincronizacion
                SET accion = ?, estado = ?, intentos = 0, ultimo_error = NULL, actualizado = ?
                WHERE sede = ? AND dni = ? AND equipo = ?
            """, (P.ACCION_BAJA, P.ESTADO_PENDIENTE, P.ahora_txt(),
                  args.sede, f["dni"], f["equipo"]))
        conn.commit()
    finally:
        conn.close()

    print("\n" + "-" * 70)
    print("  Listo: %d reactivadas, %d bajas encoladas." % (len(gente), len(fuera)))
    print()
    print("  AHORA HAY QUE REINICIAR EL PANEL. Las altas de los reactivados las")
    print("  arma la reconciliacion al arrancar, leyendo la configuracion:")
    print()
    print('      Stop-ScheduledTask "Panel RRHH"; Start-Sleep 3; Start-ScheduledTask "Panel RRHH"')
    print()
    print("  Y se sigue con:")
    print("      Get-Content logs\\panel_personas.log -Tail 30 -Wait")
    return 0


if __name__ == "__main__":
    sys.exit(main())
