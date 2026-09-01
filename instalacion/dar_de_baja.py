# -*- coding: utf-8 -*-
"""
Da de baja en lote a las personas de una sede, opcionalmente filtrando por tipo.

Se apoya en el mismo mecanismo que usa el panel cuando apretas "Baja": marca a
la persona como inactiva y encola la baja SOLO en los lectores donde de verdad
esta cargada. El worker del panel la saca de los equipos por su cuenta, asi que
el panel tiene que estar corriendo para que la baja llegue al lector.

No borra nada de la base: la persona queda inactiva y con su historial. Si mas
adelante hay que volver a darla de alta, se la vuelve a guardar desde el panel.

Uso, desde C:\\proyectos\\conector-dahua:

    # ver que haria, sin tocar nada
    python instalacion\\dar_de_baja.py --sede deposito --tipo eventual

    # hacerlo
    python instalacion\\dar_de_baja.py --sede deposito --tipo eventual --aplicar

    # solo algunos, por DNI
    python instalacion\\dar_de_baja.py --sede deposito --dni 42885489 428885489 --aplicar
"""

import argparse
import logging
import os
import sqlite3
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.chdir(BASE)

# El panel escribe su propio log con rotacion; si este script escribiera ahi
# tambien, dos procesos rotarian el mismo archivo y se pisarian.
logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stderr)

import panel_personas as P  # noqa: E402  (necesita el chdir de arriba)

logging.getLogger().handlers = [logging.StreamHandler(sys.stderr)]
logging.getLogger().setLevel(logging.WARNING)


def personas_a_dar_de_baja(sede, tipo, dnis):
    conn = sqlite3.connect(P.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        sql = ["SELECT dni, nombre, tipo FROM personas WHERE sede = ? AND activo = 1"]
        args = [sede]
        if tipo:
            sql.append("AND tipo = ?")
            args.append(tipo)
        if dnis:
            sql.append("AND dni IN (%s)" % ",".join("?" * len(dnis)))
            args.extend(dnis)
        sql.append("ORDER BY nombre")
        return [dict(r) for r in conn.execute(" ".join(sql), args)]
    finally:
        conn.close()


def donde_esta(dni, sede):
    conn = sqlite3.connect(P.DB_PATH, timeout=30)
    try:
        return [r[0] for r in conn.execute(
            "SELECT equipo FROM sincronizacion WHERE sede = ? AND dni = ? AND estado = 'ok'",
            (sede, dni))]
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="Baja en lote de personas del panel")
    ap.add_argument("--sede", default="deposito")
    ap.add_argument("--tipo", default=None, help="fijo | eventual (si se omite, todos)")
    ap.add_argument("--dni", nargs="*", default=None, help="solo estos DNI")
    ap.add_argument("--aplicar", action="store_true",
                    help="sin esto solo muestra que haria")
    args = ap.parse_args()

    gente = personas_a_dar_de_baja(args.sede, args.tipo, args.dni)
    if not gente:
        print("No hay nadie que coincida con ese filtro.")
        return 0

    filtro = "sede=%s" % args.sede
    if args.tipo:
        filtro += ", tipo=%s" % args.tipo
    if args.dni:
        filtro += ", %d DNI puntuales" % len(args.dni)

    print("=" * 68)
    print("  %s BAJA de %d personas  (%s)"
          % ("APLICANDO" if args.aplicar else "SIMULACION -", len(gente), filtro))
    print("=" * 68)

    total_lectores = 0
    for p in gente:
        equipos = donde_esta(p["dni"], args.sede)
        total_lectores += len(equipos)
        print("  %-12s %-30s %-9s -> %s"
              % (p["dni"], (p["nombre"] or "")[:30], p["tipo"] or "?",
                 ", ".join(equipos) if equipos else "no esta en ningun lector"))

    print("-" * 68)
    print("  %d personas, %d bajas a encolar en lectores" % (len(gente), total_lectores))

    if not args.aplicar:
        print()
        print("  Esto fue una SIMULACION. No se toco nada.")
        print("  Para hacerlo de verdad, agregar  --aplicar")
        return 0

    for p in gente:
        P.marcar_baja(p["dni"], args.sede)

    print()
    print("  Listo: %d personas quedaron inactivas y las bajas estan encoladas." % len(gente))
    print("  El panel las va a ir sacando de los lectores; se sigue con:")
    print("      Get-Content logs\\panel_personas.log -Tail 20 -Wait")
    print()
    print("  OJO: el panel tiene que estar corriendo. Si esta detenido, las")
    print("  bajas quedan pendientes y se aplican cuando arranque.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
