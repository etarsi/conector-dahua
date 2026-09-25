# -*- coding: utf-8 -*-
"""
Ver y cambiar si el panel ESCRIBE en las puertas de una sede (o de una puerta).

El Deposito arranca en solo lectura (escritura: false): las altas y bajas que se
hacen en el panel quedan "pendientes" y NO se mandan a los lectores hasta
habilitarla. Este script muestra que hay en cola y cambia la bandera en
config.json sin romperlo: hace un respaldo antes y guarda en UTF-8 SIN BOM (el
panel no arranca si el archivo tiene BOM, que es lo que agrega PowerShell 5.1
al guardar con -Encoding utf8).

    python escritura.py                     estado + pendientes de cada puerta
    python escritura.py 192.168.88.248 on   habilita solo esa puerta
    python escritura.py deposito on         habilita toda la sede
    python escritura.py deposito off        vuelve a solo lectura

Despues de cambiar:  Restart-Service monitoreo_sebigus  (la config se lee al arrancar).
"""

import json
import os
import shutil
import sqlite3
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(BASE_DIR, "config.json")
BASE = os.path.join(BASE_DIR, "data", "monitoreo.sqlite3")


def leer():
    with open(CONFIG, "r", encoding="utf-8-sig") as fh:     # tolera un BOM previo
        return json.load(fh)


def escritura_de_sede(sede):
    # Misma regla que nucleo.iniciar_sedes: sin la clave, solo las sedes de IDs
    # compartidos escriben (el Deposito, "por_lector", arranca en solo lectura).
    return sede.get("escritura", sede.get("ids") == "compartidos")


def pendientes():
    """(ip, permitido) -> [nombres] de lo que esta en cola. Solo lectura de la base."""
    if not os.path.exists(BASE):
        return {}
    cx = sqlite3.connect(f"file:{BASE}?mode=ro", uri=True)
    try:
        filas = cx.execute("SELECT a.lector, a.permitido, p.nombre FROM accesos a"
                           " JOIN personas p ON p.pid=a.pid WHERE a.estado='pendiente'").fetchall()
    finally:
        cx.close()
    cola = {}
    for ip, permitido, nombre in filas:
        cola.setdefault((ip, int(permitido)), []).append(nombre)
    return cola


def mostrar(cfg):
    cola = pendientes()
    for clave, sede in cfg["sedes"].items():
        propia = escritura_de_sede(sede)
        print(f"\n== {sede.get('nombre', clave)} ({clave}) - sede: "
              f"{'ESCRIBE' if propia else 'SOLO LECTURA'}")
        for lec in sede.get("lectores", []):
            ip = lec["ip"]
            escribe = lec.get("escritura", propia)
            altas, bajas = cola.get((ip, 1), []), cola.get((ip, 0), [])
            print(f"  {ip:16} {lec.get('nombre', '')[:26]:26} "
                  f"{'escribe' if escribe else 'SOLO LECTURA':13} "
                  f"en cola: {len(altas)} alta(s), {len(bajas)} baja(s)")
            # Las bajas se listan: al habilitar, sacan a esa gente de la puerta.
            for nombre in bajas:
                print(f"      baja en cola: {nombre}")


def cambiar(cfg, objetivo, valor):
    if objetivo in cfg["sedes"]:
        cfg["sedes"][objetivo]["escritura"] = valor
        return f"sede {objetivo}"
    for clave, sede in cfg["sedes"].items():
        for lec in sede.get("lectores", []):
            if lec["ip"] == objetivo:
                lec["escritura"] = valor
                return f"puerta {objetivo} ({lec.get('nombre', '')}) de {clave}"
    sys.exit(f"No encontre la sede ni la puerta '{objetivo}'. Sedes: {', '.join(cfg['sedes'])}")


def guardar(cfg):
    respaldo = f"{CONFIG}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(CONFIG, respaldo)
    texto = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
    json.loads(texto)                                   # que siga siendo JSON valido
    with open(CONFIG, "w", encoding="utf-8", newline="\n") as fh:   # utf-8 = sin BOM
        fh.write(texto)
    return respaldo


def main():
    cfg = leer()
    if len(sys.argv) == 1:
        mostrar(cfg)
        return
    if len(sys.argv) != 3 or sys.argv[2].lower() not in ("on", "off"):
        sys.exit(__doc__)
    objetivo, valor = sys.argv[1], sys.argv[2].lower() == "on"
    que = cambiar(cfg, objetivo, valor)
    respaldo = guardar(cfg)
    print(f"Listo: {que} -> escritura {'SI' if valor else 'NO'}. "
          f"Respaldo: {os.path.basename(respaldo)}")
    mostrar(cfg)
    print("\nPara que tome el cambio:  Restart-Service monitoreo_sebigus")


if __name__ == "__main__":
    main()
