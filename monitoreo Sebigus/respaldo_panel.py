# -*- coding: utf-8 -*-
"""
Respaldo diario del panel de personas (el registro de asistencia).

En su base estan la gente cargada en los fichadores, las huellas respaldadas y
el vinculo de cada uno con Odoo. Hasta ahora la unica copia era un .bak manual:
si se perdia, habia que volver a enrolar huellas y rehacer los vinculos a mano.

Una vez por dia arma un zip con:
  - panel_personas.sqlite3   copia consistente (API de backup de SQLite: sirve
                             aunque el panel este en uso, sin frenarlo)
  - config.json              el del conector y el panel de personas (raiz)
  - monitoreo/config.json    el de este panel

Va a C:\\proyectos\\conector-dahua\\data\\respaldos\\panel_personas-AAAA-MM-DD.zip
y se conservan los ultimos 14 dias (uno por dia: reiniciar no suma copias).
Los config llevan claves de los equipos y de Odoo: la carpeta se deja solo para
Administradores y SYSTEM.

Para restaurar: frenar la tarea "Panel RRHH", sacar panel_personas.sqlite3 del
zip a C:\\proyectos\\conector-dahua\\data\\ (reemplazando el que esta) y volver a
arrancar la tarea. Los config se restauran igual, a mano, si hiciera falta.

Configuracion (config.json de monitoreo, seccion "respaldo_panel", opcional):
    "respaldo_panel": {"activo": true, "dias": 14}
"""

import glob
import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime

log = logging.getLogger("monitoreo")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.normpath(os.path.join(BASE_DIR, ".."))
BASE_PANEL = os.path.join(RAIZ, "data", "panel_personas.sqlite3")
CARPETA = os.path.join(RAIZ, "data", "respaldos")
CONFIGS = (
    (os.path.join(RAIZ, "config.json"), "config.json"),
    (os.path.join(BASE_DIR, "config.json"), "monitoreo/config.json"),
)
PREFIJO = "panel_personas-"


def _sid_propio():
    """SID del usuario que corre el proceso (el servicio corre como SYSTEM; si
    alguien lo corre a mano con su usuario, tiene que poder seguir escribiendo)."""
    try:
        r = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True,
                           text=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        sid = r.stdout.strip().split(",")[-1].strip().strip('"')
        return sid if sid.startswith("S-1-") else None
    except Exception:
        return None


def _restringir(carpeta):
    """Deja la carpeta solo para Administradores, SYSTEM y el usuario que corre el
    panel (por SID, asi anda con Windows en castellano). Si falla, avisa en el log
    y sigue: el respaldo es mas importante que el permiso."""
    if sys.platform != "win32":
        return
    permisos = []
    for sid in ("S-1-5-32-544", "S-1-5-18", _sid_propio()):
        if sid and f"*{sid}:(OI)(CI)F" not in permisos:
            permisos += ["/grant:r", f"*{sid}:(OI)(CI)F"]
    try:
        r = subprocess.run(
            ["icacls", carpeta] + permisos + ["/inheritance:r"],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode != 0:
            log.warning("Respaldo del panel: no se pudo restringir %s: %s",
                        carpeta, (r.stdout + r.stderr).strip()[:200])
    except Exception as exc:
        log.warning("Respaldo del panel: no se pudo restringir %s: %s", carpeta, exc)


def _copiar_base(origen, destino):
    """Copia consistente con la API de backup y verifica que este sana."""
    src = sqlite3.connect(f"file:{origen}?mode=ro", uri=True, timeout=30)
    try:
        dst = sqlite3.connect(destino)
        try:
            src.backup(dst)
            estado = dst.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            dst.close()
    finally:
        src.close()
    if estado != "ok":
        raise RuntimeError(f"la copia de la base no esta sana: {estado}")


def respaldar(dias=14, base=None, carpeta=None, configs=None, hoy=None):
    """Arma el zip de hoy si todavia no esta. Devuelve la ruta del zip, o None si
    ya estaba (o no hay base del panel). Lanza la excepcion si algo falla."""
    base = base or BASE_PANEL
    carpeta = carpeta or CARPETA
    configs = CONFIGS if configs is None else configs
    if not os.path.exists(base):
        log.info("Respaldo del panel: no hay base en %s (el panel de personas no corre aca)", base)
        return None
    nueva = not os.path.isdir(carpeta)
    os.makedirs(carpeta, exist_ok=True)
    if nueva:
        _restringir(carpeta)
    fecha = (hoy or datetime.now()).strftime("%Y-%m-%d")
    destino = os.path.join(carpeta, f"{PREFIJO}{fecha}.zip")
    if os.path.exists(destino):
        return None

    with tempfile.TemporaryDirectory(prefix="resp_panel_") as tmp:
        copia = os.path.join(tmp, "panel_personas.sqlite3")
        _copiar_base(base, copia)
        parcial = destino + ".parcial"
        with zipfile.ZipFile(parcial, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(copia, "panel_personas.sqlite3")
            for ruta, nombre in configs:
                if os.path.exists(ruta):
                    z.write(ruta, nombre)
                else:
                    log.warning("Respaldo del panel: no esta %s, va sin ese config", ruta)
        with zipfile.ZipFile(parcial) as z:
            malo = z.testzip()
        if malo:
            os.remove(parcial)
            raise RuntimeError(f"el zip quedo danado ({malo})")
        os.replace(parcial, destino)        # recien ahora cuenta como respaldo hecho

    # Rotar: uno por dia, se quedan los ultimos `dias`
    if dias and dias > 0:
        zips = sorted(glob.glob(os.path.join(carpeta, f"{PREFIJO}????-??-??.zip")))
        for viejo in zips[:-dias]:
            try:
                os.remove(viejo)
            except OSError:
                pass
    return destino
