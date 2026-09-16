# -*- coding: utf-8 -*-
"""
Asistencias: el LOG de entrada/salida de los 5 fichadores Dahua, como area aparte
de los accesos de puerta.

Idea: NO administramos estos equipos (eso lo hace otro conector que va a Odoo y no
tocamos). Solo LEEMOS sus marcas por HTTP (RecordFinder) y las mostramos con la
foto que el fichador saca al marcar. La foto NO se baja del equipo: el server ya
las guarda en disco (config `asistencia.capturas_dir`, p.ej. C:\\Lector\\Capturas,
en carpetas por fecha). El historial nos da la ruta relativa (campo URL, del tipo
/SnapShotFilePath/AAAA-MM-DD/hh/mm/archivo.jpg), que mapeamos a esa carpeta.

Solo lectura sobre los equipos: RecordFinder no escribe nada.
"""

import logging
import os
import threading
import time
from datetime import datetime, timedelta

import base
from lector import Lector

log = logging.getLogger("monitoreo")

LECTORES = {}            # ip -> Lector (con ._sede)
CFG = {}
CAPTURAS_DIR = ""
DIAS_FOTO = 7            # solo se busca foto de marcas mas nuevas que esto (las viejas ya se purgaron)
PARAR = threading.Event()
_ULTIMO_COUNT = {}       # ip -> ultimo getQuerySize visto (para no releer si no cambio)


def iniciar(cfg, parar=None):
    """Arma los lectores de asistencia desde config.asistencia. Devuelve cuantos."""
    global CFG, CAPTURAS_DIR, PARAR
    CFG = cfg.get("asistencia") or {}
    CAPTURAS_DIR = CFG.get("capturas_dir", "")
    if parar is not None:
        PARAR = parar
    LECTORES.clear()
    for eq in CFG.get("lectores", []):
        ip = eq["ip"]
        l = Lector(ip, eq.get("usuario", "admin"), eq.get("clave", ""), eq.get("nombre", ip))
        l._sede = eq.get("sede", "")
        LECTORES[ip] = l
    if LECTORES:
        log.info("Asistencia: %d fichador(es) configurados (capturas en %s)",
                 len(LECTORES), CAPTURAS_DIR or "(sin carpeta)")
    return len(LECTORES)


def _foto_desde_disco(user_id, ts):
    """Bytes del JPEG de captura de esa marca, leyendo del disco del server. El
    conector guarda la foto como `<dni>_<unixts>.jpg` en la carpeta del dia; la
    buscamos por (dni, hora) tomando la mas cercana en el tiempo. None si no esta
    (o si la marca es vieja: no vale la pena buscar)."""
    if not user_id or not ts or not CAPTURAS_DIR:
        return None
    ts = int(ts)
    if (time.time() - ts) > DIAS_FOTO * 86400:
        return None                                   # muy vieja: la foto ya no esta
    base_dt = datetime.fromtimestamp(ts)
    pref = f"{user_id}_"
    mejor, mejor_dist = None, 10 ** 9
    # Se mira la carpeta del dia y las de +/- 1 dia (por si el reloj del equipo esta
    # corrido o la marca cae cerca de medianoche).
    for delta in (0, -1, 1):
        carpeta = os.path.join(CAPTURAS_DIR, (base_dt + timedelta(days=delta)).strftime("%Y-%m-%d"))
        if not os.path.isdir(carpeta):
            continue
        try:
            nombres = os.listdir(carpeta)
        except OSError:
            continue
        for fn in nombres:
            if fn.startswith(pref) and fn.endswith(".jpg"):
                try:
                    fts = int(fn[len(pref):-4])
                except ValueError:
                    continue
                dist = abs(fts - ts)
                if dist < mejor_dist and dist <= 300:      # +/- 5 min
                    mejor_dist, mejor = dist, os.path.join(carpeta, fn)
    if mejor:
        try:
            with open(mejor, "rb") as fh:
                return fh.read()
        except OSError:
            return None
    return None


def sincronizar_uno(ip):
    """Trae las marcas nuevas de un fichador y las guarda con su foto. Devuelve
    cuantas marcas nuevas entraron."""
    l = LECTORES.get(ip)
    if not l:
        return 0
    # Atajo: si el total no cambio desde la ultima vez, no hay nada nuevo.
    try:
        total = l.cantidad_marcas()
    except Exception as exc:
        log.debug("Asistencia: %s sin getQuerySize (%s)", l.nombre, str(exc)[:60])
        total = None
    if total is not None and _ULTIMO_COUNT.get(ip) == total:
        return 0

    desde = base.ultimo_recno_asistencia(ip)
    try:
        nuevas = l.marcas(desde_recno=desde)
    except Exception as exc:
        log.warning("Asistencia: no pude leer %s: %s", l.nombre, str(exc)[:80])
        return 0
    if total is not None:
        _ULTIMO_COUNT[ip] = total
    if not nuevas:
        return 0

    sede = getattr(l, "_sede", "")
    filas = []
    for m in nuevas:
        foto_rel = ""
        jpg = _foto_desde_disco(m.get("id"), m.get("ts"))
        if jpg:
            try:
                foto_rel = base.guardar_foto_captura(sede, ip, m.get("id", ""), m.get("ts") or 0, jpg)
            except OSError:
                foto_rel = ""
        filas.append({**m, "sede": sede, "lector_nom": l.nombre, "foto": foto_rel})
    n = base.guardar_asistencias(filas)
    if n:
        con_foto = sum(1 for f in filas if f["foto"])
        log.info("Asistencia: %d marca(s) nuevas de %s (%d con foto)", n, l.nombre, con_foto)
    return n


def lectores_de(sede):
    """[{ip, nombre}] de los fichadores de esa sede (para el filtro de la UI)."""
    return [{"ip": ip, "nombre": l.nombre} for ip, l in LECTORES.items()
            if getattr(l, "_sede", "") == sede]


def sincronizar_sede(sede):
    """Trae lo nuevo de todos los fichadores de una sede ahora. Devuelve el total."""
    return sum(sincronizar_uno(ip) for ip, l in LECTORES.items()
               if getattr(l, "_sede", "") == sede)


def reintentar_fotos_recientes(horas=3):
    """Marcas recientes que quedaron sin foto (porque se leyeron justo antes de que
    el conector la guardara): se reintenta engancharla desde el disco. Devuelve cuantas."""
    if not CAPTURAS_DIR:
        return 0
    desde = int(time.time()) - horas * 3600
    n = 0
    for m in base.asistencias_sin_foto(desde):
        jpg = _foto_desde_disco(m["user_id"], m["ts"])
        if not jpg:
            continue
        try:
            rel = base.guardar_foto_captura(m["sede"], m["lector"], m["user_id"], m["ts"], jpg)
        except OSError:
            continue
        if base.poner_foto_asistencia(m["id"], rel):
            n += 1
    if n:
        log.info("Asistencia: %d foto(s) enganchadas a marcas que estaban sin foto", n)
    return n


def hilo_asistencia():
    """Cada `cada_segundos` recorre los fichadores y trae lo nuevo."""
    if not LECTORES:
        return
    cada = int(CFG.get("cada_segundos", 120))
    PARAR.wait(15)
    while not PARAR.is_set():
        for ip in list(LECTORES):
            if PARAR.is_set():
                break
            try:
                sincronizar_uno(ip)
            except Exception:
                log.exception("Asistencia: error sincronizando %s", ip)
        try:
            reintentar_fotos_recientes()
        except Exception:
            log.exception("Asistencia: error reintentando fotos")
        PARAR.wait(cada)


def arrancar(cfg, parar=None):
    """iniciar() + lanza el hilo. Devuelve el hilo (o None si no hay fichadores)."""
    if not iniciar(cfg, parar):
        return None
    h = threading.Thread(target=hilo_asistencia, name="asistencia", daemon=True)
    h.start()
    return h
