# -*- coding: utf-8 -*-
"""
Estado en memoria que comparten los hilos del panel.

Lo que se indexa por IP funciona para las dos sedes porque las IP son unicas en
todo config.json (lo valida config_sedes).

CANDADO[ip] serializa lo que LEE el padron de un lector y despues ESCRIBE en base
a esa lectura: el worker, la importacion, la conciliacion y la accion "es la
misma persona". Sin eso, un alta del worker entre la lectura y el COMMIT de una
importacion queda desmapeada. La vigilancia, los eventos en vivo y abrir la
puerta NO lo toman: no deciden nada sobre el padron.

Credenciales: ante un rechazo de usuario o clave, ningun hilo vuelve a pedirle
nada a ese lector hasta que el operador lo pida. Con unos 5 intentos fallidos por
minuto se bloquea la cuenta admin, tambien para SmartPSS y la web del equipo.
"""

import contextlib
import threading
import time

PARAR = threading.Event()

CFG = None
SEDE_DE_IP = {}      # ip -> sede
LECTORES = {}        # ip -> Lector (o LectorFalso en las pruebas)
LECTORES_DE = {}     # sede -> [ip, ...] en el orden del config
GRABADORES = {}      # sede -> NVR o None
CANDADO = {}         # ip -> threading.Lock
TRABAJO = {}         # sede -> threading.Event que despierta a su worker

ESTADO = {}          # ip -> dict con lo que se muestra en Puertas
_ESTADO_LOCK = threading.Lock()

ESPERAS = {}         # ip -> (monotonic hasta, escalon)
_ESPERAS_LOCK = threading.Lock()
ESCALONES_ESPERA = (20, 60, 120)


def configurar(cfg, lectores, grabadores=None):
    """Carga la config validada y los clientes ya construidos (reales o falsos)."""
    global CFG
    CFG = cfg
    SEDE_DE_IP.clear()
    SEDE_DE_IP.update(cfg["sede_de_ip"])
    LECTORES.clear()
    LECTORES.update(lectores)
    GRABADORES.clear()
    GRABADORES.update(grabadores or {})
    LECTORES_DE.clear()
    CANDADO.clear()
    TRABAJO.clear()
    with _ESPERAS_LOCK:
        ESPERAS.clear()
    with _ESTADO_LOCK:
        ESTADO.clear()
        for clave, sede in cfg["sedes"].items():
            LECTORES_DE[clave] = [l["ip"] for l in sede["lectores"]]
            TRABAJO[clave] = threading.Event()
            GRABADORES.setdefault(clave, None)
            for l in sede["lectores"]:
                CANDADO[l["ip"]] = threading.Lock()
                ESTADO[l["ip"]] = {
                    "ip": l["ip"], "sede": clave, "nombre": l["nombre"], "sector": l["sector"],
                    "modelo": l["modelo"], "en_linea": False, "puerta": "", "visto": "",
                    "error": "", "credenciales": False, "sin_credenciales": l["sin_credenciales"],
                    "serie": "", "escritura": l["escritura"],
                }


def config_sede(sede):
    return CFG["sedes"][sede]


def config_lector(ip):
    for l in CFG["sedes"][SEDE_DE_IP[ip]]["lectores"]:
        if l["ip"] == ip:
            return l
    raise KeyError(ip)


# ----------------------------------------------------------------------
# Estado visible de cada lector
# ----------------------------------------------------------------------
def poner_estado(ip, **campos):
    with _ESTADO_LOCK:
        if ip in ESTADO:
            ESTADO[ip].update(campos)


def estado_de(ip):
    with _ESTADO_LOCK:
        return dict(ESTADO.get(ip) or {})


def estados_de_sede(sede):
    with _ESTADO_LOCK:
        return [dict(ESTADO[ip]) for ip in LECTORES_DE.get(sede, []) if ip in ESTADO]


# ----------------------------------------------------------------------
# Credenciales
# ----------------------------------------------------------------------
def no_contactar(ip):
    """True si nadie tiene que pedirle nada a este lector (clave rechazada o sin credenciales)."""
    e = estado_de(ip)
    return bool(e.get("credenciales") or e.get("sin_credenciales"))


def marcar_credenciales(ip, rechazadas=True):
    poner_estado(ip, credenciales=bool(rechazadas),
                 error="usuario o clave rechazados: no se reintenta hasta pedirlo" if rechazadas else "")


# ----------------------------------------------------------------------
# Esperas por lector (20 s, 60 s, tope 120 s)
# ----------------------------------------------------------------------
def en_espera(ip, ahora=None):
    ahora = time.monotonic() if ahora is None else ahora
    with _ESPERAS_LOCK:
        hasta = (ESPERAS.get(ip) or (0, 0))[0]
    return ahora < hasta


def poner_espera(ip, ahora=None):
    """Agrega o sube la espera del lector. Devuelve los segundos que va a esperar."""
    ahora = time.monotonic() if ahora is None else ahora
    with _ESPERAS_LOCK:
        escalon = (ESPERAS.get(ip) or (0, -1))[1] + 1
        escalon = min(escalon, len(ESCALONES_ESPERA) - 1)
        segundos = ESCALONES_ESPERA[escalon]
        ESPERAS[ip] = (ahora + segundos, escalon)
    return segundos


def borrar_espera(ip):
    with _ESPERAS_LOCK:
        ESPERAS.pop(ip, None)


def borrar_esperas_sede(sede):
    for ip in LECTORES_DE.get(sede, []):
        borrar_espera(ip)


# ----------------------------------------------------------------------
# Trabajo y candados
# ----------------------------------------------------------------------
def avisar_trabajo(sede):
    evento = TRABAJO.get(sede)
    if evento is not None:
        evento.set()


@contextlib.contextmanager
def candados(ips):
    """Toma CANDADO de varias IP siempre en el mismo orden, para no trabarse."""
    tomados = []
    try:
        for ip in sorted(set(ips)):
            CANDADO[ip].acquire()
            tomados.append(ip)
        yield
    finally:
        for ip in reversed(tomados):
            CANDADO[ip].release()
