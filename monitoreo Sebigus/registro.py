# -*- coding: utf-8 -*-
"""
Puente al panel de personas (alta / baja de gente que ficha).

El alta de asistencia ya funciona en panel_personas.py: crea a la persona en
los fichadores por NetSDK y la sincroniza con Odoo (hr.employee). Esa logica es
delicada -toca nomina- asi que NO se reescribe: este modulo la reusa por HTTP.

La pagina de monitoreo no muestra el login del panel viejo. Este puente entra
una sola vez con la clave -que vive en el server, nunca viaja al navegador- y
cachea el token. El usuario ya autenticado en monitoreo no vuelve a loguearse:
lo unico que decide quien registra es la seccion "registro" de su usuario.

Configuracion (config.json de monitoreo, seccion "registro", opcional):
    "registro": { "base_url": "https://127.0.0.1:8443", "password": "..." }
Si falta, se toma del propio config.json del panel viejo (../config.json,
seccion "panel"): asi no hay que copiar la clave a dos lados.
"""

import json
import logging
import os
import ssl
import threading
import urllib.error
import urllib.request
from urllib.parse import urlparse

log = logging.getLogger("monitoreo.registro")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

_CFG = {"base_url": "", "password": ""}
_TOKEN = None
_LOCK = threading.Lock()
# El panel viejo sirve por https con certificado autofirmado; contra localhost
# la verificacion no aporta nada y solo haria fallar la llamada.
_CTX = ssl._create_unverified_context()
_TIMEOUT = 30           # el alta espera a Odoo (sincrono); la sync al lector es aparte


class RegistroError(Exception):
    """Error del panel de personas, con el codigo HTTP para reenviarlo tal cual."""
    def __init__(self, mensaje, codigo=502):
        super().__init__(mensaje)
        self.codigo = codigo


def _config_panel_viejo():
    """La clave y el puerto del panel viejo salen de su propio config.json, un
    nivel mas arriba. Gitignoreado, pero presente en el server."""
    ruta = os.path.normpath(os.path.join(BASE_DIR, "..", "config.json"))
    try:
        with open(ruta, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def configurar(cfg):
    """cfg = CFG de monitoreo. Arma base_url y clave del puente."""
    reg = (cfg or {}).get("registro") or {}
    base_url = reg.get("base_url")
    password = reg.get("password")
    if not base_url or not password:
        panel = (_config_panel_viejo().get("panel") or {})
        password = password or panel.get("password") or ""
        if not base_url:
            https = panel.get("https") or {}
            if https.get("enabled", True):
                base_url = f"https://127.0.0.1:{int(https.get('port', 8443))}"
            else:
                base_url = f"http://127.0.0.1:{int(panel.get('port', 8080))}"
    _CFG["base_url"] = (base_url or "").rstrip("/")
    _CFG["password"] = password or ""
    log.info("Registro: puente al panel de personas en %s (%s)",
             _CFG["base_url"] or "sin URL",
             "con clave" if _CFG["password"] else "SIN clave -> deshabilitado")


def disponible():
    return bool(_CFG["base_url"] and _CFG["password"])


# ---------------------------------------------------------------- HTTP crudo
def _bruto(metodo, ruta, cuerpo=None, binario=False, sin_token=False):
    """Una sola llamada al panel viejo. Devuelve (status, datos, content_type).
    No reintenta ni renueva el token."""
    datos = json.dumps(cuerpo).encode("utf-8") if cuerpo is not None else None
    req = urllib.request.Request(_CFG["base_url"] + ruta, data=datos, method=metodo)
    if datos is not None:
        req.add_header("Content-Type", "application/json")
    if _TOKEN and not sin_token:
        req.add_header("X-Panel-Token", _TOKEN)
    try:
        resp = urllib.request.urlopen(req, timeout=_TIMEOUT, context=_CTX)
        crudo, status = resp.read(), resp.status
        ctype = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:      # 4xx/5xx: el cuerpo trae el {"error"}
        crudo, status = e.read(), e.code
        ctype = e.headers.get("Content-Type", "") if e.headers else ""
    except (urllib.error.URLError, OSError) as e:
        raise RegistroError(f"no se pudo conectar con el panel de personas: {e}", 502)
    if binario and status == 200:
        return status, crudo, ctype
    try:
        return status, json.loads(crudo.decode("utf-8")), ctype
    except Exception:
        return status, {}, ctype


def _login():
    """Entra al panel y guarda el token. Se llama con _LOCK tomado."""
    global _TOKEN
    status, datos, _ = _bruto("POST", "/api/login", {"password": _CFG["password"]}, sin_token=True)
    if status == 200 and datos.get("token"):
        _TOKEN = datos["token"]
        return True
    log.warning("Registro: el panel de personas rechazo la clave (%s)", status)
    return False


def _asegurar_token():
    if _TOKEN:
        return True
    with _LOCK:
        return bool(_TOKEN) or _login()      # otro hilo pudo entrar mientras esperaba


# ---------------------------------------------------------------- API publica
def token_iframe():
    """Un token ya valido del panel viejo + como armar su URL, para embeberlo
    (iframe) sin volver a pedir la clave. La pagina de monitoreo arma
    <scheme>://<host>:<port>/?panelToken=<token>; el panel lo levanta de la URL
    y salta su pantalla de login. El alta/baja lo sigue haciendo el panel viejo.
    """
    global _TOKEN
    if not disponible():
        raise RegistroError("el registro de asistencia no esta configurado en el servidor", 503)
    if not _asegurar_token():
        # El token pudo vencer: se fuerza un login nuevo.
        with _LOCK:
            _TOKEN = None
        if not _asegurar_token():
            raise RegistroError("no se pudo autenticar con el panel de personas", 502)
    u = urlparse(_CFG["base_url"])
    puerto = u.port or (443 if u.scheme == "https" else 80)
    return {"token": _TOKEN, "scheme": u.scheme or "https", "port": puerto}
