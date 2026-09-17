# -*- coding: utf-8 -*-
"""
Monitoreo Sebigus — servidor web, dos sedes.

    python servidor.py

Levanta el panel en http://<ip-del-servidor>:8090. Solo biblioteca estandar.

Todo lo de datos cuelga de /api/<sede>/... y valida que cada IP recibida sea de
esa sede: administrar el Deposito nunca puede tocar una puerta de Lavalle.

La maquina donde corra tiene que llegar por red a las dos sedes (192.168.0.x y
192.168.88.x) y, para camaras, al NVR (192.168.5.2).
"""

import base64
import json
import logging
import mimetypes
import os
import queue
import secrets
import socket
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from urllib.parse import parse_qs, unquote, urlparse

import asistencia
import base
import gateway
import nucleo
import registro

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

CFG = {}
SESIONES = {}
_SES_LOCK = threading.Lock()
_HTTPS = False          # lo pone main() si se sirve por TLS (agrega Secure a la cookie)

# Qué sección/es del panel habilita cada recurso de /api/<sede>/... El usuario
# tiene que tener AL MENOS UNA de las secciones listadas. Es un filtro extra
# sobre el rol: un portero (rol operador + sección "puertas") no puede listar
# personas ni ver cámaras aunque llegue a la URL. Recurso no listado => sin
# chequeo de sección (igual pasa por el chequeo de rol donde corresponde).
_SECCION_GET = {
    "estado": ("en_vivo", "puertas", "personas", "asistencias"),
    "personas": ("personas",),
    "eventos": ("en_vivo", "asistencias"),
    "asistencias": ("asistencias",),
    "registro": ("registro",),
    "duplicados": ("personas",),
    "perfiles": ("personas",),
    "camaras": ("camaras",),
}
_SECCION_POST = {
    "personas": ("personas",),
    "unir": ("personas",),
    "separar": ("personas",),
    "perfiles": ("personas",),
    "importar": ("personas",),
    "sincronizar": ("personas",),
    "reintentar_credenciales": ("personas",),
    "abrir": ("puertas",),
    "asistencias": ("asistencias",),
    "registro": ("registro",),
}

log = logging.getLogger("monitoreo")


def configurar_log(nivel="INFO"):
    carpeta = os.path.join(BASE_DIR, "logs")
    os.makedirs(carpeta, exist_ok=True)
    formato = logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s: %(message)s")
    raiz = logging.getLogger()
    raiz.setLevel(nivel.upper())
    raiz.handlers.clear()
    archivo = RotatingFileHandler(os.path.join(carpeta, "monitoreo.log"),
                                  maxBytes=5_242_880, backupCount=3, encoding="utf-8")
    archivo.setFormatter(formato)
    raiz.addHandler(archivo)
    if sys.stdout is not None:
        consola = logging.StreamHandler(sys.stdout)
        consola.setFormatter(formato)
        raiz.addHandler(consola)


# ----------------------------------------------------------------------
# Sesiones
# ----------------------------------------------------------------------
def nueva_sesion(usuario):
    """Crea una sesion para un usuario ya autenticado. `usuario` es
    {usuario, nombre, rol}. Devuelve el token."""
    token = secrets.token_urlsafe(32)
    ahora = time.time()
    with _SES_LOCK:
        # De paso, limpiar las sesiones vencidas (si no, quedan para siempre las
        # de quien no vuelve a entrar: fuga lenta con el proceso dias arriba).
        for t in [t for t, s in SESIONES.items() if s["vence"] < ahora]:
            SESIONES.pop(t, None)
        SESIONES[token] = {**usuario, "vence": ahora + CFG.get("sesion_horas", 12) * 3600}
    return token


# Freno de fuerza bruta: por IP, cuenta fallos y bloquea un rato tras varios.
_FALLOS = {}                    # ip -> [cantidad, bloqueado_hasta]
_FALLOS_LOCK = threading.Lock()
FALLOS_MAX = 5                  # a partir de aca, bloqueo
BLOQUEO_SEG = 300              # 5 min


def login_bloqueado(ip):
    with _FALLOS_LOCK:
        reg = _FALLOS.get(ip)
        if reg and reg[1] > time.time():
            return int(reg[1] - time.time())
    return 0


def _login_fallo(ip):
    with _FALLOS_LOCK:
        reg = _FALLOS.get(ip) or [0, 0]
        reg[0] += 1
        if reg[0] >= FALLOS_MAX:
            reg[1] = time.time() + BLOQUEO_SEG
            reg[0] = 0
        _FALLOS[ip] = reg


def _login_ok(ip):
    with _FALLOS_LOCK:
        _FALLOS.pop(ip, None)


def sesion_de(token):
    """Devuelve los datos de la sesion {usuario, nombre, rol} si el token es
    valido y no vencio; None si no."""
    if not token:
        return None
    with _SES_LOCK:
        datos = SESIONES.get(token)
        if not datos:
            return None
        if datos["vence"] < time.time():
            SESIONES.pop(token, None)
            return None
    return datos


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MonitoreoSebigus"

    def log_message(self, formato, *args):
        log.debug("%s %s", self.address_string(), formato % args)

    # ---------------- utilidades ----------------
    def _json(self, datos, codigo=200):
        cuerpo = json.dumps(datos, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(cuerpo)

    def _error(self, mensaje, codigo=400):
        self._json({"error": mensaje}, codigo)

    def _cuerpo(self):
        largo = int(self.headers.get("Content-Length") or 0)
        if not largo:
            return {}
        try:
            return json.loads(self.rfile.read(largo).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _token(self):
        for parte in (self.headers.get("Cookie") or "").split(";"):
            if "=" in parte:
                k, v = parte.strip().split("=", 1)
                if k == "sesion":
                    return v
        return None

    def _sesion(self):
        return sesion_de(self._token())

    def _autorizado(self):
        return self._sesion() is not None

    def _rol(self):
        s = self._sesion()
        return s["rol"] if s else None

    def _exigir(self, rol_minimo):
        """True si el usuario tiene al menos ese rol. Si no, responde 403 (o 401
        si ni siquiera hay sesion) y devuelve False."""
        s = self._sesion()
        if not s:
            self._error("sesion vencida", 401)
            return False
        if base.ROLES.get(s["rol"], 0) < base.ROLES.get(rol_minimo, 99):
            log.warning("'%s' (%s) intento algo de rol %s desde %s",
                        s["usuario"], s["rol"], rol_minimo, self.address_string())
            self._error(f"tu rol ({s['rol']}) no puede hacer esto", 403)
            return False
        return True

    def _secciones(self):
        s = self._sesion()
        return s.get("secciones") or base.secciones_de_rol(s["rol"]) if s else []

    def _exigir_seccion(self, *opciones):
        """True si el usuario tiene ALGUNA de esas secciones habilitadas. Si no, 403/401."""
        s = self._sesion()
        if not s:
            self._error("sesion vencida", 401)
            return False
        if not (set(self._secciones()) & set(opciones)):
            log.warning("'%s' sin seccion %s desde %s", s["usuario"], opciones, self.address_string())
            self._error("no tenés acceso a esta sección", 403)
            return False
        return True

    def _sedes(self):
        """Sedes que el usuario puede ver. Lista guardada vacia = TODAS."""
        s = self._sesion()
        if not s:
            return []
        todas = list(nucleo.SEDES.keys())
        propias = [x for x in (s.get("sedes") or []) if x in todas]
        return propias or todas

    def _exigir_sede(self, sede):
        """True si el usuario puede ver esa sede. Si no, 403/401 y False."""
        s = self._sesion()
        if not s:
            self._error("sesion vencida", 401)
            return False
        if sede not in self._sedes():
            log.warning("'%s' sin acceso a la sede %s desde %s", s["usuario"], sede, self.address_string())
            self._error("no tenés acceso a esta sede", 403)
            return False
        return True

    def _sede_valida(self, sede):
        """Devuelve la sede si existe, o None (y responde 404)."""
        if sede in nucleo.SEDES:
            return sede
        self._error("sede desconocida", 404)
        return None

    def _ips_de_sede(self, sede, ips):
        """True si TODAS las ips son de la sede. Si no, responde 400 y False."""
        for ip in ips:
            if nucleo.sede_de(ip) != sede:
                self._error(f"la puerta {ip} no es de la sede {sede}", 400)
                return False
        return True

    # ---------------- GET ----------------
    def do_GET(self):
        ruta = urlparse(self.path)
        camino = unquote(ruta.path)
        params = parse_qs(ruta.query)

        if camino in ("/", "/index.html"):
            return self._archivo(os.path.join(WEB_DIR, "index.html"), "text/html; charset=utf-8")
        if camino.startswith("/web/"):
            destino = os.path.normpath(os.path.join(WEB_DIR, camino[5:]))
            if not destino.startswith(WEB_DIR):
                return self._error("ruta invalida", 403)
            return self._archivo(destino, mimetypes.guess_type(destino)[0] or "application/octet-stream")

        if camino == "/api/sesion":
            s = self._sesion()
            return self._json({"abierta": bool(s),
                               "usuario": s["usuario"] if s else None,
                               "nombre": s["nombre"] if s else None,
                               "rol": s["rol"] if s else None,
                               "puertas": s.get("puertas", []) if s else [],
                               "secciones": self._secciones() if s else [],
                               "sedes": self._sedes() if s else []})
        if camino == "/api/sedes":
            permitidas = self._sedes()
            return self._json([
                {"clave": c, "nombre": d["nombre"], "ids": d["ids"], "tiene_nvr": d["tiene_nvr"],
                 "solo_lectura": not d["escritura"],
                 "lectores": [{"ip": ip, "nombre": nucleo.ESTADO.get(ip, {}).get("nombre", ip)}
                              for ip in d["lectores"]],
                 "fichadores": asistencia.lectores_de(c)}
                for c, d in nucleo.SEDES.items() if c in permitidas])

        if not self._autorizado():
            return self._error("sesion vencida", 401)
        if camino == "/api/usuarios":
            if not self._exigir("admin"):
                return
            return self._json(base.listar_usuarios())
        if camino == "/api/stream":
            return self._stream()

        # /api/<sede>/...
        if camino.startswith("/api/"):
            partes = camino[5:].split("/")
            sede = partes[0]
            if sede in nucleo.SEDES:
                return self._get_sede(sede, partes[1:], params)
        return self._error("no encontrado", 404)

    def _get_sede(self, sede, resto, params):
        if not self._exigir_sede(sede):
            return
        seccion = resto[0] if resto else ""
        necesita = _SECCION_GET.get(seccion)
        if necesita and not self._exigir_seccion(*necesita):
            return
        if seccion == "estado":
            return self._json({"lectores": nucleo.estado_lectores(sede),
                               "resumen": nucleo.resumen_sede(sede),
                               "perfiles": base.listar_perfiles(sede)})
        if seccion == "personas" and len(resto) == 1:
            return self._json(base.listar_personas(
                sede, busqueda=(params.get("q") or [""])[0],
                lector=(params.get("lector") or [None])[0],
                solo_activos=(params.get("activos") or ["0"])[0] == "1"))
        if seccion == "personas" and len(resto) >= 2:
            try:
                pid = int(resto[1])
            except ValueError:
                return self._error("pid invalido", 400)
            if len(resto) == 3 and resto[2] == "foto":
                imagen = base.foto(sede, pid)
                if not imagen:
                    return self._error("sin foto", 404)
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Length", str(len(imagen)))
                self.send_header("Cache-Control", "max-age=60")
                self.end_headers()
                return self.wfile.write(imagen)
            datos = base.persona(sede, pid)
            return self._json(datos) if datos else self._error("no existe", 404)
        if seccion == "eventos":
            return self._json(base.listar_eventos(
                sede, limite=int((params.get("limite") or ["100"])[0]),
                lector=(params.get("lector") or [None])[0],
                pid=int(params["pid"][0]) if params.get("pid") else None,
                user_id=(params.get("user_id") or [None])[0],
                solo_rechazos=(params.get("rechazos") or ["0"])[0] == "1",
                desde_ts=(params.get("desde") or [None])[0],
                busqueda=(params.get("q") or [""])[0]))
        if seccion == "asistencias" and len(resto) == 1:
            # El LOG de fichadas de los fichadores de asistencia (area aparte de las
            # puertas): entrada/salida con la foto que saca el equipo al marcar.
            return self._json(base.listar_asistencias(
                sede=sede, limite=int((params.get("limite") or ["500"])[0]),
                offset=int((params.get("offset") or ["0"])[0]),
                lector=(params.get("lector") or [None])[0],
                tipo=(params.get("tipo") or [None])[0],
                user_id=(params.get("user_id") or [None])[0],
                solo_rechazos=(params.get("rechazos") or ["0"])[0] == "1",
                ocultar_rechazos=(params.get("solo_ok") or ["0"])[0] == "1",
                desde_ts=(params.get("desde") or [None])[0],
                hasta_ts=(params.get("hasta") or [None])[0],
                busqueda=(params.get("q") or [""])[0]))
        if seccion == "asistencias" and len(resto) == 3 and resto[2] == "foto":
            try:
                mid = int(resto[1])
            except ValueError:
                return self._error("id invalido", 400)
            rel = base.ruta_foto_asistencia(sede, mid)
            imagen = base.leer_foto_captura(rel) if rel else None
            if not imagen:
                return self._error("sin foto", 404)
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(imagen)))
            self.send_header("Cache-Control", "max-age=300")
            self.end_headers()
            return self.wfile.write(imagen)
        if seccion == "registro":
            return self._registro_get(sede, resto[1:], params)
        if seccion == "duplicados":
            return self._json(nucleo.duplicados(sede))
        if seccion == "perfiles":
            return self._json(base.listar_perfiles(sede))
        if seccion == "camaras":
            return self._get_camaras(sede, resto[1:])
        return self._error("no encontrado", 404)

    # ---------------- registro de asistencia (puente al panel de personas) ----
    def _registro_get(self, sede, resto, params):
        try:
            if not resto:
                return self._json({"personas": registro.listar(sede, (params.get("q") or [""])[0])})
            if resto[0] == "opciones":
                return self._json(registro.opciones())
            if resto[0] == "persona" and len(resto) >= 3 and resto[2] == "foto":
                imagen = registro.foto(sede, resto[1])
                if not imagen:
                    return self._error("sin foto", 404)
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Length", str(len(imagen)))
                self.send_header("Cache-Control", "max-age=60")
                self.end_headers()
                return self.wfile.write(imagen)
        except registro.RegistroError as e:
            return self._error(str(e), e.codigo)
        except Exception:
            log.exception("registro GET %s", resto)
            return self._error("no se pudo consultar el panel de personas", 502)
        return self._error("no encontrado", 404)

    def _registro_post(self, sede, resto, datos):
        try:
            if resto and resto[0] == "baja":
                dni = str(datos.get("dni") or "").strip()
                if not dni:
                    return self._error("falta el DNI", 400)
                return self._json(registro.baja(sede, dni))
            if not resto:
                cuerpo = dict(datos or {})
                cuerpo["sede"] = sede       # la sede la fija el server, no el navegador
                return self._json(registro.alta(cuerpo))
        except registro.RegistroError as e:
            return self._error(str(e), e.codigo)
        except Exception:
            log.exception("registro POST %s", resto)
            return self._error("no se pudo guardar en el panel de personas", 502)
        return self._error("no encontrado", 404)

    def _archivo(self, ruta, tipo):
        if not os.path.exists(ruta):
            return self._error("no encontrado", 404)
        with open(ruta, "rb") as fh:
            cuerpo = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    # ---------------- cámaras ----------------
    def _get_camaras(self, sede, resto):
        grabador = nucleo.GRABADORES.get(sede)
        if not resto:
            if not grabador:
                return self._json({"nvr": None, "canales": []})
            try:
                canales = grabador.canales()
            except Exception as exc:
                return self._json({"nvr": {"nombre": grabador.nombre, "en_linea": False,
                                           "error": str(exc)}, "canales": []})
            return self._json({
                "nvr": {"nombre": grabador.nombre, "ip": grabador.ip, "en_linea": True},
                "gateway": {"instalado": gateway.disponible(), "vivo": gateway.vivo(timeout=2)},
                "canales": canales})
        if not grabador:
            return self._error("esta sede no tiene NVR", 404)
        canal, _, accion = resto[0].partition("/")
        # resto viene ya partido por "/", asi que rearmo canal/accion
        if len(resto) >= 2:
            canal, accion = resto[0], resto[1]
        if not canal.isdigit():
            return self._error("canal invalido", 400)
        if accion == "foto":
            return self._camara_foto(grabador, int(canal))
        if accion == "vivo":
            return self._relay(grabador.abrir_mjpeg(int(canal),
                               subtipo=CFG.get("nvr_mjpeg_subtipo", 1)))
        if accion == "hd":
            return self._camara_hd(grabador, int(canal))
        return self._error("no encontrado", 404)

    def _camara_foto(self, grabador, canal):
        try:
            imagen = grabador.snapshot(canal)
        except Exception as exc:
            return self._error(str(exc), 502)
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", str(len(imagen)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(imagen)

    def _camara_hd(self, grabador, canal):
        if not gateway.disponible() or not gateway.vivo():
            return self._error("el gateway de video no esta corriendo", 503)
        cabeceras = {h: self.headers[h] for h in ("User-Agent", "Accept") if self.headers.get(h)}
        pedido = urllib.request.Request(gateway.url_hd(canal), headers=cabeceras)
        try:
            origen = urllib.request.urlopen(pedido, timeout=20)
        except Exception as exc:
            log.error("Gateway no entrego el canal %s: %s", canal, exc)
            return self._error("no se pudo abrir el canal", 502)
        self._bombear(origen)

    def _relay(self, origen):
        try:
            self.send_response(200)
            self.send_header("Content-Type", origen.headers.get("Content-Type",
                                                                "multipart/x-mixed-replace"))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            while not nucleo.PARAR.is_set():
                trozo = origen.read(8192)
                if not trozo:
                    break
                self.wfile.write(trozo)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                origen.close()
            except Exception:
                pass

    def _bombear(self, origen):
        try:
            self.send_response(200)
            self.send_header("Content-Type", origen.headers.get("Content-Type", "video/mp4"))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            while not nucleo.PARAR.is_set():
                trozo = origen.read(65536)
                if not trozo:
                    break
                self.wfile.write(trozo)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                origen.close()
            except Exception:
                pass

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        cola = nucleo.suscribir()
        try:
            self.wfile.write(b": conectado\n\n")
            self.wfile.flush()
            while not nucleo.PARAR.is_set():
                try:
                    mensaje = cola.get(timeout=20)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                self.wfile.write(f"data: {mensaje}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            nucleo.desuscribir(cola)

    # ---------------- POST / DELETE ----------------
    def do_POST(self):
        camino = unquote(urlparse(self.path).path)
        datos = self._cuerpo()

        if camino == "/api/entrar":
            ip = self.address_string()
            espera = login_bloqueado(ip)
            if espera:
                return self._error(f"demasiados intentos; probá de nuevo en {espera}s", 429)
            u = base.verificar_usuario(datos.get("usuario", ""), datos.get("clave", ""))
            if not u:
                _login_fallo(ip)
                log.warning("Login rechazado (usuario '%s') desde %s",
                            datos.get("usuario", ""), ip)
                return self._error("usuario o clave incorrectos", 401)
            _login_ok(ip)
            token = nueva_sesion(u)
            log.info("Login OK: %s (%s) desde %s", u["usuario"], u["rol"], self.address_string())
            cuerpo = json.dumps({"ok": True, **u}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.send_header("Set-Cookie", f"sesion={token}; Path=/; HttpOnly; SameSite=Strict"
                             + ("; Secure" if _HTTPS else ""))
            self.end_headers()
            return self.wfile.write(cuerpo)

        if not self._autorizado():
            return self._error("sesion vencida", 401)
        if camino == "/api/salir":
            with _SES_LOCK:
                SESIONES.pop(self._token(), None)
            return self._json({"ok": True})

        # Cambiar la propia clave: cualquier usuario logueado.
        if camino == "/api/mi-clave":
            ok, error = base.cambiar_clave_propia(
                self._sesion()["usuario"], datos.get("actual", ""), datos.get("nueva", ""))
            return self._json({"ok": True}) if ok else self._error(error, 400)

        # Gestion de usuarios: solo admin.
        if camino == "/api/usuarios" or camino.startswith("/api/usuarios/"):
            if not self._exigir("admin"):
                return
            return self._usuarios_post(camino, datos)

        # Lo de una sede es escritura. El rol se exige adentro de _post_sede:
        # casi todo pide supervisor+, pero "abrir" tambien lo puede un operador
        # sobre las puertas que tenga asignadas.
        if camino.startswith("/api/"):
            partes = camino[5:].split("/")
            sede = partes[0]
            if self._sede_valida(sede):
                return self._post_sede(sede, partes[1:], datos)
        return self._error("no encontrado", 404)

    def _puertas_validas(self, puertas):
        """Filtra la lista de IPs a solo las que son lectores conocidos."""
        if puertas is None:
            return None
        return [ip for ip in puertas if ip in nucleo.LECTORES]

    def _sedes_validas(self, sedes):
        """Filtra a claves de sede reales. None => None (no cambia)."""
        if sedes is None:
            return None
        return [s for s in sedes if s in nucleo.SEDES]

    def _usuarios_post(self, camino, datos):
        # secciones y puertas los limpia base (secciones válidas / IPs conocidas);
        # acá solo filtramos las puertas/sedes a valores reales para no guardar basura.
        if camino == "/api/usuarios":
            ok, error = base.crear_usuario(
                datos.get("usuario", ""), datos.get("clave", ""),
                datos.get("rol", ""), (datos.get("nombre") or "").strip(),
                puertas=self._puertas_validas(datos.get("puertas")),
                secciones=datos.get("secciones"),
                sedes=self._sedes_validas(datos.get("sedes")))
            return self._json({"ok": True}) if ok else self._error(error, 400)
        objetivo = unquote(camino[len("/api/usuarios/"):])
        if objetivo == self._sesion()["usuario"] and (
                datos.get("rol") not in (None, "admin") or datos.get("activo") is False):
            return self._error("no te podes quitar tu propio rol admin ni desactivarte", 400)
        ok, error = base.actualizar_usuario(
            objetivo, nombre=datos.get("nombre"), rol=datos.get("rol"),
            activo=datos.get("activo"), clave=datos.get("clave"),
            puertas=self._puertas_validas(datos.get("puertas")),
            secciones=datos.get("secciones"),
            sedes=self._sedes_validas(datos.get("sedes")))
        return self._json({"ok": True}) if ok else self._error(error, 400)

    def _post_sede(self, sede, resto, datos):
        if not self._exigir_sede(sede):
            return
        seccion = resto[0] if resto else ""

        # Primero el filtro por sección: sin la sección habilitada no se sigue,
        # aunque el rol alcanzara. Un portero (sección "puertas") solo abre.
        necesita = _SECCION_POST.get(seccion)
        if necesita and not self._exigir_seccion(*necesita):
            return

        # "abrir" (rol + puertas asignadas), "asistencias" (solo dispara una
        # lectura) y "registro" (lo habilita la seccion, no el rol: un RRHH sin
        # rango puede cargar gente) tienen su propio control. El resto pide
        # supervisor+.
        if seccion not in ("abrir", "asistencias", "registro") and not self._exigir("supervisor"):
            return

        if seccion == "asistencias" and len(resto) >= 2 and resto[1] == "sincronizar":
            return self._json({"nuevas": asistencia.sincronizar_sede(sede)})

        if seccion == "registro":
            return self._registro_post(sede, resto[1:], datos)

        if seccion == "personas" and len(resto) == 1:
            return self._guardar_persona(sede, None, datos)
        if seccion == "personas" and len(resto) >= 2:
            try:
                pid = int(resto[1])
            except ValueError:
                return self._error("pid invalido", 400)
            if len(resto) == 2:
                return self._guardar_persona(sede, pid, datos)
            accion = resto[2]
            if accion == "baja":
                if not base.persona(sede, pid):
                    return self._error("no existe", 404)
                incluir = [int(x) for x in datos.get("incluir_pids", []) if str(x).isdigit()]
                base.dar_de_baja(sede, pid, incluir)
                nucleo.avisar_trabajo(sede)
                return self._json({"ok": True})
            if accion == "reactivar":
                base.reactivar(sede, pid)
                nucleo.avisar_trabajo(sede)
                return self._json({"ok": True})
            if accion == "accesos" and len(resto) >= 5:
                ip = resto[3]
                if not self._ips_de_sede(sede, [ip]):
                    return
                ok, error = base.accion_acceso(sede, pid, ip, resto[4], datos)
                nucleo.avisar_trabajo(sede)
                return self._json({"ok": ok}) if ok else self._error(error, 409)
            return self._error("no encontrado", 404)

        if seccion == "unir":
            ok, error = base.unir(sede, int(datos["destino"]), int(datos["origen"]))
            return self._json({"ok": ok}) if ok else self._error(error, 409)
        if seccion == "separar":
            nuevo = base.separar(sede, int(datos["pid"]), datos.get("lectores", []))
            return self._json({"ok": bool(nuevo), "pid": nuevo})
        if seccion == "perfiles":
            nombre = (datos.get("nombre") or "").strip()
            if not nombre:
                return self._error("falta el nombre del perfil")
            lectores = [ip for ip in (datos.get("lectores") or []) if nucleo.sede_de(ip) == sede]
            base.guardar_perfil(sede, nombre, lectores)
            return self._json({"ok": True, "perfiles": base.listar_perfiles(sede)})
        if seccion == "abrir":
            return self._abrir_puerta(sede, datos)
        if seccion == "importar" and len(resto) >= 2 and resto[1] == "personas":
            resultado = nucleo.importar(sede, forzar=datos.get("forzar", []),
                                        forzar_sin=datos.get("forzar_sin", []))
            if resultado.get("error"):
                return self._json(resultado, 409)
            return self._json(resultado)
        if seccion == "importar" and len(resto) >= 2 and resto[1] == "historial":
            ips = [ip for ip in (datos.get("lectores") or nucleo.lectores_de(sede))
                   if nucleo.sede_de(ip) == sede]
            salida = [nucleo.importar_historial(ip, completo=bool(datos.get("completo"))) for ip in ips]
            nucleo.difundir("resumen", nucleo.resumen_sede(sede), sede)
            return self._json({"resultados": salida})
        if seccion == "sincronizar":
            for ip in nucleo.lectores_de(sede):
                nucleo._revivir(ip)
            nucleo.avisar_trabajo(sede)
            return self._json({"ok": True})
        if seccion == "reintentar_credenciales":
            ip = datos.get("lector")
            if not self._ips_de_sede(sede, [ip]):
                return
            nucleo.reintentar_credenciales(ip)
            return self._json({"ok": True})
        return self._error("no encontrado", 404)

    def do_DELETE(self):
        camino = unquote(urlparse(self.path).path)
        if not self._autorizado():
            return self._error("sesion vencida", 401)
        partes = camino[5:].split("/") if camino.startswith("/api/") else []
        if len(partes) < 2:
            return self._error("no encontrado", 404)
        # Borrar usuarios: solo admin.
        if partes[0] == "usuarios":
            if not self._exigir("admin"):
                return
            if unquote(partes[1]) == self._sesion()["usuario"]:
                return self._error("no te podes borrar a vos mismo", 400)
            ok, error = base.borrar_usuario(unquote(partes[1]))
            return self._json({"ok": True}) if ok else self._error(error, 400)
        sede = partes[0]
        if not self._sede_valida(sede):
            return
        if not self._exigir_sede(sede):
            return
        if not self._exigir_seccion("personas"):
            return
        if not self._exigir("supervisor"):
            return
        if partes[1] == "perfiles" and len(partes) >= 3:
            base.borrar_perfil(sede, unquote(partes[2]))
            return self._json({"ok": True, "perfiles": base.listar_perfiles(sede)})
        if partes[1] == "personas" and len(partes) >= 3:
            try:
                pid = int(partes[2])
            except ValueError:
                return self._error("pid invalido", 400)
            ok, error = base.borrar_persona(sede, pid)
            return self._json({"ok": ok}) if ok else self._error(error, 409)
        return self._error("no encontrado", 404)

    # ---------------- acciones ----------------
    def _guardar_persona(self, sede, pid, datos):
        nombre = (datos.get("nombre") or "").strip()
        if not nombre:
            return self._error("falta el nombre")
        lectores = datos.get("lectores") or []
        perfil = (datos.get("perfil") or "").strip()
        if perfil and not lectores:
            match = [p for p in base.listar_perfiles(sede) if p["nombre"] == perfil]
            lectores = match[0]["lectores"] if match else []
        if not self._ips_de_sede(sede, lectores):
            return

        foto_bytes = None
        if datos.get("foto"):
            crudo = datos["foto"].split(",", 1)[-1]
            try:
                foto_bytes = base64.b64decode(crudo)
            except Exception:
                return self._error("la foto no se pudo leer")
            if len(foto_bytes) > CFG.get("max_foto_kb", 200) * 1024:
                return self._error(f"la foto supera {CFG.get('max_foto_kb', 200)} KB")

        # Vigencia: al crear se pone sola en hoy + N años (config validez_anios, 10).
        # Al editar se conserva la que ya tenía (no está en el formulario).
        if pid is None:
            desde, hasta = base.vigencia_por_defecto(CFG.get("validez_anios", 10))
        else:
            previa = base.persona(sede, pid) or {}
            desde, hasta = previa.get("desde", "") or "", previa.get("hasta", "") or ""

        campos = {
            "nombre": nombre, "documento": (datos.get("documento") or "").strip(),
            "sector": (datos.get("sector") or "").strip(), "perfil": perfil,
            "desde": desde, "hasta": hasta,
            "notas": (datos.get("notas") or "").strip(), "activo": datos.get("activo", True),
            "id_preferido": (datos.get("id_preferido") or "").strip() or None,
            "foto_bytes": foto_bytes,
        }
        nuevo_pid, error = base.guardar_persona(sede, pid, campos, lectores,
                                                nucleo.ids_compartidos(sede))
        if error:
            return self._error(error, 409)
        nucleo.avisar_trabajo(sede)
        log.info("Guardada persona pid=%s (%s) en %d puerta(s) [%s]",
                 nuevo_pid, nombre, len(lectores), sede)
        return self._json({"ok": True, "persona": base.persona(sede, nuevo_pid)})

    def _puede_abrir(self, ip):
        """Puede abrir esa puerta si es supervisor/admin, o si es un operador con
        esa puerta asignada."""
        s = self._sesion()
        if not s:
            return False
        if base.ROLES.get(s["rol"], 0) >= base.ROLES["supervisor"]:
            return True
        return ip in (s.get("puertas") or [])

    def _abrir_puerta(self, sede, datos):
        ip = datos.get("lector")
        if not self._ips_de_sede(sede, [ip]):
            return
        if not self._puede_abrir(ip):
            log.warning("'%s' (%s) intento abrir %s sin permiso desde %s",
                        self._sesion()["usuario"], self._rol(), ip, self.address_string())
            return self._error("no tenés permiso para abrir esta puerta", 403)
        equipo = nucleo.LECTORES.get(ip)
        if not equipo:
            return self._error("no existe ese lector", 404)
        try:
            equipo.abrir_puerta()
        except Exception as exc:
            log.error("No se pudo abrir %s: %s", ip, exc)
            return self._error(str(exc), 502)
        log.warning("APERTURA REMOTA de %s [%s] desde %s", ip, sede, self.address_string())
        nucleo.difundir("apertura", {"lector": nucleo.ESTADO.get(ip, {}).get("nombre", ip),
                                     "ip": ip, "momento": base.ahora()}, sede)
        return self._json({"ok": True})


# ----------------------------------------------------------------------
# Instancia unica + gateway
# ----------------------------------------------------------------------
def _tomar_lock_instancia(puerto):
    """Un socket suelto al puerto detecta si ya hay otro panel. En Windows sin
    SO_REUSEADDR, dos servidores no pueden compartir el 8090."""
    prueba = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        prueba.bind(("0.0.0.0", puerto))
        prueba.close()
        return True
    except OSError:
        return False


def _arrancar_gateway():
    for sede, grabador in nucleo.GRABADORES.items():
        if not grabador or not gateway.disponible():
            continue
        try:
            canales = grabador.canales()
        except Exception as exc:
            log.warning("No se pudo leer canales del NVR de %s: %s", sede, exc)
            continue
        gateway.escribir_config(CFG, canales)
        if gateway.vivo():
            log.info("Gateway de video ya estaba corriendo")
            return
        gateway.arrancar()
        for _ in range(10):
            if gateway.vivo(timeout=2):
                log.info("Gateway de video arriba (%d canales)", len(canales))
                return
        log.warning("El gateway de video no respondio")
        return


def _sembrar_usuarios():
    """La primera vez crea 3 usuarios genericos (admin, supervisor, operador).
    Las claves por defecto se pueden dar por config.usuarios_iniciales; si no,
    se usan estas y hay que cambiarlas desde el panel."""
    if base.hay_usuarios():
        return
    # Solo se siembra el admin de arranque; desde ahi el admin crea a los demas
    # (con nombre real y el rol que corresponda).
    defecto = CFG.get("usuarios_iniciales") or [
        {"usuario": "admin", "clave": "admin.sebigus", "rol": "admin", "nombre": "Administrador"},
    ]
    creados = base.sembrar_usuarios(
        [(u["usuario"], u["clave"], u["rol"], u.get("nombre", "")) for u in defecto])
    if creados:
        log.warning("Usuarios creados por primera vez: %s. CAMBIA LAS CLAVES desde el panel "
                    "(Usuarios) o config.usuarios_iniciales.", ", ".join(creados))


def main():
    global CFG
    CFG = nucleo.cargar_config()
    configurar_log(CFG.get("log_level", "INFO"))

    puerto = CFG.get("puerto", 8090)
    if not _tomar_lock_instancia(puerto):
        raise SystemExit(f"ya hay algo escuchando en el puerto {puerto}: "
                         "¿otro panel corriendo? Cerralo antes de arrancar.")

    estado = base.iniciar(sede_v1=CFG.get("sede_v1"))
    log.info("Base: %s", estado)
    _sembrar_usuarios()
    nucleo.iniciar_sedes(CFG)
    log.info("Sedes: %s", ", ".join(f"{s} ({len(d['lectores'])} lectores)"
                                    for s, d in nucleo.SEDES.items()))
    _arrancar_gateway()
    nucleo.arrancar(CFG)
    if asistencia.arrancar(CFG, nucleo.PARAR):
        log.info("Asistencia: lectura de fichadores activada")
    registro.configurar(CFG)

    servidor = ThreadingHTTPServer((CFG.get("host", "0.0.0.0"), puerto), Handler)
    servidor.daemon_threads = True
    # HTTPS opcional: si config.https.enabled y estan el cert y la key, se envuelve
    # el socket. Apagado por defecto para no romper el acceso http:// actual.
    https = CFG.get("https") or {}
    esquema = "http"
    if https.get("enabled"):
        cert, key = https.get("cert", "certs/panel.crt"), https.get("key", "certs/panel.key")
        cert = cert if os.path.isabs(cert) else os.path.join(BASE_DIR, cert)
        key = key if os.path.isabs(key) else os.path.join(BASE_DIR, key)
        if os.path.exists(cert) and os.path.exists(key):
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            servidor.socket = ctx.wrap_socket(servidor.socket, server_side=True)
            esquema = "https"
            global _HTTPS
            _HTTPS = True
        else:
            log.warning("https.enabled pero falta el cert (%s) o la key (%s): sigo en HTTP",
                        cert, key)
    log.info("Panel escuchando en %s://%s:%s", esquema, CFG.get("host", "0.0.0.0"), puerto)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        log.info("Cerrando...")
    finally:
        nucleo.PARAR.set()
        servidor.shutdown()


if __name__ == "__main__":
    main()
