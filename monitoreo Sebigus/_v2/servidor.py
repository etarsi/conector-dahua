# -*- coding: utf-8 -*-
"""
Monitoreo Sebigus — servidor web.

    python servidor.py

Levanta el panel en http://<ip-del-servidor>:8090 y arranca los hilos que
escuchan los lectores. Solo biblioteca estandar: no hay nada que instalar.

Ojo con donde corre: tiene que ser una maquina que llegue por red a la 192.168.0.x,
porque le habla directo a cada lector.
"""

import json
import logging
import mimetypes
import os
import queue
import secrets
import sys
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
import urllib.request
from urllib.parse import parse_qs, unquote, urlparse

import base
import camaras
import gateway
import nucleo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

CFG = {}
SESIONES = {}
_SES_LOCK = threading.Lock()

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
def nueva_sesion():
    token = secrets.token_urlsafe(32)
    with _SES_LOCK:
        SESIONES[token] = time.time() + CFG.get("sesion_horas", 12) * 3600
    return token


def sesion_valida(token):
    if not CFG.get("clave_panel"):
        return True          # panel sin clave: uso interno
    if not token:
        return False
    with _SES_LOCK:
        vence = SESIONES.get(token)
        if not vence:
            return False
        if vence < time.time():
            SESIONES.pop(token, None)
            return False
    return True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MonitoreoSebigus"

    def log_message(self, formato, *args):
        log.debug("%s %s", self.address_string(), formato % args)

    # ---------------- utilidades de respuesta ----------------
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
        crudo = self.rfile.read(largo)
        try:
            return json.loads(crudo.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def _token(self):
        galletas = self.headers.get("Cookie") or ""
        for parte in galletas.split(";"):
            if "=" in parte:
                clave, valor = parte.strip().split("=", 1)
                if clave == "sesion":
                    return valor
        return None

    def _autorizado(self):
        return sesion_valida(self._token())

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
            tipo = mimetypes.guess_type(destino)[0] or "application/octet-stream"
            return self._archivo(destino, tipo)

        if camino == "/api/sesion":
            return self._json({"abierta": self._autorizado(),
                               "pide_clave": bool(CFG.get("clave_panel"))})

        if not self._autorizado():
            return self._error("sesion vencida", 401)

        if camino == "/api/estado":
            return self._json({"lectores": nucleo.estado_lectores(),
                               "resumen": base.resumen(),
                               "perfiles": base.listar_perfiles()})

        if camino == "/api/personas":
            return self._json(base.listar_personas(
                busqueda=(params.get("q") or [""])[0],
                lector=(params.get("lector") or [None])[0],
                solo_activos=(params.get("activos") or ["0"])[0] == "1"))

        if camino.startswith("/api/personas/") and camino.endswith("/foto"):
            id_persona = camino[len("/api/personas/"):-len("/foto")]
            imagen = base.foto(id_persona)
            if not imagen:
                return self._error("sin foto", 404)
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(imagen)))
            self.send_header("Cache-Control", "max-age=60")
            self.end_headers()
            return self.wfile.write(imagen)

        if camino.startswith("/api/personas/"):
            datos = base.persona(camino[len("/api/personas/"):])
            return self._json(datos) if datos else self._error("no existe", 404)

        if camino == "/api/eventos":
            return self._json(base.listar_eventos(
                limite=int((params.get("limite") or ["100"])[0]),
                lector=(params.get("lector") or [None])[0],
                persona_id=(params.get("persona") or [None])[0],
                solo_rechazos=(params.get("rechazos") or ["0"])[0] == "1",
                desde_ts=(params.get("desde") or [None])[0],
                busqueda=(params.get("q") or [""])[0]))

        if camino == "/api/duplicados":
            return self._json(nucleo.duplicados())

        if camino == "/api/camaras":
            return self._camaras()

        if camino.startswith("/api/camaras/"):
            resto = camino[len("/api/camaras/"):]
            canal, _, accion = resto.partition("/")
            if not canal.isdigit():
                return self._error("canal invalido", 400)
            if accion == "foto":
                return self._camara_foto(int(canal))
            if accion == "vivo":
                return self._camara_vivo(int(canal))
            if accion == "hd":
                return self._camara_hd(int(canal))
            return self._error("no encontrado", 404)

        if camino == "/api/stream":
            return self._stream()

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

    # ---------------- camaras ----------------
    def _camaras(self):
        grabador = nucleo.GRABADOR
        if not grabador:
            return self._json({"nvr": None, "canales": []})
        try:
            canales = grabador.canales()
        except Exception as exc:
            return self._json({"nvr": {"nombre": grabador.nombre, "ip": grabador.ip,
                                       "en_linea": False, "error": str(exc)},
                               "canales": []})
        return self._json({
            "nvr": {"nombre": grabador.nombre, "ip": grabador.ip, "en_linea": True,
                    "modelo": CFG.get("nvr", {}).get("modelo", "")},
            "gateway": {"instalado": gateway.disponible(), "vivo": gateway.vivo(timeout=2)},
            "canales": canales})

    def _camara_foto(self, canal):
        grabador = nucleo.GRABADOR
        if not grabador:
            return self._error("no hay NVR configurado", 404)
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

    def _camara_vivo(self, canal):
        """Reenvia el MJPEG del NVR al navegador tal cual va llegando.

        El navegador no puede pedirselo directo al NVR: habria que mandarle las
        credenciales al cliente. Asi el panel es el unico que las conoce.
        """
        grabador = nucleo.GRABADOR
        if not grabador:
            return self._error("no hay NVR configurado", 404)
        subtipo = CFG.get("nvr", {}).get("mjpeg_subtipo", 1)
        try:
            origen = grabador.abrir_mjpeg(canal, subtipo=subtipo)
        except Exception as exc:
            return self._error(str(exc), 502)
        try:
            tipo = origen.headers.get("Content-Type", "multipart/x-mixed-replace")
            self.send_response(200)
            self.send_header("Content-Type", tipo)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            while not nucleo.PARAR.is_set():
                trozo = origen.read(8192)
                if not trozo:
                    break
                self.wfile.write(trozo)
        except (BrokenPipeError, ConnectionResetError, OSError):
            # El usuario cerro la pestana o cambio de camara: es lo normal.
            pass
        finally:
            try:
                origen.close()
            except Exception:
                pass

    def _camara_hd(self, canal):
        """La camara ampliada en 1080p, pasando por el gateway.

        go2rtc negocia el codec con el navegador: si la PC decodifica HEVC por
        hardware le manda el H.265 tal cual, y si no lo transcodifica a H.264.
        Por eso anda igual en una maquina vieja o por Escritorio Remoto.

        El navegador nunca ve al gateway: pide aca, con su cookie de sesion, y
        el panel relaya desde 127.0.0.1.
        """
        if not gateway.disponible():
            return self._error("el gateway de video no esta instalado", 503)
        if not gateway.vivo():
            return self._error("el gateway de video no esta corriendo", 503)
        cabeceras = {}
        # Le pasamos las capacidades del navegador para que negocie el codec.
        for h in ("User-Agent", "Accept"):
            if self.headers.get(h):
                cabeceras[h] = self.headers[h]
        pedido = urllib.request.Request(gateway.url_hd(canal), headers=cabeceras)
        try:
            origen = urllib.request.urlopen(pedido, timeout=20)
        except Exception as exc:
            log.error("Gateway no entrego el canal %s: %s", canal, exc)
            return self._error(f"no se pudo abrir el canal {canal}", 502)
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
            pass          # cerro la pestana o cambio de camara: normal
        finally:
            try:
                origen.close()
            except Exception:
                pass

    def _stream(self):
        """Eventos en vivo hacia el navegador (Server-Sent Events)."""
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
                    # Comentario SSE: mantiene viva la conexion sin ensuciar
                    # el flujo de eventos del navegador.
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
            clave = CFG.get("clave_panel") or ""
            if clave and datos.get("clave") != clave:
                log.warning("Intento de acceso rechazado desde %s", self.address_string())
                return self._error("clave incorrecta", 401)
            token = nueva_sesion()
            cuerpo = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.send_header("Set-Cookie",
                             f"sesion={token}; Path=/; HttpOnly; SameSite=Strict")
            self.end_headers()
            return self.wfile.write(cuerpo)

        if not self._autorizado():
            return self._error("sesion vencida", 401)

        if camino == "/api/personas":
            return self._guardar_persona(datos)

        if camino.startswith("/api/personas/") and camino.endswith("/baja"):
            id_persona = camino[len("/api/personas/"):-len("/baja")]
            base.dar_de_baja(id_persona)
            nucleo.avisar_trabajo()
            log.info("Baja de %s", id_persona)
            return self._json({"ok": True})

        if camino == "/api/abrir":
            return self._abrir_puerta(datos)

        if camino == "/api/perfiles":
            nombre = (datos.get("nombre") or "").strip()
            if not nombre:
                return self._error("falta el nombre del perfil")
            base.guardar_perfil(nombre, datos.get("lectores") or [])
            return self._json({"ok": True, "perfiles": base.listar_perfiles()})

        if camino == "/api/importar/personas":
            resultado = nucleo.importar_personas()
            if resultado.get("error"):
                log.warning("Importacion de padron rechazada: %s", resultado["error"])
                return self._json(resultado, 409)
            log.info("Importacion de padron: %s", resultado)
            return self._json(resultado)

        if camino == "/api/importar/historial":
            ips = datos.get("lectores") or list(nucleo.LECTORES)
            completo = bool(datos.get("completo"))
            salida = [nucleo.importar_historial(ip, completo=completo) for ip in ips]
            nucleo.difundir("resumen", base.resumen())
            return self._json({"resultados": salida})

        if camino == "/api/sincronizar":
            nucleo.avisar_trabajo()
            return self._json({"ok": True, "pendientes": len(base.pendientes(limite=999))})

        if camino == "/api/salir":
            with _SES_LOCK:
                SESIONES.pop(self._token(), None)
            return self._json({"ok": True})

        return self._error("no encontrado", 404)

    def do_DELETE(self):
        camino = unquote(urlparse(self.path).path)
        if not self._autorizado():
            return self._error("sesion vencida", 401)
        if camino.startswith("/api/perfiles/"):
            base.borrar_perfil(camino[len("/api/perfiles/"):])
            return self._json({"ok": True, "perfiles": base.listar_perfiles()})
        if camino.startswith("/api/personas/"):
            id_persona = camino[len("/api/personas/"):]
            # Se saca de los equipos primero; el borrado real lo hace el worker
            # cuando termina de limpiar.
            base.dar_de_baja(id_persona)
            nucleo.avisar_trabajo()
            return self._json({"ok": True})
        return self._error("no encontrado", 404)

    # ---------------- acciones ----------------
    def _guardar_persona(self, datos):
        id_persona = str(datos.get("id") or "").strip()
        nombre = (datos.get("nombre") or "").strip()
        if not id_persona or not nombre:
            return self._error("hacen falta el ID y el nombre")
        if not id_persona.isalnum():
            return self._error("el ID solo puede tener letras y numeros")

        lectores = datos.get("lectores")
        perfil = (datos.get("perfil") or "").strip()
        if perfil and lectores is None:
            coincide = [p for p in base.listar_perfiles() if p["nombre"] == perfil]
            lectores = coincide[0]["lectores"] if coincide else []
        lectores = [ip for ip in (lectores or []) if ip in nucleo.LECTORES]

        foto_bytes = None
        if datos.get("foto"):
            import base64
            crudo = datos["foto"]
            if "," in crudo:
                crudo = crudo.split(",", 1)[1]
            try:
                foto_bytes = base64.b64decode(crudo)
            except Exception:
                return self._error("la foto no se pudo leer")
            tope = CFG.get("max_foto_kb", 200) * 1024
            if len(foto_bytes) > tope:
                return self._error(f"la foto supera {CFG.get('max_foto_kb', 200)} KB")

        base.guardar_persona(
            id_persona=id_persona,
            nombre=nombre,
            lectores=lectores,
            documento=(datos.get("documento") or "").strip(),
            sector=(datos.get("sector") or "").strip(),
            perfil=perfil,
            desde=(datos.get("desde") or "").strip(),
            hasta=(datos.get("hasta") or "").strip(),
            clave=(datos.get("clave") or "").strip(),
            notas=(datos.get("notas") or "").strip(),
            foto_bytes=foto_bytes,
            activo=datos.get("activo", True),
        )
        nucleo.avisar_trabajo()
        log.info("Guardada persona %s (%s) en %d lector(es)", id_persona, nombre, len(lectores))
        return self._json({"ok": True, "persona": base.persona(id_persona)})

    def _abrir_puerta(self, datos):
        ip = datos.get("lector")
        equipo = nucleo.LECTORES.get(ip)
        if not equipo:
            return self._error("no existe ese lector", 404)
        try:
            equipo.abrir_puerta()
        except Exception as exc:
            log.error("No se pudo abrir %s: %s", equipo.nombre, exc)
            return self._error(str(exc), 502)
        log.warning("APERTURA REMOTA de %s desde %s", equipo.nombre, self.address_string())
        nucleo.difundir("apertura", {"lector": equipo.nombre, "ip": ip,
                                     "momento": base.ahora()})
        return self._json({"ok": True})


def _arrancar_gateway(grabador):
    """Levanta go2rtc si esta instalado. Sin el, el panel anda igual: solo se
    pierde la camara ampliada en 1080p."""
    if not gateway.disponible():
        log.info("Sin gateway de video: la camara ampliada queda en 704x576")
        return
    try:
        canales = grabador.canales()
    except Exception as exc:
        log.warning("No se pudo leer los canales para el gateway: %s", exc)
        return
    gateway.escribir_config(CFG, canales)
    if gateway.vivo():
        log.info("El gateway de video ya estaba corriendo")
        return
    gateway.arrancar()
    for _ in range(10):
        if gateway.vivo(timeout=2):
            log.info("Gateway de video arriba (%d canales)", len(canales))
            return
    log.warning("El gateway de video no respondio; la camara ampliada va a fallar")


def main():
    global CFG
    CFG = nucleo.cargar_config()
    configurar_log(CFG.get("log_level", "INFO"))
    base.iniciar()
    nucleo.iniciar_lectores(CFG)
    log.info("Lectores configurados: %d", len(nucleo.LECTORES))
    grabador = nucleo.iniciar_nvr(CFG)
    if grabador:
        log.info("NVR configurado: %s (%s)", grabador.nombre, grabador.ip)
        _arrancar_gateway(grabador)
    nucleo.arrancar(CFG)

    host = CFG.get("host", "0.0.0.0")
    puerto = CFG.get("puerto", 8090)
    servidor = ThreadingHTTPServer((host, puerto), Handler)
    servidor.daemon_threads = True
    log.info("Panel escuchando en http://%s:%s", host, puerto)
    if not CFG.get("clave_panel"):
        log.warning("El panel esta SIN CLAVE: cualquiera en la red puede abrir puertas. "
                    "Poné 'clave_panel' en config.json.")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        log.info("Cerrando...")
    finally:
        nucleo.PARAR.set()
        servidor.shutdown()


if __name__ == "__main__":
    main()
