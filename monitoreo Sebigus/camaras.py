# -*- coding: utf-8 -*-
"""
Cliente del NVR (grabador de las camaras).

Un NVR Dahua habla la misma API CGI que los fichadores, asi que esto es primo
hermano de `lector.py`. Verificado contra el DH-NVR804-32-HDS3/I del edificio:
32 canales, todos con imagen.

Tres formas de sacar video, de menos a mas:

  snapshot.cgi          un JPEG suelto. Sirve para el mosaico y para pegarle
                        una imagen a cada marca de una puerta.
  mjpg/video.cgi        video de verdad metido en un <img>, sin instalar nada.
                        Solo anda en el sub-stream (subtype=1): el principal
                        es H.265 y no se puede mostrar asi.
  rtsp://...:554/       el stream bueno. El navegador NO lo reproduce solo;
                        necesita un gateway aparte (go2rtc / MediaMTX).

**El navegador nunca habla con el NVR.** No puede: haria falta mandarle las
credenciales al cliente. El panel hace de intermediario y las claves se quedan
en el servidor.
"""

import threading
import urllib.error
import urllib.parse
import urllib.request


class ErrorNVR(Exception):
    pass


class NVR:
    def __init__(self, ip, usuario, clave, puerto=80, puerto_rtsp=554, nombre="NVR"):
        self.ip = ip
        self.usuario = usuario
        self.clave = clave
        self.puerto = puerto
        self.puerto_rtsp = puerto_rtsp
        self.nombre = nombre
        self._lock = threading.Lock()
        self._canales = None

    @property
    def base(self):
        return f"http://{self.ip}:{self.puerto}"

    def _abrir(self, ruta, timeout=20):
        """Cada llamada arma su propio opener.

        Compartir uno solo entre hilos hace que se pisen el nonce del digest y
        el equipo empiece a devolver 401. Con streams largos abiertos en
        paralelo eso pasa enseguida.
        """
        gestor = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        gestor.add_password(None, f"{self.base}/", self.usuario, self.clave)
        op = urllib.request.build_opener(
            urllib.request.HTTPDigestAuthHandler(gestor),
            urllib.request.HTTPBasicAuthHandler(gestor))
        try:
            return op.open(self.base + ruta, timeout=timeout)
        except urllib.error.HTTPError as exc:
            raise ErrorNVR(f"{self.nombre}: HTTP {exc.code} en {ruta.split('?')[0]}") from exc
        except Exception as exc:
            raise ErrorNVR(f"{self.nombre}: sin respuesta ({exc})") from exc

    def _texto(self, ruta, timeout=20):
        with self._abrir(ruta, timeout) as r:
            crudo = r.read()
        try:
            return crudo.decode("utf-8")
        except UnicodeDecodeError:
            return crudo.decode("latin-1")

    # ------------------------------------------------------------------
    def info(self):
        datos = {}
        for linea in self._texto("/cgi-bin/magicBox.cgi?action=getSystemInfo").splitlines():
            if "=" in linea:
                clave, valor = linea.split("=", 1)
                datos[clave.strip()] = valor.strip()
        return {"modelo": datos.get("updateSerial", ""),
                "serie": datos.get("serialNumber", ""),
                "tipo": datos.get("deviceType", "")}

    def en_linea(self):
        try:
            self._texto("/cgi-bin/magicBox.cgi?action=getSystemInfo", timeout=8)
            return True
        except ErrorNVR:
            return False

    def canales(self, refrescar=False):
        """Lista de canales con su nombre. El CGI numera desde 1, la config desde 0."""
        if self._canales is not None and not refrescar:
            return self._canales
        with self._lock:
            texto = self._texto(
                "/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle")
            nombres = {}
            for linea in texto.splitlines():
                if "].Name=" in linea:
                    indice = int(linea[linea.index("[") + 1:linea.index("]")])
                    nombres[indice] = linea.split("=", 1)[1].strip()
            self._canales = [{"canal": i + 1, "nombre": nombres[i] or f"Cámara {i + 1}",
                              "piso": _piso_de(nombres[i])}
                             for i in sorted(nombres) if i < self.max_canales]
        return self._canales

    max_canales = 32

    # ------------------------------------------------------------------
    def snapshot(self, canal, timeout=15):
        """Un JPEG del canal, ahora."""
        with self._abrir(f"/cgi-bin/snapshot.cgi?channel={int(canal)}", timeout) as r:
            return r.read()

    def abrir_mjpeg(self, canal, subtipo=1, timeout=20):
        """Devuelve la respuesta cruda del stream MJPEG, para ir relevandola.

        Solo el sub-stream (subtipo=1) sirve: el principal es H.265 y el
        equipo no lo transcodifica, se queda colgado hasta el timeout.
        """
        return self._abrir(
            f"/cgi-bin/mjpg/video.cgi?channel={int(canal)}&subtype={int(subtipo)}", timeout)

    def url_rtsp(self, canal, subtipo=0):
        """Para VLC o para un gateway tipo go2rtc. Lleva la clave adentro."""
        usuario = urllib.parse.quote(self.usuario, safe="")
        clave = urllib.parse.quote(self.clave, safe="")
        return (f"rtsp://{usuario}:{clave}@{self.ip}:{self.puerto_rtsp}"
                f"/cam/realmonitor?channel={int(canal)}&subtype={int(subtipo)}")


def _piso_de(nombre):
    """Saca el piso del nombre del canal para poder agrupar el mosaico.

    Los canales ya vienen rotulados como "3° Piso Entrada", "Planta Baja Reja".
    """
    limpio = (nombre or "").lower()
    if "planta baja" in limpio:
        return "Planta Baja"
    for numero, etiqueta in (("1", "1° Piso"), ("2", "2° Piso"), ("3", "3° Piso"),
                             ("4", "4° Piso"), ("5", "5° Piso")):
        if limpio.startswith(f"{numero}°") or limpio.startswith(f"{numero}º") \
                or f"{numero}° piso" in limpio:
            return etiqueta
    return "Otros"
