# -*- coding: utf-8 -*-
"""
go2rtc: el puente entre el RTSP del NVR y el navegador.

El navegador no reproduce RTSP, y tampoco conviene que hable con el NVR. go2rtc
se queda en el medio: abre **una sola** sesion RTSP por camara contra el NVR y
la reparte a todos los navegadores que esten mirando. Con tres operadores
abiertos, el NVR ve la misma carga que con uno.

Se ata a 127.0.0.1: NO es alcanzable desde la red. El unico que le habla es el
panel, que antes valida su cookie de sesion. Asi la clave del NVR se queda del
lado del servidor, igual que hoy.

Dos streams por camara, porque sirven para cosas distintas:

    camN_sub   sub-stream (MJPEG 704x576) -> el mosaico. Liviano.
    camN_hd    principal (H.265 1080p)    -> la camara ampliada. Pesado.

`camN_hd` se transcodifica a H.264 y NO se deja en H.265 a proposito: Chrome y
Edge no traen decodificador HEVC por software, dependen de que la PC tenga GPU
que lo soporte. Cuando no la tiene el modo de falla es **pantalla negra sin
ningun error**, que es imposible de diagnosticar desde soporte. H.264 anda en
cualquier maquina, en RDP y en una VM.

Los streams son on-demand: go2rtc se conecta al NVR recien cuando alguien mira,
y corta cuando deja de mirar. Tener las 32 configuradas no cuesta nada.
"""

import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CARPETA = os.path.join(BASE_DIR, "gateway")
EXE = os.path.join(CARPETA, "go2rtc.exe")
YAML = os.path.join(CARPETA, "go2rtc.yaml")

API = "127.0.0.1:1984"


def _rtsp(nvr, canal, subtipo):
    usuario = urllib.parse.quote(nvr.get("usuario", "admin"), safe="")
    clave = urllib.parse.quote(nvr.get("clave", ""), safe="")
    puerto = nvr.get("puerto_rtsp", 554)
    return (f"rtsp://{usuario}:{clave}@{nvr['ip']}:{puerto}"
            f"/cam/realmonitor?channel={canal}&subtype={subtipo}")


def escribir_config(cfg, canales):
    """Arma go2rtc.yaml desde config.json. Se regenera en cada arranque."""
    nvr = cfg.get("nvr") or {}
    if not nvr.get("ip"):
        return None
    lineas = [
        "# GENERADO POR gateway.py — no editar a mano, se pisa en cada arranque.",
        "# Los datos salen de la seccion \"nvr\" de config.json.",
        "",
        "api:",
        f'  listen: "{API}"',
        "",
        "# Sin escuchas externas: al gateway solo le habla el panel, por loopback.",
        "rtsp:",
        '  listen: ""',
        "webrtc:",
        '  listen: ""',
        "",
        "log:",
        "  level: warn",
        "",
        "streams:",
    ]
    for c in canales:
        n = c["canal"]
        lineas.append(f"  # {c['nombre']}")
        lineas.append(f"  cam{n}_sub:")
        lineas.append(f"    - {_rtsp(nvr, n, 1)}")
        lineas.append(f"  cam{n}_hd:")
        lineas.append(f"    - {_rtsp(nvr, n, 0)}")
        # Transcodifica solo si el navegador no puede con el codec original.
        lineas.append(f"    - 'ffmpeg:cam{n}_hd#video=h264#hardware'")
    os.makedirs(CARPETA, exist_ok=True)
    with open(YAML, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lineas) + "\n")
    return YAML


def disponible():
    return os.path.exists(EXE)


def arrancar():
    """Levanta go2rtc en segundo plano. Devuelve el Popen, o None si no esta."""
    if not disponible():
        return None
    return subprocess.Popen(
        [EXE, "-config", YAML], cwd=CARPETA,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def vivo(timeout=4):
    try:
        with urllib.request.urlopen(f"http://{API}/api/streams", timeout=timeout):
            return True
    except Exception:
        return False


def url_cuadro(canal):
    """Un JPEG suelto del sub-stream. Para las miniaturas del mosaico."""
    return f"http://{API}/api/frame.jpeg?src=cam{canal}_sub"


def url_mjpeg(canal):
    """MJPEG del sub-stream, para ver una camara en movimiento sin H.264."""
    return f"http://{API}/api/stream.mjpeg?src=cam{canal}_sub"


def url_hd(canal):
    """fMP4 del stream principal, ya en H.264. Para la camara ampliada."""
    return f"http://{API}/api/stream.mp4?src=cam{canal}_hd"
