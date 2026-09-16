# -*- coding: utf-8 -*-
"""
El motor: mantiene los lectores conectados, escucha los eventos en vivo y
aplica a los equipos lo que se decide en la base.

Tres hilos por su cuenta:
  - uno por lector, escuchando el stream de eventos (monitoreo en vivo)
  - uno que vigila el estado de los equipos (en linea, puerta abierta/cerrada)
  - uno que aplica los accesos pendientes

Nada de esto bloquea al servidor web: la pagina siempre responde, aunque haya
lectores caidos.
"""

import json
import logging
import os
import queue
import threading
import time
import unicodedata
from datetime import datetime
from difflib import SequenceMatcher

import base
from camaras import NVR
from lector import ErrorLector, Lector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(BASE_DIR, "config.json")

log = logging.getLogger("monitoreo")

PARAR = threading.Event()
HAY_TRABAJO = threading.Event()

LECTORES = {}          # ip -> Lector
ESTADO = {}            # ip -> {en_linea, puerta, visto, error, usuarios}
_ESTADO_LOCK = threading.Lock()

GRABADOR = None        # NVR, o None si no esta configurado

_SUSCRIPTORES = []     # colas de los navegadores conectados (SSE)
_SUS_LOCK = threading.Lock()


# ----------------------------------------------------------------------
# Configuracion
# ----------------------------------------------------------------------
def cargar_config():
    if not os.path.exists(CONFIG):
        raise SystemExit(
            "Falta config.json. Copia config.example.json a config.json y "
            "pone la clave de los lectores.")
    with open(CONFIG, "r", encoding="utf-8") as fh:
        return json.load(fh)


def iniciar_lectores(cfg):
    for equipo in cfg.get("lectores", []):
        ip = equipo["ip"]
        LECTORES[ip] = Lector(
            ip=ip,
            usuario=equipo.get("usuario", cfg.get("usuario", "admin")),
            clave=equipo.get("clave", cfg.get("clave", "")),
            nombre=equipo.get("nombre", ip),
            puerto=equipo.get("puerto", 80),
            canal=equipo.get("canal", 1),
        )
        with _ESTADO_LOCK:
            ESTADO[ip] = {"ip": ip, "nombre": equipo.get("nombre", ip),
                          "sector": equipo.get("sector", ""), "modelo": equipo.get("modelo", ""),
                          "en_linea": False, "puerta": "", "visto": "", "error": "",
                          "usuarios": None}
    return LECTORES


def iniciar_nvr(cfg):
    """Arma el cliente del NVR si esta configurado. Sin NVR el panel anda igual."""
    global GRABADOR
    datos = cfg.get("nvr") or {}
    if not datos.get("ip") or datos.get("clave") in (None, "", "CAMBIAR"):
        log.info("Sin NVR configurado: la vista de camaras queda vacia")
        return None
    GRABADOR = NVR(ip=datos["ip"], usuario=datos.get("usuario", "admin"),
                   clave=datos["clave"], puerto=datos.get("puerto", 80),
                   puerto_rtsp=datos.get("puerto_rtsp", 554),
                   nombre=datos.get("nombre", "NVR"))
    GRABADOR.max_canales = datos.get("max_canales", 32)
    return GRABADOR


def lectores_config(cfg):
    return [{"ip": e["ip"], "nombre": e.get("nombre", e["ip"]),
             "sector": e.get("sector", ""), "modelo": e.get("modelo", "")}
            for e in cfg.get("lectores", [])]


# ----------------------------------------------------------------------
# Difusion a los navegadores (SSE)
# ----------------------------------------------------------------------
def suscribir():
    cola = queue.Queue(maxsize=200)
    with _SUS_LOCK:
        _SUSCRIPTORES.append(cola)
    return cola


def desuscribir(cola):
    with _SUS_LOCK:
        if cola in _SUSCRIPTORES:
            _SUSCRIPTORES.remove(cola)


def difundir(tipo, datos):
    mensaje = json.dumps({"tipo": tipo, "datos": datos}, ensure_ascii=False)
    with _SUS_LOCK:
        colas = list(_SUSCRIPTORES)
    for cola in colas:
        try:
            cola.put_nowait(mensaje)
        except queue.Full:
            # Navegador lento o colgado: se descarta el mensaje antes que
            # frenar al resto.
            pass


# ----------------------------------------------------------------------
# Estado de los equipos
# ----------------------------------------------------------------------
def estado_lectores():
    with _ESTADO_LOCK:
        return [dict(v) for v in ESTADO.values()]


def _poner_estado(ip, **campos):
    with _ESTADO_LOCK:
        if ip in ESTADO:
            ESTADO[ip].update(campos)


def hilo_vigilancia(intervalo=20):
    """Consulta estado de puerta y conexion de cada lector, en rueda."""
    while not PARAR.is_set():
        for ip, equipo in list(LECTORES.items()):
            if PARAR.is_set():
                break
            try:
                puerta = equipo.estado_puerta()
                _poner_estado(ip, en_linea=True, puerta=puerta or "",
                              visto=base.ahora(), error="")
            except ErrorLector as exc:
                _poner_estado(ip, en_linea=False, puerta="", error=str(exc))
        difundir("estado", estado_lectores())
        PARAR.wait(intervalo)


def refrescar_conteo(ip):
    """Cuenta cuantas personas tiene cargadas el equipo. Es una consulta cara."""
    equipo = LECTORES.get(ip)
    if not equipo:
        return None
    try:
        total = equipo.cantidad_usuarios()
        _poner_estado(ip, usuarios=total, en_linea=True)
        return total
    except ErrorLector as exc:
        _poner_estado(ip, en_linea=False, error=str(exc))
        return None


# ----------------------------------------------------------------------
# Eventos en vivo
# ----------------------------------------------------------------------
def hilo_eventos(ip):
    """Escucha el stream de un lector y reconecta solo si se corta."""
    equipo = LECTORES[ip]
    espera = 5
    while not PARAR.is_set():
        try:
            log.info("Escuchando eventos de %s", equipo.nombre)
            equipo.escuchar(lambda ev: _entro_evento(ev), PARAR)
            espera = 5
        except ErrorLector as exc:
            log.warning("Stream de %s cortado: %s", equipo.nombre, exc)
        except Exception:
            log.exception("Error escuchando %s", equipo.nombre)
        if PARAR.is_set():
            break
        PARAR.wait(espera)
        espera = min(espera * 2, 60)   # no machacar un equipo caido


# Marcas esperando saber si la puerta llego a abrir. ip -> {evento, timer}
_PENDIENTES = {}
_APERTURAS = {}        # ip -> time.monotonic() de la ultima apertura vista
_PEND_LOCK = threading.Lock()

# Ventana para aparear la marca con la apertura de la puerta.
#
# Es una ventana y no una espera porque **el DoorStatus puede llegar ANTES que
# el _DoorFace_**: el equipo abre apenas reconoce la cara y recien despues manda
# los datos de quien era. Mirando solo hacia adelante, toda marca daba
# rechazada aunque la puerta hubiera abierto.
ESPERA_PUERTA = 3.0


def _entro_evento(evento):
    """Ordena los tres tipos de evento que manda el lector.

    El `_DoorFace_` dice QUIEN paso pero no si le abrieron; el `DoorStatus` que
    viene despues dice si la puerta se abrio. Se juntan los dos antes de dar la
    marca por buena, porque si no toda marca figuraria como concedida.
    """
    clase = evento.get("clase")

    if clase == "puerta":
        _poner_estado(evento["ip"], puerta="Open" if evento["abierta"] else "Close",
                      en_linea=True, visto=base.ahora())
        if evento["abierta"]:
            with _PEND_LOCK:
                _APERTURAS[evento["ip"]] = time.monotonic()
            _resolver(evento["ip"], concedida=True)
        difundir("estado", estado_lectores())
        return

    if clase == "foto":
        # Por ahora solo se anota en el log: bajar la imagen del equipo es
        # otro trabajo (ver README).
        log.debug("Foto de rostro en %s: %s", evento["lector"], evento.get("archivo"))
        return

    if clase != "marca":
        return

    if not evento.get("ts"):
        evento["ts"] = int(time.time())

    # El lector manda el UserID; el nombre lo pone la base.
    if evento.get("id"):
        persona = base.persona(evento["id"])
        if persona:
            evento["nombre"] = persona["nombre"]

    ip = evento["ip"]
    with _PEND_LOCK:
        anterior = _PENDIENTES.pop(ip, None)
        abierta_recien = (time.monotonic() - _APERTURAS.get(ip, -999)) <= ESPERA_PUERTA
    if anterior:
        # Dos personas seguidas: la anterior ya no va a poder resolverse sola.
        anterior["timer"].cancel()
        _publicar(anterior["evento"], concedida=True)

    if abierta_recien:
        # La puerta ya se habia abierto: es esta marca la que la abrio.
        _publicar(evento, concedida=True)
        return

    temporizador = threading.Timer(ESPERA_PUERTA, _vencio, args=(ip,))
    temporizador.daemon = True
    with _PEND_LOCK:
        _PENDIENTES[ip] = {"evento": evento, "timer": temporizador}
    temporizador.start()


def _resolver(ip, concedida):
    with _PEND_LOCK:
        pendiente = _PENDIENTES.pop(ip, None)
    if not pendiente:
        return
    pendiente["timer"].cancel()
    _publicar(pendiente["evento"], concedida)


def _vencio(ip):
    """No llego ningun DoorStatus para esta marca.

    NO alcanza para darla por rechazada: si la puerta ya estaba abierta porque
    entro alguien justo antes, el equipo no manda una apertura nueva. Probado
    contra los lectores reales, esa suposicion daba 2 rechazos falsos de cada 3.

    Como el rechazo es el caso raro, la marca sale como concedida y queda
    provisoria: la importacion del historial trae el ErrorCode del equipo y la
    corrige si de verdad fue rechazada (`base.corregir_desde_historial`).
    """
    with _PEND_LOCK:
        pendiente = _PENDIENTES.pop(ip, None)
    if pendiente:
        _publicar(pendiente["evento"], concedida=True)


def _publicar(evento, concedida):
    evento["concedido"] = bool(concedida)
    if base.guardar_evento(evento, vivo=True):
        difundir("evento", evento)
        difundir("resumen", base.resumen())


# ----------------------------------------------------------------------
# Importacion del historial
# ----------------------------------------------------------------------
def importar_historial(ip, completo=False):
    """Trae del equipo las marcas que todavia no tenemos.

    `completo=True` ignora el ultimo RecNo guardado y relee todo (~14s por
    equipo). Sin eso, recorre igual el conjunto pero solo guarda lo nuevo.
    """
    equipo = LECTORES.get(ip)
    if not equipo:
        return {"error": f"no existe el lector {ip}"}
    desde = 0 if completo else base.ultimo_recno(ip)
    try:
        marcas = equipo.marcas(desde_recno=desde)
    except ErrorLector as exc:
        _poner_estado(ip, en_linea=False, error=str(exc))
        return {"error": str(exc)}
    guardadas = base.guardar_eventos(marcas)
    # Las marcas que ya habian entrado en vivo llevan un veredicto provisorio:
    # el historial trae el ErrorCode real del equipo y las corrige.
    corregidas = base.corregir_desde_historial(marcas)
    if marcas:
        base.poner_ultimo_recno(ip, max(m["recno"] for m in marcas))
    log.info("Historial de %s: %d leidas, %d nuevas, %d corregidas",
             equipo.nombre, len(marcas), guardadas, corregidas)
    return {"lector": equipo.nombre, "leidas": len(marcas),
            "nuevas": guardadas, "corregidas": corregidas}


def hilo_historial(cada_minutos=30):
    """Red de seguridad: si el stream en vivo se perdio algo, esto lo recupera."""
    PARAR.wait(60)
    while not PARAR.is_set():
        for ip in list(LECTORES):
            if PARAR.is_set():
                break
            try:
                importar_historial(ip)
            except Exception:
                log.exception("Error importando historial de %s", ip)
        difundir("resumen", base.resumen())
        PARAR.wait(cada_minutos * 60)


# ----------------------------------------------------------------------
# Sincronizacion de accesos
# ----------------------------------------------------------------------
def aplicar(tarea):
    """Empuja una fila de `accesos` al equipo. Devuelve (estado, error)."""
    ip = tarea["lector"]
    equipo = LECTORES.get(ip)
    if not equipo:
        return base.ERROR, f"el lector {ip} no esta en config.json"
    try:
        if tarea["permitido"]:
            equipo.alta(
                id_persona=tarea["persona_id"],
                nombre=tarea["nombre"],
                puertas=(0,),
                desde=tarea["desde"] or None,
                hasta=tarea["hasta"] or None,
                clave_teclado=tarea["clave"] or "",
            )
            return base.OK, ""
        equipo.baja(tarea["persona_id"])
        # Sacada del equipo: queda como "no corresponde que este".
        return base.AUSENTE, ""
    except ErrorLector as exc:
        return base.ERROR, str(exc)
    except Exception as exc:
        log.exception("Error aplicando %s en %s", tarea["persona_id"], ip)
        return base.ERROR, str(exc)


def hilo_sincronizacion(intervalo=20):
    while not PARAR.is_set():
        HAY_TRABAJO.clear()
        tareas = base.pendientes(limite=50)
        if tareas:
            hechas = 0
            for tarea in tareas:
                if PARAR.is_set():
                    break
                estado, error = aplicar(tarea)
                base.marcar_acceso(tarea["persona_id"], tarea["lector"], estado, error)
                hechas += 1
                if error:
                    log.warning("%s en %s: %s", tarea["persona_id"], tarea["lector"], error)
            if hechas:
                difundir("sincronizado", {"aplicadas": hechas,
                                          "restantes": len(base.pendientes(limite=1))})
                difundir("resumen", base.resumen())
        # Si alguien toco algo mientras tanto, arranca de nuevo enseguida.
        HAY_TRABAJO.wait(timeout=intervalo)


def avisar_trabajo():
    HAY_TRABAJO.set()


# ----------------------------------------------------------------------
# Importar el padron que ya tienen los lectores
# ----------------------------------------------------------------------
def _normalizar_nombre(texto):
    limpio = unicodedata.normalize("NFKD", (texto or "").strip().lower())
    return " ".join("".join(c for c in limpio if not unicodedata.combining(c)).split())


def choques_de_id(padrones):
    """IDs que en distintos lectores corresponden a personas distintas.

    `padrones` es {ip: [usuario, ...]}. Devuelve {id: {ip: nombre}} solo para
    los IDs cuyo nombre cambia de un equipo a otro. Un tipeo ("Roiner" contra
    "Roinel") no cuenta como choque: son la misma persona mal escrita.
    """
    nombres = {}
    for ip, usuarios in padrones.items():
        for usuario in usuarios:
            if usuario.get("id") and (usuario.get("nombre") or "").strip():
                nombres.setdefault(usuario["id"], {})[ip] = usuario["nombre"]
    choques = {}
    for id_persona, por_ip in nombres.items():
        normalizados = [_normalizar_nombre(n) for n in por_ip.values()]
        if any(SequenceMatcher(None, normalizados[0], otro).ratio() < 0.85
               for otro in normalizados[1:]):
            choques[id_persona] = por_ip
    return choques


def importar_personas():
    """Lee las personas cargadas en los equipos y arma la base con eso.

    Es lo primero que hay que correr: el sistema ya venia funcionando con
    SmartPSS, asi que la base arranca reflejando la realidad y no vacia.
    """
    padrones = {}
    errores = []
    for ip, equipo in LECTORES.items():
        try:
            padrones[ip] = equipo.usuarios()
            _poner_estado(ip, en_linea=True, error="")
        except ErrorLector as exc:
            errores.append(str(exc))
            _poner_estado(ip, en_linea=False, error=str(exc))

    # Esta importacion asume que un UserID es la misma persona en todas las
    # puertas, que es como estan cargados los lectores de Lavalle (0 choques en
    # 432 registros). En el Deposito NO: cada lector numera por su cuenta y el
    # ID 2 es una persona distinta en cada puerta. Importar asi mezclaria gente
    # distinta bajo un mismo ID, y un alta posterior renombraria el registro de
    # otra persona en otro equipo. Antes que eso, no se escribe nada.
    choques = choques_de_id(padrones)
    if choques:
        ejemplos = []
        for id_persona in sorted(choques, key=lambda x: (len(x), x))[:3]:
            detalle = ", ".join(
                f"{nombre} en {LECTORES[ip].nombre if ip in LECTORES else ip}"
                for ip, nombre in choques[id_persona].items())
            ejemplos.append(f"ID {id_persona}: {detalle}")
        return {"error": (f"No se importo nada: en {len(choques)} IDs el mismo numero es "
                          f"una persona distinta segun el lector. " + " | ".join(ejemplos)),
                "choques": len(choques), "errores": errores}

    encontradas = {}      # id -> {nombre, lectores[]}
    for ip, usuarios in padrones.items():
        for usuario in usuarios:
            if not usuario["id"]:
                continue
            registro = encontradas.setdefault(usuario["id"], {
                "nombre": usuario["nombre"], "lectores": [],
                "desde": usuario["desde"], "hasta": usuario["hasta"],
                "clave": usuario["clave"]})
            registro["lectores"].append(ip)
            if usuario["nombre"] and not registro["nombre"]:
                registro["nombre"] = usuario["nombre"]

    momento = base.ahora()
    nuevas = actualizadas = 0
    with base._LOCK, base.conectar() as cx:
        for id_persona, datos in encontradas.items():
            existe = cx.execute("SELECT 1 FROM personas WHERE id=?", (id_persona,)).fetchone()
            if existe:
                cx.execute("UPDATE personas SET nombre=?, actualizado=? WHERE id=?",
                           (datos["nombre"], momento, id_persona))
                actualizadas += 1
            else:
                cx.execute("""INSERT INTO personas
                    (id, nombre, desde, hasta, clave, activo, creado, actualizado)
                    VALUES (?,?,?,?,?,1,?,?)""",
                    (id_persona, datos["nombre"], datos["desde"], datos["hasta"],
                     datos["clave"], momento, momento))
                nuevas += 1
            # Estado real del equipo: lo que ya esta cargado es 'ok', el resto
            # 'ausente'. Asi la importacion no dispara ninguna escritura.
            for ip in LECTORES:
                tiene = ip in datos["lectores"]
                cx.execute("""
                    INSERT INTO accesos (persona_id, lector, permitido, estado, error, actualizado)
                    VALUES (?,?,?,?,'',?)
                    ON CONFLICT(persona_id, lector) DO UPDATE
                       SET permitido=?, estado=?, actualizado=?""",
                    (id_persona, ip, 1 if tiene else 0,
                     base.OK if tiene else base.AUSENTE, momento,
                     1 if tiene else 0, base.OK if tiene else base.AUSENTE, momento))
    return {"personas": len(encontradas), "nuevas": nuevas,
            "actualizadas": actualizadas, "errores": errores}


def duplicados():
    """Personas con el mismo nombre cargadas con dos IDs distintos.

    Pasa cuando alguien vuelve a cargar a una persona en un equipo en vez de
    darle permiso al ID que ya tenia: termina con dos identidades y una sola
    contesta cuando le sacan el acceso.
    """
    por_nombre = {}
    for p in base.listar_personas():
        if not p["nombre"]:
            continue
        por_nombre.setdefault(_normalizar_nombre(p["nombre"]), []).append(p)
    grupos = []
    for personas in por_nombre.values():
        if len(personas) > 1:
            grupos.append(sorted(personas, key=lambda x: -x["puertas"]))
    return sorted(grupos, key=lambda g: g[0]["nombre"].lower())


# ----------------------------------------------------------------------
# Arranque
# ----------------------------------------------------------------------
def arrancar(cfg):
    hilos = []
    if cfg.get("eventos_en_vivo", True):
        for ip in LECTORES:
            hilos.append(threading.Thread(target=hilo_eventos, args=(ip,),
                                          name=f"eventos-{ip}", daemon=True))
    hilos.append(threading.Thread(target=hilo_vigilancia,
                                  args=(cfg.get("vigilancia_segundos", 20),),
                                  name="vigilancia", daemon=True))
    hilos.append(threading.Thread(target=hilo_sincronizacion,
                                  args=(cfg.get("sincronizacion_segundos", 20),),
                                  name="sincronizacion", daemon=True))
    if cfg.get("importar_historial_minutos", 30):
        hilos.append(threading.Thread(target=hilo_historial,
                                      args=(cfg["importar_historial_minutos"],),
                                      name="historial", daemon=True))
    for hilo in hilos:
        hilo.start()
    return hilos
