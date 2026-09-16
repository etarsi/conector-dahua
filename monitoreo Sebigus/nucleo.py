# -*- coding: utf-8 -*-
"""
El motor del panel, en dos sedes.

Mantiene los lectores conectados por sede, escucha los eventos en vivo, aplica a
los equipos lo que se decide en la base e importa/concilia el padron. Nada de
esto bloquea al servidor web.

Dos ideas que ordenan todo el modulo:

  - La persona es del PANEL (un `pid`), no del equipo. En el Deposito el mismo
    UserID es otra persona en cada puerta, asi que el UserID vive por acceso.
  - Una escritura o una vinculacion se decide SIEMPRE contra un padron recien
    leido y validado, y comparando nombres con IGUALDAD exacta
    (`identidad.mismo_registro`), nunca con similitud. La similitud solo sugiere.

Ver docs/diseno-multisede.md para el detalle y los casos de prueba.
"""

import json
import logging
import os
import queue
import threading
import time

import base
import identidad
from camaras import NVR
from lector import (ErrorCredenciales, ErrorLector, ErrorSinRespuesta, Lector,
                    PadronInvalido, ResultadoIncierto)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(BASE_DIR, "config.json")

log = logging.getLogger("monitoreo")

PARAR = threading.Event()

# Estado en memoria, indexado por sede e ip.
SEDES = {}             # clave -> {nombre, ids, escritura, rango_ids_nuevos, lectores:[ip], tiene_nvr}
SEDE_DE_IP = {}        # ip -> clave de sede
LECTORES = {}          # ip -> Lector
GRABADORES = {}        # sede -> NVR | None
ESTADO = {}            # ip -> dict de estado en vivo del equipo
CANDADO = {}           # ip -> Lock (serializa worker/importacion/conciliacion sobre un lector)
ESPERAS = {}           # ip -> monotonic hasta cuando no tocar el lector
CREDS_MALAS = set()    # ips con credenciales rechazadas: no se les habla mas
_ESTADO_LOCK = threading.Lock()

TRABAJO = {}           # sede -> Event (despierta al worker de esa sede)

_SUSCRIPTORES = []
_SUS_LOCK = threading.Lock()


# ======================================================================
# Configuracion
# ======================================================================
def cargar_config():
    if not os.path.exists(CONFIG):
        raise SystemExit("Falta config.json. Copia config.example.json y completalo.")
    with open(CONFIG, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    if "sedes" not in cfg:
        raise SystemExit(
            "config.json es del formato viejo (una sede). Este panel necesita la "
            "seccion 'sedes'. Ver config.example.json.")
    _validar_config(cfg)
    return cfg


def _validar_config(cfg):
    ips_vistas = {}
    for clave, sede in cfg["sedes"].items():
        if not clave.replace("_", "").isalnum() or not clave.islower():
            raise SystemExit(f"la clave de sede '{clave}' debe ser minusculas, letras/numeros/_")
        if sede.get("ids") not in ("compartidos", "por_lector"):
            raise SystemExit(f"la sede '{clave}' necesita ids: 'compartidos' o 'por_lector'")
        nombres = set()
        for eq in sede.get("lectores", []):
            ip = eq["ip"]
            if ip in ips_vistas:
                raise SystemExit(f"la IP {ip} esta repetida (en '{ips_vistas[ip]}' y '{clave}')")
            ips_vistas[ip] = clave
            nom = eq.get("nombre", ip)
            if nom in nombres:
                raise SystemExit(f"el nombre de lector '{nom}' esta repetido en la sede '{clave}'")
            nombres.add(nom)


def iniciar_sedes(cfg):
    """Arma LECTORES, SEDES, SEDE_DE_IP, GRABADORES y los candados desde el config."""
    for clave, sede in cfg["sedes"].items():
        ids = sede["ids"]
        escritura_sede = sede.get("escritura", ids == "compartidos")  # Deposito arranca en solo lectura
        ips = []
        for eq in sede.get("lectores", []):
            ip = eq["ip"]
            usuario = eq.get("usuario", sede.get("usuario", "admin"))
            clave_eq = eq.get("clave", sede.get("clave", ""))
            if not clave_eq or clave_eq == "CAMBIAR":
                log.warning("Lector %s sin credenciales: queda fuera", ip)
                continue
            LECTORES[ip] = Lector(ip, usuario, clave_eq, eq.get("nombre", ip),
                                  eq.get("puerto", 80), eq.get("canal", 1))
            SEDE_DE_IP[ip] = clave
            CANDADO[ip] = threading.Lock()
            ips.append(ip)
            with _ESTADO_LOCK:
                ESTADO[ip] = {
                    "ip": ip, "sede": clave, "nombre": eq.get("nombre", ip),
                    "sector": eq.get("sector", ""), "modelo": eq.get("modelo", ""),
                    "en_linea": False, "puerta": "", "visto": "", "error": "",
                    "escritura": eq.get("escritura", escritura_sede),
                    "eventos_en_vivo": eq.get("eventos_en_vivo", sede.get("eventos_en_vivo", True)),
                    "historial": eq.get("historial", sede.get("historial", True)),
                    "credenciales_ok": True}
        nvr = _armar_nvr(sede.get("nvr"))
        GRABADORES[clave] = nvr
        SEDES[clave] = {"nombre": sede.get("nombre", clave), "ids": ids,
                        "escritura": escritura_sede,
                        "rango_ids_nuevos": sede.get("rango_ids_nuevos", 9000),
                        "lectores": ips, "tiene_nvr": nvr is not None}
        TRABAJO[clave] = threading.Event()
    return SEDES


def _armar_nvr(datos):
    datos = datos or {}
    if not datos.get("ip") or datos.get("clave") in (None, "", "CAMBIAR"):
        return None
    nvr = NVR(datos["ip"], datos.get("usuario", "admin"), datos["clave"],
              datos.get("puerto", 80), datos.get("puerto_rtsp", 554), datos.get("nombre", "NVR"))
    nvr.max_canales = datos.get("max_canales", 32)
    return nvr


def sede_de(ip):
    return SEDE_DE_IP.get(ip)


def ids_compartidos(sede):
    return SEDES.get(sede, {}).get("ids") == "compartidos"


def lectores_de(sede):
    return list(SEDES.get(sede, {}).get("lectores", []))


# ======================================================================
# Difusion a los navegadores (SSE), siempre con sede
# ======================================================================
def suscribir():
    cola = queue.Queue(maxsize=300)
    with _SUS_LOCK:
        _SUSCRIPTORES.append(cola)
    return cola


def desuscribir(cola):
    with _SUS_LOCK:
        if cola in _SUSCRIPTORES:
            _SUSCRIPTORES.remove(cola)


def difundir(tipo, datos, sede):
    """Cada mensaje SSE lleva su sede; el navegador filtra por la que mira."""
    if sede is None:
        raise ValueError("difundir sin sede")
    mensaje = json.dumps({"tipo": tipo, "sede": sede, "datos": datos}, ensure_ascii=False)
    with _SUS_LOCK:
        colas = list(_SUSCRIPTORES)
    for cola in colas:
        try:
            cola.put_nowait(mensaje)
        except queue.Full:
            pass


# ======================================================================
# Estado de los equipos
# ======================================================================
def estado_lectores(sede=None):
    with _ESTADO_LOCK:
        return [dict(v) for v in ESTADO.values() if sede is None or v["sede"] == sede]


def _poner_estado(ip, **campos):
    with _ESTADO_LOCK:
        if ip in ESTADO:
            ESTADO[ip].update(campos)


def resumen_sede(sede):
    return base.resumen(sede, lectores_de(sede))


# ======================================================================
# Esperas y credenciales por lector
# ======================================================================
def _en_espera(ip):
    return ESPERAS.get(ip, 0) > time.monotonic()


def _demorar(ip):
    st = ESTADO.get(ip, {})
    intentos = st.get("_reintentos", 0) + 1
    segundos = min(20 * (2 ** (intentos - 1)), 120)
    ESPERAS[ip] = time.monotonic() + segundos
    _poner_estado(ip, _reintentos=intentos)


def _revivir(ip):
    ESPERAS.pop(ip, None)
    _poner_estado(ip, _reintentos=0)


def _marcar_credenciales(ip):
    CREDS_MALAS.add(ip)
    _poner_estado(ip, credenciales_ok=False, en_linea=False,
                  error="usuario o clave rechazados; el panel no le habla mas a este lector")
    log.error("Credenciales rechazadas en %s: se deja de tocar el equipo", ip)


def reintentar_credenciales(ip):
    CREDS_MALAS.discard(ip)
    _revivir(ip)
    _poner_estado(ip, credenciales_ok=True, error="")


def _saltear(ip):
    """True si al lector no hay que tocarlo ahora (creds malas o en espera)."""
    return ip in CREDS_MALAS or _en_espera(ip)


# ======================================================================
# Vigilancia (por sede): estado de puerta y conexion
# ======================================================================
def hilo_vigilancia(sede, intervalo):
    while not PARAR.is_set():
        for ip in lectores_de(sede):
            if PARAR.is_set():
                break
            if ip in CREDS_MALAS:
                continue
            equipo = LECTORES.get(ip)
            try:
                puerta = equipo.estado_puerta()
                antes = ESTADO.get(ip, {}).get("en_linea")
                _poner_estado(ip, en_linea=True, puerta=puerta or "", visto=base.ahora(), error="")
                if not antes:                    # volvio: destrabar esperas y despertar al worker
                    _revivir(ip)
                    avisar_trabajo(sede)
            except ErrorCredenciales:
                _marcar_credenciales(ip)
            except ErrorLector as exc:
                _poner_estado(ip, en_linea=False, puerta="", error=str(exc))
        difundir("estado", estado_lectores(sede), sede)
        PARAR.wait(intervalo)


# ======================================================================
# Eventos en vivo
# ======================================================================
def hilo_eventos(ip):
    equipo = LECTORES[ip]
    espera = 5
    while not PARAR.is_set():
        if ip in CREDS_MALAS:
            PARAR.wait(30)
            continue
        try:
            log.info("Escuchando eventos de %s", equipo.nombre)
            equipo.escuchar(_entro_evento, PARAR)
            espera = 5
        except ErrorCredenciales:
            _marcar_credenciales(ip)
        except ErrorLector as exc:
            log.warning("Stream de %s cortado: %s", equipo.nombre, exc)
        except Exception:
            log.exception("Error escuchando %s", equipo.nombre)
        if PARAR.is_set():
            break
        PARAR.wait(espera)
        espera = min(espera * 2, 60)


# Marcas de rostro esperando el DoorStatus para saber si abrio. ip -> {evento, timer}
_PENDIENTES = {}
_APERTURAS = {}
_PEND_LOCK = threading.Lock()
ESPERA_PUERTA = 3.0

# Fotos de captura (_NewFile_): se bajan del equipo en un hilo aparte para no
# frenar el pareo marca/puerta del stream, y se asocian a la marca por (lector,
# user_id, ts). La descarga puede tardar mas que la ventana de publicacion, asi
# que la asociacion reintenta hasta que la marca exista en la base.
_COLA_CAPTURAS = queue.Queue(maxsize=500)
_CAPTURAS_ON = True


def _entro_evento(evento):
    clase = evento.get("clase")
    ip = evento["ip"]
    sede = sede_de(ip)
    if sede is None:
        return

    if clase == "puerta":
        _poner_estado(ip, puerta="Open" if evento["abierta"] else "Close",
                      en_linea=True, visto=base.ahora())
        if evento["abierta"]:
            with _PEND_LOCK:
                _APERTURAS[ip] = time.monotonic()
            _resolver(ip, concedida=True)
        difundir("estado", estado_lectores(sede), sede)
        return

    if clase == "foto":
        # La foto que saco el lector al fichar. Se encola para bajarla sin frenar
        # el stream; el hilo de capturas la baja y la pega a la marca.
        if _CAPTURAS_ON and evento.get("archivo"):
            item = (ip, evento.get("id") or "", evento["archivo"],
                    evento.get("ts") or int(time.time()), sede)
            try:
                _COLA_CAPTURAS.put_nowait(item)
            except queue.Full:
                log.debug("Cola de capturas llena; se descarta la foto de %s", evento["lector"])
        return

    if clase == "marca_directa":
        # AccessControl: el ErrorCode ya dice si le abrio, no hay que esperar nada.
        _identificar(evento)
        _publicar(evento)
        return

    if clase != "marca":
        return

    # _DoorFace_: no dice si abrio. Se empareja con el DoorStatus (que puede llegar
    # antes o despues). Si nunca llega, se publica igual como concedida provisoria.
    if not evento.get("ts"):
        evento["ts"] = int(time.time())
    _identificar(evento)
    with _PEND_LOCK:
        anterior = _PENDIENTES.pop(ip, None)
        abierta_recien = (time.monotonic() - _APERTURAS.get(ip, -999)) <= ESPERA_PUERTA
    if anterior:
        anterior["timer"].cancel()
        anterior["evento"]["concedido"] = True
        _publicar(anterior["evento"])
    if abierta_recien:
        evento["concedido"] = True
        _publicar(evento)
        return
    temporizador = threading.Timer(ESPERA_PUERTA, _vencio, args=(ip,))
    temporizador.daemon = True
    with _PEND_LOCK:
        _PENDIENTES[ip] = {"evento": evento, "timer": temporizador}
    temporizador.start()


def _identificar(evento):
    """Le pone sede, pid y nombre a la marca, buscando por (lector, user_id)."""
    ip = evento["ip"]
    evento["sede"] = sede_de(ip)
    uid = evento.get("id") or ""
    if not uid:
        return
    with base.conectar() as cx:
        fila = cx.execute(
            "SELECT a.pid, a.nombre_en_lector, p.nombre FROM accesos a JOIN personas p ON p.pid=a.pid"
            " WHERE a.lector=? AND a.user_id=? AND a.confirmado=1 AND a.estado!='error'",
            (ip, uid)).fetchone()
    if fila:
        evento["pid"] = fila["pid"]
        if not evento.get("nombre"):
            evento["nombre"] = fila["nombre"]


def _resolver(ip, concedida):
    with _PEND_LOCK:
        pendiente = _PENDIENTES.pop(ip, None)
    if pendiente:
        pendiente["timer"].cancel()
        pendiente["evento"]["concedido"] = concedida
        _publicar(pendiente["evento"])


def _vencio(ip):
    """No llego DoorStatus. Se publica como concedida provisoria; la importacion
    del historial la corrige con el ErrorCode real si fue rechazo."""
    with _PEND_LOCK:
        pendiente = _PENDIENTES.pop(ip, None)
    if pendiente:
        pendiente["evento"]["concedido"] = True
        _publicar(pendiente["evento"])


def _publicar(evento):
    sede = evento.get("sede") or sede_de(evento["ip"])
    if base.guardar_evento(evento, vivo=True):
        difundir("evento", evento, sede)
        # El resumen solo se recalcula y difunde si hay un navegador mirando: si
        # nadie esta conectado, no tiene sentido pegarle a la base por cada fichada.
        if _SUSCRIPTORES:
            difundir("resumen", resumen_sede(sede), sede)


# Primer resultado por lector, para dejar en el log si el equipo deja bajar la
# foto de captura (se confirma en produccion con la primera fichada real).
_CAP_VISTO = {}


def _capturar_foto(ip, uid, ruta, ts, sede):
    """Baja del equipo la foto de captura de una marca y la asocia al evento.
    Corre en el hilo de capturas: la marca puede tardar hasta ESPERA_PUERTA en
    publicarse, asi que la asociacion se reintenta unos segundos."""
    equipo = LECTORES.get(ip)
    if not equipo:
        return
    try:
        jpg = equipo.bajar_archivo(ruta, timeout=8)
    except Exception as exc:
        if _CAP_VISTO.get(ip) != "fallo":       # avisar una vez por lector
            _CAP_VISTO[ip] = "fallo"
            log.warning("No se pudo bajar la foto de captura de %s (%s): %s",
                        equipo.nombre, ruta, exc)
        else:
            log.debug("Foto de captura no bajada (%s %s): %s", ip, ruta, exc)
        return
    if _CAP_VISTO.get(ip) != "ok":
        _CAP_VISTO[ip] = "ok"
        log.info("Foto de captura OK desde %s (%d KB)", equipo.nombre, len(jpg) // 1024)
    try:
        rel = base.guardar_foto_captura(sede, ip, uid, ts, jpg)
    except OSError as exc:
        log.warning("Foto de captura no guardada: %s", exc)
        return
    # Pegarla a la marca. Si todavia no se guardo (ventana de pareo), reintentar.
    for _ in range(6):
        if base.adjuntar_foto_evento(sede, ip, uid, rel, ts):
            difundir("foto", {"lector_ip": ip, "user_id": uid, "ts": ts}, sede)
            return
        if PARAR.wait(1):
            return
    log.debug("Foto guardada pero sin marca para asociar todavia (%s %s)", ip, uid)


def hilo_capturas():
    """Baja las fotos de captura encoladas por _entro_evento, una por una."""
    while not PARAR.is_set():
        try:
            item = _COLA_CAPTURAS.get(timeout=1)
        except queue.Empty:
            continue
        if item is None:
            break
        try:
            _capturar_foto(*item)
        except Exception:
            log.exception("Error bajando una foto de captura")


def avisar_trabajo(sede):
    if sede in TRABAJO:
        TRABAJO[sede].set()


# ======================================================================
# Importar / conciliar el padron de una sede
# ======================================================================
class _AbortarImport(Exception):
    pass


def _res_vacio():
    return {"nuevas": 0, "vinculadas": 0, "cambios_fuera": [], "accesos_fuera": [],
            "bajas_con_registro": [], "posibles_duplicados": [], "nombres_distintos_mismo_id": [],
            "sin_importar": [], "choque": None}


def _leer_padrones(sede, forzar):
    """Lee el padron de cada lector. Devuelve (padrones, sin_leer).

    padrones: {ip: {user_id: registro}} solo de los LEIDOS.
    Un padron vacio de un lector que en la base tiene gente cargada cuenta como
    NO leido (padron vacio sospechoso), salvo que la ip venga en `forzar`.
    """
    padrones, sin_leer = {}, []
    for ip in lectores_de(sede):
        equipo = LECTORES.get(ip)
        nombre = ESTADO.get(ip, {}).get("nombre", ip)
        if ip in CREDS_MALAS:
            sin_leer.append({"ip": ip, "nombre": nombre, "motivo": "credenciales rechazadas"})
            continue
        try:
            registros = equipo.padron()
        except ErrorCredenciales:
            _marcar_credenciales(ip)
            sin_leer.append({"ip": ip, "nombre": nombre, "motivo": "credenciales rechazadas"})
            continue
        except (ErrorSinRespuesta, PadronInvalido) as exc:
            sin_leer.append({"ip": ip, "nombre": nombre, "motivo": str(exc)})
            continue
        if not registros and ip not in forzar:
            with base.conectar() as cx:
                tiene = cx.execute(
                    "SELECT 1 FROM accesos a JOIN personas p ON p.pid=a.pid"
                    " WHERE p.sede=? AND a.lector=? AND a.user_id!='' LIMIT 1",
                    (sede, ip)).fetchone()
            if tiene:
                sin_leer.append({"ip": ip, "nombre": nombre, "motivo": "padron vacio sospechoso"})
                continue
        padrones[ip] = {r["UserID"]: r for r in registros if r.get("UserID")}
        _poner_estado(ip, en_linea=True, error="")
        _revivir(ip)
    return padrones, sin_leer


def importar(sede, forzar=(), forzar_sin=(), automatica=False):
    """Concilia la base con los equipos de la sede. NUNCA escribe en los equipos.
    Devuelve el resultado, o {'error': ...} para un 409."""
    if sede not in SEDES:
        return {"error": "sede desconocida"}
    forzar, forzar_sin = set(forzar), set(forzar_sin)
    candados = [CANDADO[ip] for ip in sorted(lectores_de(sede))]
    for c in candados:
        c.acquire()
    try:
        padrones, sin_leer = _leer_padrones(sede, forzar)
        if not padrones:
            return {"error": "no se pudo leer ningun lector de la sede", "sin_leer": sin_leer}
        with base.conectar() as cx:
            primera = cx.execute("SELECT 1 FROM personas WHERE sede=? LIMIT 1",
                                 (sede,)).fetchone() is None
        no_leidos = [s["ip"] for s in sin_leer if s["ip"] not in forzar_sin]
        if primera and no_leidos:
            return {"error": "primera importacion incompleta: falta leer algun lector",
                    "sin_leer": sin_leer}
        try:
            with base._LOCK, base.conectar() as cx:
                if ids_compartidos(sede):
                    res = _importar_compartidos(cx, sede, padrones)
                else:
                    res = _importar_por_lector(cx, sede, padrones)
        except _AbortarImport as exc:
            return {"error": str(exc), "sin_leer": sin_leer, "choque": True}
        _atribuir_todo(sede)
        res.update({"leidos": [ESTADO.get(ip, {}).get("nombre", ip) for ip in padrones],
                    "sin_leer": sin_leer})
        difundir("resumen", resumen_sede(sede), sede)
        return res
    finally:
        for c in candados:
            c.release()


def _vincular(cx, sede, pid, ip, reg, momento, res):
    """Upsert de la fila (pid, lector) como observada/confirmada desde el equipo."""
    uid, nombre_eq = reg["UserID"], reg.get("UserName", "")
    fila = cx.execute("SELECT * FROM accesos WHERE pid=? AND lector=?", (pid, ip)).fetchone()
    activo = cx.execute("SELECT activo FROM personas WHERE pid=?", (pid,)).fetchone()["activo"]
    if fila is None or (fila["permitido"] == 0 and fila["estado"] == base.AUSENTE):
        if activo:
            cx.execute(
                "INSERT INTO accesos (pid, lector, permitido, version, user_id, confirmado,"
                " nombre_en_lector, estado, visto, actualizado) VALUES (?,?,1,0,?,1,?,'ok',?,?)"
                " ON CONFLICT(pid,lector) DO UPDATE SET permitido=1, user_id=excluded.user_id,"
                " confirmado=1, nombre_en_lector=excluded.nombre_en_lector, estado='ok',"
                " visto=excluded.visto, actualizado=excluded.actualizado",
                (pid, ip, uid, nombre_eq, momento, momento))
            res["accesos_fuera"].append({"pid": pid, "lector": ip, "nombre": nombre_eq})
        else:
            cx.execute(
                "INSERT INTO accesos (pid, lector, permitido, version, user_id, confirmado,"
                " nombre_en_lector, estado, error, visto, actualizado)"
                " VALUES (?,?,0,0,?,1,?,'error',?,?,?)"
                " ON CONFLICT(pid,lector) DO UPDATE SET user_id=excluded.user_id, confirmado=1,"
                " nombre_en_lector=excluded.nombre_en_lector, estado='error',"
                " error=excluded.error, visto=excluded.visto, actualizado=excluded.actualizado",
                (pid, ip, uid, nombre_eq, f"dado de baja y sigue cargado en {ip}", momento, momento))
            res["bajas_con_registro"].append({"pid": pid, "lector": ip, "nombre": nombre_eq})
    elif fila["permitido"] == 1 and fila["user_id"] == "" and fila["estado"] in ("pendiente", "error"):
        cx.execute(
            "UPDATE accesos SET user_id=?, confirmado=1, nombre_en_lector=?, estado='pendiente',"
            " error='', visto=?, actualizado=? WHERE pid=? AND lector=?",
            (uid, nombre_eq, momento, momento, pid, ip))
    else:
        cx.execute(
            "UPDATE accesos SET user_id=?, confirmado=1, nombre_en_lector=?, visto=?,"
            " actualizado=? WHERE pid=? AND lector=?", (uid, nombre_eq, momento, momento, pid, ip))


def _paso1_vinculadas(cx, sede, padrones, res, consumidos):
    """Repasa las filas que ya tenian user_id y las concilia con el equipo (punto 4.4)."""
    momento = base.ahora()
    filas = cx.execute(
        "SELECT a.* FROM accesos a JOIN personas p ON p.pid=a.pid"
        " WHERE p.sede=? AND a.user_id!=''", (sede,)).fetchall()
    for f in filas:
        ip, uid = f["lector"], f["user_id"]
        if ip not in padrones:
            continue
        reg = padrones[ip].get(uid)
        coincide = bool(reg and identidad.mismo_registro(reg.get("UserName", ""), f["nombre_en_lector"]))
        if reg and coincide:
            consumidos.add((ip, uid))
            cx.execute(
                "UPDATE accesos SET nombre_en_lector=?, confirmado=1, visto=?, actualizado=?"
                " WHERE pid=? AND lector=?",
                (reg.get("UserName", ""), momento, momento, f["pid"], ip))
        elif reg and not coincide:
            if f["permitido"] == 1 and f["estado"] == base.OK:
                cx.execute(
                    "UPDATE accesos SET permitido=0, version=version+1, user_id='', confirmado=0,"
                    " estado='ausente', aviso=?, actualizado=? WHERE pid=? AND lector=?",
                    (f"el ID {uid} ahora es '{reg.get('UserName','')}' (cambio fuera del panel)",
                     momento, f["pid"], ip))
                res["cambios_fuera"].append({"lector": ip, "user_id": uid, "ahora": reg.get("UserName", "")})
            else:
                cx.execute(
                    "UPDATE accesos SET user_id='', confirmado=0, estado=?, error=?, actualizado=?"
                    " WHERE pid=? AND lector=?",
                    (base.ERROR if f["permitido"] == 1 else base.AUSENTE,
                     f"el ID {uid} en {ip} ahora es '{reg.get('UserName','')}'" if f["permitido"] == 1 else "",
                     momento, f["pid"], ip))
        else:
            if f["permitido"] == 1 and f["estado"] == base.OK:
                cx.execute(
                    "UPDATE accesos SET permitido=0, version=version+1, user_id='', confirmado=0,"
                    " estado='ausente', aviso='desaparecio del equipo', actualizado=?"
                    " WHERE pid=? AND lector=?", (momento, f["pid"], ip))
                res["cambios_fuera"].append({"lector": ip, "user_id": uid, "ahora": "(borrado)"})
            elif f["permitido"] == 0:
                cx.execute(
                    "UPDATE accesos SET user_id='', confirmado=0, estado='ausente', error='',"
                    " actualizado=? WHERE pid=? AND lector=?", (momento, f["pid"], ip))


def _vigencia_comun(registros):
    desdes = {r.get("ValidFrom", "") for _, r in registros}
    hastas = {r.get("ValidTo", "") for _, r in registros}
    return (next(iter(desdes)) if len(desdes) == 1 else "",
            next(iter(hastas)) if len(hastas) == 1 else "")


def _importar_compartidos(cx, sede, padrones):
    res = _res_vacio()
    momento = base.ahora()
    consumidos = set()
    _paso1_vinculadas(cx, sede, padrones, res, consumidos)
    grupos = {}
    for ip, reg_por_id in padrones.items():
        for uid, reg in reg_por_id.items():
            if (ip, uid) not in consumidos:
                grupos.setdefault(uid, []).append((ip, reg))
    for uid in sorted(grupos, key=lambda x: (len(x), x)):
        registros = grupos[uid]
        nombres = [r.get("UserName", "") for _, r in registros]
        base_n = nombres[0]
        if any(identidad.parecido(base_n, n) < identidad.UMBRAL_PARECIDO for n in nombres[1:]):
            raise _AbortarImport(f"el ID {uid} es personas distintas segun el lector: {nombres}")
        comun = max(set(nombres), key=nombres.count)
        pid = base.pid_por_id_preferido(cx, sede, uid)
        admin = any(r.get("Authority") == 1 for _, r in registros)
        if pid is None:
            desde, hasta = _vigencia_comun(registros)
            cx.execute(
                "INSERT INTO personas (sede, id_preferido, nombre, desde, hasta, admin,"
                " creado, actualizado) VALUES (?,?,?,?,?,?,?,?)",
                (sede, uid, comun, desde, hasta, 1 if admin else 0, momento, momento))
            pid = cx.execute("SELECT last_insert_rowid()").fetchone()[0]
            res["nuevas"] += 1
        for ip, reg in registros:
            _vincular(cx, sede, pid, ip, reg, momento, res)
            res["vinculadas"] += 1
        if len(set(nombres)) > 1:
            res["nombres_distintos_mismo_id"].append(
                {"user_id": uid, "nombres": sorted(set(nombres))})
    return res


def _candidato_por_nombre(cx, sede, ip, nnorm):
    """El unico pid de la sede con ese nombre exacto y sin fila cargada en este
    lector. 0 o mas de 1 -> None (persona nueva)."""
    filas = cx.execute(
        "SELECT p.pid FROM personas p WHERE p.sede=? AND normalizar(p.nombre)=?"
        " AND NOT EXISTS (SELECT 1 FROM accesos a WHERE a.pid=p.pid AND a.lector=? AND a.user_id!='')",
        (sede, nnorm, ip)).fetchall()
    return filas[0]["pid"] if len(filas) == 1 else None


def _marcar_duplicados(cx, sede, res):
    personas = [(p["pid"], p["nombre"]) for p in
                cx.execute("SELECT pid, nombre FROM personas WHERE sede=?", (sede,)).fetchall()]
    for i, (_, na) in enumerate(personas):
        for _, nb in personas[i + 1:]:
            if not identidad.es_generico(na) and identidad.son_parecidos(na, nb):
                res["posibles_duplicados"].append({"a": na, "b": nb})


def _importar_por_lector(cx, sede, padrones):
    res = _res_vacio()
    momento = base.ahora()
    consumidos = set()
    _paso1_vinculadas(cx, sede, padrones, res, consumidos)
    repetidos = set()
    for ip, reg_por_id in padrones.items():
        vistos = {}
        for uid, reg in reg_por_id.items():
            vistos.setdefault(identidad.normalizar(reg.get("UserName", "")), []).append(uid)
        for n, uids in vistos.items():
            if n and len(uids) > 1:
                repetidos.add((ip, n))
    for ip in sorted(padrones):
        for uid in sorted(padrones[ip], key=lambda x: (len(x), x)):
            if (ip, uid) in consumidos:
                continue
            reg = padrones[ip][uid]
            nombre = reg.get("UserName", "")
            nnorm = identidad.normalizar(nombre)
            forzar_solo = identidad.es_generico(nombre) or (ip, nnorm) in repetidos
            pid = None if forzar_solo else _candidato_por_nombre(cx, sede, ip, nnorm)
            if pid is None:
                cx.execute(
                    "INSERT INTO personas (sede, nombre, desde, hasta, admin, creado, actualizado)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (sede, nombre, reg.get("ValidFrom", "") or "", reg.get("ValidTo", "") or "",
                     1 if reg.get("Authority") == 1 else 0, momento, momento))
                pid = cx.execute("SELECT last_insert_rowid()").fetchone()[0]
                res["nuevas"] += 1
            _vincular(cx, sede, pid, ip, reg, momento, res)
            res["vinculadas"] += 1
    _marcar_duplicados(cx, sede, res)
    return res


def _atribuir_todo(sede):
    with base.conectar() as cx:
        filas = cx.execute(
            "SELECT a.lector, a.user_id, a.pid, a.nombre_en_lector FROM accesos a"
            " JOIN personas p ON p.pid=a.pid WHERE p.sede=? AND a.user_id!='' AND a.confirmado=1",
            (sede,)).fetchall()
    for f in filas:
        base.atribuir_eventos(sede, f["lector"], f["user_id"], f["pid"], f["nombre_en_lector"])


# ======================================================================
# Worker: aplica lo pendiente a los equipos (un hilo por sede)
# ======================================================================
def _elegir_id_nuevo(cx, sede, ip, padron):
    """Un UserID libre para un alta en por_lector: mayor a todo lo que hay en el
    equipo, lo mapeado en la base y el contador monotonico, dentro del rango."""
    rango = SEDES[sede]["rango_ids_nuevos"]
    candidatos = [rango, base.proximo_id(ip)]
    for uid in padron:
        if uid.isdigit():
            candidatos.append(int(uid) + 1)
    for uid in base.user_ids_en_uso(sede, ip):
        if uid.isdigit():
            candidatos.append(int(uid) + 1)
    return max(candidatos)


def _aplicar_alta(equipo, sede, ip, tarea, padron):
    """permitido=1. Devuelve (estado, error, aviso, observado) sin escribir la base."""
    compartidos = ids_compartidos(sede)
    uid = tarea["user_id"]
    nombre = tarea["nombre"]

    # Sin user_id no deberia llegar aca: por_lector lo resuelve
    # `_alta_por_lector_sin_id` antes, y compartidos reserva el ID al guardar.
    if not uid:
        return None

    # B/C) con user_id
    reg = padron.get(uid)
    if reg is None:
        try:
            equipo.crear(uid, nombre, tarea["desde"] or None, tarea["hasta"] or None,
                         equipo.plantilla(padron.values() if hasattr(padron, "values") else padron))
        except ResultadoIncierto:
            return ("pendiente", "sin respuesta; se reintenta", "", {"confirmado": 0})
        except ErrorSinRespuesta as exc:
            return ("pendiente", str(exc), "", {"confirmado": 0})
        except ErrorLector as exc:
            return ("pendiente", str(exc), "", {})   # p.ej. "ya existe": lo ve la vuelta que viene
        return ("ok", "", "", {"confirmado": 1, "nombre_en_lector": nombre, "cara": "?"})

    if not tarea["confirmado"]:
        # reserva que resulto ya cargada
        if identidad.mismo_registro(reg.get("UserName", ""), nombre):
            return ("ok", "", "", {"confirmado": 1, "nombre_en_lector": reg.get("UserName", "")})
        if compartidos:
            return ("error", f"el ID {uid} en {ip} es '{reg.get('UserName','')}'", "", {})
        return None   # por_lector: liberar y reelegir (se maneja afuera)

    # confirmado: comparar y actualizar si hace falta
    if not identidad.mismo_registro(reg.get("UserName", ""), tarea["nombre_en_lector"]):
        return ("error", f"conflicto: el ID {uid} en {ip} es '{reg.get('UserName','')}', "
                f"no '{tarea['nombre_en_lector']}'", "", {})
    cambios = {}
    if not identidad.mismo_registro(reg.get("UserName", ""), nombre):
        cambios["nombre"] = nombre
    if tarea["desde"] and tarea["desde"] != reg.get("ValidFrom", ""):
        cambios["desde"] = tarea["desde"]
    if tarea["hasta"] and tarea["hasta"] != reg.get("ValidTo", ""):
        cambios["hasta"] = tarea["hasta"]
    if tarea["documento"] and tarea["documento"] != reg.get("CitizenIDNo", ""):
        cambios["documento"] = tarea["documento"]
    if not cambios:
        return ("ok", "", "", {})
    try:
        equipo.actualizar(uid, nombre_esperado=tarea["nombre_en_lector"], **cambios)
    except ResultadoIncierto as exc:
        return ("pendiente", str(exc), "", {})
    except ErrorLector as exc:
        return ("error", str(exc), "", {})
    return ("ok", "", "", {"nombre_en_lector": nombre if "nombre" in cambios else None})


def _aplicar_baja(equipo, sede, ip, tarea, padron):
    """permitido=0. Devuelve (estado, error, aviso, observado)."""
    uid = tarea["user_id"]
    aviso = ""
    # aviso de restos: un suelto parecido que sigue entrando
    for u, r in padron.items():
        if u != uid and identidad.son_parecidos(r.get("UserName", ""), tarea["nombre"]):
            aviso = f"en {ip} sigue '{r.get('UserName','')}' con ID {u} sin vincular: sigue entrando"
            break
    if not uid:
        return ("ausente", "", aviso, {})
    reg = padron.get(uid)
    if reg is None:
        return ("ausente", "", aviso, {"user_id": "", "confirmado": 0})
    if not tarea["confirmado"]:
        return ("ausente", "", aviso, {"user_id": "", "confirmado": 0})
    if not identidad.mismo_registro(reg.get("UserName", ""), tarea["nombre_en_lector"]):
        return ("error", f"conflicto al dar de baja: el ID {uid} en {ip} es "
                f"'{reg.get('UserName','')}'", "", {})
    try:
        equipo.quitar(uid, nombre_esperado=tarea["nombre_en_lector"])
    except ResultadoIncierto as exc:
        return ("pendiente", str(exc), "", {})
    except ErrorLector as exc:
        return ("error", str(exc), "", {})
    return ("ausente", "", aviso, {"user_id": "", "confirmado": 0})


def _procesar_lector(sede, ip, tareas):
    equipo = LECTORES.get(ip)
    if not equipo:
        return
    with CANDADO[ip]:
        try:
            padron_lista = equipo.padron()
        except ErrorCredenciales:
            _marcar_credenciales(ip)
            return
        except (ErrorSinRespuesta, PadronInvalido) as exc:
            _demorar(ip)
            for t in tareas:
                base.poner_estado(t["pid"], ip, t["version"], "pendiente",
                                  f"sin respuesta desde {base.ahora()[11:]}")
            return
        _revivir(ip)
        padron = {r["UserID"]: r for r in padron_lista if r.get("UserID")}
        compartidos = ids_compartidos(sede)
        for t in tareas:
            if PARAR.is_set():
                break
            if sede_de(ip) != sede:
                base.poner_estado(t["pid"], ip, t["version"], "error", "acceso de otra sede")
                continue
            resultado = None
            if t["permitido"]:
                # por_lector sin ID: adoptar o reservar antes de _aplicar_alta B/C
                if not t["user_id"] and not compartidos:
                    resultado = _alta_por_lector_sin_id(equipo, sede, ip, t, padron)
                    if resultado is None:
                        continue      # ya se grabo la reserva/estado, siguiente tarea
                if resultado is None:
                    resultado = _aplicar_alta(equipo, sede, ip, t, padron)
            else:
                resultado = _aplicar_baja(equipo, sede, ip, t, padron)
            if resultado is None:
                continue
            estado, error, aviso, observado = resultado
            observado = {k: v for k, v in observado.items() if v is not None}
            # Empujar la foto: si la persona tiene foto y este lector todavia no la
            # tiene cargada, se enrola una vez que el usuario ya existe (estado ok).
            if estado == "ok" and t["permitido"] and t.get("tiene_foto") \
                    and t.get("cara") != "vista":
                uid = observado.get("user_id") or t["user_id"]
                foto = base.foto(sede, t["pid"]) if uid else None
                if foto:
                    try:
                        equipo.cargar_cara(uid, foto)
                        observado["cara"] = "vista"
                    except ErrorSinRespuesta as exc:
                        aviso = (aviso + " | " if aviso else "") + f"foto sin enviar: {exc}"
                    except ErrorLector as exc:
                        aviso = (aviso + " | " if aviso else "") + f"foto rechazada: {exc}"
            if observado:
                base.observar(t["pid"], ip, **observado)
            if aviso:
                base.observar(t["pid"], ip, aviso=aviso)
            base.poner_estado(t["pid"], ip, t["version"], estado, error,
                              intentos=t["intentos"] + 1 if estado == "pendiente" else 0)
            time.sleep(0.3)
            if estado == "pendiente" and error:      # sin respuesta: cortar este lector
                _demorar(ip)
                break


def _alta_por_lector_sin_id(equipo, sede, ip, tarea, padron):
    """por_lector, permitido=1, sin user_id todavia. Adopta un registro suelto con
    el mismo nombre, o reserva un ID nuevo. Graba y devuelve None (ya resuelto), o
    devuelve un resultado de conflicto para grabar afuera."""
    nombre = tarea["nombre"]
    en_uso = base.user_ids_en_uso(sede, ip)
    sueltos = {u: r for u, r in padron.items() if u not in en_uso}
    if not tarea["forzar_nuevo"] and not identidad.es_generico(nombre):
        iguales = [(u, r) for u, r in sueltos.items()
                   if identidad.mismo_registro(r.get("UserName", ""), nombre)]
        parecidos = [(u, r) for u, r in sueltos.items()
                     if identidad.son_parecidos(r.get("UserName", ""), nombre)]
        if len(iguales) == 1 and not parecidos:
            uid, reg = iguales[0]
            base.observar(tarea["pid"], ip, user_id=uid, confirmado=1,
                          nombre_en_lector=reg.get("UserName", ""),
                          aviso=f"se tomo el registro que ya existia (ID {uid})")
            base.poner_estado(tarea["pid"], ip, tarea["version"], "ok", "")
            return None
        if len(iguales) > 1 or parecidos or (iguales and iguales[0][0] in en_uso):
            base.poner_estado(tarea["pid"], ip, tarea["version"], "error",
                              f"ya figura un nombre parecido en {ip}: vincular o crear nuevo")
            return None
    # reservar un ID nuevo
    with base.conectar() as cx:
        cand = _elegir_id_nuevo(cx, sede, ip, padron)
    if base.reservar_id(tarea["pid"], ip, str(cand), nombre):
        base.subir_proximo_id(ip, cand + 1)
        tarea["user_id"] = str(cand)          # sigue a _aplicar_alta B (insert)
        tarea["confirmado"] = 0
        return _aplicar_alta(equipo, sede, ip, tarea, padron)
    base.poner_estado(tarea["pid"], ip, tarea["version"], "pendiente", "reeligiendo ID")
    return None


def hilo_worker(sede, intervalo):
    ev = TRABAJO[sede]
    while not PARAR.is_set():
        ev.clear()
        tareas = base.pendientes(sede, lectores_de(sede))
        if tareas:
            por_lector = {}
            for t in tareas:
                por_lector.setdefault(t["lector"], []).append(t)
            hechas = 0
            for ip, grupo in por_lector.items():
                if PARAR.is_set():
                    break
                if not ESTADO.get(ip, {}).get("escritura", True) or _saltear(ip):
                    continue
                _procesar_lector(sede, ip, grupo)
                hechas += len(grupo)
            if hechas:
                difundir("resumen", resumen_sede(sede), sede)
        ev.wait(timeout=intervalo)


# ======================================================================
# Historial de marcas (por sede)
# ======================================================================
def importar_historial(ip, completo=False):
    equipo = LECTORES.get(ip)
    sede = sede_de(ip)
    if not equipo or sede is None:
        return {"error": f"no existe el lector {ip}"}
    if ip in CREDS_MALAS:
        return {"error": "credenciales rechazadas"}
    with CANDADO[ip]:
        try:
            info = equipo.info()
        except ErrorLector:
            info = {"serie": ""}
        st = base.estado_lector(ip)
        # equipo reemplazado en la misma IP: la serie cambio -> releer todo
        reemplazado = st.get("serie") and info.get("serie") and st["serie"] != info["serie"]
        desde = 0 if (completo or reemplazado) else st.get("ultimo_recno", 0)
        try:
            marcas = equipo.marcas(desde_recno=desde)
        except ErrorLector as exc:
            _poner_estado(ip, error=str(exc))
            return {"error": str(exc)}
    for m in marcas:
        m["sede"] = sede
        m["ip"] = ip
    guardadas = base.guardar_eventos(marcas)
    corregidas = base.corregir_desde_historial(marcas)
    if marcas:
        base.poner_ultimo_recno(ip, max(m["recno"] for m in marcas), serie=info.get("serie"))
    elif info.get("serie"):
        base.poner_ultimo_recno(ip, st.get("ultimo_recno", 0), serie=info.get("serie"))
    log.info("Historial de %s: %d leidas, %d nuevas, %d corregidas",
             equipo.nombre, len(marcas), guardadas, corregidas)
    return {"lector": equipo.nombre, "leidas": len(marcas), "nuevas": guardadas,
            "corregidas": corregidas}


def hilo_padron_historial(sede, cada_minutos):
    """Concilia el padron y trae el historial de la sede, cada tanto."""
    PARAR.wait(60)
    while not PARAR.is_set():
        try:
            importar(sede, automatica=True)
        except Exception:
            log.exception("Error conciliando padron de %s", sede)
        for ip in lectores_de(sede):
            if PARAR.is_set():
                break
            if ip in CREDS_MALAS or not ESTADO.get(ip, {}).get("historial", True):
                continue
            try:
                importar_historial(ip)
            except Exception:
                log.exception("Error importando historial de %s", ip)
        difundir("resumen", resumen_sede(sede), sede)
        PARAR.wait(cada_minutos * 60)


# ======================================================================
# Duplicados (por sede, para la UI)
# ======================================================================
def duplicados(sede):
    personas = base.listar_personas(sede)
    grupos = {}
    for p in personas:
        if p["nombre"] and not identidad.es_generico(p["nombre"]):
            grupos.setdefault(identidad.normalizar(p["nombre"]), []).append(p)
    exactos = [sorted(g, key=lambda x: -x["puertas"]) for g in grupos.values() if len(g) > 1]
    # parecidos por tipeo (distinto nombre normalizado)
    claves = list(grupos)
    tipeos = []
    for i, a in enumerate(claves):
        for b in claves[i + 1:]:
            if identidad.son_parecidos(a, b):
                tipeos.append([grupos[a][0], grupos[b][0]])
    return {"exactos": exactos, "tipeos": tipeos}


# ======================================================================
# Mantenimiento (backup diario + retencion + higiene de la base)
# ======================================================================
def hilo_mantenimiento(cfg):
    """Una vez por dia: respalda la base (rotando), purga eventos viejos si se
    configuro retencion, y hace checkpoint/optimize. La base es la fuente de verdad."""
    conservar = cfg.get("backups_conservar", 14)
    meses = cfg.get("retencion_meses", 0)     # 0 = no borrar eventos
    dias_foto = cfg.get("capturas_dias", 60)  # fotos de captura: se purgan aparte
    PARAR.wait(120)                            # dejar que el arranque se asiente
    while not PARAR.is_set():
        try:
            destino = base.respaldar_auto(conservar)
            log.info("Respaldo automatico: %s", destino)
            borrados = base.purgar_eventos(meses)
            if borrados:
                log.info("Retencion: %d eventos viejos borrados (> %d meses)", borrados, meses)
            carpetas = base.purgar_capturas(dias_foto)
            if carpetas:
                log.info("Retencion: %d dia(s) de fotos de captura borrados (> %d dias)",
                         carpetas, dias_foto)
            base.mantenimiento()
        except Exception:
            log.exception("Error en el mantenimiento de la base")
        PARAR.wait(24 * 3600)


# ======================================================================
# Arranque de los hilos
# ======================================================================
def arrancar(cfg):
    global _CAPTURAS_ON
    # OFF por defecto: los lectores de PUERTA no llevan foto (y la descarga HTTP no
    # anda en estos equipos). La foto de ASISTENCIA la guarda el conector (NetSDK)
    # en C:\Lector\Capturas; el panel la lee de ahi. Solo se prende con guardar_fotos=true.
    _CAPTURAS_ON = cfg.get("guardar_fotos", False)
    hilos = []
    if cfg.get("backup_automatico", True):
        hilos.append(threading.Thread(target=hilo_mantenimiento, args=(cfg,),
                                      name="mantenimiento", daemon=True))
    if _CAPTURAS_ON:
        hilos.append(threading.Thread(target=hilo_capturas, name="capturas", daemon=True))
    for sede in SEDES:
        hilos.append(threading.Thread(
            target=hilo_vigilancia, args=(sede, cfg.get("vigilancia_segundos", 20)),
            name=f"vigilancia-{sede}", daemon=True))
        hilos.append(threading.Thread(
            target=hilo_worker, args=(sede, cfg.get("sincronizacion_segundos", 20)),
            name=f"worker-{sede}", daemon=True))
        if cfg.get("importar_historial_minutos", 30):
            hilos.append(threading.Thread(
                target=hilo_padron_historial, args=(sede, cfg["importar_historial_minutos"]),
                name=f"padron-{sede}", daemon=True))
    for ip in LECTORES:
        if ESTADO.get(ip, {}).get("eventos_en_vivo", True):
            hilos.append(threading.Thread(target=hilo_eventos, args=(ip,),
                                          name=f"eventos-{ip}", daemon=True))
    for h in hilos:
        h.start()
    return hilos
