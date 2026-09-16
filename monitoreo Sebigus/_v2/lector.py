# -*- coding: utf-8 -*-
"""
Cliente de un lector de puerta Dahua (serie ASI).

Es un cliente fino: habla con el equipo y valida lo que el equipo devuelve, pero
no decide nada sobre personas. Eso lo hacen importacion.py y worker.py.

Verificado contra los equipos de Sebigus (ASI3213A-W / ASI3214A-W firmware 3.000
de 2023, y ASI3213G-MW firmware 2.000 de 2021 en la Reja del Deposito):

  RPC2 AccessUser.startFind/doFind/stopFind            -> padron, buscar_persona
  RPC2 AccessUser.insertMulti/updateMulti/removeMulti  -> alta / modificacion / baja
  RPC2 RecordFinder (con estado)                       -> historial de marcas
  CGI  accessControl.cgi getDoorStatus / openDoor      -> estado y apertura de la puerta
  CGI  eventManager.cgi attach                         -> eventos en vivo
  CGI  recordFinder.cgi AccessControlCard              -> solo control cruzado informativo

Tres cosas que parecian andar y no andaban:
  - recordUpdater.cgi insert devuelve HTTP 400 en los dos firmwares: el alta del
    panel v1 nunca funciono.
  - recordFinder.cgi find ignora el offset y corta en 1024, asi que siempre
    devuelve lo mas viejo. Por eso el historial va por el RecordFinder de RPC2.
  - HTTPResponse.read(n) sobre el stream de eventos bloquea hasta juntar n bytes:
    las marcas llegaban hasta 90 s tarde. Se lee con read1.
"""

import collections
import hashlib
import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

import identidad

TIMEOUT = 15
# Vigencia que usa el equipo cuando no se dice otra cosa. El firmware guarda
# 2037 como "sin vencimiento": es el techo del timestamp de 32 bits.
FIN_SIN_VENCIMIENTO = "2037-12-31 23:59:59"
PAGINA_PADRON = 50
MAX_PAGINAS_PADRON = 40


# ----------------------------------------------------------------------
# Errores. Quien llama decide segun el tipo, no segun el texto.
# ----------------------------------------------------------------------
class ErrorEquipo(Exception):
    """Base de todo lo que puede salir mal hablando con un equipo."""


class ErrorLector(ErrorEquipo):
    """El equipo contesto y rechazo la operacion."""


class IdOcupado(ErrorLector):
    """Se quiso crear un UserID que ya existe en el equipo."""


class ConflictoIdentidad(ErrorLector):
    """El UserID en el equipo es otra persona, o no se sabe a quien se esperaba."""


class ErrorSinRespuesta(ErrorEquipo):
    """No hubo respuesta usable: red, timeout, HTTP 5xx o JSON roto."""


class ResultadoIncierto(ErrorSinRespuesta):
    """Se mando una escritura y se perdio la respuesta: no se sabe si se aplico."""


class ErrorCredenciales(ErrorEquipo):
    """El equipo rechazo usuario o clave. No hay que reintentar: bloquea la cuenta."""


class PadronInvalido(ErrorEquipo):
    """El padron que devolvio el equipo no es confiable y no puede decidir nada."""


# ----------------------------------------------------------------------
# Parseo del texto clave=valor del CGI
# ----------------------------------------------------------------------
def parsear_registros(texto):
    """`records[0].CardName=Juan` -> `[{"CardName": "Juan"}]`."""
    filas = {}
    for linea in texto.splitlines():
        if "=" not in linea:
            continue
        clave, valor = linea.split("=", 1)
        if not clave.startswith("records["):
            continue
        try:
            indice = int(clave[8:clave.index("]")])
        except (ValueError, IndexError):
            continue
        campo = clave[clave.index("].") + 2:]
        filas.setdefault(indice, {})[campo] = valor
    return [filas[i] for i in sorted(filas)]


def parsear_plano(texto):
    """`Info.status=Close` -> `{"Info.status": "Close"}`."""
    salida = {}
    for linea in texto.splitlines():
        if "=" in linea:
            clave, valor = linea.split("=", 1)
            salida[clave.strip()] = valor.strip()
    return salida


def _detalle(respuesta):
    error = (respuesta or {}).get("error") or {}
    return error.get("message") or error.get("code") or "sin detalle"


def _sesion_vencida(respuesta):
    error = (respuesta or {}).get("error") or {}
    return "session" in str(error.get("message", "")).lower()


class Lector:
    def __init__(self, ip, usuario, clave, nombre=None, puerto=80, canal=1):
        self.ip = ip
        self.usuario = usuario
        self.clave = clave
        self.nombre = nombre or ip
        self.puerto = puerto
        self.canal = canal
        # El opener de urllib guarda el nonce del digest: dos hilos con el mismo
        # opener se lo pisan y el equipo responde 401. _lock lo protege.
        self._lock = threading.Lock()
        self._op = self._nuevo_opener()
        self._rpc = None
        self._rpc_lock = threading.Lock()

    @property
    def base(self):
        return f"http://{self.ip}:{self.puerto}"

    def _nuevo_opener(self):
        gestor = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        gestor.add_password(None, self.base, self.usuario, self.clave)
        return urllib.request.build_opener(
            urllib.request.HTTPDigestAuthHandler(gestor),
            urllib.request.HTTPBasicAuthHandler(gestor))

    # ------------------------------------------------------------------
    # Transporte CGI
    # ------------------------------------------------------------------
    def _traducir_http(self, exc, ruta):
        corta = ruta.split("?")[0]
        if isinstance(exc, urllib.error.HTTPError):
            if exc.code == 401:
                return ErrorCredenciales(f"{self.nombre}: usuario o clave rechazados")
            if exc.code >= 500:
                return ErrorSinRespuesta(f"{self.nombre}: HTTP {exc.code} en {corta}")
            return ErrorLector(f"{self.nombre}: HTTP {exc.code} en {corta}")
        return ErrorSinRespuesta(f"{self.nombre}: sin respuesta ({exc})")

    def _pedir(self, ruta, timeout=TIMEOUT, crudo=False):
        try:
            with self._lock:
                respuesta = self._op.open(self.base + ruta, timeout=timeout)
            with respuesta:
                cuerpo = respuesta.read()
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            raise self._traducir_http(exc, ruta) from exc
        if crudo:
            return cuerpo
        # El firmware manda UTF-8; algunos equipos viejos mandan latin-1.
        try:
            return cuerpo.decode("utf-8")
        except UnicodeDecodeError:
            return cuerpo.decode("latin-1")

    # ------------------------------------------------------------------
    # Estado del equipo y puerta
    # ------------------------------------------------------------------
    def info(self):
        datos = parsear_plano(self._pedir("/cgi-bin/magicBox.cgi?action=getSystemInfo"))
        return {"modelo": datos.get("deviceType", ""), "serie": datos.get("serialNumber", ""),
                "hardware": datos.get("hardwareVersion", "")}

    def estado_puerta(self):
        """'Open' | 'Close' | None si el equipo no lo informa."""
        datos = parsear_plano(
            self._pedir(f"/cgi-bin/accessControl.cgi?action=getDoorStatus&channel={self.canal}"))
        return datos.get("Info.status") or datos.get("status")

    def abrir_puerta(self):
        """Apertura remota. Es una accion fisica sobre una puerta real.

        Usa un opener propio y no toma _lock: si no, quedaba en cola detras de la
        lectura del padron o de la vigilancia.
        """
        consulta = urllib.parse.urlencode({"action": "openDoor", "channel": self.canal,
                                           "UserID": "", "Type": "Remote"})
        ruta = f"/cgi-bin/accessControl.cgi?{consulta}"
        try:
            with self._nuevo_opener().open(self.base + ruta, timeout=8) as r:
                texto = r.read().decode("utf-8", "replace")
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            raise self._traducir_http(exc, ruta) from exc
        if "OK" not in texto.upper() and "ERROR" in texto.upper():
            raise ErrorLector(f"{self.nombre}: el equipo rechazo la apertura ({texto.strip()})")
        return True

    # ------------------------------------------------------------------
    # RPC2
    # ------------------------------------------------------------------
    def _sesion_rpc(self):
        with self._rpc_lock:
            if self._rpc is None:
                self._rpc = _RPC2(self.ip, self.usuario, self.clave, self.puerto).login()
            return self._rpc

    def _descartar_sesion(self):
        with self._rpc_lock:
            self._rpc = None

    def _llamar_rpc(self, metodo, params=None, reintentar=True, timeout=20):
        """Llama un metodo RPC2 reusando la sesion.

        Con reintentar=True, un corte de red se reintenta una vez con sesion nueva.
        Con reintentar=False (el alta), un corte lanza ResultadoIncierto: repetir un
        insert que quizas entro deja un "ya existe" falso o un registro duplicado.
        Una sesion vencida si se repite siempre: el equipo la rechazo sin ejecutar.
        """
        for intento in (1, 2):
            rpc = self._sesion_rpc()
            try:
                respuesta = rpc.llamar(metodo, params, timeout=timeout)
            except ErrorSinRespuesta as exc:
                self._descartar_sesion()
                if not reintentar:
                    raise ResultadoIncierto(
                        f"{self.nombre}: {metodo} sin respuesta; no se sabe si se aplico") from exc
                if intento == 2:
                    raise
                continue
            if _sesion_vencida(respuesta) and intento == 1:
                self._descartar_sesion()
                continue
            return respuesta
        raise ErrorSinRespuesta(f"{self.nombre}: {metodo} sin respuesta")

    def cerrar(self):
        with self._rpc_lock:
            rpc, self._rpc = self._rpc, None
        if rpc:
            rpc.logout()

    # ------------------------------------------------------------------
    # Padron (AccessUser)
    # ------------------------------------------------------------------
    def padron(self):
        """Padron completo: dict UserID -> registro, validado.

        Lanza PadronInvalido si el equipo devuelve algo que no se puede creer: sin
        Token, un Total que no cierra, registros sin UserID, UserID repetidos (el
        Offset ignorado) o mas de 40 paginas. Un padron invalido nunca decide nada.
        """
        r = self._llamar_rpc("AccessUser.startFind", {"Condition": {}})
        p = r.get("params") or {}
        token, total = p.get("Token"), p.get("Total")
        if token is None:
            raise PadronInvalido(f"{self.nombre}: AccessUser.startFind sin Token ({_detalle(r)})")
        registros = collections.OrderedDict()
        try:
            for _ in range(MAX_PAGINAS_PADRON):
                d = self._llamar_rpc("AccessUser.doFind", {"Token": token, "Offset": len(registros),
                                                           "Count": PAGINA_PADRON})
                lote = (d.get("params") or {}).get("Info") or []
                vistos = set()
                for reg in lote:
                    uid = str(reg.get("UserID") or "")
                    if not uid:
                        raise PadronInvalido(f"{self.nombre}: el equipo devolvio un registro sin UserID")
                    if uid in registros or uid in vistos:
                        raise PadronInvalido(
                            f"{self.nombre}: UserID {uid} repetido en el padron (el equipo ignoro el Offset)")
                    vistos.add(uid)
                for reg in lote:
                    registros[str(reg["UserID"])] = reg
                if len(lote) < PAGINA_PADRON:
                    break
            else:
                raise PadronInvalido(f"{self.nombre}: el padron supera {MAX_PAGINAS_PADRON} paginas")
        finally:
            try:
                self._llamar_rpc("AccessUser.stopFind", {"Token": token})
            except ErrorEquipo:
                pass
        if total is not None and int(total) != len(registros):
            raise PadronInvalido(f"{self.nombre}: el equipo informo {total} personas y se leyeron {len(registros)}")
        return registros

    def buscar_persona(self, user_id):
        """El registro de ese UserID, o None. Verifica que el equipo respeto el filtro."""
        user_id = str(user_id)
        r = self._llamar_rpc("AccessUser.startFind", {"Condition": {"UserID": user_id}})
        p = r.get("params") or {}
        token = p.get("Token")
        if token is None:
            raise PadronInvalido(f"{self.nombre}: AccessUser.startFind sin Token ({_detalle(r)})")
        try:
            if not p.get("Total"):
                return None
            d = self._llamar_rpc("AccessUser.doFind", {"Token": token, "Offset": 0, "Count": 1})
            info = (d.get("params") or {}).get("Info") or []
        finally:
            try:
                self._llamar_rpc("AccessUser.stopFind", {"Token": token})
            except ErrorEquipo:
                pass
        if not info:
            return None
        if str(info[0].get("UserID")) != user_id:
            # Un firmware que ignora el filtro devolveria al primero de la lista.
            raise PadronInvalido(f"{self.nombre}: se pidio el ID {user_id} y el equipo devolvio {info[0].get('UserID')}")
        return info[0]

    def plantilla(self, padron=None):
        """Puertas y horario que usa la gente ya cargada en este lector.

        No depende del firmware sino de quien cargo a la persona: SmartPSS deja
        TimeSections [0] y la web del equipo [255]. Un alta copia lo que usa la
        mayoria de ESE lector. Authority y UserType no se copian: hay 1 o 2 usuarios
        con Authority 1 por equipo y un alta nunca tiene que salir con ese nivel.
        """
        if padron is None:
            padron = self.padron()
        registros = padron.values() if isinstance(padron, dict) else padron
        conteo = collections.Counter(
            (tuple(p.get("Doors") or []), tuple(p.get("TimeSections") or []),
             tuple(p.get("SpecialDaysSchedule") or []), p.get("UseTime"))
            for p in registros if p.get("Doors"))
        if conteo:
            (puertas, horarios, especiales, usos), _ = conteo.most_common(1)[0]
        else:
            puertas, horarios, especiales, usos = (0,), (0,), (255,), 200
        return {"Doors": list(puertas), "TimeSections": list(horarios),
                "SpecialDaysSchedule": list(especiales), "UseTime": usos}

    # ------------------------------------------------------------------
    # Escritura (AccessUser)
    # ------------------------------------------------------------------
    # Lo que se reenvia al actualizar. Password queda afuera a proposito:
    # updateMulti conserva los campos que no se mandan (verificado en los dos
    # firmwares), asi que no se le borra la clave de teclado a nadie.
    _CAMPOS_ACTUALIZABLES = ("UserID", "UserName", "UserType", "UserStatus", "Authority",
                             "Doors", "TimeSections", "SpecialDaysSchedule", "UseTime",
                             "ValidFrom", "ValidTo", "CitizenIDNo", "IsFirstEnter",
                             "FirstEnterDoors")

    def crear(self, user_id, nombre, desde, hasta, plantilla, puertas=None, documento=""):
        """Da de alta a una persona. Lanza IdOcupado si el UserID ya existe.

        El insert no se reintenta: ante un corte lanza ResultadoIncierto y quien
        llama confirma leyendo el padron en la vuelta siguiente.
        """
        user_id = str(user_id)
        existente = self.buscar_persona(user_id)
        if existente:
            raise IdOcupado(f"{self.nombre}: el ID {user_id} ya existe en el equipo "
                            f"({existente.get('UserName')!r})")
        doors = list(plantilla["Doors"] if puertas is None else puertas)
        horario = (plantilla.get("TimeSections") or [0])[0]
        registro = {
            "UserID": user_id, "UserName": nombre, "UserType": 0, "UserStatus": 0,
            "Authority": 2, "Doors": doors, "TimeSections": [horario] * len(doors),
            "SpecialDaysSchedule": list(plantilla.get("SpecialDaysSchedule") or [255]),
            "UseTime": plantilla.get("UseTime", 0), "CitizenIDNo": documento or "",
            "ValidFrom": desde or datetime.now().strftime("%Y-%m-%d 00:00:00"),
            "ValidTo": hasta or FIN_SIN_VENCIMIENTO,
        }
        r = self._llamar_rpc("AccessUser.insertMulti", {"UserList": [registro]}, reintentar=False)
        if not r.get("result"):
            raise ErrorLector(f"{self.nombre}: alta rechazada ({_detalle(r)})")
        return registro

    def _conflicto(self, actual, user_id, nombre_esperado, accion):
        """La regla de oro: igualdad exacta, y sin nombre esperado no se toca nada."""
        if not identidad.normalizar(nombre_esperado):
            raise ConflictoIdentidad(f"{self.nombre}: no se {accion} el ID {user_id} "
                                     "sin saber a quien se espera encontrar")
        if not identidad.mismo_registro(actual.get("UserName"), nombre_esperado):
            raise ConflictoIdentidad(
                f"{self.nombre}: el ID {user_id} en el equipo es {actual.get('UserName')!r}, "
                f"no {nombre_esperado!r}. No se {accion} para no pisar a otra persona")

    def actualizar(self, user_id, nombre_esperado, **cambios):
        """Cambia campos de una persona existente y respeta el resto.

        `cambios` acepta nombre, desde, hasta, puertas y documento. Se relee el
        registro y se reenv