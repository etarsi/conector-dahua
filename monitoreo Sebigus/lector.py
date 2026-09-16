# -*- coding: utf-8 -*-
"""
Cliente de un lector de puerta Dahua (serie ASI).

Habla la API HTTP/CGI del equipo con autenticacion digest. Es a proposito la
unica forma en que este proyecto toca los lectores: no depende del NetSDK ni de
sus DLL, asi que corre en cualquier maquina con Python y nada mas.

Lo que se verifico contra los equipos de Sebigus (firmware 3.000.0000000.2.R,
DHI-ASI3213A-W y DHI-ASI3214A-W):

  - recordFinder.cgi  name=AccessControlCard     -> padron de personas
  - RPC2 AccessUser.insertMulti/updateMulti/removeMulti -> alta / modificacion / baja
    (recordUpdater.cgi insert devuelve HTTP 400 en estos firmwares: ver crear())
  - accessControl.cgi action=getDoorStatus       -> estado de la puerta
  - accessControl.cgi action=openDoor            -> apertura remota
  - eventManager.cgi  action=attach              -> eventos en vivo

El equipo devuelve texto plano `clave=valor`, una linea por campo, con los
registros indexados: `records[0].CardName=Juan`. `parsear_registros` lo
convierte en una lista de diccionarios.

El historial de marcas es la excepcion y va por RPC2 (JSON), no por CGI:

    El `find` del CGI ignora el `offset` y corta en 1024 registros, asi que
    siempre devuelve los 1024 MAS VIEJOS y no hay forma de llegar al final.
    El buscador con estado de RPC2 (`RecordFinder.doFind`) si avanza: pagina de
    a 1024 y en ~13s recorre los 16.793 registros de un equipo.
"""

import collections
import hashlib
import json
import socket
import threading
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from difflib import SequenceMatcher

TIMEOUT = 15
# Vigencia que usa el equipo cuando no se dice otra cosa. El firmware guarda
# 2037 como "sin vencimiento": es el techo del timestamp de 32 bits.
FIN_SIN_VENCIMIENTO = "2037-12-31 23:59:59"


class ErrorLector(Exception):
    """Rechazo logico del equipo: un ID que ya existe, un conflicto de nombre.
    Es un error que reintentar no arregla."""


class ErrorSinRespuesta(ErrorLector):
    """No se pudo hablar con el equipo: timeout, red, HTTP 5xx. Reintentar mas tarde."""


class ResultadoIncierto(ErrorSinRespuesta):
    """Una escritura (alta) se mando y no se sabe si entro (se perdio la respuesta).
    NO se puede reintentar a ciegas: hay que releer el equipo antes."""


class ErrorCredenciales(ErrorLector):
    """El equipo rechazo usuario o clave. NO reintentar: bloquea la cuenta admin,
    que tambien usa SmartPSS."""


class PadronInvalido(ErrorLector):
    """El padron leido no es confiable (paginacion rota, total que no cierra)."""


import identidad  # noqa: E402  (despues de definir las excepciones, para evitar ciclos)


def parsear_registros(texto):
    """`records[0].CardName=Juan` -> `[{"CardName": "Juan"}]`.

    Respeta el indice que manda el equipo, asi que si una pagina viene salteada
    los registros no se mezclan entre si.
    """
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


def _agrupar_puertas(registro):
    """Los permisos vienen como `Doors[0]`, `Doors[1]`... -> [0, 1]."""
    puertas = []
    for clave, valor in registro.items():
        if clave.startswith("Doors[") and valor.strip().isdigit():
            puertas.append(int(valor))
    return sorted(set(puertas))


class Lector:
    def __init__(self, ip, usuario, clave, nombre=None, puerto=80, canal=1):
        self.ip = ip
        self.usuario = usuario
        self.clave = clave
        self.nombre = nombre or ip
        self.puerto = puerto
        self.canal = canal
        self._lock = threading.Lock()
        self._rpc = None              # sesion RPC2 reutilizada
        self._rpc_lock = threading.Lock()
        self._ep_archivo = None       # endpoint que funciono para bajar archivos (cache)
        gestor = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        gestor.add_password(None, self.base, usuario, clave)
        self._op = urllib.request.build_opener(
            urllib.request.HTTPDigestAuthHandler(gestor),
            urllib.request.HTTPBasicAuthHandler(gestor),
        )

    @property
    def base(self):
        return f"http://{self.ip}:{self.puerto}"

    # ------------------------------------------------------------------
    # Transporte
    # ------------------------------------------------------------------
    def _pedir(self, ruta, timeout=TIMEOUT, crudo=False):
        url = self.base + ruta
        try:
            # El opener de urllib guarda estado del desafio digest, asi que dos
            # hilos pidiendo a la vez se pisan el nonce y el equipo responde 401.
            with self._lock:
                respuesta = self._op.open(url, timeout=timeout)
            with respuesta:
                cuerpo = respuesta.read()
        except urllib.error.HTTPError as exc:
            raise ErrorLector(f"{self.nombre}: HTTP {exc.code} en {ruta.split('?')[0]}") from exc
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            raise ErrorLector(f"{self.nombre}: sin respuesta ({exc})") from exc
        if crudo:
            return cuerpo
        # El firmware manda UTF-8; algunos equipos viejos mandan latin-1.
        try:
            return cuerpo.decode("utf-8")
        except UnicodeDecodeError:
            return cuerpo.decode("latin-1")

    # Endpoints para bajar un archivo del equipo por ruta absoluta. RPC_Loadfile
    # es el que usa SmartPSS; se prueban en orden y se recuerda el que anda.
    _EP_ARCHIVO = ("/cgi-bin/RPC_Loadfile", "/RPC_Loadfile")

    def bajar_archivo(self, ruta_absoluta, timeout=20):
        """Baja un archivo del equipo por su ruta absoluta (p.ej. la foto de
        captura del evento _NewFile_: /mnt/.../SnapShot/.../xxx.jpg). Devuelve los
        bytes del JPEG o lanza ErrorLector. Recuerda el endpoint que funciono."""
        if not ruta_absoluta:
            raise ErrorLector(f"{self.nombre}: ruta de archivo vacia")
        orden = list(dict.fromkeys(
            ([self._ep_archivo] if self._ep_archivo else []) + list(self._EP_ARCHIVO)))
        ultimo = None
        for ep in orden:
            try:
                datos = self._pedir(ep + ruta_absoluta, timeout=timeout, crudo=True)
            except ErrorLector as exc:
                ultimo = exc
                continue
            if datos[:2] == b"\xff\xd8":       # JPEG
                self._ep_archivo = ep
                return datos
            ultimo = ErrorLector(f"{self.nombre}: {ep} no devolvio un JPEG")
        self._ep_archivo = None
        raise ultimo or ErrorLector(f"{self.nombre}: no se pudo bajar {ruta_absoluta}")

    @staticmethod
    def _query(**campos):
        partes = []
        for clave, valor in campos.items():
            if valor is None:
                continue
            # Doors_0 -> Doors[0]: los nombres con corchete no son validos
            # como argumento de Python, asi que se escriben con guion bajo.
            if "_" in clave and clave.rsplit("_", 1)[-1].isdigit():
                base, indice = clave.rsplit("_", 1)
                clave = f"{base}[{indice}]"
            partes.append(f"{urllib.parse.quote(clave, safe='[]')}={urllib.parse.quote(str(valor))}")
        return "&".join(partes)

    # ------------------------------------------------------------------
    # Estado del equipo
    # ------------------------------------------------------------------
    def info(self):
        datos = parsear_plano(self._pedir("/cgi-bin/magicBox.cgi?action=getSystemInfo"))
        return {
            "modelo": datos.get("deviceType", ""),
            "serie": datos.get("serialNumber", ""),
            "hardware": datos.get("hardwareVersion", ""),
        }

    def en_linea(self):
        try:
            self._pedir("/cgi-bin/magicBox.cgi?action=getSystemInfo", timeout=6)
            return True
        except ErrorLector:
            return False

    def estado_puerta(self, timeout=6):
        """'Open' | 'Close' | None si el equipo no lo informa.

        timeout corto (6s): la vigilancia consulta esto en rueda, y un lector
        colgado (que acepta la conexion pero no contesta) no debe frenar la ronda.
        """
        datos = parsear_plano(
            self._pedir(f"/cgi-bin/accessControl.cgi?action=getDoorStatus&channel={self.canal}",
                        timeout=timeout))
        return datos.get("Info.status") or datos.get("status")

    def abrir_puerta(self, motivo="Panel de monitoreo"):
        """Apertura remota. Es una accion fisica sobre una puerta real."""
        ruta = ("/cgi-bin/accessControl.cgi?action=openDoor&"
                + self._query(channel=self.canal, UserID="", Type="Remote"))
        respuesta = self._pedir(ruta)
        if "OK" not in respuesta.upper() and "ERROR" in respuesta.upper():
            raise ErrorLector(f"{self.nombre}: el equipo rechazo la apertura ({respuesta.strip()})")
        return True

    # ------------------------------------------------------------------
    # Padron de personas
    # ------------------------------------------------------------------
    def cantidad_usuarios(self):
        datos = parsear_plano(
            self._pedir("/cgi-bin/recordFinder.cgi?action=getQuerySize&name=AccessControlCard"))
        return int(datos.get("count") or datos.get("Size") or 0)

    def usuarios(self):
        """Padron de tarjetas (recordFinder). SOLO control cruzado informativo:
        la fuente de verdad de personas es `padron()` (AccessUser).

        Una sola lectura, sin bucle de offset: el `find` del CGI ignora el offset
        y con >100 registros el bucle viejo se colgaba. Devuelve hasta 1024."""
        texto = self._pedir(
            "/cgi-bin/recordFinder.cgi?action=find&name=AccessControlCard&count=1024",
            timeout=30)
        return [self._normalizar_usuario(r) for r in parsear_registros(texto)]

    @staticmethod
    def _normalizar_usuario(registro):
        return {
            "recno": registro.get("RecNo", ""),
            "id": registro.get("UserID", ""),
            "nombre": registro.get("CardName", ""),
            "tarjeta": registro.get("CardNo", ""),
            "clave": registro.get("Password", ""),
            "puertas": _agrupar_puertas(registro),
            "desde": registro.get("ValidDateStart", ""),
            "hasta": registro.get("ValidDateEnd", ""),
            "estado": registro.get("CardStatus", ""),
        }

    def buscar_usuario(self, id_persona):
        """El registro de tarjeta de esa persona (control cruzado), o None."""
        for usuario in self.usuarios():
            if usuario["id"] == str(id_persona):
                return usuario
        return None

    # ------------------------------------------------------------------
    # Personas por la API AccessUser (RPC2): lectura completa y escritura
    # ------------------------------------------------------------------
    # recordUpdater.cgi insert devuelve HTTP 400 en estos firmwares, con y sin
    # fechas (probado en 3.000 de 2023 y 2.000 de 2021): el alta nunca anduvo por
    # ahi. La web del propio lector carga gente con AccessUser.insertMulti por
    # RPC2, y eso si funciona en los dos. El CGI AccessUser.cgi solo existe en el
    # firmware 2023, asi que se usa RPC2 para tener un unico camino.

    # Lo que se reenvia al actualizar. Password queda afuera a proposito: mandarla
    # vacia podria borrarle la clave de teclado a quien la tenga.
    _CAMPOS_ACTUALIZABLES = ("UserID", "UserName", "UserType", "UserStatus", "Authority",
                             "Doors", "TimeSections", "SpecialDaysSchedule", "UseTime",
                             "ValidFrom", "ValidTo", "CitizenIDNo", "IsFirstEnter",
                             "FirstEnterDoors")

    def _llamar_rpc(self, metodo, params=None, reintentar=True):
        """Llama un metodo RPC2 reusando la sesion; si se cayo, reconecta una vez.

        `reintentar=False` es para las ESCRITURAS: si se pierde la respuesta no se
        sabe si entraron, asi que en vez de reintentar a ciegas se lanza
        `ResultadoIncierto` y quien llama decide (releer el equipo).

        Un rechazo logico del equipo (un ID que ya existe) vuelve en la respuesta,
        no como excepcion: eso lo interpreta quien llama.
        """
        intentos = 2 if reintentar else 1
        ultimo = None
        for i in range(intentos):
            with self._rpc_lock:
                if self._rpc is None:
                    # login() puede lanzar ErrorCredenciales o ErrorSinRespuesta.
                    self._rpc = _RPC2(self.ip, self.usuario, self.clave, self.puerto).login()
                rpc = self._rpc
            try:
                respuesta = rpc.llamar(metodo, params)
            except ErrorSinRespuesta as exc:
                with self._rpc_lock:
                    self._rpc = None
                ultimo = exc
                if not reintentar:
                    raise ResultadoIncierto(
                        f"{self.nombre}: {metodo} sin respuesta (no se sabe si entro)") from exc
                continue
            error = (respuesta or {}).get("error") or {}
            if "session" in str(error.get("message", "")).lower():
                with self._rpc_lock:
                    self._rpc = None
                continue      # sesion vencida: reconecta y reintenta
            return respuesta
        raise ultimo or ErrorSinRespuesta(f"{self.nombre}: {metodo} sin respuesta del equipo")

    def cerrar(self):
        with self._rpc_lock:
            rpc, self._rpc = self._rpc, None
        if rpc:
            rpc.logout()

    def _buscar(self, condicion, validar_total):
        """Recorre AccessUser.startFind/doFind. Si `validar_total`, verifica que el
        offset avance y que el Total del equipo cierre (padron confiable)."""
        r = self._llamar_rpc("AccessUser.startFind", {"Condition": condicion or {}})
        params = r.get("params") or {}
        token = params.get("Token")
        if token is None:
            raise PadronInvalido(
                f"{self.nombre}: AccessUser.startFind sin Token ({r.get('error')})")
        total = params.get("Total")
        salida, vistos, paginas = [], set(), 0
        try:
            while True:
                paginas += 1
                if paginas > 40:
                    raise PadronInvalido(f"{self.nombre}: mas de 40 paginas leyendo el padron")
                d = self._llamar_rpc(
                    "AccessUser.doFind", {"Token": token, "Offset": len(salida), "Count": 50})
                lote = (d.get("params") or {}).get("Info") or []
                if not lote:
                    break
                for reg in lote:
                    uid = reg.get("UserID")
                    if validar_total:
                        if not uid:
                            raise PadronInvalido(f"{self.nombre}: un registro sin UserID")
                        if uid in vistos:
                            raise PadronInvalido(
                                f"{self.nombre}: el offset no avanza (UserID {uid} repetido)")
                        vistos.add(uid)
                    salida.append(reg)
                if len(lote) < 50:
                    break
            if validar_total and total is not None and len(salida) != total:
                raise PadronInvalido(
                    f"{self.nombre}: el equipo dijo Total={total} pero llegaron {len(salida)}")
            return salida
        finally:
            try:
                self._llamar_rpc("AccessUser.stopFind", {"Token": token})
            except ErrorLector:
                pass

    def padron(self):
        """Padron completo y VALIDADO por AccessUser. Lanza PadronInvalido si la
        lectura no es confiable (offset roto, total que no cierra). Es la unica
        lectura sobre la que se decide una escritura."""
        return self._buscar(None, validar_total=True)

    def buscar_persona(self, user_id):
        encontrados = self._buscar({"UserID": str(user_id)}, validar_total=False)
        return encontrados[0] if encontrados else None

    def plantilla(self, personas=None):
        """Puertas y horario que usa la gente ya cargada en este lector.

        No es igual en todos, y no depende del firmware sino de quien cargo a la
        persona: SmartPSS deja TimeSections [0] y la web del equipo [255]. Un alta
        nueva copia lo que usa la mayoria de ESE lector. Authority y UserType no se
        copian: hay 1 o 2 usuarios con Authority 1 por equipo y un alta nunca tiene
        que salir con ese nivel.
        """
        personas = self.padron() if personas is None else personas
        conteo = collections.Counter(
            (tuple(p.get("Doors") or []), tuple(p.get("TimeSections") or []),
             tuple(p.get("SpecialDaysSchedule") or []), p.get("UseTime"))
            for p in personas if p.get("Doors"))
        if conteo:
            (puertas, horarios, especiales, usos), _ = conteo.most_common(1)[0]
        else:
            puertas, horarios, especiales, usos = (0,), (0,), (255,), 200
        return {"Doors": list(puertas), "TimeSections": list(horarios),
                "SpecialDaysSchedule": list(especiales), "UseTime": usos}

    def crear(self, user_id, nombre, desde, hasta, plantilla, puertas=None, documento=""):
        """Da de alta a una persona. Falla si el ID ya existe: nunca pisa a nadie."""
        if self.buscar_persona(user_id):
            raise ErrorLector(f"{self.nombre}: el ID {user_id} ya existe en el equipo")
        doors = list(plantilla["Doors"] if puertas is None else puertas)
        horario = (plantilla["TimeSections"] or [0])[0]
        registro = {
            "UserID": str(user_id), "UserName": nombre, "UserType": 0, "UserStatus": 0,
            "Authority": 2, "Doors": doors, "TimeSections": [horario] * len(doors),
            "SpecialDaysSchedule": list(plantilla["SpecialDaysSchedule"]),
            "UseTime": plantilla["UseTime"], "CitizenIDNo": documento or "",
            "ValidFrom": desde or datetime.now().strftime("%Y-%m-%d 00:00:00"),
            "ValidTo": hasta or FIN_SIN_VENCIMIENTO,
        }
        # reintentar=False: si se pierde la respuesta, ResultadoIncierto y quien
        # llama relee antes de volver a intentar (no duplica el alta).
        r = self._llamar_rpc("AccessUser.insertMulti", {"UserList": [registro]}, reintentar=False)
        if not r.get("result"):
            raise ErrorLector(f"{self.nombre}: alta rechazada ({r.get('error')})")
        return registro

    def _conflicto(self, actual, user_id, nombre_esperado, accion):
        # Sin un nombre con que comparar, NO se toca: es la regla de oro. Un
        # nombre_esperado vacio nunca habilita una escritura.
        if not nombre_esperado:
            raise ErrorLector(
                f"{self.nombre}: no se {accion} el ID {user_id}: no se sabe con que nombre comparar")
        if not identidad.mismo_registro(actual.get("UserName"), nombre_esperado):
            raise ErrorLector(
                f"{self.nombre}: el ID {user_id} en el equipo es {actual.get('UserName')!r}, "
                f"no {nombre_esperado!r}. No se {accion} para no pisar a otra persona")

    def actualizar(self, user_id, nombre_esperado=None, **cambios):
        """Cambia campos de una persona existente y respeta el resto.

        Se relee el registro y se reenvia completo (menos la clave) en vez de mandar
        solo lo que cambia, para no depender de como trate cada firmware los campos
        que faltan. Con `nombre_esperado`, se niega si el ID ahora es otra persona.
        """
        actual = self.buscar_persona(user_id)
        if not actual:
            raise ErrorLector(f"{self.nombre}: el ID {user_id} no existe en el equipo")
        self._conflicto(actual, user_id, nombre_esperado, "modifica")
        registro = {k: actual[k] for k in self._CAMPOS_ACTUALIZABLES if k in actual}
        mapa = {"nombre": "UserName", "desde": "ValidFrom", "hasta": "ValidTo",
                "puertas": "Doors", "documento": "CitizenIDNo"}
        for clave, valor in cambios.items():
            if valor is not None:
                registro[mapa[clave]] = valor
        if cambios.get("puertas") is not None:
            horario = (actual.get("TimeSections") or [0])[0]
            registro["TimeSections"] = [horario] * len(registro["Doors"])
        r = self._llamar_rpc("AccessUser.updateMulti", {"UserList": [registro]})
        if not r.get("result"):
            raise ErrorLector(f"{self.nombre}: modificacion rechazada ({r.get('error')})")
        return registro

    def quitar(self, user_id, nombre_esperado=None):
        """Saca a la persona del equipo. Si no estaba, no hace nada.

        Con `nombre_esperado`, se niega a borrar si el ID ahora es otra persona.
        """
        actual = self.buscar_persona(user_id)
        if not actual:
            return False
        self._conflicto(actual, user_id, nombre_esperado, "borra")
        r = self._llamar_rpc("AccessUser.removeMulti", {"UserIDList": [str(user_id)]})
        if not r.get("result"):
            raise ErrorLector(f"{self.nombre}: baja rechazada ({r.get('error')})")
        return True

    # ------------------------------------------------------------------
    # Rostro (foto)
    # ------------------------------------------------------------------
    # El lector guarda por usuario un PhotoData (el JPEG) y calcula solo el
    # FaceData (los rasgos). Para enrolar se le manda el JPEG en base64; el
    # equipo detecta la cara y arma la plantilla. Si la foto no tiene una cara
    # clara, el equipo la rechaza (no es un error del panel).
    def tiene_cara(self, user_id):
        """True si el usuario ya tiene un rostro cargado en el equipo."""
        r = self._llamar_rpc("AccessFace.list", {"UserIDList": [str(user_id)]})
        lista = (r.get("params") or {}).get("FaceDataList") or []
        return bool(lista) and lista[0] is not None

    def cargar_cara(self, user_id, jpg_bytes):
        """Enrola (o reemplaza) el rostro del usuario a partir de un JPEG.

        Usa insertMulti; si ya tenia una cara, cae en updateMulti. Devuelve True,
        o lanza ErrorLector con el motivo del equipo (p.ej. 'no se detecto cara').
        """
        import base64
        b64 = base64.b64encode(jpg_bytes).decode("ascii")
        cara = {"UserID": str(user_id), "PhotoData": [b64]}
        metodo = "AccessFace.updateMulti" if self.tiene_cara(user_id) else "AccessFace.insertMulti"
        r = self._llamar_rpc(metodo, {"FaceList": [cara]})
        if not r.get("result"):
            err = r.get("error") or {}
            detalle = err.get("detail") or {}
            codigos = detalle.get("FailCodes") or []
            raise ErrorLector(f"{self.nombre}: el equipo rechazo la foto "
                              f"({err.get('message','')}{' codigos '+str(codigos) if codigos else ''})")
        return True

    def borrar_cara(self, user_id):
        try:
            self._llamar_rpc("AccessFace.removeMulti", {"UserIDList": [str(user_id)]})
        except ErrorLector:
            pass

    # ------------------------------------------------------------------
    # Historial de marcas
    # ------------------------------------------------------------------
    def cantidad_marcas(self):
        datos = parsear_plano(
            self._pedir("/cgi-bin/recordFinder.cgi?action=getQuerySize&name=AccessControlCardRec"))
        return int(datos.get("count") or datos.get("Size") or 0)

    def marcas(self, desde_recno=0, tope=None, al_avanzar=None):
        """Marcas del historial del equipo con RecNo mayor a `desde_recno`.

        Recorre todo el conjunto de a 1024 y devuelve solo lo nuevo. Guardando
        el ultimo RecNo, las corridas siguientes salen practicamente vacias.
        """
        rpc = _RPC2(self.ip, self.usuario, self.clave, self.puerto)
        nuevas = []
        try:
            rpc.login()
            objeto = rpc.llamar("RecordFinder.factory.create",
                                {"name": "AccessControlCardRec"}).get("result")
            if not objeto:
                raise ErrorLector(f"{self.nombre}: el equipo no abrio el buscador de marcas")
            try:
                rpc.llamar("RecordFinder.startFind", {"condition": {}}, objeto=objeto)
                while True:
                    respuesta = rpc.llamar("RecordFinder.doFind", {"count": 1024},
                                           objeto=objeto, timeout=60)
                    registros = (respuesta.get("params") or {}).get("records") or []
                    if not registros:
                        break
                    for registro in registros:
                        if int(registro.get("RecNo") or 0) > desde_recno:
                            nuevas.append(self._normalizar_marca(registro))
                    if al_avanzar:
                        al_avanzar(len(nuevas))
                    if tope and len(nuevas) >= tope:
                        break
                    if len(registros) < 1024:
                        break
            finally:
                try:
                    rpc.llamar("RecordFinder.destroy", None, objeto=objeto)
                except Exception:
                    pass
        finally:
            rpc.logout()
        return nuevas

    def _normalizar_marca(self, registro):
        crudo = str(registro.get("CreateTimeRealUTC") or registro.get("CreateTime") or "0")
        try:
            momento = datetime.fromtimestamp(int(crudo))
        except (ValueError, OSError, OverflowError):
            momento = None
        codigo = str(registro.get("ErrorCode", "0"))
        metodo = str(registro.get("Method", ""))
        return {
            "recno": int(registro.get("RecNo") or 0),
            "lector": self.nombre,
            "ip": self.ip,
            "id": str(registro.get("UserID", "") or registro.get("CardID", "")),
            "nombre": str(registro.get("CardName", "")),
            "momento": momento.strftime("%Y-%m-%d %H:%M:%S") if momento else "",
            "ts": int(crudo) if crudo.isdigit() else 0,
            "metodo": METODOS.get(metodo, f"Metodo {metodo}" if metodo else ""),
            "concedido": codigo in ("0", ""),
            "motivo": MOTIVOS.get(codigo, "" if codigo in ("0", "") else f"Rechazo {codigo}"),
            # Para asistencia: direccion de la marca y ruta de la foto de captura.
            "tipo": str(registro.get("Type", "")),          # Entry | Exit
            "url": str(registro.get("URL", "")),            # /SnapShotFilePath/AAAA-MM-DD/hh/mm/xxx.jpg
        }

    # ------------------------------------------------------------------
    # Eventos en vivo
    # ------------------------------------------------------------------
    def escuchar(self, al_recibir, parar, codigos="_DoorFace_,AccessControl,DoorStatus,_NewFile_"):
        """Se queda escuchando el stream de eventos y llama `al_recibir(dict)`.

        Bloquea: va en su propio hilo. El equipo manda un "Heartbeat" cada pocos
        segundos, que sirve para saber que sigue vivo sin tocar la red.

        Ojo con los codigos: **estos lectores NO emiten `AccessControl` ni
        `NewFaceRecognition`** (el equipo contesta "No Events" si se preguntan).
        Los reales, capturados escuchando `codes=[All]` mientras la gente fichaba:

            _DoorFace_   la marca en si: UserID, Similarity, OpenDoorMethod
            DoorStatus   la puerta abriendo o cerrando (Status: Open | Close)
            _NewFile_    la foto del rostro que capturo, con su ruta

        Los guiones bajos son parte del nombre, no un error de tipeo.
        """
        ruta = (f"/cgi-bin/eventManager.cgi?action=attach&codes=[{codigos}]&heartbeat=5")
        with self._lock:
            respuesta = self._op.open(self.base + ruta, timeout=20)
        try:
            # 30s: mas del doble del heartbeat, asi una pausa normal no corta.
            respuesta.fp.raw._sock.settimeout(30)
            buffer = b""
            while not parar.is_set():
                try:
                    # read1 y no read: read(n) bloquea hasta juntar n bytes, y con un
                    # heartbeat de ~70 bytes cada 5 s las marcas quedaban retenidas hasta
                    # 90 s (medido sobre 539 marcas en vivo de Lavalle: mediana de 60 s en
                    # los lectores de poco movimiento). read1 devuelve lo que ya llego.
                    trozo = respuesta.read1(4096)
                except (socket.timeout, OSError):
                    break
                if not trozo:
                    break
                buffer += trozo
                buffer = self._consumir(buffer, al_recibir)
        finally:
            try:
                respuesta.close()
            except Exception:
                pass

    def _consumir(self, buffer, al_recibir):
        """Corta el multipart en bloques completos y despacha los que sean eventos."""
        while b"--myboundary" in buffer:
            inicio = buffer.index(b"--myboundary")
            siguiente = buffer.find(b"--myboundary", inicio + 12)
            if siguiente == -1:
                return buffer[inicio:]
            bloque = buffer[inicio:siguiente]
            buffer = buffer[siguiente:]
            texto = bloque.decode("utf-8", "replace")
            if "Heartbeat" in texto or "Code=" not in texto:
                continue
            evento = self._parsear_evento(texto)
            if evento:
                try:
                    al_recibir(evento)
                except Exception:
                    pass
        return buffer

    def _parsear_evento(self, texto):
        """El cuerpo es `Code=AccessControl;action=Pulse;index=0;data={json}`."""
        cuerpo = texto.split("\r\n\r\n", 1)[-1].strip()
        if not cuerpo.startswith("Code="):
            return None
        codigo = cuerpo[5:cuerpo.index(";")] if ";" in cuerpo else cuerpo[5:]
        datos = {}
        if "data=" in cuerpo:
            crudo = cuerpo[cuerpo.index("data=") + 5:]
            try:
                datos = json.loads(crudo)
            except json.JSONDecodeError:
                # A veces viene basura pegada despues del JSON; se corta en la
                # llave que balancea la primera.
                profundidad = 0
                for i, letra in enumerate(crudo):
                    if letra == "{":
                        profundidad += 1
                    elif letra == "}":
                        profundidad -= 1
                        if profundidad == 0:
                            try:
                                datos = json.loads(crudo[:i + 1])
                            except json.JSONDecodeError:
                                datos = {}
                            break
        comun = {"tipo": codigo, "lector": self.nombre, "ip": self.ip,
                 "ts": int(datos.get("RealUTC") or 0),
                 "momento": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        if codigo == "_DoorFace_":
            # La marca. No trae el nombre de la persona ni si le abrio: solo el
            # UserID. El nombre sale de la base y el resultado se resuelve
            # mirando si despues llega un DoorStatus=Open (ver nucleo.py).
            return {**comun, "clase": "marca",
                    "id": str(datos.get("UserID", "") or ""),
                    "nombre": "",
                    "metodo": "Rostro",
                    "similitud": int(datos.get("Similarity") or 0),
                    "puerta": int(datos.get("Door") or 0),
                    "concedido": None,        # todavia no se sabe
                    "motivo": ""}

        if codigo == "AccessControl":
            # La marca de metodos que NO son rostro (tarjeta, clave, boton). A
            # diferencia de _DoorFace_, trae el ErrorCode, asi que el veredicto
            # ya viene resuelto y no necesita la ventana de DoorStatus. Sin UserID
            # es un boton de salida o apertura sin persona: no interesa en vivo.
            uid = str(datos.get("UserID", "") or datos.get("CardNo", ""))
            if not uid:
                return None
            codigo_error = str(datos.get("ErrorCode", "0"))
            metodo = str(datos.get("Method", ""))
            return {**comun, "clase": "marca_directa",
                    "id": uid, "nombre": datos.get("CardName", "") or "",
                    "metodo": METODOS.get(metodo, f"Metodo {metodo}" if metodo else ""),
                    "concedido": codigo_error in ("0", ""),
                    "motivo": MOTIVOS.get(codigo_error,
                                          "" if codigo_error in ("0", "") else f"Rechazo {codigo_error}")}

        if codigo == "DoorStatus":
            return {**comun, "clase": "puerta",
                    "abierta": str(datos.get("Status", "")).lower() == "open"}

        if codigo == "_NewFile_":
            # La foto del rostro que capturo. El nombre del archivo es
            # {UserID}_{similitud}_{vivacidad}_{timestamp}.jpg
            ruta = str(datos.get("File", ""))
            usuario = ""
            hoja = ruta.rsplit("/", 1)[-1]
            if "_" in hoja:
                candidato = hoja.split("_", 1)[0]
                if candidato.isdigit():
                    usuario = candidato
            return {**comun, "clase": "foto", "archivo": ruta, "id": usuario}

        return None


class _RPC2:
    """Cliente JSON-RPC del lector. Solo se usa para paginar el historial.

    El login es un desafio-respuesta con dos MD5: primero contra el `realm` que
    manda el equipo, despues contra el `random` de esa sesion.
    """

    def __init__(self, ip, usuario, clave, puerto=80):
        self.base = f"http://{ip}:{puerto}"
        self.usuario = usuario
        self.clave = clave
        self.sesion = None
        self._id = 0

    def _post(self, ruta, cuerpo, timeout=20):
        pedido = urllib.request.Request(self.base + ruta, method="POST",
                                        data=json.dumps(cuerpo).encode())
        pedido.add_header("Content-Type", "application/json")
        if self.sesion:
            pedido.add_header("Cookie", f"DhWebClientSessionID={self.sesion}")
        try:
            with urllib.request.urlopen(pedido, timeout=timeout) as respuesta:
                return json.loads(respuesta.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise ErrorCredenciales(f"RPC2 {self.base}: 401") from exc
            raise ErrorSinRespuesta(f"RPC2 {self.base}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, socket.timeout, OSError, json.JSONDecodeError) as exc:
            raise ErrorSinRespuesta(f"RPC2 {self.base}: {exc}") from exc

    def login(self):
        desafio = self._post("/RPC2_Login", {
            "method": "global.login",
            "params": {"userName": self.usuario, "password": "", "clientType": "Web3.0"},
            "id": 1})
        parametros = desafio.get("params") or {}
        self.sesion = desafio.get("session")
        if not parametros.get("realm"):
            raise ErrorLector(f"RPC2 {self.base}: el equipo no mando el desafio de login")
        uno = hashlib.md5(
            f"{self.usuario}:{parametros['realm']}:{self.clave}".encode()).hexdigest().upper()
        dos = hashlib.md5(
            f"{self.usuario}:{parametros['random']}:{uno}".encode()).hexdigest().upper()
        respuesta = self._post("/RPC2_Login", {
            "method": "global.login",
            "params": {"userName": self.usuario, "password": dos, "clientType": "Web3.0",
                       "loginType": "Direct", "authorityType": "Default",
                       "passwordType": "Default"},
            "id": 2, "session": self.sesion})
        if not respuesta.get("result"):
            raise ErrorCredenciales(f"RPC2 {self.base}: usuario o clave rechazados")
        return self

    def llamar(self, metodo, params=None, objeto=None, timeout=20):
        self._id += 1
        cuerpo = {"method": metodo, "params": params, "id": self._id, "session": self.sesion}
        if objeto is not None:
            cuerpo["object"] = objeto
        return self._post("/RPC2", cuerpo, timeout)

    def logout(self):
        if not self.sesion:
            return
        try:
            self.llamar("global.logout", timeout=5)
        except Exception:
            pass
        self.sesion = None


# Como se identifico la persona. Salen del campo Method del evento/marca.
METODOS = {
    "0": "Sin definir", "1": "Tarjeta", "2": "Huella", "3": "Tarjeta + huella",
    "4": "Clave", "6": "Clave + huella", "8": "Boton", "15": "Rostro",
    "16": "Rostro", "17": "Rostro + tarjeta", "100": "Remoto",
}

# Por que se rechazo. Solo los codigos que aparecen en estos equipos.
MOTIVOS = {
    "0": "", "1": "Sin permiso en esta puerta", "2": "Fuera de horario",
    "3": "Vigencia vencida", "4": "Clave incorrecta", "5": "Persona desconocida",
    "16": "Sin permiso", "0x16": "Sin permiso",
}
