# -*- coding: utf-8 -*-
"""
Base local del panel (SQLite, sin dependencias). Esquema v2, dos sedes.

La idea que ordena todo sigue igual: **la base es la fuente de verdad, no los
lectores**. Se da de alta a la persona una vez, se eligen las puertas, y un
worker empuja eso a cada equipo. Si un lector esta caido, la fila queda
`pendiente` y se sincroniza sola cuando vuelve.

Lo que cambio de v1 a v2, y por que:

  - La persona ya no se identifica por su UserID, sino por un `pid` interno.
    En el Deposito el mismo UserID es OTRA persona en cada puerta, asi que el
    UserID no puede ser la identidad. El UserID vive por acceso (por lector).
  - `accesos` separa lo DESEADO (permitido: lo que el operador quiere) de lo
    OBSERVADO (user_id, nombre_en_lector, estado: lo que hay en el equipo). En
    v1 la importacion pisaba `permitido` y cancelaba bajas en curso.
  - `confirmado=0` es una "reserva": un ID elegido pero todavia no escrito. Si
    se pierde la respuesta del alta, el reintento no duplica ni da falso "ID ocupado".
  - Invariantes como CHECK: la base rechaza los estados imposibles que en v1
    quedaban colgados (permitido=0 con estado=ok, ausente con user_id, etc.).

Ver el diseño completo en docs/diseno-multisede.md.
"""

import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import threading
from datetime import datetime, timedelta

import identidad

# Jerarquia de roles: un numero mas alto puede todo lo del mas bajo.
#   operador   -> solo mira (en vivo, historial, camaras, personas)
#   supervisor -> + altas/bajas, abrir puertas, importar
#   admin      -> + gestionar usuarios y ajustes del sistema
ROLES = {"operador": 1, "supervisor": 2, "admin": 3}

# Secciones de la app. Cada usuario tiene acceso a un subconjunto (visibilidad y
# endpoints). El `rol` sigue mandando el nivel de escritura (operador mira,
# supervisor edita, admin ademas gestiona usuarios). Las secciones dan flexibilidad:
# un RRHH ve solo asistencias, un portero solo puertas.
# "registro" = alta de personas de ASISTENCIA (DNI/tipo/turno/foto/huella -> fichadores + Odoo).
# Es distinto de "personas" (accesos de puerta) y de "asistencias" (el log de fichadas).
SECCIONES = ("en_vivo", "puertas", "personas", "asistencias", "registro", "camaras", "usuarios")

# Secciones por defecto de cada rol (se usan cuando el usuario no tiene una lista
# propia, y como base de los presets).
SECCIONES_POR_ROL = {
    "admin": list(SECCIONES),
    "supervisor": ["en_vivo", "puertas", "personas", "asistencias", "registro", "camaras"],
    "operador": ["en_vivo", "camaras"],
}


def secciones_de_rol(rol):
    return list(SECCIONES_POR_ROL.get(rol, ["en_vivo"]))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RUTA = os.path.join(BASE_DIR, "data", "monitoreo.sqlite3")
RESPALDOS = os.path.join(BASE_DIR, "data", "respaldos")
# Fotos de captura (la que saca el lector al fichar, evento _NewFile_). Se guardan
# en disco, no en la base: son muchas y pesan. En eventos solo va la ruta relativa.
CAPTURAS = os.path.join(BASE_DIR, "data", "capturas")

_LOCK = threading.Lock()

PENDIENTE, OK, ERROR, AUSENTE = "pendiente", "ok", "error", "ausente"

# Los pid arrancan alto para que un UserID (numeros chicos) confundido con un
# pid de por error de a un 404, no abra la ficha de otra persona.
PID_INICIAL = 1_000_000


def conectar():
    os.makedirs(os.path.dirname(RUTA), exist_ok=True)
    cx = sqlite3.connect(RUTA, timeout=30)
    cx.row_factory = sqlite3.Row
    cx.execute("PRAGMA journal_mode=WAL")
    cx.execute("PRAGMA foreign_keys=ON")
    cx.create_function("normalizar", 1, identidad.normalizar, deterministic=True)
    return cx


# ----------------------------------------------------------------------
# Esquema
# ----------------------------------------------------------------------
_ESQUEMA = """
CREATE TABLE IF NOT EXISTS personas (
    pid          INTEGER PRIMARY KEY AUTOINCREMENT,
    sede         TEXT NOT NULL,
    id_preferido TEXT,                    -- compartidos: el UserID en toda la sede. por_lector: NULL
    nombre       TEXT NOT NULL,
    documento    TEXT NOT NULL DEFAULT '',
    sector       TEXT NOT NULL DEFAULT '',
    perfil       TEXT NOT NULL DEFAULT '',
    desde        TEXT NOT NULL DEFAULT '',  -- '' = el panel no administra la vigencia
    hasta        TEXT NOT NULL DEFAULT '',
    foto         BLOB,
    activo       INTEGER NOT NULL DEFAULT 1,
    admin        INTEGER NOT NULL DEFAULT 0, -- Authority 1 en el equipo: baja con confirmacion
    notas        TEXT NOT NULL DEFAULT '',
    creado       TEXT NOT NULL,
    actualizado  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_personas_id
    ON personas(sede, id_preferido) WHERE id_preferido IS NOT NULL;

CREATE TABLE IF NOT EXISTS accesos (
    pid              INTEGER NOT NULL REFERENCES personas(pid) ON DELETE RESTRICT,
    lector           TEXT NOT NULL,               -- ip
    -- DESEADO (solo lo cambia una accion del operador)
    permitido        INTEGER NOT NULL,
    version          INTEGER NOT NULL DEFAULT 0,  -- +1 en cada cambio de deseo
    forzar_nuevo     INTEGER NOT NULL DEFAULT 0,
    -- OBSERVADO / estado de sincronizacion (lo escriben worker e importacion)
    user_id          TEXT NOT NULL DEFAULT '',
    confirmado       INTEGER NOT NULL DEFAULT 0,  -- 0 = reserva sin confirmar en el equipo
    nombre_en_lector TEXT NOT NULL DEFAULT '',    -- texto crudo leido del equipo
    estado           TEXT NOT NULL,               -- pendiente|ok|error|ausente
    error            TEXT NOT NULL DEFAULT '',    -- por que no avanza (bloquea)
    aviso            TEXT NOT NULL DEFAULT '',     -- informativo, no bloquea
    cara             TEXT NOT NULL DEFAULT '?',    -- '?' | 'vista'
    intentos         INTEGER NOT NULL DEFAULT 0,
    visto            TEXT NOT NULL DEFAULT '',     -- ultima lectura del padron que lo encontro
    actualizado      TEXT NOT NULL,
    PRIMARY KEY (pid, lector),
    CHECK (estado IN ('pendiente','ok','error','ausente')),
    CHECK (NOT (estado='ausente' AND user_id!='')),
    CHECK (NOT (estado='ok' AND (permitido=0 OR user_id='' OR confirmado=0))),
    CHECK (NOT (user_id='' AND confirmado=1))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_accesos_uid
    ON accesos(lector, user_id) WHERE user_id != '';
CREATE INDEX IF NOT EXISTS ix_accesos_pid ON accesos(pid);
CREATE INDEX IF NOT EXISTS ix_accesos_pend ON accesos(estado) WHERE estado='pendiente';

CREATE TABLE IF NOT EXISTS perfiles (
    sede     TEXT NOT NULL,
    nombre   TEXT NOT NULL,
    lectores TEXT NOT NULL DEFAULT '[]',
    creado   TEXT NOT NULL,
    PRIMARY KEY (sede, nombre)
);

CREATE TABLE IF NOT EXISTS eventos (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sede       TEXT NOT NULL DEFAULT '',
    lector     TEXT NOT NULL,
    lector_nom TEXT NOT NULL DEFAULT '',
    recno      INTEGER,
    persona_id TEXT NOT NULL DEFAULT '',       -- el UserID crudo del equipo
    pid        INTEGER,                          -- a quien se le atribuyo (NULL = sin atribuir)
    nombre     TEXT NOT NULL DEFAULT '',
    ts         INTEGER NOT NULL,
    momento    TEXT NOT NULL,
    metodo     TEXT NOT NULL DEFAULT '',
    concedido  INTEGER NOT NULL DEFAULT 1,
    motivo     TEXT NOT NULL DEFAULT '',
    vivo       INTEGER NOT NULL DEFAULT 0,
    foto       TEXT NOT NULL DEFAULT ''        -- ruta relativa de la foto de captura ('' = sin foto)
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_evento_unico
    ON eventos (lector, ts, persona_id, metodo);
CREATE INDEX IF NOT EXISTS ix_evento_sede ON eventos (sede, ts DESC);
CREATE INDEX IF NOT EXISTS ix_evento_pid  ON eventos (pid, ts DESC);
-- Atribucion de marcas: el UPDATE ... WHERE pid IS NULL escaneaba la particion
-- entera de la sede (medido 84ms -> 1ms con este indice parcial).
CREATE INDEX IF NOT EXISTS ix_evento_atrib ON eventos (lector, persona_id) WHERE pid IS NULL;
-- Filtro del historial por puerta.
CREATE INDEX IF NOT EXISTS ix_evento_sede_lector ON eventos (sede, lector, ts DESC);

CREATE TABLE IF NOT EXISTS estado_lector (
    lector       TEXT PRIMARY KEY,
    ultimo_recno INTEGER NOT NULL DEFAULT 0,
    proximo_id   INTEGER NOT NULL DEFAULT 0,   -- contador de IDs nuevos, monotonico
    serie        TEXT NOT NULL DEFAULT '',     -- serie del equipo: si cambia, se reemplazo
    visto        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ajustes (
    clave TEXT PRIMARY KEY,
    valor TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS usuarios (
    usuario       TEXT PRIMARY KEY,        -- nombre de login, en minusculas
    nombre        TEXT NOT NULL DEFAULT '',-- nombre visible
    rol           TEXT NOT NULL,           -- admin | supervisor | operador (nivel de escritura)
    clave_hash    TEXT NOT NULL,           -- pbkdf2-sha256, hex
    salt          TEXT NOT NULL,
    activo        INTEGER NOT NULL DEFAULT 1,
    puertas       TEXT NOT NULL DEFAULT '[]', -- IPs que puede abrir aparte del rol
    secciones     TEXT NOT NULL DEFAULT '[]', -- secciones habilitadas ([] = las del rol)
    sedes         TEXT NOT NULL DEFAULT '[]', -- sedes que puede ver ([] = todas)
    creado        TEXT NOT NULL,
    ultimo_acceso TEXT NOT NULL DEFAULT '',
    CHECK (rol IN ('admin','supervisor','operador'))
);

-- Marcas de ASISTENCIA (entrada/salida) de los 5 fichadores. Es un area aparte
-- de los accesos de puerta: estos equipos registran la jornada (van a Odoo por
-- otro conector, que NO tocamos). El panel las lee por HTTP (RecordFinder) y las
-- muestra con la foto que saca el fichador al marcar. `foto` = ruta relativa.
CREATE TABLE IF NOT EXISTS asistencias (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    lector     TEXT NOT NULL,                 -- ip del fichador
    lector_nom TEXT NOT NULL DEFAULT '',
    sede       TEXT NOT NULL DEFAULT '',
    recno      INTEGER,                        -- RecNo del equipo (para no duplicar)
    user_id    TEXT NOT NULL DEFAULT '',
    nombre     TEXT NOT NULL DEFAULT '',
    ts         INTEGER NOT NULL,
    momento    TEXT NOT NULL,
    tipo       TEXT NOT NULL DEFAULT '',       -- Entry | Exit (direccion de la marca)
    metodo     TEXT NOT NULL DEFAULT '',
    concedido  INTEGER NOT NULL DEFAULT 1,
    motivo     TEXT NOT NULL DEFAULT '',
    foto       TEXT NOT NULL DEFAULT '',       -- ruta relativa de la foto de captura ('' = sin foto)
    creado     TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_asistencia_recno
    ON asistencias (lector, recno) WHERE recno IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_asistencia_sede ON asistencias (sede, ts DESC);
CREATE INDEX IF NOT EXISTS ix_asistencia_uid  ON asistencias (lector, user_id, ts);
"""


def _ejecutar_ddl(cx, script):
    """Corre el DDL sentencia por sentencia. NO usa executescript porque ese hace
    un COMMIT implicito y rompe la atomicidad de la migracion."""
    for sentencia in script.split(";"):
        if sentencia.strip():
            cx.execute(sentencia)


def _version(cx):
    return cx.execute("PRAGMA user_version").fetchone()[0]


def _tiene_tabla(cx, nombre):
    return cx.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                      (nombre,)).fetchone() is not None


def _columnas(cx, tabla):
    return {f["name"] for f in cx.execute(f"PRAGMA table_info({tabla})").fetchall()}


class MigracionAbortada(Exception):
    """La base v1 no esta en condiciones de migrar; se explica por que."""


def iniciar(sede_v1=None):
    """Crea el esquema v2 o migra desde v1. Devuelve 'nueva' | 'v2' | 'migrada'.

    `sede_v1` es la clave de sede a la que pertenece la base v1 (una sola sede
    por definicion). Si hay una base v1 y no se pasa, se aborta.
    """
    os.makedirs(os.path.dirname(RUTA), exist_ok=True)
    with _LOCK, conectar() as cx:
        if not _tiene_tabla(cx, "personas"):
            cx.executescript(_ESQUEMA)
            cx.execute(f"UPDATE sqlite_sequence SET seq={PID_INICIAL} WHERE name='personas'")
            cx.execute("INSERT OR IGNORE INTO sqlite_sequence(name, seq) VALUES ('personas', ?)",
                       (PID_INICIAL,))
            cx.execute("PRAGMA user_version=2")
            return "nueva"
        version = _version(cx)
        if version > 2:
            raise MigracionAbortada(
                f"la base es version {version}, mas nueva que este panel (2)")
        if version == 2 or "pid" in _columnas(cx, "personas"):
            cx.executescript(_ESQUEMA)          # crea lo que falte, idempotente
            # Columnas agregadas despues de crear la tabla usuarios: el CREATE IF
            # NOT EXISTS no las suma solo.
            if "puertas" not in _columnas(cx, "usuarios"):
                cx.execute("ALTER TABLE usuarios ADD COLUMN puertas TEXT NOT NULL DEFAULT '[]'")
            if "secciones" not in _columnas(cx, "usuarios"):
                cx.execute("ALTER TABLE usuarios ADD COLUMN secciones TEXT NOT NULL DEFAULT '[]'")
            if "sedes" not in _columnas(cx, "usuarios"):
                cx.execute("ALTER TABLE usuarios ADD COLUMN sedes TEXT NOT NULL DEFAULT '[]'")
            if "foto" not in _columnas(cx, "eventos"):
                cx.execute("ALTER TABLE eventos ADD COLUMN foto TEXT NOT NULL DEFAULT ''")
            if version < 2:
                cx.execute("PRAGMA user_version=2")
            return "v2"
    # Es v1: migrar fuera del lock de arriba (usa su propia transaccion).
    return _migrar_v1(sede_v1)


def _migrar_v1(sede_v1):
    if not sede_v1:
        raise MigracionAbortada(
            "hay una base v1 (una sola sede) y no se indico a que sede pertenece. "
            "Pone 'sede_v1' en config.json o convierte la base a mano.")
    with _LOCK, conectar() as cx:
        # Controles previos: no migrar con escrituras a medio camino.
        pendientes = cx.execute(
            "SELECT persona_id, lector, estado, error FROM accesos "
            "WHERE estado IN ('pendiente','error') OR (permitido=0 AND estado='ok') "
            "LIMIT 20").fetchall()
        if pendientes:
            detalle = "; ".join(f"{f['persona_id']}@{f['lector']} ({f['estado']})"
                                for f in pendientes)
            raise MigracionAbortada(
                "hay accesos sin sincronizar en la base v1; sincronizalos o resolvelos "
                f"antes de migrar: {detalle}")

        _respaldar(cx)

        cx.execute("BEGIN IMMEDIATE")
        try:
            cx.execute("ALTER TABLE personas RENAME TO personas_v1")
            cx.execute("ALTER TABLE accesos RENAME TO accesos_v1")
            cx.execute("ALTER TABLE perfiles RENAME TO perfiles_v1")
            # Sumar las columnas nuevas a eventos y estado_lector ANTES del DDL,
            # porque el esquema crea indices que las referencian.
            for tabla, col, tipo, defecto in (
                    ("eventos", "sede", "TEXT", f"'{sede_v1}'"),
                    ("eventos", "pid", "INTEGER", None),
                    ("estado_lector", "proximo_id", "INTEGER", "0"),
                    ("estado_lector", "serie", "TEXT", "''")):
                if col not in _columnas(cx, tabla):
                    cola = f" NOT NULL DEFAULT {defecto}" if defecto is not None else ""
                    cx.execute(f"ALTER TABLE {tabla} ADD COLUMN {col} {tipo}{cola}")
            _ejecutar_ddl(cx, _ESQUEMA)     # crea personas/accesos/perfiles v2 e indices
            cx.execute(f"UPDATE sqlite_sequence SET seq={PID_INICIAL} WHERE name='personas'")
            cx.execute("INSERT OR IGNORE INTO sqlite_sequence(name, seq) VALUES ('personas', ?)",
                       (PID_INICIAL,))
            cx.execute("UPDATE eventos SET sede=? WHERE sede=''", (sede_v1,))
            cx.execute("PRAGMA user_version=2")
            cx.execute("COMMIT")
        except Exception:
            try:
                cx.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
    return "migrada"


def _respaldar(cx):
    """Copia consistente de la base antes de migrar. Deja el WAL adentro del archivo."""
    os.makedirs(RESPALDOS, exist_ok=True)
    cx.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    sello = datetime.now().strftime("%Y%m%d-%H%M%S")
    destino = os.path.join(RESPALDOS, f"monitoreo-v1-{sello}.sqlite3")
    with sqlite3.connect(destino) as copia:
        cx.backup(copia)
    with sqlite3.connect(destino) as copia:
        estado = copia.execute("PRAGMA integrity_check").fetchone()[0]
    if estado != "ok":
        raise MigracionAbortada(f"el respaldo {destino} no paso integrity_check ({estado})")
    return destino


def ahora():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def vigencia_por_defecto(anios=10):
    """(desde, hasta) para una persona nueva: hoy 00:00 hasta hoy + N años 23:59."""
    hoy = datetime.now()
    desde = hoy.strftime("%Y-%m-%d 00:00:00")
    try:
        fin = hoy.replace(year=hoy.year + anios)
    except ValueError:          # 29 de febrero -> 28
        fin = hoy.replace(year=hoy.year + anios, month=2, day=28)
    return desde, fin.strftime("%Y-%m-%d 23:59:59")


# ----------------------------------------------------------------------
# Personas
# ----------------------------------------------------------------------
def _persona_dict(fila):
    datos = {k: fila[k] for k in fila.keys() if k != "foto"}
    if "foto" in fila.keys():
        datos["tiene_foto"] = fila["foto"] is not None
    datos["activo"] = bool(datos.get("activo", 1))
    datos["admin"] = bool(datos.get("admin", 0))
    return datos


def listar_personas(sede, busqueda="", lector=None, solo_activos=False):
    sql = """
        SELECT p.*,
               (SELECT COUNT(*) FROM accesos a
                 WHERE a.pid=p.pid AND a.permitido=1)                       AS puertas,
               (SELECT COUNT(*) FROM accesos a
                 WHERE a.pid=p.pid AND a.permitido=1 AND a.estado!='ok')    AS sin_sincronizar,
               (SELECT COUNT(*) FROM accesos a
                 WHERE a.pid=p.pid AND a.estado='error')                    AS con_error,
               (SELECT COUNT(*) FROM accesos a
                 WHERE a.pid=p.pid AND a.user_id!='' AND p.activo=0)        AS baja_incompleta
          FROM personas p WHERE p.sede=?
    """
    parametros = [sede]
    if busqueda:
        sql += (" AND (p.nombre LIKE ? OR p.documento LIKE ?"
                " OR p.id_preferido LIKE ? OR EXISTS (SELECT 1 FROM accesos a"
                " WHERE a.pid=p.pid AND a.user_id LIKE ?))")
        comodin = f"%{busqueda}%"
        parametros += [comodin, comodin, comodin, comodin]
    if lector:
        sql += (" AND EXISTS (SELECT 1 FROM accesos a WHERE a.pid=p.pid"
                " AND a.lector=? AND a.permitido=1)")
        parametros.append(lector)
    if solo_activos:
        sql += " AND (p.activo=1 OR EXISTS (SELECT 1 FROM accesos a WHERE a.pid=p.pid" \
               " AND (a.user_id!='' OR a.estado IN ('pendiente','error'))))"
    sql += " ORDER BY p.activo DESC, p.nombre COLLATE NOCASE"
    with conectar() as cx:
        return [_persona_dict(f) for f in cx.execute(sql, parametros).fetchall()]


def persona(sede, pid):
    with conectar() as cx:
        fila = cx.execute("SELECT * FROM personas WHERE pid=? AND sede=?", (pid, sede)).fetchone()
        if not fila:
            return None
        datos = _persona_dict(fila)
        datos["accesos"] = [dict(a) for a in cx.execute(
            "SELECT lector, permitido, version, forzar_nuevo, user_id, confirmado,"
            " nombre_en_lector, estado, error, aviso, cara, intentos, actualizado"
            " FROM accesos WHERE pid=? ORDER BY lector", (pid,)).fetchall()]
    return datos


def foto(sede, pid):
    with conectar() as cx:
        fila = cx.execute("SELECT foto FROM personas WHERE pid=? AND sede=?",
                          (pid, sede)).fetchone()
    return fila["foto"] if fila else None


def pid_por_id_preferido(cx, sede, id_preferido):
    fila = cx.execute("SELECT pid FROM personas WHERE sede=? AND id_preferido=?",
                      (sede, id_preferido)).fetchone()
    return fila["pid"] if fila else None


def _upsert_persona(cx, sede, pid, datos, momento):
    """Crea o actualiza los campos propios de la persona (no toca accesos). Devuelve pid."""
    campos = ("nombre", "documento", "sector", "perfil", "desde", "hasta", "notas")
    if pid is None:
        cols = ", ".join(campos)
        marcas = ",".join("?" * len(campos))
        cx.execute(
            f"INSERT INTO personas (sede, id_preferido, {cols}, activo, admin, creado, actualizado) "
            f"VALUES (?,?,{marcas},?,?,?,?)",
            (sede, datos.get("id_preferido")) + tuple(datos.get(c, "") for c in campos)
            + (1 if datos.get("activo", True) else 0, 1 if datos.get("admin") else 0,
               momento, momento))
        pid = cx.execute("SELECT last_insert_rowid()").fetchone()[0]
    else:
        sets = ", ".join(f"{c}=?" for c in campos)
        cx.execute(
            f"UPDATE personas SET {sets}, id_preferido=?, activo=?, actualizado=? WHERE pid=?",
            tuple(datos.get(c, "") for c in campos)
            + (datos.get("id_preferido"), 1 if datos.get("activo", True) else 0, momento, pid))
    if datos.get("foto_bytes") is not None:
        cx.execute("UPDATE personas SET foto=? WHERE pid=?", (datos["foto_bytes"], pid))
    return pid


def _cambio_vigencia(cx, pid, datos):
    fila = cx.execute("SELECT desde, hasta, documento FROM personas WHERE pid=?", (pid,)).fetchone()
    if not fila:
        return True
    return (datos.get("desde", "") != fila["desde"] or datos.get("hasta", "") != fila["hasta"]
            or datos.get("documento", "") != fila["documento"])


def guardar_persona(sede, pid, datos, lectores_deseados, ids_compartidos):
    """Alta o edicion de una persona y su conjunto de puertas deseadas.

    No toca los equipos: deja las filas en `pendiente` y el worker las aplica.
    `lectores_deseados` son IP ya validadas como de esta sede (lo hace el servidor).
    `ids_compartidos` dice si la sede numera igual en todas las puertas.

    Devuelve (pid, error). Si error != '', no se escribio nada.
    """
    momento = ahora()
    deseados = set(lectores_deseados or [])
    activo = bool(datos.get("activo", True))
    id_pref = None
    with _LOCK, conectar() as cx:
        if pid is not None and not cx.execute(
                "SELECT 1 FROM personas WHERE pid=? AND sede=?", (pid, sede)).fetchone():
            return None, "esa persona no existe en esta sede"

        if ids_compartidos:
            id_pref = (datos.get("id_preferido") or "").strip()
            if not id_pref.isalnum():
                return None, "el ID solo puede tener letras y numeros"
            datos["id_preferido"] = id_pref
            # Si todavia esta CARGADO en algun lector para otra persona, no se puede
            # reusar (aunque el otro figure inactivo): seguiria entrando.
            ocupa = cx.execute(
                "SELECT a.lector FROM accesos a JOIN personas p ON p.pid=a.pid"
                " WHERE p.sede=? AND a.user_id=? AND a.pid IS NOT ? LIMIT 1",
                (sede, id_pref, pid if pid is not None else -1)).fetchone()
            if ocupa:
                return None, f"el ID {id_pref} esta cargado en {ocupa['lector']} para otra persona"
            otro = cx.execute(
                "SELECT pid, nombre, activo FROM personas WHERE sede=? AND id_preferido=? "
                "AND pid IS NOT ?", (sede, id_pref, pid if pid is not None else -1)).fetchone()
            if otro:
                # El numero ya NO esta en ningun lector (paso el `ocupa` de arriba).
                # Si el que lo tenia esta dado de baja, se libera para reusarlo. Si
                # esta activo, es un choque real y no se toca.
                if otro["activo"]:
                    return None, f"el ID {id_pref} ya lo usa {otro['nombre']} en esta sede"
                cx.execute("UPDATE personas SET id_preferido=NULL WHERE pid=?", (otro["pid"],))
        else:
            datos["id_preferido"] = None

        pid = _upsert_persona(cx, sede, pid, datos, momento)
        actuales = {f["lector"]: f for f in cx.execute(
            "SELECT * FROM accesos WHERE pid=?", (pid,)).fetchall()}

        for ip in deseados:
            fila = actuales.get(ip)
            if fila is None:
                if ids_compartidos:
                    if cx.execute("SELECT 1 FROM accesos WHERE lector=? AND user_id=?",
                                  (ip, id_pref)).fetchone():
                        return None, f"el ID {id_pref} en {ip} esta asignado a otra persona"
                    cx.execute(
                        "INSERT INTO accesos (pid, lector, permitido, version, user_id, confirmado,"
                        " nombre_en_lector, estado, actualizado) VALUES (?,?,1,1,?,0,?,?,?)",
                        (pid, ip, id_pref, datos.get("nombre", ""), PENDIENTE, momento))
                else:
                    cx.execute(
                        "INSERT INTO accesos (pid, lector, permitido, version, estado, actualizado)"
                        " VALUES (?,?,1,1,?,?)", (pid, ip, PENDIENTE, momento))
            elif fila["permitido"] == 0 or fila["estado"] == AUSENTE:
                cx.execute(
                    "UPDATE accesos SET permitido=1, version=version+1, forzar_nuevo=0,"
                    " estado=?, error='' WHERE pid=? AND lector=?", (PENDIENTE, pid, ip))
            else:
                cambio_nombre = bool(ids_compartidos and fila["nombre_en_lector"] and
                                     not identidad.mismo_registro(fila["nombre_en_lector"],
                                                                  datos.get("nombre", "")))
                if fila["estado"] != ERROR and (cambio_nombre or _cambio_vigencia(cx, pid, datos)):
                    cx.execute(
                        "UPDATE accesos SET version=version+1, estado=? "
                        "WHERE pid=? AND lector=? AND estado!='error'", (PENDIENTE, pid, ip))

        for ip, fila in actuales.items():
            if ip in deseados:
                continue
            if fila["permitido"] == 0 and fila["estado"] == AUSENTE and fila["user_id"] == "":
                continue
            cx.execute(
                "UPDATE accesos SET permitido=0, version=version+1, estado=?, error=''"
                " WHERE pid=? AND lector=?", (PENDIENTE, pid, ip))

        if not activo:
            cx.execute(
                "UPDATE accesos SET permitido=0, version=version+1, estado=? "
                "WHERE pid=? AND (user_id!='' OR estado!='ausente')", (PENDIENTE, pid))

        # Foto nueva: marcar la cara como no cargada y re-encolar los accesos
        # activos para que el worker la empuje (aunque no haya cambiado nada mas).
        if activo and datos.get("foto_bytes") is not None:
            cx.execute("UPDATE accesos SET cara='?' WHERE pid=?", (pid,))
            cx.execute(
                "UPDATE accesos SET version=version+1, estado=? "
                "WHERE pid=? AND permitido=1 AND estado='ok'", (PENDIENTE, pid))
        cx.execute("UPDATE personas SET actualizado=? WHERE pid=?", (momento, pid))
    return pid, ""


def dar_de_baja(sede, pid, incluir_pids=()):
    """Baja: activo=0 y toda puerta con registro pasa a permitido=0 pendiente,
    incluidas las que estaban en error. La persona queda en la base."""
    momento = ahora()
    with _LOCK, conectar() as cx:
        objetivos = [pid] + list(incluir_pids)
        marca = ",".join("?" * len(objetivos))
        validos = [f["pid"] for f in cx.execute(
            f"SELECT pid FROM personas WHERE sede=? AND pid IN ({marca})",
            [sede] + objetivos).fetchall()]
        for p in validos:
            cx.execute("UPDATE personas SET activo=0, actualizado=? WHERE pid=?", (momento, p))
            cx.execute(
                "UPDATE accesos SET permitido=0, version=version+1, estado=? "
                "WHERE pid=? AND (user_id!='' OR estado!='ausente')", (PENDIENTE, p))
    return validos


def reactivar(sede, pid):
    with _LOCK, conectar() as cx:
        cx.execute("UPDATE personas SET activo=1, actualizado=? WHERE pid=? AND sede=?",
                   (ahora(), pid, sede))


def borrar_persona(sede, pid):
    """Solo si ninguna puerta la tiene cargada ni pendiente. Devuelve (ok, error)."""
    with _LOCK, conectar() as cx:
        if not cx.execute("SELECT 1 FROM personas WHERE pid=? AND sede=?", (pid, sede)).fetchone():
            return False, "no existe"
        traba = cx.execute(
            "SELECT lector FROM accesos WHERE pid=? AND (user_id!='' OR estado IN"
            " ('pendiente','error')) LIMIT 1", (pid,)).fetchone()
        if traba:
            return False, f"sigue cargada o pendiente en {traba['lector']}; sacala primero"
        cx.execute("DELETE FROM accesos WHERE pid=?", (pid,))
        cx.execute("DELETE FROM personas WHERE pid=?", (pid,))
    return True, ""


# ----------------------------------------------------------------------
# Worker: leer pendientes y grabar resultados
# ----------------------------------------------------------------------
def pendientes(sede, lectores_sede):
    """Accesos pendientes de la sede, con los datos de la persona. Bajas primero."""
    if not lectores_sede:
        return []
    marca = ",".join("?" * len(lectores_sede))
    with conectar() as cx:
        filas = cx.execute(
            f"SELECT a.pid, a.lector, a.permitido, a.version, a.forzar_nuevo, a.user_id,"
            f" a.confirmado, a.nombre_en_lector, a.intentos, a.cara,"
            f" p.nombre, p.desde, p.hasta, p.documento, p.activo, p.id_preferido, p.admin,"
            f" (p.foto IS NOT NULL) AS tiene_foto"
            f" FROM accesos a JOIN personas p ON p.pid=a.pid"
            f" WHERE a.estado='pendiente' AND a.lector IN ({marca})"
            f" ORDER BY a.permitido ASC, a.actualizado", lectores_sede).fetchall()
    return [dict(f) for f in filas]


def observar(pid, lector, **campos):
    """Escribe columnas OBSERVADAS. Sin condicion de version: el operador nunca
    toca estas columnas, asi que no hay carrera que perder."""
    permitidas = {"user_id", "confirmado", "nombre_en_lector", "aviso", "cara", "visto"}
    usar = {k: v for k, v in campos.items() if k in permitidas}
    if not usar:
        return
    sets = ", ".join(f"{k}=?" for k in usar)
    with _LOCK, conectar() as cx:
        cx.execute(f"UPDATE accesos SET {sets}, actualizado=? WHERE pid=? AND lector=?",
                   list(usar.values()) + [ahora(), pid, lector])


def poner_estado(pid, lector, version, estado, error="", intentos=None):
    """Escribe el estado de sincronizacion solo si la version no cambio. Devuelve
    True si escribio (False = el operador toco el deseo mientras tanto)."""
    with _LOCK, conectar() as cx:
        extra = ", intentos=?" if intentos is not None else ""
        args = [estado, error]
        if intentos is not None:
            args.append(intentos)
        args += [ahora(), pid, lector, version]
        cur = cx.execute(
            f"UPDATE accesos SET estado=?, error=?{extra}, actualizado=? "
            f"WHERE pid=? AND lector=? AND version=?", args)
        return cur.rowcount > 0


def reservar_id(pid, lector, user_id, nombre_en_lector):
    """Reserva un ID (confirmado=0) para un alta. Devuelve True si no choco el
    indice unico (lector, user_id)."""
    with _LOCK, conectar() as cx:
        try:
            cx.execute(
                "UPDATE accesos SET user_id=?, confirmado=0, nombre_en_lector=?, actualizado=? "
                "WHERE pid=? AND lector=?", (user_id, nombre_en_lector, ahora(), pid, lector))
            return True
        except sqlite3.IntegrityError:
            return False


def proximo_id(lector):
    with conectar() as cx:
        fila = cx.execute("SELECT proximo_id FROM estado_lector WHERE lector=?",
                          (lector,)).fetchone()
    return fila["proximo_id"] if fila else 0


def subir_proximo_id(lector, valor):
    with _LOCK, conectar() as cx:
        cx.execute(
            "INSERT INTO estado_lector (lector, proximo_id, visto) VALUES (?,?,?) "
            "ON CONFLICT(lector) DO UPDATE SET proximo_id=MAX(proximo_id, ?), visto=?",
            (lector, valor, ahora(), valor, ahora()))


def user_ids_en_uso(sede, lector):
    """UserID (numericos) que la base ya tiene mapeados en ese lector de la sede."""
    with conectar() as cx:
        filas = cx.execute(
            "SELECT a.user_id FROM accesos a JOIN personas p ON p.pid=a.pid"
            " WHERE p.sede=? AND a.lector=? AND a.user_id!=''", (sede, lector)).fetchall()
    return {f["user_id"] for f in filas}


# ----------------------------------------------------------------------
# Acciones de resolucion por acceso (las llama el servidor)
# ----------------------------------------------------------------------
def _acceso(cx, sede, pid, lector):
    return cx.execute(
        "SELECT a.* FROM accesos a JOIN personas p ON p.pid=a.pid"
        " WHERE a.pid=? AND a.lector=? AND p.sede=?", (pid, lector, sede)).fetchone()


def accion_acceso(sede, pid, lector, accion, extra=None):
    """Botones de la ficha para destrabar conflictos. Devuelve (ok, error)."""
    momento = ahora()
    with _LOCK, conectar() as cx:
        fila = _acceso(cx, sede, pid, lector)
        if not fila:
            return False, "no existe ese acceso"

        def set(**kw):
            sets = ", ".join(f"{k}=?" for k in kw)
            cx.execute(f"UPDATE accesos SET {sets}, actualizado=? WHERE pid=? AND lector=?",
                       list(kw.values()) + [momento, pid, lector])

        if accion == "reintentar":
            set(estado=PENDIENTE, error="", intentos=0, version=fila["version"] + 1)
        elif accion == "desvincular":
            if fila["permitido"] == 1:
                set(user_id="", confirmado=0, estado=ERROR,
                    error="desvinculado; reintentá para crear un registro nuevo")
            else:
                set(user_id="", confirmado=0, estado=AUSENTE, error="")
        elif accion == "crear_nuevo":
            set(forzar_nuevo=1, user_id="", confirmado=0, estado=PENDIENTE, error="",
                version=fila["version"] + 1)
        elif accion == "sacar":
            set(permitido=0, estado=PENDIENTE, error="", version=fila["version"] + 1)
        elif accion == "vincular":
            uid = str((extra or {}).get("user_id") or "").strip()
            if not uid:
                return False, "falta el ID a vincular"
            if cx.execute("SELECT 1 FROM accesos WHERE lector=? AND user_id=? AND pid!=?",
                          (lector, uid, pid)).fetchone():
                return False, f"el ID {uid} en {lector} ya esta asignado a otra persona"
            set(user_id=uid, confirmado=1, estado=PENDIENTE, error="",
                nombre_en_lector=(extra or {}).get("nombre", ""), version=fila["version"] + 1)
        elif accion == "adoptar_nombre":
            nombre = (extra or {}).get("nombre", "")
            if not nombre:
                return False, "falta el nombre leido del equipo"
            set(nombre_en_lector=nombre, estado=PENDIENTE, error="")
        else:
            return False, f"accion desconocida: {accion}"
    return True, ""


def unir(sede, pid_destino, pid_origen):
    """Fusiona dos personas de la misma sede en una. Devuelve (ok, error)."""
    if pid_destino == pid_origen:
        return False, "son la misma persona"
    with _LOCK, conectar() as cx:
        d = cx.execute("SELECT 1 FROM personas WHERE pid=? AND sede=?", (pid_destino, sede)).fetchone()
        o = cx.execute("SELECT 1 FROM personas WHERE pid=? AND sede=?", (pid_origen, sede)).fetchone()
        if not d or not o:
            return False, "alguna de las dos no existe en esta sede"
        choque = cx.execute(
            "SELECT d.lector FROM accesos d JOIN accesos o ON d.lector=o.lector"
            " WHERE d.pid=? AND o.pid=? AND d.user_id!='' AND o.user_id!=''"
            " LIMIT 1", (pid_destino, pid_origen)).fetchone()
        if choque:
            return False, f"las dos tienen un registro en {choque['lector']}; sacá el sobrante primero"
        destino_lectores = {f["lector"] for f in cx.execute(
            "SELECT lector FROM accesos WHERE pid=?", (pid_destino,)).fetchall()}
        for fila in cx.execute("SELECT * FROM accesos WHERE pid=?", (pid_origen,)).fetchall():
            if fila["lector"] in destino_lectores:
                dest = cx.execute("SELECT user_id FROM accesos WHERE pid=? AND lector=?",
                                  (pid_destino, fila["lector"])).fetchone()
                # Conservar la fila que tenga user_id; si el origen lo tiene y el destino no, mover.
                if not dest["user_id"] and fila["user_id"]:
                    cx.execute("DELETE FROM accesos WHERE pid=? AND lector=?",
                               (pid_destino, fila["lector"]))
                    cx.execute("UPDATE accesos SET pid=? WHERE pid=? AND lector=?",
                               (pid_destino, pid_origen, fila["lector"]))
                else:
                    cx.execute("DELETE FROM accesos WHERE pid=? AND lector=?",
                               (pid_origen, fila["lector"]))
            else:
                cx.execute("UPDATE accesos SET pid=? WHERE pid=? AND lector=?",
                           (pid_destino, pid_origen, fila["lector"]))
        cx.execute("DELETE FROM personas WHERE pid=?", (pid_origen,))
    return True, ""


def separar(sede, pid, lectores):
    """Saca esos lectores del pid a una persona nueva con el mismo nombre. Devuelve nuevo pid."""
    momento = ahora()
    with _LOCK, conectar() as cx:
        p = cx.execute("SELECT nombre FROM personas WHERE pid=? AND sede=?", (pid, sede)).fetchone()
        if not p:
            return None
        cx.execute("INSERT INTO personas (sede, nombre, creado, actualizado) VALUES (?,?,?,?)",
                   (sede, p["nombre"], momento, momento))
        nuevo = cx.execute("SELECT last_insert_rowid()").fetchone()[0]
        for ip in lectores:
            cx.execute("UPDATE accesos SET pid=? WHERE pid=? AND lector=?", (nuevo, pid, ip))
    return nuevo


# ----------------------------------------------------------------------
# Perfiles de acceso (por sede)
# ----------------------------------------------------------------------
def listar_perfiles(sede):
    with conectar() as cx:
        filas = cx.execute("SELECT nombre, lectores FROM perfiles WHERE sede=? ORDER BY nombre",
                           (sede,)).fetchall()
    return [{"nombre": f["nombre"], "lectores": json.loads(f["lectores"])} for f in filas]


def guardar_perfil(sede, nombre, lectores):
    with _LOCK, conectar() as cx:
        cx.execute(
            "INSERT INTO perfiles (sede, nombre, lectores, creado) VALUES (?,?,?,?) "
            "ON CONFLICT(sede, nombre) DO UPDATE SET lectores=?",
            (sede, nombre, json.dumps(lectores), ahora(), json.dumps(lectores)))


def borrar_perfil(sede, nombre):
    with _LOCK, conectar() as cx:
        cx.execute("DELETE FROM perfiles WHERE sede=? AND nombre=?", (sede, nombre))


# ----------------------------------------------------------------------
# Eventos
# ----------------------------------------------------------------------
def _fila_evento(e, vivo):
    return (e.get("sede", ""), e.get("ip", ""), e.get("lector", ""), e.get("recno"),
            e.get("id", ""), e.get("pid"), e.get("nombre", ""), e.get("ts", 0),
            e.get("momento", ""), e.get("metodo", ""),
            1 if e.get("concedido") else 0, e.get("motivo", ""), 1 if vivo else 0,
            e.get("foto", ""))


_INSERT_EVENTO = (
    "INSERT OR IGNORE INTO eventos (sede, lector, lector_nom, recno, persona_id, pid,"
    " nombre, ts, momento, metodo, concedido, motivo, vivo, foto)"
    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)")


def guardar_evento(evento, vivo=False):
    """Devuelve True si el evento es nuevo."""
    with _LOCK, conectar() as cx:
        cur = cx.execute(_INSERT_EVENTO, _fila_evento(evento, vivo))
        return cur.rowcount > 0


def guardar_eventos(eventos):
    """Alta masiva (historial). Devuelve cuantos entraron nuevos."""
    if not eventos:
        return 0
    filas = [_fila_evento(e, False) for e in eventos]
    with _LOCK, conectar() as cx:
        antes = cx.total_changes
        cx.executemany(_INSERT_EVENTO, filas)
        return cx.total_changes - antes


def corregir_desde_historial(eventos):
    """Corrige el veredicto (concedido/motivo) de las marcas vivas con el dato real
    del historial. Devuelve cuantas corrigio."""
    if not eventos:
        return 0
    corregidos = 0
    with _LOCK, conectar() as cx:
        for e in eventos:
            cur = cx.execute(
                "UPDATE eventos SET concedido=?, motivo=?, recno=? "
                "WHERE lector=? AND ts=? AND persona_id=? AND vivo=1 "
                "AND (concedido!=? OR motivo!=?)",
                (1 if e.get("concedido") else 0, e.get("motivo", ""), e.get("recno"),
                 e.get("ip", ""), e.get("ts", 0), e.get("id", ""),
                 1 if e.get("concedido") else 0, e.get("motivo", "")))
            corregidos += cur.rowcount
    return corregidos


def atribuir_eventos(sede, lector, user_id, pid, nombre_en_lector):
    """Le pone `pid` a las marcas de ese (lector, user_id) cuyo nombre coincide con
    el actual. Las de otro nombre quedan en NULL: son de un dueño anterior del ID."""
    with _LOCK, conectar() as cx:
        cx.execute(
            "UPDATE eventos SET pid=? WHERE sede=? AND lector=? AND persona_id=? AND pid IS NULL"
            " AND (nombre='' OR normalizar(nombre)=normalizar(?))",
            (pid, sede, lector, user_id, nombre_en_lector))


# ----------------------------------------------------------------------
# Fotos de captura (evento _NewFile_): la que saca el lector al fichar
# ----------------------------------------------------------------------
def _relpath_captura(sede, lector_ip, user_id, ts):
    """Ruta relativa (dentro de CAPTURAS) donde guardar la foto de una marca.
    Se agrupa por dia para que la purga sea barata (borrar carpetas viejas)."""
    momento = datetime.fromtimestamp(ts) if ts else datetime.now()
    dia = momento.strftime("%Y-%m-%d")
    seguro = lambda s: "".join(c for c in str(s) if c.isalnum() or c in "._-")
    nombre = f"{seguro(sede)}_{seguro(lector_ip)}_{seguro(user_id) or 'x'}_{int(ts or 0)}.jpg"
    return f"{dia}/{nombre}"


def guardar_foto_captura(sede, lector_ip, user_id, ts, jpg_bytes):
    """Escribe la foto en disco y devuelve la ruta relativa a guardar en eventos."""
    rel = _relpath_captura(sede, lector_ip, user_id, ts)
    destino = os.path.join(CAPTURAS, *rel.split("/"))
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    with open(destino, "wb") as fh:
        fh.write(jpg_bytes)
    return rel


def leer_foto_captura(relpath):
    """Devuelve los bytes de una foto de captura, o None. Cuida el path traversal."""
    if not relpath:
        return None
    destino = os.path.normpath(os.path.join(CAPTURAS, *relpath.split("/")))
    if not destino.startswith(os.path.normpath(CAPTURAS) + os.sep):
        return None
    try:
        with open(destino, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def adjuntar_foto_evento(sede, lector_ip, user_id, relpath, ts=None, ventana=180):
    """Le pega la ruta de la foto a la marca de ese (sede, lector, user_id) mas
    cercana en el tiempo que todavia no tenga foto, dentro de +/- `ventana`
    segundos. Devuelve True si engancho con una marca ya guardada."""
    sql = ("UPDATE eventos SET foto=? WHERE id=(SELECT id FROM eventos"
           " WHERE sede=? AND lector=? AND persona_id=? AND foto=''")
    args = [relpath, sede, lector_ip, user_id]
    if ts:
        sql += " AND ts>=? AND ts<=? ORDER BY ABS(ts-?) ASC, id DESC LIMIT 1)"
        args += [int(ts) - ventana, int(ts) + ventana, int(ts)]
    else:
        sql += " ORDER BY ts DESC, id DESC LIMIT 1)"
    with _LOCK, conectar() as cx:
        return cx.execute(sql, args).rowcount > 0


def ruta_captura(sede, evento_id):
    """Ruta relativa de la foto de un evento (para servirla), o None."""
    with conectar() as cx:
        fila = cx.execute("SELECT foto FROM eventos WHERE id=? AND sede=?",
                          (evento_id, sede)).fetchone()
    return fila["foto"] if fila and fila["foto"] else None


def purgar_capturas(dias):
    """Borra carpetas de fotos de captura mas viejas que `dias` (0 = no borrar).
    Devuelve cuantas carpetas borro. Independiente de la retencion de eventos:
    la marca queda en la base aunque su foto ya no este."""
    if not dias or dias <= 0 or not os.path.isdir(CAPTURAS):
        return 0
    corte = (datetime.now() - timedelta(days=dias)).strftime("%Y-%m-%d")
    borradas = 0
    for nombre in os.listdir(CAPTURAS):
        ruta = os.path.join(CAPTURAS, nombre)
        if os.path.isdir(ruta) and len(nombre) == 10 and nombre < corte:
            shutil.rmtree(ruta, ignore_errors=True)
            borradas += 1
    return borradas


def listar_eventos(sede, limite=100, lector=None, pid=None, user_id=None,
                   solo_rechazos=False, desde_ts=None, busqueda=""):
    sql = "SELECT * FROM eventos WHERE sede=?"
    parametros = [sede]
    if lector:
        sql += " AND lector=?"; parametros.append(lector)
    if pid is not None:
        sql += " AND pid=?"; parametros.append(pid)
    if user_id:
        sql += " AND persona_id=?"; parametros.append(user_id)
    if solo_rechazos:
        sql += " AND concedido=0"
    if desde_ts:
        sql += " AND ts>=?"; parametros.append(int(desde_ts))
    if busqueda:
        sql += " AND (nombre LIKE ? OR persona_id LIKE ?)"
        parametros += [f"%{busqueda}%", f"%{busqueda}%"]
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    parametros.append(int(limite))
    with conectar() as cx:
        filas = []
        for f in cx.execute(sql, parametros).fetchall():
            d = dict(f)
            # No se filtra la ruta interna de la foto: solo si hay o no. La imagen
            # se pide aparte por /api/<sede>/asistencias/<id>/foto.
            d["tiene_foto"] = bool(d.pop("foto", ""))
            filas.append(d)
        return filas


# ----------------------------------------------------------------------
# Asistencias (marcas de entrada/salida de los fichadores, area aparte)
# ----------------------------------------------------------------------
_INSERT_ASISTENCIA = (
    "INSERT OR IGNORE INTO asistencias (lector, lector_nom, sede, recno, user_id,"
    " nombre, ts, momento, tipo, metodo, concedido, motivo, foto, creado)"
    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)")


def _fila_asistencia(m):
    return (m.get("ip") or m.get("lector") or "", m.get("lector_nom", ""), m.get("sede", ""),
            m.get("recno"), m.get("id") or m.get("user_id") or "", m.get("nombre", ""),
            int(m.get("ts") or 0), m.get("momento", ""), m.get("tipo", ""), m.get("metodo", ""),
            1 if m.get("concedido", True) else 0, m.get("motivo", ""), m.get("foto", ""), ahora())


def guardar_asistencias(marcas):
    """Alta masiva de marcas de asistencia. Devuelve cuantas entraron nuevas.
    El indice unico (lector, recno) descarta las repetidas al re-consultar."""
    if not marcas:
        return 0
    filas = [_fila_asistencia(m) for m in marcas]
    with _LOCK, conectar() as cx:
        antes = cx.total_changes
        cx.executemany(_INSERT_ASISTENCIA, filas)
        return cx.total_changes - antes


def ultimo_recno_asistencia(lector):
    with conectar() as cx:
        fila = cx.execute("SELECT MAX(recno) FROM asistencias WHERE lector=?", (lector,)).fetchone()
    return int(fila[0] or 0)


def listar_asistencias(sede=None, limite=200, offset=0, lector=None, tipo=None, user_id=None,
                       desde_ts=None, hasta_ts=None, solo_rechazos=False,
                       ocultar_rechazos=False, busqueda=""):
    """El log de fichadas. Devuelve `tiene_foto` (no la ruta interna).

    `ocultar_rechazos` deja solo las fichadas con permiso (lo normal para RRHH:
    las 'entrada sin permiso' -caras no reconocidas- son ruido). `solo_rechazos`
    es lo contrario, para auditar. Si vienen los dos, manda `solo_rechazos`."""
    sql = "SELECT * FROM asistencias WHERE 1=1"
    p = []
    if sede:
        sql += " AND sede=?"; p.append(sede)
    if lector:
        sql += " AND lector=?"; p.append(lector)
    if tipo:
        sql += " AND tipo=?"; p.append(tipo)
    if user_id:
        sql += " AND user_id=?"; p.append(user_id)
    if desde_ts:
        sql += " AND ts>=?"; p.append(int(desde_ts))
    if hasta_ts:
        sql += " AND ts<=?"; p.append(int(hasta_ts))
    if solo_rechazos:
        sql += " AND concedido=0"
    elif ocultar_rechazos:
        sql += " AND concedido=1"
    if busqueda:
        sql += " AND (nombre LIKE ? OR user_id LIKE ?)"; p += [f"%{busqueda}%", f"%{busqueda}%"]
    sql += " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"; p += [int(limite), int(offset)]
    with conectar() as cx:
        filas = []
        for f in cx.execute(sql, p).fetchall():
            d = dict(f)
            d["tiene_foto"] = bool(d.pop("foto", ""))
            filas.append(d)
        return filas


def ruta_foto_asistencia(sede, marca_id):
    """Ruta relativa de la foto de una marca de asistencia (para servirla), o None."""
    with conectar() as cx:
        fila = cx.execute("SELECT foto FROM asistencias WHERE id=? AND sede=?",
                          (marca_id, sede)).fetchone()
    return fila["foto"] if fila and fila["foto"] else None


def adjuntar_foto_asistencia(lector, user_id, ruta, ts=None, ventana=180):
    """Pega la ruta de foto a la marca de asistencia mas cercana de ese (lector,
    user_id) que no tenga foto. Para cuando la foto llega por otra via (en vivo)."""
    sql = ("UPDATE asistencias SET foto=? WHERE id=(SELECT id FROM asistencias"
           " WHERE lector=? AND user_id=? AND foto=''")
    args = [ruta, lector, user_id]
    if ts:
        sql += " AND ts>=? AND ts<=? ORDER BY ABS(ts-?) ASC, id DESC LIMIT 1)"
        args += [int(ts) - ventana, int(ts) + ventana, int(ts)]
    else:
        sql += " ORDER BY ts DESC, id DESC LIMIT 1)"
    with _LOCK, conectar() as cx:
        return cx.execute(sql, args).rowcount > 0


def asistencias_sin_foto(desde_ts, limite=300):
    """Marcas de asistencia recientes que todavia no tienen foto (para reintentar
    engancharla: cubre la carrera entre el poldel panel y el guardado del conector)."""
    with conectar() as cx:
        return [dict(f) for f in cx.execute(
            "SELECT id, sede, lector, user_id, ts FROM asistencias"
            " WHERE foto='' AND ts>=? ORDER BY ts DESC LIMIT ?",
            (int(desde_ts), limite)).fetchall()]


def poner_foto_asistencia(marca_id, ruta):
    """Le pone la ruta de foto a una marca puntual (por id). True si actualizo."""
    with _LOCK, conectar() as cx:
        return cx.execute("UPDATE asistencias SET foto=? WHERE id=? AND foto=''",
                          (ruta, marca_id)).rowcount > 0


# ----------------------------------------------------------------------
# Estado del lector (historial)
# ----------------------------------------------------------------------
def estado_lector(lector):
    with conectar() as cx:
        fila = cx.execute("SELECT * FROM estado_lector WHERE lector=?", (lector,)).fetchone()
    return dict(fila) if fila else {"ultimo_recno": 0, "proximo_id": 0, "serie": ""}


def poner_ultimo_recno(lector, recno, serie=None):
    with _LOCK, conectar() as cx:
        if serie is None:
            cx.execute(
                "INSERT INTO estado_lector (lector, ultimo_recno, visto) VALUES (?,?,?) "
                "ON CONFLICT(lector) DO UPDATE SET ultimo_recno=?, visto=?",
                (lector, recno, ahora(), recno, ahora()))
        else:
            cx.execute(
                "INSERT INTO estado_lector (lector, ultimo_recno, serie, visto) VALUES (?,?,?,?) "
                "ON CONFLICT(lector) DO UPDATE SET ultimo_recno=?, serie=?, visto=?",
                (lector, recno, serie, ahora(), recno, serie, ahora()))


# ----------------------------------------------------------------------
# Resumen para el tablero (por sede)
# ----------------------------------------------------------------------
def resumen(sede, lectores_sede):
    hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    ips = list(lectores_sede or [])
    marca = ",".join("?" * len(ips)) or "''"
    with conectar() as cx:
        def uno(sql, args=()):
            fila = cx.execute(sql, args).fetchone()
            return fila[0] if fila else 0
        return {
            "personas": uno("SELECT COUNT(*) FROM personas WHERE sede=? AND activo=1", (sede,)),
            "bajas": uno("SELECT COUNT(*) FROM personas WHERE sede=? AND activo=0", (sede,)),
            "pendientes": uno(
                f"SELECT COUNT(*) FROM accesos a JOIN personas p ON p.pid=a.pid"
                f" WHERE p.sede=? AND a.estado='pendiente'", (sede,)),
            "con_error": uno(
                "SELECT COUNT(*) FROM accesos a JOIN personas p ON p.pid=a.pid"
                " WHERE p.sede=? AND a.estado='error'", (sede,)),
            "bajas_incompletas": uno(
                "SELECT COUNT(DISTINCT p.pid) FROM personas p JOIN accesos a ON a.pid=p.pid"
                " WHERE p.sede=? AND p.activo=0 AND (a.user_id!='' OR a.estado IN"
                " ('pendiente','error'))", (sede,)),
            "avisos": uno(
                "SELECT COUNT(*) FROM accesos a JOIN personas p ON p.pid=a.pid"
                " WHERE p.sede=? AND a.aviso!=''", (sede,)),
            "eventos_hoy": uno(
                f"SELECT COUNT(*) FROM eventos WHERE sede=? AND ts>=?", (sede, int(hoy))),
            "rechazos_hoy": uno(
                f"SELECT COUNT(*) FROM eventos WHERE sede=? AND ts>=? AND concedido=0",
                (sede, int(hoy))),
            # eventos_total (COUNT sobre toda la particion) se saco: no se muestra en
            # la UI y corria en cada marca en vivo, escaneando una tabla que solo crece.
        }


def respaldar_auto(conservar=14):
    """Copia consistente de la base a data/respaldos/auto-*.sqlite3, rotando las
    ultimas `conservar`. Devuelve la ruta creada."""
    import glob
    os.makedirs(RESPALDOS, exist_ok=True)
    sello = datetime.now().strftime("%Y%m%d-%H%M%S")
    destino = os.path.join(RESPALDOS, f"auto-{sello}.sqlite3")
    with _LOCK, conectar() as cx, sqlite3.connect(destino) as copia:
        cx.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        cx.backup(copia)
    viejos = sorted(glob.glob(os.path.join(RESPALDOS, "auto-*.sqlite3")))
    for v in viejos[:-conservar] if conservar > 0 else []:
        try:
            os.remove(v)
        except OSError:
            pass
    return destino


def purgar_eventos(meses):
    """Borra eventos mas viejos que `meses` (0 = no borrar nada). Devuelve cuantos.

    Es destructivo por diseno: solo corre si el usuario configura `retencion_meses`.
    El indice unico deja reimportar del equipo si hiciera falta.
    """
    if not meses or meses <= 0:
        return 0
    corte = int((datetime.now() - timedelta(days=30 * meses)).timestamp())
    with _LOCK, conectar() as cx:
        cur = cx.execute("DELETE FROM eventos WHERE ts < ?", (corte,))
        return cur.rowcount


def mantenimiento():
    """Tareas baratas de higiene de la base: checkpoint del WAL y optimize."""
    with _LOCK, conectar() as cx:
        cx.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        cx.execute("PRAGMA optimize")


def contar_violaciones_sede(sede_de_ip):
    """Accesos cuyo lector no pertenece a la sede de la persona (invariante roto)."""
    with conectar() as cx:
        malos = 0
        for f in cx.execute(
                "SELECT a.lector, p.sede FROM accesos a JOIN personas p ON p.pid=a.pid").fetchall():
            if sede_de_ip.get(f["lector"]) != f["sede"]:
                malos += 1
    return malos


# ----------------------------------------------------------------------
# Usuarios del panel (login por usuario + clave, con roles)
# ----------------------------------------------------------------------
# La clave NUNCA se guarda en claro: pbkdf2-sha256 con salt por usuario.
_PBKDF2_VUELTAS = 200_000


def _hash_clave(clave, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"),
                             bytes.fromhex(salt), _PBKDF2_VUELTAS)
    return dk.hex(), salt


def _lista_json(fila, campo):
    try:
        return json.loads(fila[campo]) if campo in fila.keys() and fila[campo] else []
    except (json.JSONDecodeError, TypeError):
        return []


def _usuario_dict(fila):
    # secciones vacias = las del rol (asi los usuarios viejos siguen andando y el
    # admin solo guarda una lista propia cuando quiere personalizar).
    secciones = _lista_json(fila, "secciones") or secciones_de_rol(fila["rol"])
    return {"usuario": fila["usuario"], "nombre": fila["nombre"], "rol": fila["rol"],
            "activo": bool(fila["activo"]), "puertas": _lista_json(fila, "puertas"),
            "secciones": secciones, "sedes": _lista_json(fila, "sedes"),  # [] = todas
            "creado": fila["creado"], "ultimo_acceso": fila["ultimo_acceso"]}


def hay_usuarios():
    with conectar() as cx:
        return cx.execute("SELECT 1 FROM usuarios LIMIT 1").fetchone() is not None


def listar_usuarios():
    with conectar() as cx:
        return [_usuario_dict(f) for f in cx.execute(
            "SELECT * FROM usuarios ORDER BY rol DESC, usuario").fetchall()]


def usuario(nombre_usuario):
    with conectar() as cx:
        fila = cx.execute("SELECT * FROM usuarios WHERE usuario=?",
                          (nombre_usuario.lower(),)).fetchone()
    return _usuario_dict(fila) if fila else None


def verificar_usuario(nombre_usuario, clave):
    """Devuelve {usuario, nombre, rol} si el login es valido y el usuario esta
    activo; None si no. Compara en tiempo constante para no filtrar nada."""
    with conectar() as cx:
        fila = cx.execute("SELECT * FROM usuarios WHERE usuario=?",
                          (str(nombre_usuario).lower(),)).fetchone()
    if not fila or not fila["activo"]:
        # Se calcula un hash igual aunque no exista, para no delatar por el tiempo
        # si el usuario existe o no.
        _hash_clave(clave or "")
        return None
    calc, _ = _hash_clave(clave or "", fila["salt"])
    if not hmac.compare_digest(calc, fila["clave_hash"]):
        return None
    with _LOCK, conectar() as cx:
        cx.execute("UPDATE usuarios SET ultimo_acceso=? WHERE usuario=?",
                   (ahora(), fila["usuario"]))
    d = _usuario_dict(fila)
    return {"usuario": d["usuario"], "nombre": d["nombre"], "rol": d["rol"],
            "puertas": d["puertas"], "secciones": d["secciones"], "sedes": d["sedes"]}


def _limpiar_secciones(secciones):
    """Deja solo secciones validas. None/[] => '[]' (usa las del rol)."""
    if not secciones:
        return "[]"
    return json.dumps([s for s in secciones if s in SECCIONES])


def crear_usuario(nombre_usuario, clave, rol, nombre="", activo=True, puertas=None,
                  secciones=None, sedes=None):
    """Devuelve (ok, error). El usuario se normaliza a minusculas.
    `puertas`: IPs que puede abrir aparte del rol. `secciones`: [] = las del rol.
    `sedes`: sedes que puede ver, [] = todas."""
    u = str(nombre_usuario or "").strip().lower()
    if not u.replace("_", "").replace(".", "").isalnum() or len(u) < 3:
        return False, "el usuario debe tener 3+ caracteres (letras, numeros, _ o .)"
    if rol not in ROLES:
        return False, "rol invalido"
    if not clave or len(clave) < 4:
        return False, "la clave debe tener al menos 4 caracteres"
    h, salt = _hash_clave(clave)
    with _LOCK, conectar() as cx:
        if cx.execute("SELECT 1 FROM usuarios WHERE usuario=?", (u,)).fetchone():
            return False, f"el usuario '{u}' ya existe"
        cx.execute(
            "INSERT INTO usuarios (usuario, nombre, rol, clave_hash, salt, activo, puertas, "
            "secciones, sedes, creado) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (u, nombre or u, rol, h, salt, 1 if activo else 0,
             json.dumps(list(puertas or [])), _limpiar_secciones(secciones),
             json.dumps(list(sedes or [])), ahora()))
    return True, ""


def actualizar_usuario(nombre_usuario, nombre=None, rol=None, activo=None, clave=None,
                       puertas=None, secciones=None, sedes=None):
    """Cambia campos de un usuario. Devuelve (ok, error).

    No deja quedarse sin ningun admin activo: si esta es la ultima cuenta admin,
    no se le puede bajar el rol ni desactivar.
    """
    u = str(nombre_usuario or "").lower()
    with _LOCK, conectar() as cx:
        fila = cx.execute("SELECT * FROM usuarios WHERE usuario=?", (u,)).fetchone()
        if not fila:
            return False, "no existe"
        baja_admin = (fila["rol"] == "admin" and
                      ((rol is not None and rol != "admin") or activo is False))
        if baja_admin:
            otros = cx.execute(
                "SELECT COUNT(*) FROM usuarios WHERE rol='admin' AND activo=1 AND usuario!=?",
                (u,)).fetchone()[0]
            if otros == 0:
                return False, "es el unico admin activo; primero dale rol admin a otro"
        if rol is not None:
            if rol not in ROLES:
                return False, "rol invalido"
            cx.execute("UPDATE usuarios SET rol=? WHERE usuario=?", (rol, u))
        if nombre is not None:
            cx.execute("UPDATE usuarios SET nombre=? WHERE usuario=?", (nombre, u))
        if activo is not None:
            cx.execute("UPDATE usuarios SET activo=? WHERE usuario=?", (1 if activo else 0, u))
        if puertas is not None:
            cx.execute("UPDATE usuarios SET puertas=? WHERE usuario=?",
                       (json.dumps(list(puertas)), u))
        if secciones is not None:
            cx.execute("UPDATE usuarios SET secciones=? WHERE usuario=?",
                       (_limpiar_secciones(secciones), u))
        if sedes is not None:
            cx.execute("UPDATE usuarios SET sedes=? WHERE usuario=?",
                       (json.dumps(list(sedes)), u))
        if clave:
            if len(clave) < 4:
                return False, "la clave debe tener al menos 4 caracteres"
            h, salt = _hash_clave(clave)
            cx.execute("UPDATE usuarios SET clave_hash=?, salt=? WHERE usuario=?", (h, salt, u))
    return True, ""


def cambiar_clave_propia(nombre_usuario, clave_actual, clave_nueva):
    """El propio usuario cambia su clave. Devuelve (ok, error)."""
    if not verificar_usuario(nombre_usuario, clave_actual):
        return False, "la clave actual no es correcta"
    if not clave_nueva or len(clave_nueva) < 4:
        return False, "la clave nueva debe tener al menos 4 caracteres"
    h, salt = _hash_clave(clave_nueva)
    with _LOCK, conectar() as cx:
        cx.execute("UPDATE usuarios SET clave_hash=?, salt=? WHERE usuario=?",
                   (h, salt, str(nombre_usuario).lower()))
    return True, ""


def borrar_usuario(nombre_usuario):
    """Devuelve (ok, error). No se puede borrar el ultimo admin activo."""
    u = str(nombre_usuario or "").lower()
    with _LOCK, conectar() as cx:
        fila = cx.execute("SELECT rol FROM usuarios WHERE usuario=?", (u,)).fetchone()
        if not fila:
            return False, "no existe"
        if fila["rol"] == "admin":
            otros = cx.execute(
                "SELECT COUNT(*) FROM usuarios WHERE rol='admin' AND activo=1 AND usuario!=?",
                (u,)).fetchone()[0]
            if otros == 0:
                return False, "es el unico admin; no se puede borrar"
        cx.execute("DELETE FROM usuarios WHERE usuario=?", (u,))
    return True, ""


def sembrar_usuarios(iniciales):
    """Crea los usuarios que falten. `iniciales` es una lista de
    (usuario, clave, rol, nombre). Devuelve los que realmente creo (para avisar
    de las claves por unica vez). No pisa usuarios que ya existan."""
    creados = []
    for u, clave, rol, nombre in iniciales:
        ok, _ = crear_usuario(u, clave, rol, nombre)
        if ok:
            creados.append(u)
    return creados
