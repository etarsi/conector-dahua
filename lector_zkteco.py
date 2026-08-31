# -*- coding: utf-8 -*-
"""
Operaciones sobre los lectores ZKTeco (sede Lavalle).

Este modulo lo usa el panel unificado para dar de alta, modificar y dar de baja
gente en Lavalle, igual que hace con los Dahua del Deposito pero hablando el
protocolo de ZKTeco.

Diferencias con Dahua que conviene tener presentes:
  - El equipo acepta UNA conexion por vez: se abre, se opera y se cierra.
  - NUNCA se llama a disable_device(): dejaria al lector sin aceptar marcas.
  - No se puede subir una foto desde aca. La libreria no expone la carga de
    rostro, asi que en Lavalle el rostro se enrola parado frente al equipo.
"""

import logging
import threading
from datetime import datetime
from struct import unpack

try:
    from zk import ZK, const
except ImportError:  # el panel avisa mejor que esto
    ZK = None
    const = None

ZK_LOCK = threading.Lock()


# =========================
# CONEXION
# =========================
def abrir(equipo, timeout=30):
    if ZK is None:
        raise RuntimeError("Falta la libreria pyzk (python -m pip install pyzk)")
    zk = ZK(equipo["ip"], port=int(equipo.get("puerto", 4370)), timeout=timeout,
            password=int(equipo.get("password", 0)), ommit_ping=True)
    return zk.connect()


def info_equipo(equipo, timeout=30):
    """Estado del lector: nombre, firmware y contadores."""
    conn = None
    with ZK_LOCK:
        try:
            conn = abrir(equipo, timeout)
            datos = {
                "ip": equipo["ip"],
                "conectado": True,
                "nombre": equipo.get("nombre") or conn.get_device_name(),
                "firmware": conn.get_firmware_version(),
                "serie": conn.get_serialnumber(),
                "hora_equipo": conn.get_time().strftime("%Y-%m-%d %H:%M:%S"),
                "error": "",
            }
            try:
                conn.read_sizes()
                datos.update({"usuarios": conn.users, "rostros": conn.faces,
                              "huellas": conn.fingers, "marcas": conn.records})
            except Exception:
                logging.debug("No se pudieron leer los contadores", exc_info=True)
            return datos
        except Exception as exc:
            return {"ip": equipo["ip"], "conectado": False, "error": str(exc),
                    "nombre": equipo.get("nombre") or equipo["ip"]}
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass


# =========================
# PERSONAS
# =========================
def listar_personas(equipo, timeout=30):
    """Devuelve las personas cargadas en el lector."""
    conn = None
    with ZK_LOCK:
        try:
            conn = abrir(equipo, timeout)
            return [{"user_id": str(u.user_id), "uid": u.uid, "nombre": u.name,
                     "privilegio": u.privilege, "tarjeta": str(u.card)}
                    for u in conn.get_users()]
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass


def siguiente_id(equipo, timeout=30):
    """
    Proximo ID libre para dar de alta a alguien.

    Se toma el mas alto que haya + 1, no el primer hueco. Reusar un numero
    liberado es riesgoso: BioTime tambien crea gente en este lector y sigue su
    propio contador, asi que un hueco puede volver a usarse del otro lado y
    terminar con dos personas distintas compartiendo ID.
    """
    personas = listar_personas(equipo, timeout)
    numeros = [int(p["user_id"]) for p in personas if str(p["user_id"]).isdigit()]
    return str(max(numeros) + 1) if numeros else "1"


def _uid_libre(conn, user_id):
    """
    Busca el indice interno que le toca a la persona.

    Si ya existe se reusa el suyo (asi se actualiza en vez de duplicar);
    si es nueva, se toma el primer numero libre.
    """
    usados = set()
    for u in conn.get_users():
        if str(u.user_id) == str(user_id):
            return u.uid, True
        usados.add(u.uid)
    for n in range(1, 65535):
        if n not in usados:
            return n, False
    raise RuntimeError("El lector no tiene lugar para mas personas")


def alta_persona(equipo, user_id, nombre, privilegio=0, tarjeta=0, timeout=30):
    """
    Crea o actualiza la persona en el lector.
    Devuelve (ok, mensaje).
    """
    conn = None
    with ZK_LOCK:
        try:
            conn = abrir(equipo, timeout)
            uid, existia = _uid_libre(conn, user_id)
            # El nombre en estos equipos entra en 24 caracteres
            conn.set_user(uid=uid, name=(nombre or "")[:24], privilege=int(privilegio),
                          password="", group_id="", user_id=str(user_id), card=int(tarjeta or 0))
            accion = "actualizada" if existia else "creada"
            logging.info(f"ZKTeco {equipo['ip']}: persona {accion} | ID={user_id} {nombre}")
            return True, f"persona {accion} en el lector"
        except Exception as exc:
            logging.exception(f"Error dando de alta {user_id} en {equipo['ip']}")
            return False, str(exc)
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass


def baja_persona(equipo, user_id, timeout=30):
    """Borra la persona del lector. Devuelve (ok, mensaje)."""
    conn = None
    with ZK_LOCK:
        try:
            conn = abrir(equipo, timeout)
            objetivo = next((u for u in conn.get_users() if str(u.user_id) == str(user_id)), None)
            if not objetivo:
                return True, "no estaba cargada en el lector"
            conn.delete_user(uid=objetivo.uid, user_id=str(user_id))
            logging.info(f"ZKTeco {equipo['ip']}: persona borrada | ID={user_id}")
            return True, "persona borrada del lector"
        except Exception as exc:
            logging.exception(f"Error dando de baja {user_id} en {equipo['ip']}")
            return False, str(exc)
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass


def existe_persona(equipo, user_id, timeout=30):
    """True si la persona esta cargada en el lector."""
    try:
        return any(str(p["user_id"]) == str(user_id) for p in listar_personas(equipo, timeout))
    except Exception:
        return None


# =========================
# MARCAS
# =========================
def _fecha_zk(valor):
    t = valor
    seg = t % 60; t //= 60
    mi = t % 60;  t //= 60
    ho = t % 24;  t //= 24
    di = t % 31 + 1; t //= 31
    me = t % 12 + 1; t //= 12
    try:
        return datetime(t + 2000, me, di, ho, mi, seg)
    except ValueError:
        return None


def leer_marcas(conn):
    """
    Lee el historial de marcas con el tamaño de registro correcto.

    pyzk supone 8, 16 o 40 bytes; el Horus de Lavalle usa 49
    (2.792.804 / 56.996 = 49 exacto). Con get_attendance() salen fechas del
    año 2133 y miles de usuarios inexistentes, asi que se parsea aca.
    """
    datos, size = conn.read_with_buffer(const.CMD_ATTLOG_RRQ)
    if size < 4:
        return [], 0
    total = unpack("I", datos[:4])[0]
    cuerpo = datos[4:]
    cantidad = int(getattr(conn, "records", 0) or 0)
    tam = (total // cantidad) if cantidad and total % cantidad == 0 else 0
    if not tam:
        for c in (49, 40, 32, 16, 8):
            if len(cuerpo) % c == 0:
                tam = c
                break
    if tam < 8:
        return [], 0

    marcas, malas = [], 0
    for i in range(0, len(cuerpo) - tam + 1, tam):
        r = cuerpo[i:i + tam]
        if tam == 8:
            uid, estado, crudo, punch = unpack("<HB4sB", r[:8])
            user_id = str(uid)
        elif tam == 16:
            num, crudo, estado, punch, _ = unpack("<I4sBB6s", r[:16])
            user_id = str(num)
        else:
            _uid, ubytes, estado, crudo, punch = unpack("<H24sB4sB", r[:32])
            user_id = ubytes.split(b"\x00", 1)[0].decode("ascii", "ignore").strip()
        f = _fecha_zk(unpack("<I", crudo)[0])
        if f is None or not user_id:
            malas += 1
            continue
        marcas.append({"user_id": user_id, "fecha": f, "estado": estado, "punch": punch})
    return marcas, malas
