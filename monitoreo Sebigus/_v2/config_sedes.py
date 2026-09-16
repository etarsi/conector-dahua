# -*- coding: utf-8 -*-
"""
Lectura y validacion de config.json con sedes.

Todo se valida al arrancar y ante cualquier problema el panel NO arranca: un error
de config puede terminar escribiendo en el lector equivocado, o probando la clave
de una sede contra los equipos de la otra y bloqueando la cuenta admin (que en la
Reja del Deposito tambien usa SmartPSS).

Reglas que no son obvias:
  - Solo se acepta el formato con "sedes". El viejo, con "lectores" en la raiz,
    le heredaba la clave de la raiz a todos los equipos.
  - Credenciales: primero las del lector, despues las de la sede, NUNCA las de la
    raiz. Un lector sin credenciales no arranca y figura "sin credenciales".
  - Una IP no se puede repetir en todo el archivo: los lectores se indexan por IP.
"""

import json
import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RUTA = os.path.join(BASE_DIR, "config.json")

MODOS_IDS = ("compartidos", "por_lector")
CLAVE_SEDE = re.compile(r"^[a-z0-9_]+$")
BANDERAS_LECTOR = ("escritura", "eventos_en_vivo", "historial")

GLOBAL_POR_DEFECTO = {
    "host": "0.0.0.0", "puerto": 8090, "clave_panel": "", "sesion_horas": 12,
    "log_level": "INFO", "max_foto_kb": 200, "vigilancia_segundos": 20,
    "sincronizacion_segundos": 20, "importar_historial_minutos": 30,
}


class ConfigInvalida(SystemExit):
    """El panel no arranca. Los problemas se listan todos juntos."""

    def __init__(self, problemas):
        self.problemas = list(problemas)
        super().__init__("config.json invalido, el panel no arranca:\n  - "
                         + "\n  - ".join(self.problemas))


def cargar(ruta=None):
    ruta = ruta or RUTA
    if not os.path.exists(ruta):
        raise ConfigInvalida([f"falta {ruta}: copiar config.example.json y completar las claves"])
    with open(ruta, "r", encoding="utf-8") as fh:
        try:
            crudo = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ConfigInvalida([f"{ruta} no es JSON valido: {exc}"]) from exc
    return validar(crudo)


def validar(crudo):
    """Devuelve la config normalizada, con cada lector ya resuelto (sede, credenciales, banderas)."""
    sedes_crudas = crudo.get("sedes")
    if not isinstance(sedes_crudas, dict) or not sedes_crudas:
        raise ConfigInvalida([
            'no hay "sedes". Desde la version 2 cada lector va dentro de su sede, con sus '
            "credenciales (ver config.example.json). La clave de la raiz ya no se usa"])

    problemas = []
    cfg = {"global": {k: crudo.get(k, v) for k, v in GLOBAL_POR_DEFECTO.items()},
           "sedes": {}, "sede_de_ip": {}}
    donde_ip = {}

    for clave, sede in sedes_crudas.items():
        if not isinstance(clave, str) or not CLAVE_SEDE.match(clave):
            problemas.append(f"la sede {clave!r} tiene que ser minusculas, numeros o _ (ej. \"deposito\")")
            continue
        if not isinstance(sede, dict):
            problemas.append(f"la sede {clave} no es un objeto")
            continue
        ids = sede.get("ids")
        if ids not in MODOS_IDS:
            problemas.append(f'sede {clave}: "ids" tiene que ser {" o ".join(MODOS_IDS)}, no {ids!r}')
        nvr = sede.get("nvr") or None
        if nvr is not None and (not isinstance(nvr, dict) or not nvr.get("ip")):
            problemas.append(f'sede {clave}: "nvr" necesita al menos "ip"')
            nvr = None
        banderas_sede = {b: bool(sede.get(b, True)) for b in BANDERAS_LECTOR}
        normal = {
            "clave": clave, "nombre": sede.get("nombre") or clave, "ids": ids,
            "rango_ids_nuevos": int(sede.get("rango_ids_nuevos", 9000)),
            "padron_minutos": int(sede.get("padron_minutos", 30)),
            "nvr": nvr, "lectores": [], **banderas_sede,
        }
        nombres = set()
        for i, lec in enumerate(sede.get("lectores") or []):
            lec = lec or {}
            ip = str(lec.get("ip") or "").strip()
            if not ip:
                problemas.append(f"sede {clave}: el lector #{i + 1} no tiene ip")
                continue
            if ip in donde_ip:
                problemas.append(f"la IP {ip} esta repetida (sedes {donde_ip[ip]} y {clave})")
                continue
            donde_ip[ip] = clave
            nombre = str(lec.get("nombre") or "").strip()
            if not nombre:
                problemas.append(f"sede {clave}: el lector {ip} no tiene nombre")
            elif nombre in nombres:
                problemas.append(f"sede {clave}: el nombre de lector {nombre!r} esta repetido")
            nombres.add(nombre)
            # Credenciales: lector, despues sede. La raiz no se mira nunca.
            usuario = lec.get("usuario") or sede.get("usuario") or ""
            clave_equipo = lec.get("clave") or sede.get("clave") or ""
            normal["lectores"].append({
                "ip": ip, "sede": clave, "nombre": nombre or ip,
                "sector": lec.get("sector", ""), "modelo": lec.get("modelo", ""),
                "puerto": int(lec.get("puerto", 80)), "canal": int(lec.get("canal", 1)),
                "usuario": usuario, "clave": clave_equipo,
                "sin_credenciales": not (usuario and clave_equipo) or clave_equipo == "CAMBIAR",
                **{b: bool(lec.get(b, banderas_sede[b])) for b in BANDERAS_LECTOR},
            })
        cfg["sedes"][clave] = normal

    if problemas:
        raise ConfigInvalida(problemas)
    cfg["sede_de_ip"] = dict(donde_ip)
    return cfg


def publico(cfg):
    """Lo que puede ver el navegador: sin usuarios ni claves."""
    return [{
        "clave": s["clave"], "nombre": s["nombre"], "ids": s["ids"],
        "tiene_nvr": bool(s["nvr"]), "escritura": s["escritura"],
        "lectores": [{"ip": l["ip"], "nombre": l["nombre"], "sector": l["sector"],
                      "modelo": l["modelo"], "escritura": l["escritura"],
                      "sin_credenciales": l["sin_credenciales"]} for l in s["lectores"]],
    } for s in cfg["sedes"].values()]
