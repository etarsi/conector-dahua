# -*- coding: utf-8 -*-
"""
Quien es quien. Las unicas funciones del panel que comparan nombres de personas.

Son tres preguntas distintas y no se mezclan:

  mismo_registro(a, b)  ¿Es el MISMO registro? Igualdad exacta despues de
                        normalizar. Es lo unico que autoriza a escribir, borrar o
                        vincular. Un nombre vacio nunca coincide con nada.
  parecido(a, b)        Similitud entre 0 y 1. Solo SUGIERE (duplicados, avisos).
                        Nunca decide una escritura ni una vinculacion.
  es_generico(nombre)   Nombres que no identifican a nadie: "Visita", "Prueba 3",
                        una sola palabra. No se unen entre lectores.

Por que la tolerancia no decide nada: Mario/Maria da 0,909 y Daniel/Daniela
0,963. Con "parecido >= 0,85" como regla de oro, el panel borraba a otra persona.
"""

import unicodedata
from difflib import SequenceMatcher

PALABRAS_GENERICAS = frozenset({
    "visita", "visitante", "temporal", "prueba", "test", "usuario", "invitado",
    "proveedor", "limpieza", "seguridad", "guardia", "admin",
})


def normalizar(texto):
    """Sin tildes, en minusculas y con los espacios colapsados."""
    limpio = unicodedata.normalize("NFKD", str(texto or "")).lower()
    sin_marcas = "".join(c for c in limpio if not unicodedata.combining(c))
    return " ".join(sin_marcas.split())


def mismo_registro(nombre_equipo, nombre_esperado):
    """True solo si los dos nombres son iguales normalizados y no estan vacios."""
    a, b = normalizar(nombre_equipo), normalizar(nombre_esperado)
    return bool(a) and a == b


def parecido(a, b):
    return SequenceMatcher(None, normalizar(a), normalizar(b)).ratio()


def es_generico(texto):
    """Nombres que no alcanzan para decir que dos registros son la misma persona."""
    n = normalizar(texto)
    if not n:
        return True
    if any(c.isdigit() for c in n):
        return True
    palabras = n.split()
    if sum(1 for p in palabras if len(p) >= 3) < 2:
        return True
    return any(p in PALABRAS_GENERICAS for p in palabras)
