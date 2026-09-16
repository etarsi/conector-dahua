# -*- coding: utf-8 -*-
"""
Reglas de identidad de personas, en un solo lugar.

Las usan la importacion, el worker y el servidor, y es a proposito que vivan
juntas: decidir "esta persona del equipo es la misma que esta del panel" es lo
que, si se hace mal, termina escribiendo sobre el registro de otra persona.

Dos funciones que parecen iguales pero NO lo son, y mezclarlas es el error mas
peligroso del sistema:

    mismo_registro(a, b)  -> IGUALDAD EXACTA (normalizada). Es la unica que puede
                             habilitar una escritura o vincular un ID a una persona.
    parecido(a, b)        -> SIMILITUD (tolera tipeos). SOLO sugiere: duplicados,
                             avisos, el guardian de choques. NUNCA decide.

Por que la diferencia importa: "Mario" y "Maria" se parecen en 0,91; "Daniel" y
"Daniela" en 0,96. Si `parecido` decidiera una baja, se le sacaria el acceso a
Maria por dar de baja a Mario. `mismo_registro` no los confunde nunca.
"""

import unicodedata
from difflib import SequenceMatcher

# Nombres que no identifican a nadie: no se usan para unir personas entre
# lectores. Una palabra suelta o con un digito tampoco alcanza.
_GENERICOS = {
    "visita", "visitante", "temporal", "prueba", "test", "usuario", "invitado",
    "proveedor", "limpieza", "seguridad", "guardia", "admin", "mantenimiento",
    "onst", "mant", "personal", "obra",
}

# Umbral de `parecido`. Es solo para sugerir uniones a mano, nunca para decidir.
UMBRAL_PARECIDO = 0.85


def normalizar(texto):
    """Minusculas, sin tildes, espacios colapsados. Base de todo lo demas."""
    limpio = unicodedata.normalize("NFKD", (texto or "").strip().lower())
    return " ".join("".join(c for c in limpio if not unicodedata.combining(c)).split())


def mismo_registro(a, b):
    """True solo si son el mismo nombre, normalizado. Un vacio nunca coincide.

    Esta es la que habilita escrituras y vinculaciones. Igualdad exacta a
    proposito: ver el docstring del modulo.
    """
    na, nb = normalizar(a), normalizar(b)
    return na != "" and na == nb


def parecido(a, b):
    """Cuanto se parecen dos nombres (0 a 1). Para SUGERIR, nunca para decidir."""
    na, nb = normalizar(a), normalizar(b)
    if not na or not nb:
        return 0.0
    return SequenceMatcher(None, na, nb).ratio()


def son_parecidos(a, b):
    """`parecido` por encima del umbral, pero sin ser iguales (eso ya es otra cosa)."""
    p = parecido(a, b)
    return p >= UMBRAL_PARECIDO and not mismo_registro(a, b)


def es_generico(texto):
    """El nombre no sirve para identificar: pocas letras, tiene digitos, o es una
    palabra de la lista (visita, mantenimiento, etc.)."""
    n = normalizar(texto)
    if not n:
        return True
    if any(c.isdigit() for c in n):
        return True
    palabras = [p for p in n.split() if len(p) >= 3]
    if len(palabras) < 2:
        return True
    return any(p in _GENERICOS for p in n.split())
