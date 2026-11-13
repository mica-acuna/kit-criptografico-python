"""Cifrados clásicos (César y Vigenère) y sus ataques.

ADVERTENCIA: estos cifrados son didácticos y NO sirven para proteger
información real. Se rompen en segundos con fuerza bruta o análisis de
frecuencias, justamente lo que implementa este módulo.

Reglas del módulo:
- El alfabeto es A-Z (26 letras). Se conservan mayúsculas y minúsculas.
- Todo lo que no sea una letra A-Z/a-z (espacios, números, signos y también
  letras con acento o la ñ) queda intacto y no consume letras de la clave.
- Los ataques normalizan el texto (mayúsculas, sin acentos, ñ como n) solo
  para calcular; el texto de salida nunca se modifica.
"""

import math
import unicodedata
from collections import Counter

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Frecuencias aproximadas (en %) de las letras en español, con la ñ sumada a la n.
# Varían un poco según el corpus; los ataques toleran esas diferencias.
_PORCENTAJES_ES = {
    "A": 12.53, "B": 1.42, "C": 4.68, "D": 5.86, "E": 13.68, "F": 0.69,
    "G": 1.01, "H": 0.70, "I": 6.25, "J": 0.44, "K": 0.02, "L": 4.97,
    "M": 3.15, "N": 7.02, "O": 8.68, "P": 2.51, "Q": 0.88, "R": 6.87,
    "S": 7.98, "T": 4.63, "U": 3.93, "V": 0.90, "W": 0.01, "X": 0.22,
    "Y": 0.90, "Z": 0.52,
}
_TOTAL_PORCENTAJES = sum(_PORCENTAJES_ES.values())
FRECUENCIAS_ES = {
    letra: porcentaje / _TOTAL_PORCENTAJES
    for letra, porcentaje in _PORCENTAJES_ES.items()
}

# Un texto en español tiene un índice de coincidencia cercano a 0,075;
# uno al azar, cercano a 1/26 (0,038).
_TOLERANCIA_IC = 0.01
# Con menos letras por columna, el índice de coincidencia es puro ruido y elige mal el largo.
_LETRAS_MINIMAS_POR_COLUMNA = 15


def _es_letra(caracter: str) -> bool:
    return ("A" <= caracter <= "Z") or ("a" <= caracter <= "z")


def _desplazar_letra(letra: str, desplazamiento: int) -> str:
    base = ord("A") if letra.isupper() else ord("a")
    return chr((ord(letra) - base + desplazamiento) % 26 + base)


def _normalizar(texto: str) -> str:
    """Devuelve solo las letras A-Z en mayúsculas, sin acentos (ñ -> N)."""
    sin_acentos = "".join(
        c for c in unicodedata.normalize("NFD", texto) if not unicodedata.combining(c)
    )
    return "".join(c for c in sin_acentos.upper() if "A" <= c <= "Z")


def _validar_clave(clave: str) -> None:
    if not isinstance(clave, str):
        raise TypeError("La clave debe ser un texto.")
    if not clave:
        raise ValueError("La clave no puede estar vacía.")
    if not (clave.isascii() and clave.isalpha()):
        raise ValueError(
            "La clave solo puede tener letras de la A a la Z "
            "(sin números, espacios, signos ni acentos)."
        )


def _validar_desplazamiento(desplazamiento: int) -> None:
    if isinstance(desplazamiento, bool) or not isinstance(desplazamiento, int):
        raise TypeError("El desplazamiento debe ser un número entero.")


# --- César ---

def cesar_cifrar(texto: str, desplazamiento: int) -> str:
    """Desplaza cada letra `desplazamiento` posiciones en el alfabeto."""
    _validar_desplazamiento(desplazamiento)
    return "".join(
        _desplazar_letra(c, desplazamiento) if _es_letra(c) else c for c in texto
    )


def cesar_descifrar(texto: str, desplazamiento: int) -> str:
    """Revierte `cesar_cifrar` con el mismo desplazamiento."""
    _validar_desplazamiento(desplazamiento)
    return cesar_cifrar(texto, -desplazamiento)


# --- Vigenère ---

def _vigenere(texto: str, clave: str, signo: int) -> str:
    _validar_clave(clave)
    desplazamientos = [ord(c.upper()) - ord("A") for c in clave]
    resultado = []
    posicion = 0  # solo avanza con las letras, no con espacios ni signos
    for c in texto:
        if _es_letra(c):
            desplazamiento = signo * desplazamientos[posicion % len(clave)]
            resultado.append(_desplazar_letra(c, desplazamiento))
            posicion += 1
        else:
            resultado.append(c)
    return "".join(resultado)


def vigenere_cifrar(texto: str, clave: str) -> str:
    """Cifra con una clave de letras que se repite a lo largo del texto."""
    return _vigenere(texto, clave, 1)


def vigenere_descifrar(texto: str, clave: str) -> str:
    """Revierte `vigenere_cifrar` con la misma clave."""
    return _vigenere(texto, clave, -1)


# --- Ataque de fuerza bruta al César ---

def cesar_fuerza_bruta(texto_cifrado: str) -> list[tuple[int, str]]:
    """Devuelve los 26 desplazamientos posibles con el texto descifrado de cada uno."""
    return [(d, cesar_descifrar(texto_cifrado, d)) for d in range(26)]


def _puntaje_espanol(texto: str) -> float:
    """Verosimilitud logarítmica de que el texto sea español (más alto = más probable)."""
    return sum(math.log(FRECUENCIAS_ES[letra]) for letra in _normalizar(texto))


def cesar_romper(texto_cifrado: str) -> tuple[int, str]:
    """Elige el desplazamiento más probable puntuando con frecuencias del español."""
    if not _normalizar(texto_cifrado):
        raise ValueError("El texto no tiene letras para analizar.")
    return max(cesar_fuerza_bruta(texto_cifrado), key=lambda c: _puntaje_espanol(c[1]))


# --- Análisis de frecuencias contra Vigenère ---

def _indice_coincidencia(letras: str) -> float:
    """Probabilidad de que dos letras tomadas al azar del texto sean iguales."""
    n = len(letras)
    if n < 2:
        return 0.0
    return sum(v * (v - 1) for v in Counter(letras).values()) / (n * (n - 1))


def _estimar_largo_clave(letras: str, largo_max: int) -> int:
    """Largo cuyas columnas se parecen más al español (índice de coincidencia alto).

    Los múltiplos del largo real también dan un índice alto, así que se elige el
    menor largo que quede cerca del máximo.
    """
    medios = {}
    for largo in range(1, largo_max + 1):
        indices = [_indice_coincidencia(letras[i::largo]) for i in range(largo)]
        medios[largo] = sum(indices) / largo
    mejor = max(medios.values())
    return next(l for l in range(1, largo_max + 1) if medios[l] >= mejor - _TOLERANCIA_IC)


def _desplazamiento_probable(columna: str) -> int:
    """Desplazamiento cuyo descifrado se parece más al español (chi-cuadrado mínimo)."""
    conteo = Counter(columna)
    n = len(columna)

    def chi_cuadrado(d: int) -> float:
        total = 0.0
        for k, letra in enumerate(ALFABETO):
            observado = conteo[ALFABETO[(k + d) % 26]]
            esperado = FRECUENCIAS_ES[letra] * n
            total += (observado - esperado) ** 2 / esperado
        return total

    return min(range(26), key=chi_cuadrado)


def vigenere_romper(texto_cifrado: str, largo_max_clave: int = 12) -> tuple[str, str]:
    """Estima la clave y descifra. Devuelve (clave_estimada, texto_descifrado).

    El largo de clave que prueba nunca supera 1/15 de las letras del texto
    (aunque `largo_max_clave` sea mayor): con menos letras por columna el
    análisis no es confiable.
    """
    if largo_max_clave < 1:
        raise ValueError("largo_max_clave debe ser al menos 1.")
    # Mismas letras que consume el cifrado, para que las columnas queden alineadas.
    letras = "".join(c.upper() for c in texto_cifrado if _es_letra(c))
    if not letras:
        raise ValueError("El texto no tiene letras para analizar.")
    tope = max(1, len(letras) // _LETRAS_MINIMAS_POR_COLUMNA)
    largo = _estimar_largo_clave(letras, min(largo_max_clave, tope))
    clave = "".join(
        ALFABETO[_desplazamiento_probable(letras[i::largo])] for i in range(largo)
    )
    return clave, vigenere_descifrar(texto_cifrado, clave)
