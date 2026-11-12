"""Cifrado simétrico de archivos con AES-256-GCM y clave derivada de una contraseña.

PROYECTO DIDÁCTICO: no está auditado ni pensado para proteger información real.

Límites:
- GCM se aplica en memoria: el archivo se lee entero, se cifra o descifra entero
  y recién después se escribe. No sirve para archivos muy grandes (ocupan RAM y
  la librería limita el tamaño de cada mensaje). Para eso habría que cifrar por
  bloques, cada uno con su propio nonce.
- Python no permite borrar de forma segura la contraseña ni la clave de la memoria.

Formato del archivo cifrado (versión 1):

    marca "KCRIPTO" (7 bytes) | versión (1 byte) | sal (16) | nonce (12) | texto cifrado + etiqueta (16)

Los primeros 36 bytes (marca, versión, sal y nonce) se autentican como datos
asociados (AAD): si se modifica cualquiera, el descifrado falla.
La versión 1 deriva la clave con scrypt (N=2^17, r=8, p=1), 256 bits.
"""

import contextlib
import os
import tempfile
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MARCA = b"KCRIPTO"
VERSION = 1
TAM_SAL = 16
TAM_NONCE = 12
TAM_ETIQUETA = 16
TAM_CLAVE = 32  # 256 bits

_LARGO_PREFIJO = len(MARCA) + 1 + TAM_SAL + TAM_NONCE

# Valores mínimos recomendados por OWASP para scrypt (usa ~128 MiB de memoria).
_SCRYPT_N = 2**17
_SCRYPT_R = 8
_SCRYPT_P = 1


class ErrorDescifrado(Exception):
    """No se pudo descifrar: contraseña incorrecta, archivo alterado o formato inválido."""


def _validar_contrasena(contrasena: str) -> None:
    if not isinstance(contrasena, str):
        raise TypeError("La contraseña debe ser un texto.")
    if not contrasena:
        raise ValueError("La contraseña no puede estar vacía.")


def _validar_rutas(ruta_entrada: str, ruta_salida: str) -> None:
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError(f"No existe el archivo de entrada: {ruta_entrada}")
    misma = os.path.normcase(os.path.abspath(ruta_entrada)) == os.path.normcase(
        os.path.abspath(ruta_salida)
    )
    if not misma and os.path.exists(ruta_salida):
        misma = os.path.samefile(ruta_entrada, ruta_salida)
    if misma:
        raise ValueError("El archivo de salida no puede ser el mismo que el de entrada.")
    carpeta = os.path.dirname(os.path.abspath(ruta_salida))
    if not os.path.isdir(carpeta):
        raise FileNotFoundError(f"No existe la carpeta de salida: {carpeta}")


def _escribir_atomico(ruta: str, datos: bytes) -> None:
    """Escribe en un temporal y lo renombra al final: nunca queda un archivo a medias."""
    carpeta = os.path.dirname(os.path.abspath(ruta))
    fd, ruta_temporal = tempfile.mkstemp(dir=carpeta, prefix=".kcripto-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as archivo:
            archivo.write(datos)
        os.replace(ruta_temporal, ruta)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.remove(ruta_temporal)
        raise


def derivar_clave(contrasena: str, sal: bytes) -> bytes:
    """Deriva una clave de 256 bits con scrypt a partir de la contraseña y la sal."""
    _validar_contrasena(contrasena)
    if not isinstance(sal, bytes) or len(sal) != TAM_SAL:
        raise ValueError(f"La sal debe ser de {TAM_SAL} bytes.")
    kdf = Scrypt(salt=sal, length=TAM_CLAVE, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    # NFKC: la misma contraseña con acentos compuestos o descompuestos da la misma clave.
    return kdf.derive(unicodedata.normalize("NFKC", contrasena).encode("utf-8"))


def cifrar_archivo(ruta_entrada: str, ruta_salida: str, contrasena: str) -> None:
    """Cifra un archivo con AES-GCM. Si la salida ya existe, la reemplaza."""
    _validar_contrasena(contrasena)
    _validar_rutas(ruta_entrada, ruta_salida)
    with open(ruta_entrada, "rb") as archivo:
        datos = archivo.read()
    sal = os.urandom(TAM_SAL)
    nonce = os.urandom(TAM_NONCE)  # nuevo en cada cifrado: nunca se reutiliza
    prefijo = MARCA + bytes([VERSION]) + sal + nonce
    clave = derivar_clave(contrasena, sal)
    cifrado = AESGCM(clave).encrypt(nonce, datos, prefijo)
    _escribir_atomico(ruta_salida, prefijo + cifrado)


def descifrar_archivo(ruta_entrada: str, ruta_salida: str, contrasena: str) -> None:
    """Descifra un archivo de `cifrar_archivo`. Si falla, no escribe nada."""
    _validar_contrasena(contrasena)
    _validar_rutas(ruta_entrada, ruta_salida)
    with open(ruta_entrada, "rb") as archivo:
        contenido = archivo.read()
    if (
        len(contenido) < _LARGO_PREFIJO + TAM_ETIQUETA
        or not contenido.startswith(MARCA)
        or contenido[len(MARCA)] != VERSION
    ):
        raise ErrorDescifrado("No se pudo descifrar: el archivo no tiene el formato esperado.")
    prefijo = contenido[:_LARGO_PREFIJO]
    sal = prefijo[len(MARCA) + 1 : len(MARCA) + 1 + TAM_SAL]
    nonce = prefijo[len(MARCA) + 1 + TAM_SAL :]
    clave = derivar_clave(contrasena, sal)
    try:
        datos = AESGCM(clave).decrypt(nonce, contenido[_LARGO_PREFIJO:], prefijo)
    except InvalidTag:
        # Mensaje único a propósito: no distingue contraseña mala de archivo alterado.
        raise ErrorDescifrado(
            "No se pudo descifrar: contraseña incorrecta o archivo alterado."
        ) from None
    _escribir_atomico(ruta_salida, datos)
