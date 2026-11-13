"""Firma digital con RSA-PSS y SHA-256.

PROYECTO DIDÁCTICO: no está auditado ni pensado para proteger información real.

Cómo se usa:
- `generar_par_claves` crea dos archivos PEM: la clave privada (cifrada con una
  contraseña) y la clave pública.
- `firmar_archivo` devuelve la firma (bytes). Con `guardar_firma` y `leer_firma`
  se guarda en un archivo aparte, por ejemplo `documento.sig`, en binario.
- `verificar_firma` devuelve True o False; una firma inválida no lanza excepción.

Detalles:
- El archivo se hashea por bloques (con `hashing.sha256_archivo`) y se firma ese
  hash, así que el tamaño del archivo no se carga entero en memoria.
- La clave privada se guarda en PKCS#8 cifrado. En POSIX se crea con permisos 0o600;
  en Windows hay que proteger la carpeta que la contiene.
- Nunca subas claves privadas a un repositorio (`*.pem`, `*.key` y `claves/` están
  en el .gitignore).
"""

import contextlib
import os
import unicodedata

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from kit_cripto.hashing import sha256_archivo

EXPONENTE_PUBLICO = 65537
BITS_MINIMOS = 2048
BITS_POR_DEFECTO = 3072


class ErrorClave(Exception):
    """No se pudo abrir una clave: contraseña incorrecta o archivo de clave inválido."""


def _relleno() -> padding.PSS:
    """PSS con MGF1-SHA256 y una sal aleatoria del largo del hash (32 bytes)."""
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256.digest_size
    )


def _bytes_contrasena(contrasena: str) -> bytes:
    if not isinstance(contrasena, str):
        raise TypeError("La contraseña debe ser un texto.")
    if not contrasena:
        raise ValueError("La contraseña no puede estar vacía.")
    # NFKC: igual que en simetrico.py, los acentos compuestos o descompuestos dan lo mismo.
    return unicodedata.normalize("NFKC", contrasena).encode("utf-8")


def _hash_archivo(ruta_archivo: str) -> bytes:
    if not os.path.isfile(ruta_archivo):
        raise FileNotFoundError(f"No existe el archivo: {ruta_archivo}")
    return bytes.fromhex(sha256_archivo(ruta_archivo))


def _leer_clave_privada(ruta: str, contrasena: str) -> rsa.RSAPrivateKey:
    password = _bytes_contrasena(contrasena)
    if not os.path.isfile(ruta):
        raise FileNotFoundError(f"No existe la clave privada: {ruta}")
    with open(ruta, "rb") as archivo:
        datos = archivo.read()
    try:
        clave = serialization.load_pem_private_key(datos, password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # Mensaje único a propósito: la librería no distingue bien contraseña mala de archivo roto.
        raise ErrorClave(
            "No se pudo abrir la clave privada: contraseña incorrecta o archivo de clave inválido."
        ) from None
    if not isinstance(clave, rsa.RSAPrivateKey):
        raise ErrorClave("La clave privada no es una clave RSA.")
    return clave


def _leer_clave_publica(ruta: str) -> rsa.RSAPublicKey:
    if not os.path.isfile(ruta):
        raise FileNotFoundError(f"No existe la clave pública: {ruta}")
    with open(ruta, "rb") as archivo:
        datos = archivo.read()
    try:
        clave = serialization.load_pem_public_key(datos)
    except (ValueError, UnsupportedAlgorithm):
        raise ErrorClave(
            "No se pudo leer la clave pública: el archivo no es una clave pública PEM válida."
        ) from None
    if not isinstance(clave, rsa.RSAPublicKey):
        raise ErrorClave("La clave pública no es una clave RSA.")
    return clave


def _guardar_pem(ruta: str, datos: bytes, privada: bool, sobrescribir: bool) -> None:
    """Crea el archivo con permisos 0o600 si es privada (en POSIX)."""
    banderas = os.O_WRONLY | os.O_CREAT | getattr(os, "O_BINARY", 0)
    banderas |= os.O_TRUNC if sobrescribir else os.O_EXCL
    try:
        descriptor = os.open(ruta, banderas, 0o600 if privada else 0o644)
    except FileExistsError:
        raise FileExistsError(
            f"Ya existe {ruta}. Usá sobrescribir=True para reemplazarla."
        ) from None
    try:
        with os.fdopen(descriptor, "wb") as archivo:
            archivo.write(datos)
        if privada and os.name == "posix":
            os.chmod(ruta, 0o600)  # por si el archivo ya existía con otros permisos
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(ruta)  # no dejar una clave a medio escribir
        raise


def generar_par_claves(
    ruta_privada: str,
    ruta_publica: str,
    contrasena: str,
    bits: int = BITS_POR_DEFECTO,
    sobrescribir: bool = False,
) -> None:
    """Genera un par RSA (e=65537). La privada se guarda cifrada con la contraseña."""
    password = _bytes_contrasena(contrasena)
    if isinstance(bits, bool) or not isinstance(bits, int):
        raise TypeError("bits debe ser un número entero.")
    if bits < BITS_MINIMOS:
        raise ValueError(f"bits debe ser al menos {BITS_MINIMOS} (se recibió {bits}).")
    if os.path.normcase(os.path.abspath(ruta_privada)) == os.path.normcase(
        os.path.abspath(ruta_publica)
    ):
        raise ValueError("La clave privada y la pública deben ir en archivos distintos.")
    for ruta in (ruta_privada, ruta_publica):
        carpeta = os.path.dirname(os.path.abspath(ruta))
        if not os.path.isdir(carpeta):
            raise FileNotFoundError(f"No existe la carpeta: {carpeta}")
        if not sobrescribir and os.path.exists(ruta):
            raise FileExistsError(f"Ya existe {ruta}. Usá sobrescribir=True para reemplazarla.")

    clave = rsa.generate_private_key(public_exponent=EXPONENTE_PUBLICO, key_size=bits)
    pem_privada = clave.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    pem_publica = clave.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _guardar_pem(ruta_privada, pem_privada, privada=True, sobrescribir=sobrescribir)
    _guardar_pem(ruta_publica, pem_publica, privada=False, sobrescribir=sobrescribir)


def firmar_archivo(ruta_archivo: str, ruta_clave_privada: str, contrasena: str) -> bytes:
    """Firma el archivo con RSA-PSS y SHA-256 y devuelve la firma."""
    clave = _leer_clave_privada(ruta_clave_privada, contrasena)
    digest = _hash_archivo(ruta_archivo)
    return clave.sign(digest, _relleno(), utils.Prehashed(hashes.SHA256()))


def verificar_firma(ruta_archivo: str, firma: bytes, ruta_clave_publica: str) -> bool:
    """True si la firma es válida; False si el documento, la firma o la clave no coinciden."""
    if not isinstance(firma, bytes):
        raise TypeError("La firma debe ser de tipo bytes.")
    clave = _leer_clave_publica(ruta_clave_publica)
    digest = _hash_archivo(ruta_archivo)
    try:
        clave.verify(firma, digest, _relleno(), utils.Prehashed(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def guardar_firma(firma: bytes, ruta_firma: str) -> None:
    """Guarda la firma en binario (por ejemplo `documento.sig`). Reemplaza si existe."""
    if not isinstance(firma, bytes):
        raise TypeError("La firma debe ser de tipo bytes.")
    with open(ruta_firma, "wb") as archivo:
        archivo.write(firma)


def leer_firma(ruta_firma: str) -> bytes:
    """Lee una firma guardada con `guardar_firma`."""
    if not os.path.isfile(ruta_firma):
        raise FileNotFoundError(f"No existe el archivo de firma: {ruta_firma}")
    with open(ruta_firma, "rb") as archivo:
        return archivo.read()
