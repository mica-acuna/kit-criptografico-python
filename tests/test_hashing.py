import hashlib
import random

import pytest

from kit_cripto.hashing import sha256_archivo, verificar

HASH_HOLA = "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79"
HASH_VACIO = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
HASH_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
BLOQUE = 65536  # tamaño de lectura de sha256_archivo


def _archivo(tmp_path, contenido: bytes):
    ruta = tmp_path / "datos.bin"
    ruta.write_bytes(contenido)
    return str(ruta)


def test_sha256_archivo_conocido(tmp_path):
    archivo = tmp_path / "hola.txt"
    archivo.write_bytes(b"hola")
    assert sha256_archivo(str(archivo)) == HASH_HOLA


def test_verificar(tmp_path):
    archivo = tmp_path / "hola.txt"
    archivo.write_bytes(b"hola")
    assert verificar(str(archivo), HASH_HOLA) is True
    assert verificar(str(archivo), HASH_HOLA.upper()) is True
    assert verificar(str(archivo), "0" * 64) is False
    archivo.write_bytes(b"hola!")
    assert verificar(str(archivo), HASH_HOLA) is False


# --- Vectores conocidos (NIST) ---

@pytest.mark.parametrize(
    "contenido, esperado",
    [(b"", HASH_VACIO), (b"abc", HASH_ABC)],
    ids=["cadena-vacia", "abc"],
)
def test_vectores_conocidos(tmp_path, contenido, esperado):
    assert sha256_archivo(_archivo(tmp_path, contenido)) == esperado


def test_archivo_vacio_se_puede_verificar(tmp_path):
    ruta = _archivo(tmp_path, b"")
    assert verificar(ruta, HASH_VACIO) is True


# --- Archivos que cruzan el límite del bloque de lectura ---

@pytest.mark.parametrize(
    "tamano",
    [BLOQUE - 1, BLOQUE, BLOQUE + 1, 2 * BLOQUE, 2 * BLOQUE + 1, 5 * BLOQUE + 123],
)
def test_archivos_alrededor_del_limite_del_bloque(tmp_path, tamano):
    contenido = random.Random(tamano).randbytes(tamano)  # determinista
    esperado = hashlib.sha256(contenido).hexdigest()
    assert sha256_archivo(_archivo(tmp_path, contenido)) == esperado


# --- verificar ---

def test_verificar_acepta_mayusculas_y_minusculas(tmp_path):
    ruta = _archivo(tmp_path, b"abc")
    assert verificar(ruta, HASH_ABC.lower()) is True
    assert verificar(ruta, HASH_ABC.upper()) is True
    mezcla = "".join(c.upper() if i % 2 else c for i, c in enumerate(HASH_ABC))
    assert mezcla not in (HASH_ABC, HASH_ABC.upper())
    assert verificar(ruta, mezcla) is True


@pytest.mark.parametrize(
    "hash_incorrecto",
    [
        "0" * 64,
        HASH_ABC[:-1] + "0",  # difiere solo en el último carácter
        HASH_ABC[:-1],  # un carácter de menos
        HASH_ABC + "0",  # un carácter de más
        "",
        "no es un hash",
    ],
    ids=["ceros", "ultimo-caracter", "corto", "largo", "vacio", "texto"],
)
def test_verificar_hash_incorrecto_da_false(tmp_path, hash_incorrecto):
    assert verificar(_archivo(tmp_path, b"abc"), hash_incorrecto) is False


def test_verificar_detecta_un_solo_byte_cambiado(tmp_path):
    contenido = bytearray(random.Random(1).randbytes(3 * BLOQUE))
    ruta = _archivo(tmp_path, bytes(contenido))
    esperado = sha256_archivo(ruta)
    contenido[BLOQUE] ^= 0x01  # justo en el límite entre bloques
    (tmp_path / "datos.bin").write_bytes(bytes(contenido))
    assert verificar(ruta, esperado) is False


def test_archivo_inexistente(tmp_path):
    inexistente = str(tmp_path / "no_existe.bin")
    with pytest.raises(FileNotFoundError):
        sha256_archivo(inexistente)
    with pytest.raises(FileNotFoundError):
        verificar(inexistente, HASH_ABC)


def test_directorio_en_lugar_de_archivo(tmp_path):
    with pytest.raises(OSError):  # PermissionError en Windows, IsADirectoryError en POSIX
        sha256_archivo(str(tmp_path))


# --- Bug conocido (pendiente de decidir): ver el informe del diagnóstico ---

@pytest.mark.xfail(
    strict=True,
    raises=TypeError,
    reason="hmac.compare_digest no acepta str con caracteres no ASCII: debería dar False",
)
def test_verificar_hash_con_caracteres_no_ascii_da_false(tmp_path):
    assert verificar(_archivo(tmp_path, b"abc"), "ñ" * 64) is False


@pytest.mark.xfail(
    strict=True,
    raises=AttributeError,
    reason="hash_esperado=None da AttributeError en vez de un error claro (TypeError)",
)
def test_verificar_hash_que_no_es_texto_da_un_error_claro(tmp_path):
    with pytest.raises(TypeError):
        verificar(_archivo(tmp_path, b"abc"), None)
