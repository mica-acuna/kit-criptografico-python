import os
import random

import pytest

from kit_cripto import simetrico
from kit_cripto.simetrico import (
    MARCA,
    TAM_ETIQUETA,
    TAM_NONCE,
    TAM_SAL,
    ErrorDescifrado,
    cifrar_archivo,
    derivar_clave,
    descifrar_archivo,
)

CONTRASENA = "contraseña-de-prueba-123"
LARGO_PREFIJO = len(MARCA) + 1 + TAM_SAL + TAM_NONCE  # 36
TEXTO = "Mensaje secreto con acentos: canción, año, ¿qué?\n".encode("utf-8") * 20


@pytest.fixture(scope="module", autouse=True)
def scrypt_rapido():
    """Con los parámetros reales (128 MiB) cada derivación tarda ~1 s; acá se achican."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(simetrico, "_SCRYPT_N", 2**10)
        yield


@pytest.fixture(scope="module")
def cifrado_de_referencia(tmp_path_factory, scrypt_rapido):
    """Un archivo cifrado (derivar la clave tarda, así que se hace una sola vez)."""
    carpeta = tmp_path_factory.mktemp("referencia")
    original = carpeta / "original.txt"
    original.write_bytes(TEXTO)
    cifrado = carpeta / "original.kcripto"
    cifrar_archivo(str(original), str(cifrado), CONTRASENA)
    return cifrado.read_bytes()


# --- Ida y vuelta ---

@pytest.mark.parametrize(
    "contenido",
    [
        TEXTO,
        bytes(range(256)) * 40,
        random.Random(0).randbytes(200_000),  # determinista
        b"",
    ],
    ids=["texto", "binario", "grande", "vacio"],
)
def test_ida_y_vuelta(tmp_path, contenido):
    original = tmp_path / "original.bin"
    cifrado = tmp_path / "original.kcripto"
    recuperado = tmp_path / "recuperado.bin"
    original.write_bytes(contenido)
    cifrar_archivo(str(original), str(cifrado), CONTRASENA)
    descifrar_archivo(str(cifrado), str(recuperado), CONTRASENA)
    assert recuperado.read_bytes() == contenido


def test_formato_del_archivo_cifrado(cifrado_de_referencia):
    assert cifrado_de_referencia.startswith(MARCA)
    assert cifrado_de_referencia[len(MARCA)] == 1
    assert len(cifrado_de_referencia) == LARGO_PREFIJO + len(TEXTO) + TAM_ETIQUETA
    assert b"Mensaje secreto" not in cifrado_de_referencia


# --- Contraseña incorrecta ---

def test_contrasena_incorrecta(tmp_path, cifrado_de_referencia):
    cifrado = tmp_path / "datos.kcripto"
    salida = tmp_path / "salida.txt"
    cifrado.write_bytes(cifrado_de_referencia)
    with pytest.raises(ErrorDescifrado) as error:
        descifrar_archivo(str(cifrado), str(salida), "otra-contraseña")
    assert "otra-contraseña" not in str(error.value)
    assert not salida.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["datos.kcripto"]  # sin temporales


def test_si_falla_no_pisa_una_salida_existente(tmp_path, cifrado_de_referencia):
    cifrado = tmp_path / "datos.kcripto"
    salida = tmp_path / "salida.txt"
    cifrado.write_bytes(cifrado_de_referencia)
    salida.write_bytes(b"contenido previo")
    with pytest.raises(ErrorDescifrado):
        descifrar_archivo(str(cifrado), str(salida), "incorrecta")
    assert salida.read_bytes() == b"contenido previo"


# --- Archivo alterado ---

@pytest.mark.parametrize(
    "posicion",
    [
        0,  # marca
        len(MARCA),  # versión
        len(MARCA) + 1,  # sal (primer byte)
        len(MARCA) + TAM_SAL,  # sal (último byte)
        len(MARCA) + 1 + TAM_SAL,  # nonce (primer byte)
        LARGO_PREFIJO - 1,  # nonce (último byte)
        LARGO_PREFIJO,  # texto cifrado (primer byte)
        -1,  # etiqueta de autenticación (último byte)
    ],
    ids=["marca", "version", "sal-inicio", "sal-fin", "nonce-inicio", "nonce-fin", "texto", "etiqueta"],
)
def test_archivo_alterado(tmp_path, cifrado_de_referencia, posicion):
    alterado = bytearray(cifrado_de_referencia)
    alterado[posicion] ^= 0x01
    cifrado = tmp_path / "alterado.kcripto"
    salida = tmp_path / "salida.txt"
    cifrado.write_bytes(bytes(alterado))
    with pytest.raises(ErrorDescifrado):
        descifrar_archivo(str(cifrado), str(salida), CONTRASENA)
    assert not salida.exists()


@pytest.mark.parametrize(
    "contenido",
    [b"", b"KCRIPTO", b"no soy un archivo cifrado " * 10, None],
    ids=["vacio", "solo-marca", "otro-formato", "truncado"],
)
def test_archivo_que_no_es_valido(tmp_path, cifrado_de_referencia, contenido):
    if contenido is None:
        contenido = cifrado_de_referencia[: LARGO_PREFIJO + 5]
    cifrado = tmp_path / "raro.kcripto"
    salida = tmp_path / "salida.txt"
    cifrado.write_bytes(contenido)
    with pytest.raises(ErrorDescifrado):
        descifrar_archivo(str(cifrado), str(salida), CONTRASENA)
    assert not salida.exists()


# --- Sal y nonce nuevos en cada cifrado ---

def test_dos_cifrados_del_mismo_archivo_son_distintos(tmp_path):
    original = tmp_path / "original.txt"
    original.write_bytes(TEXTO)
    uno = tmp_path / "uno.kcripto"
    dos = tmp_path / "dos.kcripto"
    cifrar_archivo(str(original), str(uno), CONTRASENA)
    cifrar_archivo(str(original), str(dos), CONTRASENA)
    a, b = uno.read_bytes(), dos.read_bytes()
    assert a != b
    assert a[len(MARCA) + 1 : len(MARCA) + 1 + TAM_SAL] != b[len(MARCA) + 1 : len(MARCA) + 1 + TAM_SAL]
    assert a[LARGO_PREFIJO - TAM_NONCE : LARGO_PREFIJO] != b[LARGO_PREFIJO - TAM_NONCE : LARGO_PREFIJO]
    assert a[LARGO_PREFIJO:] != b[LARGO_PREFIJO:]


# --- Validaciones ---

def test_contrasena_vacia(tmp_path):
    original = tmp_path / "original.txt"
    original.write_bytes(TEXTO)
    salida = tmp_path / "salida.kcripto"
    with pytest.raises(ValueError, match="vacía"):
        cifrar_archivo(str(original), str(salida), "")
    with pytest.raises(ValueError, match="vacía"):
        descifrar_archivo(str(original), str(salida), "")
    assert not salida.exists()


def test_archivo_de_entrada_inexistente(tmp_path):
    salida = tmp_path / "salida"
    with pytest.raises(FileNotFoundError, match="entrada"):
        cifrar_archivo(str(tmp_path / "no_existe.txt"), str(salida), CONTRASENA)
    with pytest.raises(FileNotFoundError, match="entrada"):
        descifrar_archivo(str(tmp_path / "no_existe.txt"), str(salida), CONTRASENA)
    assert not salida.exists()


def test_la_salida_no_puede_ser_la_entrada(tmp_path):
    archivo = tmp_path / "datos.txt"
    archivo.write_bytes(TEXTO)
    otra_forma = tmp_path / "." / "datos.txt"  # misma ruta escrita distinto
    for salida in (archivo, otra_forma):
        with pytest.raises(ValueError, match="mismo"):
            cifrar_archivo(str(archivo), str(salida), CONTRASENA)
        with pytest.raises(ValueError, match="mismo"):
            descifrar_archivo(str(archivo), str(salida), CONTRASENA)
    assert archivo.read_bytes() == TEXTO


def test_carpeta_de_salida_inexistente(tmp_path):
    original = tmp_path / "original.txt"
    original.write_bytes(TEXTO)
    with pytest.raises(FileNotFoundError, match="carpeta"):
        cifrar_archivo(str(original), str(tmp_path / "no_existe" / "salida"), CONTRASENA)


# --- Derivación de clave ---

def test_derivar_clave_es_determinista():
    sal = bytes(range(TAM_SAL))
    clave = derivar_clave(CONTRASENA, sal)
    assert len(clave) == 32
    assert derivar_clave(CONTRASENA, sal) == clave


def test_derivar_clave_cambia_con_la_sal_y_con_la_contrasena():
    sal = bytes(range(TAM_SAL))
    otra_sal = bytes(reversed(sal))
    assert derivar_clave(CONTRASENA, sal) != derivar_clave(CONTRASENA, otra_sal)
    assert derivar_clave(CONTRASENA, sal) != derivar_clave(CONTRASENA + "x", sal)


def test_derivar_clave_ignora_la_forma_de_escribir_los_acentos():
    sal = bytes(range(TAM_SAL))
    compuesta = "contraseña"  # ñ en un solo carácter
    descompuesta = "contraseña"  # n + tilde combinada
    assert derivar_clave(compuesta, sal) == derivar_clave(descompuesta, sal)


@pytest.mark.lento
def test_parametros_reales_de_scrypt(tmp_path, monkeypatch):
    monkeypatch.setattr(simetrico, "_SCRYPT_N", 2**17)  # el valor de producción
    assert simetrico._SCRYPT_R == 8 and simetrico._SCRYPT_P == 1
    original = tmp_path / "original.txt"
    cifrado = tmp_path / "original.kcripto"
    recuperado = tmp_path / "recuperado.txt"
    original.write_bytes(TEXTO)
    cifrar_archivo(str(original), str(cifrado), CONTRASENA)
    descifrar_archivo(str(cifrado), str(recuperado), CONTRASENA)
    assert recuperado.read_bytes() == TEXTO


def test_derivar_clave_valida_entradas():
    with pytest.raises(ValueError, match="vacía"):
        derivar_clave("", bytes(TAM_SAL))
    with pytest.raises(ValueError, match="sal"):
        derivar_clave(CONTRASENA, b"corta")


@pytest.mark.parametrize("sal", ["a" * TAM_SAL, bytearray(TAM_SAL), None, b"", bytes(TAM_SAL + 1)])
def test_derivar_clave_rechaza_sales_que_no_son_bytes_de_16(sal):
    with pytest.raises(ValueError, match="sal"):
        derivar_clave(CONTRASENA, sal)


@pytest.mark.parametrize("contrasena", [None, 12345, b"bytes", ["lista"]])
def test_la_contrasena_debe_ser_texto(tmp_path, contrasena):
    original = tmp_path / "original.txt"
    original.write_bytes(TEXTO)
    salida = tmp_path / "salida"
    with pytest.raises(TypeError, match="texto"):
        cifrar_archivo(str(original), str(salida), contrasena)
    with pytest.raises(TypeError, match="texto"):
        descifrar_archivo(str(original), str(salida), contrasena)
    with pytest.raises(TypeError, match="texto"):
        derivar_clave(contrasena, bytes(TAM_SAL))
    assert not salida.exists()


# --- Archivos grandes ---

def test_ida_y_vuelta_con_un_archivo_de_varios_megabytes(tmp_path):
    contenido = random.Random(7).randbytes(5 * 1024 * 1024 + 123)  # no múltiplo de 16
    original = tmp_path / "grande.bin"
    cifrado = tmp_path / "grande.kcripto"
    recuperado = tmp_path / "recuperado.bin"
    original.write_bytes(contenido)
    cifrar_archivo(str(original), str(cifrado), CONTRASENA)
    assert cifrado.stat().st_size == LARGO_PREFIJO + len(contenido) + TAM_ETIQUETA
    descifrar_archivo(str(cifrado), str(recuperado), CONTRASENA)
    assert recuperado.read_bytes() == contenido


def test_el_archivo_cifrado_vacio_mide_exactamente_el_minimo(tmp_path):
    original = tmp_path / "vacio"
    cifrado = tmp_path / "vacio.kcripto"
    original.write_bytes(b"")
    cifrar_archivo(str(original), str(cifrado), CONTRASENA)
    assert cifrado.stat().st_size == LARGO_PREFIJO + TAM_ETIQUETA  # 52 bytes


# --- Contraseñas con acentos, emojis y otros caracteres ---

@pytest.mark.parametrize(
    "contrasena",
    [
        "contraseña",
        "pässwörd-ÄÖÜ",
        "🔐clave🗝️",
        "日本語のパスワード",
        "пароль",
        "con espacios al final   ",
        "con\nsalto\tde línea",
        "a",
        "x" * 2000,
    ],
    ids=["enie", "dieresis", "emojis", "japones", "cirilico", "espacios", "controles", "una-letra", "larga"],
)
def test_ida_y_vuelta_con_contrasenas_de_todo_tipo(tmp_path, contrasena):
    original = tmp_path / "original.txt"
    cifrado = tmp_path / "original.kcripto"
    recuperado = tmp_path / "recuperado.txt"
    original.write_bytes(TEXTO)
    cifrar_archivo(str(original), str(cifrado), contrasena)
    descifrar_archivo(str(cifrado), str(recuperado), contrasena)
    assert recuperado.read_bytes() == TEXTO


def test_contrasenas_parecidas_no_abren_el_archivo(tmp_path):
    original = tmp_path / "original.txt"
    cifrado = tmp_path / "original.kcripto"
    original.write_bytes(TEXTO)
    cifrar_archivo(str(original), str(cifrado), "🔐clave🗝️")
    for parecida in ("🔐clave🔑", "🔐clave", "🔐Clave🗝️", "🔐clave🗝️ ", " 🔐clave🗝️"):
        with pytest.raises(ErrorDescifrado):
            descifrar_archivo(str(cifrado), str(tmp_path / "salida"), parecida)
    assert not (tmp_path / "salida").exists()


def test_cifrar_con_acento_compuesto_y_descifrar_con_descompuesto(tmp_path):
    original = tmp_path / "original.txt"
    cifrado = tmp_path / "original.kcripto"
    recuperado = tmp_path / "recuperado.txt"
    original.write_bytes(TEXTO)
    cifrar_archivo(str(original), str(cifrado), "contraseña")  # ñ en un carácter
    descifrar_archivo(str(cifrado), str(recuperado), "contraseña")  # n + tilde
    assert recuperado.read_bytes() == TEXTO


# --- Archivos truncados, con encabezado inválido o con datos de más ---

def _descifrar_y_comprobar_que_falla(tmp_path, contenido: bytes):
    cifrado = tmp_path / "invalido.kcripto"
    salida = tmp_path / "salida"
    cifrado.write_bytes(contenido)
    with pytest.raises(ErrorDescifrado):
        descifrar_archivo(str(cifrado), str(salida), CONTRASENA)
    assert not salida.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["invalido.kcripto"]  # sin temporales


@pytest.mark.parametrize(
    "largo",
    [0, 1, len(MARCA), len(MARCA) + 1, LARGO_PREFIJO - 1, LARGO_PREFIJO, LARGO_PREFIJO + TAM_ETIQUETA - 1],
    ids=["vacio", "un-byte", "solo-marca", "marca-y-version", "sin-ultimo-byte-del-nonce", "sin-datos", "sin-etiqueta-completa"],
)
def test_archivo_truncado_en_el_encabezado_o_la_etiqueta(tmp_path, cifrado_de_referencia, largo):
    _descifrar_y_comprobar_que_falla(tmp_path, cifrado_de_referencia[:largo])


@pytest.mark.parametrize("quitar", [1, 16, 17, 100])
def test_archivo_truncado_al_final(tmp_path, cifrado_de_referencia, quitar):
    _descifrar_y_comprobar_que_falla(tmp_path, cifrado_de_referencia[:-quitar])


@pytest.mark.parametrize("extra", [b"\x00", b"basura al final", bytes(100)])
def test_archivo_con_bytes_de_mas_al_final(tmp_path, cifrado_de_referencia, extra):
    _descifrar_y_comprobar_que_falla(tmp_path, cifrado_de_referencia + extra)


@pytest.mark.parametrize("version", [0, 2, 255])
def test_version_no_soportada(tmp_path, cifrado_de_referencia, version):
    contenido = bytearray(cifrado_de_referencia)
    contenido[len(MARCA)] = version
    _descifrar_y_comprobar_que_falla(tmp_path, bytes(contenido))


@pytest.mark.parametrize("marca", [b"kcripto", b"KCRIPTA", b"\x00" * len(MARCA), MARCA[::-1]], ids=["minusculas", "una-letra", "ceros", "invertida"])
def test_marca_invalida(tmp_path, cifrado_de_referencia, marca):
    contenido = marca + cifrado_de_referencia[len(marca) :]
    _descifrar_y_comprobar_que_falla(tmp_path, contenido)


def test_archivo_de_texto_comun_no_se_confunde_con_uno_cifrado(tmp_path):
    _descifrar_y_comprobar_que_falla(tmp_path, TEXTO)


# --- Rutas problemáticas ---

def test_entrada_que_es_una_carpeta(tmp_path):
    with pytest.raises(FileNotFoundError, match="entrada"):
        cifrar_archivo(str(tmp_path), str(tmp_path / "salida"), CONTRASENA)
    with pytest.raises(FileNotFoundError, match="entrada"):
        descifrar_archivo(str(tmp_path), str(tmp_path / "salida"), CONTRASENA)


def test_salida_que_es_una_carpeta_no_deja_temporales(tmp_path):
    original = tmp_path / "original.txt"
    carpeta = tmp_path / "carpeta"
    original.write_bytes(TEXTO)
    carpeta.mkdir()
    with pytest.raises(OSError):  # PermissionError en Windows, IsADirectoryError en POSIX
        cifrar_archivo(str(original), str(carpeta), CONTRASENA)
    assert carpeta.is_dir()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["carpeta", "original.txt"]


def test_la_salida_igual_a_la_entrada_no_toca_el_archivo(tmp_path, cifrado_de_referencia):
    cifrado = tmp_path / "datos.kcripto"
    cifrado.write_bytes(cifrado_de_referencia)
    with pytest.raises(ValueError, match="mismo"):
        descifrar_archivo(str(cifrado), str(cifrado), CONTRASENA)
    assert cifrado.read_bytes() == cifrado_de_referencia


def test_rutas_relativas(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "original.txt").write_bytes(TEXTO)
    cifrar_archivo("original.txt", "original.kcripto", CONTRASENA)
    descifrar_archivo("original.kcripto", "recuperado.txt", CONTRASENA)
    assert (tmp_path / "recuperado.txt").read_bytes() == TEXTO


# --- Sal y nonce: nunca se repiten ---

def test_veinte_cifrados_no_repiten_sal_ni_nonce(tmp_path):
    cantidad = 20
    original = tmp_path / "original.txt"
    original.write_bytes(TEXTO)
    sales, nonces = set(), set()
    for i in range(cantidad):
        salida = tmp_path / f"cifrado-{i}.kcripto"
        cifrar_archivo(str(original), str(salida), CONTRASENA)
        contenido = salida.read_bytes()
        sales.add(contenido[len(MARCA) + 1 : len(MARCA) + 1 + TAM_SAL])
        nonces.add(contenido[LARGO_PREFIJO - TAM_NONCE : LARGO_PREFIJO])
    assert len(sales) == cantidad
    assert len(nonces) == cantidad
