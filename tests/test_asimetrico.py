import inspect
import os
import stat
from collections import namedtuple

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from kit_cripto.asimetrico import (
    BITS_POR_DEFECTO,
    ErrorClave,
    firmar_archivo,
    generar_par_claves,
    guardar_firma,
    leer_firma,
    verificar_firma,
)

CONTRASENA = "contraseña-de-prueba-123"
DOCUMENTO = "Contrato: el proveedor entregará 100 unidades el 30 de noviembre.\n".encode("utf-8") * 50

Par = namedtuple("Par", "privada publica")


def _generar(carpeta, nombre):
    carpeta.mkdir(exist_ok=True)
    par = Par(carpeta / f"{nombre}.pem", carpeta / f"{nombre}.pub.pem")
    generar_par_claves(str(par.privada), str(par.publica), CONTRASENA, bits=2048)
    return par


@pytest.fixture(scope="module")
def par(tmp_path_factory):
    """Un par de claves en una carpeta temporal (nunca dentro del repo)."""
    return _generar(tmp_path_factory.mktemp("claves_a"), "a")


@pytest.fixture(scope="module")
def otro_par(tmp_path_factory):
    return _generar(tmp_path_factory.mktemp("claves_b"), "b")


@pytest.fixture
def documento(tmp_path):
    ruta = tmp_path / "documento.txt"
    ruta.write_bytes(DOCUMENTO)
    return ruta


# --- Generación de claves ---

def test_las_claves_generadas_tienen_el_formato_esperado(par):
    privada = par.privada.read_bytes()
    assert privada.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert par.publica.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")
    publica = serialization.load_pem_public_key(par.publica.read_bytes())
    assert publica.key_size == 2048
    assert publica.public_numbers().e == 65537


def test_por_defecto_usa_3072_bits():
    assert BITS_POR_DEFECTO == 3072
    assert inspect.signature(generar_par_claves).parameters["bits"].default == 3072


@pytest.mark.parametrize("bits", [0, 1024, 2047])
def test_bits_menores_a_2048(tmp_path, bits):
    with pytest.raises(ValueError, match="2048"):
        generar_par_claves(str(tmp_path / "p.pem"), str(tmp_path / "p.pub.pem"), CONTRASENA, bits=bits)
    assert list(tmp_path.iterdir()) == []


def test_contrasena_vacia(tmp_path, par, documento):
    with pytest.raises(ValueError, match="vacía"):
        generar_par_claves(str(tmp_path / "p.pem"), str(tmp_path / "p.pub.pem"), "", bits=2048)
    with pytest.raises(ValueError, match="vacía"):
        firmar_archivo(str(documento), str(par.privada), "")
    assert not (tmp_path / "p.pem").exists()


def test_la_privada_y_la_publica_no_pueden_ser_el_mismo_archivo(tmp_path):
    ruta = tmp_path / "clave.pem"
    with pytest.raises(ValueError, match="distintos"):
        generar_par_claves(str(ruta), str(ruta), CONTRASENA, bits=2048)
    assert not ruta.exists()


def test_carpeta_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError, match="carpeta"):
        generar_par_claves(
            str(tmp_path / "no_existe" / "p.pem"), str(tmp_path / "p.pub.pem"), CONTRASENA, bits=2048
        )


# --- No sobrescribir claves existentes ---

def test_no_sobrescribe_una_clave_existente(tmp_path):
    p = _generar(tmp_path, "a")
    privada, publica = p.privada.read_bytes(), p.publica.read_bytes()
    with pytest.raises(FileExistsError, match="sobrescribir"):
        generar_par_claves(str(p.privada), str(p.publica), CONTRASENA, bits=2048)
    assert p.privada.read_bytes() == privada
    assert p.publica.read_bytes() == publica


def test_si_ya_existe_la_publica_no_crea_la_privada(tmp_path):
    (tmp_path / "a.pub.pem").write_bytes(b"algo")
    with pytest.raises(FileExistsError):
        generar_par_claves(
            str(tmp_path / "a.pem"), str(tmp_path / "a.pub.pem"), CONTRASENA, bits=2048
        )
    assert not (tmp_path / "a.pem").exists()


def test_sobrescribe_solo_con_el_parametro_explicito(tmp_path):
    p = _generar(tmp_path, "a")
    antes = p.publica.read_bytes()
    generar_par_claves(str(p.privada), str(p.publica), CONTRASENA, bits=2048, sobrescribir=True)
    assert p.publica.read_bytes() != antes


@pytest.mark.skipif(os.name != "posix", reason="Los permisos 0o600 solo aplican en POSIX")
def test_la_clave_privada_tiene_permisos_600(par, tmp_path):
    assert stat.S_IMODE(os.stat(par.privada).st_mode) == 0o600
    # También cuando se reemplaza un archivo que existía con permisos abiertos.
    existente = tmp_path / "vieja.pem"
    existente.write_bytes(b"x")
    existente.chmod(0o644)
    generar_par_claves(
        str(existente), str(tmp_path / "vieja.pub.pem"), CONTRASENA, bits=2048, sobrescribir=True
    )
    assert stat.S_IMODE(os.stat(existente).st_mode) == 0o600


# --- Firmar y verificar ---

def test_firma_valida(par, documento):
    firma = firmar_archivo(str(documento), str(par.privada), CONTRASENA)
    assert isinstance(firma, bytes)
    assert len(firma) == 256  # 2048 bits
    assert verificar_firma(str(documento), firma, str(par.publica)) is True


def test_documento_alterado(par, documento):
    firma = firmar_archivo(str(documento), str(par.privada), CONTRASENA)
    alterado = bytearray(DOCUMENTO)
    alterado[10] ^= 0x01
    documento.write_bytes(bytes(alterado))
    assert verificar_firma(str(documento), firma, str(par.publica)) is False


@pytest.mark.parametrize("posicion", [0, 100, -1])
def test_firma_alterada(par, documento, posicion):
    firma = bytearray(firmar_archivo(str(documento), str(par.privada), CONTRASENA))
    firma[posicion] ^= 0x01
    assert verificar_firma(str(documento), bytes(firma), str(par.publica)) is False


@pytest.mark.parametrize("recorte", [b"", b"corta"], ids=["vacia", "corta"])
def test_firma_de_largo_incorrecto_da_false(par, documento, recorte):
    assert verificar_firma(str(documento), recorte, str(par.publica)) is False


def test_clave_publica_de_otro_par(par, otro_par, documento):
    firma = firmar_archivo(str(documento), str(par.privada), CONTRASENA)
    assert verificar_firma(str(documento), firma, str(otro_par.publica)) is False


def test_documento_grande(par, tmp_path):
    grande = tmp_path / "grande.bin"
    grande.write_bytes(os.urandom(300_000))
    firma = firmar_archivo(str(grande), str(par.privada), CONTRASENA)
    assert verificar_firma(str(grande), firma, str(par.publica)) is True


def test_pss_es_aleatorio_pero_ambas_firmas_verifican(par, documento):
    uno = firmar_archivo(str(documento), str(par.privada), CONTRASENA)
    dos = firmar_archivo(str(documento), str(par.privada), CONTRASENA)
    assert uno != dos
    assert verificar_firma(str(documento), uno, str(par.publica)) is True
    assert verificar_firma(str(documento), dos, str(par.publica)) is True


def test_es_una_firma_rsa_pss_estandar(par, documento):
    """La librería, sin pre-hashear, valida la firma con PSS; con PKCS#1 v1.5 no."""
    firma = firmar_archivo(str(documento), str(par.privada), CONTRASENA)
    publica = serialization.load_pem_public_key(par.publica.read_bytes())
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    publica.verify(firma, DOCUMENTO, pss, hashes.SHA256())  # no lanza excepción
    with pytest.raises(InvalidSignature):
        publica.verify(firma, DOCUMENTO, padding.PKCS1v15(), hashes.SHA256())


# --- Errores esperados ---

def test_contrasena_incorrecta_al_abrir_la_clave_privada(par, documento):
    with pytest.raises(ErrorClave, match="contraseña incorrecta") as error:
        firmar_archivo(str(documento), str(par.privada), "otra-contraseña")
    assert "otra-contraseña" not in str(error.value)


def test_archivos_inexistentes(par, documento, tmp_path):
    firma = firmar_archivo(str(documento), str(par.privada), CONTRASENA)
    inexistente = str(tmp_path / "no_existe")
    with pytest.raises(FileNotFoundError, match="archivo"):
        firmar_archivo(inexistente, str(par.privada), CONTRASENA)
    with pytest.raises(FileNotFoundError, match="archivo"):
        verificar_firma(inexistente, firma, str(par.publica))
    with pytest.raises(FileNotFoundError, match="clave privada"):
        firmar_archivo(str(documento), inexistente, CONTRASENA)
    with pytest.raises(FileNotFoundError, match="clave pública"):
        verificar_firma(str(documento), firma, inexistente)


def test_claves_mal_formadas(par, documento, tmp_path):
    basura = tmp_path / "basura.pem"
    basura.write_bytes(b"esto no es una clave")
    with pytest.raises(ErrorClave):
        firmar_archivo(str(documento), str(basura), CONTRASENA)
    with pytest.raises(ErrorClave):
        verificar_firma(str(documento), b"x" * 256, str(basura))
    # Una clave privada no sirve como clave pública.
    with pytest.raises(ErrorClave):
        verificar_firma(str(documento), b"x" * 256, str(par.privada))


def test_la_firma_debe_ser_bytes(par, documento):
    with pytest.raises(TypeError):
        verificar_firma(str(documento), "texto", str(par.publica))


# --- Guardar y leer la firma ---

def test_guardar_y_leer_firma(par, documento, tmp_path):
    firma = firmar_archivo(str(documento), str(par.privada), CONTRASENA)
    ruta = tmp_path / "documento.sig"
    guardar_firma(firma, str(ruta))
    assert leer_firma(str(ruta)) == firma
    assert verificar_firma(str(documento), leer_firma(str(ruta)), str(par.publica)) is True


def test_leer_firma_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError, match="firma"):
        leer_firma(str(tmp_path / "no_existe.sig"))
