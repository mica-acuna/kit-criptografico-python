import inspect
import os
import random
import stat
from collections import namedtuple

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from kit_cripto import asimetrico
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
    grande.write_bytes(random.Random(0).randbytes(300_000))  # determinista
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


# --- Documentos vacíos y grandes ---

def test_firmar_un_documento_vacio(par, tmp_path):
    vacio = tmp_path / "vacio.txt"
    vacio.write_bytes(b"")
    firma = firmar_archivo(str(vacio), str(par.privada), CONTRASENA)
    assert verificar_firma(str(vacio), firma, str(par.publica)) is True
    vacio.write_bytes(b"x")  # agregarle un byte invalida la firma
    assert verificar_firma(str(vacio), firma, str(par.publica)) is False


def test_documento_de_mas_de_un_megabyte_y_un_solo_byte_cambiado(par, tmp_path):
    contenido = bytearray(random.Random(3).randbytes(1024 * 1024 + 17))
    grande = tmp_path / "grande.bin"
    grande.write_bytes(bytes(contenido))
    firma = firmar_archivo(str(grande), str(par.privada), CONTRASENA)
    assert verificar_firma(str(grande), firma, str(par.publica)) is True
    contenido[-1] ^= 0x01  # el último byte
    grande.write_bytes(bytes(contenido))
    assert verificar_firma(str(grande), firma, str(par.publica)) is False


def test_la_firma_de_un_documento_no_sirve_para_otro(par, documento, tmp_path):
    otro = tmp_path / "otro.txt"
    otro.write_bytes(DOCUMENTO + b"!")
    firma = firmar_archivo(str(documento), str(par.privada), CONTRASENA)
    assert verificar_firma(str(otro), firma, str(par.publica)) is False


# --- Firmas de largo o contenido incorrecto ---

@pytest.mark.parametrize(
    "transformar",
    [
        lambda firma: firma + b"\x00",  # un byte de más
        lambda firma: firma[:-1],  # un byte de menos
        lambda firma: firma * 2,
        lambda firma: bytes(len(firma)),  # del largo correcto pero todo ceros
        lambda firma: b"\xff" * len(firma),
        lambda firma: firma[::-1],
    ],
    ids=["un-byte-de-mas", "un-byte-de-menos", "duplicada", "ceros", "unos", "invertida"],
)
def test_firmas_de_largo_o_contenido_incorrecto_dan_false(par, documento, transformar):
    firma = firmar_archivo(str(documento), str(par.privada), CONTRASENA)
    assert verificar_firma(str(documento), transformar(firma), str(par.publica)) is False


# --- Claves públicas mal formadas ---

def _pem_publico_valido(par) -> str:
    return par.publica.read_text()


@pytest.mark.parametrize(
    "modificar",
    [
        lambda pem: "",
        lambda pem: pem[: len(pem) // 2],  # cortada a la mitad
        lambda pem: pem.splitlines()[0] + "\n",  # solo el encabezado
        lambda pem: pem.replace("A", "B", 20),  # cuerpo base64 alterado
        lambda pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        lambda pem: pem.replace("PUBLIC KEY", "CERTIFICATE"),  # etiqueta de otro tipo
    ],
    ids=["vacia", "cortada", "solo-encabezado", "cuerpo-alterado", "cuerpo-minimo", "otra-etiqueta"],
)
def test_clave_publica_mal_formada(par, documento, tmp_path, modificar):
    mala = tmp_path / "mala.pub.pem"
    mala.write_text(modificar(_pem_publico_valido(par)))
    with pytest.raises(ErrorClave, match="pública"):
        verificar_firma(str(documento), bytes(256), str(mala))


def test_clave_publica_con_codificacion_binaria_en_lugar_de_pem(par, documento, tmp_path):
    publica = serialization.load_pem_public_key(par.publica.read_bytes())
    der = tmp_path / "publica.der"
    der.write_bytes(
        publica.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(ErrorClave):
        verificar_firma(str(documento), bytes(256), str(der))


def test_clave_ec_como_publica_no_se_acepta(documento, tmp_path):
    clave_ec = ec.generate_private_key(ec.SECP256R1())
    ruta = tmp_path / "ec.pub.pem"
    ruta.write_bytes(
        clave_ec.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    with pytest.raises(ErrorClave, match="RSA"):
        verificar_firma(str(documento), bytes(256), str(ruta))


# --- Claves privadas con contraseña errónea o mal formadas ---

@pytest.mark.parametrize(
    "contrasena",
    [CONTRASENA + "x", CONTRASENA[:-1], CONTRASENA.upper(), " " + CONTRASENA, "a"],
    ids=["de-mas", "de-menos", "mayusculas", "espacio-inicial", "otra"],
)
def test_contrasenas_parecidas_no_abren_la_clave_privada(par, documento, contrasena):
    with pytest.raises(ErrorClave, match="contraseña incorrecta"):
        firmar_archivo(str(documento), str(par.privada), contrasena)


@pytest.mark.parametrize("contrasena", [None, 123, b"bytes"])
def test_la_contrasena_debe_ser_texto(tmp_path, par, documento, contrasena):
    with pytest.raises(TypeError, match="texto"):
        firmar_archivo(str(documento), str(par.privada), contrasena)
    with pytest.raises(TypeError, match="texto"):
        generar_par_claves(str(tmp_path / "p.pem"), str(tmp_path / "p.pub.pem"), contrasena, bits=2048)
    assert list(tmp_path.glob("*.pem")) == []


def test_clave_privada_sin_cifrar_no_se_abre_con_contrasena(documento, tmp_path):
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sin_cifrar = tmp_path / "sin_cifrar.pem"
    sin_cifrar.write_bytes(
        clave.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ErrorClave):
        firmar_archivo(str(documento), str(sin_cifrar), CONTRASENA)


def test_clave_privada_corrupta(par, documento, tmp_path):
    pem = par.privada.read_text()
    corrupta = tmp_path / "corrupta.pem"
    corrupta.write_text(pem.replace("A", "B", 30))
    with pytest.raises(ErrorClave):
        firmar_archivo(str(documento), str(corrupta), CONTRASENA)
    corrupta.write_text(pem[: len(pem) // 2])
    with pytest.raises(ErrorClave):
        firmar_archivo(str(documento), str(corrupta), CONTRASENA)


def test_clave_ec_como_privada_no_se_acepta(documento, tmp_path):
    clave_ec = ec.generate_private_key(ec.SECP256R1())
    ruta = tmp_path / "ec.pem"
    ruta.write_bytes(
        clave_ec.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(CONTRASENA.encode("utf-8")),
        )
    )
    with pytest.raises(ErrorClave, match="RSA"):
        firmar_archivo(str(documento), str(ruta), CONTRASENA)


def test_la_clave_publica_no_sirve_para_firmar(par, documento):
    with pytest.raises(ErrorClave):
        firmar_archivo(str(documento), str(par.publica), CONTRASENA)


# --- El archivo de la clave privada no filtra secretos ---

def test_la_clave_privada_guardada_no_contiene_la_contrasena_ni_la_clave_en_claro(par):
    contenido = par.privada.read_bytes()
    assert CONTRASENA.encode("utf-8") not in contenido
    assert b"-----BEGIN PRIVATE KEY-----" not in contenido  # sin cifrar
    assert b"-----BEGIN RSA PRIVATE KEY-----" not in contenido


def test_dos_pares_generados_son_distintos(par, otro_par):
    assert par.publica.read_bytes() != otro_par.publica.read_bytes()
    assert par.privada.read_bytes() != otro_par.privada.read_bytes()


# --- bits: tipos y valores ---

@pytest.mark.parametrize("bits", [2048.0, "2048", None, True, [2048]])
def test_bits_que_no_son_enteros(tmp_path, bits):
    with pytest.raises(TypeError, match="entero"):
        generar_par_claves(str(tmp_path / "p.pem"), str(tmp_path / "p.pub.pem"), CONTRASENA, bits=bits)
    assert list(tmp_path.iterdir()) == []


def test_bits_negativos(tmp_path):
    with pytest.raises(ValueError, match="2048"):
        generar_par_claves(str(tmp_path / "p.pem"), str(tmp_path / "p.pub.pem"), CONTRASENA, bits=-1)


@pytest.mark.lento
def test_generar_con_los_bits_por_defecto_da_una_clave_de_3072(tmp_path):
    privada, publica = tmp_path / "p.pem", tmp_path / "p.pub.pem"
    generar_par_claves(str(privada), str(publica), CONTRASENA)
    assert serialization.load_pem_public_key(publica.read_bytes()).key_size == 3072
    documento = tmp_path / "doc.txt"
    documento.write_bytes(DOCUMENTO)
    firma = firmar_archivo(str(documento), str(privada), CONTRASENA)
    assert len(firma) == 384
    assert verificar_firma(str(documento), firma, str(publica)) is True


# --- Guardar y leer firmas ---

@pytest.mark.parametrize("firma", ["texto", bytearray(b"abc"), None, 123])
def test_guardar_firma_exige_bytes(tmp_path, firma):
    with pytest.raises(TypeError, match="bytes"):
        guardar_firma(firma, str(tmp_path / "doc.sig"))
    assert not (tmp_path / "doc.sig").exists()


def test_guardar_firma_reemplaza_la_anterior(tmp_path):
    ruta = tmp_path / "doc.sig"
    guardar_firma(b"primera", str(ruta))
    guardar_firma(b"segunda", str(ruta))
    assert leer_firma(str(ruta)) == b"segunda"


def test_leer_firma_de_una_carpeta(tmp_path):
    with pytest.raises(FileNotFoundError, match="firma"):
        leer_firma(str(tmp_path))


def test_la_firma_guardada_conserva_todos_los_bytes(tmp_path):
    todos = bytes(range(256))  # incluye \x00, \r, \n y \x1a, que en modo texto se alteran
    ruta = tmp_path / "doc.sig"
    guardar_firma(todos, str(ruta))
    assert ruta.read_bytes() == todos
    assert leer_firma(str(ruta)) == todos


# --- Rutas relativas ---

def test_rutas_relativas(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "claves").mkdir()
    (tmp_path / "doc.txt").write_bytes(DOCUMENTO)
    generar_par_claves("claves/privada.pem", "claves/publica.pem", CONTRASENA, bits=2048)
    firma = firmar_archivo("doc.txt", "claves/privada.pem", CONTRASENA)
    guardar_firma(firma, "doc.sig")
    assert verificar_firma("doc.txt", leer_firma("doc.sig"), "claves/publica.pem") is True


# --- Fallos a mitad de la escritura (simulados) ---

def test_si_falla_la_escritura_no_queda_una_clave_a_medias(tmp_path, monkeypatch):
    class ArchivoQueFalla:
        def __init__(self, archivo):
            self._archivo = archivo

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self._archivo.close()
            return False

        def write(self, datos):
            raise OSError("disco lleno (simulado)")

    class OsConFallo:
        """Delega todo en `os`, salvo fdopen, que devuelve un archivo cuya escritura falla."""

        def __getattr__(self, nombre):
            return getattr(os, nombre)

        @staticmethod
        def fdopen(descriptor, modo):
            return ArchivoQueFalla(os.fdopen(descriptor, modo))

    monkeypatch.setattr(asimetrico, "os", OsConFallo())
    with pytest.raises(OSError, match="disco lleno"):
        generar_par_claves(str(tmp_path / "p.pem"), str(tmp_path / "p.pub.pem"), CONTRASENA, bits=2048)
    assert list(tmp_path.iterdir()) == []


def test_carrera_si_otro_proceso_crea_la_clave_despues_del_chequeo(tmp_path, monkeypatch):
    """Entre el chequeo de existencia y la escritura aparece el archivo: O_EXCL lo protege."""
    privada, publica = tmp_path / "p.pem", tmp_path / "p.pub.pem"
    generar_real = rsa.generate_private_key

    def generar_y_que_aparezca_la_privada(*args, **kwargs):
        privada.write_bytes(b"clave de otro proceso")
        return generar_real(*args, **kwargs)

    monkeypatch.setattr(asimetrico.rsa, "generate_private_key", generar_y_que_aparezca_la_privada)
    with pytest.raises(FileExistsError, match="sobrescribir"):
        generar_par_claves(str(privada), str(publica), CONTRASENA, bits=2048)
    assert privada.read_bytes() == b"clave de otro proceso"
    assert not publica.exists()
