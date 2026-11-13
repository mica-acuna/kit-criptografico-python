import os

from PIL import Image

from demo_ecb import (
    TAM_BLOQUE,
    cifrar_ecb_inseguro,
    cifrar_gcm,
    crear_imagen_original,
    generar_demo,
)

ARCHIVOS = ["original.png", "ecb.png", "gcm.png", "comparacion.png"]


def _bloques(datos: bytes) -> list[bytes]:
    return [datos[i : i + TAM_BLOQUE] for i in range(0, len(datos) - TAM_BLOQUE + 1, TAM_BLOQUE)]


def _tamano(ruta) -> tuple[int, int]:
    with Image.open(ruta) as imagen:
        return imagen.size


# --- Bloques iguales ---

def test_ecb_repite_bloques_iguales_y_gcm_no():
    clave = os.urandom(32)
    bloque = bytes(range(TAM_BLOQUE))
    datos = bloque * 2
    ecb = cifrar_ecb_inseguro(datos, clave)
    gcm = cifrar_gcm(datos, clave)
    assert ecb[:TAM_BLOQUE] == ecb[TAM_BLOQUE : 2 * TAM_BLOQUE]
    assert gcm[:TAM_BLOQUE] != gcm[TAM_BLOQUE : 2 * TAM_BLOQUE]


def test_ecb_coincide_con_el_vector_de_prueba_de_fips_197():
    """AES-256, FIPS-197 apéndice C.3: confirma que usamos AES-ECB de verdad."""
    clave = bytes(range(32))
    texto = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert cifrar_ecb_inseguro(texto, clave).hex() == "8ea2b7ca516745bfeafc49904b496089"


def test_gcm_no_deja_bloques_repetidos_pero_ecb_si_sobre_la_imagen():
    clave = os.urandom(32)
    pixeles = crear_imagen_original().tobytes()
    distintos_ecb = len(set(_bloques(cifrar_ecb_inseguro(pixeles, clave))))
    distintos_gcm = len(set(_bloques(cifrar_gcm(pixeles, clave))))
    total = len(pixeles) // TAM_BLOQUE
    assert distintos_ecb < total * 0.05  # casi todos los bloques se repiten
    assert distintos_gcm == total  # ninguno se repite


def test_los_tamanos_de_salida_alcanzan_para_una_imagen():
    pixeles = crear_imagen_original().tobytes()
    clave = os.urandom(32)
    assert len(cifrar_ecb_inseguro(pixeles, clave)) >= len(pixeles)
    assert len(cifrar_gcm(pixeles, clave)) == len(pixeles)  # sin la etiqueta


# --- El script genera los archivos ---

def test_genera_los_archivos_esperados(tmp_path):
    rutas = generar_demo(tmp_path / "salida")
    assert sorted(p.name for p in (tmp_path / "salida").iterdir()) == sorted(ARCHIVOS)
    assert set(rutas) == {"original", "ecb", "gcm", "comparacion"}


def test_las_imagenes_cifradas_tienen_el_tamano_de_la_original(tmp_path):
    rutas = generar_demo(tmp_path)
    tamano = _tamano(rutas["original"])
    assert tamano == crear_imagen_original().size
    assert _tamano(rutas["ecb"]) == tamano
    assert _tamano(rutas["gcm"]) == tamano
    ancho_comparacion, alto_comparacion = _tamano(rutas["comparacion"])
    assert ancho_comparacion > 3 * tamano[0]
    assert alto_comparacion > tamano[1]


def test_dos_ejecuciones_dan_imagenes_cifradas_distintas(tmp_path):
    uno = generar_demo(tmp_path / "uno")
    dos = generar_demo(tmp_path / "dos")
    assert uno["original"].read_bytes() == dos["original"].read_bytes()
    assert uno["ecb"].read_bytes() != dos["ecb"].read_bytes()
    assert uno["gcm"].read_bytes() != dos["gcm"].read_bytes()


# --- Advertencia visible ---

def test_la_funcion_de_ecb_advierte_que_es_insegura():
    assert "inseguro" in cifrar_ecb_inseguro.__name__
    assert "INSEGURO" in cifrar_ecb_inseguro.__doc__
    import demo_ecb

    assert "INSEGURO" in demo_ecb.__doc__
