import subprocess
import sys
from pathlib import Path

import pytest
from PIL import Image

import demo_ecb
from demo_ecb import (
    ALTO,
    ANCHO,
    TAM_BLOQUE,
    bytes_a_imagen,
    cifrar_ecb_inseguro,
    cifrar_gcm,
    crear_comparacion,
    crear_imagen_original,
    generar_demo,
    main,
)

ARCHIVOS = ["original.png", "ecb.png", "gcm.png", "comparacion.png"]
CLAVE = bytes(range(32))  # clave fija: estos tests no dependen del azar


def _bloques(datos: bytes) -> list[bytes]:
    return [datos[i : i + TAM_BLOQUE] for i in range(0, len(datos) - TAM_BLOQUE + 1, TAM_BLOQUE)]


def _tamano(ruta) -> tuple[int, int]:
    with Image.open(ruta) as imagen:
        return imagen.size


# --- Bloques iguales ---

def test_ecb_repite_bloques_iguales_y_gcm_no():
    bloque = bytes(range(TAM_BLOQUE))
    datos = bloque * 2
    ecb = cifrar_ecb_inseguro(datos, CLAVE)
    gcm = cifrar_gcm(datos, CLAVE)
    assert ecb[:TAM_BLOQUE] == ecb[TAM_BLOQUE : 2 * TAM_BLOQUE]
    assert gcm[:TAM_BLOQUE] != gcm[TAM_BLOQUE : 2 * TAM_BLOQUE]


def test_ecb_coincide_con_el_vector_de_prueba_de_fips_197():
    """AES-256, FIPS-197 apéndice C.3: confirma que usamos AES-ECB de verdad."""
    clave = bytes(range(32))
    texto = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert cifrar_ecb_inseguro(texto, clave).hex() == "8ea2b7ca516745bfeafc49904b496089"


def test_gcm_no_deja_bloques_repetidos_pero_ecb_si_sobre_la_imagen():
    pixeles = crear_imagen_original().tobytes()
    distintos_ecb = len(set(_bloques(cifrar_ecb_inseguro(pixeles, CLAVE))))
    distintos_gcm = len(set(_bloques(cifrar_gcm(pixeles, CLAVE))))
    total = len(pixeles) // TAM_BLOQUE
    assert distintos_ecb < total * 0.05  # casi todos los bloques se repiten
    assert distintos_gcm == total  # ninguno se repite


def test_los_tamanos_de_salida_alcanzan_para_una_imagen():
    pixeles = crear_imagen_original().tobytes()
    assert len(cifrar_ecb_inseguro(pixeles, CLAVE)) >= len(pixeles)
    assert len(cifrar_gcm(pixeles, CLAVE)) == len(pixeles)  # sin la etiqueta


# --- Casos borde de las funciones de cifrado ---

@pytest.mark.parametrize("largo", [0, 1, 15, 16, 17, 31, 100])
def test_ecb_rellena_hasta_un_multiplo_del_bloque(largo):
    salida = cifrar_ecb_inseguro(bytes(largo), CLAVE)
    assert len(salida) % TAM_BLOQUE == 0
    assert len(salida) == -(-largo // TAM_BLOQUE) * TAM_BLOQUE  # redondeo hacia arriba


@pytest.mark.parametrize("largo", [0, 1, 15, 16, 17, 100])
def test_gcm_devuelve_tantos_bytes_como_el_texto_plano(largo):
    assert len(cifrar_gcm(bytes(largo), CLAVE)) == largo


@pytest.mark.parametrize("clave", [b"", b"corta", bytes(15), bytes(17), bytes(33)])
def test_las_claves_de_largo_invalido_se_rechazan(clave):
    with pytest.raises(ValueError):
        cifrar_ecb_inseguro(bytes(32), clave)
    with pytest.raises(ValueError):
        cifrar_gcm(bytes(32), clave)


def test_gcm_con_el_mismo_texto_y_clave_da_salidas_distintas_por_el_nonce():
    datos = bytes(64)
    assert cifrar_gcm(datos, CLAVE) != cifrar_gcm(datos, CLAVE)


def test_ecb_es_determinista_con_la_misma_clave():
    datos = bytes(range(64))
    assert cifrar_ecb_inseguro(datos, CLAVE) == cifrar_ecb_inseguro(datos, CLAVE)


# --- bytes_a_imagen ---

def test_bytes_a_imagen_corta_el_sobrante():
    datos = bytes(range(256)) * 10  # 2560 bytes; la imagen de 10x10 usa 300
    imagen = bytes_a_imagen(datos, (10, 10))
    assert imagen.size == (10, 10)
    assert imagen.mode == "RGB"
    assert imagen.tobytes() == datos[:300]


def test_bytes_a_imagen_con_datos_insuficientes_da_error():
    with pytest.raises(ValueError):
        bytes_a_imagen(bytes(10), (10, 10))


# --- La imagen original ---

def test_la_imagen_original_es_siempre_la_misma_y_tiene_el_tamano_esperado():
    uno, dos = crear_imagen_original(), crear_imagen_original()
    assert uno.size == (ANCHO, ALTO)
    assert uno.mode == "RGB"
    assert uno.tobytes() == dos.tobytes()


def test_la_imagen_original_tiene_zonas_planas_y_bordes():
    imagen = crear_imagen_original()
    colores = {color for _, color in imagen.getcolors(maxcolors=10_000)}
    assert 4 <= len(colores) <= 10  # pocos colores planos
    assert imagen.getpixel((0, 0)) == imagen.getpixel((5, 5))  # fondo uniforme


# --- La comparación ---

def test_la_comparacion_tiene_el_ancho_y_alto_esperados():
    paneles = [(titulo, Image.new("RGB", (40, 30), color)) for titulo, color in
               (("A", "red"), ("B", "green"), ("C", "blue"))]
    comparacion = crear_comparacion(paneles)
    margen, alto_titulo = 16, 36
    assert comparacion.size == (3 * (40 + margen) + margen, 30 + alto_titulo + 2 * margen)
    # Cada panel queda pegado donde corresponde, debajo de su título.
    for i, color in enumerate(((255, 0, 0), (0, 128, 0), (0, 0, 255))):
        x = margen + i * (40 + margen) + 5
        assert comparacion.getpixel((x, margen + alto_titulo + 5)) == color


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


def test_crea_las_carpetas_intermedias_que_no_existen(tmp_path):
    destino = tmp_path / "a" / "b" / "c"
    generar_demo(destino)
    assert sorted(p.name for p in destino.iterdir()) == sorted(ARCHIVOS)


def test_volver_a_generar_en_la_misma_carpeta_reemplaza_los_archivos(tmp_path):
    generar_demo(tmp_path)
    antes = (tmp_path / "ecb.png").read_bytes()
    generar_demo(tmp_path)
    assert (tmp_path / "ecb.png").read_bytes() != antes  # clave nueva
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(ARCHIVOS)


def test_acepta_la_carpeta_como_texto_o_como_path(tmp_path):
    assert generar_demo(str(tmp_path / "texto"))["ecb"].exists()
    assert generar_demo(tmp_path / "path")["ecb"].exists()


def test_la_carpeta_de_salida_por_defecto_es_docs_ecb_vs_gcm_del_repo():
    raiz = Path(demo_ecb.__file__).resolve().parent.parent
    assert demo_ecb.CARPETA_POR_DEFECTO == raiz / "docs" / "ecb_vs_gcm"


# --- Línea de comandos ---

def test_main_con_la_opcion_salida(tmp_path, monkeypatch, capsys):
    destino = tmp_path / "cli"
    monkeypatch.setattr(sys, "argv", ["demo_ecb.py", "--salida", str(destino)])
    main()
    impreso = capsys.readouterr().out
    assert sorted(p.name for p in destino.iterdir()) == sorted(ARCHIVOS)
    for nombre in ARCHIVOS:
        assert f"Guardado: {destino / nombre}" in impreso


def test_main_no_imprime_ninguna_clave(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["demo_ecb.py", "--salida", str(tmp_path)])
    main()
    salida = capsys.readouterr()
    assert salida.err == ""
    assert all(linea.startswith("Guardado: ") for linea in salida.out.splitlines())


def test_el_script_se_ejecuta_desde_otra_carpeta(tmp_path):
    script = Path(demo_ecb.__file__)
    destino = tmp_path / "salida"
    resultado = subprocess.run(
        [sys.executable, str(script), "--salida", str(destino)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert resultado.returncode == 0, resultado.stderr
    assert sorted(p.name for p in destino.iterdir()) == sorted(ARCHIVOS)


# --- Advertencia visible ---

def test_la_funcion_de_ecb_advierte_que_es_insegura():
    assert "inseguro" in cifrar_ecb_inseguro.__name__
    assert "INSEGURO" in cifrar_ecb_inseguro.__doc__
    assert "INSEGURO" in demo_ecb.__doc__


def test_el_kit_no_ofrece_ecb():
    """ECB solo existe en la demo, no en el paquete kit_cripto."""
    import kit_cripto

    carpeta = Path(kit_cripto.__file__).parent
    for modulo in carpeta.glob("*.py"):
        codigo = modulo.read_text(encoding="utf-8")
        assert "modes.ECB" not in codigo, f"{modulo.name} usa ECB"
