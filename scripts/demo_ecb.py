"""Demostración visual: por qué el modo ECB es INSEGURO.

ADVERTENCIA GRANDE: ECB NUNCA se usa en sistemas reales. Este script existe solo
para mostrar el problema y vive fuera del paquete `kit_cripto` a propósito: el kit
no ofrece ECB. No importes `cifrar_ecb_inseguro` desde otro código.

Qué hace:
1. Dibuja una imagen propia (formas geométricas de colores planos).
2. Toma los bytes crudos de los píxeles (RGB) y los cifra con AES-256 en modo ECB
   y con AES-256-GCM. La clave de cada uno es aleatoria y nueva en cada ejecución:
   no se guarda ni se imprime.
3. Reinterpreta los bytes cifrados como píxeles (descartando la etiqueta de GCM y
   el sobrante) y guarda las imágenes y una comparación lado a lado.

Uso (desde la raíz del repositorio, con el entorno activado):

    python scripts/demo_ecb.py
"""

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, ImageDraw, ImageFont

ANCHO, ALTO = 320, 240
TAM_BLOQUE = 16  # AES siempre trabaja con bloques de 16 bytes (128 bits)
TAM_CLAVE = 32  # AES-256
TAM_NONCE = 12
TAM_ETIQUETA = 16
CARPETA_POR_DEFECTO = Path(__file__).resolve().parent.parent / "docs" / "ecb_vs_gcm"


def crear_imagen_original() -> Image.Image:
    """Dibujo propio: formas de color plano con bordes marcados."""
    imagen = Image.new("RGB", (ANCHO, ALTO), (210, 230, 245))
    dibujo = ImageDraw.Draw(imagen)
    dibujo.rectangle([20, 20, 140, 120], fill=(200, 40, 40))
    dibujo.ellipse([170, 20, 300, 150], fill=(30, 70, 160))
    dibujo.polygon([(40, 220), (110, 130), (180, 220)], fill=(240, 200, 40))
    dibujo.rectangle([200, 170, 300, 220], fill=(40, 150, 80))
    dibujo.line([(150, 10), (150, 230)], fill=(20, 20, 20), width=6)
    return imagen


def cifrar_ecb_inseguro(datos: bytes, clave: bytes) -> bytes:
    """INSEGURO: cifra con AES-ECB. Solo para esta demo; nunca lo uses para proteger datos.

    ECB cifra cada bloque de 16 bytes por separado y sin nonce: bloques iguales
    de texto plano dan bloques iguales de texto cifrado. Si el largo no es múltiplo
    de 16, se rellena con ceros (el relleno se descarta al armar la imagen).
    """
    faltante = -len(datos) % TAM_BLOQUE
    cifrador = Cipher(algorithms.AES(clave), modes.ECB()).encryptor()
    return cifrador.update(datos + b"\x00" * faltante) + cifrador.finalize()


def cifrar_gcm(datos: bytes, clave: bytes) -> bytes:
    """Cifra con AES-GCM y un nonce aleatorio; devuelve solo el texto cifrado.

    Se descartan el nonce y la etiqueta de autenticación porque en la demo solo
    importa cómo se ve el texto cifrado.
    """
    nonce = os.urandom(TAM_NONCE)  # nuevo en cada cifrado
    return AESGCM(clave).encrypt(nonce, datos, None)[:-TAM_ETIQUETA]


def bytes_a_imagen(datos: bytes, tamano: tuple[int, int]) -> Image.Image:
    """Reinterpreta bytes como píxeles RGB, cortando el sobrante."""
    ancho, alto = tamano
    return Image.frombytes("RGB", tamano, datos[: ancho * alto * 3])


def _fuente() -> ImageFont.ImageFont:
    return ImageFont.load_default(size=18)


def crear_comparacion(imagenes: list[tuple[str, Image.Image]]) -> Image.Image:
    """Une las imágenes lado a lado, cada una con su título arriba."""
    margen, alto_titulo = 16, 36
    ancho, alto = imagenes[0][1].size
    lienzo = Image.new(
        "RGB",
        (len(imagenes) * (ancho + margen) + margen, alto + alto_titulo + 2 * margen),
        "white",
    )
    dibujo = ImageDraw.Draw(lienzo)
    fuente = _fuente()
    for i, (titulo, imagen) in enumerate(imagenes):
        x = margen + i * (ancho + margen)
        dibujo.text((x, margen), titulo, fill="black", font=fuente)
        lienzo.paste(imagen, (x, margen + alto_titulo))
    return lienzo


def generar_demo(carpeta_salida: str | Path) -> dict[str, Path]:
    """Genera las cuatro imágenes de la demo y devuelve sus rutas."""
    carpeta = Path(carpeta_salida)
    carpeta.mkdir(parents=True, exist_ok=True)

    original = crear_imagen_original()
    pixeles = original.tobytes()  # bytes crudos RGB
    # Dos claves aleatorias nuevas en cada ejecución; no se guardan ni se imprimen.
    ecb = bytes_a_imagen(cifrar_ecb_inseguro(pixeles, os.urandom(TAM_CLAVE)), original.size)
    gcm = bytes_a_imagen(cifrar_gcm(pixeles, os.urandom(TAM_CLAVE)), original.size)
    comparacion = crear_comparacion(
        [("Original", original), ("AES-256-ECB (INSEGURO)", ecb), ("AES-256-GCM", gcm)]
    )

    rutas = {
        "original": carpeta / "original.png",
        "ecb": carpeta / "ecb.png",
        "gcm": carpeta / "gcm.png",
        "comparacion": carpeta / "comparacion.png",
    }
    for nombre, imagen in (
        ("original", original),
        ("ecb", ecb),
        ("gcm", gcm),
        ("comparacion", comparacion),
    ):
        imagen.save(rutas[nombre])
    return rutas


def main() -> None:
    parser = argparse.ArgumentParser(description="Demo visual: ECB vs GCM (ECB es INSEGURO).")
    parser.add_argument(
        "--salida", default=str(CARPETA_POR_DEFECTO), help="carpeta donde guardar las imágenes"
    )
    argumentos = parser.parse_args()
    for ruta in generar_demo(argumentos.salida).values():
        print(f"Guardado: {ruta}")


if __name__ == "__main__":
    main()
