import pytest

from kit_cripto.clasicos import (
    cesar_cifrar,
    cesar_descifrar,
    cesar_fuerza_bruta,
    cesar_romper,
    vigenere_cifrar,
    vigenere_descifrar,
    vigenere_romper,
)

TEXTO_CESAR = (
    "El pan de la mañana estaba caliente y olía a canela. "
    "Mi abuela siempre decía que la paciencia es la mejor receta. "
    "Después del desayuno salimos a caminar por el parque, "
    "donde los chicos jugaban a la pelota."
)

TEXTO_VIGENERE = (
    "La criptografía es la ciencia que estudia cómo proteger la información "
    "para que solo las personas autorizadas puedan leerla. Desde la antigüedad, "
    "los pueblos buscaron maneras de ocultar sus mensajes: los espartanos "
    "enrollaban tiras de cuero alrededor de un bastón y los romanos desplazaban "
    "las letras del alfabeto para que un mensajero no pudiera revelar el "
    "contenido de una carta si era capturado. Con el tiempo, los cifrados se "
    "volvieron más complejos, pero también aparecieron los analistas, que "
    "aprendieron a romperlos observando cuántas veces se repite cada letra en "
    "un texto. En el español, por ejemplo, la letra e y la letra a son las más "
    "frecuentes, y esa regularidad delata al mensaje aunque esté disfrazado. "
    "Hoy los algoritmos modernos protegen las conversaciones, las compras en "
    "línea y los documentos de millones de personas todos los días, y su "
    "seguridad no depende de que el método sea secreto, sino de que la clave "
    "lo sea."
)


# --- César ---

def test_cesar_desplazamiento_3():
    assert cesar_cifrar("HOLA", 3) == "KROD"
    assert cesar_descifrar("KROD", 3) == "HOLA"


def test_cesar_ida_y_vuelta_conserva_el_formato():
    original = "Hola, Mundo! Año 2026: ¿qué tal, ñandú?"
    cifrado = cesar_cifrar(original, 7)
    assert cifrado != original
    assert cifrado.startswith("Ovsh, Tbukv! ")
    assert cesar_descifrar(cifrado, 7) == original


def test_cesar_deja_intactos_numeros_signos_y_acentos():
    assert cesar_cifrar("¡ñandú 123, ok!", 1) == "¡ñboeú 123, pl!"


def test_cesar_desplazamientos_negativos_y_mayores_a_26():
    assert cesar_cifrar("KROD", -3) == "HOLA"
    assert cesar_cifrar("HOLA", 29) == "KROD"
    assert cesar_cifrar("HOLA", 26) == "HOLA"
    assert cesar_cifrar("Hola", -23) == "Krod"
    for d in range(-60, 61):
        assert cesar_descifrar(cesar_cifrar(TEXTO_CESAR, d), d) == TEXTO_CESAR


def test_cesar_desplazamiento_no_entero():
    with pytest.raises(TypeError):
        cesar_cifrar("HOLA", "3")


# --- Vigenère ---

@pytest.mark.parametrize(
    "texto, clave, esperado",
    [
        # Calculado a mano letra por letra (clave LIMON repetida).
        ("ATAQUEALAMANECER", "LIMON", "LBMEHPIXOZLVQQRC"),
        # Ejemplo clásico de los libros de texto.
        ("ATTACKATDAWN", "LEMON", "LXFOPVEFRNHR"),
    ],
)
def test_vigenere_casos_conocidos(texto, clave, esperado):
    assert vigenere_cifrar(texto, clave) == esperado
    assert vigenere_descifrar(esperado, clave) == texto


def test_vigenere_ida_y_vuelta_con_texto_mixto():
    original = "Ataque al amanecer, ¡Año Nuevo 2026! Sí: ñandú."
    cifrado = vigenere_cifrar(original, "Limon")
    assert cifrado != original
    assert vigenere_descifrar(cifrado, "limon") == original


def test_vigenere_la_clave_no_avanza_con_espacios_ni_signos():
    assert vigenere_cifrar("A T, A", "BC") == "B V, B"


def test_vigenere_clave_vacia():
    with pytest.raises(ValueError, match="vacía"):
        vigenere_cifrar("hola", "")


@pytest.mark.parametrize("clave", ["clave1", "12345", "dos palabras", "ñandú", "a-b"])
def test_vigenere_clave_invalida(clave):
    with pytest.raises(ValueError, match="clave"):
        vigenere_cifrar("hola", clave)
    with pytest.raises(ValueError, match="clave"):
        vigenere_descifrar("hola", clave)


# --- Fuerza bruta contra César ---

def test_cesar_fuerza_bruta_devuelve_26_candidatos():
    cifrado = cesar_cifrar(TEXTO_CESAR, 11)
    candidatos = cesar_fuerza_bruta(cifrado)
    assert [d for d, _ in candidatos] == list(range(26))
    assert (11, TEXTO_CESAR) in candidatos


@pytest.mark.parametrize("desplazamiento", [1, 3, 7, 13, 20, 25])
def test_cesar_romper_elige_el_original(desplazamiento):
    cifrado = cesar_cifrar(TEXTO_CESAR, desplazamiento)
    assert cesar_romper(cifrado) == (desplazamiento, TEXTO_CESAR)


def test_cesar_romper_sin_letras():
    with pytest.raises(ValueError):
        cesar_romper("123 ... !!!")


# --- Análisis de frecuencias contra Vigenère ---

@pytest.mark.parametrize("clave", ["LUNA", "CIFRA", "ESCUDO"])
def test_vigenere_romper_recupera_clave_y_texto(clave):
    assert len([c for c in TEXTO_VIGENERE if c.isalpha()]) >= 400
    cifrado = vigenere_cifrar(TEXTO_VIGENERE, clave)
    assert vigenere_romper(cifrado) == (clave, TEXTO_VIGENERE)


def test_vigenere_romper_clave_en_minusculas_devuelve_mayusculas():
    cifrado = vigenere_cifrar(TEXTO_VIGENERE, "cifra")
    clave, texto = vigenere_romper(cifrado)
    assert clave == "CIFRA"
    assert texto == TEXTO_VIGENERE


def test_vigenere_romper_entradas_invalidas():
    with pytest.raises(ValueError):
        vigenere_romper("123 !!!")
    with pytest.raises(ValueError):
        vigenere_romper("hola", largo_max_clave=0)
