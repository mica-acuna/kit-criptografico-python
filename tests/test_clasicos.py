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


# --- Casos borde: texto vacío, solo signos, desplazamientos 0 y 26 ---

@pytest.mark.parametrize("texto", ["", "123 ... !!! ¿¡?!", "ñáéíóú ÑÁÉÍÓÚ", "\n\t "])
def test_texto_sin_letras_ascii_queda_intacto(texto):
    assert cesar_cifrar(texto, 5) == texto
    assert cesar_descifrar(texto, 5) == texto
    assert vigenere_cifrar(texto, "CLAVE") == texto
    assert vigenere_descifrar(texto, "CLAVE") == texto


@pytest.mark.parametrize("desplazamiento", [0, 26, -26, 52])
def test_cesar_con_desplazamiento_equivalente_a_cero_no_cambia_el_texto(desplazamiento):
    assert cesar_cifrar(TEXTO_CESAR, desplazamiento) == TEXTO_CESAR


@pytest.mark.parametrize("desplazamiento", [True, 3.5, "3", None])
def test_cesar_rechaza_desplazamientos_que_no_son_enteros(desplazamiento):
    with pytest.raises(TypeError):
        cesar_cifrar("HOLA", desplazamiento)
    with pytest.raises(TypeError):
        cesar_descifrar("HOLA", desplazamiento)


def test_cesar_conserva_mayusculas_y_minusculas_en_los_extremos_del_alfabeto():
    assert cesar_cifrar("xyzXYZ abcABC", 3) == "abcABC defDEF"


# --- Vigenère: claves de una letra, largas y mezcladas ---

def test_vigenere_con_clave_de_una_letra_equivale_a_cesar():
    assert vigenere_cifrar(TEXTO_CESAR, "D") == cesar_cifrar(TEXTO_CESAR, 3)
    assert vigenere_descifrar(vigenere_cifrar(TEXTO_CESAR, "D"), "D") == TEXTO_CESAR


def test_vigenere_con_clave_a_no_cambia_el_texto():
    assert vigenere_cifrar(TEXTO_CESAR, "A") == TEXTO_CESAR
    assert vigenere_cifrar(TEXTO_CESAR, "aaaa") == TEXTO_CESAR


def test_vigenere_con_clave_mas_larga_que_el_texto():
    clave = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 2
    cifrado = vigenere_cifrar("Hola", clave)
    assert cifrado == "Hpnd"  # solo usa las primeras 4 letras de la clave: A, B, C, D
    assert vigenere_descifrar(cifrado, clave) == "Hola"


@pytest.mark.parametrize("clave", ["limon", "LIMON", "LiMoN"])
def test_vigenere_la_clave_es_indiferente_a_mayusculas(clave):
    assert vigenere_cifrar("ATAQUEALAMANECER", clave) == "LBMEHPIXOZLVQQRC"


@pytest.mark.parametrize("texto", ["a", "Zz", "Hola, mundo!", TEXTO_CESAR])
@pytest.mark.parametrize("clave", ["A", "Z", "LIMON", "ESCUDO" * 20])
def test_vigenere_ida_y_vuelta_con_varios_largos(texto, clave):
    assert vigenere_descifrar(vigenere_cifrar(texto, clave), clave) == texto


# --- Ataques con textos muy cortos o raros: no deben romperse ---

def test_cesar_fuerza_bruta_con_texto_vacio_devuelve_26_candidatos_vacios():
    assert cesar_fuerza_bruta("") == [(d, "") for d in range(26)]


@pytest.mark.parametrize("texto", ["a", "ab", "Ola", "¡Hola!"])
def test_cesar_romper_con_textos_cortos_devuelve_un_candidato_valido(texto):
    desplazamiento, descifrado = cesar_romper(cesar_cifrar(texto, 7))
    assert 0 <= desplazamiento < 26
    assert len(descifrado) == len(texto)  # no adivina necesariamente, pero no se rompe


@pytest.mark.parametrize("texto", ["a", "ab", "hola", "Hola, mundo!", "x" * 3])
def test_vigenere_romper_con_textos_cortos_devuelve_clave_y_texto(texto):
    clave, descifrado = vigenere_romper(vigenere_cifrar(texto, "CLAVE"))
    cantidad_de_letras = sum(c.isalpha() for c in texto)
    assert clave.isalpha() and clave.isascii() and clave.isupper()
    assert 1 <= len(clave) <= cantidad_de_letras  # nunca más larga que las letras disponibles
    assert len(descifrado) == len(texto)  # no adivina necesariamente, pero no se rompe


@pytest.mark.parametrize("largo_max", [1, 2, 3])
def test_vigenere_romper_con_largo_max_menor_que_la_clave_real_no_se_rompe(largo_max):
    cifrado = vigenere_cifrar(TEXTO_VIGENERE, "LUNA")
    clave, descifrado = vigenere_romper(cifrado, largo_max_clave=largo_max)
    assert 1 <= len(clave) <= largo_max
    assert len(descifrado) == len(TEXTO_VIGENERE)


@pytest.mark.parametrize("largo_max", [4, 12, 50])
def test_vigenere_romper_con_largo_max_razonable_recupera_la_clave(largo_max):
    cifrado = vigenere_cifrar(TEXTO_VIGENERE, "LUNA")
    assert vigenere_romper(cifrado, largo_max_clave=largo_max) == ("LUNA", TEXTO_VIGENERE)


@pytest.mark.parametrize("largo_max", [200, 1000, 10**6])
def test_vigenere_romper_con_largo_max_enorme_sigue_recuperando_la_clave(largo_max):
    """Un límite más generoso no debe empeorar el resultado (antes elegía un largo equivocado)."""
    cifrado = vigenere_cifrar(TEXTO_VIGENERE, "LUNA")
    assert vigenere_romper(cifrado, largo_max_clave=largo_max) == ("LUNA", TEXTO_VIGENERE)


@pytest.mark.parametrize("clave", ["ABC", "LUNA", "CIFRA", "ESCUDO"])
@pytest.mark.parametrize("largo_max", [12, 50, 1000])
def test_vigenere_romper_da_el_mismo_resultado_sin_importar_el_limite(clave, largo_max):
    cifrado = vigenere_cifrar(TEXTO_VIGENERE, clave)
    assert vigenere_romper(cifrado, largo_max_clave=largo_max) == (clave, TEXTO_VIGENERE)


@pytest.mark.parametrize(
    "letras, tope",
    [(14, 1), (15, 1), (29, 1), (30, 2), (100, 6), (300, 12)],
)
def test_vigenere_romper_no_prueba_claves_con_menos_de_15_letras_por_columna(letras, tope):
    texto = ("ESTE ES UN TEXTO DE PRUEBA PARA ROMPER " * 40)
    texto = "".join(c for c in texto if c.isalpha())[:letras]
    clave, descifrado = vigenere_romper(vigenere_cifrar(texto, "LUNA"), largo_max_clave=1000)
    assert 1 <= len(clave) <= tope
    assert len(descifrado) == letras


def test_vigenere_romper_con_texto_de_solo_signos_y_acentos_da_error():
    with pytest.raises(ValueError, match="letras"):
        vigenere_romper("¡¿ñáé?! 123")


def test_vigenere_romper_con_un_texto_largo_de_una_sola_letra_no_se_rompe():
    clave, descifrado = vigenere_romper("A" * 500)
    assert clave.isalpha() and clave.isupper()  # solo importa que devuelva algo válido
    assert len(descifrado) == 500


# --- Clave que no es texto ---

@pytest.mark.parametrize("clave", [5, 3.5, b"clave", ["a"], None, True])
def test_vigenere_clave_que_no_es_texto_da_un_error_claro(clave):
    with pytest.raises(TypeError, match="texto"):
        vigenere_cifrar("hola", clave)
    with pytest.raises(TypeError, match="texto"):
        vigenere_descifrar("hola", clave)


def test_vigenere_clave_vacia_sigue_dando_value_error_y_no_type_error():
    with pytest.raises(ValueError, match="vacía"):
        vigenere_cifrar("hola", "")
