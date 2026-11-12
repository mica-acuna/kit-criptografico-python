# Kit criptográfico en Python

Kit criptográfico con fines educativos. No usar en producción.

## Organización de carpetas del proyecto

```
kit-criptografico-python/
├── .gitignore
├── README.md
├── pytest.ini
├── requirements.txt
├── src/
│   └── kit_cripto/
│       ├── __init__.py
│       ├── clasicos.py
│       ├── hashing.py
│       └── simetrico.py
├── tests/
│   ├── test_clasicos.py
│   ├── test_hashing.py
│   └── test_simetrico.py
└── docs/
```

| Ruta | Qué contiene |
|---|---|
| `.gitignore` | Lista de archivos que git no debe versionar: claves privadas (`*.pem`, `*.key`), variables de entorno (`.env`), caché de Python (`__pycache__/`, `.pytest_cache/`) y el entorno virtual (`.venv/`). Evita subir secretos por accidente. |
| `README.md` | Este archivo: descripción del proyecto, aclaración de que es educativo y la organización de carpetas. |
| `pytest.ini` | Configuración de pytest: agrega `src/` al camino de búsqueda de Python para que los tests puedan importar `kit_cripto`. |
| `requirements.txt` | Dependencias con versión exacta (`cryptography`, `pytest`) para reproducir el entorno: `pip install -r requirements.txt`. |
| `src/kit_cripto/` | Paquete de Python con el código del kit. Está dentro de `src/` para separar el código de los tests y la documentación. |
| `src/kit_cripto/__init__.py` | Marca la carpeta como paquete importable (`from kit_cripto import hashing`). Por ahora está vacío. |
| `src/kit_cripto/clasicos.py` | Cifrados clásicos César y Vigenère, con fuerza bruta contra el César y análisis de frecuencias contra el Vigenère. Solo didáctico. |
| `src/kit_cripto/hashing.py` | Módulo de hashes: calcular SHA-256 de un archivo y verificar integridad. |
| `src/kit_cripto/simetrico.py` | Cifrado y descifrado de archivos con AES-256-GCM, con la clave derivada de una contraseña con scrypt. |
| `tests/` | Pruebas automáticas con pytest. |
| `tests/test_clasicos.py` | Tests del módulo `clasicos.py`. |
| `tests/test_hashing.py` | Tests del módulo `hashing.py`. |
| `tests/test_simetrico.py` | Tests del módulo `simetrico.py`. |
| `docs/` | Documentación y material de apoyo (informe TLS, imágenes de la demo ECB vs GCM). Todavía está vacía; git no versiona carpetas vacías. |

## Hashes (SHA-256)

El módulo `kit_cripto.hashing` calcula el hash SHA-256 de un archivo y permite verificar si fue modificado. El archivo se lee en bloques de 64 KB, así que funciona con archivos grandes sin cargarlos enteros en memoria. La comparación usa `hmac.compare_digest`, que tarda lo mismo sin importar dónde difieran los hashes.

```python
from kit_cripto.hashing import sha256_archivo, verificar

print(sha256_archivo("documento.pdf"))
print(verificar("documento.pdf", "b221d9db...ddb79"))  # True si coincide, False si cambió
```

## Cifrados clásicos (César y Vigenère)

> **Advertencia:** son cifrados didácticos y **no sirven para proteger información real**. El módulo incluye los ataques que los rompen.

`kit_cripto.clasicos` trabaja con el alfabeto A-Z, respeta mayúsculas y minúsculas y deja intactos espacios, números, signos y letras con acento. Incluye:

- `cesar_cifrar` / `cesar_descifrar` y `vigenere_cifrar` / `vigenere_descifrar`.
- `cesar_fuerza_bruta`: prueba los 26 desplazamientos. `cesar_romper` elige el más probable comparando con las frecuencias de letras del español.
- `vigenere_romper`: estima el largo de la clave con el índice de coincidencia y recupera cada letra con chi-cuadrado contra las frecuencias del español. Necesita un texto de unos 400 caracteres o más para ser confiable.

```python
from kit_cripto.clasicos import (
    cesar_cifrar, cesar_romper, vigenere_cifrar, vigenere_romper,
)

cesar_cifrar("Hola, mundo", 3)                  # 'Krod, pxqgr'

cifrado = cesar_cifrar("Los mensajes secretos de los romanos se rompen con facilidad si uno conoce el idioma.", 5)
cesar_romper(cifrado)                           # (5, 'Los mensajes secretos de los romanos ...')

vigenere_cifrar("Ataque al amanecer", "LIMON")  # 'Lbmehp ix ozlvqqrc'
# vigenere_romper(texto_largo_cifrado) devuelve (clave_estimada, texto_descifrado)
```

## Cifrado de archivos (AES-GCM)

`kit_cripto.simetrico` cifra y descifra archivos con **AES-256-GCM** usando la librería `cryptography`. La clave no se usa directamente desde la contraseña: se deriva con **scrypt** (N=2^17, r=8, p=1) y una sal aleatoria de 16 bytes. Cada cifrado usa además un nonce aleatorio de 12 bytes. Si la contraseña es incorrecta o el archivo fue alterado, se lanza `ErrorDescifrado` y no queda ningún archivo de salida.

```python
from getpass import getpass
from kit_cripto.simetrico import cifrar_archivo, descifrar_archivo, ErrorDescifrado

contrasena = getpass("Contraseña: ")  # nunca la escribas en el código
cifrar_archivo("notas.txt", "notas.txt.kcripto", contrasena)

try:
    descifrar_archivo("notas.txt.kcripto", "notas_recuperadas.txt", contrasena)
except ErrorDescifrado as error:
    print(error)  # contraseña incorrecta o archivo alterado
```

**Formato del archivo cifrado (versión 1):**

| Campo | Tamaño | Detalle |
|---|---|---|
| Marca | 7 bytes | `KCRIPTO` |
| Versión | 1 byte | `1` |
| Sal | 16 bytes | Aleatoria, nueva en cada cifrado |
| Nonce | 12 bytes | Aleatorio, nuevo en cada cifrado |
| Texto cifrado + etiqueta | datos + 16 bytes | La etiqueta de GCM autentica todo |

Los primeros 36 bytes (marca, versión, sal y nonce) se usan como datos asociados (AAD): modificar cualquiera hace fallar el descifrado.

**Límites:** el archivo se procesa entero en memoria, así que no es apto para archivos muy grandes. Es un proyecto didáctico, no está auditado.
