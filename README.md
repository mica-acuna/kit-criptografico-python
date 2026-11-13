# Kit criptográfico en Python

Kit criptográfico con fines educativos. No usar en producción.

## Organización de carpetas del proyecto

```
kit-criptografico-python/
├── .gitignore
├── README.md
├── pytest.ini
├── requirements.txt
├── requirements-dev.txt
├── scripts/
│   └── demo_ecb.py
├── src/
│   └── kit_cripto/
│       ├── __init__.py
│       ├── asimetrico.py
│       ├── clasicos.py
│       ├── hashing.py
│       └── simetrico.py
├── tests/
│   ├── test_asimetrico.py
│   ├── test_clasicos.py
│   ├── test_demo_ecb.py
│   ├── test_hashing.py
│   └── test_simetrico.py
└── docs/
    └── ecb_vs_gcm/
```

| Ruta | Qué contiene |
|---|---|
| `.gitignore` | Lista de archivos que git no debe versionar: claves privadas (`*.pem`, `*.key`), variables de entorno (`.env`), caché de Python (`__pycache__/`, `.pytest_cache/`), los archivos de cobertura (`.coverage`, `htmlcov/`) y el entorno virtual (`.venv/`). Evita subir secretos por accidente. |
| `README.md` | Este archivo: descripción del proyecto, aclaración de que es educativo y la organización de carpetas. |
| `pytest.ini` | Configuración de pytest: agrega `src/` y `scripts/` al camino de búsqueda de Python para que los tests puedan importar `kit_cripto` y la demo. |
| `requirements.txt` | Dependencias con versión exacta (`cryptography`, `pillow`, `pytest`) para reproducir el entorno: `pip install -r requirements.txt`. Pillow solo lo usa la demo de ECB. |
| `requirements-dev.txt` | Dependencias de desarrollo: incluye `requirements.txt` más `pytest-cov` (cobertura) y `pytest-randomly` (orden aleatorio de los tests): `pip install -r requirements-dev.txt`. |
| `scripts/demo_ecb.py` | Demo visual de por qué ECB es inseguro. Está fuera del paquete a propósito: el kit no ofrece ECB. |
| `src/kit_cripto/` | Paquete de Python con el código del kit. Está dentro de `src/` para separar el código de los tests y la documentación. |
| `src/kit_cripto/__init__.py` | Marca la carpeta como paquete importable (`from kit_cripto import hashing`). Por ahora está vacío. |
| `src/kit_cripto/asimetrico.py` | Firma digital RSA-PSS con SHA-256: generar el par de claves, firmar un archivo y verificar la firma. |
| `src/kit_cripto/clasicos.py` | Cifrados clásicos César y Vigenère, con fuerza bruta contra el César y análisis de frecuencias contra el Vigenère. Solo didáctico. |
| `src/kit_cripto/hashing.py` | Módulo de hashes: calcular SHA-256 de un archivo y verificar integridad. |
| `src/kit_cripto/simetrico.py` | Cifrado y descifrado de archivos con AES-256-GCM, con la clave derivada de una contraseña con scrypt. |
| `tests/` | Pruebas automáticas con pytest. |
| `tests/test_asimetrico.py` | Tests del módulo `asimetrico.py`. Generan sus claves en carpetas temporales, nunca en el repo. |
| `tests/test_clasicos.py` | Tests del módulo `clasicos.py`. |
| `tests/test_demo_ecb.py` | Tests de la demo de ECB. |
| `tests/test_hashing.py` | Tests del módulo `hashing.py`. |
| `tests/test_simetrico.py` | Tests del módulo `simetrico.py`. |
| `docs/` | Documentación y material de apoyo (informe TLS, demo ECB vs GCM). |
| `docs/ecb_vs_gcm/` | Imágenes y explicación de la demo de ECB: `original.png`, `ecb.png`, `gcm.png`, `comparacion.png` y su `README.md`. |

## Cómo correr los tests

Con el entorno virtual activado (`.\.venv\Scripts\Activate.ps1` en Windows) y las dependencias de desarrollo instaladas:

```
python -m pip install -r requirements-dev.txt
```

| Qué | Comando |
|---|---|
| Todos los tests | `pytest` |
| Con cobertura (muestra las líneas sin cubrir) | `pytest --cov=kit_cripto --cov=demo_ecb --cov-report=term-missing` |
| Sin los tests lentos (scrypt y RSA con parámetros reales) | `pytest -m "not lento"` |
| Solo los lentos | `pytest -m lento` |
| Un solo módulo | `pytest tests/test_hashing.py` |
| Un solo test | `pytest tests/test_hashing.py::test_vectores_conocidos` |
| En orden fijo (sin mezclar) | `pytest -p no:randomly` |
| Repetir un orden aleatorio que falló | `pytest -p randomly --randomly-seed=NÚMERO` (el número se muestra al inicio de cada corrida) |

- Los tests **no escriben dentro del repositorio**: todo va a carpetas temporales (`tmp_path`). Las claves RSA de los tests se generan ahí y se descartan.
- `pytest-randomly` mezcla el orden en cada corrida; así se comprueba que los tests no dependen unos de otros.
- Los tests marcados `xfail` documentan casos conocidos que todavía no están resueltos. Si se arregla el código, pasan a `XPASS` y fallan a propósito (`strict`) para recordar que hay que quitar la marca.
- El test de permisos `0o600` de la clave privada se saltea en Windows (solo corre en Linux y macOS).

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

## Firma digital (RSA-PSS)

`kit_cripto.asimetrico` genera un par de claves RSA (3072 bits por defecto, exponente 65537), firma archivos con **RSA-PSS y SHA-256** y verifica firmas. La clave privada se guarda en PEM **cifrada con una contraseña**; la pública, en PEM. El archivo se hashea por bloques, así que no se carga entero en memoria. La firma es un archivo binario aparte (por ejemplo `contrato.sig`).

```python
from getpass import getpass
from kit_cripto.asimetrico import (
    generar_par_claves, firmar_archivo, verificar_firma, guardar_firma, leer_firma,
)

contrasena = getpass("Contraseña de la clave privada: ")  # nunca la escribas en el código

# 1. Generar el par de claves (fuera del repositorio, o en la carpeta claves/, que está ignorada)
generar_par_claves("claves/privada.pem", "claves/publica.pem", contrasena)

# 2. Firmar un documento y guardar la firma
firma = firmar_archivo("contrato.txt", "claves/privada.pem", contrasena)
guardar_firma(firma, "contrato.sig")

# 3. Verificar con la clave pública (esto lo puede hacer cualquiera)
verificar_firma("contrato.txt", leer_firma("contrato.sig"), "claves/publica.pem")  # True

# 4. Si alguien cambia el documento (o la firma), la verificación falla
#    (por ejemplo, cambiar "100 unidades" por "900 unidades" en contrato.txt)
verificar_firma("contrato.txt", leer_firma("contrato.sig"), "claves/publica.pem")  # False
```

- Una firma inválida **no lanza excepción**: devuelve `False`. Un archivo inexistente, una clave mal formada o una contraseña incorrecta sí dan un error claro (`FileNotFoundError` o `ErrorClave`).
- `generar_par_claves` **no sobrescribe** claves existentes salvo que pases `sobrescribir=True`. Rechaza claves de menos de 2048 bits.
- En POSIX la clave privada se crea con permisos `0o600`. **En Windows no se aplican esos permisos:** guardá la clave en una carpeta que solo pueda leer tu usuario, y fuera de carpetas sincronizadas como OneDrive.

> **Las claves no se suben al repositorio.** El `.gitignore` excluye `*.pem`, `*.key`, `*.sig` y la carpeta `claves/`. Una clave privada que llegó a GitHub se considera filtrada para siempre. Los tests generan sus claves en carpetas temporales.

## Demo: por qué ECB es inseguro

Se cifra una imagen con AES-256 en modo **ECB** y con **GCM**. En ECB se siguen viendo las formas del dibujo; en GCM, solo ruido. Explicación completa en [docs/ecb_vs_gcm](docs/ecb_vs_gcm/README.md).

![Original, cifrada con ECB y cifrada con GCM](docs/ecb_vs_gcm/comparacion.png)

Para regenerar las imágenes (necesita `pip install -r requirements.txt`):

```
python scripts/demo_ecb.py
```

> **ECB nunca se usa en sistemas reales.** Está solo en `scripts/demo_ecb.py`, fuera del paquete `kit_cripto`, con una función llamada `cifrar_ecb_inseguro`.
