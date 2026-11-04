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
│       └── hashing.py
├── tests/
│   └── test_hashing.py
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
| `src/kit_cripto/hashing.py` | Módulo de hashes: calcular SHA-256 de un archivo y verificar integridad. |
| `tests/` | Pruebas automáticas con pytest. |
| `tests/test_hashing.py` | Tests del módulo `hashing.py`. |
| `docs/` | Documentación y material de apoyo (informe TLS, imágenes de la demo ECB vs GCM). Todavía está vacía; git no versiona carpetas vacías. |

## Hashes (SHA-256)

El módulo `kit_cripto.hashing` calcula el hash SHA-256 de un archivo y permite verificar si fue modificado. El archivo se lee en bloques de 64 KB, así que funciona con archivos grandes sin cargarlos enteros en memoria. La comparación usa `hmac.compare_digest`, que tarda lo mismo sin importar dónde difieran los hashes.

```python
from kit_cripto.hashing import sha256_archivo, verificar

print(sha256_archivo("documento.pdf"))
print(verificar("documento.pdf", "b221d9db...ddb79"))  # True si coincide, False si cambió
```
