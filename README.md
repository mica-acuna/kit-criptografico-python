# Kit criptográfico en Python

Kit criptográfico con fines educativos. No usar en producción.

## Organización de carpetas del proyecto

```
kit-criptografico-python/
├── .gitignore
├── README.md
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
| `requirements.txt` | Dependencias con versión exacta (`cryptography`, `pytest`) para reproducir el entorno: `pip install -r requirements.txt`. |
| `src/kit_cripto/` | Paquete de Python con el código del kit. Está dentro de `src/` para separar el código de los tests y la documentación. |
| `src/kit_cripto/__init__.py` | Marca la carpeta como paquete importable (`from kit_cripto import hashing`). Por ahora está vacío. |
| `src/kit_cripto/hashing.py` | Módulo de hashes: calcular SHA-256 de un archivo y verificar integridad. |
| `tests/` | Pruebas automáticas con pytest. |
| `tests/test_hashing.py` | Tests del módulo `hashing.py`. |
| `docs/` | Documentación y material de apoyo (informe TLS, imágenes de la demo ECB vs GCM). Todavía está vacía; git no versiona carpetas vacías. |
