import hashlib
import hmac

def sha256_archivo(ruta: str) -> str:
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(65536), b""):
            h.update(bloque)
    return h.hexdigest()

def verificar(ruta: str, hash_esperado: str) -> bool:
    return hmac.compare_digest(sha256_archivo(ruta), hash_esperado.lower())
