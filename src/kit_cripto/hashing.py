import hashlib
import hmac

def sha256_archivo(ruta: str) -> str:
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(65536), b""):
            h.update(bloque)
    return h.hexdigest()

def verificar(ruta: str, hash_esperado: str) -> bool:
    if not isinstance(hash_esperado, str):
        raise TypeError("hash_esperado debe ser un texto.")
    # Se compara en bytes: compare_digest no acepta str con caracteres no ASCII.
    return hmac.compare_digest(sha256_archivo(ruta).encode(), hash_esperado.lower().encode("utf-8"))
