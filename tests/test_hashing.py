from kit_cripto.hashing import sha256_archivo, verificar

HASH_HOLA = "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79"


def test_sha256_archivo_conocido(tmp_path):
    archivo = tmp_path / "hola.txt"
    archivo.write_bytes(b"hola")
    assert sha256_archivo(str(archivo)) == HASH_HOLA


def test_verificar(tmp_path):
    archivo = tmp_path / "hola.txt"
    archivo.write_bytes(b"hola")
    assert verificar(str(archivo), HASH_HOLA) is True
    assert verificar(str(archivo), HASH_HOLA.upper()) is True
    assert verificar(str(archivo), "0" * 64) is False
    archivo.write_bytes(b"hola!")
    assert verificar(str(archivo), HASH_HOLA) is False
