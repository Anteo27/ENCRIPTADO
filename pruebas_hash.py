import hashlib

def hash_texto(texto_plano):
    # Crear un objeto hash usando SHA256
    hash_obj = hashlib.sha256()

    # Codificar el texto plano a bytes y actualizar el objeto hash
    hash_obj.update(texto_plano.encode('utf-8'))

    # Obtener el hash en formato hexadecimal
    hash_hex = hash_obj.hexdigest()

    return hash_hex

def obtener_primeros_256_bits(cadena_bytes):
    # Asegurarse de que la cadena de bytes tiene al menos 32 bytes (256 bits)
    assert len(cadena_bytes) >= 32, "La cadena de bytes es demasiado corta"

    # Obtener los primeros 32 bytes (256 bits)
    primeros_256_bits = cadena_bytes[:32]

    return primeros_256_bits

# Prueba del método
texto = "cripto"
print(f"Texto plano: {texto}")
print(f"Hash: {hash_texto(texto)}")
print(f"Hash256bits: {obtener_primeros_256_bits(hash_texto(texto))}")