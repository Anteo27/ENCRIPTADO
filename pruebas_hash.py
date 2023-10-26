import hashlib

def hash_texto(texto_plano):
    # Crear un objeto hash usando SHA256
    hash_obj = hashlib.sha256()

    # Codificar el texto plano a bytes y actualizar el objeto hash
    hash_obj.update(texto_plano.encode('utf-8'))

    # Obtener el hash en formato hexadecimal
    hash_hex = hash_obj.hexdigest()

    return hash_hex

# Prueba del método
texto = "crioto"
print(f"Texto plano: {texto}")
print(f"Hash: {hash_texto(texto)}")