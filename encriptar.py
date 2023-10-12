from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(input_file, output_file, key):
    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16
    
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * block_size), backend=default_backend())
    encryptor = cipher.encryptor()

    # Abre el archivo de entrada y salida en modo binario
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Lee y cifra el archivo en bloques
        while True:
            # Lee un bloque del archivo de entrada
            file_block = infile.read(block_size)
            if not file_block:
                break  # Fin del archivo
            
            # Añade padding si el bloque no es del tamaño completo
            file_block += b'\0' * (block_size - len(file_block))
            
            # Cifra el bloque y escribe el resultado en el archivo de salida
            ciphertext_block = encryptor.update(file_block)
            outfile.write(ciphertext_block)
    
    # Finaliza el cifrado (puede haber datos adicionales en el buffer del cifrador)
    ciphertext_block = encryptor.finalize()
    outfile.write(ciphertext_block)






def decrypt_file(input_file, output_file, key):
    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16
    
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * block_size), backend=default_backend())
    decryptor = cipher.decryptor()

    # Abre el archivo cifrado y el archivo de salida en modo binario
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Lee y descifra el archivo en bloques
        while True:
            # Lee un bloque cifrado del archivo de entrada
            ciphertext_block = infile.read(block_size)
            if not ciphertext_block:
                break  # Fin del archivo
            
            # Descifra el bloque y escribe el resultado en el archivo de salida
            plaintext_block = decryptor.update(ciphertext_block)
            outfile.write(plaintext_block)
    
    # Finaliza el descifrado (puede haber datos adicionales en el buffer del descifrador)
    plaintext_block = decryptor.finalize()

    

if __name__ == "__main__":
    key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10' \
          b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
    
    # Rutas de los archivos de entrada y salida
    input_file = 'archivo.bin'  # Cambia 'archivo.bin' al nombre de tu archivo de entrada
    output_file = 'archivo_cifrado.bin'  # Nombre del archivo cifrado de salida
    
    # Cifra el archivo
    encrypt_file(input_file, output_file, key)
    print(f'El archivo "{input_file}" ha sido cifrado y guardado en "{output_file}" usando AES.')
