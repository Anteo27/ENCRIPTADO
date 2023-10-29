from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
import os as os

def encrypt_file(input_file, key):
    if input_file.endswith(".cif"):
       return 1

    output_file = input_file+".cif"
    
    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16 
    IV=os.urandom(block_size)
    print(IV)
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()

    # Crea un objeto Padder para hacer el padding PKCS7
    padder = padding.PKCS7(block_size * 8).padder()

    # Abre el archivo de entrada y salida en modo binario
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        outfile.write(IV)
        while True:
            block = infile.read(block_size)
            if len(block) == 0:
                break
            # Añade padding al bloque si es necesario
            if len(block) != block_size:
                block = padder.update(block) + padder.finalize()
            else:
                block = padder.update(block)
            # Cifra el bloque y escribe el resultado en el archivo de salida
            outfile.write(encryptor.update(block))
        # Finaliza el cifrado y escribe cualquier dato restante en el archivo de salida
        outfile.write(encryptor.finalize())
    os.remove(input_file)


def decrypt_file(input_file, key):
    if not input_file.endswith(".cif"):
       return 1

    output_file = input_file.replace(".cif", "")
    
    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16
    IV=""
    with open(input_file, 'rb') as f:
        IV = f.read(block_size)

    print(IV)
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()

    # Crea un objeto Unpadder para eliminar el padding PKCS7
    unpadder = padding.PKCS7(block_size * 8).unpadder()

    # Abre el archivo de entrada y salida en modo binario
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Lee y descifra el archivo en bloques
        infile.read(block_size)
        while True:
            # Lee un bloque del archivo de entrada
                
            file_block = infile.read(block_size)
            if not file_block:
                break  # Fin del archivo
            
            # Descifra el bloque
            plaintext_block = decryptor.update(file_block)
            
            # Elimina el padding usando PKCS7 y escribe el resultado en el archivo de salida
            plaintext_block = unpadder.update(plaintext_block)
           
            outfile.write(plaintext_block)
        
        # Finaliza el descifrado y elimina cualquier padding restante
        plaintext_block = decryptor.finalize()
        plaintext_block = unpadder.update(plaintext_block) + unpadder.finalize()
        outfile.write(plaintext_block)

    os.remove(input_file)
