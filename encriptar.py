from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import filedialog
import tkinter as tk
import os as os

def encrypt_file(input_file, key):
    if ".cif" in input_file:
       print("No se puede volver a encriptar un archivo cifrado")
       return

    output_file = input_file+".cif"
    
    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16
    
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * block_size), backend=default_backend())
    encryptor = cipher.encryptor()

    # Crea un objeto Padder para hacer el padding PKCS7
    padder = padding.PKCS7(block_size * 8).padder()

    # Abre el archivo de entrada y salida en modo binario
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Lee todo el archivo
        file_data = infile.read()
        
        # Añade padding a los datos usando PKCS7
        padded_data = padder.update(file_data) + padder.finalize()
        
        # Cifra los datos y escribe el resultado en el archivo de salida
        ciphertext_data = encryptor.update(padded_data) + encryptor.finalize()
        outfile.write(ciphertext_data)
    
    os.remove(input_file)
def decrypt_file(input_file, key):
    if ".cif" not in input_file:
       print("El archivo no está cifrado")
       return

    output_file = input_file.replace(".cif", "")
    
    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16
    
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * block_size), backend=default_backend())
    decryptor = cipher.decryptor()

    # Crea un objeto Unpadder para eliminar el padding PKCS7
    unpadder = padding.PKCS7(block_size * 8).unpadder()

    # Abre el archivo de entrada y salida en modo binario
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Lee y descifra el archivo en bloques
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
