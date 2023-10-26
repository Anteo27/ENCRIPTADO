from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import filedialog
import tkinter as tk
import os as os
import sys
import hashlib
from cryptography.fernet import Fernet


def limpiar_padding(lectura, escritura):
    with open(lectura, 'r') as infile, open(escritura, 'w') as outfile:
      data = infile.read()
      data = data.replace('\x00', '')
      outfile.write(data)

def abrir_explorador_archivos():
    root = tk.Tk()
    root.withdraw()  # Ocultar la ventana de Tkinter
    ruta_archivo = filedialog.askopenfilename()  # Abrir el explorador de archivos
    return ruta_archivo

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
    os.remove(input_file)
    
def decrypt_file(input_file, key, funcionamiento):
    if funcionamiento == 1:
        if ".cif" not in input_file:
            print("No se puede desencriptar un archivo no cifrado")
            return
     
        output_file=os.path.splitext(input_file)[0]
    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16
    
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * block_size), backend=default_backend())
    decryptor = cipher.decryptor()
    clave = b''
    if funcionamiento == 1:
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
                
    else:
        
        for i in range(0, len(input_file), block_size):

            # Obtiene un bloque cifrado de los datos de entrada
            ciphertext_block = input_file[i:i+block_size]
            if not ciphertext_block:
                break  # Fin de los datos

            # Descifra el bloque
            plaintext_block = decryptor.update(ciphertext_block)

            # Añade el bloque descifrado a la clave
            clave += plaintext_block
                
    # Finaliza el descifrado (puede haber datos adicionales en el buffer del descifrador)
    plaintext_block = decryptor.finalize()

    if funcionamiento == 1:
        # Abre el archivo de salida en modo escritura y recorta el relleno
        limpiar_padding(output_file, "final")

    
        temporal = output_file
        os.remove(output_file)
        os.rename("final", temporal)
        os.remove(input_file)
    else:    
        return clave

def hash_texto(texto_plano):
    # Crear un objeto hash usando SHA256
    hash_obj = hashlib.sha256()

    # Codificar el texto plano a bytes y actualizar el objeto hash
    hash_obj.update(texto_plano.encode('utf-8'))

    # Obtener el hash en formato hexadecimal
    hash_hex = hash_obj.hexdigest()

    return hash_hex

def verificar_contraseña(contraseña):
    contraseñaHash = hash_texto(contraseña)
    if hash_texto(contraseñaHash) == "1b8ba62af6c2eabb53e46cdd40b9b231aa4ff1e453795cb5b0ce097a0ccda54c":  # Reemplaza "tu_contraseña" con la contraseña que desees.
        return True
        
    else:
        return False




def obtener_primeros_256_bits(cadena_bytes):
    # Asegurarse de que la cadena de bytes tiene al menos 32 bytes (256 bits)
    assert len(cadena_bytes) >= 32, "La cadena de bytes es demasiado corta"

    # Obtener los primeros 32 bytes (256 bits)
    primeros_256_bits=b''
    primeros_256_bits = cadena_bytes[:32]

    return primeros_256_bits

#if __name__ == "__main__":
   # key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10' \
         # b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
    

   # directorio_actual = os.getcwd()
   # ruta_relativa = os.path.join(directorio_actual, 'archivoPrueba.txt')
    
    # Rutas de los archivos de entrada y salida
    #input_file = ruta_relativa+'.cif'  # Cambia 'archivo.bin' al nombre de tu archivo de entrada
    

    #input_file = abrir_explorador_archivos()

   

    
    # Cifra el archivo
    #encrypt_file(input_file, key)
    

    #Descifra el archivo
    #decrypt_file(input_file, key)
    


    
