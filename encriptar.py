from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os as os
import secrets
import hashlib

diccionario = {}
runtime_hash=b''
ruta_diccionario=""
def cargarRutaDisccionario(ruta):
    global ruta_diccionario
    ruta_diccionario=ruta

def generar_clave_fichero():
    global runtime_hash,ruta_diccionario
    # Genera una clave de 256 bits
    clave = secrets.token_hex(16)

    # Convierte la clave en una secuencia de bytes utilizando UTF-8
    clave_bytes = clave.encode('utf-8')

    # Genera el hash de la clave generada
    sha3_256_hash = hashlib.sha3_256()
    sha3_256_hash.update(clave_bytes)
    
    sha3_256_result = sha3_256_hash.hexdigest()

    # Escribe la clave con su hash en el archivo
    with open(ruta_diccionario, 'a') as claves:
        claves.write('\n'+sha3_256_result+','+clave)

    cargar_claves()   
    #return sha3_256_result.encode('utf-8')
    runtime_hash=sha3_256_result.encode('utf-8')

def obtener_clave(hash):
    clave=diccionario[hash.decode()]
    return clave.encode('utf-8')

def cargar_claves():
    global diccionario,ruta_diccionario
    with open(ruta_diccionario, 'r') as claves:
     for line in claves:
        # Divide cada línea en llave y valor utilizando el signo igual (=) como separador
        hash, clave = line.strip().split(',')
        # Almacena la llave y el valor en el diccionario
        diccionario[hash] = clave.encode('utf-8')
  

def encrypt_file(input_file):
    global runtime_hash
    if input_file.endswith(".cif"):
       return 1
    
    
    key = b''
    key = diccionario[runtime_hash.decode()]

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
        outfile.write(runtime_hash)
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


def decrypt_file(input_file):
    if not input_file.endswith(".cif"):
       return 1

    global diccionario
    output_file = input_file.replace(".cif", "")
    hash=""
    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16
    IV=""
    with open(input_file, 'rb') as f:
        IV = f.read(block_size)
        hash=f.read(block_size)
        hash+=f.read(block_size)
        hash+=f.read(block_size)
        hash+=f.read(block_size)
    print(IV)
    hash = hash.decode()
    key = diccionario[hash]
   
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()

    # Crea un objeto Unpadder para eliminar el padding PKCS7
    unpadder = padding.PKCS7(block_size * 8).unpadder()

    # Abre el archivo de entrada y salida en modo binario
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Lee y descifra el archivo en bloques
        infile.read(block_size)
        infile.read(block_size)
        infile.read(block_size)
        infile.read(block_size)
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
    if hash_texto(contraseñaHash) == "1b8ba62af6c2eabb53e46cdd40b9b231aa4ff1e453795cb5b0ce097a0ccda54c":  
        return True
        
    else:
        return False

#generar_clave_fichero()
#clave = obtener_clave("hash3")
#print(clave)
#print(diccionario)

#ruta_actual = os.getcwd()
#ruta_completa = os.path.join(ruta_actual, 'prueba.docx.cif')
#encrypt_file(ruta_completa)

#cargar_claves()
#decrypt_file(ruta_completa)