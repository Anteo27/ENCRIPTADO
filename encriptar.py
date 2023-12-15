from cryptography.hazmat.primitives import padding,serialization,hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa,padding as padrsa
from cryptography.hazmat.backends import default_backend
import os as os
import secrets
import hashlib
from hamming import Hamming
from mceliece import McEliece, genKey
import numpy as np
diccionario_descifrado=""
diccionario = {}
runtime_hash=b''
mode=0

private_key_pem =""""""
public_key_pem =""""""
ruta_diccionario=""

# ------------------------------------------------------------------------------------------------------------
def read_file(file):
    data = file.read()
    return data
def read_key_from_file(filename):
    with open(filename, 'r') as f:
        key = np.loadtxt(f, dtype=int)
    return key


# ------------------------------------------------------------------------------------------------------------
def firmar_documento(documento, clave_privada):#documento ruta
    leerdocumento=b''
    with open(documento, 'rb') as infile:
        leerdocumento=infile.read()
    if isinstance(leerdocumento, str):
        leerdocumento = leerdocumento.encode('utf-8')

    clave_privada_desde_str = serialization.load_pem_private_key(
        clave_privada.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

    firma = clave_privada_desde_str.sign(
        leerdocumento,
        padrsa.PSS(
            mgf=padrsa.MGF1(hashes.SHA256()),
            salt_length=padrsa.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return firma

def verificar_documento(documento, firma, clave_publica):
    # Asegúrate de que el documento es un objeto de bytes
    leerdocumento=b''
    with open(documento, 'rb') as infile:
        leerdocumento=infile.read()
    if isinstance(leerdocumento, str):
        leerdocumento = leerdocumento.encode('utf-8')

    clave_publica_desde_str = serialization.load_pem_public_key(
        clave_publica.encode('utf-8'),
        backend=default_backend()
    )
    try:
        clave_publica_desde_str.verify(
            firma,
            leerdocumento,
            padrsa.PSS(
                mgf=padrsa.MGF1(hashes.SHA256()),
                salt_length=padrsa.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


# def comprobar_hash(hash_original, hash_desencriptado):
#     if(hash_original == hash_desencriptado):
#         return True
#     return False



# def hash_archivo(ruta_archivo):
#     with open(ruta_archivo, 'rb') as infile:
#        contenido = infile.read()
#     sha3_256_hash = hashlib.sha3_256()
#     sha3_256_hash.update(contenido)
#     sha3_256_result = sha3_256_hash.hexdigest()

#     result = b''
#     result = sha3_256_result

#     return result.encode()

def encriptar_MCLIECE():
    global ruta_diccionario, diccionario_descifrado,public_key_pem
    # os.remove(ruta_diccionario)
      # Seleccionar el código de corrección de errores
    h = Hamming(15)  # h = Goppa()
    # Leer las claves desde los archivos
    S = read_key_from_file("private_key_S.txt")
    G = read_key_from_file("private_key_G.txt")
    P = read_key_from_file("private_key_P.txt")
    pubKey = read_key_from_file("public_key.txt")
    # Asegúrate de que tus datos son bytes
    # if isinstance(diccionario_descifrado, str):
    #     diccionario_descifrado = diccionario_descifrado.encode()

    pvKey = (S, G, P)
    mceliece = McEliece(h, pvKey, pubKey)
    with open(ruta_diccionario, 'w') as f:
        f.write(mceliece.encrypt_str(diccionario_descifrado.encode('utf8')))
        
def leer_diccionario_cifrado():
    global ruta_diccionario,diccionario_descifrado,private_key_pem
    h = Hamming(15)  # h = Goppa()
    # Leer las claves desde los archivos
    S = read_key_from_file("private_key_S.txt")
    G = read_key_from_file("private_key_G.txt")
    P = read_key_from_file("private_key_P.txt")
    pubKey = read_key_from_file("public_key.txt")
    # Asegúrate de que tus datos son bytes
    if isinstance(diccionario_descifrado, str):
        diccionario_descifrado = diccionario_descifrado.encode()
    # Leer el texto cifrado del archivo
    pvKey = (S, G, P)
    mceliece = McEliece(h, pvKey, pubKey)
    plaintext =""
    with open(ruta_diccionario, 'r') as f:
        data = read_file(f)
        plaintext += mceliece.decrypt_str(data)
    print(plaintext)
    # Convierte los bytes a string y guarda en diccionario_descifrado
    diccionario_descifrado = plaintext
    separador=diccionario_descifrado.split('+')
    for parhashclave in separador:
        if parhashclave:
            # Divide cada par en la clave y el valor
            hash,Aes= parhashclave.split(',')
        
            # Agrega el par clave-valor al diccionario
            diccionario[hash] = Aes



def cargarRutaDiccionario(ruta):
    global ruta_diccionario
    ruta_diccionario=ruta

def generar_clave_fichero():
    global ruta_diccionario,diccionario_descifrado,runtime_hash
    # Genera una clave de 256 bits
    clave = secrets.token_hex(16)

    # Convierte la clave en una secuencia de bytes utilizando UTF-8
    clave_bytes = clave.encode('utf-8')

    # Genera el hash de la clave generada
    sha3_256_hash = hashlib.sha3_256()
    sha3_256_hash.update(clave_bytes)
    sha3_256_result = sha3_256_hash.hexdigest()
    # Escribe la clave con su hash en el archivo
    
    diccionario_descifrado += (sha3_256_result + "," + clave + "+")

    #return sha3_256_result.encode('utf-8')
    runtime_hash=sha3_256_result.encode()

def obtener_clave(hash):
    clave=diccionario[hash.decode()]
    return clave.encode('utf-8')


def encrypt_file(input_file):
    global runtime_hash,mode
    firma_original=firmar_documento(input_file,private_key_pem)
    #hash_original=hash_archivo(input_file)
    if input_file.endswith(".cif"):
       return 1
    key=b''
    key = diccionario[runtime_hash.decode()]
    if isinstance(key, str):
    # Si la clave es una cadena, la convertimos a bytes
        key = key.encode()
    output_file = input_file+".cif"
    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16 
    IV=os.urandom(block_size)
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    # Crea un objeto Padder para hacer el padding PKCS7
    padder = padding.PKCS7(block_size * 8).padder()

    # Abre el archivo de entrada y salida en modo binario
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        outfile.write(IV)
        outfile.write(firma_original)
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
    firma_original_desencriptado=""
    global diccionario
    output_file = input_file.replace(".cif", "")
    hash=""
    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16
    IV=""
    with open(input_file, 'rb') as f:
        IV = f.read(block_size)
        firma_original_desencriptado=f.read(block_size*16)
        hash=f.read(block_size)
        hash+=f.read(block_size)
        hash+=f.read(block_size)
        hash+=f.read(block_size)
    hash = hash.decode()
    key = diccionario[hash]
    if isinstance(key, str):
    # Si la clave es una cadena, la convertimos a bytes
        key = key.encode()
   
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()

    # Crea un objeto Unpadder para eliminar el padding PKCS7
    unpadder = padding.PKCS7(block_size * 8).unpadder()

    # Abre el archivo de entrada y salida en modo binario
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Lee y descifra el archivo en bloques
        infile.read(block_size)
        infile.read(block_size*16)
        infile.read(block_size*4)
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
        plaintext_block =  unpadder.finalize()
        outfile.write(plaintext_block)
    flag=verificar_documento(output_file,firma_original_desencriptado,public_key_pem)
    os.remove(input_file)
    if(flag==True):
        print("no se ha modificado")
    else:
        print("Se ha modificado en el proceso")
        print(firma_original_desencriptado.decode())
        return 2
    

def decrypt_file_keys(input_file, key):
    if not input_file.endswith(".cif"):
       return 1

    # Tamaño del bloque AES en bytes (128 bits)
    block_size = 16
    
    # Crea un objeto AES Cipher con la clave proporcionada y modo de operación CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * block_size), backend=default_backend())
    decryptor = cipher.decryptor()

    # Crea un objeto Unpadder para eliminar el padding PKCS7
    unpadder = padding.PKCS7(block_size * 8).unpadder()

    plaintext = b''

    # Abre el archivo de entrada en modo binario
    with open(input_file, 'rb') as infile:
        # Lee y descifra el archivo en bloques
        while True:
            # Lee un bloque del archivo de entrada
            file_block = infile.read(block_size)
            if not file_block:
                break  # Fin del archivo
            
            # Descifra el bloque
            plaintext_block = decryptor.update(file_block)
            
            # Elimina el padding usando PKCS7
            plaintext_block = unpadder.update(plaintext_block)

            # Añade el bloque de texto plano a la variable plaintext
            plaintext += plaintext_block
        
        # Finaliza el descifrado y elimina cualquier padding restante
        plaintext_block = decryptor.finalize()
        plaintext_block = unpadder.update(plaintext_block) + unpadder.finalize()

        # Añade el último bloque de texto plano a la variable plaintext
        plaintext += plaintext_block
    return plaintext

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
    primeros_256_bits=b''
    primeros_256_bits = cadena_bytes[:32]

    return primeros_256_bits



def verificar_contraseña(contraseña):
    global runtime_hash,mode,public_key_pem,private_key_pem
    contraseñaHash = hash_texto(contraseña)
    if hash_texto(contraseñaHash) == "1b8ba62af6c2eabb53e46cdd40b9b231aa4ff1e453795cb5b0ce097a0ccda54c":  
        ruta_actual = os.getcwd()
        filekey = os.path.join(ruta_actual, 'parkeys.txt.cif')
        key=b''
        key=obtener_primeros_256_bits(contraseñaHash)
        key = bytes.fromhex(key)
        # encrypt_file_keys(filekey,key)
        decrypt=decrypt_file_keys(filekey,key)
        print(decrypt)
        dividir_cadena=decrypt.decode().split("split")
        private_key_pem=dividir_cadena[0]
        public_key_pem=dividir_cadena[1]
        return True
        
    else:
        return False
    