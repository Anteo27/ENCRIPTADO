from cryptography.hazmat.primitives import padding,serialization,hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa,padding as padrsa
from cryptography.hazmat.backends import default_backend
import os as os
import secrets
import hashlib

diccionario_descifrado=""
diccionario = {}
runtime_hash=b''
mode=0

private_key_pem =""""""
public_key_pem =""""""
ruta_diccionario=""

def limpiar_padding(lectura, escritura):
    with open(lectura, 'r') as infile, open(escritura, 'w') as outfile:
      data = infile.read()
      data = data.replace('\x00', '')
      outfile.write(data)



def encriptar_rsa():
    global ruta_diccionario, diccionario_descifrado,public_key_pem
    os.remove(ruta_diccionario)
    # Cargar la clave publica
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        None,
    )
    # Asegúrate de que tus datos son bytes
    if isinstance(diccionario_descifrado, str):
        diccionario_descifrado = diccionario_descifrado.encode()

    # Divide los datos en bloques de 190 bytes
    bloques = [diccionario_descifrado[i:i+190] for i in range(0, len(diccionario_descifrado), 190)]

    ciphertext = b""
    for bloque in bloques:
        # Cifra cada bloque individualmente
        bloque_cifrado = public_key.encrypt(
            bloque,
            padrsa.OAEP(
                mgf=padrsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Añade el bloque cifrado al texto cifrado total
        ciphertext += bloque_cifrado
    # Write the concatenated encrypted data to the file
    with open(ruta_diccionario, 'wb') as file:
        file.write(ciphertext)

        
def leer_diccionario_cifrado():
    global ruta_diccionario,diccionario_descifrado,private_key_pem

    # Cargar la clave privada
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf8"),
        password=None,
    )

    # Asegúrate de que tus datos son bytes
    if isinstance(diccionario_descifrado, str):
        diccionario_descifrado = diccionario_descifrado.encode()
    # Leer el texto cifrado del archivo
    with open(ruta_diccionario, 'rb') as file:
        ciphertext = file.read()

    # Divide el texto cifrado en bloques del tamaño de la clave
    tamaño_bloque = (private_key.key_size + 7) // 8
    bloques = [ciphertext[i:i+tamaño_bloque] for i in range(0, len(ciphertext), tamaño_bloque)]

    plaintext = b""
    for bloque in bloques:
        # Desencripta cada bloque individualmente
        bloque_descifrado = private_key.decrypt(
            bloque,
            padrsa.OAEP(
                mgf=padrsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Añade el bloque descifrado al texto descifrado total
        plaintext += bloque_descifrado

    # Convierte los bytes a string y guarda en diccionario_descifrado
    diccionario_descifrado = plaintext.decode()
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
        plaintext_block =  unpadder.finalize()
        outfile.write(plaintext_block)

    os.remove(input_file)


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