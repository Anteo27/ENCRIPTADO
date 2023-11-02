from cryptography.hazmat.primitives import padding,serialization,hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa,padding as padrsa
from cryptography.hazmat.backends import default_backend
import os as os
import secrets
import hashlib
import base64

diccionario_descifrado=""
diccionario = {}
runtime_hash=b''
ruta_diccionario=""
def encriptar_rsa():
    global ruta_diccionario, diccionario_descifrado
    public_key_pem = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgm519dta7PDxY2hIGFdB
5/jrIGayQgh77GG8CJSaJBNiWsGxcfqITAWtvKxjIHCyg3SNpaNe8fWCx4gGczbE
cKYtkIY+Tm8qKITRW23CJ9frKOQhgiFDLpbiMPSYSYYIrBzmW4KQp6WuBc9O/8i6
f41yoDLcpUbZuktweemfxaUASMP8VOzxXKQX0NbIXlaVli///YtN+9l1SpZRAjgz
c20ffe1D7231fcn8geO3HVHT7gcJrRfIU+T/Gd4QC+PO1+VqefQW5IWt9dQ3ND5x
/Li94aUh7vpEzd8+EGS1XUewkyCoPq/kWIbFPG3chlTofOBz3pR4alyV/e2+e0+B
kwIDAQAB
-----END PUBLIC KEY-----
"""
  
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

        
def leer_claves_cifradas():
    global ruta_diccionario,diccionario_descifrado
    private_key_pem = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCCbnX121rs8PFj
aEgYV0Hn+OsgZrJCCHvsYbwIlJokE2JawbFx+ohMBa28rGMgcLKDdI2lo17x9YLH
iAZzNsRwpi2Qhj5ObyoohNFbbcIn1+so5CGCIUMuluIw9JhJhgisHOZbgpCnpa4F
z07/yLp/jXKgMtylRtm6S3B56Z/FpQBIw/xU7PFcpBfQ1sheVpWWL//9i0372XVK
llECODNzbR997UPvbfV9yfyB47cdUdPuBwmtF8hT5P8Z3hAL487X5Wp59Bbkha31
1Dc0PnH8uL3hpSHu+kTN3z4QZLVdR7CTIKg+r+RYhsU8bdyGVOh84HPelHhqXJX9
7b57T4GTAgMBAAECggEAEez6e0qlaXEHy+C2H9pGLYpxTievEhI2bdtUy10Y/iJH
3y9FouOKvd/967NJgFjcv+JR4VTdpKVYTvHr6QO65byBAJ7ii0cN5TmzyDwCdhVf
tWP9EvRdVlbYSWAkWd547KagJi2AkfncO+Is+kxtDUC0Yz36QyDEpazejXLFSZVc
hPgluQrlpAhagfUMLMw6d9vGamsmkYIUIi06xDEbKkZuvlIpDeRrG8kRPbJ7NG1h
P2UnEZOuk6a8UxebelAyunIAih4bkgWli3XJl9GHzQsdwtWHEyW43WWdusHeC54h
clCwnPKwnC6X21MYXOKih8PkCJ8WK/vqc55dLtK5yQKBgQC4PM5+USF0FEQC0C3E
8SmzZQp1hhhIIDoqn2SZTuP4z4MZIl4ZBoJgVYcc6orMjCtoosSZ9XQVV/y/p8VE
Ov7IsL7axxznmp1tpECTz1PThsWvLe6UposEYgQeZkCbjdc2n9h/HGK/lFiGkiZ6
fJtSA+S7TkXmtoaKK5DD9GKztQKBgQC1PGZsRh1wowOqaPRULcDtjvY9Ap4N/xMu
AwJIReDTAGlxD+bXAW9vEMeFC1jG5klqj7exm6aJelltIBJp0WpaH2YkfHNCudQG
38OkXyvxwBPG79/+htsV7TE9Yj50NT5AlNSgO99yKfvSjIWjAxL+HhOhPim2FMD5
DDx/XiQ9JwKBgQCJTffut/QgmIHfPtr9bWXQprrWv2sVRb9TyJqmjt7jrXNcpfpO
2EUOGm+pozpyGvy27KdsvjsXNQ3On/AqW3VKiD6UudPW36n37nOaNOeaO1TUq3yl
GEF+sLW1GiuIQntj4Fju0m7drGcVU5KNspPm2bP7y+fYe6tlCfbHszhkCQKBgAok
Bgsa5TzPMj5PvxQSt0/Thv2k7tkTo6wYaQFIP6suw7eazyzKnMSXKMLN/rqqWgNH
ZVzfu7LHkMdlWwJmwE+ooBt8hyp9oVp9HMJOvPO67qBb/amNPCb+7ZlkrN/ttr0A
VuFcWEVYCgoe6L9VRbPIVQrZopXYlW+Z+qyZxOdTAoGAVeY/Zyuq/q9MOWGMqacK
U/J07TXlfGl8zVNBYK3kswPKrX5F2DqMOcVSx6butoK0jcgOD71RW/tZW6GMiIgX
PkTLx2qw1B7vIQM5fssqAw65/jz7TirQlasvs8aNssa0q8Cv8coFXEDBq+Ffkgdx
JCbgwVWzkBX6Nu7KiD+WiMA=
-----END PRIVATE KEY-----
"""

    # Cargar la clave privada
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
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
    global runtime_hash
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
