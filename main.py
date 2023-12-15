from hamming import Hamming
from mceliece import McEliece, genKey
import numpy as np

def read_file(file):
    data = file.read()
    return data

def encrypt_file(mceliece, filename):
    with open(filename, 'r') as f:
        data = read_file(f)
        return mceliece.encrypt_str(data)

def decrypt_file(mceliece, filename):
    with open(filename, 'r') as f:
        data = read_file(f)
        return mceliece.decrypt_str(data)

def write_decrypted_file(mceliece, input_filename, output_filename):
    with open(output_filename, 'w') as f:
        decrypted_data = decrypt_file(mceliece, input_filename)
        f.write(decrypted_data)

def write_encrypted_file(mceliece, input_filename, output_filename):
    with open(output_filename, 'w') as f:
        encrypted_data = encrypt_file(mceliece, input_filename)
        f.write(encrypted_data)

def read_key_from_file(filename):
    with open(filename, 'r') as f:
        key = np.loadtxt(f, dtype=int)
    return key

if __name__ == '__main__':
    # Seleccionar el código de corrección de errores
    h = Hamming(15)  # h = Goppa()
    # Leer las claves desde los archivos
    S = read_key_from_file("private_key_S.txt")
    G = read_key_from_file("private_key_G.txt")
    P = read_key_from_file("private_key_P.txt")
    pubKey = read_key_from_file("public_key.txt")
    pvKey = (S, G, P)
    mceliece = McEliece(h, pvKey, pubKey)
    # Seleccionar el archivo a encriptar
    input_filename = "clave1s.txt.cif"
    output_filename = "claves.txt.cif"
    write_encrypted_file(mceliece, input_filename, output_filename)
    # Seleccionar el archivo a desencriptar
    decrypted_filename = "salida.txt"
    #write_decrypted_file(mceliece, output_filename, decrypted_filename)
