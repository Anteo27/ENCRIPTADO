import random

from ecc import ECC
from util import *
def write_key_to_file(key, filename):
    with open(filename, 'w') as f:
        np.savetxt(f, key, fmt='%d')

# Crear clave privada / clave pública
def genKey(ecc: ECC):
    S = randInvMatrix(ecc.k)
    P = randPerMatrix(ecc.n)
    pub_key = (S@ecc.G@P)%2
    pv_key = (S, ecc.G, P)
    write_key_to_file(pub_key, "public_key.txt")
    write_key_to_file(pv_key[0], "private_key_S.txt")
    write_key_to_file(pv_key[1], "private_key_G.txt")
    write_key_to_file(pv_key[2], "private_key_P.txt")
    return pv_key, pub_key


class McEliece():
    def __init__(self, ecc: ECC, private_key, public_key):
        self.ecc = ecc
        if private_key is not None:
            S, G, P = private_key
            self.S, self.G, self.P, self.S_inv, self.P_inv = S, G, P, np.linalg.inv(S).astype(int), np.linalg.inv(
                P).astype(int)
        if public_key is not None:
            self.pub_key = public_key

    # Generar aleatoriamente un código de error e con un número aleatorio de 1s, weight(e)<=t
    def random_error_code(self):
        # Generar una lista de longitud n con todos los elementos 0
        e = np.zeros(self.ecc.n, dtype=int)
        idx = random.randint(0, self.ecc.n - 1)
        e[idx] = 1
        return e

    # Encriptar
    def encrypt(self, m):
        assert self.pub_key is not None, 'No se ha seleccionado ninguna clave pública'
        assert len(m) == self.ecc.k, 'La longitud del texto plano no es correcta'
        m = np.array(m, dtype=int)
        # Generar un código de error aleatorio
        e = self.random_error_code()
        # El texto plano m se multiplica por la clave pública para obtener el texto cifrado
        encrypted = ((m@self.pub_key)%2 + e)%2
        return encrypted

    # Desencriptar
    def decrypt(self, c):
        assert self.S is not None, 'No se ha seleccionado ninguna clave privada'
        assert len(c) == self.ecc.n, 'La longitud del texto cifrado no es correcta'
        c = np.array(c, dtype=int)
        # El texto cifrado c se multiplica por la inversa de P para obtener c_hat
        c_hat = (c@self.P_inv)%2
        # Corregir c_hat
        c_hat = self.ecc.correct(c_hat)
        # Decodificar c_hat para obtener m_hat
        m_hat = self.ecc.decode(c_hat)
        # m_hat se multiplica por la inversa de S para obtener el texto plano
        decrypted = (m_hat@self.S_inv)%2
        return decrypted

    # Encriptar cadena
    def encrypt_str(self, m: str):
        # Convertir el texto plano en una cadena binaria
        s = str2bin(m, self.ecc.k)
        # Dividir la cadena binaria en grupos de longitud k
        rows = bin2vec(s, self.ecc.k)
        encrypted_bin = ''
        # Encriptar cada grupo de cadena binaria
        for row in rows:
            encrypted_bin += vec2bin([self.encrypt(row)])
        return encrypted_bin

    # Desencriptar cadena
    def decrypt_str(self, c: str):
        # Dividir la cadena binaria en grupos de longitud n
        rows = bin2vec(c, self.ecc.n)
        
        decrypted_bin = ''
        # Desencriptar cada grupo de cadena binaria
        for row in rows:
            decrypted_bin += vec2bin([self.decrypt(row)])
        return bin2str(decrypted_bin)
