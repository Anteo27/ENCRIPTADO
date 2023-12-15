import numpy as np

from ecc import ECC

class Hamming(ECC):
    def __init__(self, k=4):
        assert k > 0, 'La longitud de los datos codificados debe ser mayor que 0'
        self.k_ = k
        r = 1
        while 2 ** r - r - 1 < k:
            r += 1
        self.r_ = r
        print(f'Hamming({self.n},{self.k},{self.r})')
        # Generar una matriz donde cada columna es el índice correspondiente en binario
        bin_matrix = np.array([[((j + 1)//(2 ** i))%2 for j in range(2 ** r - 1)] for i in range(r)], dtype=int)
        # Eliminar las columnas de verificación
        check_cols = []
        for i in range(r):
            check_cols.append(2 ** i - 1)
        bin_matrix = np.delete(bin_matrix, check_cols, axis=1)
        # Mantener la longitud de los datos k
        control_matrix = bin_matrix[:, :k]
        # Crear la matriz de corrección de errores
        self.H_ = np.hstack((control_matrix, np.eye(r))).astype(int)
        # Crear la matriz generadora
        self.G_ = np.hstack((np.eye(k), control_matrix.T)).astype(int)

    # Longitud de los datos
    @property
    def k(self):
        return self.k_

    # Longitud del código
    @property
    def n(self):
        return self.k + self.r

    # Longitud de la verificación
    @property
    def r(self):
        return self.r_

    # Capacidad de corrección
    @property
    def t(self):
        return 1

    # Matriz generadora de código Hamming
    @property
    def G(self):
        return self.G_

    # Matriz de corrección de errores de código Hamming
    @property
    def H(self):
        return self.H_

    # Codificar el mensaje m en un código
    def encode(self, m):
        return m@self.G

    # Decodificar el código c en un mensaje
    def decode(self, c):
        return c[:self.k]

    # Corregir el código c (hasta 1 bit)
    def correct(self, c):
        syndrome = (self.H@c.T)%2
        for idx, col in enumerate(self.H.T):
            if np.all(col == syndrome):
                c[idx] ^= 1
                break
        return c
