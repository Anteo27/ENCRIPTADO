from reedsolo import RSCodec, ReedSolomonError

def codificar(nombre_archivo, num_simbolos):
    # Inicialización
    rsc = RSCodec(num_simbolos)

    # Leer el archivo
    with open(nombre_archivo, 'rb') as f:
        texto = f.read()

    # Codificación
    texto_codificado = rsc.encode(texto)
    print("Texto codificado: ", texto_codificado)
    with open("codificar.txt", 'wb') as f:
        f.write(texto_codificado)

def reparar_errores(nombre_archivo,num_simbolos):
    rsc = RSCodec(num_simbolos)
  # Decodificación (reparación)
    with open(nombre_archivo, 'rb') as f:
        texto = f.read()
    try:
        texto_decodificado, _, _ = rsc.decode(texto)  # Ignoramos el número de errores corregidos y detectados
        print("Texto decodificado: ", texto_decodificado)
        with open("salida.txt", 'wb') as f:
         f.write(texto_decodificado)
    except ReedSolomonError as e:
        print("Error al decodificar: ", e)


# Llamar a la función
#codificar('mi_archivo.txt', 30)
reparar_errores('codificar.txt',30)
