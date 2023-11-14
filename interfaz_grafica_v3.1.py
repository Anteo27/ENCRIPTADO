import tkinter as tk
from tkinter import filedialog, messagebox
import encriptar as lib
import os

ruta = ""
filekey=""

def cifrar():
    global ruta,filekey
    if not ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo antes de cifrar.")
        return
    if not filekey or not ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo con la clave antes de cifrar.")
        return
    if "claves.txt" in ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo que no sea la propia clave.")
        return
    if "claves.txt" not in filekey:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un fichero válido de clave.")
        return
    if "parkeys.txt" in ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo que no sea la propia clave.")
        return
    #if lib.encrypt_file(ruta, clave) == 1:
    if lib.encrypt_file(ruta) == 1:
        messagebox.showwarning("Advertencia", "El archivo ya esta cifrado ")
     # Mostrar el mensaje de "Proceso completado"
    messagebox.showinfo("Información", "Proceso completado")
    entrada.config(state='normal')
    entrada.delete(0, tk.END)
    entrada.config(state='readonly')

def descifrar():
    global ruta,filekey
    if not ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo antes de descifrar.")
        return
    if "claves.txt" in ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo que no sea la propia clave.")
        return
    if "parkeys.txt" in ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo que no sea la propia clave.")
        return
    if "claves.txt" not in filekey:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un fichero válido de clave.")
        return
    try:
        finalizacion=lib.decrypt_file(ruta)
        if finalizacion == 1:
            messagebox.showwarning("Advertencia", "El archivo ya esta descifrado ")
        if finalizacion==2:
             messagebox.showwarning("Advertencia", "El archivo encriptado ha sido modificado abralo bajo su reponsabilidad ")
        # Mostrar el mensaje de "Proceso completado"
        messagebox.showinfo("Información", "Proceso completado")
        entrada.config(state='normal')
        entrada.delete(0, tk.END)
        entrada.config(state='readonly')
    except ValueError as e:
        messagebox.showwarning("Advertencia", "No se puede desencriptar por modificacion a nivel de byte")


nombre_Archivo = ""
def seleccionar_archivo():
    global nombre_Archivo, ruta
    ruta = filedialog.askopenfilename()
    nombre_Archivo = ruta
    entrada.config(state='normal')
    entrada.delete(0, tk.END)
    entrada.insert(0, nombre_Archivo)

def confirmar_cifrado():
    global nombre_Archivo
    if messagebox.askyesno("Confirmación", "¿Estás seguro de que deseas cifrar el archivo? " + nombre_Archivo):
        cifrar()
    entrada.config(state='readonly')
    entrada.delete(0, tk.END)
    nombre_Archivo = ""

def verificar_contraseña():
    Condicion = lib.verificar_contraseña(entrada_contraseña.get())
    if Condicion == False: 
        messagebox.showwarning("Advertencia", "Contraseña incorrecta. Inténtalo de nuevo.")
    else:
        global filekey
        ruta_actual = os.getcwd()
        filekey = os.path.join(ruta_actual, 'claves.txt.cif')
        marco.grid()
        marco_contraseña.grid_remove()
        lib.cargarRutaDiccionario(filekey)
        lib.leer_diccionario_cifrado()
        lib.generar_clave_fichero()
        lib.encriptar_rsa()
        lib.leer_diccionario_cifrado()
# Crear ventana principal
ventana = tk.Tk()
ventana.title('Cifrador y Descifrador')
ventana.configure(background="lightblue")

# Crear un marco para los widgets
marco = tk.Frame(ventana, padx=10, pady=10, bg="lightblue")
marco.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    # Crear un marco para la contraseña
marco_contraseña = tk.Frame(ventana, padx=10, pady=10, bg="lightblue")
marco_contraseña.grid(row=0, column=0)

# Crear un botón para seleccionar un archivo
boton_seleccionar_archivo = tk.Button(marco, text="Seleccionar archivo", command=seleccionar_archivo, bg="white", fg="black")
boton_seleccionar_archivo.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

# Crear un widget de entrada de texto para la contraseña
entrada_contraseña = tk.Entry(marco_contraseña, show="*", bg="white")
entrada_contraseña.grid(row=1, column=1)

# Crear un widget de entrada de texto
entrada = tk.Entry(marco, state='readonly', bg="white")
entrada.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

# Ocultar el marco hasta que se verifique la contraseña
marco.grid_remove()

etiqueta = tk.Label(marco, text="", bg="lightblue", fg="black")
etiqueta.grid(row=2, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
# Crear un botón para verificar la contraseña
boton_verificar = tk.Button(marco_contraseña, text="Verificar contraseña", command=verificar_contraseña, bg="green", fg="white")
boton_verificar.grid(row=2, column=1)


# Crear los botones de cifrar y descifrar
boton_cifrar = tk.Button(marco, text="Cifrar y elegir clave", command=confirmar_cifrado, bg="red", fg="white")
boton_cifrar.grid(row=3, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

boton_descifrar = tk.Button(marco, text="Descifrar y elegir clave", command=descifrar, bg="green", fg="white")
boton_descifrar.grid(row=4, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

# Configurar el marco para expandirse con la ventana
ventana.columnconfigure(0, weight=1)
ventana.rowconfigure(0, weight=1)
marco.columnconfigure(0, weight=1)

# Iniciar el bucle principal de la ventana
ventana.geometry("600x400")
ventana.mainloop()
