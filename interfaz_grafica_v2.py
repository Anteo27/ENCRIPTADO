import tkinter as tk
from tkinter import filedialog, messagebox
import encriptar as lib


ruta = ""


def cifrar():
    global ruta
    if not ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo antes de cifrar.")
        return
    filekey = filedialog.askopenfilename()
    if not filekey or not ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo con la clave antes de cifrar.")
        return
    if "Clave_256.txt" in ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo que no sea la propia clave.")
        return
    if "Clave_256.txt" not in filekey:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un fichero válido de clave.")
        return
    clave = b''
    with open(filekey, 'rb') as infile:
        lectura = infile.read()
        clave += lectura
    if lib.encrypt_file(ruta, clave) == 1:
        messagebox.showwarning("Advertencia", "El archivo ya esta cifrado ")

    entrada.config(state='normal')
    entrada.delete(0, tk.END)
    entrada.config(state='readonly')

def descifrar():
    global ruta
    if not ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo antes de descifrar.")
        return
    filekey = filedialog.askopenfilename()
    if not filekey:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo con la clave antes de descifrar.")
        return
    if "Clave_256.txt" in ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo que no sea la propia clave.")
        return
    if "Clave_256.txt" not in filekey:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un fichero válido de clave.")
        return
    
    clave = b''
    with open(filekey, 'rb') as infile:
        lectura = infile.read()
        clave += lectura
    if lib.decrypt_file(ruta, clave) == 1:
        messagebox.showwarning("Advertencia", "El archivo ya esta descifrado ")
    
    entrada.config(state='normal')
    entrada.delete(0, tk.END)
    entrada.config(state='readonly')


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

# Crear ventana principal
ventana = tk.Tk()
ventana.title('Cifrador y Descifrador')
ventana.configure(background="red")

# Crear un marco para los widgets
marco = tk.Frame(ventana, padx=10, pady=10, bg="lightblue")
marco.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Crear un botón para seleccionar un archivo
boton_seleccionar_archivo = tk.Button(marco, text="Seleccionar archivo", command=seleccionar_archivo, bg="white", fg="black")
boton_seleccionar_archivo.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

# Crear un widget de entrada de texto
entrada = tk.Entry(marco, state='readonly', bg="white")
entrada.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

etiqueta = tk.Label(marco, text="", bg="lightblue", fg="black")
etiqueta.grid(row=2, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

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
