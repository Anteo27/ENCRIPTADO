import tkinter as tk
from tkinter import filedialog, ttk, simpledialog, messagebox
from ttkthemes import ThemedTk
import encriptar
import os
ruta=""
def cifrar():
    global ruta
    if not ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo antes de cifrar.")
        return
    filekey=filedialog.askopenfilename()
    if not filekey:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo con la clave antes de cifrar.")
        return
    if "Clave_256.txt" in ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo que no sea la propia clave.")
        return
    if "Clave_256.txt" not in filekey:
         messagebox.showwarning("Advertencia", "Por favor, selecciona un fichero valido de clave.")
         return
    respuesta=b''
    with open(filekey, 'rb') as infile:
            lectura=infile.read()
            respuesta+=lectura
    encriptar.encrypt_file(ruta,respuesta)
    entrada.state(['!readonly'])
    entrada.delete(0, tk.END)
    entrada.state(['readonly'])

def descifrar():
    global ruta
    if not ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo antes de descifrar.")
        return
    filekey=filedialog.askopenfilename()
    if not filekey:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo con la clave antes de descifrar.")
        return
    if "Clave_256.txt" in ruta:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo que no sea la propia clave.")
        return
    if "Clave_256.txt" not in filekey:
         messagebox.showwarning("Advertencia", "Por favor, selecciona un fichero valido de clave.")
         return
    respuesta=b''
    with open(filekey, 'rb') as infile:
            lectura=infile.read()
            respuesta+=lectura
    encriptar.decrypt_file(ruta,respuesta)
    entrada.state(['!readonly'])
    entrada.delete(0, tk.END)
    entrada.state(['readonly'])
nombre_Archivo=""
def seleccionar_archivo():
    global nombre_Archivo
    # Abre un cuadro de diálogo para seleccionar un archivo
    global ruta
    ruta = filedialog.askopenfilename()
    nombre_Archivo= os.path.basename(ruta)
    # Actualiza el widget de entrada con la ruta del archivo seleccionado
    entrada.state(['!readonly'])
    entrada.delete(0, tk.END)
    entrada.insert(0, nombre_Archivo)
    entrada.state(['readonly'])

def confirmar_cifrado():
    global nombre_Archivo
    if messagebox.askyesno("Confirmación", "¿Estás seguro de que deseas cifrar el archivo? "+nombre_Archivo):
        cifrar()  # Ejecuta la acción de cifrado si el usuario confirma
    entrada.delete(0, tk.END)
    nombre_Archivo=""
# Crea la ventana principal con un tema
ventana = ThemedTk(theme="arc")
ventana.title('Cifrador y Descifrador')

# Crea un marco para los widgets
marco = ttk.Frame(ventana, padding="100")
marco.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Crea un widget de entrada de texto
entrada = ttk.Entry(marco, text=nombre_Archivo)
entrada.grid(row=0, column=0, sticky=(tk.W, tk.E))
entrada.state(['readonly'])

# Crea los botones de cifrar y descifrar
boton_cifrar = ttk.Button(marco, text="Cifrar", command=confirmar_cifrado)
boton_cifrar.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)

boton_descifrar = ttk.Button(marco, text="Descifrar", command=descifrar)
boton_descifrar.grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)

# Crea un botón para seleccionar un archivo
boton_seleccionar_archivo = ttk.Button(marco, text="Seleccionar archivo", command=seleccionar_archivo)
boton_seleccionar_archivo.grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)

# Configura el marco para expandirse con la ventana
ventana.columnconfigure(0, weight=1)
ventana.rowconfigure(0, weight=1)
marco.columnconfigure(0, weight=1)

# Inicia el bucle principal de la ventana
ventana.mainloop()
