# Librerias que se usan
import json     # Libreria para manejar archivos JSON
import random   # Libreria para generar claves aleatorias
import Crypto   # Libreria para encriptar y funciones hash

"""
Clase que se encarga de crear los usuarios y guardarlos en un archivo JSON
User: Nombre, Apellido, DNI, contraseña, dinero, clave (en este caso solo se necesita la clave publica)
"""

class User:
    # Todos los usuarios tendrán la misma clave
    # clave = Crypto.generate_key()
    def __init__(self, nombre, apellido1, apellido2, dni, password, dinero):
        """Constructor de la clase User"""
        self.nombre = nombre
        self.apellido1 = apellido1
        self.apellido2 = apellido2
        self.dni = dni
        self.password = password # lo he llamado así para evitar la ñ
        self.dinero = dinero
    
    def ingreso(self, dinero):
        """Funcion que se encarga de ingresar dinero a la cuenta"""
        self.money += dinero
    
    def retiro(self, dinero):
        """Funcion que se encarga de retirar dinero de la cuenta"""
        self.money -= dinero


print("Bienvenido a la simulación de la banca en linea\n")
n_usuarios = input("Por favor ingrese el número de usuarios que desea crear: ")
l_usuarios = []

# TODO: pasar esto a una función creación de cuenta y llamarla desde aquí
# TODO: crear una función de chequeo de parámetros introducidos por el usuario (no unitests pero basarse en software)
# TODO: hacer funciones criptográficas para encriptar y desencriptar los datos y hashes
for i in range(int(n_usuarios)):
    nombre = input(f"Ingrese el nombre del usuario {i}: ")
    apellido1 = input(f"Ingrese el primer apellido del usuario {i}: ")
    apellido2 = input(f"Ingrese el segundo apellido del usuario {i}: ")
    dni = input(f"Ingrese el DNI del usuario {i}: ")
    password = input(f"Ingrese la contraseña del usuario {i}: ")
    dinero= input(f"Ingrese la cantidad de dinero que desea ingresar en la cuenta del usuario {i}: ")
    usuario = User(nombre, apellido1, apellido2, dni, password, dinero)
    l_usuarios.append(usuario)
    print("Usario creado con exito\n")


    
    




