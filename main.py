# Librerias que se usan
import json                                     # Libreria para manejar archivos JSON
from Crypto.Random import get_random_bytes      # Funciones para la generación de clave
from Crypto.Hash import HMAC, SHA256            # Funciones para el manejo de HMAC
from pathlib import Path                        # Función para los paths del JSON

"""
CUIDADO, esta ruta está definida para nuestro equipo
para que funcione en su equipo, debe cambiarlo a su ruta absoluta de los JSON en
r_cuentas y en r_passwords
"""
home = str(Path.home())
r_cuentas = home + "\ClonedRepositories\CryptoPython\cuentas.json"               # Ruta raw del JSON de cuentas de usuarios
r_passwords = home + "\ClonedRepositories\CryptoPython\passwords.json"         # Ruta raw del JSON de contraseñas


enter_sys = False                                             # Variable que controla la autenticación del usuario
exit_program = False                                          # Variable que controla el cierre del programa

"""
Clase para crear un usuario
User: Nombre, Apellido, DNI, contraseña, PIN, dinero, clave (en este caso solo se necesita la clave publica)
"""

class User():
    # Se genera la clave publica válida para todos los usuarios
    common_key = get_random_bytes(16)
    def __init__(self, nombre, apellido, DNI, password, PIN, dinero):
        self.nombre = nombre
        self.apellido = apellido
        self.DNI = DNI
        self.password = password
        self.PIN = PIN
        self.dinero = dinero
        self.__common_key = User.common_key
    
    def __str__(self):
        return f"Nombre: {self.nombre} {self.apellido} \nDNI: {self.DNI} \nDinero: {self.dinero}"

    def ingreso(self, dinero):
        """Funcion que se encarga de ingresar dinero a la cuenta"""
        self.dinero += dinero
        
    def retiro(self, dinero):
        """Funcion que se encarga de retirar dinero de la cuenta"""
        self.dinero -= dinero

    

def creacion_cuenta():
    print("\nBienvenido a la creacion de cuentas\n")
    nombre = input("Por favor, Ingrese su nombre: ")
    apellido = input("\nPor favor, Ingrese su apellido: ")
    DNI = input("\nPor favor, Ingrese su DNI: ")
    password = input("\nPor favor, Ingrese su contraseña: ")                          # A la contraseña se le aplica un Hash
    PIN = input("\nPor favor, Ingrese su PIN (8 dígitos numéricos): ")                # Permitirá iniciar sesión - 8 digitos
    dinero = input("\nPor favor, Ingrese el dinero que desea depositar: ")
    usuario = User(nombre, apellido, DNI, password, PIN, dinero)
    u_json = {'nombre': usuario.nombre, 'apellido': usuario.apellido, 'DNI': usuario.DNI, 'dinero': usuario.dinero}
    with open(r_cuentas, "a+") as f:
        json.dump(u_json, f)
    print("\nCuenta creada exitosamente")
    return usuario  


    

# def inicio_sesion():
#     """Funcion que se encarga de iniciar sesion
#     Retorna el usuario que se logueó pillando la info del JSON
#     """
#     print("Bienvenido a la sesion de inicio de cuenta`\n")
#     DNI = input("Por favor, Ingrese su DNI: ")
#     password = input("Por favor, Ingrese su contraseña: ")
#     PIN = input("Por favor, Ingrese su PIN (8 dígitos numéricos): ")

#     return usuario

# def transaccion(usuario_emisor, usuario_receptor, dinero):
#     """Funcion que se encarga de realizar una transaccion entre dos usuarios"""



while(not exit_program):
    print("\nBienvenido a la simulación de la banca en linea\n")
    init_oper = input("Por favor, seleccione el método de entrada al sistema ('crear cuenta' o 'iniciar sesión'): ")
    if init_oper == "crear cuenta":
        """Si se selecciona iniciar sesión, se invoca a la función de inicio de sesión"""
        creacion_cuenta()
    elif init_oper == "salir":
        print("\nGracias por usar el programa\n")
        exit_program = True
    else:
        exit
# TODO: pasar esto a una función creación de cuenta y llamarla desde aquí
# TODO: crear una función de chequeo de parámetros introducidos por el usuario (no unitests pero basarse en software)
# TODO: hacer funciones criptográficas para encriptar y desencriptar los datos y hashes
# for i in range(int(n_usuarios)):
#     nombre = input(f"Ingrese el nombre del usuario {i}: ")
#     apellido1 = input(f"Ingrese el primer apellido del usuario {i}: ")
#     apellido2 = input(f"Ingrese el segundo apellido del usuario {i}: ")
#     dni = input(f"Ingrese el DNI del usuario {i}: ")
#     password = input(f"Ingrese la contraseña del usuario {i}: ")
#     dinero= input(f"Ingrese la cantidad de dinero que desea ingresar en la cuenta del usuario {i}: ")
#     usuario = User(nombre, apellido1, apellido2, dni, password, dinero)
#     l_usuarios.append(usuario)
#     print("Usario creado con exito\n")




    
    




