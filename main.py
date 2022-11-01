# Librerias que se usan
import json                                     # Libreria para manejar archivos JSON
from Crypto.Random import get_random_bytes      # Funciones para la generación de clave
from Crypto.Hash import HMAC, SHA256            # Funciones para el manejo de HMAC
from pathlib import Path                        # Función para los paths del JSON

"""
# TODO: Cambiar rutas antes de presentar trabajo
CUIDADO, esta ruta está definida para nuestro equipo
para que funcione en su equipo, debe cambiarlo a su ruta absoluta de los JSON en
r_cuentas y en r_passwords
"""
home = str(Path.home())
r_cuentas = home + "\ClonedRepositories\CriptoPython\cuentas.json"               # Ruta raw del JSON de cuentas de usuarios
r_passwords = home + "\ClonedRepositories\CriptoPython\passwords.json"           # Ruta raw del JSON de contraseñas


enter_sys = False                                             # Variable que controla la autenticación del usuario
exit_program = False                                          # Variable que controla el cierre del programa


"""
Clase para crear un usuario
User: Nombre, Apellido, DNI, contraseña, PIN, dinero, clave (en este caso solo se necesita la clave publica)
"""

class User():
    # Se genera la clave publica válida para todos los usuarios
    common_key = get_random_bytes(16)
    def __init__(self, nombre, apellido, DNI, dinero):
        self.nombre = nombre
        self.apellido = apellido
        self.DNI = DNI
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
    
    def classtodict(self):
        """Funcion que convierte la clase en un diccionario"""
        return {"nombre": self.nombre, "apellido": self.apellido, "DNI": self.DNI, "dinero": self.dinero}
    

def dicttoJSON(dict, ruta_json):
    """Funcion que convierte la clase en un JSON"""
    try:
        with open(ruta_json, "x", encoding="utf-8", newline="") as f:
            l_users = [dict]
            json.dump(l_users, f, indent=2)
    except FileExistsError as ex:
        with open(ruta_json, "r", encoding="utf-8") as f:
            l_users = json.load(f)
            l_users.append(dict)
        with open(ruta_json, "w", encoding="utf-8", newline="") as f:
            json.dump(l_users, f, indent=2)
                

def crearpasswordsJSON(dni):
    """Funcion que crea el JSON de contraseñas"""
    password = input("\nPor favor, Ingrese su contraseña: ")               # A la contraseña se le aplica un Hash
    PIN = input("\nPor favor, Ingrese su PIN (8 dígitos numéricos): ")     # Permitirá iniciar sesión - 8 digitos
    # TODO: validar parámetros password
    # comprobacion_parametros_password(password, PIN)
    
    # Implementación de HMAC
    secret = bytearray(password, encoding='utf8')
    key = bytearray(PIN, encoding='utf8')
    hash = HMAC.new(key, secret, SHA256)
    hashed_password = hash.hexdigest()
    pass_dict = {"DNI": dni, "password": hashed_password}
    dicttoJSON(pass_dict, r_passwords)

def creacion_cuenta():
    print("\nBienvenido a la creacion de cuentas\n")
    nombre = input("Por favor, Ingrese su nombre: ")
    apellido = input("\nPor favor, Ingrese su apellido: ")
    DNI = input("\nPor favor, Ingrese su DNI: ")
    dinero = input("\nPor favor, Ingrese el dinero que desea depositar: ")
    # TODO: validar parámetros user
    # comprobacion_parametros_user(nombre, apellido, DNI, password, PIN, dinero)
   
    usuario = User(nombre, apellido, DNI, dinero)
    dicttoJSON(usuario.classtodict(),r_cuentas)
    crearpasswordsJSON(DNI)
    
    print("\nCuenta creada exitosamente")
    print("\nInicia sesión para continuar")

def inicio_sesion():
    """
    Funcion que se encarga de iniciar sesion
    Retorna el usuario que se logueó pillando la info del JSON
    """
    
    print("\nBienvenido a la sección de inicio de sesión\n")
    DNI = input("Por favor, Ingrese su DNI: ")
    password = input("Por favor, Ingrese su contraseña: ")
    PIN = input("Por favor, Ingrese su PIN: ")
    with open(r_cuentas, "r", encoding="utf-8") as f:
        l_users = json.load(f)
    user_found = False
    for elem in l_users:
        if elem["DNI"] == DNI: 
            user = User(elem["nombre"], elem["apellido"], elem["DNI"], elem["dinero"])
            user_found = True
    
    if not user_found:
        print("\nEl usuario no existe")
        l_results = [None, False]
        return l_results
    
    with open(r_passwords, "r", encoding="utf-8") as f:
        l_passwords = json.load(f)
    password_found = False
    for elem in l_passwords:
        if elem["DNI"] == DNI:
            secret = bytearray(password, encoding='utf8')
            key = bytearray(PIN, encoding='utf8')
            hash = HMAC.new(key, secret, SHA256)
            hashed_password = hash.hexdigest()
            if elem["password"] == hashed_password:
                password_found = True
                print("\nInicio de sesión exitoso")
    
    if not password_found:
        print("\nContraseña o PIN incorrecto")
        l_results = [None, False]
        return l_results
    
    l_results = [user, password_found]
    return l_results
        
def transaccion(user, usuario_a_transferir):
    """
    Funcion que se encarga de realizar la transaccion
    """   
    # TODO: encriptar la cantidad de dinero a transferir
    
    




    

# def inicio_sesion():
#     
#     print("Bienvenido a la sesion de inicio de cuenta`\n")
#     DNI = input("Por favor, Ingrese su DNI: ")
#     password = input("Por favor, Ingrese su contraseña: ")
#     PIN = input("Por favor, Ingrese su PIN (8 dígitos numéricos): ")

#     return usuario

# def transaccion(usuario_emisor, usuario_receptor, dinero):
#     """Funcion que se encarga de realizar una transaccion entre dos usuarios"""


while(not exit_program):
    print("\nBienvenido a la simulación de la banca en linea\n")
    init_oper = input("Por favor, seleccione el método de entrada al sistema ('crear cuenta', 'iniciar sesión' o 'salir'): ")
    if init_oper == "crear cuenta":
        """Si se selecciona iniciar sesión, se invoca a la función de inicio de sesión"""
        creacion_cuenta()
    
    elif init_oper == "iniciar sesión":
        l_results = inicio_sesion()
        if l_results[1]:
            print("\nBienvenido a la sección de transacciones\n")
            init_user = l_results[0]
            enter_sys = True
        else:
            print("\nNo se pudo iniciar sesión")
            print("\nPor favor, vuelva a intentarlo")
            continue
        
        
    elif init_oper == "salir":
        print("\nGracias por usar el programa\n")
        exit_program = True
    
    while(enter_sys):
        usuario_a_transferir = input("\nPor favor, ingrese el DNI del usuario al que desea transferir dinero: ")
        with open(r_cuentas, "r", encoding="utf-8") as f:
            l_users = json.load(f)
        user_found = False
        for elem in l_users:
            if elem["DNI"] == usuario_a_transferir:
                user_found = True
                transfer_user = User(elem["nombre"], elem["apellido"], elem["DNI"], elem["dinero"])
        if not user_found:
            print("\nEl usuario a transferir no existe")
            continue
        if user_found:    
            transaccion(init_user, transfer_user)


# TODO: Al final del programa cerrar el archivo JSON y borrarlo





    
    




