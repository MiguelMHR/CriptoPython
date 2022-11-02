# Librerias que se usan
import json                                     # Libreria para manejar archivos JSON
from Crypto.Random import get_random_bytes      # Funciones para la generación de clave
from Crypto.Hash import HMAC, SHA256            # Funciones para el manejo de HMAC
from Crypto.Cipher import AES                   # Funciones para el manejo de AES
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


enter_sys = False                                             # Variable que controla la autenticación del usuario en el sistema
exit_program = False                                          # Variable que controla el cierre del programa


###################     CLASE USER, MÉTODOS ASOCIADOS Y FUNCIONES EXTERNAS   ########################

class User():
    """
    Clase para crear un usuario
    User: Nombre, Apellido, DNI, dinero, clave oculta (en este caso solo se necesita una clave común)
    """
    # Se genera la clave válida para todos los usuarios -> cifrado simétrico
    common_key = get_random_bytes(16)                   # Clave en bytearray 
    def __init__(self, nombre, apellido, DNI, dinero):
        self.nombre = nombre            # Nombre -> string sin espacios con el primer caracter en mayúscula                 
        self.apellido = apellido        # Apellido -> string sin espacios con el primer caracter en mayúscula
        self.DNI = DNI                  # DNI -> string de 8 caracteres integers con el último caracter en mayúscula
        self.dinero = float(dinero)     # Dinero -> float positivo
        self.__common_key = User.common_key
    
    def __str__(self):
        return f"Nombre: {self.nombre} {self.apellido} \nDNI: {self.DNI} \nDinero: {self.dinero}"
    
    def get_common_key(self):
        """
        Funcion que devuelve la clave publica
        Necesario para la ocultación de la clave
        """
        return self.__common_key

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
        # Si no está creado el JSON, se crea y se mete el primer elemento/ diccionario
        with open(ruta_json, "x", encoding="utf-8", newline="") as f:
            l_users = [dict]
            json.dump(l_users, f, indent=2)     # indent es para que se vea bonito
            f.close()
    except FileExistsError:
        # Si ya existe, sacamos los datos del JSON, apendamos la nueva cuenta/ diccionario y volvemos a escribir el JSON
        with open(ruta_json, "r", encoding="utf-8") as f:
            l_users = json.load(f)
            l_users.append(dict)
            f.close()
        with open(ruta_json, "w", encoding="utf-8", newline="") as f:
            json.dump(l_users, f, indent=2)
            f.close()
                

def validar_param_cuenta(nombre, apellido, dni, dinero):
    """Funcion que valida los parámetros de la cuenta"""

    # Cadenas comparativas de caracteres
    letras = "abcdefghijklmnñopqrstuvwxyzABCDEFGHIJKLMNÑOPQRSTUVWXYZ"
    numeros_y_coma = "0123456789,"
    numeros_DNI = "0123456789"
    dni_letras = "TRWAGMYFPDXBNJZSQVHLCKE"

    # validación del nombre
    if (len(nombre) == 0) or (nombre[0].islower()) or (" " in nombre) or (not letras in nombre):
        print("Nombre no válido")
        return False

    # validación del apellido
    if (type(apellido) != str) or (len(apellido) == 0) or (apellido[0].islower()) or (" " in apellido) or (not letras in apellido):
        print("Apellido no válido")
        return False

    # validación del DNI
    if (len(dni) != 9) or (dni[8] not in dni_letras) or ((dni[0:7]) not in numeros_DNI):
        print("DNI no valido")
        return False

    # Bucle para comprobar que solo hay una coma en el dinero
    counter_puntos = 0
    for elem in dinero:
        if elem == ",":
            counter_comas += 1
    if counter_comas > 1:
        print("Dinero no válido")
        return False

    # validación del dinero
    if (float(dinero) < 0) or ((not numeros_y_coma in dinero) and ((dinero[0] != ",")) and (dinero[-1] != ",")):
        print("Dinero no válido")
        return False

    # Si todo es correcto, devolvemos True
    return True


def comprobacion_parametros_password(password, PIN):
    """Función que valida la contraseña y el pin"""
    numeros = "0123456789"
    
    # validación del PIN
    if (len(PIN) != 8) or (PIN not in numeros):
        print("El PIN no es válido")
        return False

    # validación de la contraseña
    if len(password) == 0:
        print("La contraseña no es válida")
        return False

    # si todo es correcto, devolvemos True
    return True


def crearpasswordsJSON(dni):
    """Funcion que crea el JSON de contraseñas"""
    # Recogida de datos inicial con la interacción de la terminal
    print("\nSección de seguridad\n")
    password = input("Por favor, ingrese su contraseña: ")               # A la contraseña se le aplica un Hash
    PIN = input("Por favor, ingrese su PIN (8 dígitos numéricos): ")     # Permitirá iniciar sesión - 8 digitos
    # Si los parámetros no son válidos, devolvemos False
    if not comprobacion_parametros_password(password, PIN):
        print("No se han podido crear los datos de seguridad")
        return False
    
    # Implementación de HMAC para la contraseña
    # Pasamos las dos contraseñas a bytes
    secret = bytearray(password, encoding='utf8')
    key = bytearray(PIN, encoding='utf8')
    # Generamos el hash de la contraseña
    hash = HMAC.new(key, secret, SHA256)
    # Obtenemos el hash en forma legible
    hashed_password = hash.hexdigest()
    # Creamos el diccionario con los datos de seguridad con el password hasheado
    pass_dict = {"DNI": dni, "password": hashed_password}
    # Lo pasamos al JSON de contraseñas.json
    dicttoJSON(pass_dict, r_passwords)
    # Enseñamos al usuario que se ha creado correctamente las contraseñas
    print("\nContraseña creada con éxito\n")
    return True


def creacion_cuenta():
    """
    Funcion que crea una cuenta de usuario
    y guarda la infomación en un JSON de cuentas del sistema
    """
    # Recogida de datos inicial con la interacción de la terminal
    print("\nBienvenido a la sección de creacion de cuentas\n")
    nombre = input("Por favor, ingrese su nombre: ")
    apellido = input("Por favor, ingrese su apellido: ")
    DNI = input("Por favor, ingrese su DNI: ")
    dinero = input("Por favor, ingrese el dinero que desea depositar: ")
    # Si los datos introducidos son erroneos, se vuelve a pedir la información
    if not validar_param_cuenta(nombre, apellido, DNI, dinero):
        print("No se ha podido crear la cuenta")
        return

    # Si todo está bien, Creamos el usuario con los datos obtenidos
    usuario = User(nombre, apellido, DNI, dinero)
    # Lo pasamos al JSON de cuentas.json
    dicttoJSON(usuario.classtodict(),r_cuentas)
    # Invocamos la creación de la contraseña y su seguridad
    if crearpasswordsJSON(DNI):
        # Información final si se ha creado la contraseña correctamente
        print("\nCuenta creada exitosamente")
        print("\nInicia sesión para continuar")
    else:
        # Si no se han creado bien las contraseñas, se vuelven a pedir la información
        print("\nNo se ha podido crear la cuenta")	
        print("\nVuelve a intentarlo")	

# TODO: Comentar bien lo que queda 
# TODO: Lectura final de revisión
# TODO: Probar el código

def inicio_sesion():
    """
    Funcion que se encarga del iniciar sesion
    Retorna el usuario que se logueó obteniendo la información del JSON de cuentas.json
    """
    # Recogida de datos inicial con interacción de la terminal
    print("\nBienvenido a la sección de inicio de sesión\n")
    DNI = input("Por favor, ingrese su DNI: ")
    password = input("Por favor, ingrese su contraseña: ")
    PIN = input("Por favor, ingrese su PIN: ")
    
    # Abrimos el JSON de cuentas para obtener la información del usuario con el DNI proporcionado
    with open(r_cuentas, "r", encoding="utf-8") as f:
        # Cargamos el JSON en una lista de diccionarios
        l_users = json.load(f)
        f.close()
    # Variable para controlar si el usuario existe
    user_found = False
    for elem in l_users:
        # Para los elementos de la lista de diccionarios, si el DNI coincide con el proporcionado, 
        # creamos el usuario y decimos que lo hemos encontrado
        if elem["DNI"] == DNI: 
            user = User(elem["nombre"], elem["apellido"], elem["DNI"], elem["dinero"])
            user_found = True
    if not user_found:
        # Si no se ha encontrado el usuario, se muestra un mensaje de error y se vuelve al buclee principal
        print("\nEl usuario no existe")
        # l_results[0] -> usuario (en este caso None porque no existe) y l_results[1] -> booleano que indica si se ha logueado
        l_results = [None, False]
        return l_results
    
    # El siguiente bloque de código tiene un funcionamiento similar al anterior
    with open(r_passwords, "r", encoding="utf-8") as f:
        l_passwords = json.load(f)
        f.close()
    password_found = False
    for elem in l_passwords:
        # En este caso, si el DNI coincide, se comprueba la contraseña como en crearpasswordsJSON
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
    # Retornamos el usuario y un booleano que indica si se ha logueado
    l_results = [user, password_found]
    return l_results
        
def transaccion(user, usuario_a_transferir):
    """
    Funcion que se encarga de realizar la transaccion
    """
    dinero_a_enviar = input("\nPor favor, Ingrese el dinero que desea enviar: ")
    # Encriptación de la transacción -> dinero a enviar
    bin_dinero = dinero_a_enviar.encode("utf-8")    # Convertimos el dinero a enviar a binario -> es lo mismo que usar bytearray
    clave = user.get_common_key()                   # Obtenemos la clave pública del usuario que envía el dinero -> Está ya en bytearray
    encriptacion = AES.new(clave, AES.MODE_CTR)     # Creamos el objeto AES con la clave pública y el modo CTR (Counter mode) -> más recomendable
    enc_datos = encriptacion.encrypt(bin_dinero)    # Encriptamos los datos
    decriptacion = AES.new(clave, AES.MODE_CTR, nonce=encriptacion.nonce)
    mnsj_bin = decriptacion.decrypt(enc_datos)      # Desencriptamos los datos
    mnsj = mnsj_bin.decode("utf-8")                 # Convertimos el mensaje a string
    if mnsj == dinero_a_enviar:
        print("\nTransacción protegida correctamente")
        user.retiro(float(dinero_a_enviar))
        usuario_a_transferir.ingreso(float(dinero_a_enviar))

        with open(r_cuentas, "r", encoding="utf-8") as f:
            l_users = json.load(f)
            for elem in l_users:
                if elem["DNI"] == user.get_DNI():
                    elem["dinero"] = user.get_dinero()
                elif elem["DNI"] == usuario_a_transferir.get_DNI():
                    elem["dinero"] = usuario_a_transferir.get_dinero() 
            f.close()
        with open(r_cuentas, "w", encoding="utf-8", newline="") as f:
            json.dump(l_users, f, indent=2) 
            f.close()  

        user.dicttoJSON(usuario_a_transferir.classtodict(), r_cuentas)
    else:
        print("\nError en la transacción")
        return
        
    

#################################                 MAIN PROGRAM                 ##############################################
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
            f.close()
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
            if (input("\n¿Desea realizar otra transacción? (s/n): ") == "n"):
                enter_sys = False
                if (input("\n¿Desea salir del programa? (s/n): ") == "s"):
                    print("\nGracias por usar el programa\n")
                    enter_sys = False
                    exit_program = True








    
    




