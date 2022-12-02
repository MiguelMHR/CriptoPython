###################     LIBRERIAS USADAS    #####################
import json                                     # Libreria para manejar archivos JSON
from Crypto.Random import get_random_bytes      # Funciones para la generación de clave
from Crypto.Hash import HMAC, SHA256            # Funciones para el manejo de HMAC
from Crypto.Cipher import AES                   # Funciones para el manejo de AES
from pathlib import Path                        # Función para los paths del JSON


###################    MANEJO DE JSONS    ###################
"""
# TODO: Cambiar rutas antes de presentar trabajo
CUIDADO, esta ruta está definida para nuestro equipo
para que funcione en su equipo, debe cambiarlo a su ruta absoluta de los JSON en
r_cuentas y en r_passwords
"""
home = str(Path.home())
r_cuentas = home + "\clonedRepos\CriptoPython"               # Ruta raw del JSON de cuentas de usuarios
r_passwords = home + "\clonedRepos\CriptoPython"             # Ruta raw del JSON de contraseñas


###################     CLASE USER, MÉTODOS ASOCIADOS Y FUNCIONES EXTERNAS   ########################

#TODO: Crear aquí las claves privada y pública QUE TENDRÁ EL BANCO, mirar foto: https://cutt.ly/n1FyLT3
# Luego, ciframos con asimétrico la clave que se usará en simétrico para cifrar los datos de la cuenta
# El usuario tiene la clave simétrica y se la tiene que mandar al banco con asimétrico para que
# el banco pueda hacer el cifrado simétrico de la parte 1   

class User():
    """
    Clase para crear un usuario
    User: Nombre, Apellido, DNI, dinero, clave oculta (en este caso solo se necesita una clave común)
    """
    # Se genera la clave válida para todos los usuarios -> cifrado simétrico
    common_key = get_random_bytes(16)                    # Clave en bytearray 
    def __init__(self, nombre, apellido, DNI, dinero):
        self.nombre = nombre            # Nombre -> string sin espacios con el primer caracter en mayúscula                 
        self.apellido = apellido        # Apellido -> string sin espacios con el primer caracter en mayúscula
        self.DNI = DNI                  # DNI -> string de 8 caracteres integers con el último caracter en mayúscula
        self.dinero = float(dinero)     # Dinero -> float positivo
        self.__common_key = User.common_key  # Mensaje que se debe codificar para el cifrado asimétrico
    
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
        """
        Funcion que se encarga de retirar dinero de la cuenta
        Si hay suficiente dinero, se retira y se devuelve True
        Si falta dinero, se devuelve False y se printea un mensaje de error
        """
        if dinero <= self.dinero:
            self.dinero -= dinero
            return True
        else:
            print("No tiene suficiente dinero en su cuenta")
            return False	
    
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
    letras_min = ("a","b","c","d","e","f","g","h","i","j","k", "l","m","n","ñ","o","p","q","r","s","t","u","v","w","x","y","z")
    letras_mayus = ("A","B","C","D","E","F","G","H","I","J","K","L","M","N","Ñ","O","P","Q","R","S","T","U","V","W","X","Y","Z")
    numeros_y_punto = ("0","1","2","3","4","5","6","7","8","9",".")
    numeros_DNI = ("0","1","2","3","4","5","6","7","8","9")
    dni_letras = ("T","R","W","A","G","M","Y","F","P","D","X","B","N","J","Z","S","Q","V","H","L","C","K","E")
    
    # Bucle de comprobación de nombre
    for i in range(len(nombre)):
        if ((nombre[i] not in letras_min) and (nombre[i] not in letras_mayus)) or (nombre[i] == " "):
            print("Nombre no válido")
            return False

    # validación del nombre
    if (len(nombre) == 0) or (nombre[0].islower()):
        print("Nombre no válido")
        return False

    # Bucle de comprobación de apellido
    for elem in apellido:
        if ((apellido[i] not in letras_min) and (apellido[i] not in letras_mayus)) or (elem == " "):
            print("Apellido no válido")
            return False
    # validación del apellido
    if (len(apellido) == 0) or (apellido[0].islower()):
        print("Apellido no válido")
        return False
    
    # Bucle de comprobación de DNI
    for i in range(len(dni)):
        if i == 8:
            if dni[i] not in dni_letras:
                print("DNI no válido")
                return False
        else:
            if dni[i] not in numeros_DNI:
                print("DNI no válido")
                return False
    # validación del DNI
    if (len(dni) != 9):
        print("DNI no valido")
        return False

    # Bucle para comprobar que solo hay un punto en el dinero
    counter_puntos = 0
    for elem in dinero:
        if elem == ".":
            counter_puntos += 1
        if elem not in numeros_y_punto:
            print("Dinero no válido")
            return False
    if counter_puntos > 1:
        print("Dinero no válido")
        return False

    # validación del dinero
    if (dinero[0] == ".") or (dinero[-1] == "."):
        print("Dinero no válido")
        return False

    # Si todo es correcto, devolvemos True
    return True


def comprobacion_parametros_password(password, PIN):
    """Función que valida la contraseña y el pin"""
    numeros = ("0","1","2","3","4","5","6","7","8","9")
    
    # Bucle de validación de PIN
    for elem in PIN:
        if elem not in numeros:
            print("PIN no válido")
            return False
    # validación del PIN
    if (len(PIN) != 8):
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
    
    #############    HMAC    ##################
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
    dinero = input("Por favor, ingrese el dinero que desea depositar (formato n.n): ")
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
        # Si no se ha encontrado el usuario, se muestra un mensaje de error y se vuelve al bucle principal
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
                print("\nInicio de sesión exitoso\n")
    if not password_found:
        # Si no se ha encontrado la contraseña, se muestra un mensaje de error y se vuelve al bucle principal
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
    # Pedimos el dinero de la transacción, que va a ser el mensaje a encriptar
    dinero_a_enviar = input("\nPor favor, ingrese el dinero que desea enviar (formato n.n): ")
    
    #####    Encriptación de la transacción    ######
    # Convertimos el dinero a enviar a binario -> es lo mismo que usar bytearray
    bin_dinero = dinero_a_enviar.encode("utf-8")    
    # Creamos el objeto AES con la clave del usuario emisor y el modo CTR (Counter mode) -> más recomendable
    encriptacion = AES.new(user.get_common_key(), AES.MODE_CTR) 
    # Encriptamos los datos
    enc_datos = encriptacion.encrypt(bin_dinero)  
    # Creamos el objeto AES con la clave del usuario receptor y el modo CTR (Counter mode) -> más recomendable
    decriptacion = AES.new(usuario_a_transferir.get_common_key(), AES.MODE_CTR, nonce=encriptacion.nonce)
    # Desencriptamos los datos
    mnsj_bin = decriptacion.decrypt(enc_datos) 
    # Convertimos el mensaje a string
    mnsj = mnsj_bin.decode("utf-8")                              
    if mnsj == dinero_a_enviar:
        # Si el mensaje es el mismo, se ha realizado la transacción segura correctamente
        print("\nTransacción protegida correctamente\n")
        # Realizamos las operaciones de dinero
        if not user.retiro(float(dinero_a_enviar)):
            # Si no se ha podido realizar el retiro, se muestra un mensaje de error
            print("\nNo se puede realizar la transferencia")
            return
        # Si se ha podido realizar el retiro, se realiza el ingreso
        usuario_a_transferir.ingreso(float(dinero_a_enviar))
        # Actualizamos el JSON de cuentas
        with open(r_cuentas, "r", encoding="utf-8") as f:
            l_users = json.load(f)
            for elem in l_users:
                if elem["DNI"] == user.DNI:
                    elem["dinero"] = user.dinero
                elif elem["DNI"] == usuario_a_transferir.DNI:
                    elem["dinero"] = usuario_a_transferir.dinero
            f.close()
        with open(r_cuentas, "w", encoding="utf-8", newline="") as f:
            json.dump(l_users, f, indent=2) 
            f.close()  
        print("\nTransacción realizada correctamente")
    else:
        # Si el mensaje no es el mismo, se ha producido un error en la encriptación
        print("\nError en la transacción")
        return
        
    

#################################                 MAIN PROGRAM                 ##############################################
"""
En esta sección de código se ejecuta el programa principal
Tenemos dos loops controlados por las variables globales enter_sys y exit_program
enter_sys -> controla el acceso al sistema de transacciones
exit_program -> controla la salida del programa
Inicializadas a False, se vuelven True cuando se accede al sistema o se sale del programa
Esto permite que el programa se ejecute hasta que el usuario decida salir y tengamos
una interacción óptima con el usuario mediante la terminal
"""

enter_sys = False
exit_program = False

while(not exit_program):
    # Mientras no se haya salido del programa, se ejecuta el programa
    print("\nBienvenido a la simulación de la banca en linea\n")
    init_oper = input("Por favor, seleccione el método de entrada al sistema ('crear cuenta', 'iniciar sesión' o 'salir'): ")
    if init_oper == "crear cuenta":
        # Si se selecciona 'crear cuenta', se invoca a la función de creación de cuenta
        creacion_cuenta()
        # Una vez creada la cuenta ya se puede iniciar sesión
    elif init_oper == "iniciar sesión":
        # Si se selecciona 'iniciar sesión', se invoca a la función de inicio de sesión
        l_results = inicio_sesion()
        if l_results[1]:
            # Si se devuelve true en inicio_sesión, se ha logueado correctamente
            print("\nBienvenido a la sección de transacciones\n")
            # Creamos un objeto usuario con los datos del usuario logueado
            init_user = l_results[0]
            # Podemos acceder a las transacciones
            enter_sys = True
        else:
            # Si se devuelve false en inicio_sesión, no se ha logueado correctamente, por lo que no se puede acceder a las transacciones
            print("\nNo se pudo iniciar sesión")
            print("\nPor favor, vuelva a intentarlo")
              
    elif init_oper == "salir":
        # Si se selecciona 'salir', se sale del programa y no se entra a las transacciones
        print("\nGracias por usar el programa\n")
        exit_program = True
    
    else:
        print("\nPor favor, seleccione una opción válida")
    
    while(enter_sys):
        # Mientras queramos hacer transacciones, se ejecuta el programa para encontrar al usuario a transferir
        usuario_a_transferir = input("\nPor favor, ingrese el DNI del usuario al que desea transferir dinero: ")
        with open(r_cuentas, "r", encoding="utf-8") as f:
            # Abrimos el JSON de cuentas para encontrar al destinatario
            l_users = json.load(f)
            f.close()
        # Creamos el booleano para saber si se ha encontrado al usuario
        user_found = False
        for elem in l_users:
            if elem["DNI"] == usuario_a_transferir:
                # Si coinciden los DNI, se ha encontrado al usuario y se crea el segundo user
                user_found = True
                transfer_user = User(elem["nombre"], elem["apellido"], elem["DNI"], elem["dinero"])
        if not user_found:
            # Si no se encuentra, se volverá a ejecutar la transacción
            print("\nEl usuario a transferir no existe")
            continue
        else:    
            transaccion(init_user, transfer_user)
            if (input("\n¿Desea realizar otra transacción? (s/n): ") == "n"):
                enter_sys = False
                if (input("\n¿Desea salir del programa? (s/n): ") == "s"):
                    print("\nGracias por usar el programa\n")
                    enter_sys = False
                    exit_program = True
