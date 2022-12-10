###################     LIBRERIAS USADAS    #####################
import json                                           # Libreria para manejar archivos JSON
from Crypto.Random import get_random_bytes            # Funciones para la generación de clave
from Crypto.Hash import HMAC, SHA256                  # Funciones para el manejo de HMAC y SHA 
from Crypto.Cipher import AES                         # Funciones para el manejo de AES
from Crypto.Signature import pkcs1_15                 # Funciones para el manejo de la firma digital
from base64 import b64encode, b64decode               # Funciones para el manejo del nonce en AES
from Crypto.PublicKey import RSA                      # Funciones de la generación de claves asimétrico
from Crypto.Cipher import PKCS1_OAEP                  # Funciones para el manejo de las claves asimétricos
from pathlib import Path                              # Función para los paths del JSON
import sys                                            # Librería usada para la finalización del programa

###################    MANEJO DE JSONS    ###################
"""
# TODO: Cambiar rutas antes de presentar trabajo
CUIDADO, esta ruta está definida para nuestro equipo
para que funcione en su equipo, debe cambiarlo a su ruta absoluta de los JSON en
r_cuentas y en r_passwords
"""
home = str(Path.home())
r_cuentas = home + "\ClonedRepositories\CriptoPython\cuentas.json"                   # Ruta raw del JSON de cuentas de usuarios
r_passwords = home + "\ClonedRepositories\CriptoPython\contraseñas.json"             # Ruta raw del JSON de contraseñas

# Se ha creado un archivo PEM con el pin del Banco hasheado con SHA256 fuera de este archivo como medida de seguridad
r_hashed_pin_bank = home + "\ClonedRepositories\CriptoPython\hashed_pin_bank.json"   # Ruta raw del JSON con el PIN del Banco hasheado

# Ruta con el archivo PEM de la clave privada de A y el certificado de A sacado de la PKI
r_priv_a = home + "\ClonedRepositories\CriptoPython\A\Akey.pem"
r_cert_a = home + "\ClonedRepositories\CriptoPython\A\Acert.pem" # Ruta raw del archivo PEM de la clave privada de A

###################     CLASE USER, MÉTODOS ASOCIADOS Y FUNCIONES EXTERNAS   ########################

# TODO: Crear aquí las claves privada y pública QUE TENDRÁ EL BANCO, mirar foto: https://cutt.ly/n1FyLT3
# video YT asimétrico + clave pública: https://www.youtube.com/watch?v=apn1BN6XMVo
# LINK PARA REPORT:
# https://securityboulevard.com/2020/05/types-of-encryption-5-encryption-algorithms-how-to-choose-the-right-one/
# ELEGIR EL MEJOR: RSA PUESTO QUE ES EL MÁS USADO Y SIMPLE Y POR LA IMPLEMENTACION CON PKI (ECC ES MÁS SEGURO PERO MENOS USADO)
#TODO: firma: https://github.com/JackCloudman/PyCrypto

# DATO CURIOSO: PKCS#1 OAEP does not guarantee authenticity of the message you decrypt. 
# Since the public key is not secret, everybody could have created the encrypted message. 
# Asymmetric encryption is typically paired with a digital signature.

# RAZONES PARA USAR PKCS_V1.5 en vez de PSS: https://www.cryptosys.net/pki/manpki/pki_rsaschemes.html (punto 4 y 5 de diferencias)
    

class User():
    """
    Clase para crear un usuario
    User: Nombre, Apellido, DNI, dinero
    """
       
    def __init__(self, nombre, apellido, DNI, dinero):
        self.nombre = nombre                                  # Nombre -> string sin espacios con el primer caracter en mayúscula                 
        self.apellido = apellido                              # Apellido -> string sin espacios con el primer caracter en mayúscula
        self.DNI = DNI                                        # DNI -> string de 8 caracteres integers con el último caracter en mayúscula
        self.dinero = float(dinero)                           # Dinero -> float positivo 

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
        return {"nombre": self.nombre, "apellido": self.apellido, "DNI": self.DNI}

def cifrado_asimetrico(sym_key):
    """
    Funcion que cifra la clave simétrica con la clave pública del banco
    """
    ####  CIFRADO ASIMÉTRICO  ####
    public_file = open("public_rsa.pem", "rb")              # Abrimos el archivo con la clave pública del banco
    read_public_file = public_file.read()                   # Leemos el archivo
    public_rsa = RSA.import_key(read_public_file)           # Clave pública del banco
    cifrador_rsa = PKCS1_OAEP.new(public_rsa)               # Cifrador asimétrico
    print("\nEncriptación asimétrica completada")
    public_file.close()                                     # Cerramos el archivo
    return cifrador_rsa.encrypt(sym_key)                    # Ciframos la clave simétrica con la clave pública del banco

def descifrado_asimétrico(sym_key_encrypted):
    """
    Funcion que se encarga de descifrar la clave simétrica del usuario con la clave privada del banco
    """
    ####  DESCIFRADO ASIMÉTRICO  ####
    private_file = open("private_rsa.pem", "rb")                                # Abrimos el archivo con la clave privada del banco
    read_private_file = private_file.read()                                     # Leemos el archivo
    private_rsa = RSA.import_key(read_private_file, passphrase=pin_bank)        # Clave privada del banco
    descifrador_rsa = PKCS1_OAEP.new(private_rsa)                               # Descifrador asimétrico
    msg_key_decrypted = descifrador_rsa.decrypt(sym_key_encrypted)              # Desciframos la clave simétrica 
    print("\nDesencriptación asimétrica completada")                                 
    private_file.close()                                                        # Cerramos el archivo                      
    return msg_key_decrypted                                                    # Devolvemos la clave simétrica en formato string

def firmar_transaccion(b_msg):
    """Función que firma la transacción cifrada con AES con la clave privada del banco"""
    private_file = open(r_priv_a, "rb")                                # Abrimos el archivo con la clave privada del banco
    read_private_file = private_file.read()                                     # Leemos el archivo
    private_rsa = RSA.import_key(read_private_file, passphrase=input("\nescribe contraseña de firma: "))        # Clave privada del banco
    hashed_b_msg = SHA256.new(b_msg)                                            # Hash del mensaje
    obj_pkcs1 = pkcs1_15.new(private_rsa)                                       # Creamos el objeto para firmar
    signature = obj_pkcs1.sign(hashed_b_msg)                                    # Firma del mensaje
    return signature                                                            # Devolvemos la firma y el hash del mensaje

def comprobar_firma(signature, b_msg):
    """Función que comprueba la firma de la transacción con la clave pública del banco"""
    public_file = open(r_cert_a, "rb")              # Abrimos el archivo con la clave pública del banco
    read_public_file = public_file.read()                   # Leemos el archivo
    public_rsa = RSA.import_key(read_public_file)           # Clave pública del banco
    hashed_b_msg = SHA256.new(b_msg)                        # Hash del mensaje
    try:
        obj_pkcs1 = pkcs1_15.new(public_rsa)
        signature = obj_pkcs1.verify(hashed_b_msg, signature)
        return True
    except (ValueError, TypeError):
        return False

def dicttoJSON(dict, ruta_json):
    """Funcion que convierte un diccionario en un JSON"""
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
    password = input("Por favor, ingrese su contraseña: ")                    # A la contraseña se le aplica un Hash
    pin_user = input("Por favor, ingrese su PIN (8 dígitos numéricos): ")     # Permitirá iniciar sesión - 8 digitos
    # Si los parámetros no son válidos, devolvemos False
    if not comprobacion_parametros_password(password, pin_user):
        print("No se han podido crear los datos de seguridad")
        return False
    
    #############    HMAC    ##################
    # Pasamos las dos contraseñas a bytes
    b_pass = bytearray(password, encoding='utf8')
    b_pin_user = bytearray(pin_user, encoding='utf8')
    # Generamos el hash de la contraseña
    hash = HMAC.new(b_pin_user, b_pass, SHA256)
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
        print("Cuenta creada exitosamente")
        print("\nInicia sesión para continuar\n")
    else:
        # Si no se han creado bien las contraseñas, se vuelven a pedir la información
        print("No se ha podido crear la cuenta")	
        print("\nVuelve a intentarlo\n")	

def inicio_sesion():
    """
    Funcion que se encarga del iniciar sesion
    Retorna el usuario que se logueó obteniendo la información del JSON de cuentas.json
    """
    # Recogida de datos inicial con interacción de la terminal
    print("\nBienvenido a la sección de inicio de sesión\n")
    DNI = input("Por favor, ingrese su DNI: ")
    password = input("Por favor, ingrese su contraseña: ")
    pin_user = input("Por favor, ingrese su PIN: ")
    
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
            key = bytearray(pin_user, encoding='utf8')
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
    
    ##############    ENCRIPTACIÓN TRANSACCIÓN -> SYM/ASYM    ##############
    
    # Convertimos el dinero a enviar a binario -> es lo mismo que usar bytearray
    bin_dinero = dinero_a_enviar.encode('utf-8')  
    # Clave simétrica que se debe codificar para el cifrado asimétrico -> Clave en bytearray   
    sym_key = get_random_bytes(16)   
    # Firmamos la transacción encriptada con AES
    signed_transaction = firmar_transaccion(bin_dinero)        
    # Creamos el objeto AES con la clave del usuario emisor y el modo CTR (Counter mode) -> más recomendable
    enc_AES = AES.new(sym_key, AES.MODE_CTR) 
    # Encriptamos los datos
    enc_sym = enc_AES.encrypt(bin_dinero)
    print("\nTransacción encriptada con cifrado asimétrico")   
    # Creamos el nonce y el ciphertext para la desencriptación
    enc_nonce = b64encode(enc_AES.nonce).decode('utf-8')
    enc_ciphertext = b64encode(enc_sym).decode('utf-8')
    # Encriptamos con asimétrico la clave simétrica
    print("\nEncriptando clave simétrica con cifrado asimétrico")
    enc_asym = cifrado_asimetrico(sym_key)
    # Desciframos con asimétrico la clave simétrica
    desenc_asym = descifrado_asimétrico(enc_asym)
    # Desencriptamos el nonce y el ciphertext
    dec_nonce = b64decode(enc_nonce)
    dec_ciphertext = b64decode(enc_ciphertext)
    # Creamos el objeto AES con la clave del usuario receptor y el modo CTR (Counter mode) -> más recomendable
    desenc_AES = AES.new(desenc_asym, AES.MODE_CTR, nonce=dec_nonce)
    # Desencriptamos los datos
    mnsj = desenc_AES.decrypt(dec_ciphertext).decode('utf-8')
    # Comprobamos la firma de la transacción encriptada con AES
    good_signature = comprobar_firma(signed_transaction, bin_dinero) 
    if good_signature:
        print("\nFirma verificada correctamente")
    else:
        print("\nFirma no verificada, se cerrará el programa")
        sys.exit()
    print("\nTransacción desencriptada con cifrado simétrico")
    
    ################    FIN ENCRIPTACIÓN DESENCRIPTACIÓN   ################
                                
    if mnsj == dinero_a_enviar:
        # Si el mensaje es el mismo, se ha realizado la transacción segura correctamente
        print("\nTransacción protegida correctamente")
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

### Variables globales ###
enter_sys = False
exit_program = False
validate_pin_bank = False

### CLAVES PARA EL CIFRADO ASIMÉTRICO ###
asym_keys = RSA.generate(2048)                                                       # Generamos las claves -> 2048 bits -> 256 bytes
pin_file = open(r_hashed_pin_bank, "r", encoding="utf-8")                            # Abrimos el fichero con el PIN Hasheado
pin_json = json.load(pin_file)                                                       # Cargamos el JSON
p_bank = pin_json[0]["pin"]                                                          # Obtenemos el PIN              
counter = 0                                                                          # Contador para el número de intentos de PIN                                     

while ((not validate_pin_bank) and (counter < 3)):                                   # Hacemos 3 intentos para acceder al sistema                             
    pin_bank = input("Por favor, introduzca el PIN privado del banco: ")             # PIN del banco -> donotshareitwithanyone
    b_pin_bank = bytearray(pin_bank, encoding='utf8')                                # Convertimos el PIN a bytes
    h_pin_bank = SHA256.new(data=b_pin_bank)                                         # Creamos el objeto SHA256
    if p_bank != h_pin_bank.hexdigest():                                             # Comparamos el pin del banco con el del fichero
        print("\nPIN incorrecto, vuelve a intentarlo\n")     
    else:
        print("\nPIN correcto\n")
        print("Inicio del programa activado")
        validate_pin_bank = True
    counter += 1
        
pin_file.close()

if not validate_pin_bank:                                                            # Si no se ha validado el PIN del banco, se sale del programa                 
    print("Demasiados intentos fallidos\n")
    print("El programa se cerrará\n")
    ### Cerramos el programa ###
    sys.exit()

                                                                                                                                                                                                               
# Después de validar el PIN del banco, se comienza la exportación de las claves
private_rsa = asym_keys.export_key(passphrase=pin_bank)
with open("private_rsa.pem", "wb") as f:
    f.write(private_rsa)
    f.close()
public_rsa = asym_keys.publickey().export_key()
with open("public_rsa.pem", "wb") as f:
    f.write(public_rsa)
    f.close()

###############         COMIENZA LA EJECUCIÓN DE LA BANCA         ###############
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
        print("\nPor favor, seleccione una opción válida\n")
    
    while(enter_sys):
        # Mientras queramos hacer transacciones, se ejecuta el programa para encontrar al usuario a transferir
        usuario_a_transferir = input("\nPor favor, ingrese el DNI del usuario al que desea transferir dinero (o salir del sistema): ")
        if usuario_a_transferir == "salir":
            # Si se selecciona 'salir', se sale del programa y no se entra a las transacciones
            print("\nGracias por usar el programa\n")
            enter_sys = False
            exit_program = True
            continue
        
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
