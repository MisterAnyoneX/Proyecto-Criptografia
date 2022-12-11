from Crypto.Cipher import AES
from secrets import token_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes


#####ALGORITMO DE DIFFIE HELLMAN
#PREGUNTANDO POR NÚMERO PRIMO Y RAIZ PRIMITIVA
p = int(input("ingresar un numero primo P: "))    #numeros primos grandes   71
g = int(input("ingresar una raiz primitiva de P, G: "))   #g^(p-1)===1         7  

#PRIVATE VALUES DE SENSOR Y SERVIDOR
SensorValue= int(input("Sensor: escoger un numero aleatorio entre 2 y g-2: "))  #5
ServerValue=int(input("Servidor: escoger un numero aleatorio entre 2 y g-2: "))       #12

#CALCULO DE LLAVES PÚBLICAS
publicSensorKey= g**SensorValue %p
publicServerKey= g**ServerValue %p

#LLAVE PRIVADA COMÚN ENTRE SENSOR Y SERVIDOR
key1= publicServerKey**SensorValue %p
key2=publicSensorKey**ServerValue %p

if (key1 == key2):
    password=key1

print('la llave secreta compartida es: ',password)
print('sin embargo, esta contraseña no es compatible con el algortimo AES, por lo que es necesario alterarla usando una funcion de derivacion de llave.\n')



#FUNCION DE DERIVACIÓN PARA IMPRLEMENTAR LLAVE COMO CIFRADO EN AES
salt = get_random_bytes(16)
key = PBKDF2(password, salt, 16, count=1000000, hmac_hash_module=SHA512)
print('llave secreta luego de la derivacion y compatible con el algoritmo AES: ',key)
def encrypt(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce= cipher.nonce #some random bytes 
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce,ciphertext,tag

def decrypt(nonce,ciphertext,tag):
    cipher=AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext=cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

print('Temperaturas recopiladas por lo sensores para el dia de hoy: ')
temperaturas=('23 24 25 26 27 29')
print(temperaturas)

nonce, ciphertext,tag =encrypt(temperaturas)
plaintext=decrypt(nonce,ciphertext,tag)
print(f'Cipher text: {ciphertext}')
if not plaintext:
    print('message is corrupted')
else:
    print(f'plain text: {plaintext}')


