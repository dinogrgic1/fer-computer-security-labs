from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def AES_encrypt(key, plaintext):
    cipher = AES.new(m, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return (ciphertext, nonce, tag)

def AES_decrypt(key, ciphertext, nonce, tag):
    cipher = AES.new(m, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")

master_pass = input("Upišite master passowrd\n")
salt = get_random_bytes(16)

keys = PBKDF2(master_pass, salt, 64, count=1000000, hmac_hash_module=SHA512)
m = keys[:32]
v = keys[32:]

#print(m)
#print(v)

val = AES_encrypt(m, 'passowrd')

master_pass_unos = input('Unesite master password\n')
keys = PBKDF2(master_pass, salt, 64, count=1000000, hmac_hash_module=SHA512)
m = keys[:32]
v = keys[32:]

AES_decrypt(m, val[0], val[1], val[2])