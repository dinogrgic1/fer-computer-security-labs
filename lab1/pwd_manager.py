import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

FILE_PATH = 'vault.bin'

PBKDF2_KEY_SIZE = 32
PBKDF2_ITTERATIONS = 1000000
PBKDF2_SALT_SIZE = 16

AES_TAG_SIZE = 16
AES_NONCE_SIZE = 16

AES_NONCE_POSITION = PBKDF2_SALT_SIZE
AES_TAG_POSITION = AES_NONCE_POSITION + AES_TAG_SIZE

VAULT_HEADER_SIZE = PBKDF2_SALT_SIZE + AES_TAG_SIZE + AES_NONCE_SIZE
VAULT_EMPTY = '==vault=='

def AES_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    if type(plaintext) is bytes:
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    else:
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return (ciphertext, nonce, tag)


def AES_decrypt(key, ciphertext, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        raise Exception("Key incorrect or message corrupted")

def key_password_derivation(master_pass=None, salt=get_random_bytes(PBKDF2_SALT_SIZE)):
    if master_pass is None:
        master_pass = input("Input master password: ")
    keys = PBKDF2(master_pass, salt, PBKDF2_KEY_SIZE,
                  count=PBKDF2_ITTERATIONS, hmac_hash_module=SHA512)
    return (keys, salt)

def vault_init():
    key, salt = key_password_derivation()

    newfile = open(FILE_PATH, 'wb')
    newfile.write(salt)

    vault, nonce, tag = AES_encrypt(key, VAULT_EMPTY)
    newfile.write(nonce)
    newfile.write(tag)

    newfile.write(vault)
    print(salt,nonce,tag)
    newfile.close()

def vault_put_password(master_password, address):
    vault_file = open(FILE_PATH, 'r+b')
    password = input(f"Password for {address} will be: ")

    vault_file_content = vault_file.read()
    vault_header = vault_file_content[:VAULT_HEADER_SIZE]
    vault_body = vault_file_content[VAULT_HEADER_SIZE:]

    salt = vault_header[:PBKDF2_SALT_SIZE]
    nonce = vault_header[AES_NONCE_POSITION: AES_TAG_POSITION]
    tag = vault_header[AES_TAG_POSITION:]

    key, salt = key_password_derivation(master_password, salt)

    vault_body = AES_decrypt(key, vault_body, nonce, tag)
    if  vault_body == VAULT_EMPTY.encode('utf-8'):
        vault_body = b''
    vault_body += f'{address}\t{password}\n'.encode('utf-8')
    
    ciphertext, nonce, tag = AES_encrypt(key, vault_body)
    vault_file.truncate(0)
    vault_file.seek(0)
    vault_file.write(salt)
    vault_file.write(nonce)
    vault_file.write(tag)

    vault_file.write(ciphertext)

def vault_get_password(address):
    pass

def parse_args(args):
    try:
        if args[1] == 'init':
            vault_init()
        elif args[1] == 'put':
            vault_put_password(args[2], args[3])
        elif args[1] == 'get':
            vault_get_password(args[3])
        else:
            raise Exception("Inavlid action.")
    except IndexError:
        print("Function argument is not defined.")

if __name__ == "__main__":
    parse_args(sys.argv)