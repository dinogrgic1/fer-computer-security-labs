import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

PBKDF2_KEY_SIZE = 32
PBKDF2_ITTERATIONS = 1000000
PBKDF2_SALT_SIZE = 16

AES_TAG_SIZE = 16
AES_NONCE_SIZE = 16
AES_NONCE_POSITION = PBKDF2_SALT_SIZE
AES_TAG_POSITION = AES_NONCE_POSITION + AES_TAG_SIZE

VAULT_PATH = 'vault.bin'
VAULT_EMPTY = '==vault=='
VAULT_HEADER_SIZE = PBKDF2_SALT_SIZE + AES_TAG_SIZE + AES_NONCE_SIZE
VAULT_ENTRY_SEPARATOR = '\n'
VAULT_ADDRESS_SEPARATOR = '\t'
VAULT_PADDING_SIZE = 256

def AES_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    if type(plaintext) is bytes:
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    else:
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('ascii'))
    return (ciphertext, nonce, tag)

def AES_decrypt(key, ciphertext, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        raise Exception("Master password is incorrect or vault is corrupted.")

def key_password_derivation(master_pass=None, salt=get_random_bytes(PBKDF2_SALT_SIZE)):
    keys = PBKDF2(master_pass, salt, PBKDF2_KEY_SIZE,
                  count=PBKDF2_ITTERATIONS, hmac_hash_module=SHA512)
    return (keys, salt)

def get_vault_header(vault_content):
    vault_header = vault_content[:VAULT_HEADER_SIZE]
    salt = vault_header[:PBKDF2_SALT_SIZE]
    nonce = vault_header[AES_NONCE_POSITION: AES_TAG_POSITION]
    tag = vault_header[AES_TAG_POSITION:]

    return (salt, nonce, tag)

def vault_init(master_pass):
    key, salt = key_password_derivation(master_pass)
    vault_file = open(VAULT_PATH, 'wb')
    vault_file.write(salt)

    vault, nonce, tag = AES_encrypt(key, VAULT_EMPTY)
    vault_file.write(nonce)
    vault_file.write(tag)
    vault_file.write(vault)
    vault_file.close()
    print(f'Vault initalized in file {VAULT_PATH}.')

def vault_put_password(master_password, address, password):
    if len(address) > 256:
        raise Exception(
            f"Address size is to big {len(address)} characters, limit is 256.")
    if len(password) > 256:
        raise Exception(
            f"Password size is to big {len(password)} characters, limit is 256.")

    vault_file = open(VAULT_PATH, 'r+b')
    vault_file_content = vault_file.read()
    salt, nonce, tag = get_vault_header(vault_file_content)

    vault_body = vault_file_content[VAULT_HEADER_SIZE:]
    key, salt = key_password_derivation(master_password, salt)
    vault_body = AES_decrypt(key, vault_body, nonce, tag)

    if vault_body == VAULT_EMPTY.encode('ascii'):
        vault_body = b''

    pad_address = pad(bytes(address, encoding=('ascii')), VAULT_PADDING_SIZE)
    pad_password = pad(bytes(password, encoding=('ascii')), VAULT_PADDING_SIZE)

    vault_body += pad_address
    vault_body += VAULT_ADDRESS_SEPARATOR.encode('ascii')
    vault_body += pad_password
    vault_body += VAULT_ENTRY_SEPARATOR.encode('ascii')

    ciphertext, nonce, tag = AES_encrypt(key, vault_body)
    vault_file.truncate(0)
    vault_file.seek(0)
    vault_file.write(salt)
    vault_file.write(nonce)
    vault_file.write(tag)
    vault_file.write(ciphertext)

def vault_get_password(master_password, address):
    vault_file = open(VAULT_PATH, 'rb')

    vault_file_content = vault_file.read()
    salt, nonce, tag = get_vault_header(vault_file_content)
    key, salt = key_password_derivation(master_password, salt)

    vault_body = vault_file_content[VAULT_HEADER_SIZE:]
    vault_body = AES_decrypt(key, vault_body, nonce, tag)

    entries = vault_body.decode('ascii', 'ignore').split(VAULT_ENTRY_SEPARATOR)
    match = None
    for entry in entries:
        if len(entry) < 1:
            continue
        pair = entry.split(VAULT_ADDRESS_SEPARATOR)
        if pair[0] == address:
            match = (pair[0], pair[1])
    return match

if __name__ == "__main__":
    args = sys.argv
    try:
        if args[1] == 'init':
            vault_init(args[2])
        elif args[1] == 'put':
            vault_put_password(args[2], args[3], args[4])
            print(f'Stored password for {args[3]}')
        elif args[1] == 'get':
            pair = vault_get_password(args[2], args[3])
            if pair != None:
                print(f'Passowrd for {pair[0]} is: {pair[1]}')
            else:
                raise Exception("Adress is not in the dictioniary.")    
        else:
            raise Exception("Inavlid action.")
    except IndexError:
        print("Function argument is not defined.")
    except FileNotFoundError:
        print("Vault is not initialized.")
    except Exception as e:
        print(e)
