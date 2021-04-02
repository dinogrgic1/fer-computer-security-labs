import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# TODO(Dino): Check if key size of 32 is big enough
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
    if master_pass is None:
        master_pass = input("Input master password: ")
    keys = PBKDF2(master_pass, salt, PBKDF2_KEY_SIZE,
                  count=PBKDF2_ITTERATIONS, hmac_hash_module=SHA512)
    return (keys, salt)


def vault_init():
    key, salt = key_password_derivation()
    vault_file = open(VAULT_PATH, 'wb')
    vault_file.write(salt)

    vault, nonce, tag = AES_encrypt(key, VAULT_EMPTY)
    vault_file.write(nonce)
    vault_file.write(tag)
    vault_file.write(vault)
    vault_file.close()


def vault_put_password(master_password, address):
    vault_file = open(VAULT_PATH, 'r+b')
    password = input(f"Password for {address} will be: ")

    # TODO(Dino): Don't read the whole file in memory when doing I/O?
    vault_file_content = vault_file.read()
    vault_header = vault_file_content[:VAULT_HEADER_SIZE]
    vault_body = vault_file_content[VAULT_HEADER_SIZE:]

    salt = vault_header[:PBKDF2_SALT_SIZE]
    nonce = vault_header[AES_NONCE_POSITION: AES_TAG_POSITION]
    tag = vault_header[AES_TAG_POSITION:]

    key, salt = key_password_derivation(master_password, salt)
    vault_body = AES_decrypt(key, vault_body, nonce, tag)

    # TODO(Dino): Don't add password if it exists already
    if vault_body == VAULT_EMPTY.encode('ascii'):
        vault_body = b''

    pad_address = pad(bytes(address , encoding=('ascii')), VAULT_PADDING_SIZE)
    pad_password = pad(bytes(password , encoding=('ascii')), VAULT_PADDING_SIZE)

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
    vault_header = vault_file_content[:VAULT_HEADER_SIZE]
    vault_body = vault_file_content[VAULT_HEADER_SIZE:]

    salt = vault_header[:PBKDF2_SALT_SIZE]
    nonce = vault_header[AES_NONCE_POSITION: AES_TAG_POSITION]
    tag = vault_header[AES_TAG_POSITION:]

    key, salt = key_password_derivation(master_password, salt)
    vault_body = AES_decrypt(key, vault_body, nonce, tag)

    entries = vault_body.decode('ascii', 'ignore').split(VAULT_ENTRY_SEPARATOR)
    for entry in entries:
        if len(entry) < 1:
            continue
        pair = entry.split(VAULT_ADDRESS_SEPARATOR)
        if pair[0] == address:
            return (pair[0], pair[1])
    raise Exception('Adress not found in the vault.')


def parse_args(args):
    # TODO(Dino): Check if password or address is longer then 256 characters
    try:
        if args[1] == 'init':
            vault_init()
        elif args[1] == 'put':
            vault_put_password(args[2], args[3])
            print(f'Stored password for {args[3]}')
        elif args[1] == 'get':
            pair = vault_get_password(args[2], args[3])
            print(f'Passowrd for {pair[0]} is: {pair[1]}')
        else:
            raise Exception("Inavlid action.")
    except IndexError:
        print("Function argument is not defined.")
    except Exception as e:
        print(e)


if __name__ == "__main__":
    parse_args(sys.argv)
