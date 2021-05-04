import sys
import getpass
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

USER_BASE_PATH = 'users.bin'
USER_MAX_SIZE = 256

PWD_MIN_REGEX = ''
PWD_MAX_SIZE = 256

PBKDF2_SALT_SIZE = 128
PBKDF2_KEY_SIZE = 256
PBKDF2_ITTERATIONS = 1000000

def input_password():
    #TODO: length and safe password check
    pwd = getpass.getpass("Password: ")
    pwd_again = getpass.getpass("Repeat password: ")
    if pwd != pwd_again:
        raise Exception("Password mismatch.")
    return key_password_derivation(master_pass=pwd)

def key_password_derivation(master_pass=None, salt=get_random_bytes(PBKDF2_SALT_SIZE)):
    keys = PBKDF2(master_pass, salt, PBKDF2_KEY_SIZE,
                  count=PBKDF2_ITTERATIONS, hmac_hash_module=SHA512)
    return (keys, salt)

def add_user(user):
    try:
        pwd = input_password()
    except Exception as e:
        raise type(e)('User add failed. ' + e.__str__())
    
    vault_file = open(USER_BASE_PATH, 'wb')
   
    pad_user = pad(bytes(user, encoding=('ascii')), USER_MAX_SIZE)
    pad_salt = pad(pwd[1], PBKDF2_SALT_SIZE)

    vault_file.write(pad_user)
    vault_file.write(pwd[0])
    vault_file.write(pad_salt)
    vault_file.close()

def del_user(): 
    pass

def pwd_change():
    pass

def pwd_force():
    pass

if __name__ == '__main__':
    args = sys.argv
    try:
        if args[1] == 'add':
            add_user(args[2])
        elif args[1] == 'passwrd':
            input_password()
        elif args[1] == 'forcepass':
            input_password()
        elif args[1] == 'del':
            input_password()
        else:
            raise Exception("Inavlid action.")
    except IndexError:
        print("Function argument is not defined.")
    except FileNotFoundError:
        print("User base is not initialized.")
    except Exception as e:
        print(e)
