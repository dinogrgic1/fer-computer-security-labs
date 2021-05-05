import sys
import getpass
import re
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

USER_BASE_PATH = 'users.bin'
USER_MAX_SIZE = 256

PWD_MIN_SIZE = 8
PWD_MIN_REGEX = ''
PWD_MAX_SIZE = 256
PWD_SAFE_REGEX = '^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$'

USER_ENTRY_SEPARATOR = '\n'
PWD_ENTRY_SEPARATOR = '\t'

PBKDF2_SALT_SIZE = 128
PBKDF2_KEY_SIZE = 256
PBKDF2_ITTERATIONS = 1000000

def is_safe_password(pwd):
    regex = re.compile(PWD_SAFE_REGEX, re.I)
    match = regex.match(pwd)
    return bool(match)

def input_password():

    pwd = getpass.getpass("Password: ")
    pwd_again = getpass.getpass("Repeat password: ")
    if pwd != pwd_again:
        raise Exception("Password mismatch.")

    if is_safe_password(pwd) == False:
        raise Exception("Password not safe enough. Password must have 8 characters, at least one number and one letter")
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
    
    users_sys = open(USER_BASE_PATH, 'wb')
   
    pad_user = pad(bytes(user, encoding=('ascii')), USER_MAX_SIZE)
    pad_salt = pad(pwd[1], PBKDF2_SALT_SIZE)
    pwd_separator = PWD_ENTRY_SEPARATOR.encode('ascii')
    user_separator = USER_ENTRY_SEPARATOR.encode('ascii')

    #user(256) pwd_change(1) pwd(256) salt(256)
    file_content = (pad_user + pwd_separator + b'0' + pwd_separator + pwd[0] + pwd_separator + pad_salt + user_separator)
    users_sys.seek(0)
    users_sys.write(file_content)
    users_sys.close()

def del_user(user): 
    users_sys = open(USER_BASE_PATH, 'r+b')
    users_sys_content = users_sys.read()

    entries = users_sys_content.decode('ascii', 'ignore').split(USER_ENTRY_SEPARATOR)
    
    for entry in entries:
        entry_split = entry.split(PWD_ENTRY_SEPARATOR)
        if entry_split[0] == user:    
            print('User sucessfully removed.')
            entries.remove(entry)
            break

    users_sys.truncate(0)
    users_sys.seek(0)
    if len(entries) > 1:    
        users_sys.write(bytes(USER_ENTRY_SEPARATOR.join(entries), encoding=('ascii')))
    else:
        users_sys.write(b'')

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
            pass
        elif args[1] == 'forcepass':
            pass
        elif args[1] == 'del':
            del_user(args[2])
        else:
            raise Exception("Inavlid action.")
    except IndexError:
        print("Function argument is not defined.")
    except FileNotFoundError:
        print("User base is not initialized.")
    except Exception as e:
        print(e)
