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

PBKDF2_SALT_SIZE = 128
PBKDF2_KEY_SIZE = 256
PBKDF2_ITTERATIONS = 1000000

# user(256) pwd_change(1) pwd(256) salt(128)
BLOCK_SIZE = USER_MAX_SIZE + PBKDF2_SALT_SIZE + PWD_MAX_SIZE + 1

def is_safe_password(pwd):
    regex = re.compile(PWD_SAFE_REGEX, re.I)
    match = regex.match(pwd)
    return bool(match)

def input_password(sal=get_random_bytes(PBKDF2_SALT_SIZE)):
    pwd = getpass.getpass("Password: ")
    pwd_again = getpass.getpass("Repeat password: ")
    if pwd != pwd_again:
        raise Exception("Password mismatch.")

    if is_safe_password(pwd) == False:
        raise Exception(
            "Password not safe enough. Password must have 8 characters, at least one number and one letter")
    return key_password_derivation(master_pass=pwd, salt=sal)


def key_password_derivation(master_pass=None, salt=None):
    keys = PBKDF2(master_pass, salt, PBKDF2_KEY_SIZE,
                  count=PBKDF2_ITTERATIONS, hmac_hash_module=SHA512)
    return (keys, salt)

def init_file_if_not_exists(path=USER_BASE_PATH):
    try:
        file = open(path, 'r+b')
    except IOError:
        file = open(path, 'w')
        file.close()
        file = open(path, 'r+b')
    finally:
        return file

def user_exists(user, file):
    for i in range(0, len(file), BLOCK_SIZE):
        entry_split = file[i:i+BLOCK_SIZE]
        user_unpad = unpad(entry_split[0:USER_MAX_SIZE], USER_MAX_SIZE)
        user_unpad = user_unpad.decode('ascii')
        if user_unpad == user:
            return i
    return None

def add_user(user):
    users_sys = init_file_if_not_exists(USER_BASE_PATH)
    user_id = user_exists(user, users_sys.read())
    if user_id != None:
        raise Exception('User already exists.')
    try:
        pwd = input_password()
    except Exception as e:
        raise type(e)('User add failed. ' + e.__str__())
    
    file_content = users_sys.read()
    pad_user = pad(bytes(user, encoding=('ascii')), USER_MAX_SIZE)

    file_content += pad_user
    file_content += b'0'
    file_content += pwd[0]
    file_content += pwd[1]
    
    users_sys.truncate(0)
    users_sys.seek(0)
    users_sys.write(file_content)
    users_sys.close()

def del_user(user):
    users_sys = init_file_if_not_exists(USER_BASE_PATH)
    users_sys_content = users_sys.read()
    
    user_id = user_exists(user, users_sys_content)
    if user_id != None:
        print('User sucessfully removed.')
        users_sys_content = users_sys_content[:user_id] + users_sys_content[user_id+BLOCK_SIZE:]

    users_sys.truncate(0)
    users_sys.seek(0)
    users_sys.write(users_sys_content)
    users_sys.close()

def pwd_change(user):
    users_sys = init_file_if_not_exists(USER_BASE_PATH)
    users_sys_content = users_sys.read()

    user_id = user_exists(user, users_sys_content)
    if user_id != None:
        pwd = input_password()
        print('User will change password on next login.')
        users_sys_content = users_sys_content[:user_id + BLOCK_SIZE - PBKDF2_SALT_SIZE - PWD_MAX_SIZE] + pwd[0] + pwd[1] +  users_sys_content[user_id + BLOCK_SIZE:]

    users_sys.truncate(0)
    users_sys.seek(0)
    users_sys.write(users_sys_content)
    users_sys.close()

def pwd_force(user):
    users_sys = init_file_if_not_exists(USER_BASE_PATH)
    users_sys_content = users_sys.read()

    user_id = user_exists(user, users_sys_content)
    if user_id != None:
        print('User will change password on next login.')
        users_sys_content = users_sys_content[:user_id + USER_MAX_SIZE] + b'1' +  users_sys_content[user_id + USER_MAX_SIZE + 1:]

    users_sys.truncate(0)
    users_sys.seek(0)
    users_sys.write(users_sys_content)
    users_sys.close()

def user_login(user):
    users_sys = init_file_if_not_exists(USER_BASE_PATH)
    users_sys_content = users_sys.read()

    user_id = user_exists(user, users_sys_content)
    if user_id != None:
        salt = users_sys_content[user_id + BLOCK_SIZE - PBKDF2_SALT_SIZE: user_id + BLOCK_SIZE]
        pwd2 = users_sys_content[user_id + USER_MAX_SIZE + 1: user_id + USER_MAX_SIZE + 1 + PWD_MAX_SIZE]
        pwd1 = input_password(sal=salt)
        
        if pwd1[0] == pwd2:
            print('password correct')
        debug_user(users_sys_content, user_id)

    users_sys.truncate(0)
    users_sys.seek(0)
    users_sys.write(users_sys_content)
    users_sys.close()

def debug_user(users_sys_content, user_id):
    usr = unpad(users_sys_content[user_id: user_id + USER_MAX_SIZE], USER_MAX_SIZE)
    usr = usr.decode('ascii')
    pwd_chn = users_sys_content[user_id + USER_MAX_SIZE: user_id + USER_MAX_SIZE + 1]
    pwd_chn = pwd_chn.decode('ascii')
    passw = users_sys_content[user_id + USER_MAX_SIZE + 1: user_id + USER_MAX_SIZE + PWD_MAX_SIZE]
    salt = users_sys_content[user_id + BLOCK_SIZE - PBKDF2_SALT_SIZE: user_id + BLOCK_SIZE]

    print(usr)
    print(pwd_chn)
    print(passw)
    print(salt)
    

if __name__ == '__main__':
    args = sys.argv
    try:
        if args[1] == 'add':
            add_user(args[2])
        elif args[1] == 'passwrd':
            pwd_change(args[2])
        elif args[1] == 'forcepass':
            pwd_force(args[2])
        elif args[1] == 'del':
            del_user(args[2])
        elif args[1] == 'login':
            user_login(args[2])
        else:
            raise Exception("Inavlid action.")
    except IndexError:
        print("Function argument is not defined.")
    except FileNotFoundError:
        print("User base is not initialized.")
    except Exception as e:
        print(e)
