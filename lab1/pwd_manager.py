from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

ciphertext = 'Napadamo u zoru!'.encode('utf-8')

if __name__ == '__main__':
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(ciphertext)
    print(ciphertext)