from PIL import Image
import numpy as np
from math import log10, sqrt 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
def encrypt(message,key):
    cipher=AES.new(key,AES.MODE_CBC)
    ciphered_data=cipher.encrypt(pad(message,AES.block_size))
    return cipher.iv + ciphered_data

def decrypt(ciphertext,key):
    iv = ciphertext[:AES.block_size]
    cipher=AES.new(key,AES.MODE_CBC,iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext

simple_key=get_random_bytes(32)
print(simple_key)
salt=simple_key
password = bytes(input("Enter your password: "), 'utf-8')
key=PBKDF2(password, salt, dkLen=32)
key2=b'8\x85\\R\xee\xf8\xf9\xdd\x08\xb4, !\xea\x8a\xe8'
m=input("enter message:")
m = bytes(m, 'utf-8')
p=encrypt(m,key)
o=encrypt(p,key2)
p=decrypt(o,key2)
print(decrypt(p,key).decode('utf-8'))
# print(len(encrypt(m)))
