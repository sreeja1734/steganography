from PIL import Image
import numpy as np
from math import log10, sqrt 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def encrypt(message, key):
    message = bytes(message, 'utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(message, AES.block_size))
    return cipher.iv + ciphered_data

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return decrypted_data.decode('utf-8')


def encode(file,message,key):
    img = np.asarray(Image.open(file))
    W, H, c= img.shape
    message=encrypt(message,key)
    print(message)
    message_bits = ''.join([format(i,'08b') for i in message])
    print(message_bits)
    reqmessage=len(message_bits)
    img = img.flatten()
    if(reqmessage>len(img)):
        print("can't encode")
    else:
        for idx, bit in enumerate(message_bits):
            val = img[idx]
            val = bin(val)
            val = val[:-1] + bit
            img[idx] = int(val,2)
        img = img.reshape((W,H,c))
        img = Image.fromarray(img)
        opname=input("Enter output filename:")
        img.save(opname)

def decode(file, key):
    img = np.asarray(Image.open(file))
    img = img.flatten()
    msg_bits = ""
    idx = 0
    k = 1
    while k < 49:
        bits = [bin(i)[-1] for i in img[idx:idx+8]]
        bits = ''.join(bits)
        print("bits:", bits)
        try:
            msg_bits += bits
        except ValueError as e:
            print(f"Error appending bits '{bits}': {e}")
        idx += 8
        k += 1
        if idx > img.shape[0]:
            print("No hidden message")
            break

    # Check if the length is a multiple of 8
    if len(msg_bits) % 8 != 0:
        print("Invalid data length. Unable to decode.")
        return ""

    # Convert binary string to bytes
    msg_bytes=int(msg_bits, 2).to_bytes((len(msg_bits) + 7) // 8, byteorder='big')
    return decrypt(msg_bytes,key)











# Key generation
# ... (previous code)

# simple_key = get_random_bytes(16)
# salt = simple_key
# password = bytes(input("Enter your password: "), 'utf-8')
key = b'8\x85\\R\xee\xf8\xf9\xdd\x08\xb4, !\xea\x8a\xe8'

# ... (remaining code)


# Example usage
file_name = "c.png"
message_to_hide = "This is a secret message"

# Encoding
encode(file_name, message_to_hide, key)

# Decoding
decoded_message = decode("d.png", key)
print("Decoded Message:", decoded_message)
