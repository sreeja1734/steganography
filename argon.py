from PIL import Image
import numpy as np
import csv
from math import log10, sqrt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from argon2 import PasswordHasher  

class SteganographyError(Exception):
    pass

class LengthMismatchError(SteganographyError):
    pass

class PasswordError(SteganographyError):
    pass

class PSNRCalculationError(SteganographyError):
    pass

# Replace PBKDF2 with Argon2 for key derivation
def derive_key(password, salt, dklen=32):
    ph = PasswordHasher()
    return ph.hash(password, salt=salt).encode('utf-8')[:dklen]

def encrypt(message, key, flag=True):
    if flag:
        message = bytes(message, 'utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(message, AES.block_size))
    return cipher.iv + ciphered_data

def decrypt(ciphertext, key, flag=True):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    if flag:
        return decrypted_data.decode('utf-8')
    else:
        return decrypted_data

def encode(file, message):
    img = np.asarray(Image.open(file))
    W, H, c = img.shape
    even_message = message[::2]
    odd_message = message[1::2]
    salt = get_random_bytes(32)
    key2 = get_random_bytes(32)
    print(salt)
    print(key2)
    
    # Update key derivation with Argon2
    passeven = bytes(input("Set password for even: "), 'utf-8')
    keyeven = derive_key(passeven, salt)
    
    passodd = bytes(input("Set password for odd: "), 'utf-8')
    keyodd = derive_key(passodd, salt)
    
    even_ciphered_data = encrypt(even_message, keyeven) 
    even_ciphered_data = salt + encrypt(even_ciphered_data, key2, False) + b'[END]'
    odd_ciphered_data = encrypt(odd_message, keyodd)
    odd_ciphered_data = b'[DNE]' + key2 + encrypt(odd_ciphered_data, key2, False)
    message_bits = ''.join([format(i, '08b') for i in even_ciphered_data])

    leneve = len(message_bits)
    revmessage_bits = ''.join([format(i, '08b') for i in odd_ciphered_data])
    lenodd = -(len(revmessage_bits))
    i = 0
    j = -1
    req_message = len(message_bits) 
    img = img.flatten()
    if req_message > len(img):
        raise LengthMismatchError("Message is too long to encode in the image.")   

    while (i < leneve) or (j > lenodd):
        if i < leneve:
            val = img[i]
            val = bin(val)
            val = val[:-1] + message_bits[i]
            img[i] = int(val, 2)
            i += 1
        if j > lenodd:
            val = img[j]
            val = bin(val)
            val = val[:-1] + revmessage_bits[j]
            img[j] = int(val, 2)
            j -= 1

    img = img.reshape((W, H, c))
    img = Image.fromarray(img)    
    opname = input("Enter output filename:")
    img.save(opname)

def decode(file):  
    img = np.asarray(Image.open(file))
    delimiter = b'[END]'
    del_bits = ''.join([format(i, '08b') for i in delimiter])
    limiter = b'[DNE]'
    oe = ''.join([format(i, '08b') for i in limiter])
    oe = oe[::-1]
    img = img.flatten()
    msg_bits = ""
    odd_message = ""
    idx = 0
    k = 1
    while not msg_bits.endswith(del_bits):
        bits = [bin(i)[-1] for i in img[idx:idx+8]]
        bits = ''.join(bits)
        try:
            msg_bits += bits
        except ValueError as e:
            print(f"Error appending bits '{bits}': {e}")
        idx += 8
        if idx > img.shape[0]:
            raise SteganographyError("No hidden message found in the image.")
    
    idx = len(img) - 1  
    while not odd_message.endswith(oe):
        bits = [bin(i)[-1] for i in img[idx:idx-8:-1]]
        bits = ''.join(bits)
        try:
            odd_message += bits
        except ValueError as e:
            print(f"Error appending bits '{bits}': {e}")
        idx -= 8
        if idx < 0:
            raise SteganographyError("No hidden message found in the image.")    

    if len(msg_bits + odd_message) % 8 != 0:
        raise SteganographyError("Invalid data length. Unable to decode.")

    odd_message = odd_message[::-1]
    
    evmsg_bytes = int(msg_bits, 2).to_bytes((len(msg_bits) + 7) // 8, byteorder='big')
    odmsg_bytes = int(odd_message, 2).to_bytes((len(odd_message) + 7) // 8, byteorder='big')
    key2 = odmsg_bytes[5:37]
    salt = evmsg_bytes[:32]
    
    passeven = bytes(input("Enter password for even: "), 'utf-8')
    keyeven = derive_key(passeven, salt)
    
    passodd = bytes(input("Enter password for odd: "), 'utf-8')
    keyodd = derive_key(passodd, salt)  
    
    ev_message = decrypt(evmsg_bytes[32:-5], key2, False)
    ev_message = decrypt(ev_message, keyeven)
    
    od_message = decrypt(odmsg_bytes[37:], key2, False)
    od_message = decrypt(od_message, keyodd)
    
    result = ''.join([elem for pair in zip(ev_message, od_message) for elem in pair])
    if len(ev_message) > len(od_message):
        result += ev_message[-1]
    elif len(ev_message) < len(od_message):
        result += od_message[-1]
    
    return result

def PSNR():
    try:
        n = int(input("No. of input image:"))
        d = int(input("No. of outputs per input:"))
        for i in range(n):
            inpfile = input("Enter input file:")
            for j in range(d):
                opfile = input("Enter output file:")
                data = []
                original = np.array(Image.open(inpfile))
                compressed = np.array(Image.open(opfile))
                hidden = int(input("No. of characters encoded:"))
                mse = np.mean((original - compressed) ** 2)
                if mse == 0:
                    raise PSNRCalculationError("MSE is zero. Cannot calculate PSNR.")
                max_pixel = 255.0
                psnr = 20 * log10(max_pixel / sqrt(mse))
                data.append(inpfile + " " + opfile)
                data.append(hidden)
                data.append(mse)
                data.append(psnr)
                datas.append(data)
        with open("data.csv", "w", newline="", encoding='utf-8') as d:
            writer = csv.writer(d)
            writer.writerow(fields)
            writer.writerows(datas)
    except FileNotFoundError as e:
        raise SteganographyError(f"File not found: {e}")

datas = []
fields = ["file", "characters", "MSE", "PSNR"]

while True:
    try:
        choice = int(input("1 for encode, 2 for decode, 3 for PSNR:"))
        if choice == 1:
            file = input("Enter image name with correct path:")
            message = input("Enter message:")
            encode(file, message)
        elif choice == 2:
            file = input("Enter image to decode:")
            msg = decode(file)
            print(msg)
        elif choice == 3:
            PSNR()
        else:
            break
    except SteganographyError as e:
        print(f"SteganographyError: {e}")
    except FileNotFoundError as e:
        print(f"FileNotFoundError: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
