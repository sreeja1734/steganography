from PIL import Image
import numpy as np
import csv
from math import log10, sqrt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from argon2 import PasswordHasher               # Import Argon2 for password hashing
from Crypto.Random import get_random_bytes

# Custom exception classes for steganography errors

class SteganographyError(Exception):
    pass

class LengthMismatchError(SteganographyError):
    pass

class PasswordError(SteganographyError):
    pass

class PSNRCalculationError(SteganographyError):
    pass

# Helper functions for password hashing, verification, encryption, and decryption

def hash_password(password, salt):
    ph = PasswordHasher()
    hashed_result = ph.hash(password + salt)
    key = hashed_result[:16].encode('utf-8')
    return key

def verify_password(hashed, password):
    ph = PasswordHasher()
    try:
        ph.verify(hashed, password)
        return True
    except Exception:
        return False


def encrypt(message, key):
    """Encrypts the given data using AES encryption with the provided password.Returns the encrypted data. """
    message = bytes(message, 'utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(message, AES.block_size))
    return cipher.iv + ciphered_data

def decrypt(ciphertext, key):
    """Decrypts the given data using AES encryption with the provided password.
    Returns the decrypted data.
    """
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return decrypted_data.decode('utf-8')




def encode(file, message, salt):
    """
    Encodes the given message into the provided image file using steganography.
    Saves the modified image with a user-specified output filename.
    """
    img = np.asarray(Image.open(file))
    W, H, c = img.shape

    even_message = message[::2]
    odd_message = message[1::2]

    passeven = bytes(input("Set password for even: "),'utf-8')
    keyeven = hash_password(passeven, salt)
    passodd = bytes(input("Set password for odd: "),'utf-8')
    keyodd = hash_password(passodd, salt)

    even_ciphered_data = encrypt(even_message, keyeven) + b'[DEND]'
    odd_ciphered_data = encrypt(odd_message, keyodd) + b'[END]'

    message_bits = ''.join([format(i, '08b') for i in even_ciphered_data + odd_ciphered_data])

    req_message = len(message_bits)

    img = img.flatten()

    if req_message > len(img):
        raise LengthMismatchError("Message is too long to encode in the image.")

    for idx, bit in enumerate(message_bits):
        val = img[idx]
        val = bin(val)
        val = val[:-1] + bit
        img[idx] = int(val, 2)

    img = img.reshape((W, H, c))
    img = Image.fromarray(img)

    opname = input("Enter output filename:")
    img.save(opname)

def decode(file, salt):
    """
    Decodes the hidden message from the provided image file using steganography.
    Returns the decoded message.
    """
    passeven = bytes(input("Enter password for even: "),'utf-8')
    keyeven = hash_password(passeven, salt)
    even_valid = verify_password(keyeven,passeven)
    passodd = bytes(input("Enter password for odd: "),'utf-8')
    keyodd = hash_password(passodd, salt)
    odd_valid = verify_password(keyodd,passodd)

    img = np.asarray(Image.open(file))
    delimiter = b'[END]'
    del_bits = ''.join([format(i, '08b') for i in delimiter])
    limiter = b'[DEND]'
    oe = ''.join([format(i, '08b') for i in limiter])

    img = img.flatten()
   
    msg_bits = ""
    even_message = ""
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
        k += 1
        if idx > img.shape[0]:
            raise SteganographyError("No hidden message found in the image.")
        if msg_bits.endswith(oe) and even_valid is True:
            try:
                even_message += decrypt(msg_bytes[:-6], keyeven)
            except Exception as e:
                raise PasswordError("Incorrect password for even part of the message.")
            msg_bits = "" ""

    if len(msg_bits) % 8 != 0:
        raise SteganographyError("Invalid data length. Unable to decode.")
    
    msg_bytes = int(msg_bits, 2).to_bytes((len(msg_bits) + 7) // 8, byteorder='big')
    if odd_valid is True:
        try:
            odd_message += decrypt(msg_bytes[:-5], keyodd)
        except Exception:
            raise PasswordError("Incorrect password for odd part of the message.")
    
    result = ''.join([elem for pair in zip(even_message, odd_message) for elem in pair])
    if len(even_message) > len(odd_message):
        result += even_message[-1]
    elif len(even_message) < len(odd_message):
        result += odd_message[-1]

    return result





def PSNR():
    """
    Calculates the Peak Signal-to-Noise Ratio (PSNR) for a given set of input and output images.
    Writes the calculated data to a CSV file.
    """
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

# Initialize necessary variables
salt = b'8\x85\\R\xee\xf8\xf9\xdd\x08\xb4, !\xea\x8a\xe8'
datas = []
fields = ["file", "characters", "MSE", "PSNR"]

# Main program loop

while True:
    try:
        choice = int(input("1 for encode, 2 for decode, 3 for PSNR:"))
        if choice == 1:
            file = input("Enter image name with correct path:")
            message = input("Enter message:")
            encode(file, message, salt)
        elif choice == 2:
            file = input("Enter image to decode:")
            msg = decode(file, salt)
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
