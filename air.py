from PIL import Image
import numpy as np
import csv
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


def encode(file, message,salt):
    img = np.asarray(Image.open(file))
    W, H, c = img.shape
    
    # Split the message into odd and even indexed characters
    even_message = message[::2]
    odd_message = message[1::2]

    # Encrypt the even and odd messages separately
    passeven = bytes(input("set password for even: "), 'utf-8')
    keyeven=PBKDF2(passeven, salt, dkLen=16)
    passodd = bytes(input("set password for odd: "), 'utf-8')
    keyodd=PBKDF2(passodd, salt, dkLen=16)
    even_ciphered_data = encrypt(even_message, keyeven)+ b'[DEND]'
    odd_ciphered_data = encrypt(odd_message, keyodd)+ b'[END]'

    # Combine the ciphered data with the delimiter
    message_bits = ''.join([format(i, '08b') for i in even_ciphered_data + odd_ciphered_data])
    
    req_message = len(message_bits)
    choice=int(input("Enter one for column 2 for row:"))
    if(choice==2):
        img = img.flatten()
    else:
        img=img.flatten('F')
    # column wise choice F
    
    if req_message > len(img):
        print("Can't encode")
    else:
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
    passeven = bytes(input("enter password for even: "), 'utf-8')
    keyeven=PBKDF2(passeven, salt, dkLen=16)
    passodd = bytes(input("enter password for odd: "), 'utf-8')
    keyodd=PBKDF2(passodd, salt, dkLen=16)
    img = np.asarray(Image.open(file))
    delimiter = b'[END]'
    del_bits = ''.join([format(i, '08b') for i in delimiter])
    limiter = b'[DEND]'
    oe = ''.join([format(i, '08b') for i in limiter])
    # row wise
    choice=int(input("Enter one for column 2 for row:"))
    if(choice==2):
        img = img.flatten()
    else:
        img=img.flatten('F')
    msg_bits = ""
    even_message=""
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
            print("No hidden message")
            break
        if msg_bits.endswith(oe):
            msg_bytes = int(msg_bits, 2).to_bytes((len(msg_bits) + 7) // 8, byteorder='big')
            even_message+=decrypt(msg_bytes[:-6],keyeven)
            msg_bits=""
    if len(msg_bits) % 8 != 0:
        print("Invalid data length. Unable to decode.")
        return ""
    msg_bytes = int(msg_bits, 2).to_bytes((len(msg_bits) + 7) // 8, byteorder='big')
    odd_message=decrypt(msg_bytes[:-5],keyodd)
    result= ''.join([elem for pair in zip(even_message, odd_message) for elem in pair])
    if(len(even_message)>len(odd_message)):
        result+=even_message[-1]
    elif(len(even_message)<len(odd_message)):
        result+=odd_message[-1]
    return result
def PSNR(): 
    n=int(input("No.of input image:"))
    d=int(input("No.of op per ip:"))
    for i in range (n):
        inpfile=input("Enter inpfile:")
        for j in range (d):
            opfile=input("Enter opfile:")
            data=[]
            original = np.array(Image.open(inpfile))
            compressed = np.array(Image.open(opfile))
            hidden=int(input("No.of characters encoded:"))
            mse = np.mean((original - compressed) ** 2) 
            if mse == 0:  
                return 100
            max_pixel = 255.0
            psnr = 20*log10(max_pixel / sqrt(mse)) 
            data.append(inpfile+" "+opfile)
            data.append(hidden)
            data.append(mse)
            data.append(psnr)
            datas.append(data)
    with open("data.csv","w",newline="",encoding='utf-8') as d:
            writer=csv.writer(d)
            writer.writerow(fields)
            writer.writerows(datas)
salt= b'8\x85\\R\xee\xf8\xf9\xdd\x08\xb4, !\xea\x8a\xe8'
datas=[]
fields=["file","characters","MSE","PSNR"]
while(True):
    choice=int(input("1 for encode 2 for decode 3 for psnr:"))
    if(choice==1):
        file=input("Enter img name with correct path:")
        message=input("Enter message:")
        encode(file,message,salt)
    elif choice==2:
        file=input("Enter img to decode:")
        msg=decode(file,salt)
        print(msg)
    elif choice==3:
        PSNR()
    else:
        break
    #double aes,exception,data,2 field,reshape error,grayscale,