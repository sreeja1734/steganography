from PIL import Image
import numpy as np
from math import log10, sqrt 
import cv2 
import csv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
fields=["file","characters","MSE","PSNR"]
datas=[]

def encode(file):
    img = np.asarray(Image.open(file))
    print(img)
    # W, H, c= img.shape
    # message = input("Enter message:")
    # message += '[END]'
    # message=str(encrypt(message))
    # message = message.encode('ascii')
    # message_bits = ''.join([format(i,'08b') for i in message])
    # reqmessage=len(message_bits)
    img = img.flatten()
    print(img)
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

def decode(file):
    img = np.asarray(Image.open(file))
    img = img.flatten()
    msg = ""
    idx = 0
    while msg[-5:] != '[END]':
        bits = [bin(i)[-1] for i in img[idx:idx+8]]
        bits = ''.join(bits)
        print("bits:", bits)
        try:
            msg += chr(int(bits, 2))
        except ValueError as e:
            print(f"Error converting bits '{bits}' to integer: {e}")
        idx += 8
        if idx > img.shape[0]:
            print("No hidden message")
            break
    return decrypt(msg[:-5])

def PSNR(inpfile, opfile): 
    data=[]
    original = np.array(Image.open(inpfile))
    compressed = np.array(Image.open(opfile))
    hidden=decode(opfile)
    mse = np.mean((original - compressed) ** 2) 
    if mse == 0:  
        return 100
    max_pixel = 255.0
    psnr = 20*log10(max_pixel / sqrt(mse)) 
    data.append(inpfile+" "+opfile)
    data.append(len(hidden))
    data.append(mse)
    data.append(psnr)
    datas.append(data)

def encrypt(message):
    message = bytes(message, 'utf-8')
    cipher=AES.new(key,AES.MODE_CBC)
    ciphered_data=cipher.encrypt(pad(message,AES.block_size))
    return cipher.iv + ciphered_data

def decrypt(ciphertext):
    iv = ciphertext[:AES.block_size]
    cipher=AES.new(key,AES.MODE_CBC,iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext.decode('utf-8')

simple_key=get_random_bytes(16)
salt=simple_key
password = bytes(input("Enter your password: "), 'utf-8')
key=PBKDF2(password, salt, dkLen=16)
while(True):
    choice=int(input("1 for encode 2 for decode 3 for psnr 4 for writing in csv:"))
    if(choice==1):
        file=input("Enter img name with correct path:")
        encode(file)
    elif choice==2:
        file=input("Enter img to decode:")
        msg=decode(file)
        print(msg)
    elif choice==3:
        inpfile=input("Enter original image:")
        opfile=input("Enter encoded image:")
        PSNR(inpfile,opfile)
    elif choice==4:
        with open("data.csv","w",newline="",encoding='utf-8') as d:
            writer=csv.writer(d)
            writer.writerow(fields)
            writer.writerows(datas)
    else:
        break