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


def encode(file,message,key):
    img = np.asarray(Image.open(file))
    W, H, c= img.shape
    message=encrypt(message,key)+b'[END]'
    message_bits = ''.join([format(i,'08b') for i in message])
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
    delimiter = b'[END]'
    del_bits = ''.join([format(i, '08b') for i in delimiter])
    img = img.flatten()
    msg_bits = ""
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
    if len(msg_bits) % 8 != 0:
        print("Invalid data length. Unable to decode.")
        return ""
    msg_bytes = int(msg_bits, 2).to_bytes((len(msg_bits) + 7) // 8, byteorder='big')
    return decrypt(msg_bytes[:-5],key)
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
            hidden=decode(opfile,key)
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
simple_key=get_random_bytes(16)
salt=simple_key
password = bytes(input("Enter your password: "), 'utf-8')
key=PBKDF2(password, salt, dkLen=16)
datas=[]
fields=["file","characters","MSE","PSNR"]
while(True):
    choice=int(input("1 for encode 2 for decode 3 for psnr 4 for writing in csv:"))
    if(choice==1):
        file=input("Enter img name with correct path:")
        message=input("Enter message:")
        encode(file,message,key)
    elif choice==2:
        file=input("Enter img to decode:")
        msg=decode(file,key)
        print(msg)
    elif choice==3:
        PSNR()
    elif choice==4:
        with open("data.csv","w",newline="",encoding='utf-8') as d:
            writer=csv.writer(d)
            writer.writerow(fields)
            writer.writerows(datas)
    else:
        break












# Key generation
# ... (previous code)

# simple_key = get_random_bytes(16)
# salt = simple_key
# password = bytes(input("Enter your password: "), 'utf-8')

