from PIL import Image
import numpy as np
from math import log10, sqrt 
import cv2 
import csv
fields=["file","characters","MSE","PSNR"]
datas=[]
def encode(file):
    img = np.asarray(Image.open(file))
    W, H, c= img.shape
    message = input("Enter message:")
    message += '[END]'
    message = message.encode('ascii')
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
def decode(file):
    img = np.asarray(Image.open(file))
    img = img.flatten()
    msg = ""
    idx = 0
    while msg[-5:] != '[END]':
        # //use special chars
        bits = [bin(i)[-1] for i in img[idx:idx+8]]
        bits = ''.join(bits)
        msg += chr(int(bits,2))
        idx+=8
        if idx > img.shape[0]:
            print("No hidden message")
            break
    return msg[:-5]
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