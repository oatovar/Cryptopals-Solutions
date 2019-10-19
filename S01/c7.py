#!/usr/bin/env python3

from base64 import b64decode
from Crypto.Cipher import AES

def aes_ecb(data: str, key: str):
    ciphertext = AES.new(key, AES.MODE_ECB)
    return ciphertext.decrypt(data)

if __name__ == "__main__":
    file = open('c7_input.txt', 'r')
    txt = b64decode(file.read())
    print(aes_ecb(txt, 'YELLOW SUBMARINE').decode())
