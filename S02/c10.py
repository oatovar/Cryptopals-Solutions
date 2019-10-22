#!/usr/bin/env python3

from base64 import b64decode
from Crypto.Cipher import AES
from c9 import pkcs7_padding

def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    '''
    Decrypts a given cleartext using the given key, iv, and block size

    returns ciphertext bytes
    '''
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def encrypt_aes_ecb(cleartext: bytes, key: bytes) -> bytes:
    '''
    Encrypts a given cleartext using the given key, iv, and block size

    returns ciphertext bytes
    '''
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(cleartext)

def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    '''
    Decrypts a given cleartext using the given key, iv, and block size

    returns ciphertext bytes
    '''
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

def encrypt_aes_cbc(cleartext: bytes, key: bytes, iv: bytes) -> bytes:
    '''
    Encrypts a given cleartext using the given key, iv, and block size

    returns ciphertext bytes
    '''
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7_padding(cleartext, AES.block_size))

if __name__ == '__main__':
    from pathlib import Path
    filepath = str(Path(__file__).parent.absolute()) + '/' + 'c10_input.txt'
    file = open(filepath, 'r')
    cleartext = b64decode(file.read())
    file.close()
    print(decrypt_aes_cbc(cleartext, b'YELLOW SUBMARINE', bytes(AES.block_size)).decode())
