#!/usr/bin/env python3

import random
from Crypto.Cipher import AES
from c10 import encrypt_aes_ecb
from c11 import generate_plaintext_padding, duplicate_blocks
from base64 import b64decode

random_str = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'

def generate_consistent_key(keysize: int) -> bytes:
    '''
    Creates a key at startup that is consistently the same.

    keysize (int) - the size of the key in bytes

    returns bytes forming the key
    '''
    random.seed(1)
    return bytes([random.randrange(0, 256) for _ in range(keysize)])

def ecb_oracle(cleartext: bytes) -> bytes:
    '''
    Oracle for AES encryption in ECB mode.

    cleartext (bytes) - the cleartext bytes to encrypt

    returns a ciphertext that leaks information
    '''
    block_size = 16
    key = generate_consistent_key(block_size)
    new_plaintext = cleartext + b64decode(random_str)
    ciphertext = encrypt_aes_ecb(new_plaintext, key)
    return ciphertext

def detect_blocksize() -> int:
    '''
    Detects the block size used by the ecb oracle.

    returns block size (int)
    '''
    # blocksizes are the sizes used by AES 128, 256, 
    blocksizes = (16, 24, 32)
    length = 1
    duplicate_count = 0
    while duplicate_count < 1 and length < 128:
        plaintext = b'A' * length
        ciphertext = ecb_oracle(plaintext)
        for block_size in blocksizes:
            duplicate_count = duplicate_blocks(ciphertext, block_size)
            if duplicate_count > 0:
                return block_size
        length += 1
    return -1

def decrypte_byte(blocksize: int, plaintext: bytes):
    length = (blocksize - (1 + len(plaintext))) % blocksize
    index = length + len(plaintext) + 1
    byte_str = b'A' * length
    a = ecb_oracle(byte_str)[:index]

    decrypted_byte = b''
    for byte in range(256):
        payload = byte_str + plaintext + bytes([byte])
        b = ecb_oracle(payload)[:index]
        if a == b:
            decrypted_byte = bytes([byte])
            break
    return decrypted_byte

def exploit_ecb_oracle(blocksize: int):
    decrypted = b''
    ciphertext_length = len(ecb_oracle(b''))
    for _ in range(ciphertext_length):
        decrypted += decrypte_byte(blocksize, decrypted)
    return decrypted

if __name__ == '__main__':
    block_size = detect_blocksize()
    plaintext = exploit_ecb_oracle(block_size)
    print('Block Size:', block_size)
    print('Plaintext:', plaintext.decode())
