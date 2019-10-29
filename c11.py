#!/usr/bin/env python3

from random import randrange, randint
from Crypto.Cipher import AES
from c10 import encrypt_aes_cbc, encrypt_aes_ecb

def duplicate_blocks(ciphertext: bytes, blocksize: int) -> int:
    '''
    Returns the number of duplicate blocks within the ciphertext bytes
    '''
    blocks = [ciphertext[i:i + blocksize] for i in range(0, len(ciphertext), blocksize)]
    block_count = len(blocks)
    return (block_count - len(set(blocks)))

def generate_plaintext_padding() -> bytes:
    '''
    Generates 5-10 randomly generated bytes that will be used
    to prepend and append the text.

    returns bytes
    '''
    return bytes([randrange(0, 256) for _ in range(randrange(5, 11))])

def encryption_oracle(cleartext: bytes) -> bytes:
    '''
    The encryption oracle will encrypt the given cleartext
    using a randomly generated key.

    Returns the ciphertext bytes
    '''
    block_size = 16
    key = bytes([randrange(0, 256) for _ in range(block_size)])
    prefix = generate_plaintext_padding()
    suffix = generate_plaintext_padding()
    new_plaintext = prefix + cleartext + suffix

    if randint(1,2) == 1:
        # Encrypt using CBC
        iv = bytes([randrange(0, 256) for _ in range(block_size)])
        return encrypt_aes_cbc(new_plaintext, key, iv)
    else:
        # Encrypt using EBC
        return encrypt_aes_ecb(new_plaintext, key)
        

if __name__ == '__main__':
    ciphertext = encryption_oracle(bytes([0]*128))
    print('CIPHERTEXT HEX:', ciphertext.hex())
    print('LENGTH:', len(ciphertext.hex()) // 2)
    count = duplicate_blocks(ciphertext, AES.block_size)
    if count > 0:
        print('MODE: ECB')
    else:
        print('MODE: CBC')
