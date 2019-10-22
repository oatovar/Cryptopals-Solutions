#!/usr/bin/env python3

from Crypto.Cipher import AES

def duplicate_blocks(ciphertext: bytes) -> int:
    '''
    Returns the number of duplicate blocks within the ciphertext bytes
    '''
    blocks = [ciphertext[i:i + AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]
    block_count = len(blocks)
    return (block_count - len(set(blocks)))

def detect_aes_ecb(filepath: str) -> list:
    '''
    Generates a list of candidates that are highly likely to be
    encrypted with AES in EBC mode.

    Returns a list of candidate details
    The details are a tuple (hexstring, duplicate_block_count)
    '''
    ciphertexts = []
    candidates = []
    with open(filepath, 'r') as file:
        for line in file:
            b = bytes.fromhex(line.strip())
            ciphertexts.append(b)
    for _, c in enumerate(ciphertexts):
        duplicate_count = duplicate_blocks(c)
        if duplicate_count > 0:
            tmp = (c.hex(), duplicate_count)
            candidates.append(tmp)
    return sorted(candidates, key=lambda c: c[1], reverse=True)

if __name__ == "__main__":
    from pathlib import Path
    filepath = str(Path(__file__).parent.absolute()) + '/' + 'c8_input.txt'
    aes_ebc_candidates = detect_aes_ecb(filepath)
