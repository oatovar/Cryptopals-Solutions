#!/usr/bin/env python3

import base64
import c3, c5
from itertools import combinations

def beautify(candidates: list):
    '''
    Pretty prints the candidates returned
    '''
    s = ''
    for c in candidates:
        s += 'Keysize: {}\tHamming Distance: {}\n'.format( c['keysize'], c['normalized_distance'])
    return s

def hamming_distance(str1: str, str2: str) -> int:
    '''
    Calculates the total amount of differing bits between two bits.

    returns (int) distance
    '''
    # declare bytes
    b1 = bytes.fromhex(str1)
    b2 = bytes.fromhex(str2)
    count = 0
    for i, j in zip(b1, b2):
        xor = bin(i^j)
        count += xor.count("1")
    return count

def generate_keysize_candidates(data: str) -> list:
    '''
    Calculates the hamming distance for a variety of keysizes and returns
    the top 4 candidates.

    returns a list of candidates
    '''
    distance_candidates = []
    ciphertext_bytes = base64.b64decode(data)
    for keysize in range(2, 41):

        blocks = [ciphertext_bytes[i:i+keysize] for i in range(0, len(ciphertext_bytes), keysize)][:4]
        distance = 0
        block_combinations = tuple(combinations(blocks, 2))
        for (a,b) in block_combinations:
            distance += hamming_distance(a.hex(), b.hex())
        distance /= len(block_combinations)
        normalized_distance = distance / keysize
        distance_candidate = {
            'keysize': keysize,
            'normalized_distance': normalized_distance,
        }
        distance_candidates.append(distance_candidate)

    return sorted(distance_candidates, key=lambda c: c['normalized_distance'])

def generate_blocks(filepath: str, keysize: int) -> list:
    '''
    Partitions the base64 encoded file into blocks of the given keysize

    returns list of byte blocks (list)
    '''
    blocks = []
    with open(filepath, 'r') as file:
        b64_ciphertext = file.read()
        b64_ciphertext_bytes = bytes(b64_ciphertext, 'utf-8')
        ciphertext_bytes = base64.b64decode(b64_ciphertext_bytes)
        while len(ciphertext_bytes) // keysize > 1:
            block = ciphertext_bytes[:keysize]
            ciphertext_bytes = ciphertext_bytes[keysize:]
            blocks.append(block)
        if len(ciphertext_bytes) > 0:
            padding = keysize - len(ciphertext_bytes)
            final_block = bytes(ciphertext_bytes[:] + (b'\x00'*padding))
            blocks.append(final_block)
    return blocks

def transpose_blocks(blocks: list, keysize: int) -> list:
    '''
    Transposes blocks into new blocks where the first bytes of every block is put
    into the the first block, then the second bytes into the second block, the byte
    n into block n.

    returns a list of bytes
    '''
    transposed_blocks = []
    for _ in range(keysize):
        tmp = bytearray()
        transposed_blocks.append(tmp)
    for block in blocks:
        for i in range(0, keysize):
            transposed_blocks[i] += bytes([block[i]])
    return transposed_blocks
            
def solve_repeating_xor(filepath: str, keysize: int) -> str:
    '''
    This will generate the best candidate for the key used
    to encrypt the ciphertext using a repeating XOR.

    returns str
    '''
    ciphertext_blocks = generate_blocks(filepath, keysize)
    transposed_blocks = transpose_blocks(ciphertext_blocks, keysize)
    key = ''
    for b in transposed_blocks:
        candidates = c3.singlebyte_xor_solve(b.hex())
        key += chr(candidates['byte'])
    return key

if __name__ == "__main__":
    from pathlib import Path
    path = str(Path(__file__).parent.absolute())
    file = open(path + '/' + 'c6_input.txt', 'r')
    txt = file.read()
    file.close()
    candidates = generate_keysize_candidates(txt)[:1]
    keys = []
    for candidate in candidates:
        tmp_key = solve_repeating_xor(path + '/c6_input.txt', candidate['keysize'])
        keys.append(tmp_key)
    for key in keys:
        print('\033[35mUsing Key:\033[39m', key)
        print('\033[35mKeysize:\033[39m', len(key))
        print('\033[35mResulting XOR\'d text:\033[39m', c5.repeating_xor(base64.b64decode(txt).decode(), key).decode())
