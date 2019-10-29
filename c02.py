#!/usr/bin/env python3

# Cryptopals Set 1 Challenge 2

def fixed_xor(buf1: str, buf2: str) -> bytes:
    b1 = bytes.fromhex(buf1)
    b2 = bytes.fromhex(buf2)
    b3 = bytearray()
    
    if len(b1) != len(b2):
        raise Exception('Buffers are not of the same length!')
        
    for i, j in zip(b1, b2):
        b3.append(i^j)
    
    return b3
    
if __name__ == '__main__':
    print('Problem 2:', fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965').decode())

