#!/usr/bin/env python3

# Cryptopals Set 1 Challenge 3

import string

# Distribution Statistics: http://www.data-compression.com/english.html

CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

def calculate_score(result_bytes: bytearray) -> float:
    '''
    Calculate a 'score' that indicates the probability of the bytearray
    being in the English language.
    '''
    score = 0
    for byte in result_bytes:
        score += CHARACTER_FREQ.get(chr(byte).lower(), 0)
    return score
    
def singlebyte_xor(hexstr: str, byte: int) -> bytearray:
    '''
    XOR a hex string with a given byte value
    
    Returns the XOR'ed hexstring as a bytarray
    '''
    b = bytes.fromhex(hexstr)
    result = bytearray()
    for i in b:
        result.append(i^byte)
    return result
    
def singlebyte_xor_solve(hexstr: str) -> bytes:
    '''
    Finds the byte used to XOR a plaintext and convert it into a hexstring
    
    Returns (plaintext: str, value: byte)
    '''
    bruteforce_results = []
    for val in range(256):
        plaintext = singlebyte_xor(hexstr, val)
        score = calculate_score(plaintext)
        
        result = {
            'byte': val,
            'plaintext': plaintext,
            'score': score,
        }
        
        bruteforce_results.append(result)
    return sorted(bruteforce_results, key=lambda c: c['score'], reverse=True)[0]

def beautify(result):
    return 'Plaintext: ' + result['plaintext'].decode().strip() + '\tScore: ' + '{0:.2f}'.format(result['score']) + '\tChar: ' + chr(result['byte'])

if __name__ == '__main__':
    print('Problem 3:', beautify(singlebyte_xor_solve('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')))

