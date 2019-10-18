#!/usr/bin/env python3

import base64
import bitstring

def beautify(candidates: list):
    '''
    Pretty prints the candidates returned
    '''
    for c in candidates:
        print('Keysize: {}\tHamming Distance: {}'.format( c['keysize'], c['normalized_distance']))

def hamming_distance(str1: str, str2: str) -> int:
    '''
    Calculates the total amount of differing bits between two bits.

    returns (int) distance
    '''
    # declare bitarrays
    b1 = bitstring.Bits(bytes(str1, 'utf-8')).bin
    b2 = bitstring.Bits(bytes(str2, 'utf-8')).bin
    # calculate difference in bit length as initial bit diff count
    count = abs(len(b1) - len(b2))
    for i, j in zip(b1, b2):
        count = count + 1 if i != j else count + 0
    return count

def generate_keysize_candidates():
    '''
    Calculates the hamming distance for a variety of keysizes and returns
    the top 4 candidates.

    returns a list of candidates
    '''
    distance_candidates = []
    with open('c6_input.txt', 'r') as file:
        b64_ciphertext = file.read()
        b64_ciphertext_bytes = bytes(b64_ciphertext, 'utf-8')
        ciphertext_bytes = base64.b64decode(b64_ciphertext_bytes)
        for KEYSIZE in range(2, 41):
            first_bytes = ciphertext_bytes[:KEYSIZE]
            second_bytes = ciphertext_bytes[KEYSIZE:KEYSIZE*2]
            distance = hamming_distance(first_bytes.decode(), second_bytes.decode())
            normalized_distance = distance / KEYSIZE
            distance_candidate = {
                'keysize': KEYSIZE,
                'normalized_distance': normalized_distance,
            }
            distance_candidates.append(distance_candidate)
    return sorted(distance_candidates, key=lambda c: c['normalized_distance'])[:5]

if __name__ == "__main__":
    # Test hamming_distance
    test_distance = hamming_distance('this is a test', 'wokka wokka!!!')
    print('Testing Hamming Distance. Result: {}'.format(test_distance))
    print('Keysize Candidates:')
    beautify(generate_keysize_candidates())
    
