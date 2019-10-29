#!/usr/bin/env python3

def repeating_xor(plaintext: str, key: str) -> bytes:
    '''
    XOR's the plaintext bytes repeatedly using a key.
    '''
    plaintext_bytes = bytes(plaintext, 'utf-8')
    key_bytes = bytes(key, 'utf-8')
    blocks = len(plaintext_bytes) // len(key_bytes)
    overrun = len(plaintext_bytes) % len(key_bytes)
    repeated_key_bytes = bytes((key * blocks) + key[:overrun], 'utf-8')
    result = bytearray()
    for key_byte, plaintext_byte in zip(repeated_key_bytes, plaintext_bytes):
        result.append(key_byte ^ plaintext_byte)
    return bytes(result)

if __name__ == "__main__":
    TEXT = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
    KEY = 'ICE'
    result = repeating_xor(TEXT, KEY).hex()
    half = (len(result) // 2) + 1
    part_one = result[:half]
    part_two = result[half:]
    print(part_one)
    print(part_two)

