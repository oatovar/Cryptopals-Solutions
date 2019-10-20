#!/usr/bin/env python3

def pkcs7_padding(data: bytes, cipher_block_size: int):
    padding_length = cipher_block_size - (len(data) % cipher_block_size)
    if padding_length != cipher_block_size:
        return data + bytes([padding_length]*padding_length)
    else:
        return data

if __name__ == '__main__':
    b = b'YELLOW SUBMARINE'
    result = pkcs7_padding(b, 20)
    print(result)
