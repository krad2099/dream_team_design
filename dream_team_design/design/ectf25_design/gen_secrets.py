#!/usr/bin/env python3
"""

Author: Dream Team
Date: 03/28/2025

Generate secrets for the eCTF secure system.
"""

import os
import hashlib
from Crypto.Cipher import AES

BLOCK_SIZE = 16
KEY_SIZE = 16
HASH_SIZE = 16

def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)

def encrypt_sym(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError("Plaintext length must be a multiple of 16 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def decrypt_sym(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def hash_data(data: bytes) -> bytes:
    m = hashlib.md5()
    m.update(data)
    return m.digest()

def main():
    key = generate_key()
    print("Generated Key:", key.hex())
    # Test encryption of a block of zeros.
    plaintext = b'\x00' * BLOCK_SIZE
    ciphertext = encrypt_sym(plaintext, key)
    print("Encrypted zeros:", ciphertext.hex())
    decrypted = decrypt_sym(ciphertext, key)
    print("Decrypted:", decrypted.hex())
    h = hash_data(plaintext)
    print("MD5 Hash of zeros:", h.hex())

if __name__ == "__main__":
    main()
