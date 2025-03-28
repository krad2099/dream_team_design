#!/usr/bin/env python3
"""
Author: Dream Team
Date: 03/28/2025

Encoder for the eCTF secure system on the MAX78000FTHR microcontroller.

"""

from Crypto.Cipher import AES
import hashlib

BLOCK_SIZE = 16
KEY_SIZE = 16
HASH_SIZE = 16  # MD5 digest size

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
    # Example usage: encrypt and decrypt a 16-byte message.
    key = b'\x00' * KEY_SIZE
    plaintext = b'Crypto Example!!'  # Exactly 16 bytes.
    ciphertext = encrypt_sym(plaintext, key)
    print("Encrypted:", ciphertext.hex())
    decrypted = decrypt_sym(ciphertext, key)
    print("Decrypted:", decrypted)
    h = hash_data(ciphertext)
    print("MD5 Hash:", h.hex())

if __name__ == "__main__":
    main()
