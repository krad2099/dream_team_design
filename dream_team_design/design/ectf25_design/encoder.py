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

class Encoder:
    def __init__(self, key: bytes):
        if len(key) != KEY_SIZE:
            raise ValueError("Key must be exactly 16 bytes long")
        self.key = key

    def encode(self, plaintext: bytes) -> bytes:
        """
        Encrypts the plaintext using AES-128 in ECB mode and appends an MD5 hash
        of the ciphertext for integrity. The plaintext must be a multiple of 16 bytes.
        
        Returns:
            The concatenation of the ciphertext and its MD5 hash.
        """
        ciphertext = encrypt_sym(plaintext, self.key)
        digest = hash_data(ciphertext)
        return ciphertext + digest

def main():
    # Example usage: encrypt a 16-byte message and verify integrity upon decryption.
    key = b'\x00' * KEY_SIZE
    encoder = Encoder(key)
    plaintext = b'Crypto Example!!'  # Exactly 16 bytes.
    
    encoded_message = encoder.encode(plaintext)
    print("Encoded message (ciphertext + MD5):", encoded_message.hex())
    
    # For demonstration: separate the ciphertext and the appended hash.
    ciphertext = encoded_message[:-HASH_SIZE]
    provided_hash = encoded_message[-HASH_SIZE:]
    computed_hash = hash_data(ciphertext)
    
    if provided_hash == computed_hash:
        print("Hash verified.")
        decrypted = decrypt_sym(ciphertext, key)
        print("Decrypted:", decrypted)
    else:
        print("Hash mismatch!")

if __name__ == "__main__":
    main()
