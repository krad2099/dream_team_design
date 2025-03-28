#!/usr/bin/env python3
"""
Author: Dream Team
Date: 03/25/2025

Generate subscription updates for the eCTF secure system.
This script uses AES-128 in ECB mode and MD5 for hashing to secure subscription
messages, ensuring compatibility with the WolfSSL-based encryption in the embedded C code.
"""

import os
import struct
import hashlib
from Crypto.Cipher import AES

BLOCK_SIZE = 16
KEY_SIZE = 16
HASH_SIZE = 16

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

def create_subscription_packet(channel: int, start_timestamp: int, end_timestamp: int) -> bytes:
    # Pack the subscription update packet: channel (uint32), start_timestamp (uint64), end_timestamp (uint64)
    packet = struct.pack("<IQQ", channel, start_timestamp, end_timestamp)
    return packet

def secure_subscription_packet(packet: bytes, key: bytes) -> bytes:
    # Ensure the packet length is a multiple of BLOCK_SIZE by padding with zeros if necessary.
    if len(packet) % BLOCK_SIZE != 0:
        padding_length = BLOCK_SIZE - (len(packet) % BLOCK_SIZE)
        packet += b'\x00' * padding_length
    encrypted = encrypt_sym(packet, key)
    # Append the MD5 hash of the encrypted data for integrity.
    packet_hash = hash_data(encrypted)
    return encrypted + packet_hash

def main():
    # Example: create a subscription packet for channel 1.
    channel = 1
    start_timestamp = 1000
    end_timestamp = 2000
    key = os.urandom(KEY_SIZE)
    packet = create_subscription_packet(channel, start_timestamp, end_timestamp)
    secure_packet = secure_subscription_packet(packet, key)
    print("Subscription Packet (encrypted + MD5):", secure_packet.hex())

if __name__ == "__main__":
    main()

