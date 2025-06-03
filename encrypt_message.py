#!/usr/bin/env python3

import base64
import json
import os
import sys

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def load_rsa_public_key(pubkey_file: str) -> RSA.RsaKey:
    if not os.path.isfile(pubkey_file):
        print(f"[!] Error: Public key file '{pubkey_file}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(pubkey_file, 'rb') as f:
            pubkey = RSA.import_key(f.read())
    except (ValueError, Exception) as e:
        print(f"[!] Error: could not parse RSA public key: {e}", file=sys.stderr)
        sys.exit(1)

    if pubkey.has_private():
        print(f"[!] Error: '{pubkey_file}' appears to be a private key, not a public key.", file=sys.stderr)
        sys.exit(1)

    return pubkey



def encrypt_hybrid(pubkey: RSA.RsaKey, plaintext: bytes) -> dict:

    aes_key = get_random_bytes(32)


    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)
    nonce = aes_cipher.nonce


    rsa_cipher = PKCS1_OAEP.new(pubkey)
    try:
        enc_aes_key = rsa_cipher.encrypt(aes_key)
    except ValueError as e:
        print(f"[!] RSA encryption failed: {e}")
        sys.exit(1)


    return {
        "enc_aes_key": base64.b64encode(enc_aes_key).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }


def main():
    print("=== Hybrid RSA-AES Message Encryption ===")


    pubkey_file = input("Enter recipient's public key file (e.g., alice_public.pem): ").strip()
    if not pubkey_file:
        print("[!] Public key file is required.")
        return

    pubkey = load_rsa_public_key(pubkey_file)

    mode = ""
    while mode not in ["1", "2"]:
        print("\nChoose input method:")
        print("1. Encrypt a text message")
        print("2. Encrypt a file")
        mode = input("Enter choice [1/2]: ").strip()

    if mode == "1":
        plaintext = input("Enter the message to encrypt: ").strip()
        if not plaintext:
            print("[!] Message cannot be empty.")
            return
        plaintext_bytes = plaintext.encode('utf-8')
    else:
        infile = input("Enter path to file to encrypt: ").strip()
        if not os.path.isfile(infile):
            print(f"[!] File '{infile}' not found.")
            return
        try:
            with open(infile, 'rb') as f:
                plaintext_bytes = f.read()
        except Exception as e:
            print(f"[!] Failed to read file: {e}")
            return

        if not plaintext_bytes:
            print("[!] File is empty.")
            return


    print("[*] Encrypting...")
    payload = encrypt_hybrid(pubkey, plaintext_bytes)


    outfile = input("Enter output filename for encrypted message (default: encrypted_payload.json): ").strip()
    if not outfile:
        outfile = "encrypted_payload.json"

    try:
        with open(outfile, 'w') as f:
            json.dump(payload, f, indent=2)
        print(f"[+] Encrypted payload saved to '{outfile}'")
    except Exception as e:
        print(f"[!] Failed to write output file: {e}")


if __name__ == "__main__":
    main()
