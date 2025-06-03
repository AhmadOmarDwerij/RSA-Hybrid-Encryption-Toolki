#!/usr/bin/env python3

import base64
import json
import os
import sys

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def load_rsa_private_key(privkey_file: str) -> RSA.RsaKey:
    if not os.path.isfile(privkey_file):
        print(f"[!] Error: Private key file '{privkey_file}' not found.")
        sys.exit(1)

    try:
        with open(privkey_file, 'rb') as f:
            privkey = RSA.import_key(f.read())
    except Exception as e:
        print(f"[!] Failed to parse RSA private key: {e}")
        sys.exit(1)

    if not privkey.has_private():
        print(f"[!] File does not contain a valid RSA private key.")
        sys.exit(1)

    return privkey


def decrypt_hybrid(privkey: RSA.RsaKey, payload: dict) -> bytes:
    try:
        enc_aes_key = base64.b64decode(payload["enc_aes_key"])
        nonce       = base64.b64decode(payload["nonce"])
        tag         = base64.b64decode(payload["tag"])
        ciphertext  = base64.b64decode(payload["ciphertext"])
    except (KeyError, ValueError) as e:
        print(f"[!] Invalid payload format or base64 decoding failed: {e}")
        sys.exit(1)

    try:
        rsa_cipher = PKCS1_OAEP.new(privkey)
        aes_key = rsa_cipher.decrypt(enc_aes_key)
    except ValueError as e:
        print(f"[!] RSA decryption failed: {e}")
        sys.exit(1)

    try:
        aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        print(f"[!] AES-GCM decryption failed: {e}")
        sys.exit(1)

    return plaintext


def main():
    print("=== Hybrid RSA-AES Message Decryption ===")


    privkey_file = input("Enter your RSA private key file (e.g., mykey_private.pem): ").strip()
    if not privkey_file:
        print("[!] RSA private key is required.")
        return
    privkey = load_rsa_private_key(privkey_file)


    infile = input("Enter encrypted JSON payload file (default: encrypted_payload.json): ").strip()
    if not infile:
        infile = "encrypted_payload.json"

    if not os.path.isfile(infile):
        print(f"[!] File '{infile}' not found.")
        return

    try:
        with open(infile, 'r') as f:
            payload = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read JSON file: {e}")
        return

    print("[*] Decrypting payload...")
    plaintext_bytes = decrypt_hybrid(privkey, payload)


    out_mode = ""
    while out_mode not in ["1", "2"]:
        print("\nChoose output method:")
        print("1. Display plaintext on screen")
        print("2. Save plaintext to a file")
        out_mode = input("Enter choice [1/2]: ").strip()

    if out_mode == "1":
        try:
            print("\n=== Decrypted Message ===")
            print(plaintext_bytes.decode("utf-8"))
            print("==========================")
        except UnicodeDecodeError:
            print("[!] Message contains binary data. Showing raw bytes:")
            print(plaintext_bytes)
    else:
        outfile = input("Enter filename to save plaintext (e.g., message.txt): ").strip()
        if not outfile:
            print("[!] Output filename is required.")
            return
        try:
            with open(outfile, 'wb') as f:
                f.write(plaintext_bytes)
            print(f"[+] Decrypted plaintext saved to '{outfile}'")
        except Exception as e:
            print(f"[!] Failed to write output file: {e}")


if __name__ == "__main__":
    main()
