#!/usr/bin/env python3

import os
import sys
from Crypto.PublicKey import RSA

# Allowed key sizes. Warn if < 2048.
VALID_SIZES = [1024, 2048, 3072, 4096]


def prompt_key_size() -> int:

    while True:
        try:
            raw = input(f"Enter key size in bits {VALID_SIZES}: ").strip()
            bits = int(raw)
            if bits not in VALID_SIZES:
                print(f"[!] Please choose one of the following: {VALID_SIZES}")
                continue
            return bits
        except ValueError:
            print("[!] Invalid input. Please enter a number (e.g., 2048).")


def prompt_outbase() -> str:

    base = input("Enter a base name for the key files (default: 'mykey'): ").strip()
    if base == "":
        return "mykey"
    return base


def generate_and_save_keys(bits: int, outbase: str) -> None:

    if bits < 2048:
        print(f"[!] Warning: {bits}-bit RSA is considered weak. Use 2048 or higher.", file=sys.stderr)

    print("[*] Generating RSA key pair—this may take a moment...")
    key = RSA.generate(bits)
    pubkey = key.publickey()

    private_pem = key.export_key(format='PEM')
    public_pem = pubkey.export_key(format='PEM')

    priv_filename = f"{outbase}_private.pem"
    pub_filename  = f"{outbase}_public.pem"

    try:
        with open(priv_filename, 'wb') as f:
            f.write(private_pem)
        print(f"[+] Private key saved to '{priv_filename}'.")
    except OSError as e:
        print(f"[!] Error writing private key: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(pub_filename, 'wb') as f:
            f.write(public_pem)
        print(f"[+] Public key saved to '{pub_filename}'.")
    except OSError as e:
        print(f"[!] Error writing public key: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    print("=== RSA Key Generation ===")

    key_size = prompt_key_size()

    outbase = prompt_outbase()

    generate_and_save_keys(key_size, outbase)
    print("[*] Done.")


if __name__ == "__main__":
    main()
