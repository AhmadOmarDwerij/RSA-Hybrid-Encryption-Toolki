#  RSA Hybrid Encryption Toolkit

A simple cryptographic system using **RSA** (public-key) and **AES-GCM** (symmetric-key) encryption. Ideal for secure message exchange over untrusted networks.

---

##  What Is RSA?

**RSA (Rivest–Shamir–Adleman)** is a widely used public-key cryptosystem that enables secure communication.

---

## Key Components

| Component     | Description                              | Keep Secret? | Share? |
|---------------|------------------------------------------|--------------|--------|
| `N`, `e`      | Public key used to encrypt messages      |    No        |  Yes |
| `d`           | Private key used to decrypt messages     |    Yes       |  No  |
| `p`, `q`      | Prime numbers used to generate `N` & `d` |    Yes       |  No  |

---

###  How RSA Works

### 1. Key Generation
1. Choose two large primes: `p`, `q`
2. Compute: `N = p × q`
3. Compute Euler's totient: `φ(N) = (p - 1)(q - 1)`
4. Choose public exponent: `e` (commonly 65537)
5. Compute private exponent: `d` such that `d ≡ e⁻¹ mod φ(N)`

### 2. Encryption
- ciphertext = m^e mod N

### 3. Decryption
- message = ciphertext^d mod N

### Why Hybrid Encryption?
- RSA is inefficient for large data. So this project uses hybrid encryption:

- Encrypt message with AES-GCM (symmetric, fast)

- Encrypt AES key with RSA (asymmetric, secure key exchange)

Package everything into a single encrypted JSON file

### Files in This Project
File	Purpose
generate_keys.py	  Generate RSA key pairs and export as PEM files
encrypt_message.py	Encrypt a message using AES-GCM + recipient's RSA public key
decrypt_message.py	Decrypt the payload using your RSA private key

Security Notes

Key Size	 Status
128–256	   Weak, demo only
1024	     Legacy only
2048	     Industry minimum
3072+	     Stronger, slower

Use 2048 bits or more for real-world security.

 Best Practices
 - Keep your private key safe and secret
 - Share only your public key
 - Use RSA to encrypt keys, not data
 - For large files, encrypt with AES, then RSA-encrypt the AES key

Communication Flow

[Receiver] ➜ generates RSA keys: (N, e, d)
           ➜ shares (N, e)

[Sender]   ➜ encrypts with (N, e) ➜ sends payload

[Receiver] ➜ decrypts using private key (d)

How to Use
1) Generate keys:
 - python3 generate_keys.py

Encrypt a message:
 - python3 encrypt_message.py

Decrypt the message:
 - python3 decrypt_message.py

## License
MIT — use it freely, but use it wisely.
