# SillyEncrypt

SillyEncrypt is a web-based tool for encrypting and decrypting short text messages using a passphrase. It exchanges `.zsl` files to keep encrypted payloads portable and simple.

## How It Works

### Encryption Workflow
1. User inputs plaintext and a passphrase.
2. The system derives a strong key using **Scrypt**.
3. The plaintext is encrypted using **AES‑GCM**.
4. Output file format:
   ```
   MAGIC (4 bytes) +
   VERSION (1 byte) +
   SALT (16 bytes) +
   NONCE (12 bytes) +
   CIPHERTEXT+TAG (...)
   ```
5. Browser downloads the result as a `.zsl` file.

### Decryption Workflow
1. User uploads a `.zsl` file.
2. Passphrase is provided.
3. Key is re-derived using the stored salt.
4. AES‑GCM validates and decrypts the ciphertext.
5. The plaintext is shown in the browser.
6. User may download the plaintext as `.txt`.

## Cryptography Details

### Key Derivation
Scrypt parameters:
- `n = 2^15`
- `r = 8`
- `p = 1`
- Output key length: **32 bytes**

### Encryption
- Algorithm: **AES‑256‑GCM**
- Nonce length: **12 bytes**
- Authentication tag included in ciphertext
- Associated data: empty

### File Layout
The file begins with a magic header and version:
```
MAGIC   = 5A 53 31 00   ("ZS1\0")
VERSION = 11
```

Offsets:
```
[0:4]   MAGIC
[4:5]   VERSION
[5:21]  SALT (16 bytes)
[21:33] NONCE (12 bytes)
[33:]   CIPHERTEXT + TAG
```

## Running the Application

SillyEncrypt uses Flask. Requirements:
```
flask
cryptography
```

Start:
```
python3 app.py
```

## crypto.py Reference

The tool uses the following cryptographic operations:

- `Scrypt` for deriving the key from the passphrase and salt.
- `AESGCM` for symmetric authenticated encryption.
- Secure random values for both salt and nonce.
