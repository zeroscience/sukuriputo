
from secrets import token_bytes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC = b"ZS1\0"
VERSION = b"\x11"

def _kdf(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(passphrase.encode('utf-8'))

def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
    salt = token_bytes(16)
    key = _kdf(passphrase, salt)
    aes = AESGCM(key)
    nonce = token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, b"")
    return MAGIC + VERSION + salt + nonce + ct

def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC + VERSION) or len(blob) < 33:
        raise ValueError('Not a SafeEdit file')
    salt = blob[5:21]
    nonce = blob[21:33]
    ct = blob[33:]
    key = _kdf(passphrase, salt)
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ct, b"")
    except InvalidTag:
        raise ValueError('Wrong passphrase or corrupted file')
