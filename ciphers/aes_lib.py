
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def gen_key(nbytes: int = 16) -> bytes:
    if nbytes not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes")
    return get_random_bytes(nbytes)

def gen_iv() -> bytes:
    return get_random_bytes(16)

def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)
