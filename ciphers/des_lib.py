
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def gen_key() -> bytes:
    return get_random_bytes(8)  

def gen_iv() -> bytes:
    return get_random_bytes(8)

def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext, DES.block_size))

def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size)
