
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

def generate_keypair(bits: int = 2048):
    key = RSA.generate(bits)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    return public_pem, private_pem

def load_public(pem: bytes) -> RSA.RsaKey:
    return RSA.import_key(pem)

def load_private(pem: bytes) -> RSA.RsaKey:
    return RSA.import_key(pem)

def rsa_encrypt_small(data: bytes, public_key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return cipher.encrypt(data)

def rsa_decrypt_small(data: bytes, private_key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    return cipher.decrypt(data)

def rsa_encrypt_chunked(plaintext: bytes, public_key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    k = public_key.size_in_bytes()
    
    max_chunk = k - 2*SHA256.digest_size - 2
    out = []
    for i in range(0, len(plaintext), max_chunk):
        out.append(cipher.encrypt(plaintext[i:i+max_chunk]))
    return b"".join(out)

def rsa_decrypt_chunked(ciphertext: bytes, private_key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    k = private_key.size_in_bytes()
    if len(ciphertext) % k != 0:
        raise ValueError("Invalid RSA chunked ciphertext size")
    out = []
    for i in range(0, len(ciphertext), k):
        out.append(cipher.decrypt(ciphertext[i:i+k]))
    return b"".join(out)
