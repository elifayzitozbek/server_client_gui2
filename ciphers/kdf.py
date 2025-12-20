
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


def derive_key_pbkdf2(
    passphrase: str,
    salt: bytes,
    dk_len: int,
    iterations: int = 200_000
) -> bytes:
    
    if not isinstance(passphrase, str):
        raise TypeError("passphrase str olmalı")
    if not passphrase.strip():
        raise ValueError("KDF için passphrase boş olamaz")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("salt bytes olmalı ve en az 8 byte olmalı")
    if dk_len not in (8, 16, 24, 32):
       
        raise ValueError("dk_len 8/16/24/32 olmalı")

    return PBKDF2(
        passphrase.strip().encode("utf-8"),
        bytes(salt),
        dkLen=dk_len,
        count=iterations,
        hmac_hash_module=SHA256
    )
