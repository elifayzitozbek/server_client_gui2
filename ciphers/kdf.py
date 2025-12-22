
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

def derive_key_hkdf_sha256(
    shared_secret: bytes,
    salt: bytes,
    dk_len: int,
    info: bytes = b"server_client_gui2-ecdh"
) -> bytes:
    """
    ECDH shared secret -> HKDF-SHA256 -> key
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except Exception as e:
        raise RuntimeError("HKDF için 'cryptography' paketi gerekli. Kur: pip install cryptography") from e

    if not isinstance(shared_secret, (bytes, bytearray)) or len(shared_secret) < 16:
        raise ValueError("shared_secret bytes olmalı ve yeterince uzun olmalı")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("salt bytes olmalı ve en az 8 byte olmalı")
    if dk_len not in (8, 16, 24, 32):
        raise ValueError("dk_len 8/16/24/32 olmalı")
    if not isinstance(info, (bytes, bytearray)) or len(info) < 1:
        raise ValueError("info bytes olmalı")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=dk_len,
        salt=bytes(salt),
        info=bytes(info),
    )
    return hkdf.derive(bytes(shared_secret))
