
import base64

def _need_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ec  
        from cryptography.hazmat.primitives import hashes  
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF  
        from cryptography.hazmat.primitives import serialization  
    except Exception as e:
        raise RuntimeError(
            "ECC için 'cryptography' paketi gerekli. Kur: pip install cryptography"
        ) from e


def gen_server_static_keypair_p256():
    """
    Sunucu bağlantı açıldığında 1 kez üretilecek (bu bağlantı için).
    Dönen public bytes: DER SubjectPublicKeyInfo
    """
    _need_crypto()
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub_der


def gen_client_ephemeral_keypair_p256():
    """
    İstemci her mesajda (istersen) ephemeral üretebilir.
    Dönen public bytes: DER SubjectPublicKeyInfo
    """
    return gen_server_static_keypair_p256()


def derive_shared_secret_p256(my_priv, peer_pub_der: bytes) -> bytes:
    """
    ECDH shared secret üretir.
    """
    _need_crypto()
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    peer_pub = serialization.load_der_public_key(peer_pub_der)
    if not isinstance(peer_pub, ec.EllipticCurvePublicKey):
        raise ValueError("Peer public key ECC değil.")
    return my_priv.exchange(ec.ECDH(), peer_pub)


def hkdf_sha256(shared_secret: bytes, salt: bytes, info: bytes, dk_len: int) -> bytes:
    """
    ECDH shared secret -> HKDF(SHA256) -> simetrik anahtar
    """
    _need_crypto()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if dk_len not in (8, 16, 24, 32):
        raise ValueError("dk_len 8/16/24/32 olmalı")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("salt bytes olmalı ve en az 8 byte olmalı")
    if not isinstance(info, (bytes, bytearray)) or len(info) < 1:
        raise ValueError("info bytes olmalı")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=dk_len,
        salt=bytes(salt),
        info=bytes(info),
    )
    return hkdf.derive(shared_secret)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))
