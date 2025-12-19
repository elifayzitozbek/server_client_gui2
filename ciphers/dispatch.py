
import base64
from Crypto.Random import get_random_bytes

from . import aes_lib, des_lib, rsa_lib
from . import des_manual_sdes
from . import aes_manual   


_RSA_PUBLIC_PEM = None
_RSA_PRIVATE_PEM = None


def ensure_rsa_keys():
    global _RSA_PUBLIC_PEM, _RSA_PRIVATE_PEM
    if _RSA_PUBLIC_PEM is None or _RSA_PRIVATE_PEM is None:
        pub, priv = rsa_lib.generate_keypair(2048)
        _RSA_PUBLIC_PEM, _RSA_PRIVATE_PEM = pub, priv
    return _RSA_PUBLIC_PEM, _RSA_PRIVATE_PEM


def get_server_public_pem() -> bytes:
    pub, _ = ensure_rsa_keys()
    return pub


def encrypt_for_send(cipher_name: str, mode: str, plaintext: bytes, server_public_pem: bytes) -> tuple[dict, bytes]:
    """
    returns: (header_dict, body_bytes)
    header will include iv_b64 / wrapped_key_b64 if needed
    """
    cipher_name = (cipher_name or "").upper()
    mode = (mode or "lib").lower()

    header = {"cipher": cipher_name, "mode": mode, "type": "bytes"}

    if cipher_name in ("AES", "DES"):
        
        pub_key = rsa_lib.load_public(server_public_pem)

        
        if cipher_name == "AES":
            key = aes_lib.gen_key(16)   
            iv = aes_lib.gen_iv()       

            if mode == "manual":
               
                ct = aes_manual.encrypt_cbc(plaintext, key, iv)
                header["sym"] = "AES-128-CBC-PKCS7 (manual)"
            else:
                
                ct = aes_lib.encrypt(plaintext, key, iv)
                header["sym"] = "AES-128-CBC-PKCS7 (lib)"

            wrapped = rsa_lib.rsa_encrypt_small(key, pub_key)
            header["iv_b64"] = base64.b64encode(iv).decode("utf-8")
            header["wrapped_key_b64"] = base64.b64encode(wrapped).decode("utf-8")
            return header, ct

       
        if cipher_name == "DES" and mode == "manual":
           
            key = des_lib.gen_key()         
            iv = get_random_bytes(1)         
            ct = des_manual_sdes.encrypt(plaintext, key, iv)
            wrapped = rsa_lib.rsa_encrypt_small(key, pub_key)

            header["iv_b64"] = base64.b64encode(iv).decode("utf-8")
            header["wrapped_key_b64"] = base64.b64encode(wrapped).decode("utf-8")
            header["sym"] = "S-DES(manual)-CBC"
            return header, ct

        
        if cipher_name == "DES":
            key = des_lib.gen_key()     
            iv = des_lib.gen_iv()       
            ct = des_lib.encrypt(plaintext, key, iv)
            wrapped = rsa_lib.rsa_encrypt_small(key, pub_key)

            header["iv_b64"] = base64.b64encode(iv).decode("utf-8")
            header["wrapped_key_b64"] = base64.b64encode(wrapped).decode("utf-8")
            header["sym"] = "DES-CBC-PKCS7 (lib)"
            return header, ct

    if cipher_name == "RSA":
        
        pub_key = rsa_lib.load_public(server_public_pem)
        ct = rsa_lib.rsa_encrypt_chunked(plaintext, pub_key)
        header["asym"] = "RSA-OAEP-SHA256"
        return header, ct

    raise ValueError(f"Unsupported cipher: {cipher_name}")


def decrypt_on_server(header: dict, body: bytes) -> bytes:
    cipher_name = (header.get("cipher") or "").upper()
    mode = (header.get("mode") or "lib").lower()

    _, priv_pem = ensure_rsa_keys()
    priv_key = rsa_lib.load_private(priv_pem)

    if cipher_name in ("AES", "DES"):
        wrapped_b64 = header.get("wrapped_key_b64")
        iv_b64 = header.get("iv_b64")
        if not wrapped_b64 or not iv_b64:
            raise ValueError("Missing wrapped_key_b64 or iv_b64")

        key = rsa_lib.rsa_decrypt_small(base64.b64decode(wrapped_b64), priv_key)
        iv = base64.b64decode(iv_b64)

        
        if cipher_name == "AES":
            if mode == "manual":
                return aes_manual.decrypt_cbc(body, key, iv)
            return aes_lib.decrypt(body, key, iv)

       
        if cipher_name == "DES" and mode == "manual":
            return des_manual_sdes.decrypt(body, key, iv)

        
        if cipher_name == "DES":
            return des_lib.decrypt(body, key, iv)

    if cipher_name == "RSA":
        return rsa_lib.rsa_decrypt_chunked(body, priv_key)

    raise ValueError(f"Unsupported cipher: {cipher_name}")
