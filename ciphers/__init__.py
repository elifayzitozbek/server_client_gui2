from importlib import import_module

_CIPHER_MODULES = {
    "caesar": "ciphers.caesar",
    "vigenere": "ciphers.vigenere",
    "substitution": "ciphers.substitution",
    "playfair": "ciphers.playfair",
    "rail_fence": "ciphers.rail_fence",
    "route_cipher": "ciphers.route_cipher",
    "columnar_transposition": "ciphers.columnar_transposition",
    "polybius": "ciphers.polybius",
    "pigpen": "ciphers.pigpen",
    "affine": "ciphers.affine",
    "vernam": "ciphers.vernam",
    "hill": "ciphers.hill",
}

def apply(cipher_name: str, mode: str, text: str, key: str) -> str:
    cipher_name = (cipher_name or "").lower().strip()
    mode = (mode or "").lower().strip()  

    if cipher_name not in _CIPHER_MODULES:
        raise ValueError(f"Cipher yok: {cipher_name}")

    m = import_module(_CIPHER_MODULES[cipher_name])

    if not hasattr(m, "encrypt") or not hasattr(m, "decrypt"):
        raise ValueError("Cipher fonksiyonları eksik (encrypt/decrypt).")

    return m.encrypt(text, key) if mode == "enc" else m.decrypt(text, key)
