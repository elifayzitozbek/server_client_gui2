from .utils import ALPHABET, only_letters_upper, keep_nonletters, modinv

def _parse(key: str):
    try:
        a, b = key.replace(" ", "").split(",")
        a, b = int(a), int(b)
        return a, b
    except:
        raise ValueError("Affine key format: a,b (örn 5,8)")

def encrypt(text: str, key: str) -> str:
    a, b = _parse(key)
    letters = only_letters_upper(text)
    out = []
    for ch in letters:
        x = ALPHABET.index(ch)
        out.append(ALPHABET[(a*x + b) % 26])
    return keep_nonletters(text, "".join(out))

def decrypt(text: str, key: str) -> str:
    a, b = _parse(key)
    inv = modinv(a, 26)
    letters = only_letters_upper(text)
    out = []
    for ch in letters:
        y = ALPHABET.index(ch)
        out.append(ALPHABET[(inv * (y - b)) % 26])
    return keep_nonletters(text, "".join(out))
