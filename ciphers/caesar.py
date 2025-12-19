from .utils import ALPHABET, only_letters_upper, keep_nonletters

def _enc(text: str, shift: int) -> str:
    letters = only_letters_upper(text)
    out = []
    for ch in letters:
        out.append(ALPHABET[(ALPHABET.index(ch) + shift) % 26])
    return keep_nonletters(text, "".join(out))

def encrypt(text: str, key: str) -> str:
    return _enc(text, int(key))

def decrypt(text: str, key: str) -> str:
    return _enc(text, -int(key))
