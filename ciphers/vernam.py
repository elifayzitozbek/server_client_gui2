from .utils import ALPHABET, only_letters_upper, keep_nonletters

def _ks(key: str, n: int):
    k = only_letters_upper(key)
    if not k:
        raise ValueError("Vernam key boş olamaz.")
    for i in range(n):
        yield ALPHABET.index(k[i % len(k)])

def encrypt(text: str, key: str) -> str:
    letters = only_letters_upper(text)
    ks = _ks(key, len(letters))
    out = []
    for ch in letters:
        out.append(ALPHABET[(ALPHABET.index(ch) ^ next(ks)) % 26])
    return keep_nonletters(text, "".join(out))

def decrypt(text: str, key: str) -> str:
    return encrypt(text, key)
