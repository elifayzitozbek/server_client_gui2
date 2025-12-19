import string
from typing import List, Tuple

ALPHABET = string.ascii_uppercase

def only_letters_upper(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch.isalpha())

def keep_nonletters(original: str, transformed_letters: str) -> str:
    out = []
    it = iter(transformed_letters)
    for ch in original:
        if ch.isalpha():
            t = next(it)
            out.append(t.lower() if ch.islower() else t)
        else:
            out.append(ch)
    return "".join(out)

def chunk(text: str, n: int, pad: str = "X") -> List[str]:
    res = []
    for i in range(0, len(text), n):
        part = text[i:i+n]
        if len(part) < n:
            part += pad * (n - len(part))
        res.append(part)
    return res

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def modinv(a: int, m: int) -> int:
    a %= m
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Modüler ters yok (anahtar geçersiz).")
    return x % m
