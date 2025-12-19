from .utils import ALPHABET, only_letters_upper, keep_nonletters

def _make_maps(key26: str):
    k = only_letters_upper(key26)
    if len(k) != 26 or len(set(k)) != 26:
        raise ValueError("Substitution key 26 harf olmalı ve tekrar etmemeli.")
    enc_map = {ALPHABET[i]: k[i] for i in range(26)}
    dec_map = {k[i]: ALPHABET[i] for i in range(26)}
    return enc_map, dec_map

def encrypt(text: str, key26: str) -> str:
    enc_map, _ = _make_maps(key26)
    letters = only_letters_upper(text)
    out = [enc_map[ch] for ch in letters]
    return keep_nonletters(text, "".join(out))

def decrypt(text: str, key26: str) -> str:
    _, dec_map = _make_maps(key26)
    letters = only_letters_upper(text)
    out = [dec_map[ch] for ch in letters]
    return keep_nonletters(text, "".join(out))
