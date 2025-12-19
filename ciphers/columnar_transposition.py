from .utils import only_letters_upper, keep_nonletters, chunk

def _order(key: str):
    k = key.upper()
    if not k or not all(ch.isalpha() for ch in k):
        raise ValueError("Columnar key harflerden oluşmalı.")
    indexed = list(enumerate(k))
    indexed.sort(key=lambda x: (x[1], x[0]))
    order = [i for i, _ in indexed]
    return order

def encrypt(text: str, key: str) -> str:
    letters = only_letters_upper(text)
    w = len(key)
    order = _order(key)
    rows = chunk(letters, w, pad="X")
    cols = []
    for c in range(w):
        col = "".join(row[c] for row in rows)
        cols.append(col)
    res = "".join(cols[i] for i in order)
    return keep_nonletters(text, res)

def decrypt(text: str, key: str) -> str:
    letters = only_letters_upper(text)
    w = len(key)
    order = _order(key)
    n = len(letters)
    h = (n + w - 1) // w

    cols = [""] * w
    idx = 0
    for i in order:
        cols[i] = letters[idx:idx+h]
        idx += h

    out = []
    for r in range(h):
        for c in range(w):
            out.append(cols[c][r])
    res = "".join(out)[:n]
    return keep_nonletters(text, res)
