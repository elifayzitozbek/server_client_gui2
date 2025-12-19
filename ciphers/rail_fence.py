from .utils import only_letters_upper, keep_nonletters

def _enc(text: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rail sayısı >= 2 olmalı.")
    letters = only_letters_upper(text)
    rows = [[] for _ in range(rails)]
    r, step = 0, 1
    for ch in letters:
        rows[r].append(ch)
        if r == 0: step = 1
        elif r == rails - 1: step = -1
        r += step
    res = "".join("".join(row) for row in rows)
    return keep_nonletters(text, res)

def _dec(text: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rail sayısı >= 2 olmalı.")
    letters = only_letters_upper(text)
    n = len(letters)
    pattern = []
    r, step = 0, 1
    for _ in range(n):
        pattern.append(r)
        if r == 0: step = 1
        elif r == rails - 1: step = -1
        r += step
    counts = [0] * rails
    for rr in pattern:
        counts[rr] += 1
    rows = []
    idx = 0
    for c in counts:
        rows.append(list(letters[idx:idx+c]))
        idx += c
    pos = [0] * rails
    out = []
    for rr in pattern:
        out.append(rows[rr][pos[rr]])
        pos[rr] += 1
    return keep_nonletters(text, "".join(out))

def encrypt(text: str, key: str) -> str:
    return _enc(text, int(key))

def decrypt(text: str, key: str) -> str:
    return _dec(text, int(key))
