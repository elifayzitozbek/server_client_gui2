from .utils import only_letters_upper

def _square(key: str):
    k = only_letters_upper(key).replace("J","I")
    base = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    seen = set()
    seq = []
    for ch in k + base:
        if ch == "J": ch = "I"
        if ch not in seen:
            seen.add(ch)
            seq.append(ch)
    sq = [seq[i*5:(i+1)*5] for i in range(5)]
    pos = {sq[i][j]:(i,j) for i in range(5) for j in range(5)}
    return sq, pos

def _digraphs(text: str):
    t = only_letters_upper(text).replace("J","I")
    out = []
    i = 0
    while i < len(t):
        a = t[i]
        b = t[i+1] if i+1 < len(t) else "X"
        if a == b:
            out.append((a, "X"))
            i += 1
        else:
            out.append((a, b))
            i += 2
    if out and len(out[-1]) == 2 and out[-1][1] == "":
        out[-1] = (out[-1][0], "X")
    return out

def encrypt(text: str, key: str) -> str:
    sq, pos = _square(key)
    pairs = _digraphs(text)
    out = []
    for a,b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(sq[ra][(ca+1)%5])
            out.append(sq[rb][(cb+1)%5])
        elif ca == cb:
            out.append(sq[(ra+1)%5][ca])
            out.append(sq[(rb+1)%5][cb])
        else:
            out.append(sq[ra][cb])
            out.append(sq[rb][ca])
    return "".join(out)

def decrypt(text: str, key: str) -> str:
    sq, pos = _square(key)
    t = only_letters_upper(text)
    if len(t) % 2 != 0:
        raise ValueError("Playfair ciphertext çift uzunluk olmalı.")
    out = []
    for i in range(0, len(t), 2):
        a,b = t[i], t[i+1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(sq[ra][(ca-1)%5])
            out.append(sq[rb][(cb-1)%5])
        elif ca == cb:
            out.append(sq[(ra-1)%5][ca])
            out.append(sq[(rb-1)%5][cb])
        else:
            out.append(sq[ra][cb])
            out.append(sq[rb][ca])
    return "".join(out)
