from .utils import only_letters_upper

_DEFAULT = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  

def _square(key: str):
    k = only_letters_upper(key)
    k = k.replace("J", "I")
    seen = set()
    seq = []
    for ch in k + _DEFAULT:
        if ch == "J": ch = "I"
        if ch not in seen and ch.isalpha():
            seen.add(ch)
            seq.append(ch)
    if len(seq) != 25:
        raise ValueError("Polybius square oluşturulamadı.")
    sq = [seq[i*5:(i+1)*5] for i in range(5)]
    pos = {sq[i][j]:(i+1,j+1) for i in range(5) for j in range(5)}
    return sq, pos

def encrypt(text: str, key: str = "") -> str:
    letters = only_letters_upper(text).replace("J","I")
    sq, pos = _square(key)
    return " ".join(f"{pos[ch][0]}{pos[ch][1]}" for ch in letters)

def decrypt(text: str, key: str = "") -> str:
    sq, _ = _square(key)
    parts = text.replace(",", " ").split()
    out = []
    for p in parts:
        if len(p) != 2 or not p.isdigit():
            continue
        r, c = int(p[0])-1, int(p[1])-1
        if 0 <= r < 5 and 0 <= c < 5:
            out.append(sq[r][c])
    return "".join(out)
