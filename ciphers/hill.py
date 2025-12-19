from .utils import ALPHABET, only_letters_upper, keep_nonletters, modinv, chunk

def _parse(key: str):
    try:
        parts = [int(x) for x in key.replace(" ", "").split(",")]
        if len(parts) != 4:
            raise ValueError()
        return parts[0], parts[1], parts[2], parts[3]
    except:
        raise ValueError("Hill 2x2 key: a,b,c,d (örn 3,3,2,5)")

def encrypt(text: str, key: str) -> str:
    a,b,c,d = _parse(key)
    letters = only_letters_upper(text)
    blocks = chunk(letters, 2, pad="X")
    out = []
    for bl in blocks:
        x1 = ALPHABET.index(bl[0])
        x2 = ALPHABET.index(bl[1])
        y1 = (a*x1 + b*x2) % 26
        y2 = (c*x1 + d*x2) % 26
        out.append(ALPHABET[y1] + ALPHABET[y2])
    return keep_nonletters(text, "".join(out))

def decrypt(text: str, key: str) -> str:
    a,b,c,d = _parse(key)
    det = (a*d - b*c) % 26
    inv_det = modinv(det, 26)
    ia = ( inv_det * d) % 26
    ib = (-inv_det * b) % 26
    ic = (-inv_det * c) % 26
    id = ( inv_det * a) % 26

    letters = only_letters_upper(text)
    blocks = chunk(letters, 2, pad="X")
    out = []
    for bl in blocks:
        y1 = ALPHABET.index(bl[0])
        y2 = ALPHABET.index(bl[1])
        x1 = (ia*y1 + ib*y2) % 26
        x2 = (ic*y1 + id*y2) % 26
        out.append(ALPHABET[x1] + ALPHABET[x2])
    return keep_nonletters(text, "".join(out))
