from .utils import only_letters_upper

SYMS = [
    "⌜","⌝","⌞","⌟","┬","┴","├","┤","┼",
    "◸","◹","◿","◺","△","▽","▷","◁","◇",
    "⟐","⟑","⟒","⟓","⟔","⟕","⟖","⟗"
]

def encrypt(text: str, key: str = "") -> str:
    letters = only_letters_upper(text)
    out = []
    for ch in letters:
        out.append(SYMS[ord(ch) - 65])
    return " ".join(out)

def decrypt(text: str, key: str = "") -> str:
    parts = text.split()
    rev = {SYMS[i]: chr(65+i) for i in range(26)}
    out = []
    for p in parts:
        if p in rev:
            out.append(rev[p])
    return "".join(out)
