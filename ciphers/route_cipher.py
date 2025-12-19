from .utils import only_letters_upper, keep_nonletters

def _parse_key(key: str):
    try:
        a, b = key.replace(" ", "").split(",")
        r, c = int(a), int(b)
        if r <= 0 or c <= 0:
            raise ValueError()
        return r, c
    except:
        raise ValueError("Route key format: rows,cols (örn 4,5)")

def encrypt(text: str, key: str) -> str:
    r, c = _parse_key(key)
    letters = only_letters_upper(text)
    total = r * c
    if len(letters) > total:
        raise ValueError(f"Metin çok uzun. max={total} harf (rows*cols)")
    letters = letters.ljust(total, "X")

    grid = [list(letters[i*c:(i+1)*c]) for i in range(r)]

    top, left, bottom, right = 0, 0, r-1, c-1
    out = []
    while top <= bottom and left <= right:
        for j in range(left, right+1): out.append(grid[top][j])
        top += 1
        for i in range(top, bottom+1): out.append(grid[i][right])
        right -= 1
        if top <= bottom:
            for j in range(right, left-1, -1): out.append(grid[bottom][j])
            bottom -= 1
        if left <= right:
            for i in range(bottom, top-1, -1): out.append(grid[i][left])
            left += 1

    res = "".join(out)
    return keep_nonletters(text, res[:len(only_letters_upper(text))])

def decrypt(text: str, key: str) -> str:
    r, c = _parse_key(key)
    letters = only_letters_upper(text)
    total = r * c
    if len(letters) > total:
        raise ValueError(f"Metin çok uzun. max={total} harf (rows*cols)")
    letters = letters.ljust(total, "X")

    grid = [[""] * c for _ in range(r)]
    top, left, bottom, right = 0, 0, r-1, c-1
    idx = 0
    while top <= bottom and left <= right:
        for j in range(left, right+1): grid[top][j], idx = letters[idx], idx+1
        top += 1
        for i in range(top, bottom+1): grid[i][right], idx = letters[idx], idx+1
        right -= 1
        if top <= bottom:
            for j in range(right, left-1, -1): grid[bottom][j], idx = letters[idx], idx+1
            bottom -= 1
        if left <= right:
            for i in range(bottom, top-1, -1): grid[i][left], idx = letters[idx], idx+1
            left += 1

    out = []
    for i in range(r):
        for j in range(c):
            out.append(grid[i][j])
    res = "".join(out)[:len(only_letters_upper(text))]
    return keep_nonletters(text, res)
