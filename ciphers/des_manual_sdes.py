

import hashlib

P10 = (3,5,2,7,4,10,1,9,8,6)
P8  = (6,3,7,4,8,5,10,9)
IP  = (2,6,3,1,4,8,5,7)
IP_INV = (4,1,3,5,7,2,8,6)
EP  = (4,1,2,3,2,3,4,1)
P4  = (2,4,3,1)

S0 = (
    (1,0,3,2),
    (3,2,1,0),
    (0,2,1,3),
    (3,1,3,2),
)
S1 = (
    (0,1,2,3),
    (2,0,1,3),
    (3,0,1,0),
    (2,1,0,3),
)

def _permute(bits, p):
    return [bits[i-1] for i in p]

def _lshift(bits, n):
    return bits[n:] + bits[:n]

def _bits_from_int(x, n):
    return [(x >> (n-1-i)) & 1 for i in range(n)]

def _int_from_bits(b):
    x = 0
    for v in b:
        x = (x << 1) | v
    return x

def _sbox(box, b4):
   
    row = (b4[0] << 1) | b4[3]
    col = (b4[1] << 1) | b4[2]
    val = box[row][col]
    return _bits_from_int(val, 2)

def _fk(L, R, subkey):
 
    er = _permute(R, EP)
    x = [er[i] ^ subkey[i] for i in range(8)]
    left4, right4 = x[:4], x[4:]
    s0 = _sbox(S0, left4)
    s1 = _sbox(S1, right4)
    p4 = _permute(s0 + s1, P4)
    L2 = [L[i] ^ p4[i] for i in range(4)]
    return L2, R

def _key_schedule(key10bits):
    p10 = _permute(key10bits, P10)
    left, right = p10[:5], p10[5:]
    left1, right1 = _lshift(left, 1), _lshift(right, 1)
    k1 = _permute(left1 + right1, P8)
    left2, right2 = _lshift(left1, 2), _lshift(right1, 2)
    k2 = _permute(left2 + right2, P8)
    return k1, k2

def _derive_10bit_key(key_bytes: bytes) -> list[int]:
 
    h = hashlib.sha256(key_bytes).digest()
    v = int.from_bytes(h[:2], "big")  
    v = v & ((1<<10)-1)
    return _bits_from_int(v, 10)

def encrypt_block8(block8: int, key_bytes: bytes) -> int:
    key10 = _derive_10bit_key(key_bytes)
    k1, k2 = _key_schedule(key10)

    bits = _bits_from_int(block8, 8)
    ip = _permute(bits, IP)
    L, R = ip[:4], ip[4:]

    L, R = _fk(L, R, k1)
    L, R = R, L  
    L, R = _fk(L, R, k2)

    pre = L + R
    out = _permute(pre, IP_INV)
    return _int_from_bits(out)

def decrypt_block8(block8: int, key_bytes: bytes) -> int:
    key10 = _derive_10bit_key(key_bytes)
    k1, k2 = _key_schedule(key10)

    bits = _bits_from_int(block8, 8)
    ip = _permute(bits, IP)
    L, R = ip[:4], ip[4:]

    L, R = _fk(L, R, k2)
    L, R = R, L
    L, R = _fk(L, R, k1)

    pre = L + R
    out = _permute(pre, IP_INV)
    return _int_from_bits(out)

def encrypt(plaintext: bytes, key8: bytes, iv1: bytes) -> bytes:
    
    if len(key8) != 8:
        raise ValueError("Manual DES expects 8-byte key (used to derive 10-bit S-DES key).")
    if len(iv1) != 1:
        raise ValueError("Manual DES expects 1-byte IV.")
    out = bytearray()
    prev = iv1[0]
    for b in plaintext:
        x = b ^ prev
        c = encrypt_block8(x, key8)
        out.append(c)
        prev = c
    return bytes(out)

def decrypt(ciphertext: bytes, key8: bytes, iv1: bytes) -> bytes:
    if len(key8) != 8:
        raise ValueError("Manual DES expects 8-byte key.")
    if len(iv1) != 1:
        raise ValueError("Manual DES expects 1-byte IV.")
    out = bytearray()
    prev = iv1[0]
    for c in ciphertext:
        x = decrypt_block8(c, key8)
        p = x ^ prev
        out.append(p)
        prev = c
    return bytes(out)
