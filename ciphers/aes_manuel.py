

_AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
_AES_INV_SBOX = [0]*256
for i,v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[v] = i

_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF

def _mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        a = _xtime(a)
        b >>= 1
    return res & 0xFF

def _add_round_key(s, rk):
    for i in range(16):
        s[i] ^= rk[i]

def _sub_bytes(s):
    for i in range(16):
        s[i] = _AES_SBOX[s[i]]

def _inv_sub_bytes(s):
    for i in range(16):
        s[i] = _AES_INV_SBOX[s[i]]

def _shift_rows(s):
    s[1], s[5], s[9],  s[13] = s[5], s[9],  s[13], s[1]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2],  s[6]
    s[3], s[7], s[11], s[15] = s[15], s[3],  s[7],  s[11]

def _inv_shift_rows(s):
    s[1], s[5], s[9],  s[13] = s[13], s[1], s[5], s[9]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]

def _mix_columns(s):
    for c in range(4):
        i = 4*c
        a0,a1,a2,a3 = s[i],s[i+1],s[i+2],s[i+3]
        s[i]   = _mul(a0,2) ^ _mul(a1,3) ^ a2 ^ a3
        s[i+1] = a0 ^ _mul(a1,2) ^ _mul(a2,3) ^ a3
        s[i+2] = a0 ^ a1 ^ _mul(a2,2) ^ _mul(a3,3)
        s[i+3] = _mul(a0,3) ^ a1 ^ a2 ^ _mul(a3,2)

def _inv_mix_columns(s):
    for c in range(4):
        i = 4*c
        a0,a1,a2,a3 = s[i],s[i+1],s[i+2],s[i+3]
        s[i]   = _mul(a0,14) ^ _mul(a1,11) ^ _mul(a2,13) ^ _mul(a3,9)
        s[i+1] = _mul(a0,9)  ^ _mul(a1,14) ^ _mul(a2,11) ^ _mul(a3,13)
        s[i+2] = _mul(a0,13) ^ _mul(a1,9)  ^ _mul(a2,14) ^ _mul(a3,11)
        s[i+3] = _mul(a0,11) ^ _mul(a1,13) ^ _mul(a2,9)  ^ _mul(a3,14)

def _rot_word(w): return w[1:] + w[:1]
def _sub_word(w): return [_AES_SBOX[b] for b in w]

def _key_expansion_128(key16: bytes):
    if len(key16) != 16:
        raise ValueError("AES-128 manual key 16 byte olmalı.")
    key = list(key16)
    w = [key[i:i+4] for i in range(0, 16, 4)]  
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= _RCON[i//4]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    rks = []
    for r in range(11):
        rk = []
        for c in range(4):
            rk += w[r*4 + c]
        rks.append(rk)
    return rks

def encrypt_block(block16: bytes, key16: bytes) -> bytes:
    s = list(block16)
    rks = _key_expansion_128(key16)
    _add_round_key(s, rks[0])
    for r in range(1, 10):
        _sub_bytes(s); _shift_rows(s); _mix_columns(s); _add_round_key(s, rks[r])
    _sub_bytes(s); _shift_rows(s); _add_round_key(s, rks[10])
    return bytes(s)

def decrypt_block(block16: bytes, key16: bytes) -> bytes:
    s = list(block16)
    rks = _key_expansion_128(key16)
    _add_round_key(s, rks[10])
    for r in range(9, 0, -1):
        _inv_shift_rows(s); _inv_sub_bytes(s); _add_round_key(s, rks[r]); _inv_mix_columns(s)
    _inv_shift_rows(s); _inv_sub_bytes(s); _add_round_key(s, rks[0])
    return bytes(s)

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    padlen = block_size - (len(data) % block_size)
    return data + bytes([padlen]) * padlen

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or (len(data) % block_size) != 0:
        raise ValueError("PKCS7 unpad: length invalid")
    padlen = data[-1]
    if padlen < 1 or padlen > block_size:
        raise ValueError("PKCS7 unpad: pad value invalid")
    if data[-padlen:] != bytes([padlen]) * padlen:
        raise ValueError("PKCS7 unpad: pad bytes invalid")
    return data[:-padlen]

def encrypt_cbc(plaintext: bytes, key16: bytes, iv16: bytes) -> bytes:
    if len(iv16) != 16:
        raise ValueError("AES manual iv 16 byte olmalı.")
    pt = pkcs7_pad(plaintext, 16)
    out = bytearray()
    prev = iv16
    for i in range(0, len(pt), 16):
        blk = pt[i:i+16]
        x = bytes([blk[j] ^ prev[j] for j in range(16)])
        ct = encrypt_block(x, key16)
        out += ct
        prev = ct
    return bytes(out)

def decrypt_cbc(ciphertext: bytes, key16: bytes, iv16: bytes) -> bytes:
    if len(iv16) != 16:
        raise ValueError("AES manual iv 16 byte olmalı.")
    if len(ciphertext) % 16 != 0:
        raise ValueError("AES CBC ciphertext length invalid")
    out = bytearray()
    prev = iv16
    for i in range(0, len(ciphertext), 16):
        ct = ciphertext[i:i+16]
        blk = decrypt_block(ct, key16)
        pt = bytes([blk[j] ^ prev[j] for j in range(16)])
        out += pt
        prev = ct
    return pkcs7_unpad(bytes(out), 16)
