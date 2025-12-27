import socket, threading, json, struct, base64
import os, mimetypes
import hashlib
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import ttkbootstrap as tb
from ttkbootstrap.constants import *

from ciphers import apply
from ciphers.kdf import derive_key_pbkdf2

from ciphers import ecc_lib
from ciphers.kdf import derive_key_hkdf_sha256

try:
    from Crypto.Cipher import AES as C_AES, DES as C_DES, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import pad as c_pad, unpad as c_unpad
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
except Exception:
    C_AES = C_DES = PKCS1_OAEP = RSA = None
    c_pad = c_unpad = None
    get_random_bytes = None
    SHA256 = None


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


def pack_msg(header: dict, body: bytes) -> bytes:
    hb = json.dumps(header).encode("utf-8")
    return struct.pack(">I", len(hb)) + hb + body


def recvall(sock: socket.socket, n: int):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _need_crypto():
    if C_AES is None or C_DES is None or RSA is None:
        raise RuntimeError("PyCryptodome yok. Kur: pip install pycryptodome")


def fp_bytes(data: bytes, n=12) -> str:
    if data is None:
        return "-"
    h = hashlib.sha256(data).hexdigest()
    return h[:n]



P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8  = (6, 3, 7, 4, 8, 5, 10, 9)
IP  = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP  = (4, 1, 2, 3, 2, 3, 4, 1)
P4  = (2, 4, 3, 1)

S0 = (
    (1, 0, 3, 2),
    (3, 2, 1, 0),
    (0, 2, 1, 3),
    (3, 1, 3, 2),
)
S1 = (
    (0, 1, 2, 3),
    (2, 0, 1, 3),
    (3, 0, 1, 0),
    (2, 1, 0, 3),
)

def _permute(bits, p): return [bits[i-1] for i in p]
def _lshift(bits, n): return bits[n:] + bits[:n]
def _bits_from_int(x, n): return [(x >> (n-1-i)) & 1 for i in range(n)]
def _int_from_bits(b):
    x = 0
    for v in b:
        x = (x << 1) | v
    return x

def _sbox(box, b4):
    row = (b4[0] << 1) | b4[3]
    col = (b4[1] << 1) | b4[2]
    return _bits_from_int(box[row][col], 2)

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

def _derive_10bit_key_from_8bytes(key8: bytes) -> list[int]:
    h = hashlib.sha256(key8).digest()
    v = int.from_bytes(h[:2], "big") & ((1 << 10) - 1)
    return _bits_from_int(v, 10)

def sdes_encrypt_block8(block8: int, key8: bytes) -> int:
    key10 = _derive_10bit_key_from_8bytes(key8)
    k1, k2 = _key_schedule(key10)
    bits = _bits_from_int(block8, 8)
    ip = _permute(bits, IP)
    L, R = ip[:4], ip[4:]
    L, R = _fk(L, R, k1)
    L, R = R, L
    L, R = _fk(L, R, k2)
    out = _permute(L + R, IP_INV)
    return _int_from_bits(out)

def sdes_decrypt_block8(block8: int, key8: bytes) -> int:
    key10 = _derive_10bit_key_from_8bytes(key8)
    k1, k2 = _key_schedule(key10)
    bits = _bits_from_int(block8, 8)
    ip = _permute(bits, IP)
    L, R = ip[:4], ip[4:]
    L, R = _fk(L, R, k2)
    L, R = R, L
    L, R = _fk(L, R, k1)
    out = _permute(L + R, IP_INV)
    return _int_from_bits(out)

def sdes_encrypt_cbc(plaintext: bytes, key8: bytes, iv1: bytes) -> bytes:
    prev = iv1[0]
    out = bytearray()
    for b in plaintext:
        c = sdes_encrypt_block8(b ^ prev, key8)
        out.append(c)
        prev = c
    return bytes(out)

def sdes_decrypt_cbc(ciphertext: bytes, key8: bytes, iv1: bytes) -> bytes:
    prev = iv1[0]
    out = bytearray()
    for c in ciphertext:
        p = sdes_decrypt_block8(c, key8) ^ prev
        out.append(p)
        prev = c
    return bytes(out)


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
for i, v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[v] = i
_AES_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def _xtime(a): return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF
def _mul(a, b):
    res = 0
    for _ in range(8):
        if b & 1: res ^= a
        a = _xtime(a)
        b >>= 1
    return res & 0xFF

def _sub_bytes(s):
    for i in range(16): s[i] = _AES_SBOX[s[i]]
def _inv_sub_bytes(s):
    for i in range(16): s[i] = _AES_INV_SBOX[s[i]]

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

def _add_round_key(s, rk):
    for i in range(16): s[i] ^= rk[i]

def _rot_word(w): return w[1:] + w[:1]
def _sub_word(w): return [_AES_SBOX[b] for b in w]

def aes128_key_expansion(key16: bytes):
    if len(key16) != 16:
        raise ValueError("Manual AES key 16 byte olmalı (AES-128).")
    key = list(key16)
    w = [key[i:i+4] for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= _AES_RCON[i//4]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    rks = []
    for r in range(11):
        rk = []
        for c in range(4):
            rk += w[r*4 + c]
        rks.append(rk)
    return rks

def aes128_encrypt_block(block16: bytes, key16: bytes) -> bytes:
    s = list(block16)
    rks = aes128_key_expansion(key16)
    _add_round_key(s, rks[0])
    for r in range(1, 10):
        _sub_bytes(s); _shift_rows(s); _mix_columns(s); _add_round_key(s, rks[r])
    _sub_bytes(s); _shift_rows(s); _add_round_key(s, rks[10])
    return bytes(s)

def aes128_decrypt_block(block16: bytes, key16: bytes) -> bytes:
    s = list(block16)
    rks = aes128_key_expansion(key16)
    _add_round_key(s, rks[10])
    for r in range(9, 0, -1):
        _inv_shift_rows(s); _inv_sub_bytes(s); _add_round_key(s, rks[r]); _inv_mix_columns(s)
    _inv_shift_rows(s); _inv_sub_bytes(s); _add_round_key(s, rks[0])
    return bytes(s)

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    padlen = block_size - (len(data) % block_size)
    return data + bytes([padlen]) * padlen

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("PKCS7 unpad: length invalid")
    padlen = data[-1]
    if padlen < 1 or padlen > block_size:
        raise ValueError("PKCS7 unpad: pad value invalid")
    if data[-padlen:] != bytes([padlen]) * padlen:
        raise ValueError("PKCS7 unpad: pad bytes invalid")
    return data[:-padlen]

def aes128_cbc_encrypt_manual(plaintext: bytes, key16: bytes, iv16: bytes) -> bytes:
    pt = pkcs7_pad(plaintext, 16)
    out = bytearray()
    prev = iv16
    for i in range(0, len(pt), 16):
        blk = bytes([pt[i+j] ^ prev[j] for j in range(16)])
        ct = aes128_encrypt_block(blk, key16)
        out += ct
        prev = ct
    return bytes(out)

def aes128_cbc_decrypt_manual(ciphertext: bytes, key16: bytes, iv16: bytes) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("AES CBC ciphertext length invalid")
    out = bytearray()
    prev = iv16
    for i in range(0, len(ciphertext), 16):
        ct = ciphertext[i:i+16]
        blk = aes128_decrypt_block(ct, key16)
        pt = bytes([blk[j] ^ prev[j] for j in range(16)])
        out += pt
        prev = ct
    return pkcs7_unpad(bytes(out), 16)



def aes_encrypt_lib(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = C_AES.new(key, C_AES.MODE_CBC, iv=iv)
    return cipher.encrypt(c_pad(plaintext, 16))

def aes_decrypt_lib(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = C_AES.new(key, C_AES.MODE_CBC, iv=iv)
    return c_unpad(cipher.decrypt(ciphertext), 16)

def des_encrypt_lib(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = C_DES.new(key, C_DES.MODE_CBC, iv=iv)
    return cipher.encrypt(c_pad(plaintext, 8))

def des_decrypt_lib(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = C_DES.new(key, C_DES.MODE_CBC, iv=iv)
    return c_unpad(cipher.decrypt(ciphertext), 8)

def rsa_generate_keypair(bits=2048):
    _need_crypto()
    key = RSA.generate(bits)
    return key.publickey().export_key(), key.export_key()

def rsa_wrap_key(sym_key: bytes, public_pem: bytes) -> bytes:
    _need_crypto()
    pub = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    return cipher.encrypt(sym_key)

def rsa_unwrap_key(wrapped: bytes, private_pem: bytes) -> bytes:
    _need_crypto()
    priv = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    return cipher.decrypt(wrapped)

def rsa_encrypt_chunked(plaintext: bytes, public_pem: bytes) -> bytes:
    _need_crypto()
    pub = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    k = pub.size_in_bytes()
    max_chunk = k - 2 * SHA256.digest_size - 2
    out = []
    for i in range(0, len(plaintext), max_chunk):
        out.append(cipher.encrypt(plaintext[i:i+max_chunk]))
    return b"".join(out)

def rsa_decrypt_chunked(ciphertext: bytes, private_pem: bytes) -> bytes:
    _need_crypto()
    priv = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    k = priv.size_in_bytes()
    if len(ciphertext) % k != 0:
        raise ValueError("RSA ciphertext boyutu hatalı (chunk uyumsuz).")
    out = []
    for i in range(0, len(ciphertext), k):
        out.append(cipher.decrypt(ciphertext[i:i+k]))
    return b"".join(out)


class App:
    def __init__(self, root):
        self.root = root
        root.title("Sunucu + İstemci | Mesaj Şifreleme")
        root.geometry("980x700")

        self._apply_makeup()

        self.nb = tb.Notebook(root, bootstyle="primary")
        self.nb.pack(fill="both", expand=True)

        self.server_sock = None
        self.server_conn = None
        self.server_thread = None
        self.server_recv_thread = None

        self.client_sock = None
        self.client_recv_thread = None

        self.server_pub_pem = None
        self.server_priv_pem = None
        self.client_server_pub_pem = None

        self.server_ecc_priv = None
        self.server_ecc_pub_der = None
        self.client_server_ecc_pub_der = None

       
        self.use_kdf = tk.BooleanVar(value=False)

        self.server_tab = ttk.Frame(self.nb)
        self.client_tab = ttk.Frame(self.nb)
        self.nb.add(self.server_tab, text="Sunucu")
        self.nb.add(self.client_tab, text="İstemci")

        self._build_server_tab()
        self._build_client_tab()

    def _apply_makeup(self):
        try:
            style = tb.Style()
            style.configure(".", font=("Segoe UI", 10))
            style.configure("TNotebook.Tab", padding=(14, 8))
            style.configure("TButton", padding=(10, 6))
            self.root.option_add("*TCombobox*Listbox.font", ("Segoe UI", 10))
        except Exception:
            pass

    def log(self, box: scrolledtext.ScrolledText, msg: str):
        box.configure(state="normal")
        box.insert("end", msg + "\n")
        box.see("end")
        box.configure(state="disabled")

    def _build_server_tab(self):
        top = ttk.Frame(self.server_tab)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="IP:").pack(side="left")
        self.s_host = ttk.Entry(top, width=16)
        self.s_host.insert(0, DEFAULT_HOST)
        self.s_host.pack(side="left", padx=6)

        ttk.Label(top, text="Port:").pack(side="left")
        self.s_port = ttk.Entry(top, width=8)
        self.s_port.insert(0, str(DEFAULT_PORT))
        self.s_port.pack(side="left", padx=6)

        self.s_status = ttk.Label(top, text="Durum: Kapalı")
        self.s_status.pack(side="left", padx=12)

        tb.Button(top, text="Sunucuyu Başlat", command=self.start_server, bootstyle="success").pack(side="left", padx=6)

        mid = ttk.Frame(self.server_tab)
        mid.pack(fill="both", expand=True, padx=10, pady=5)

        self.s_log = scrolledtext.ScrolledText(
            mid, height=18, state="disabled",
            font=("Consolas", 10),
            background="#0f1117", foreground="#e6e6e6",
            insertbackground="#ffffff",
            padx=10, pady=8, wrap="word", relief="flat"
        )
        self.s_log.pack(fill="both", expand=True)

        bot = ttk.Frame(self.server_tab)
        bot.pack(fill="x", padx=10, pady=10)

        ttk.Label(bot, text="İstemciye mesaj (plain):").pack(anchor="w")
        row = ttk.Frame(bot)
        row.pack(fill="x", pady=6)

        self.s_entry = ttk.Entry(row)
        self.s_entry.pack(side="left", fill="x", expand=True)

        tb.Button(row, text="Gönder", command=self.server_send_text, bootstyle="primary").pack(side="left", padx=8)

    def set_server_status(self, text: str):
        self.s_status.config(text=f"Durum: {text}")

    def start_server(self):
        if self.server_sock:
            messagebox.showinfo("Bilgi", "Sunucu zaten açık.")
            return

        host = self.s_host.get().strip() or DEFAULT_HOST
        port = int(self.s_port.get().strip() or DEFAULT_PORT)

        def run():
            try:
                _need_crypto()

                if self.server_pub_pem is None or self.server_priv_pem is None:
                    self.server_pub_pem, self.server_priv_pem = rsa_generate_keypair(2048)

                if self.server_ecc_priv is None or self.server_ecc_pub_der is None:
                    self.server_ecc_priv, self.server_ecc_pub_der = ecc_lib.gen_server_static_keypair_p256()

                self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_sock.bind((host, port))
                self.server_sock.listen(1)

                self.root.after(0, lambda: self.set_server_status(f"Dinlemede {host}:{port}"))
                self.root.after(0, lambda: self.log(self.s_log, f"[+] Dinlemede: {host}:{port}"))

                conn, addr = self.server_sock.accept()
                self.server_conn = conn

                self.root.after(0, lambda: self.set_server_status(f"Bağlandı {addr}"))
                self.root.after(0, lambda: self.log(self.s_log, f"[+] İstemci bağlandı: {addr}"))

                pub_body = self.server_pub_pem
                self.server_conn.sendall(pack_msg({"type": "server_pub", "size": len(pub_body)}, pub_body))

                pem_text = pub_body.decode("utf-8", errors="replace").strip()
                self.root.after(0, lambda: self.log(
                    self.s_log,
                    "[RSA PUBLIC KEY - SERVER]\n" +
                    pem_text +
                    f"\n(pub_fp={fp_bytes(pub_body)} | len={len(pub_body)})"
                ))

             
                ecc_body = self.server_ecc_pub_der
                self.server_conn.sendall(pack_msg(
                    {"type": "server_kx", "kx": "ECDH-P256", "size": len(ecc_body)},
                    ecc_body
                ))
                ecc_b64 = base64.b64encode(ecc_body).decode("utf-8")
                self.root.after(0, lambda: self.log(
                    self.s_log,
                    "[ECDH PUBLIC KEY - SERVER] (DER b64)\n" +
                    ecc_b64 +
                    f"\n(pub_fp={fp_bytes(ecc_body)} | len={len(ecc_body)})"
                ))

                self.server_recv_thread = threading.Thread(target=self.server_recv_loop, daemon=True)
                self.server_recv_thread.start()

            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Sunucu Hatası", str(e)))
                self.root.after(0, lambda: self.set_server_status("Hata"))
                self.server_sock = None

        self.server_thread = threading.Thread(target=run, daemon=True)
        self.server_thread.start()

    def server_recv_loop(self):
        try:
            while True:
                hlen_raw = recvall(self.server_conn, 4)
                if not hlen_raw:
                    self.root.after(0, lambda: self.log(self.s_log, "[-] Bağlantı kapandı."))
                    break

                hlen = struct.unpack(">I", hlen_raw)[0]
                header = json.loads(recvall(self.server_conn, hlen).decode("utf-8"))
                typ = header.get("type")

                if typ == "text":
                    size = header.get("size", 0)
                    body = recvall(self.server_conn, size) if size else b""
                    cipher = header.get("cipher", "-")
                    mode = header.get("mode", "-")

                    if cipher in ("AES", "DES", "RSA"):
                        try:
                            pt = self.server_decrypt_payload(header, body)
                            msg_pt = pt.decode("utf-8", errors="replace")
                            ct_b64 = base64.b64encode(body).decode("utf-8")
                            self.root.after(0, lambda: self.log(
                                self.s_log,
                                f"[İSTEMCİ] ({cipher}/{mode}) PT='{msg_pt}' | CT(b64)={ct_b64[:90]}..."
                            ))
                        except Exception as e:
                            self.root.after(0, lambda: self.log(self.s_log, f"[HATA] decrypt failed ({cipher}/{mode}): {e}"))
                    else:
                        data = body.decode("utf-8", errors="replace")
                        self.root.after(0, lambda: self.log(self.s_log, f"[İSTEMCİ] ({cipher}/{mode}) {data}"))

                elif typ == "file":
                    size = header.get("size", 0)
                    body = recvall(self.server_conn, size) if size else b""

                    cipher = header.get("cipher", "-")
                    mode = header.get("mode", "-")
                    filename = header.get("filename", "file.bin")
                    mimetype = header.get("mimetype", "application/octet-stream")

                    try:
                        if cipher in ("AES", "DES", "RSA"):
                            raw = self.server_decrypt_payload(header, body)
                        else:
                            raw = body

                        os.makedirs("downloads", exist_ok=True)
                        safe_name = os.path.basename(filename)
                        save_path = os.path.join("downloads", safe_name)

                        with open(save_path, "wb") as f:
                            f.write(raw)

                        self.root.after(0, lambda: self.log(
                            self.s_log,
                            f"[DOSYA] ({cipher}/{mode}) Kaydedildi: {save_path} ({mimetype}) {len(raw)} bytes"
                        ))
                    except Exception as e:
                        self.root.after(0, lambda: self.log(self.s_log, f"[HATA] DOSYA decrypt/save failed ({cipher}/{mode}): {e}"))

                elif typ == "server_pub":
                    size = header.get("size", 0)
                    _ = recvall(self.server_conn, size) if size else b""
                    self.root.after(0, lambda: self.log(self.s_log, "[*] server_pub alındı (ignore)."))

                elif typ == "server_kx":
                    size = header.get("size", 0)
                    _ = recvall(self.server_conn, size) if size else b""
                    self.root.after(0, lambda: self.log(self.s_log, "[*] server_kx alındı (ignore)."))

                else:
                    self.root.after(0, lambda: self.log(self.s_log, f"[!] Bilinmeyen type: {typ}"))
        except Exception as e:
            self.root.after(0, lambda: self.log(self.s_log, f"[HATA] {e}"))

    def server_decrypt_payload(self, header: dict, body: bytes) -> bytes:
        cipher = header.get("cipher")
        mode = header.get("mode", "lib")

        if cipher == "RSA":
            return rsa_decrypt_chunked(body, self.server_priv_pem)

        iv_b64 = header.get("iv_b64")
        if not iv_b64:
            raise ValueError("iv_b64 eksik")
        iv = base64.b64decode(iv_b64)

        kx = header.get("kx", "RSA-OAEP")

        if kx == "ECDH-P256":
            if self.server_ecc_priv is None:
                raise RuntimeError("Server ECC private key yok. Sunucuyu yeniden başlat.")

            client_pub_b64 = header.get("client_eph_pub_b64")
            salt_b64 = header.get("kdf_salt_b64")
            info_b64 = header.get("kdf_info_b64")
            if not client_pub_b64 or not salt_b64 or not info_b64:
                raise ValueError("ECDH için client_eph_pub_b64 / kdf_salt_b64 / kdf_info_b64 eksik")

            client_pub_der = base64.b64decode(client_pub_b64)
            salt = base64.b64decode(salt_b64)
            info = base64.b64decode(info_b64)

            shared = ecc_lib.derive_shared_secret_p256(self.server_ecc_priv, client_pub_der)

            if cipher == "AES":
                sym_key = derive_key_hkdf_sha256(shared, salt, dk_len=16, info=info)
            elif cipher == "DES":
                sym_key = derive_key_hkdf_sha256(shared, salt, dk_len=8, info=info)
            else:
                raise ValueError("ECDH sadece AES/DES için")
        else:
            wrapped_b64 = header.get("wrapped_key_b64")
            if not wrapped_b64:
                raise ValueError("wrapped_key_b64 eksik")
            sym_key = rsa_unwrap_key(base64.b64decode(wrapped_b64), self.server_priv_pem)

        if cipher == "AES":
            if mode == "manual":
                if len(sym_key) != 16 or len(iv) != 16:
                    raise ValueError("AES manual: key 16, iv 16 olmalı")
                return aes128_cbc_decrypt_manual(body, sym_key, iv)
            return aes_decrypt_lib(body, sym_key, iv)

        if cipher == "DES":
            if mode == "manual":
                if len(iv) != 1:
                    raise ValueError("DES manual (S-DES): iv 1 byte olmalı")
                return sdes_decrypt_cbc(body, sym_key, iv)
            return des_decrypt_lib(body, sym_key, iv)

        raise ValueError("Desteklenmeyen cipher")

    def server_send_text(self):
        if not self.server_conn:
            messagebox.showwarning("Uyarı", "İstemci bağlı değil.")
            return
        msg = self.s_entry.get().strip()
        if not msg:
            return
        body = msg.encode("utf-8")
        pkt = pack_msg({"type": "text", "size": len(body), "cipher": "server_plain", "mode": "-"}, body)
        try:
            self.server_conn.sendall(pkt)
            self.log(self.s_log, f"[SUNUCU] {msg}")
            self.s_entry.delete(0, "end")
        except Exception as e:
            messagebox.showerror("Gönderme Hatası", str(e))

    def _build_client_tab(self):
        top = ttk.Frame(self.client_tab)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="Sunucu IP:").pack(side="left")
        self.c_host = ttk.Entry(top, width=16)
        self.c_host.insert(0, DEFAULT_HOST)
        self.c_host.pack(side="left", padx=6)

        ttk.Label(top, text="Port:").pack(side="left")
        self.c_port = ttk.Entry(top, width=8)
        self.c_port.insert(0, str(DEFAULT_PORT))
        self.c_port.pack(side="left", padx=6)

        self.c_status = ttk.Label(top, text="Durum: Bağlı değil")
        self.c_status.pack(side="left", padx=12)

        tb.Button(top, text="Bağlan", command=self.client_connect, bootstyle="success").pack(side="left", padx=6)

        opts = ttk.Frame(self.client_tab)
        opts.pack(fill="x", padx=10, pady=5)

        row1 = ttk.Frame(opts)
        row1.pack(fill="x")

        ttk.Label(row1, text="Şifreleme Yöntemi:").pack(side="left")
        self.c_cipher = tk.StringVar(value="caesar")
        self.c_cipher_box = tb.Combobox(
            row1, textvariable=self.c_cipher, width=22, state="readonly",
            values=[
                "caesar","substitution","playfair","vigenere","rail_fence",
                "route_cipher","columnar_transposition","polybius","pigpen",
                "affine","vernam","hill",
                "AES","DES","RSA"
            ],
            bootstyle="secondary"
        )
        self.c_cipher_box.pack(side="left", padx=8)
        self.c_cipher_box.bind("<<ComboboxSelected>>", self._on_cipher_change)

        ttk.Label(row1, text="Anahtar(Key):").pack(side="left")
        self.c_key = ttk.Entry(row1, width=26)
        self.c_key.insert(0, "3")
        self.c_key.pack(side="left", padx=8)

        ttk.Label(row1, text="AES/DES Mod:").pack(side="left")
        self.c_impl = tk.StringVar(value="lib")
        self.c_impl_box = tb.Combobox(
            row1, textvariable=self.c_impl, width=10, state="readonly",
            values=["lib", "manual"], bootstyle="secondary"
        )
        self.c_impl_box.pack(side="left", padx=6)

        ttk.Label(row1, text="Key Exchange:").pack(side="left")
        self.c_kx = tk.StringVar(value="RSA-OAEP")
        self.c_kx_box = tb.Combobox(
            row1, textvariable=self.c_kx, width=12, state="readonly",
            values=["RSA-OAEP", "ECDH-P256"],
            bootstyle="secondary"
        )
        self.c_kx_box.pack(side="left", padx=6)

        
        self.kdf_chk = tb.Checkbutton(
            row1,
            text="KDF (PBKDF2)",
            variable=self.use_kdf,
            bootstyle="info"
        )
        self.kdf_chk.pack(side="left", padx=10)
        self.use_kdf.set(False)
        self.kdf_chk.configure(state="disabled")

        row2 = ttk.Frame(opts)
        row2.pack(fill="x", pady=(6, 0))

        ttk.Label(row2, text="Mod:").pack(side="left")

        self.c_mode = tk.StringVar(value="enc")
        tb.Radiobutton(row2, text="Şifrele", variable=self.c_mode, value="enc", bootstyle="success").pack(side="left", padx=10)
        tb.Radiobutton(row2, text="Çöz", variable=self.c_mode, value="dec", bootstyle="warning").pack(side="left", padx=10)

        mid = ttk.Frame(self.client_tab)
        mid.pack(fill="both", expand=True, padx=10, pady=5)

        self.c_log = scrolledtext.ScrolledText(
            mid, height=18, state="disabled",
            font=("Consolas", 10),
            background="#0f1117", foreground="#e6e6e6",
            insertbackground="#ffffff",
            padx=10, pady=8, wrap="word", relief="flat"
        )
        self.c_log.pack(fill="both", expand=True)

        bot = ttk.Frame(self.client_tab)
        bot.pack(fill="x", padx=10, pady=10)

        ttk.Label(bot, text="Mesaj:").pack(anchor="w")
        row = ttk.Frame(bot)
        row.pack(fill="x", pady=6)

        self.c_entry = ttk.Entry(row)
        self.c_entry.pack(side="left", fill="x", expand=True)

        tb.Button(row, text="Gönder", command=self.client_send_text, bootstyle="primary").pack(side="left", padx=8)
        tb.Button(row, text="Dosya Gönder", command=self.client_send_file, bootstyle="warning").pack(side="left", padx=8)

        self.client_server_pub_pem = None
        self.client_server_ecc_pub_der = None

        self._on_cipher_change()

    def _on_cipher_change(self, *_):
        c = self.c_cipher.get().strip()

        
        if c in ("AES", "DES", "RSA"):
            self.c_key.configure(state="disabled")
        else:
            self.c_key.configure(state="normal")

        if c in ("AES", "DES"):
            self.c_impl_box.configure(state="readonly")
            self.c_kx_box.configure(state="readonly")
            if self.c_kx.get() not in ("RSA-OAEP", "ECDH-P256"):
                self.c_kx.set("RSA-OAEP")
            if self.c_impl.get() not in ("lib", "manual"):
                self.c_impl.set("lib")
        elif c == "RSA":
            self.c_impl.set("lib")
            self.c_impl_box.configure(state="disabled")
            self.c_kx.set("RSA-OAEP")
            self.c_kx_box.configure(state="disabled")
        else:
            self.c_impl.set("lib")
            self.c_impl_box.configure(state="disabled")
            self.c_kx.set("RSA-OAEP")
            self.c_kx_box.configure(state="disabled")

        
        self.use_kdf.set(False)
        try:
            self.kdf_chk.configure(state="disabled")
        except Exception:
            pass

    def client_connect(self):
        if self.client_sock:
            messagebox.showinfo("Bilgi", "Zaten bağlı.")
            return

        host = self.c_host.get().strip() or DEFAULT_HOST
        port = int(self.c_port.get().strip() or DEFAULT_PORT)

        try:
            self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_sock.connect((host, port))
            self.c_status.config(text=f"Durum: Bağlandı {host}:{port}")
            self.log(self.c_log, f"[+] Bağlandı: {host}:{port}")

            self.client_recv_thread = threading.Thread(target=self.client_recv_loop, daemon=True)
            self.client_recv_thread.start()
        except Exception as e:
            self.client_sock = None
            messagebox.showerror("Bağlantı Hatası", str(e))

    def client_recv_loop(self):
        try:
            while True:
                hlen_raw = recvall(self.client_sock, 4)
                if not hlen_raw:
                    self.root.after(0, lambda: self.log(self.c_log, "[-] Bağlantı kapandı."))
                    break
                hlen = struct.unpack(">I", hlen_raw)[0]
                header = json.loads(recvall(self.client_sock, hlen).decode("utf-8"))
                typ = header.get("type")

                if typ == "server_pub":
                    size = header.get("size", 0)
                    pem = recvall(self.client_sock, size) if size else b""
                    self.client_server_pub_pem = pem

                    pem_text = pem.decode("utf-8", errors="replace").strip()
                    self.root.after(0, lambda: self.log(
                        self.c_log,
                        "[RSA PUBLIC KEY - RECEIVED]\n" +
                        pem_text +
                        f"\n(pub_fp={fp_bytes(pem)} | len={len(pem)})"
                    ))
                    continue

                if typ == "server_kx":
                    size = header.get("size", 0)
                    ecc_pub = recvall(self.client_sock, size) if size else b""
                    if header.get("kx") == "ECDH-P256":
                        self.client_server_ecc_pub_der = ecc_pub
                        ecc_b64 = base64.b64encode(ecc_pub).decode("utf-8")
                        self.root.after(0, lambda: self.log(
                            self.c_log,
                            "[ECDH PUBLIC KEY - RECEIVED] (DER b64)\n" +
                            ecc_b64 +
                            f"\n(pub_fp={fp_bytes(ecc_pub)} | len={len(ecc_pub)})"
                        ))
                    else:
                        self.root.after(0, lambda: self.log(self.c_log, "[!] Bilinmeyen kx tipi alındı."))
                    continue

                if typ == "text":
                    size = header.get("size", 0)
                    data = recvall(self.client_sock, size) if size else b""
                    cipher = header.get("cipher", "-")
                    mode = header.get("mode", "-")
                    msg = data.decode("utf-8", errors="replace")
                    self.root.after(0, lambda: self.log(self.c_log, f"[SUNUCU] ({cipher}/{mode}) {msg}"))
                    continue

                if typ == "file":
                    size = header.get("size", 0)
                    data = recvall(self.client_sock, size) if size else b""
                    filename = header.get("filename", "file.bin")
                    mimetype = header.get("mimetype", "application/octet-stream")
                    cipher = header.get("cipher", "-")
                    mode = header.get("mode", "-")

                    os.makedirs("downloads", exist_ok=True)
                    safe_name = os.path.basename(filename)
                    save_path = os.path.join("downloads", f"client_{safe_name}")
                    with open(save_path, "wb") as f:
                        f.write(data)

                    self.root.after(0, lambda: self.log(self.c_log, f"[SUNUCU] FILE ({cipher}/{mode}) Kaydedildi: {save_path} ({mimetype})"))
                    continue

                self.root.after(0, lambda: self.log(self.c_log, f"[!] Bilinmeyen type: {typ}"))

        except Exception as e:
            self.root.after(0, lambda: self.log(self.c_log, f"[HATA] {e}"))

    def client_send_text(self):
        if not self.client_sock:
            messagebox.showwarning("Uyarı", "Önce bağlan.")
            return

        msg = self.c_entry.get().strip()
        if not msg:
            return

        cipher = self.c_cipher.get().strip()
        key = self.c_key.get().strip()
        mode = self.c_mode.get().strip()
        impl = self.c_impl.get().strip()

        if cipher in ("AES", "DES", "RSA"):
            try:
                _need_crypto()
                if self.client_server_pub_pem is None:
                    raise RuntimeError("Server public key alınmadı. Bağlandıktan sonra 1-2 sn bekle veya tekrar bağlan.")

                if mode != "enc":
                    messagebox.showinfo("Bilgi", "AES/DES/RSA gönderimde 'Çöz' kullanılmaz. Şifreleyerek gönderiyorum.")

                plaintext = msg.encode("utf-8")
                header, body = self.client_encrypt_payload(cipher, impl, plaintext, self.client_server_pub_pem)
                self.client_sock.sendall(pack_msg(header, body))

                ct_b64 = base64.b64encode(body).decode("utf-8")
                self.log(self.c_log, f"[İSTEMCİ] ({cipher}/{header.get('mode')}) CT(b64)={ct_b64[:90]}...")
                self.c_entry.delete(0, "end")
                return

            except Exception as e:
                messagebox.showerror("AES/DES/RSA Hatası", str(e))
                return

        try:
            out_msg = apply(cipher, mode, msg, key)
        except Exception as e:
            messagebox.showerror("Şifreleme Hatası", str(e))
            return

        body = out_msg.encode("utf-8")
        pkt = pack_msg({"type": "text", "size": len(body), "cipher": cipher, "mode": mode}, body)

        try:
            self.client_sock.sendall(pkt)

            if mode == "enc":
                self.log(self.c_log, f"[İSTEMCİ] ({cipher}/{mode}) Plain='{msg}' | Cipher='{out_msg}'")
            else:
                self.log(self.c_log, f"[İSTEMCİ] ({cipher}/{mode}) Cipher='{msg}' | Plain='{out_msg}'")

            self.c_entry.delete(0, "end")
        except Exception as e:
            messagebox.showerror("Gönderme Hatası", str(e))

    def client_send_file(self):
        if not self.client_sock:
            messagebox.showwarning("Uyarı", "Önce bağlan.")
            return

        path = filedialog.askopenfilename(title="Dosya seç")
        if not path:
            return

        try:
            with open(path, "rb") as f:
                raw = f.read()

            filename = os.path.basename(path)
            mimetype, _ = mimetypes.guess_type(filename)
            if not mimetype:
                mimetype = "application/octet-stream"

            cipher = self.c_cipher.get().strip()
            impl = self.c_impl.get().strip()

            if cipher in ("AES", "DES", "RSA"):
                _need_crypto()
                if self.client_server_pub_pem is None:
                    raise RuntimeError("Server public key alınmadı. Bağlandıktan sonra 1-2 sn bekle veya tekrar bağlan.")

                header, body = self.client_encrypt_payload(cipher, impl, raw, self.client_server_pub_pem)

                header["type"] = "file"
                header["filename"] = filename
                header["mimetype"] = mimetype
                header["size"] = len(body)

                self.client_sock.sendall(pack_msg(header, body))

                ct_b64 = base64.b64encode(body).decode("utf-8")
                self.log(self.c_log, f"[İSTEMCİ] FILE ({cipher}/{header.get('mode')}) {filename} CT(b64)={ct_b64[:70]}...")
            else:
                header = {"type": "file", "filename": filename, "mimetype": mimetype, "size": len(raw), "cipher": "plain", "mode": "-"}
                self.client_sock.sendall(pack_msg(header, raw))
                self.log(self.c_log, f"[İSTEMCİ] FILE (plain) {filename} ({len(raw)} bytes)")

        except Exception as e:
            messagebox.showerror("Dosya Gönderme Hatası", str(e))

    def client_encrypt_payload(self, cipher: str, impl: str, plaintext: bytes, server_pub_pem: bytes):

        
        self.use_kdf.set(False)

        if cipher == "RSA":
            ct = rsa_encrypt_chunked(plaintext, server_pub_pem)
            header = {
                "type": "text",
                "size": len(ct),
                "cipher": "RSA",
                "mode": "lib",
                "asym": "RSA-OAEP-SHA256"
            }
            return header, ct

        if cipher == "AES":
            kdf_meta = None

            if self.use_kdf.get():
                salt = get_random_bytes(16)
                sym_key = derive_key_pbkdf2(self.c_key.get().strip(), salt, dk_len=16, iterations=200_000)
                kdf_meta = {
                    "kdf": "PBKDF2-HMAC-SHA256",
                    "kdf_iters": 200_000,
                    "kdf_salt_b64": base64.b64encode(salt).decode("utf-8"),
                }
            else:
                sym_key = get_random_bytes(16)

            iv = get_random_bytes(16)

            if impl == "manual":
                ct = aes128_cbc_encrypt_manual(plaintext, sym_key, iv)
                sym_name = "AES-128-CBC-PKCS7 (manual)"
                mode_name = "manual"
            else:
                ct = aes_encrypt_lib(plaintext, sym_key, iv)
                sym_name = "AES-128-CBC-PKCS7 (lib)"
                mode_name = "lib"

            kx = self.c_kx.get().strip()

            ecdh_meta = None
            if kx == "ECDH-P256":
                if self.client_server_ecc_pub_der is None:
                    raise RuntimeError("ECDH public key alınmadı. Bağlandıktan sonra 1-2 sn bekle veya tekrar bağlan.")

                client_priv, client_pub_der = ecc_lib.gen_client_ephemeral_keypair_p256()
                shared = ecc_lib.derive_shared_secret_p256(client_priv, self.client_server_ecc_pub_der)

                salt = get_random_bytes(16)
                info = b"server_client_gui2-ecdh-aes"
                sym_key = derive_key_hkdf_sha256(shared, salt, dk_len=16, info=info)

                if impl == "manual":
                    ct = aes128_cbc_encrypt_manual(plaintext, sym_key, iv)
                    sym_name = "AES-128-CBC-PKCS7 (manual)"
                    mode_name = "manual"
                else:
                    ct = aes_encrypt_lib(plaintext, sym_key, iv)
                    sym_name = "AES-128-CBC-PKCS7 (lib)"
                    mode_name = "lib"

                ecdh_meta = {
                    "kx": "ECDH-P256",
                    "client_eph_pub_b64": base64.b64encode(client_pub_der).decode("utf-8"),
                    "kdf": "HKDF-SHA256",
                    "kdf_salt_b64": base64.b64encode(salt).decode("utf-8"),
                    "kdf_info_b64": base64.b64encode(info).decode("utf-8"),
                }
            else:
                ecdh_meta = {"kx": "RSA-OAEP"}

            header = {
                "type": "text",
                "size": len(ct),
                "cipher": "AES",
                "mode": mode_name,
                "sym": sym_name,
                "iv_b64": base64.b64encode(iv).decode("utf-8"),
            }

            if ecdh_meta.get("kx") == "RSA-OAEP":
                wrapped = rsa_wrap_key(sym_key, server_pub_pem)
                header["wrapped_key_b64"] = base64.b64encode(wrapped).decode("utf-8")

            header.update(ecdh_meta)

            if kdf_meta:
                header.update(kdf_meta)

            return header, ct

        if cipher == "DES":
            kdf_meta = None

            if self.use_kdf.get():
                salt = get_random_bytes(16)
                sym_key = derive_key_pbkdf2(self.c_key.get().strip(), salt, dk_len=8, iterations=200_000)
                kdf_meta = {
                    "kdf": "PBKDF2-HMAC-SHA256",
                    "kdf_iters": 200_000,
                    "kdf_salt_b64": base64.b64encode(salt).decode("utf-8"),
                }
            else:
                sym_key = get_random_bytes(8)

            if impl == "manual":
                iv = get_random_bytes(1)
                ct = sdes_encrypt_cbc(plaintext, sym_key, iv)
                sym_name = "S-DES(manual)-CBC"
                mode_name = "manual"
            else:
                iv = get_random_bytes(8)
                ct = des_encrypt_lib(plaintext, sym_key, iv)
                sym_name = "DES-CBC-PKCS7 (lib)"
                mode_name = "lib"

            kx = self.c_kx.get().strip()

            ecdh_meta = None
            if kx == "ECDH-P256":
                if self.client_server_ecc_pub_der is None:
                    raise RuntimeError("ECDH public key alınmadı. Bağlandıktan sonra 1-2 sn bekle veya tekrar bağlan.")

                client_priv, client_pub_der = ecc_lib.gen_client_ephemeral_keypair_p256()
                shared = ecc_lib.derive_shared_secret_p256(client_priv, self.client_server_ecc_pub_der)

                salt = get_random_bytes(16)
                info = b"server_client_gui2-ecdh-des"
                sym_key = derive_key_hkdf_sha256(shared, salt, dk_len=8, info=info)

                if impl == "manual":
                    iv = get_random_bytes(1)
                    ct = sdes_encrypt_cbc(plaintext, sym_key, iv)
                    sym_name = "S-DES(manual)-CBC"
                    mode_name = "manual"
                else:
                    iv = get_random_bytes(8)
                    ct = des_encrypt_lib(plaintext, sym_key, iv)
                    sym_name = "DES-CBC-PKCS7 (lib)"
                    mode_name = "lib"

                ecdh_meta = {
                    "kx": "ECDH-P256",
                    "client_eph_pub_b64": base64.b64encode(client_pub_der).decode("utf-8"),
                    "kdf": "HKDF-SHA256",
                    "kdf_salt_b64": base64.b64encode(salt).decode("utf-8"),
                    "kdf_info_b64": base64.b64encode(info).decode("utf-8"),
                }
            else:
                ecdh_meta = {"kx": "RSA-OAEP"}

            header = {
                "type": "text",
                "size": len(ct),
                "cipher": "DES",
                "mode": mode_name,
                "sym": sym_name,
                "iv_b64": base64.b64encode(iv).decode("utf-8"),
            }

            if ecdh_meta.get("kx") == "RSA-OAEP":
                wrapped = rsa_wrap_key(sym_key, server_pub_pem)
                header["wrapped_key_b64"] = base64.b64encode(wrapped).decode("utf-8")

            header.update(ecdh_meta)

            if kdf_meta:
                header.update(kdf_meta)

            return header, ct

        raise ValueError("Desteklenmeyen cipher")


if __name__ == "__main__":
    root = tb.Window(themename="cyborg")
    App(root)
    root.mainloop()
