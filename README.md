# AES–DES–RSA + Klasik Şifreler
## İstemci–Sunucu GUI | (Lib + Manual) | Wireshark Analizi

Bu proje; istemci ile sunucu arasında **şifreli mesaj ve dosya iletimi** yapan bir masaüstü uygulamasıdır (Tkinter GUI).  
Klasik kripto algoritmaları (Caesar, Vigenère, Playfair vb.) ile birlikte **AES-128, DES, RSA ve ECC (ECDH)** destekler.

## Genel Yapı

- **Lib Modu:**  
  AES, DES, RSA ve ECC işlemleri kriptografik kütüphaneler ile yapılır.

- **Manuel Mod:**
  - AES-128-CBC (temel round işlemleri ile)
  - S-DES (Simplified DES – sadeleştirilmiş versiyon)

> **Not:**  
> RSA bu projede mesaj şifrelemeden çok **anahtar değişimi** amacıyla kullanılmıştır.  
> ECC tarafında **ECDH-P256** ile ortak anahtar üretilmektedir.  
> **KDF (PBKDF2)** seçeneği arayüzde **devre dışıdır**.

## Özellikler

- TCP tabanlı istemci–sunucu haberleşmesi  
- Otomatik **RSA / ECC public key** değişimi (kullanıcı girişi gerekmez)  
- AES / DES / RSA / ECC ile şifreli mesaj ve dosya gönderimi  
- Klasik şifreleme algoritmaları desteği  
- Dosyaların sunucu tarafında `downloads/` klasörüne kaydedilmesi  
- Wireshark ile paket boyutu ve ciphertext analizi  
- `ttkbootstrap` ile modern GUI  

## Desteklenen Algoritmalar

### Klasik
- Caesar, Substitution, Playfair, Vigenère  
- Rail Fence, Route Cipher, Columnar Transposition  
- Polybius, Pigpen, Affine, Vernam, Hill  

### Modern
- AES-128-CBC (lib / manual)  
- DES-CBC (lib)  
- S-DES (manual)  
- RSA-OAEP  
- ECC (ECDH-P256)  

## Kurulum

Python **3.10+** önerilir.

Gerekli paketleri kurmak için:

```bash
pip install -r requirements.txt

## Dosya Dizin Yapısı

```text
odev_kripto2/
├── app_gui.py          # Ana uygulama (Sunucu + İstemci tek GUI)
├── client_gui.py       # Ayrık istemci arayüzü (opsiyonel)
├── server_gui.py       # Ayrık sunucu arayüzü (opsiyonel)
├── demo_ciphers.py     # Klasik şifreler için demo/test
├── README.md
├── requirements.txt
├── downloads/          # Sunucuda çözülen dosyalar (runtime)
│   └── .gitignore
└── ciphers/
    ├── aes_lib.py
    ├── aes_manual.py
    ├── des_lib.py
    ├── des_manual_sdes.py
    ├── rsa_lib.py
    ├── ecc_lib.py
    ├── caesar.py
    ├── vigenere.py
    ├── playfair.py
    ├── rail_fence.py
    ├── route_cipher.py
    ├── columnar_transposition.py
    ├── polybius.py
    ├── pigpen.py
    ├── affine.py
    ├── vernam.py
    ├── hill.py
    └── utils.py

Çalıştırma
python app_gui.py