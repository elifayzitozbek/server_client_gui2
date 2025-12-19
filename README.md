# AES–DES–RSA + Klasik Şifreler | İstemci–Sunucu GUI | (Lib + Manual) | Wireshark Analizi

Bu proje; istemci ile sunucu arasında **şifreli mesaj/dosya iletimi** yapan bir masaüstü uygulamasıdır (Tkinter GUI).
Klasik kripto yöntemleri (Caesar, Vigenère, Playfair vb.) yanında **AES-128**, **DES** ve **RSA** destekler.

Ödev kapsamına uygun olarak:
- **Mod 1 (Kütüphaneli / Lib):** AES, DES, RSA işlemleri PyCryptodome ile yapılır.
- **Mod 2 (Manuel):**
  - **AES-128-CBC + PKCS7** manuel (round, S-Box, MixColumns, Key Expansion vb.)
  - **DES için S-DES (Simplified DES) + CBC** manuel (ödevde “sadeleştirilmiş versiyon” şartını karşılamak için)

> Not: Bu çalışmada RSA, simetrik şifreleme yerine **anahtar dağıtımı (key wrapping)** amacıyla kullanılır.  
> AES/DES seçildiğinde veri AES/DES ile şifrelenir, kullanılan simetrik anahtar RSA-OAEP ile sarılıp (wrap) gönderilir.  
> RSA modu seçilirse veri doğrudan RSA ile şifrelenir (paket boyutu büyür).

---

## Özellikler

### 1) İstemci–Sunucu Haberleşmesi
- TCP soket iletişimi
- Paket formatı: `4 byte header_len + header_json + body_bytes`
- Sunucu bağlantıda **RSA public key** gönderir (handshake)

### 2) Şifreleme Modları
- **Klasik Şifreler** (`ciphers/apply` üzerinden):
  - caesar, substitution, playfair, vigenere, rail_fence, route_cipher,
    columnar_transposition, polybius, pigpen, affine, vernam, hill
- **Modern Şifreler**
  - **AES-128-CBC + PKCS7** (lib / manual)
  - **DES-CBC + PKCS7** (lib)
  - **S-DES(manual) + CBC** (manual)
  - **RSA-OAEP-SHA256** (lib)

### 3) Dosya Gönderme
- İstemci GUI’den dosya seçip gönderme
- AES/DES/RSA seçiliyken dosya **şifreli** gider, sunucu çözüp `downloads/` içine kaydeder
- Klasik mod seçiliyken dosya plain gönderilir (isteğe bağlı)

### 4) Wireshark Analizi
- TCP paketlerinde payload kısmı **okunamaz** (ciphertext bytes)
- AES / DES / RSA paket boyutları karşılaştırılabilir
- RSA modunda payload daha büyüktür (OAEP + chunking nedeniyle)

---

## Kurulum

### Gereksinimler
- Python 3.10+ önerilir
- PyCryptodome (AES/DES/RSA lib modları için)

### Paket Kurulumu
```bash
pip install pycryptodome

Çalıştırma

Proje tek dosyadan çalışacak şekilde tasarlanmıştır:

python app_gui.py


server_client_gui2/
│
├── app_gui.py          # Ana GUI (sunucu + istemci)
├── client_gui.py       # Ayrık istemci (opsiyonel)
├── server_gui.py       # Ayrık sunucu (opsiyonel)
├── ciphers/
│   ├── aes_lib.py
│   ├── aes_manual.py
│   ├── des_lib.py
│   ├── des_manual_sdes.py
│   ├── rsa_lib.py
│   ├── caesar.py
│   ├── vigenere.py
│   └── ...
├── README.md
├── requirements.txt



Uygulama açılınca iki sekme gelir:

Sunucu

İstemci



Kullanım
1) Sunucuyu başlat

Sunucu sekmesi

IP ve Port kontrol et (varsayılan: 127.0.0.1:5000)

Sunucuyu Başlat butonuna bas

Sunucu, istemci bağlanınca otomatik olarak RSA public key gönderir.

2) İstemciyi bağla

İstemci sekmesi

IP/Port gir

Bağlan butonuna bas

Log’da RSA public key alındı mesajını görmelisin

3) Mesaj gönder

Klasik algoritma seçersen: Şifrele / Çöz seçeneği çalışır.

AES/DES/RSA seçersen: gönderim daima şifreli yapılır (ağda plaintext gitmez).

AES/DES için AES/DES Mod: alanından lib veya manual seçebilirsin.

4) Dosya gönder

Algoritma seç (AES/DES/RSA ise dosya şifreli gider)

Dosya Gönder butonuna bas

Sunucu downloads/ içine dosyayı kaydeder
