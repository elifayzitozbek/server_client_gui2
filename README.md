# AES–DES–RSA + Klasik Şifreler | İstemci–Sunucu GUI | (Lib + Manual) | Wireshark Analizi

Bu proje, istemci ile sunucu arasında TCP tabanlı haberleşme kurarak şifreli mesaj ve dosya iletimi yapan bir masaüstü uygulamasıdır. Uygulama Python dili ile geliştirilmiş olup grafik arayüz için Tkinter ve ttkbootstrap kullanılmıştır.

Proje kapsamında klasik şifreleme algoritmaları ile birlikte modern kriptografik algoritmalar olan AES, DES ve RSA kullanılmıştır. AES ve DES algoritmaları hem kriptografik kütüphaneler kullanılarak hem de manuel (sadeleştirilmiş) şekilde uygulanmıştır. RSA algoritması manuel olarak yazılmamış, asimetrik şifreleme ve anahtar dağıtımı amacıyla kullanılmıştır.

Bu çalışma ile simetrik ve asimetrik şifreleme algoritmalarının istemci–sunucu mimarisinde birlikte nasıl kullanıldığı, ağ trafiğine etkileri ve paket yapılarının Wireshark üzerinden nasıl gözlemlenebildiği uygulamalı olarak gösterilmiştir.

---

## Desteklenen Şifreleme Algoritmaları

### Klasik Şifreleme Yöntemleri
- Caesar
- Substitution
- Playfair
- Vigenère
- Rail Fence
- Route Cipher
- Columnar Transposition
- Polybius
- Pigpen
- Affine
- Vernam
- Hill

Bu algoritmalar için şifreleme ve çözme işlemleri istemci tarafında gerçekleştirilir. Kullanıcı arayüzünde “Şifrele / Çöz” modu aktif olarak kullanılabilir.

---

### Modern Şifreleme Yöntemleri

- AES-128-CBC + PKCS7 (Kütüphaneli)
- AES-128-CBC + PKCS7 (Manuel)
- DES-CBC + PKCS7 (Kütüphaneli)
- S-DES + CBC (Manuel)
- RSA-OAEP-SHA256

AES ve DES algoritmaları simetrik şifreleme amacıyla kullanılır. Bu algoritmalar seçildiğinde veri AES veya DES ile şifrelenir ve kullanılan simetrik anahtar RSA-OAEP yöntemi ile şifrelenerek sunucuya gönderilir.

RSA algoritması doğrudan seçildiğinde veri asimetrik olarak şifrelenir. RSA ile şifrelenen paketlerin boyutlarının diğer algoritmalara göre daha büyük olduğu gözlemlenebilir.

---

## İstemci–Sunucu Mimarisi

Uygulama TCP soketleri kullanılarak geliştirilmiştir. İstemci ve sunucu arasında gönderilen tüm veriler belirli bir paket formatına sahiptir.

Paket yapısı:
- 4 byte header uzunluğu
- JSON formatında header bilgisi
- Binary veri (body)

Sunucu, istemci bağlandığında RSA public key bilgisini otomatik olarak istemciye gönderir. İstemci bu anahtarı kullanarak simetrik anahtarları veya veriyi RSA ile şifreler.

Sunucu tarafında gelen veriler çözülür ve çözülen plaintext mesajlar sunucu log ekranında gösterilir.

---

## Manuel Şifreleme Modu

Ödev gereksinimleri doğrultusunda AES ve DES algoritmalarının sadeleştirilmiş manuel implementasyonları yapılmıştır.

- AES-128 manuel implementasyonu:
  - Key Expansion
  - SubBytes
  - ShiftRows
  - MixColumns
  - AddRoundKey
  - CBC modu ve PKCS7 padding

- DES manuel implementasyonu:
  - S-DES (Simplified DES)
  - CBC modu
  - Bit permütasyonları ve S-Box yapısı

Bu manuel implementasyonlar sayesinde algoritmaların iç çalışma yapısı doğrudan gözlemlenebilir.

---

## Anahtar Türetme (KDF)

AES ve DES için kullanıcı tarafından girilen anahtar metni PBKDF2-HMAC-SHA256 algoritması kullanılarak anahtara dönüştürülebilir. Bu işlem sırasında salt ve iterasyon sayısı kullanılarak güvenli anahtar üretimi sağlanır.

KDF seçeneği aktif edilmediğinde anahtarlar rastgele olarak üretilir.

---

## Dosya Gönderme

İstemci uygulaması üzerinden dosya gönderimi yapılabilir.

AES, DES veya RSA seçildiğinde dosyalar şifrelenerek sunucuya gönderilir. Sunucu tarafında dosya çözülür ve `downloads/` klasörü içerisine kaydedilir.

Sunucu log ekranında dosya adı, kullanılan algoritma ve çözülen veri boyutu görüntülenir.

Klasik şifreleme algoritmaları seçildiğinde dosya plain olarak gönderilir.

---

## Wireshark Analizi

Uygulama üzerinden gönderilen TCP paketleri Wireshark ile yakalanarak analiz edilmiştir.

- Paket payload alanlarının okunamaz (ciphertext) olduğu gözlemlenmiştir
- AES, DES ve RSA algoritmaları kullanıldığında paket boyutları karşılaştırılmıştır
- RSA algoritmasının OAEP padding ve chunking nedeniyle daha büyük veri ürettiği gösterilmiştir
- Manuel ve kütüphaneli şifreleme çıktıları karşılaştırılmıştır

---

## Kurulum

### Gereksinimler
- Python 3.10 veya üzeri

### Bağımlılıkların Kurulumu
```bash
pip install -r requirements.txt
Çalıştırma
bash
python app_gui.py
Uygulama açıldığında iki sekme bulunmaktadır:

Sunucu

İstemci

Kullanım
Sunucu
IP ve Port bilgileri girilir

Sunucuyu Başlat butonuna basılır

İstemci bağlandığında RSA public key otomatik olarak gönderilir

İstemci
IP ve Port bilgileri girilir

Bağlan butonuna basılır

Şifreleme algoritması seçilir

Mesaj yazılarak Gönder butonuna basılır

Dosya göndermek için Dosya Gönder butonu kullanılır

AES, DES ve RSA algoritmaları seçildiğinde gönderim her zaman şifreli yapılır. Çözme işlemi sunucu tarafında gerçekleştirilir.

Proje Yapısı
markdown
Kodu kopyala
server_client_gui2/
│
├── app_gui.py
├── client_gui.py
├── server_gui.py
├── demo_ciphers.py
├── requirements.txt
├── README.md
├── downloads/
│   └── .gitignore
└── ciphers/
    ├── __init__.py
    ├── dispatch.py
    ├── kdf.py
    ├── ecc_lib.py
    ├── aes_lib.py
    ├── aes_manual.py
    ├── des_lib.py
    ├── des_manual_sdes.py
    ├── rsa_lib.py
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
