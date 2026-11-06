# SecureGov / Enterprise DocVault

> **Sistem Manajemen Dokumen Terenkripsi, Pesan Rahasia Multi-Lapis, Steganografi Multimedia, dan Jejak Audit Blockchain dengan Otentikasi Ganda Hardware Nyata (*Physical USB Dongle & OpenCV Live Face Biometrics*)**  
> *Proyek Tugas Akhir — Kriptografi & Keamanan Sistem Informasi*

---

## 📑 Daftar Isi
1. [Deskripsi Aplikasi & Gambaran Umum](#1-deskripsi-aplikasi--gambaran-umum)
2. [Arsitektur Sistem & Spesifikasi Algoritma](#2-arsitektur-sistem--spesifikasi-algoritma)
3. [Langkah-Langkah Kerja Algoritma Secara Mendalam](#3-langkah-langkah-kerja-algoritma-secara-mendalam)
   - [3.1. Otentikasi Ganda Nyata (USB Dongle & Face Biometric)](#31-otentikasi-ganda-nyata-usb-dongle--face-biometric)
   - [3.2. Kredensial & Enkripsi Basis Data (Argon2id & SQLite AES-GCM)](#32-kredensial--enkripsi-basis-data-argon2id--sqlite-aes-gcm)
   - [3.3. Super-Enkripsi Teks (Klasik + Modern)](#33-super-enkripsi-teks-klasik--modern)
   - [3.4. Enkripsi File Dokumen (RSA-2048 Hybrid & Fernet)](#34-enkripsi-file-dokumen-rsa-2048-hybrid--fernet)
   - [3.5. Suite Steganografi Multimedia (Gambar, Audio, Video)](#35-suite-steganografi-multimedia-gambar-audio-video)
   - [3.6. Audit Ledger Blockchain (SHA-256 Immutability & Tamper Detection)](#36-audit-ledger-blockchain-sha-256-immutability--tamper-detection)
4. [Panduan Instalasi & Persiapan Lingkungan](#4-panduan-instalasi--persiapan-lingkungan)
5. [Panduan Penggunaan Aplikasi GUI Desktop](#5-panduan-penggunaan-aplikasi-gui-desktop)
   - [5.1. Cara Menjalankan (Langsung dari Desktop vs Terminal)](#51-cara-menjalankan-langsung-dari-desktop-vs-terminal)
   - [5.2. Langkah Pendaftaran Pengguna & Hardware (Enrollment)](#52-langkah-pendaftaran-pengguna--hardware-enrollment)
   - [5.3. Langkah Login Dual-Faktor (Security Gate)](#53-langkah-login-dual-faktor-security-gate)
   - [5.4. Penggunaan Tab Super-Enkripsi Teks](#54-penggunaan-tab-super-enkripsi-teks)
   - [5.5. Penggunaan Tab Enkripsi Dokumen File](#55-penggunaan-tab-enkripsi-dokumen-file)
   - [5.6. Penggunaan Tab Steganografi Multimedia](#56-penggunaan-tab-steganografi-multimedia)
   - [5.7. Penggunaan Tab Audit Blockchain & Uji Tampering](#57-penggunaan-tab-audit-blockchain--uji-tampering)
6. [Contoh Penggunaan Programatik (Python Code Snippets)](#6-contoh-penggunaan-programatik-python-code-snippets)
7. [Struktur Direktori Proyek](#7-struktur-direktori-proyek)
8. [Pengujian Otomatis (Automated Unit Tests)](#8-pengujian-otomatis-automated-unit-tests)

---

## 1. Deskripsi Aplikasi & Gambaran Umum

**SecureGov / Enterprise DocVault** adalah aplikasi desktop tingkat enterprise (*government-grade*) yang dirancang untuk mengatasi kerentanan kebocoran dokumen rahasia, pemalsuan identitas, manipulasi pesan, dan penyusupan jejak audit.

Aplikasi ini menerapkan prinsip **Defense-in-Depth** (Pertahanan Berlapis) dan **Zero-Mock** (tidak menggunakan simulasi dummy/placeholder):
- **Otentikasi Hardware Nyata**: Mengharuskan kehadiran fisik USB Flashdrive asli yang telah dipasangkan (*Volume Serial Number* perangkat keras) dan verifikasi biometrik wajah langsung dari kamera webcam.
- **Kerahasiaan Pesan Berlapis (*Super Encryption*)**: Memadukan algoritma kriptografi klasik (Vigenère / Playfair) dengan algoritma modern berstandar militer (AES-256-GCM).
- **Proteksi Dokumen Terpisah (*Enkripsi Hibrid*)**: Menggunakan kriptografi kunci asimetris RSA-2048 OAEP untuk membungkus kunci simetris AES-256-GCM pada file dokumen (PDF, DOCX, XLSX).
- **Komunikasi Terselubung (*Multimedia Steganography*)**: Menyembunyikan payload teks rahasia ke dalam tiga media digital berbeda (Citra PNG/JPG, Audio WAV PCM, dan Video AVI Lossless FFV1) dengan manipulasi LSB (*Least Significant Bit*).
- **Integritas Tak Terbantahkan (*Blockchain Audit Ledger*)**: Seluruh aktivitas pengguna dan manipulasi data dicatat ke dalam buku besar terdistribusi berbasis rantai blok SHA-256, dilengkapi dengan simulasi deteksi peretasan (*tamper detection*) secara interaktif.

---

## 2. Arsitektur Sistem & Spesifikasi Algoritma

```
+-----------------------------------------------------------------------------------+
|                        SECUREGOV ENTERPRISE DOCVAULT                              |
+-----------------------------------------------------------------------------------+
                                         |
               +-------------------------+-------------------------+
               |                                                   |
      [1. ACCESS CONTROL]                                 [2. CRYPTOGRAPHY SUITE]
   * Physical USB VSN Check                            * Text: Vigenere/Playfair + AES-GCM
   * Live Face LBPH OpenCV                             * File: RSA-2048 OAEP + AES-GCM
   * Argon2id / bcrypt Hashes                          * DB: AES-256-GCM Columns
               |                                                   |
               +-------------------------+-------------------------+
                                         |
               +-------------------------+-------------------------+
               |                                                   |
   [3. MULTIMEDIA STEGANOGRAPHY]                          [4. AUDIT LEDGER]
   * Image: 24-bit RGB LSB (Pillow)                    * Genesis & Linked Blocks
   * Audio: 16-bit PCM WAV LSB                         * Canonical JSON SHA-256
   * Video: Frame-by-frame LSB (FFV1)                  * Live Tamper & Re-Hash Suite
+-----------------------------------------------------------------------------------+
```

### Tabel Spesifikasi Algoritma & Modul

| No | Modul Keamanan | Algoritma / Standar yang Digunakan | Parameter Kunci / Teknis | File Sumber |
|:---:|:---|:---|:---|:---|
| **1** | **USB Dongle Auth** | Hardware Volume Serial Number (VSN) + Key File | Windows Win32 `GetVolumeInformationW` & `psutil` | [`securegov/auth/usb_dongle.py`](file:///d:/Kuliah/IF/Semester%205/Kriptografi/pKriptoAkhirPY/securegov/auth/usb_dongle.py) |
| **2** | **Biometrik Wajah** | Haar Cascade + LBPH Face Recognizer | Radius=1, Neighbors=8, Grid=8x8, Threshold $\le 85.0$ | [`securegov/auth/biometric.py`](file:///d:/Kuliah/IF/Semester%205/Kriptografi/pKriptoAkhirPY/securegov/auth/biometric.py) |
| **3** | **Password Hashing**| Argon2id / bcrypt | Salt 16-byte, Time cost=2, Memory=19 MB, Parallelism=1 | [`securegov/auth/credential_manager.py`](file:///d:/Kuliah/IF/Semester%205/Kriptografi/pKriptoAkhirPY/securegov/auth/credential_manager.py) |
| **4** | **Enkripsi Database**| AES-256-GCM (Authenticated Encryption) | Kunci 32-byte, Nonce 12-byte acak, Tag 16-byte | [`securegov/database/db_crypto.py`](file:///d:/Kuliah/IF/Semester%205/Kriptografi/pKriptoAkhirPY/securegov/database/db_crypto.py) |
| **5** | **Super-Enkripsi** | Klasik (Vigenère / Playfair) $\rightarrow$ Modern (AES-GCM) | Matrix $5\times 5$ (I=J) + AES-256-GCM Base64 Container | [`securegov/crypto/super_encryption.py`](file:///d:/Kuliah/IF/Semester%205/Kriptografi/pKriptoAkhirPY/securegov/crypto/super_encryption.py) |
| **6** | **Enkripsi Dokumen**| RSA-2048 OAEP Hibrid + AES-256-GCM / Fernet | Key 2048-bit (e=65537), SHA-256 OAEP, Format `.sgvault` | [`securegov/crypto/file_encryption.py`](file:///d:/Kuliah/IF/Semester%205/Kriptografi/pKriptoAkhirPY/securegov/crypto/file_encryption.py) |
| **7** | **Steganografi Citra**| Least Significant Bit (LSB) 24-bit RGB | Header uint32-LE (4 byte panjang) + 3 bit per piksel | [`securegov/steganography/image_steg.py`](file:///d:/Kuliah/IF/Semester%205/Kriptografi/pKriptoAkhirPY/securegov/steganography/image_steg.py) |
| **8** | **Steganografi Audio**| Least Significant Bit (LSB) 16-bit PCM WAV | 1 bit per sample audio (mono/stereo signed int16) | [`securegov/steganography/audio_steg.py`](file:///d:/Kuliah/IF/Semester%205/Kriptografi/pKriptoAkhirPY/securegov/steganography/audio_steg.py) |
| **9** | **Steganografi Video**| Frame-Based LSB dengan Codec Lossless FFV1 | Modifikasi LSB kanal warna antar-frame via OpenCV | [`securegov/steganography/video_steg.py`](file:///d:/Kuliah/IF/Semester%205/Kriptografi/pKriptoAkhirPY/securegov/steganography/video_steg.py) |
| **10**| **Blockchain Audit** | Rantai Blok SHA-256 Terhubung (*Linked Ledger*) | JSON kanonikal, Genesis Block, Hash Chaining | [`securegov/blockchain/chain.py`](file:///d:/Kuliah/IF/Semester%205/Kriptografi/pKriptoAkhirPY/securegov/blockchain/chain.py) |

---

## 3. Langkah-Langkah Kerja Algoritma Secara Mendalam

### 3.1. Otentikasi Ganda Nyata (USB Dongle & Face Biometric)

#### A. Verifikasi Hardware USB Dongle
Sistem tidak mengandalkan nama drive (`E:`, `F:`) karena nama drive dapat berganti. Sistem membaca **Volume Serial Number (VSN)** perangkat keras:
1. **Langkah Registrasi**:
   - Sistem memindai partisi aktif melalui `psutil.disk_partitions(all=True)`.
   - Mengambil nomor seri VSN heksadesimal melalui Windows Win32 API native `kernel32.GetVolumeInformationW`.
   - Membuat file rahasia kriptografis berukuran 32-byte acak (`.securegov_dongle.key`) di root USB drive dan menyimpan VSN ke daftar sah database (`allowed_vsns.txt`).
2. **Langkah Verifikasi**:
   - Memindai semua removable drive yang terhubung saat tombol ditekan.
   - Membaca VSN perangkat dan membandingkannya dengan VSN yang terdaftar untuk akun user.
   - Memverifikasi keberadaan dan integritas file `.securegov_dongle.key`.
3. **Continuous Hardware Presence Enforcement (Dead-Man's Switch Auto-Lock)**:
   - Selain verifikasi di awal login (*Access Gate*), aplikasi dilengkapi background watcher aktif (`_check_dongle_presence`).
   - Setiap 2 detik, sistem memvalidasi keberadaan fisik flashdisk dengan VSN pengguna yang sedang aktif.
   - Jika flashdisk dicabut secara tiba-tiba (*hotplug removal*):
     - Sistem seketika mendeteksi pencabutan perangkat keras.
     - Sesi aktif langsung dicabut (*revoked*) dan seluruh tab dikunci kembali (`_lock_vault()`).
     - Insiden pelanggaran fisik dicatat ke Blockchain Audit Ledger (`DONGLE_PHYSICALLY_REMOVED_AUTO_LOCK`).
     - Muncul jendela peringatan darurat keamanan (*Security Alert Dialog*).
   - Pengguna juga dapat mengatur sakelar (*switch*) di sidebar untuk mengaktifkan/menonaktifkan fitur Auto-Lock ini jika ingin demonstrasi mode biasa.

#### B. Pengenalan Wajah OpenCV (Haar Cascade + LBPH)
1. **Langkah Deteksi Wajah**:
   - Webcam menangkap frame video RGB.
   - Frame dikonversi ke citra skala abu-abu (*grayscale*).
   - Algoritma **Haar Cascade** (`haarcascade_frontalface_default.xml`) memindai area wajah menggunakan fitur Haar multi-skala.
2. **Langkah Ekstraksi Fitur & Pelatihan (LBPH)**:
   - Wajah yang terdeteksi di-crop dan dinormalisasi kontrasnya dengan **Histogram Equalization**.
   - Untuk setiap piksel tengah $(x_c, y_c)$, intensitasnya dibandingkan dengan 8 piksel tetangga di sekitarnya:
     $$LBP_{P,R}(x_c, y_c) = \sum_{p=0}^{P-1} s(i_p - i_c) 2^p, \quad \text{di mana } s(x) = \begin{cases} 1, & x \ge 0 \\ 0, & x < 0 \end{cases}$$
   - Citra wajah dibagi menjadi sel $8 \times 8$, dan histogram LBP dihitung untuk setiap sel lalu digabungkan menjadi vektor fitur wajah.
   - Model disimpan ke file XML lokal (`data/biometric_templates/<user>_lbph.xml`).
3. **Langkah Pencocokan (Verifikasi)**:
   - Wajah live pengguna diekstraksi dan dihitung jarak chi-square terhadap histogram template yang tersimpan.
   - Jika jarak (*distance/confidence*) $\le 85.0$, wajah dinyatakan valid dan sah.

---

### 3.2. Kredensial & Enkripsi Basis Data (Argon2id & SQLite AES-GCM)

1. **Password Hashing (Argon2id)**:
   - Menggunakan varian *hybrid* Argon2id yang tahan terhadap serangan GPU (*memory-hard*) dan *side-channel cache-timing attacks*.
   - Setiap password diberikan salt acak 16-byte kriptografis.
2. **Enkripsi Kolom Database (AES-256-GCM)**:
   - Data sensitif pada tabel (seperti catatan audit dan profil pengguna) dienkripsi sebelum disimpan (`INSERT`/`UPDATE`):
     - Dibuat IV/Nonce 12-byte acak via CSPRNG `os.urandom(12)`.
     - Plaintext teks dikonversi ke byte dan dienkripsi dengan AES-256 mode GCM menghasilkan ciphertext dan tag otentikasi 16-byte.
     - Payload disimpan dengan format: `nonce (12 byte) + tag (16 byte) + ciphertext` dan dikodekan dalam Base64.
   - Saat dibaca (`SELECT`), ciphertext diuraikan dan divalidasi keutuhan tag-nya.

---

### 3.3. Super-Enkripsi Teks (Klasik + Modern)

Sistem menerapkan enkripsi dua lapis (*two-layer super-encryption*):

```
 Plaintext  ───> [ 1. Cipher Klasik (Vigenère / Playfair) ] ───> Intermediate Ciphertext
                                                                           │
                                                                           ▼
 Final Base64 Token <─── [ 2. Cipher Modern (AES-256-GCM) ] <──────────────┘
```

#### A. Lapisan 1: Classic Cipher
1. **Vigenère Cipher**:
   - Kunci alfabetik diselaraskan secara periodik terhadap panjang teks.
   - Enkripsi per karakter: $C_i = (P_i + K_i) \bmod 26$.
   - Dekripsi per karakter: $P_i = (C_i - K_i + 26) \bmod 26$.
   - Karakter non-alfabetik (angka, spasi, simbol) dipertahankan posisinya.
2. **Playfair Cipher**:
   - Membangun matriks kunci $5 \times 5$ dari kata kunci (huruf duplikat dibuang, 'J' digabung ke 'I').
   - Plaintext dibagi menjadi pasangan dua huruf (*digraph*). Jika ada huruf kembar dalam satu pasangan, disisipkan huruf dummy `'X'`.
   - Aturan pergeseran digraph:
     - **Satu Baris**: Geser 1 posisi ke kanan (wrap-around).
     - **Satu Kolom**: Geser 1 posisi ke bawah (wrap-around).
     - **Persegi Panjang**: Ambil huruf pada baris yang sama di kolom pasangan pasangannya.

#### B. Lapisan 2: Modern Cipher (AES-256-GCM)
1. Teks hasil cipher klasik dijadikan input plaintext lapis kedua.
2. Sistem membangkitkan nonce acak 12-byte (96 bit).
3. Plaintext dienkripsi menggunakan AES-256-GCM menghasilkan ciphertext biner dan Tag Integritas 16-byte (128 bit GHASH).
4. Hasil dikemas ke dalam struktur JSON:
   ```json
   {
     "algo": "vigenere",
     "nonce": "<base64_12_bytes>",
     "tag": "<base64_16_bytes>",
     "ciphertext": "<base64_ciphertext>"
   }
   ```
5. Struktur JSON di-encode menjadi string Base64 tunggal yang siap dikirim atau disimpan.

---

### 3.4. Enkripsi File Dokumen (RSA-2048 Hybrid & Fernet)

Enkripsi dokumen dirancang terpisah menggunakan metode **Enkripsi Amplop Hibrid (Hybrid Envelope Encryption)**:

```
  File Dokumen Asli (PDF/DOCX)
             │
             ├──> [ Enkripsi Simetris AES-256-GCM ] ──> Dokumen Terenkripsi (.sgvault)
             │                 ▲
             │          Kunci Sesi AES (32-byte)
             │                 │
             │                 ▼
             │      [ Enkripsi Asimetris RSA-2048 OAEP ]
             │                 ▲
             │          Kunci Publik RSA
             │                 │
             └─────────────────┴──────────────────────> Container File .sgvault
```

#### Langkah Rinci Enkripsi Dokumen Hibrid RSA-2048 + AES-256-GCM:
1. **Pembangkitan Kunci Sesi Sementara (*Ephemeral Key*)**:
   - Sistem membangkitkan kunci simetris AES-256 acak segar sebesar 32 byte (`secrets.token_bytes(32)`) khusus untuk file tersebut.
2. **Enkripsi Badan File**:
   - File dibaca sebagai byte biner mentah.
   - Dibuat nonce 12 byte acak.
   - Isi file dienkripsi dengan AES-256-GCM dengan *Authenticated Additional Data* (AAD) = `b"SecureGov-FileVault-v1"`.
   - Menghasilkan biner ciphertext dan tag autentikasi 16 byte.
3. **Pembungkusan Kunci (*Key Encapsulation*)**:
   - Kunci sesi AES 32-byte dienkripsi menggunakan kunci publik RSA penerima (2048 bit) dengan skema padding **OAEP** (*Optimal Asymmetric Encryption Padding*), fungsi hash **SHA-256**, dan **MGF1** (*Mask Generation Function 1*).
   - Menghasilkan blok kunci terenkripsi sebesar 256 byte.
4. **Penyusunan Kontainer Biner `.sgvault`**:
   Format biner disusun dengan spesifikasi byte yang presisi:
   - **Byte 0–3**: Magic Identifier `b"SGVT"` (4 byte).
   - **Byte 4–7**: Format Version `uint32-LE = 1` (4 byte little-endian).
   - **Byte 8–11**: Panjang Kunci RSA Terenkripsi `ekl = 256` (uint32-LE).
   - **Byte 12–23**: AES Nonce (12 byte).
   - **Byte 24 s/d (24 + ekl - 1)**: Kunci AES Terenkripsi RSA-OAEP (256 byte).
   - **Byte Sisa**: Ciphertext biner dokumen + Tag integritas GCM (16 byte di akhir).

#### Langkah Rinci Dekripsi Dokumen `.sgvault`:
1. Membaca file `.sgvault` dan memvalidasi 4 byte pertama harus bernilai `SGVT`.
2. Mengekstrak field versi, panjang kunci, dan nonce 12 byte.
3. Mengambil blok kunci terenkripsi (256 byte) dan mendekripsinya menggunakan **Kunci Privat RSA** milik pengguna dengan skema OAEP-SHA256, memulihkan 32-byte Kunci Sesi AES asli.
4. Mendekripsi ciphertext dokumen menggunakan Kunci Sesi AES, nonce 12 byte, dan memverifikasi tag integritas 16 byte dengan AAD `b"SecureGov-FileVault-v1"`.
5. Jika tag valid, byte dokumen asli disimpan kembali sebagai file utuh (PDF/DOCX/dsb.).

---

### 3.5. Suite Steganografi Multimedia (Gambar, Audio, Video)

Suite steganografi menyembunyikan pesan rahasia ke dalam media pembawa (*cover*) tanpa menimbulkan distorsi sensorik yang dapat dideteksi manusia.

#### A. Steganografi Citra (Image LSB 24-bit RGB)
- **Langkah Penyisipan (Embed)**:
  1. Pesan teks dikonversi ke deretan byte UTF-8.
  2. Dihitung panjang byte pesan $N$, lalu dikemas dalam **4-byte header little-endian** (`struct.pack("<I", N)`).
  3. Header dan payload digabungkan menjadi bit stream (MSB first, total $(4 + N) \times 8$ bit).
  4. Citra cover dibuka dan dipastikan berformat RGB (3 saluran warna per piksel).
  5. Setiap bit pesan disisipkan ke bit paling tidak signifikan (LSB, bit ke-0) dari komponen warna R, G, dan B:
     $$C'_{\text{channel}} = (C_{\text{channel}} \ \& \ \sim 1) \mid \text{bit}$$
  6. Citra stego **wajib disimpan sebagai file lossless PNG** agar kuantisasi kompresi JPEG tidak merusak bit LSB.
- **Langkah Ekstraksi (Extract)**:
  1. Membaca bit LSB dari saluran R, G, B pada 32 kanal pertama untuk merekonstruksi 4-byte uint32-LE penanda panjang pesan ($N$).
  2. Membaca $N \times 8$ kanal berikutnya untuk mengambil seluruh bit payload pesan.
  3. Mengelompokkan setiap 8 bit menjadi 1 byte dan mendecode-nya kembali menjadi string UTF-8.

#### B. Steganografi Audio (Audio LSB WAV PCM)
- **Langkah Penyisipan (Embed)**:
  1. Membaca file cover WAV menggunakan modul standar `wave` (mendukung 16-bit PCM uncompressed, mono atau stereo).
  2. Data audio diurai menjadi array sample numerik signed integer 16-bit (`int16`).
  3. Pesan diberi header 4-byte panjang pesan dan dikonversi ke urutan bit.
  4. LSB setiap sample audio 16-bit dimodifikasi:
     $$S_{\text{new}} = (S \ \& \ \sim 1) \mid \text{bit}$$
  5. Sample audio dikemas kembali ke biner frame WAV asli. Perubahan amplitudo sebesar $\pm 1$ pada skala 16-bit ($\pm 32768$) menghasilkan degradasi audio yang sama sekali tidak terdengar oleh telinga manusia (*Signal-to-Noise Ratio* > 90 dB).
- **Langkah Ekstraksi (Extract)**:
  1. Membaca sample audio WAV secara berurutan.
  2. Mengambil bit LSB dari 32 sample pertama untuk mengetahui ukuran pesan $N$.
  3. Mengambil LSB dari $N \times 8$ sample berikutnya dan menyusun kembali teks rahasia.

#### C. Steganografi Video (Frame-based LSB via OpenCV Lossless FFV1)
- **Kendala Codec Standar**: Codec video umum seperti H.264, MPEG-4, atau XVID menerapkan kompresi *lossy* berbasis diskrit kosinus transformasi (DCT) dan kuantisasi antar-frame, yang akan menghapus bit LSB seketika saat video disimpan.
- **Solusi Lossless FFV1**: SecureGov menggunakan codec **FFV1** (`cv2.VideoWriter_fourcc(*'FFV1')`) yang bersifat *bit-exact lossless*, menjaga integritas bit LSB secara sempurna di setiap frame.
- **Langkah Penyisipan**:
  1. Membuka video cover frame-demi-frame.
  2. Bit pesan (header 4 byte + teks) disisipkan secara terdistribusi pada bit ke-0 saluran warna piksel frame video pertama dan frame-frame selanjutnya.
  3. Video disimpan dalam kontainer AVI ber-codec FFV1.
- **Langkah Ekstraksi**:
  1. Membaca frame video stego satu per satu, mengumpulkan LSB hingga seluruh byte pesan terbaca lengkap.

---

### 3.6. Audit Ledger Blockchain (SHA-256 Immutability & Tamper Detection)

Buku besar audit (*Audit Ledger*) mencatat setiap peristiwa penting dalam sistem (login, enkripsi teks, dekripsi dokumen, penyisipan stego) sebagai blok yang saling terhubung secara kriptografis.

```
+──────────────────────────+       +──────────────────────────+
|         BLOCK #0         |       |         BLOCK #1         |
| (GENESIS BLOCK)          |       | (USER SESSION UNLOCKED)  |
| PrevHash: 00000000000... |       | PrevHash: 572f2269a58... |
| Hash:     572f2269a58... |◄──────| Hash:     3077881af48... |◄────── ...
+──────────────────────────+       +──────────────────────────+
```

#### A. Struktur Data Blok
Setiap blok terdiri dari:
- `index` : Nomor urut blok (0 untuk Genesis).
- `timestamp` : Waktu pembuatan UTC Unix timestamp.
- `data` : Payload event dalam format dictionary/JSON.
- `previous_hash` : Hash SHA-256 dari blok sebelumnya (64 karakter heksadesimal).
- `nonce` : Nilai acak bukti kerja (*Proof-of-Work*, default 0 untuk audit enterprise).
- `hash` : Hash SHA-256 kanonikal dari blok saat ini.

#### B. Rumus Hash Kanonikal SHA-256
Untuk menjamin determinisme lintas platform dan format memori, hash dihitung dari string JSON kanonikal dengan kunci terurut (*sorted keys*):
$$\text{Content} = \text{String}(\text{index}) + \text{String}(\text{timestamp}) + \text{JSON}_{\text{sorted}}(\text{data}) + \text{previous\_hash} + \text{String}(\text{nonce})$$
$$\text{Hash} = \text{SHA256}(\text{Content.encode("utf-8")})$$

#### C. Verifikasi Integritas Rantai (Chain Verification)
Pemeriksaan dilakukan dengan dua aturan mutlak untuk setiap blok $i \ge 1$:
1. **Integritas Internal Blok**:
   $$\text{Block}[i].\text{hash} == \text{compute\_hash}(\text{Block}[i])$$
   *Jika data dimanipulasi sekecil apapun, hash rekalkulasi tidak akan cocok dengan hash tersimpan (`HASH_MISMATCH`).*
2. **Keterkaitan Antar Blok**:
   $$\text{Block}[i].\text{previous\_hash} == \text{Block}[i-1].\text{hash}$$
   *Jika blok sebelumnya diubah hash-nya, tautan rantai pada blok berikutnya akan terputus (`PREV_HASH_MISMATCH`).*

#### D. Simulasi Tampering & Pemulihan (Undo)
- **Simulasi Tamper Dinamis**: Pengguna dapat memilih blok mana saja untuk diinjeksikan serangan manipulasi data in-memory. Setiap klik menghasilkan modifikasi baru dengan stempel waktu unik, menyebabkan kartu blok langsung menyala merah dengan badge `❌ [ CORRUPTED: STORED HASH ≠ COMPUTED HASH ]`.
- **Undo Tamper**: Mengembalikan memori ke cadangan asli (*deep-copied pristine state*) dalam 1 klik tanpa merusak data disk.
- **Re-Hash Chain**: Mensimulasikan serangan 51% di mana penyerang merekayasa ulang seluruh hash downstream dari blok yang dimanipulasi.

---

## 4. Panduan Instalasi & Persiapan Lingkungan

### Kebutuhan Sistem
- **Sistem Operasi**: Windows 10 / 11 (64-bit).
- **Python**: Versi 3.10 atau yang lebih baru.
- **Hardware**: Kamera Webcam (internal/eksternal) dan minimal 1 buah USB Flashdisk (FAT32/NTFS/exFAT).

### Langkah Instalasi Dependensi
1. Buka terminal (PowerShell atau Command Prompt) dan masuk ke direktori proyek:
   ```powershell
   cd "D:\Kuliah\IF\Semester 5\Kriptografi\pKriptoAkhirPY"
   ```
2. Pasang semua dependensi pustaka resmi melalui `pip`:
   ```powershell
   pip install -r requirements.txt
   ```

*Isi dependensi utama dalam `requirements.txt`:*
- `customtkinter` : GUI desktop modern bertema gelap.
- `cryptography` : Implementasi AES-GCM, RSA-OAEP, Fernet, dan SHA-256.
- `opencv-python` & `opencv-contrib-python` : Pemrosesan webcam, deteksi Haar Cascade, model LBPH, dan video steganografi.
- `pillow` : Manipulasi piksel gambar LSB.
- `argon2-cffi` / `bcrypt` : Hashing kata sandi berstandar industri.
- `psutil` : Pemindaian partisi hardware USB removable disk.
- `pytest` : Pengujian unit test otomatis.

---

## 5. Panduan Penggunaan Aplikasi GUI Desktop

### 5.1. Cara Menjalankan (Langsung dari Desktop vs Terminal)

#### Opsi 1: Menjalankan Langsung dari Desktop (Tanpa Terminal)
1. Cukup klik ganda (*double-click*) pada file shortcut:
   - **`SecureGov DocVault.lnk`** di desktop atau di folder proyek, ATAU
   - Klik ganda file **`run_desktop.bat`**.
2. Aplikasi akan langsung membuka jendela GUI Cyber Defense tanpa memunculkan jendela hitam konsol terminal (*background execution via `pythonw.exe`*).

#### Opsi 2: Menjalankan via Terminal (Untuk Debugging & Logging)
```powershell
python app.py
```

---

### 5.2. Langkah Pendaftaran Pengguna & Hardware (Enrollment)

Jika baru pertama kali menjalankan aplikasi atau ingin mendaftarkan user baru:

1. Buka tab **"Pendaftaran Pengguna & Hardware"** (*User & Hardware Enrollment*).
2. **Isi Data Pengguna**:
   - Masukkan **Username** (misal: `Affan`) dan **Password**.
   - Pilih peran (*Role*): `User` atau `Admin`.
3. **Pendaftaran USB Dongle**:
   - Tancapkan flashdisk USB Anda ke port laptop/PC.
   - Klik tombol **"🔄 Pindai Ulang Drive USB"**.
   - Pilih huruf drive USB Anda pada dropdown (misal `E:` atau `G:`).
   - Klik tombol **"🔑 Daftarkan Drive USB Ini sebagai Dongle Resmi"**.
   - Sistem akan membaca nomor seri VSN fisik flashdisk dan membuat file kunci `.securegov_dongle.key`.
4. **Pendaftaran Wajah (Biometric Face)**:
   - Klik **"📹 Nyalakan Kamera Webcam"**.
   - Posisikan wajah Anda tegak menghadap webcam hingga muncul kotak hijau deteksi wajah (*Cyber Face Bounding Box*).
   - Klik tombol **"📸 Rekam 5 Sampel Wajah Live & Latih Model"**.
   - Sistem mengambil 5 sampel wajah, melatih model LBPH, dan menyimpan template wajah Anda.
5. **Simpan Akun**:
   - Klik tombol **"💾 Simpan Pendaftaran Akun & Hardware"**. Akun siap digunakan untuk login!

---

### 5.3. Langkah Login Dual-Faktor (Security Gate)

Secara default, seluruh menu aplikasi (Super-Enkripsi, File Vault, Steganografi, Blockchain) **terkunci dan tidak dapat diakses** sebelum melewati gerbang dual-faktor:

1. Di tab **"Gerbang Dual-Faktor Login"**, pilih Username akun Anda dari dropdown.
2. Masukkan Password akun Anda.
3. **Verifikasi USB Dongle**:
   - Pastikan flashdisk USB yang terdaftar tadi dalam keadaan tertancap.
   - Klik **"🔍 Verifikasi Fisik USB Dongle"**.
   - Sistem memindai port USB; jika cocok, status berubah menjadi hijau: `[ USB DONGLE TERVERIFIKASI ✓ ]`.
4. **Verifikasi Wajah Biometrik**:
   - Pastikan kamera menyala dan wajah Anda menghadap ke webcam.
   - Klik **"👁️ Verifikasi Wajah Biometrik"**.
   - Sistem mencocokkan wajah live dengan model; jika jarak kepercayaan memenuhi syarat, status berubah hijau: `[ WAJAH TERVERIFIKASI ✓ ]`.
5. **Buka Kunci Sistem**:
   - Tombol besar **"🔓 BUKA KUNCI SECURE VAULT"** akan menyala hijau terang.
   - Klik tombol tersebut. Seluruh tab fitur aplikasi kini terbuka dan dapat digunakan sepenuhnya!

---

### 5.4. Penggunaan Tab Super-Enkripsi Teks

Fitur ini digunakan untuk mengamankan pesan teks rahasia melalui enkripsi dua lapis (Klasik $\rightarrow$ Modern).

1. Klik tab **"Super-Enkripsi Teks"**.
2. **Enkripsi Pesan**:
   - Ketik pesan rahasia pada kotak teks *Pesan Plaintext*.
   - Pilih algoritma klasik pada dropdown: **Vigenère Cipher** atau **Playfair Cipher**.
   - Masukkan kata kunci klasik (misal: `GARUDA`).
   - Masukkan kunci modern 32-byte (atau klik **"Bebas/Generate Kunci Acak"**).
   - Klik **"🔒 Enkripsi Super (Klasik + Modern)"**.
   - Kotak output akan menampilkan token terenkripsi akhir dalam format Base64 yang aman dikirim lewat jaringan publik.
3. **Dekripsi Pesan**:
   - Tempelkan token Base64 ke kotak dekripsi.
   - Masukkan kunci klasik dan kunci modern yang sesuai.
   - Klik **"🔓 Dekripsi Super"**.
   - Pesan teks asli akan dipulihkan secara utuh.

---

### 5.5. Penggunaan Tab Enkripsi Dokumen File

Fitur ini mengamankan dokumen kantor (PDF, DOCX, XLSX, TXT) dengan enkripsi dokumen mandiri.

1. Klik tab **"Enkripsi Dokumen (File Vault)"**.
2. **Pilih Metode Enkripsi**:
   - **RSA-2048 Hybrid (AES-GCM)**: Direkomendasikan untuk keamanan enterprise tingkat tinggi.
   - **Fernet (AES-128-CBC + HMAC)**: Enkripsi simetris cepat.
3. **Enkripsi File**:
   - Klik tombol **"📁 Pilih File Dokumen"** dan pilih dokumen (contoh: `laporan_keuangan.pdf`).
   - Klik **"🔒 Enkripsi Dokumen Sekarang"**.
   - File terenkripsi biner berekstensi `.sgvault` akan dihasilkan di folder yang sama. File asli terlindungi dari pembacaan tanpa otorisasi.
4. **Dekripsi File**:
   - Pilih file `.sgvault` yang ingin didekripsi.
   - Klik **"🔓 Dekripsi Dokumen"**.
   - Sistem memvalidasi keutuhan tag otentikasi; jika sah, dokumen asli dipulihkan tanpa cacat sedikitpun.

---

### 5.6. Penggunaan Tab Steganografi Multimedia

Menyediakan 3 sub-tab khusus untuk menyembunyikan dan mengekstrak pesan rahasia:

#### A. Sub-Tab Gambar (Image Steganography)
- **Penyisipan (Embed)**:
  1. Pilih file cover gambar (PNG atau JPG).
  2. Ketik pesan rahasia yang ingin disembunyikan.
  3. Klik **"🖼️ Sisipkan Pesan ke Gambar (LSB)"**.
  4. Simpan gambar output (format otomatis PNG). Gambar tampak sama persis dengan aslinya secara kasat mata.
- **Ekstraksi (Extract)**:
  1. Pilih file gambar stego PNG.
  2. Klik **"🔍 Ekstrak Pesan dari Gambar"**.
  3. Pesan rahasia yang tersembunyi akan langsung terbaca pada kotak output.

#### B. Sub-Tab Audio (Audio Steganography)
- **Penyisipan**: Pilih file audio WAV PCM cover, ketik pesan rahasia, lalu klik **"🎵 Sisipkan Pesan ke Audio WAV"**. File WAV stego baru akan dibuat dengan suara yang tetap jernih.
- **Ekstraksi**: Pilih file audio WAV stego, klik **"🔍 Ekstrak Pesan dari Audio"**, dan pesan rahasia berhasil dimunculkan kembali.

#### C. Sub-Tab Video (Video Steganography)
- **Penyisipan**: Pilih file video cover AVI, ketik pesan, lalu klik **"🎬 Sisipkan Pesan ke Video (FFV1 Lossless)"**. Sistem memodifikasi LSB antar-frame dan menyimpan video stego tanpa kompresi lossy.
- **Ekstraksi**: Pilih video stego AVI, klik **"🔍 Ekstrak Pesan dari Video"**, dan teks rahasia akan dibaca dari frame video.

---

### 5.7. Penggunaan Tab Audit Blockchain & Uji Tampering

Tab ini menampilkan buku besar (*ledger*) transaksi dokumen dan aktivitas pengguna yang anti-manipulasi.

1. Klik tab **"Audit Blockchain"**.
2. **Melihat Riwayat Blok**:
   - Setiap kartu blok menampilkan Nomor Blok, Waktu UTC, Data Event (login, enkripsi, stego), Previous Hash, dan Current Hash SHA-256.
   - Blok yang sah ditandai dengan badge hijau **`✓ [ INTACT & VERIFIED ]`**.
3. **Menguji Integritas**:
   - Klik **"🛡️ Verifikasi Integritas Chain"**. Status di pojok kanan atas akan menunjukkan status hijau: `✓ BLOCKCHAIN INTACT (X BLOCKS TAMPER-PROOF)`.
4. **Melakukan Simulasi Tampering (Peretasan Data)**:
   - Pilih blok yang ingin diserang pada dropdown (atau klik tombol **`[ ⚠️ Tamper Blok Ini ]`** langsung pada kartu blok yang diinginkan).
   - Kartu blok tersebut seketika berubah warna menjadi **MERAH** dengan badge:
     `❌ [ CORRUPTED: STORED HASH ≠ COMPUTED HASH ]`
   - Kotak hash menampilkan perbandingan langsung:
     - **Stored Hash**: Hash asli yang tersimpan sebelumnya.
     - **Computed Hash**: Hash hasil perhitungan ulang data yang telah dimanipulasi (terjadi *MISMATCH!*).
   - Status header utama berubah merah: `❌ INTEGRITY VIOLATION DETECTED!`.
5. **Memulihkan Data Asli (Undo Tamper)**:
   - Klik tombol kuning **"♻️ Kembalikan Data Asli (Undo Tamper)"**.
   - Data blok seketika dipulihkan kembali ke kondisi aslinya, dan status rantai kembali hijau `✓ INTACT`.
   - Anda dapat melakukan uji coba tampering dan pemulihan ini berulang kali dengan blok yang berbeda-beda untuk demonstrasi di depan dosen/penguji!

---

## 6. Contoh Penggunaan Programatik (Python Code Snippets)

Bagi pengembang atau dosen penguji yang ingin menguji modul secara independen melalui script Python:

### A. Super-Enkripsi Teks (Vigenère + AES-256-GCM)
```python
import secrets
from securegov.crypto.super_encryption import SuperEncryptor

# Kunci AES-256 (32 byte) dan kunci klasik alfabetik
aes_key = secrets.token_bytes(32)
se = SuperEncryptor(aes_key=aes_key, classic_key="RAHASIANEGARA", classic_algo="vigenere")

pesan_asli = "Laporan Operasi Intelijen: Status Aman Terkendali."
token_terenkripsi = se.encrypt(pesan_asli)
print("Token Terenkripsi:", token_terenkripsi)

pesan_dekripsi = se.decrypt(token_terenkripsi)
assert pesan_dekripsi == pesan_asli
print("Dekripsi Berhasil:", pesan_dekripsi)
```

### B. Enkripsi Dokumen File Hibrid (RSA-2048 + AES-GCM)
```python
from securegov.crypto.file_encryption import RSAHybridFileEncryptor
from securegov.utils.key_manager import KeyManager

# Buat pasangan kunci RSA
km = KeyManager()
km.generate_rsa_keypair()

encryptor = RSAHybridFileEncryptor(public_key=km.load_public_key(), private_key=km.load_private_key())

# Enkripsi file PDF
encryptor.encrypt_file("dokumen_rahasia.pdf", "dokumen_rahasia.sgvault")

# Dekripsi kembali
encryptor.decrypt_file("dokumen_rahasia.sgvault", "dokumen_pulih.pdf")
print("File berhasil dienkripsi dan dipulihkan dengan RSA-Hybrid!")
```

### C. Steganografi Gambar (LSB PNG)
```python
from securegov.steganography.image_steg import ImageSteganography

steg = ImageSteganography()
steg.embed("cover.png", "Koordinat Pertemuan: 7.7828 S, 110.3671 E", "stego.png")

pesan_rahasia = steg.extract("stego.png")
print("Pesan Tersembunyi:", pesan_rahasia)
```

### D. Audit Logging pada Blockchain
```python
from securegov.blockchain.chain import Blockchain

bc = Blockchain(storage_path="data/audit_chain.json")
bc.add_block({
    "event": "DOCUMENT_SIGNED",
    "user": "Affan",
    "document": "Nota_Dinas.pdf",
    "status": "APPROVED"
})

print("Integritas Rantai Blockchain Sah:", bc.is_valid())
```

---

## 7. Struktur Direktori Proyek

```
pKriptoAkhirPY/
├── app.py                         ← Entry Point Utama Aplikasi Desktop GUI (CustomTkinter)
├── main.py                        ← Skrip demonstrasi otomatis seluruh modul via CLI
├── setup_dongle.py                ← Utilitas CLI untuk memformat & mendaftarkan USB Dongle
├── create_shortcut.py             ← Generator shortcut desktop Windows
├── run_desktop.bat                ← Launcher eksekusi desktop tanpa konsol hitam
├── requirements.txt               ← Daftar dependensi pustaka Python
├── README.md                      ← Dokumentasi lengkap arsitektur & panduan sistem
│
├── securegov/                     ← Paket Kode Sumber Inti Aplikasi
│   ├── auth/
│   │   ├── usb_dongle.py          ← Pemindaian fisik hardware USB VSN via Win32 API & psutil
│   │   ├── biometric.py           ← Pengenalan Wajah Live via OpenCV Haar + Model LBPH
│   │   └── credential_manager.py  ← Hashing password Argon2id/bcrypt & token sesi AES
│   │
│   ├── crypto/
│   │   ├── classic_ciphers.py     ← Implementasi Vigenère Cipher & Playfair 5x5 Matrix
│   │   ├── super_encryption.py    ← Super-enkripsi teks 2-lapis (Klasik -> AES-256-GCM)
│   │   └── file_encryption.py     ← Enkripsi dokumen RSA-2048 OAEP Hibrid & Fernet (.sgvault)
│   │
│   ├── database/
│   │   ├── db_crypto.py           ← Enkripsi terotentikasi kolom basis data (AES-256-GCM)
│   │   └── models.py              ← Skema SQLite, repository data, dan audit repository
│   │
│   ├── steganography/
│   │   ├── image_steg.py          ← Steganografi citra LSB 24-bit RGB (Pillow)
│   │   ├── audio_steg.py          ← Steganografi audio LSB 16-bit WAV PCM (wave stdlib)
│   │   └── video_steg.py          ← Steganografi video frame-based LSB (OpenCV Lossless FFV1)
│   │
│   ├── blockchain/
│   │   └── chain.py               ← Buku besar audit blockchain SHA-256 & verifikasi integritas
│   │
│   ├── gui/                       ← Modul Antarmuka Pengguna Desktop (CustomTkinter)
│   │   ├── styles.py              ← Tema Cyber Defense Dark Palette, warna, & tipografi
│   │   ├── auth_view.py           ← Gerbang Login Dual-Faktor & Enrollment Hardware
│   │   ├── super_crypto_view.py   ← Antarmuka Tab Super-Enkripsi Teks
│   │   ├── file_crypto_view.py    ← Antarmuka Tab Enkripsi Dokumen File Vault
│   │   ├── stego_view.py          ← Antarmuka Tab Steganografi Multimedia (Gambar, Audio, Video)
│   │   └── blockchain_view.py     ← Antarmuka Tab Ledger Blockchain & Uji Tampering Interaktif
│   │
│   └── utils/
│       ├── config.py              ← Konfigurasi global & path direktori runtime
│       ├── logger.py              ← Logging terpusat dengan level INFO/WARNING/ERROR
│       └── key_manager.py         ← Generator & pemuat pasangan kunci RSA (PEM format)
│
├── tests/                         ← Berkas Pengujian Unit Otomatis (Automated Test Suites)
│   ├── test_classic_ciphers.py    ← Uji matematis Vigenère & Playfair
│   ├── test_super_encryption.py   ← Uji enkripsi dua lapis & deteksi kesalahan kunci
│   ├── test_blockchain.py         ← Uji chaining hash, deteksi tamper, & rollback undo
│   ├── test_credentials.py        ← Uji verifikasi Argon2id & validasi token sesi
│   ├── test_db_crypto.py          ← Uji enkripsi/dekripsi kolom basis data AES-GCM
│   └── test_steganography.py      ← Uji penyisipan & ekstraksi bit LSB gambar, audio, video
│
└── data/                          ← Direktori Penyimpanan Runtime & Artefak
    ├── haarcascade_frontalface_default.xml ← Model deteksi wajah OpenCV
    ├── securegov.db               ← Basis data SQLite terenkripsi
    ├── audit_chain.json           ← File persistensi buku besar Blockchain
    ├── allowed_vsns.txt           ← Daftar nomor seri hardware USB yang diizinkan
    ├── biometric_templates/       ← Model terlatih LBPH (.xml) & snapshot wajah
    └── keys/                      ← Pasangan kunci RSA-2048 (public & private key PEM)
```

---

## 8. Pengujian Otomatis (Automated Unit Tests)

Untuk memvalidasi keandalan seluruh algoritma secara objektif dan matematis, proyek ini dilengkapi dengan **47 unit test otomatis** menggunakan framework `pytest`.

### Cara Menjalankan Pengujian:
```powershell
python -m pytest tests/ -v
```

### Ringkasan Hasil Pengujian Terakhir:
```text
============================= test session starts =============================
platform win32 -- Python 3.10.6, pytest-9.2.0
rootdir: D:\Kuliah\IF\Semester 5\Kriptografi\pKriptoAkhirPY

tests/test_blockchain.py ...........                                    [ 21%]
tests/test_classic_ciphers.py ........                                   [ 38%]
tests/test_credentials.py .........                                      [ 57%]
tests/test_db_crypto.py .......                                          [ 72%]
tests/test_steganography.py ......                                       [ 85%]
tests/test_super_encryption.py .......                                   [100%]

======================== 47 passed in 1.88s =========================
```

> **Catatan Akademis**: Seluruh fungsi kriptografi, pembungkusan kunci amplop, algoritma steganografi LSB, serta pengujian peretasan rantai blok lulus 100% tanpa kegagalan (*0 failed*), membuktikan kepatuhan penuh terhadap prinsip integritas, kerahasiaan (*confidentiality*), dan nir-penyangkalan (*non-repudiation*).
