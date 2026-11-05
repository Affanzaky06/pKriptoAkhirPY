# SecureGov / Enterprise DocVault

> **Tugas Akhir — Kriptografi & Sistem Keamanan Informasi**  
> Aplikasi Desktop Enterprise Lengkap untuk Manajemen Dokumen Terenkripsi, Pesan Rahasia, dan Jejak Audit Blockchain dengan **Otentikasi Ganda Hardware Nyata (Zero-Mock: Real Physical USB Dongle + Real OpenCV Live Face Recognition)**.

---

## Daftar Isi
1. [Arsitektur & Fitur Utama](#arsitektur--fitur-utama)
2. [Tampilan Antarmuka Desktop (GUI)](#tampilan-antarmuka-desktop-gui)
3. [Instalasi Dependensi](#instalasi-dependensi)
4. [Cara Menjalankan Aplikasi](#cara-menjalankan-aplikasi)
5. [Panduan Penggunaan Hardware Nyata](#panduan-penggunaan-hardware-nyata)
   - [A. Physical USB Dongle](#a-physical-usb-dongle-flashdisk-asli)
   - [B. Real Live Face Biometrics (Webcam)](#b-real-live-face-biometrics-webcam)
6. [Struktur Proyek Modular](#struktur-proyek-modular)
7. [Pengujian Otomatis (Unit Tests)](#pengujian-otomatis-unit-tests)

---

## Arsitektur & Fitur Utama

| No | Modul Keamanan | Teknologi & Algoritma Nyata | Implementasi File |
|---|---|---|---|
| **1** | **Strict Access Gate** | Locked by Default; Dual-Factor Physical USB + Face | `securegov/gui/auth_view.py` |
| **2** | **Physical USB Dongle** | Hardware VSN Query via `psutil` + `kernel32` & Secret Key | `securegov/auth/usb_dongle.py` |
| **3** | **Live Face Biometrics** | OpenCV Haar Cascade + OpenCV LBPH Face Recognizer | `securegov/auth/biometric.py` |
| **4** | **Credential & DB Crypto** | Argon2id Hashing + SQLite AES-256-GCM Column Encryption | `securegov/database/db_crypto.py` |
| **5** | **Super-Encryption (Text)**| Classic Cipher (Vigenère/Playfair) → Modern AES-256-GCM | `securegov/crypto/super_encryption.py` |
| **6** | **Document Encryption** | RSA-2048-OAEP Hybrid (AES-GCM) & Fernet Symmetric | `securegov/crypto/file_encryption.py` |
| **7** | **Multimedia Stego Suite** | Image LSB (Pillow), Audio LSB (WAV PCM), Video LSB (FFV1) | `securegov/steganography/` |
| **8** | **Blockchain Audit Ledger**| SHA-256 Linked Blocks with Real-Time Tamper Detection | `securegov/blockchain/chain.py` |

---

## Tampilan Antarmuka Desktop (GUI)

Aplikasi dibangun menggunakan **CustomTkinter** dengan tema gelap (*Cyber Defense Dark Palette*):
- **Dashboard Gerbang Keamanan**: Semua fitur utama (Super-Enkripsi, File Vault, Steganografi, Blockchain) terkunci (*disabled*) sampai autentikasi ganda berhasil.
- **Tab Super-Enkripsi**: Input pesan rahasia, pilih cipher klasik, enkripsi dua lapis, serta tombol dekripsi.
- **Tab File Vault**: File picker dokumen PDF/DOCX, enkripsi RSA-Hybrid / Fernet, verifikasi checksum SHA-256.
- **Tab Steganografi Multimedia**: 3 sub-tab khusus untuk Gambar (PNG/JPG), Audio (WAV), dan Video (AVI).
- **Tab Blockchain Audit**: Tabel live riwayat transaksi dengan tombol **Verifikasi Integritas** dan **Simulasi Tampering**.

---

## Instalasi Dependensi

Pastikan Anda menggunakan **Python 3.10+**:

```bash
# 1. Masuk ke direktori proyek
cd pKriptoAkhirPY

# 2. Pasang semua dependensi
pip install -r requirements.txt
```

---

## Cara Menjalankan Aplikasi

### 1. Menjalankan Aplikasi Desktop (GUI Utama)
```bash
python app.py
```

### 2. Menjalankan Demo Otomatis via Terminal (CLI)
```bash
python main.py
```

### 3. Utilitas USB Dongle CLI
```bash
python setup_dongle.py --scan
```

---

## Panduan Penggunaan Hardware Nyata

### A. Physical USB Dongle (Flashdisk Asli)
Sistem SecureGov membaca perangkat keras penyimpanan secara nyata menggunakan modul `psutil` dan fungsi native Windows `GetVolumeInformationW`:

1. **Format & Daftarkan Flashdisk**:
   - Tancapkan flashdisk USB Anda ke laptop/PC (misalkan terdeteksi sebagai drive `E:`).
   - Di aplikasi GUI pada tab **"User & Hardware Enrollment"**, pilih drive flashdisk dari dropdown, lalu klik **"Format & Jadikan Dongle Resmi"**.
   - Atau via terminal:
     ```bash
     python setup_dongle.py E:
     ```
2. **Otentikasi Login**:
   - Saat login di tab **"Dual-Factor Login Gate"**, klik tombol **"Scan Connected USB Drives"**.
   - Sistem akan memindai seluruh removable drive. Jika nomor seri VSN dan file kunci `.securegov_dongle.key` cocok, status dongle berubah menjadi hijau: `[ USB DONGLE TERVERIFIKASI ✓ ]`.

---

### B. Real Live Face Biometrics (Webcam)
Menggunakan **OpenCV Haar Cascade Face Detector** dan **OpenCV LBPHFaceRecognizer**:

1. **Perekaman Wajah (Enrollment)**:
   - Di tab **"User & Hardware Enrollment"**, klik **"Nyalakan Kamera"**.
   - Wajah Anda akan dideteksi secara live dengan kotak hijau (*Cyber Bounding Box*).
   - Klik **"Rekam 5 Sampel Wajah Live & Latih Model"**. Sistem akan mengambil 5 frame wajah, menormalisasi kontras (*Histogram Equalization*), melatih model LBPH, dan menyimpannya ke `data/biometric_templates/<user>_lbph.xml`.
2. **Verifikasi Wajah (Login)**:
   - Saat login, pastikan kamera aktif dan wajah Anda menghadap ke webcam.
   - Klik **"Verifikasi Wajah"**. Sistem mencocokkan wajah live dengan template yang tersimpan.
   - Jika jarak (*distance*) $\le 75.0$, status berubah menjadi hijau: `[ WAJAH TERVERIFIKASI ✓ ]`.
3. **Membuka Vault**:
   - Setelah Kredensial, USB Dongle, dan Wajah terverifikasi, tombol **"UNLOCK SECURE VAULT"** akan aktif. Klik untuk membuka seluruh fitur sistem!

---

## Struktur Proyek Modular

```
pKriptoAkhirPY/
├── app.py                         ← Entry Point Aplikasi Desktop GUI (CustomTkinter)
├── main.py                        ← Demonstrasi CLI lengkap
├── setup_dongle.py                ← Utilitas CLI manajemen USB Dongle
├── requirements.txt               ← Daftar dependensi
├── README.md                      ← Panduan & dokumentasi
│
├── securegov/                     ← Core Application Package
│   ├── auth/
│   │   ├── usb_dongle.py          ← Real hardware USB scanning (psutil + ctypes)
│   │   ├── biometric.py           ← Real Face Recognition (OpenCV Haar + LBPH)
│   │   └── credential_manager.py  ← Argon2id / bcrypt password hashing & AES tokens
│   │
│   ├── crypto/
│   │   ├── classic_ciphers.py     ← Vigenère & Playfair ciphers
│   │   ├── super_encryption.py    ← Classic + AES-256-GCM super-encryption
│   │   └── file_encryption.py     ← RSA-2048 Hybrid & Fernet file encryptors
│   │
│   ├── database/
│   │   ├── db_crypto.py           ← AES-256-GCM database column encryption
│   │   └── models.py              ← SQLite schema, repositories & audit logger
│   │
│   ├── steganography/
│   │   ├── image_steg.py          ← LSB image steganography (Pillow)
│   │   ├── audio_steg.py          ← LSB audio steganography (WAV PCM)
│   │   └── video_steg.py          ← Frame-based LSB video steganography (OpenCV FFV1)
│   │
│   ├── blockchain/
│   │   └── chain.py               ← SHA-256 immutable audit ledger & tamper detection
│   │
│   ├── gui/                       ← Desktop Interface Modules
│   │   ├── styles.py              ← Cyber Defense dark theme & color palette
│   │   ├── auth_view.py           ← Access Gate, USB scanning & Live Face Auth
│   │   ├── super_crypto_view.py   ← Tab Super-Enkripsi teks
│   │   ├── file_crypto_view.py    ← Tab Enkripsi Dokumen (PDF/DOCX)
│   │   ├── stego_view.py          ← Tab Steganografi Multimedia (Gambar, Audio, Video)
│   │   └── blockchain_view.py     ← Tab Tabel Blockchain & Verifikasi Integritas
│   │
│   └── utils/
│       ├── config.py              ← Konstanta & konfigurasi environment
│       ├── logger.py              ← Centralized rotating logger
│       └── key_manager.py         ← Generator & pemuat RSA keypair
│
├── tests/                         ← Automated Test Suites (pytest)
│   ├── test_classic_ciphers.py
│   ├── test_super_encryption.py
│   ├── test_blockchain.py
│   ├── test_credentials.py
│   ├── test_db_crypto.py
│   └── test_steganography.py
│
└── data/                          ← Runtime Artefacts
    ├── haarcascade_frontalface_default.xml ← Model deteksi wajah OpenCV
    ├── securegov.db               ← Basis data SQLite
    ├── audit_chain.json           ← Ledger persistensi Blockchain
    ├── allowed_vsns.txt           ← Daftar VSN USB Dongle resmi
    └── biometric_templates/       ← Model LBPH & snapshot biometrik wajah
```

---

## Pengujian Otomatis (Unit Tests)

Jalankan seluruh test suite otomatis:
```bash
python -m pytest tests/ -v
```

Hasil uji: **46 passed, 0 failed** (100% lulus untuk semua algoritma kriptografi, steganografi, dan blockchain).
