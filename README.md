# 🖋️ Ujaja Digital Sign App

Aplikasi Tanda Tangan Digital Berbasis Web untuk **Universitas Jaya Jaya (UJAJA)**. Aplikasi ini dirancang untuk memberikan kemudahan dan keamanan tingkat tinggi dalam penerbitan sertifikat identitas digital serta penandatanganan dokumen PDF.

---

## ✨ Fitur Utama

*   **Penerbitan Identitas Digital (CA):** Mengeluarkan sertifikat format `.p12` secara lokal menggunakan sistem *Certificate Authority* (CA) institusi.
*   **Tanda Tangan Kriptografis PDF:** Menandatangani file PDF secara *digital* menggunakan standar PAdES (kompatibel penuh dengan verifikasi Adobe Acrobat Reader).
*   **Enforcement SSL & VPN Blocker:** Keamanan ketat yang memastikan koneksi terenkripsi (*HTTPS/SSL*) dan menolak akses dari jaringan *Proxy* atau *VPN*.
*   **Watermark Anti-Crop:** Setiap tanda tangan visual yang dibubuhkan pada dokumen dilindungi dengan *watermark* kriptografis unik.
*   **Manajemen OTP & QR Code:** Dukungan otentikasi dua langkah (OTP) serta verifikasi *QR Code* cerdas.
*   **100% Web-Based:** Menggunakan Flask backend dengan antarmuka web modern yang ringan dan responsif.

---

## 🚀 Cara Menjalankan Aplikasi

Aplikasi ini bersifat mandiri dan akan menginisialisasi database serta *secret keys* secara otomatis saat pertama kali dijalankan.

### Prasyarat
*   Python 3.10 atau lebih baru.
*   Instal dependensi dengan perintah:
    ```bash
    pip install -r requirements.txt
    ```

### Menjalankan Server Web
Terdapat dua cara untuk menjalankan aplikasi ini:

1.  **Menggunakan HTTPS (Disarankan):**
    Jalankan file batch:
    ```bash
    RUN_WEB.bat
    ```
    *(Atau via Python: `python launchers/run_web.py`)*

2.  **Menggunakan HTTP Biasa (Tanpa SSL):**
    Jalankan file batch:
    ```bash
    RUN_NO_SSL.bat
    ```

Aplikasi dapat diakses melalui browser pada alamat: **`https://127.0.0.1:5000`** (atau `http://127.0.0.1:5000` jika tanpa SSL).

### Setup Akun Admin
Saat pertama kali membuka aplikasi di browser, sistem akan mendeteksi bahwa database masih kosong dan secara otomatis mengarahkan Anda ke halaman **Setup Admin**. Silakan buat akun admin pertama Anda di sana.

---

## 📂 Struktur Direktori Utama

*   `core/` : Modul keamanan inti, manajemen *database*, *file security*, dan audit.
*   `ujaja/` : Modul pemrosesan sertifikat digital (CA) dan manipulasi tanda tangan PDF.
*   `web_runtime/` : Konfigurasi server Flask, *routing*, dan implementasi SSL.
*   `launchers/` : Skrip utama untuk menjalankan aplikasi web.

*Catatan: Direktori `data/` (berisi database dan secret) serta file *cache* diabaikan oleh Git demi alasan keamanan.*

---
*Dikembangkan untuk Universitas Jaya Jaya.*
