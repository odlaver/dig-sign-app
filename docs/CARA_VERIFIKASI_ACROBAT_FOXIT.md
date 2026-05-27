# Cara Verifikasi PDF Ujaja Sign di Acrobat dan Foxit

Panduan ini untuk demo hasil PDF dari mode `Universitas Jaya Jaya`.

Catatan penting:

- Acrobat/Foxit bisa membaca embedded digital signature dari PDF Ujaja Sign.
- Karena sertifikat Ujaja dibuat lokal untuk simulasi, pertama kali dibuka biasanya muncul status belum dipercaya.
- Agar trusted di laptop demo, trust/import sertifikat Ujaja dari signature properties atau dari file CA yang didownload dari aplikasi.
- Ini trust lokal untuk demo, bukan CA/PSrE resmi.

## Siapkan PDF Signed

1. Buka `release/UjajaSign.exe`.
2. Pilih `Universitas Jaya Jaya`.
3. Login:

```text
reval@ujaja.ac.id
password123
```

4. Pastikan OTP sudah aktif.
5. Buka `Sign Academic Document`.
6. Pilih PDF.
7. Masukkan OTP.
8. Klik `Sign with Ujaja Digital ID`.
9. Buka file output dari folder:

```text
assets/signed_docs/
```

## Opsi 1: Adobe Acrobat Reader

### A. Verifikasi Cepat

1. Buka PDF hasil signed di Adobe Acrobat Reader.
2. Buka panel `Signatures` di sisi kanan.
3. Klik `Options`.
4. Pilih `Validate Signatures`.
5. Buka detail signature.

Yang perlu dilihat:

- Signature terdeteksi di panel Acrobat.
- Dokumen tidak berubah sejak ditandatangani.
- Jika muncul warning tentang signer/certificate belum trusted, itu normal sebelum CA Ujaja dipercaya.

### B. Trust Sertifikat Ujaja

Jika Acrobat menampilkan warning seperti signature bermasalah atau signer belum dipercaya:

1. Buka panel `Signatures`.
2. Klik kanan pada signature Ujaja.
3. Pilih `Show Signature Properties`.
4. Klik `Show Signer's Certificate`.
5. Buka tab `Trust`.
6. Klik `Add to Trusted Certificates`.
7. Konfirmasi dialog yang muncul.
8. Aktifkan trust untuk validasi signature/certified document jika diminta.
9. Tutup dialog.
10. Jalankan `Validate Signatures` lagi.
11. Jika status belum berubah, tutup dan buka ulang PDF.

Hasil yang diharapkan:

```text
Signature terbaca oleh Acrobat.
Document has not been modified since it was signed.
Signer/certificate trusted setelah Ujaja Root CA dipercaya lokal.
```

Kalimat presentasi:

> Acrobat bisa membaca digital signature PDF-nya. Karena CA Ujaja adalah CA lokal simulasi, pertama kali perlu ditambahkan ke Trusted Certificates. Setelah dipercaya, Acrobat dapat memvalidasi signature secara lokal.

## Opsi 2: Foxit PDF Reader

### A. Verifikasi Cepat

1. Buka PDF hasil signed di Foxit PDF Reader.
2. Buka panel `Digital Signatures` atau panel signature di sisi kiri/kanan.
3. Pilih signature Ujaja.
4. Klik kanan signature.
5. Pilih `Validate Signature` atau buka `Show Signature Properties`.

Yang perlu dilihat:

- Foxit mendeteksi digital signature.
- Jika signer belum trusted, status bisa tampil unknown/untrusted.
- Kalau file PDF diubah setelah signing, Foxit akan menandai signature bermasalah.

### B. Trust Sertifikat Ujaja

Jika Foxit menampilkan certificate/signature belum dipercaya:

1. Klik kanan digital signature.
2. Pilih `Show Signature Properties`.
3. Klik `Show Certificate`.
4. Buka tab `Trust`.
5. Aktifkan:

```text
Use this certificate as a trusted root
Validating Signatures
Validating Certified Documents
```

6. Simpan/OK.
7. Validate signature lagi.
8. Jika belum berubah, tutup dan buka ulang PDF.

Hasil yang diharapkan:

```text
Signature terbaca oleh Foxit.
Integritas dokumen valid.
Certificate trusted secara lokal setelah Ujaja Root CA dipercaya.
```

Kalimat presentasi:

> Foxit juga bisa membaca embedded digital signature. Sama seperti Acrobat, karena CA Ujaja adalah CA lokal, trust harus ditambahkan manual di laptop demo.

## Kalau Diminta Pakai File CA dari Aplikasi

Di aplikasi:

1. Login mode `Universitas Jaya Jaya`.
2. Buka `Certificate Authority`.
3. Klik `Download CA`.
4. Simpan sebagai:

```text
universitas_jaya_jaya_root_ca.crt
```

File ini adalah root certificate Ujaja untuk demo trust lokal.

Jika dosen bertanya "buat apa CA ini?":

> CA ini dipakai agar PDF reader seperti Acrobat/Foxit bisa mengenali Ujaja sebagai trusted root lokal. Untuk sistem resmi, root trust harus berasal dari CA/PSrE yang diakui, bukan CA lokal simulasi.

## Perbedaan Status yang Mungkin Muncul

### Signature terbaca tapi belum trusted

Artinya PDF sudah punya digital signature, tetapi Acrobat/Foxit belum percaya CA Ujaja.

Jawaban:

> Ini normal karena sertifikat dibuat lokal. Tambahkan Ujaja Root CA ke trusted certificates untuk demo.

### Signature invalid setelah file diedit

Artinya isi PDF berubah setelah signing.

Jawaban:

> Ini justru bukti digital signature bekerja. Perubahan kecil pada PDF membuat validasi gagal.

### Signature valid di aplikasi tapi belum trusted di Acrobat/Foxit

Artinya verifikasi internal Ujaja valid, tetapi trust Acrobat/Foxit belum dikonfigurasi.

Jawaban:

> Aplikasi punya verifikasi internal berbasis database dan hash. Acrobat/Foxit memakai certificate trust store. Dua-duanya perlu konteks trust masing-masing.

## Jawaban Aman Saat Presentasi

Gunakan kalimat ini kalau ditanya:

> PDF hasil Ujaja Sign sudah memakai embedded digital signature standar via pyHanko, sehingga bisa dibaca Acrobat/Foxit. Karena sertifikatnya adalah CA lokal simulasi, Acrobat/Foxit perlu import/trust Ujaja Root CA agar signer dipercaya di laptop tersebut. Kalau ingin otomatis trusted di semua komputer, harus memakai CA/PSrE resmi.

## Checklist Demo

- PDF signed sudah dibuat dari mode Universitas Jaya Jaya.
- Jangan edit PDF setelah signing.
- Buka PDF di Acrobat atau Foxit.
- Tunjukkan signature panel.
- Jika muncul untrusted, trust certificate dari signature properties.
- Validate signature ulang.
- Tunjukkan bahwa file yang sudah diedit akan gagal validasi.

