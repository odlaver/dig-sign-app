# Bahan Belajar Presentasi Ujaja Sign

Pegangan ini dibuat untuk presentasi dan tanya jawab. Pakai bahasa yang jujur: aplikasi ini adalah MVP edukatif, bukan layanan tanda tangan elektronik tersertifikasi resmi.

## Ringkasan 30 Detik

Ujaja Sign adalah aplikasi desktop Python + CustomTkinter untuk simulasi tanda tangan digital PDF. Ada dua mode: `Universitas Jaya Jaya` sebagai alur utama institusi, dan `Self-Signed Digital` sebagai pembanding tanda tangan mandiri. Pada mode Ujaja, civitas login, mengaktifkan OTP, sistem mengecek status civitas aktif, lalu PDF ditandatangani memakai Digital ID institusi. PDF hasilnya punya visual signature, QR, kode verifikasi, metadata internal, hash, signature value, dan embedded PDF digital signature standar via pyHanko agar terbaca di Acrobat/Foxit.

Kalimat aman:

> Ini simulasi edukatif end-to-end. Acrobat/Foxit bisa membaca signature PDF-nya, tetapi trust penuh butuh import CA lokal Ujaja karena sertifikatnya bukan dari CA/PSrE resmi.

## Tujuan Aplikasi

Masalah:

- Dokumen akademik sering butuh tanda tangan institusi.
- Proses manual lambat kalau pegawai harus datang langsung.
- Penerima dokumen perlu cara mengecek dokumen tidak berubah.

Solusi:

- Pegawai/civitas login.
- Signing dilindungi OTP.
- Sistem mengecek status civitas.
- Sistem menerbitkan PDF signed.
- PDF bisa diverifikasi di aplikasi dan signature PDF-nya terbaca Acrobat/Foxit.

## Akun Demo

Universitas Jaya Jaya:

```text
Email    : reval@ujaja.ac.id
Password : password123
```

Self-Signed Digital:

```text
Email    : reval@test.sign
Password : password123
```

## Struktur Folder

```text
main.py                     entry point aplikasi
core/                       database, auth, OTP, audit, security
ujaja/                      logic Universitas Jaya Jaya
self_signed/                logic Self-Signed Digital
views/                      UI CustomTkinter
assets/source/ttdreval.png  aset tanda tangan kampus
release/UjajaSign.exe       EXE portable
tests/                      smoke test
docs/                       panduan dan bahan belajar
requirements.txt            dependency
```

File penting:

- `main.py`: init database, seed akun, seed CA/Digital ID, routing view.
- `core/database.py`: schema SQLite dan path runtime.
- `core/otp_service.py`: QR OTP dan validasi TOTP.
- `core/security.py`: hash password/passphrase dengan PBKDF2 SHA-256.
- `ujaja/ca_service.py`: membuat CA lokal Ujaja, sertifikat X.509, key RSA, dan aset signature.
- `ujaja/acrobat_signature.py`: menambahkan embedded PDF digital signature via pyHanko.
- `ujaja/institution_signer.py`: signing dan verification mode Ujaja.
- `self_signed/pdf_signer.py`: signing mode personal.
- `self_signed/verifier.py`: verifikasi mode personal.

## Database

Database memakai SQLite lokal:

```text
data/ujaja_sign.db
```

Tabel penting:

- `users`: akun, password hash, OTP secret, status OTP.
- `employees`: data civitas/pegawai.
- `ujaja_ca`: data CA Universitas Jaya Jaya.
- `ujaja_digital_ids`: Digital ID institusi Ujaja.
- `ujaja_sign_requests`: dokumen yang ditandatangani institusi.
- `documents`: dokumen self-signed.
- `verification_logs`: log verifikasi.
- `audit_logs`: log aksi penting.

Jawaban kalau ditanya kenapa SQLite:

> Karena targetnya aplikasi desktop lokal untuk MVP. SQLite ringan dan tidak butuh server. Untuk produksi, database verifikasi sebaiknya dipindah ke server agar bisa dipakai lintas perangkat.

## Alur Mode Universitas Jaya Jaya

1. User pilih mode `Universitas Jaya Jaya`.
2. User login sebagai civitas.
3. Sistem mengecek akun ada di tabel `employees`.
4. Sistem mengecek `employee_status = Active`.
5. User setup OTP.
6. Sistem memastikan CA Ujaja aktif.
7. Sistem memastikan Digital ID institusi aktif.
8. User upload PDF.
9. User memasukkan OTP.
10. Sistem membuat PDF signed.
11. User atau pihak penerima memverifikasi PDF.

## Signing PDF Institusi

File utama:

```text
ujaja/institution_signer.py
ujaja/acrobat_signature.py
```

Urutan teknis saat klik sign:

1. Cek file harus PDF dan tidak terenkripsi.
2. Cek OTP valid.
3. Cek civitas aktif.
4. Cek CA aktif.
5. Cek Digital ID institusi aktif.
6. Hitung hash PDF asli dengan SHA-256.
7. Buat kode verifikasi unik format `Ujaja-XXXXXXXXXXXX`.
8. Buat overlay visual di halaman terakhir:
   - gambar tanda tangan kampus,
   - nama pegawai,
   - role,
   - Civitas ID,
   - issuer,
   - waktu,
   - QR,
   - kode verifikasi.
9. Simpan metadata internal:
   - `UjajaSignMode`,
   - `UjajaSignCode`,
   - `UjajaSignCASerial`,
   - `UjajaSignDigitalIdSerial`,
   - `UjajaSignPayloadHash`,
   - `UjajaSignSignatureValue`.
10. Tambahkan embedded PDF digital signature standar dengan pyHanko.
11. Hitung hash PDF final.
12. Simpan record ke database.
13. Catat audit log.

Output:

```text
assets/signed_docs/
```

## Verifikasi PDF Institusi

Verifikasi di aplikasi:

1. Baca kode dari metadata PDF.
2. Jika metadata tidak ada, cari kode dari teks PDF.
3. Pastikan mode dokumen adalah `institution`.
4. Cari kode di database.
5. Hitung hash file yang dipilih.
6. Cocokkan hash saat ini dengan hash final tersimpan.
7. Cocokkan serial CA.
8. Cocokkan serial Digital ID.
9. Cek status civitas masih aktif.
10. Cocokkan signature value metadata dengan database.
11. Verifikasi signature value memakai public key Digital ID.

Jika semua cocok, dokumen valid.

Penyebab tidak valid:

- Kode tidak ditemukan.
- Dokumen bukan mode institusi.
- Hash berubah.
- CA tidak cocok.
- Digital ID tidak cocok.
- Civitas tidak aktif.
- Signature value tidak cocok.
- Status dokumen bukan `Signed`.

## Acrobat/Foxit

Mode Ujaja sekarang menambahkan embedded digital signature PDF dengan pyHanko. Artinya Acrobat/Foxit bisa membuka panel signature dan mendeteksi bahwa PDF punya digital signature standar.

Namun trust punya dua level:

```text
Tanpa import CA:
Acrobat/Foxit membaca signature, tetapi identitas bisa dianggap belum trusted.

Dengan import Ujaja Root CA:
Acrobat/Foxit dapat mempercayai signature secara lokal di laptop itu.
```

Cara menjelaskan:

> pyHanko membuat struktur signature PDF standar. Sertifikat Ujaja dibuat lokal untuk simulasi, jadi Acrobat/Foxit perlu diberi trust manual lewat import CA. Kalau ingin otomatis trusted di semua komputer, harus memakai CA/PSrE resmi.

CA bisa didownload dari menu `Certificate Authority`. File yang didownload adalah `universitas_jaya_jaya_root_ca.crt`.

## Istilah Penting

### Hash

Hash adalah sidik jari digital file. Aplikasi memakai SHA-256. Kalau isi PDF berubah sedikit saja, hash berubah.

Jawaban singkat:

> Hash membuktikan integritas file, bukan menyembunyikan isi file.

### OTP / TOTP

OTP adalah kode sekali pakai. TOTP berubah mengikuti waktu. Aplikasi memakai `pyotp`.

Jawaban singkat:

> OTP mencegah signing hanya bermodal password.

### CA

CA adalah Certificate Authority. Di aplikasi ini CA adalah simulasi root certificate milik Universitas Jaya Jaya.

Jawaban singkat:

> CA dipakai sebagai akar trust. Untuk demo lokal, CA bisa di-import ke Acrobat/Foxit.

### Digital ID

Digital ID adalah identitas digital yang dipakai untuk signing. Pada mode Ujaja, Digital ID adalah milik institusi, bukan user pribadi.

### Public Key dan Private Key

Private key membuat signature. Public key memverifikasi signature.

Jawaban singkat:

> Private key tidak dibagikan; public key/sertifikat boleh dibagikan.

### Metadata PDF

Metadata menyimpan informasi internal seperti kode verifikasi, serial CA, serial Digital ID, payload hash, dan signature value.

### Signature Value

Signature value adalah hasil tanda tangan kriptografis dari payload internal aplikasi. Ini berbeda dari visual tanda tangan.

## Demo Script Utama

1. Buka `release/UjajaSign.exe`.
2. Pilih `Universitas Jaya Jaya`.
3. Login `reval@ujaja.ac.id` / `password123`.
4. Tunjukkan dashboard: Civitas, OTP, CA, Digital ID.
5. Buka `Setup OTP`.
6. Scan QR pakai Google/Microsoft Authenticator.
7. Masukkan kode OTP.
8. Buka `Certificate Authority`.
9. Jelaskan CA dan Digital ID.
10. Buka `Sign Academic Document`.
11. Pilih PDF biasa yang tidak terenkripsi.
12. Pilih posisi tanda tangan.
13. Masukkan OTP.
14. Klik `Sign with Ujaja Digital ID`.
15. Buka PDF hasil signed di Acrobat/Foxit.
16. Tunjukkan visual signature dan panel signature.
17. Kembali ke aplikasi.
18. Buka `Verify Academic Signature`.
19. Pilih PDF hasil signed.
20. Tunjukkan status valid.

## Demo Tamper

Tujuan: membuktikan file yang berubah akan ditolak.

1. Copy PDF signed ke file lain.
2. Ubah sedikit file copy tersebut.
3. Verify file yang sudah diubah.
4. Hasil harus tidak valid karena hash berubah.

Kalimat:

> Kode verifikasi masih bisa terbaca, tetapi hash file berubah dari hash final yang disimpan saat signing. Karena itu dokumen ditolak.

## Mode Self-Signed

Alur:

1. Login `reval@test.sign`.
2. Setup OTP.
3. Buat Digital ID personal.
4. Upload gambar tanda tangan.
5. Sign PDF dengan OTP dan passphrase.
6. Verify PDF.

Perbedaan utama:

- Self-Signed memakai passphrase user.
- Ujaja memakai Digital ID institusi.
- Self-Signed cocok sebagai pembanding konsep, bukan alur utama tugas.

Kalau ditanya passphrase buat apa:

> Passphrase hanya untuk mode Self-Signed sebagai proteksi tambahan Digital ID pribadi. Mode Ujaja tidak memakai passphrase user karena signing dilakukan oleh Digital ID institusi setelah user lolos login, status civitas, dan OTP.

## Pertanyaan Kritis dan Jawaban Aman

### Apakah ini tanda tangan elektronik resmi?

Belum. Ini simulasi edukatif. Untuk resmi perlu CA/PSrE resmi, kebijakan sertifikat, audit, timestamp authority, revocation check, dan standar PAdES/LTV.

### Apakah ini cuma gambar tanda tangan?

Tidak. Gambar hanya visual. Mode Ujaja juga punya embedded PDF digital signature via pyHanko, metadata, kode verifikasi, hash, CA, Digital ID, dan signature value.

### Bisa diverifikasi Acrobat/Foxit?

Bisa terbaca sebagai PDF digital signature. Agar trusted penuh di laptop demo, import `Ujaja Root CA` dari menu Certificate Authority. Tanpa import, signature bisa terbaca tetapi signer identity bisa dianggap belum dipercaya.

### Kenapa tidak trusted otomatis?

Karena sertifikat Ujaja dibuat lokal/self-issued untuk simulasi. Acrobat/Foxit hanya otomatis percaya sertifikat dari trust store/CA resmi.

### Kalau PDF dipindah ke laptop lain?

Acrobat/Foxit tetap bisa membaca embedded signature. Verifikasi internal aplikasi tetap butuh database lokal yang berisi record signing. Untuk produksi, database harus server-side.

### Kalau kode verifikasi ditempel ke PDF lain?

Tidak cukup. Hash final, metadata, CA, Digital ID, dan signature value tidak cocok, sehingga verifikasi gagal.

### Kalau PDF diedit setelah signed?

Hash final berubah. Acrobat/Foxit juga akan menandai perubahan pada signature PDF, dan aplikasi internal akan gagal di hash check.

### Kenapa perlu OTP?

Supaya signing tidak hanya bergantung pada password. User harus membuktikan memegang authenticator saat signing.

### Kenapa tidak ada register?

Karena fokus tugas adalah alur signing institusi, bukan manajemen user. Akun demo membuat presentasi stabil.

### Kenapa tidak ada admin?

Admin dianggap berjalan di belakang sistem. Data civitas, CA, dan Digital ID dibuat otomatis sebagai seed agar alur user selesai end-to-end.

### Kenapa private key lokal?

Untuk MVP desktop. Untuk produksi, private key harus disimpan di server/key vault/HSM dan tidak boleh tersebar di perangkat user.

### Kenapa SQLite?

Karena MVP desktop lokal. Untuk produksi, gunakan database server agar verifikasi lintas perangkat.

### Kenapa PDF terenkripsi ditolak?

PDF terenkripsi perlu dekripsi/password sebelum bisa diberi overlay dan signature. MVP menolak agar alur stabil.

### Kenapa EXE warning di Windows?

Karena EXE belum code-signed dengan sertifikat Windows. Itu berbeda dari signature PDF.

## Batasan yang Perlu Diakui

- Belum TTE tersertifikasi resmi.
- Trust Acrobat/Foxit masih lokal jika memakai CA Ujaja.
- Belum memakai PSrE/CA resmi.
- Belum ada timestamp authority resmi.
- Belum PAdES-LTA/long-term validation.
- Verifikasi internal masih bergantung database lokal.
- Private key masih disimpan lokal untuk simulasi.
- Belum ada admin dashboard untuk revoke.
- PDF terenkripsi belum didukung.
- EXE belum code-signed.

Kalimat aman:

> Batasan itu sengaja dipilih karena scope tugas adalah MVP desktop. Yang diprioritaskan adalah proses end-to-end: login, OTP, status civitas, identitas institusi, PDF signing, Acrobat-readable signature, dan verifikasi integritas.

## Hal yang Jangan Diklaim

Jangan bilang:

- "Ini sudah legal resmi."
- "Ini otomatis trusted di semua Acrobat/Foxit."
- "Ini aman untuk production."
- "CA ini CA resmi."
- "Database lokal cukup untuk semua perangkat."
- "Gambar tanda tangan saja yang menentukan valid."

Ganti dengan:

- "Ini MVP edukatif."
- "Mode Ujaja sudah punya embedded PDF signature via pyHanko."
- "Trust penuh perlu import CA lokal atau CA resmi."
- "Untuk production perlu server, secure key storage, timestamp, revocation, dan PSrE/CA resmi."

## Test

Perintah:

```powershell
python -m compileall .
python tests\self_signed_smoke_test.py
python tests\ujaja_smoke_test.py
```

Yang diuji:

- OTP salah ditolak.
- OTP benar diterima.
- Signing PDF berhasil.
- Verifikasi PDF valid.
- PDF yang diubah menjadi tidak valid.
- Mode Ujaja menghasilkan embedded PDF signature.
- Signature value internal valid.

## Checklist H-1

- Jalankan `release/UjajaSign.exe`.
- Siapkan PDF biasa yang tidak terenkripsi.
- Siapkan authenticator di HP.
- Coba login Ujaja.
- Coba setup OTP.
- Coba sign PDF.
- Buka hasilnya di Acrobat/Foxit.
- Coba verify di aplikasi.
- Coba tamper file dan verify ulang.
- Hafalkan: "Acrobat-readable, tetapi trust lokal perlu import CA".

## Jawaban 1 Menit

> Ujaja Sign adalah aplikasi desktop untuk simulasi tanda tangan digital dokumen akademik. User login sebagai civitas, mengaktifkan OTP, lalu sistem mengecek bahwa user adalah civitas aktif. Saat sign PDF, sistem menambahkan visual signature, QR, kode verifikasi, metadata, hash, signature value, dan embedded PDF digital signature standar via pyHanko. Verifikasi aplikasi membaca kode dari PDF, mencocokkan database, hash, CA, Digital ID, status civitas, dan signature value. Acrobat/Foxit juga bisa membaca signature PDF-nya, tetapi karena CA Ujaja lokal, trust penuh perlu import CA atau memakai CA resmi untuk produksi.
