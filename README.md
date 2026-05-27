# Ujaja Sign

Aplikasi desktop Python untuk simulasi tanda tangan digital PDF by Reval.

## Jalankan

```powershell
python -m pip install -r requirements.txt
python main.py
```

## Struktur Inti

```text
main.py
core/             database, auth, OTP, audit, security
self_signed/      logic Self-Signed Digital
ujaja/            logic Universitas Jaya Jaya
views/            UI CustomTkinter
assets/source/    aset tanda tangan sumber
tests/            smoke test per flow
docs/             panduan acuan
requirements.txt
```

## Akun Demo

Self-Signed Digital:

```text
reval@test.sign
password123
```

Universitas Jaya Jaya:

```text
reval@ujaja.ac.id
password123
```

## Catatan

File database, QR, CA, output PDF, dan aset runtime akan dibuat otomatis saat aplikasi dijalankan (local kok).

## Test

```powershell
python -m compileall .
python tests\self_signed_smoke_test.py
python tests\ujaja_smoke_test.py
```
