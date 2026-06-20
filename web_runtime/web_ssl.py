import subprocess
import sys
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from core.database import ASSETS_DIR, ensure_directories
from core.file_security import restrict_private_path
SSL_DIR = ASSETS_DIR / 'ssl'
LOCAL_ROOT_CA_CERT_FILE = SSL_DIR / 'ujaja_local_root_ca.crt'
LOCAL_ROOT_CA_KEY_FILE = SSL_DIR / 'ujaja_local_root_ca.key'
LOCALHOST_CERT_FILE = SSL_DIR / 'localhost.crt'
LOCALHOST_KEY_FILE = SSL_DIR / 'localhost.key'
LOCAL_ROOT_CA_VALID_DAYS = 3650
LOCALHOST_VALID_DAYS = 365
LOCALHOST_RENEW_WINDOW_DAYS = 30

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _load_cert(path: Path) -> x509.Certificate | None:
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError):
        return None

def _load_private_key(path: Path):
    try:
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError):
        return None

def _cert_expiring(path: Path, window_days: int) -> bool:
    cert = _load_cert(path)
    if cert is None:
        return True
    return cert.not_valid_after_utc <= _now() + timedelta(days=window_days)

def _write_private_key(path: Path, private_key) -> None:
    path.write_bytes(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    restrict_private_path(path)

def _root_ca_ready() -> bool:
    if not LOCAL_ROOT_CA_CERT_FILE.exists() or not LOCAL_ROOT_CA_KEY_FILE.exists():
        return False
    return _load_cert(LOCAL_ROOT_CA_CERT_FILE) is not None and _load_private_key(LOCAL_ROOT_CA_KEY_FILE) is not None and (not _cert_expiring(LOCAL_ROOT_CA_CERT_FILE, LOCALHOST_RENEW_WINDOW_DAYS))

def _ensure_root_ca() -> tuple[Path, object, x509.Certificate]:
    if not _root_ca_ready():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, 'ID'), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Universitas Jaya Jaya Local Development'), x509.NameAttribute(NameOID.COMMON_NAME, 'Ujaja Sign Local Root CA')])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(_now() - timedelta(minutes=5)).not_valid_after(_now() + timedelta(days=LOCAL_ROOT_CA_VALID_DAYS)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False).sign(private_key, hashes.SHA256())
        LOCAL_ROOT_CA_CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        _write_private_key(LOCAL_ROOT_CA_KEY_FILE, private_key)
    root_key = _load_private_key(LOCAL_ROOT_CA_KEY_FILE)
    root_cert = _load_cert(LOCAL_ROOT_CA_CERT_FILE)
    if root_key is None or root_cert is None:
        raise RuntimeError('Local Root CA gagal dibuat.')
    return (LOCAL_ROOT_CA_CERT_FILE, root_key, root_cert)

def _server_cert_ready(root_cert: x509.Certificate) -> bool:
    cert = _load_cert(LOCALHOST_CERT_FILE)
    if cert is None or not LOCALHOST_KEY_FILE.exists():
        return False
    if _cert_expiring(LOCALHOST_CERT_FILE, LOCALHOST_RENEW_WINDOW_DAYS):
        return False
    if cert.issuer != root_cert.subject:
        return False
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san.get_values_for_type(x509.DNSName).index('localhost')
        san.get_values_for_type(x509.IPAddress).index(ip_address('127.0.0.1'))
        san.get_values_for_type(x509.IPAddress).index(ip_address('::1'))
    except (ValueError, x509.ExtensionNotFound):
        return False
    return True

def _write_server_cert(root_key, root_cert: x509.Certificate) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, 'ID'), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Universitas Jaya Jaya Local Development'), x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(root_cert.subject).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(_now() - timedelta(minutes=5)).not_valid_after(_now() + timedelta(days=LOCALHOST_VALID_DAYS)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.IPAddress(ip_address('127.0.0.1')), x509.IPAddress(ip_address('::1'))]), critical=False).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False).sign(root_key, hashes.SHA256())
    LOCALHOST_CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private_key(LOCALHOST_KEY_FILE, private_key)

def install_local_root_ca() -> None:
    if not sys.platform.startswith('win'):
        return
    cert_path = str(LOCAL_ROOT_CA_CERT_FILE.resolve()).replace("'", "''")
    script = f"\n$certPath = '{cert_path}'\n$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)\n$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')\n$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)\ntry {{\n    $exists = $false\n    foreach ($item in $store.Certificates) {{\n        if ($item.Thumbprint -eq $cert.Thumbprint) {{\n            $exists = $true\n            break\n        }}\n    }}\n    if (-not $exists) {{\n        $store.Add($cert)\n    }}\n}} finally {{\n    $store.Close()\n}}\n"
    subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], check=True, capture_output=True, text=True)

def ensure_localhost_certificate() -> tuple[Path, Path]:
    ensure_directories()
    SSL_DIR.mkdir(parents=True, exist_ok=True)
    restrict_private_path(SSL_DIR)
    _root_path, root_key, root_cert = _ensure_root_ca()
    if not _server_cert_ready(root_cert):
        _write_server_cert(root_key, root_cert)
    install_local_root_ca()
    return (LOCALHOST_CERT_FILE, LOCALHOST_KEY_FILE)