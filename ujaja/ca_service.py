from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone
from pathlib import Path
import uuid
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from PIL import Image, ImageDraw, ImageFont
from core.audit import log_action
from core.database import BUNDLED_SOURCE_ASSETS_DIR, CA_DIR, SOURCE_ASSETS_DIR, UJAJA_DIR, get_connection
from core.file_security import restrict_private_path
from core.security import hash_secret
INSTITUTION_NAME = 'Universitas Jaya Jaya'
CA_NAME = 'Universitas Jaya Jaya'
CA_SERIAL = 'Ujaja-CA-ROOT-0001'
DIGITAL_ID_NAME = 'Universitas Jaya Jaya'
DIGITAL_ID_SERIAL = 'Ujaja-DID-0001'
SOURCE_SIGNATURE_FILE = SOURCE_ASSETS_DIR / 'ttdreval.png'
BUNDLED_SIGNATURE_FILE = BUNDLED_SOURCE_ASSETS_DIR / 'ttdreval.png'
CA_CERT_FILE = CA_DIR / 'ujaja_root_ca.crt'
SIGNER_KEY_FILE = CA_DIR / 'ujaja_academic_signer_key.pem'
SIGNER_CERT_FILE = CA_DIR / 'ujaja_academic_signer.crt'
CA_FILE = CA_CERT_FILE
UJAJA_SIGNATURE_FILE = UJAJA_DIR / 'ujaja_signature.png'
CA_VALIDITY_DAYS = 365 * 5
DIGITAL_ID_VALIDITY_DAYS = 365
CA_RENEWAL_WINDOW_DAYS = 45

def _now() -> str:
    return datetime.now().isoformat(timespec='seconds')

def _expires_at(days: int=DIGITAL_ID_VALIDITY_DAYS) -> str:
    return (datetime.now() + timedelta(days=days)).isoformat(timespec='seconds')

def _cert_not_before():
    return datetime.now(timezone.utc) - timedelta(minutes=5)

def _cert_not_after(days: int=DIGITAL_ID_VALIDITY_DAYS):
    return datetime.now(timezone.utc) + timedelta(days=days)

def _generate_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def _private_key_pem(private_key) -> str:
    return private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode('ascii')

def _public_key_pem(private_key) -> str:
    return private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')

def _certificate_pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode('ascii')

def _load_private_key(private_key_pem: str):
    return serialization.load_pem_private_key(private_key_pem.encode('ascii'), password=None)

def _load_public_key(public_key_pem: str):
    return serialization.load_pem_public_key(public_key_pem.encode('ascii'))

def _load_certificate(certificate_pem: str):
    return x509.load_pem_x509_certificate(certificate_pem.encode('ascii'))

def _serial_token(prefix: str) -> str:
    return f'{prefix}-{uuid.uuid4().hex[:16].upper()}'

def _certificate_expiring_soon(certificate_pem: str | None, window_days: int) -> bool:
    if not certificate_pem:
        return True
    try:
        certificate = _load_certificate(certificate_pem)
    except ValueError:
        return True
    expires_at = certificate.not_valid_after_utc
    return expires_at <= datetime.now(timezone.utc) + timedelta(days=window_days)

def _public_key_from_certificate_pem(certificate_pem: str) -> str:
    certificate = _load_certificate(certificate_pem)
    return certificate.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')

def _certificate_file_ready(path: Path) -> bool:
    try:
        content = path.read_text(encoding='ascii')
        _load_certificate(content)
    except (OSError, ValueError):
        return False
    return True

def _private_key_file_ready(path: Path) -> bool:
    try:
        _load_private_key(path.read_text(encoding='ascii'))
    except (OSError, ValueError, TypeError):
        return False
    return True

def _build_root_certificate(root_key) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, 'ID'), x509.NameAttribute(NameOID.ORGANIZATION_NAME, INSTITUTION_NAME), x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
    return x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(root_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(_cert_not_before()).not_valid_after(_cert_not_after(CA_VALIDITY_DAYS)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False).sign(root_key, hashes.SHA256())

def _build_signer_certificate(root_key, root_certificate, signer_key) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, 'ID'), x509.NameAttribute(NameOID.ORGANIZATION_NAME, INSTITUTION_NAME), x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Academic Services'), x509.NameAttribute(NameOID.COMMON_NAME, DIGITAL_ID_NAME)])
    return x509.CertificateBuilder().subject_name(subject).issuer_name(root_certificate.subject).public_key(signer_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(_cert_not_before()).not_valid_after(_cert_not_after(DIGITAL_ID_VALIDITY_DAYS)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False).add_extension(x509.SubjectKeyIdentifier.from_public_key(signer_key.public_key()), critical=False).sign(root_key, hashes.SHA256())

def _identity_files_ready(ca, digital_id) -> bool:
    if ca is None or digital_id is None:
        return False
    certificate_path = Path(digital_id['certificate_file_path'] or SIGNER_CERT_FILE)
    if _certificate_expiring_soon(ca['ca_certificate'], CA_RENEWAL_WINDOW_DAYS):
        return False
    if _certificate_expiring_soon(digital_id['certificate_pem'], CA_RENEWAL_WINDOW_DAYS):
        return False
    return _certificate_file_ready(CA_CERT_FILE) and _certificate_file_ready(certificate_path) and _private_key_file_ready(SIGNER_KEY_FILE)

def make_signature_payload(signature_payload_hash: str, verification_code: str, ca_serial: str, digital_id_serial: str, employee_code: str='') -> bytes:
    payload = '|'.join([signature_payload_hash, verification_code, ca_serial, digital_id_serial, employee_code])
    return payload.encode('utf-8')

def ensure_ujaja_signature_asset() -> Path:
    UJAJA_DIR.mkdir(parents=True, exist_ok=True)
    source_path = SOURCE_SIGNATURE_FILE if SOURCE_SIGNATURE_FILE.exists() else BUNDLED_SIGNATURE_FILE
    if source_path.exists():
        source = Image.open(source_path).convert('RGBA')
        padding = 18
        image = Image.new('RGBA', (source.width + padding * 2, source.height + padding * 2), (255, 255, 255, 0))
        image.alpha_composite(source, (padding, padding))
        image.save(UJAJA_SIGNATURE_FILE, format='PNG')
        return UJAJA_SIGNATURE_FILE
    if UJAJA_SIGNATURE_FILE.exists():
        return UJAJA_SIGNATURE_FILE
    image = Image.new('RGBA', (760, 260), (255, 255, 255, 0))
    draw = ImageDraw.Draw(image)
    blue = (37, 99, 235, 255)
    red = (185, 28, 28, 255)
    dark = (17, 24, 39, 255)
    draw.rounded_rectangle((26, 26, 734, 234), radius=18, outline=blue, width=7)
    draw.line((80, 154, 250, 82, 355, 172, 520, 90), fill=dark, width=10)
    draw.line((98, 192, 525, 192), fill=dark, width=4)
    draw.ellipse((565, 54, 690, 179), outline=red, width=7)
    draw.text((584, 92), 'Ujaja', fill=red)
    draw.text((584, 128), 'CA', fill=red)
    try:
        font = ImageFont.truetype('arial.ttf', 30)
        small_font = ImageFont.truetype('arial.ttf', 18)
    except OSError:
        font = ImageFont.load_default()
        small_font = ImageFont.load_default()
    draw.text((70, 42), 'Universitas Jaya Jaya', fill=blue, font=font)
    draw.text((70, 214), 'Academic Digital Signature', fill=blue, font=small_font)
    image.save(UJAJA_SIGNATURE_FILE, format='PNG')
    return UJAJA_SIGNATURE_FILE

def get_ujaja_signature_path() -> Path:
    return ensure_ujaja_signature_asset()

def ensure_ujaja_identity() -> None:
    CA_DIR.mkdir(parents=True, exist_ok=True)
    UJAJA_DIR.mkdir(parents=True, exist_ok=True)
    ensure_ujaja_signature_asset()
    with get_connection() as conn:
        ca = conn.execute('SELECT * FROM ujaja_ca WHERE serial_number = ?', (CA_SERIAL,)).fetchone()
        digital_id = conn.execute('SELECT * FROM ujaja_digital_ids WHERE serial_number = ?', (DIGITAL_ID_SERIAL,)).fetchone()
        if _identity_files_ready(ca, digital_id):
            private_key_pem = digital_id['private_key']
            if not SIGNER_KEY_FILE.exists():
                SIGNER_KEY_FILE.write_text(private_key_pem, encoding='ascii')
            restrict_private_path(SIGNER_KEY_FILE)
            return
        has_db_certs = False
        try:
            if ca and digital_id and ('ca_certificate' in ca.keys()) and ca['ca_certificate'] and ('certificate_pem' in digital_id.keys()) and digital_id['certificate_pem']:
                has_db_certs = True
        except (AttributeError, KeyError, TypeError):
            pass
        if has_db_certs:
            CA_CERT_FILE.write_text(ca['ca_certificate'], encoding='ascii')
            signer_cert_path = Path(digital_id['certificate_file_path'] or SIGNER_CERT_FILE)
            signer_cert_path.write_text(digital_id['certificate_pem'], encoding='ascii')
            SIGNER_KEY_FILE.write_text(digital_id['private_key'], encoding='ascii')
            restrict_private_path(SIGNER_KEY_FILE)
            return
        root_key = _load_private_key(ca['ca_private_key']) if ca and ca['ca_private_key'] else _generate_private_key()
        signer_key = _load_private_key(digital_id['private_key']) if digital_id and digital_id['private_key'] else _generate_private_key()
        root_certificate = _build_root_certificate(root_key)
        signer_certificate = _build_signer_certificate(root_key, root_certificate, signer_key)
        root_certificate_pem = _certificate_pem(root_certificate)
        signer_certificate_pem = _certificate_pem(signer_certificate)
        private_pem = _private_key_pem(signer_key)
        public_pem = root_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')
        root_private_pem = _private_key_pem(root_key)
        CA_CERT_FILE.write_text(root_certificate_pem, encoding='ascii')
        SIGNER_CERT_FILE.write_text(signer_certificate_pem, encoding='ascii')
        SIGNER_KEY_FILE.write_text(private_pem, encoding='ascii')
        restrict_private_path(SIGNER_KEY_FILE)
        if ca:
            conn.execute("\n                UPDATE ujaja_ca\n                SET institution_name = ?,\n                    ca_name = ?,\n                    public_key = ?,\n                    ca_file_path = ?,\n                    status = 'Active',\n                    expired_at = ?,\n                    revoked_at = NULL,\n                    ca_certificate = ?,\n                    ca_private_key = ?\n                WHERE serial_number = ?\n                ", (INSTITUTION_NAME, CA_NAME, public_pem, str(CA_CERT_FILE), _expires_at(CA_VALIDITY_DAYS), root_certificate_pem, root_private_pem, CA_SERIAL))
        else:
            conn.execute("\n                INSERT INTO ujaja_ca (\n                    institution_name, ca_name, serial_number, public_key,\n                    ca_file_path, status, issued_at, expired_at, ca_certificate, ca_private_key\n                )\n                VALUES (?, ?, ?, ?, ?, 'Active', ?, ?, ?, ?)\n                ", (INSTITUTION_NAME, CA_NAME, CA_SERIAL, public_pem, str(CA_CERT_FILE), _now(), _expires_at(CA_VALIDITY_DAYS), root_certificate_pem, root_private_pem))
        if digital_id:
            conn.execute("\n                UPDATE ujaja_digital_ids\n                SET institution_name = ?,\n                    digital_id_name = ?,\n                    certificate_file_path = ?,\n                    private_key = ?,\n                    ca_serial_number = ?,\n                    status = 'Active',\n                    expired_at = ?,\n                    revoked_at = NULL,\n                    certificate_pem = ?\n                WHERE serial_number = ?\n                ", (INSTITUTION_NAME, DIGITAL_ID_NAME, str(SIGNER_CERT_FILE), private_pem, CA_SERIAL, _expires_at(), signer_certificate_pem, DIGITAL_ID_SERIAL))
        else:
            conn.execute("\n                INSERT INTO ujaja_digital_ids (\n                    institution_name, digital_id_name, serial_number,\n                    certificate_file_path, private_key, ca_serial_number,\n                    status, issued_at, expired_at, certificate_pem\n                )\n                VALUES (?, ?, ?, ?, ?, ?, 'Active', ?, ?, ?)\n                ", (INSTITUTION_NAME, DIGITAL_ID_NAME, DIGITAL_ID_SERIAL, str(SIGNER_CERT_FILE), private_pem, CA_SERIAL, _now(), _expires_at(), signer_certificate_pem))

def _role_code(role: str | None) -> str:
    role = (role or 'civitas').strip().lower()
    mapping = {'dosen': 'DOSEN', 'mahasiswa': 'MHS', 'dekanat': 'DEKANAT', 'staf': 'STAF'}
    return mapping.get(role, 'CIVITAS')

def _fetch_employee(conn, employee_id: int):
    return conn.execute('\n        SELECT employees.*, users.name, users.email\n        FROM employees\n        JOIN users ON users.id = employees.user_id\n        WHERE employees.id = ?\n        ', (employee_id,)).fetchone()

def _unique_digital_id_serial(conn, role: str | None) -> str:
    prefix = f'Ujaja-DID-{_role_code(role)}'
    while True:
        serial = _serial_token(prefix)
        exists = conn.execute('SELECT 1 FROM ujaja_digital_ids WHERE serial_number = ?', (serial,)).fetchone()
        if not exists:
            return serial

def _write_employee_identity_files(employee_id: int, private_key_pem: str, certificate_pem: str) -> tuple[Path, Path]:
    CA_DIR.mkdir(parents=True, exist_ok=True)
    restrict_private_path(CA_DIR)
    key_path = get_ujaja_employee_signer_key_path(employee_id)
    cert_path = get_ujaja_employee_signer_certificate_path(employee_id)
    key_path.write_text(private_key_pem, encoding='ascii')
    cert_path.write_text(certificate_pem, encoding='ascii')
    restrict_private_path(key_path)
    return (key_path, cert_path)

def request_civitas_digital_id(employee_id: int, role: str, passphrase: str):
    ensure_ujaja_identity()
    role = (role or '').strip()
    if role not in {'Dosen', 'Mahasiswa', 'Dekanat', 'Staf'}:
        raise ValueError('Role Digital ID tidak valid.')
    if len(passphrase or '') < 8:
        raise ValueError('Passphrase minimal 8 karakter.')
    with get_connection() as conn:
        employee = _fetch_employee(conn, employee_id)
        if employee is None:
            raise ValueError('Data civitas/pegawai tidak ditemukan.')
        conn.execute("\n            UPDATE ujaja_digital_ids\n            SET status = 'Superseded',\n                is_approved = 0,\n                is_ready = 0,\n                is_sent = 0\n            WHERE employee_id = ? AND status = 'Pending'\n            ", (employee_id,))
        serial_number = _serial_token('Ujaja-REQ-DID')
        now_time = _now()
        cursor = conn.execute("\n            INSERT INTO ujaja_digital_ids (\n                institution_name, digital_id_name, serial_number,\n                private_key, ca_serial_number, status, issued_at,\n                employee_id, is_approved, is_ready, is_sent, is_revoked,\n                passphrase, passphrase_hash, role\n            )\n            VALUES (?, ?, ?, '', ?, 'Pending', ?, ?, 0, 0, 0, 0, NULL, ?, ?)\n            ", (INSTITUTION_NAME, employee['name'], serial_number, CA_SERIAL, now_time, employee_id, hash_secret(passphrase), role))
        request_id = int(cursor.lastrowid)
    log_action(employee['user_id'], 'REQUEST_DIGITAL_ID', f'Request Digital ID {serial_number} diajukan untuk role {role}.')
    with get_connection() as conn:
        return conn.execute('SELECT * FROM ujaja_digital_ids WHERE id = ?', (request_id,)).fetchone()

def approve_civitas_digital_id_request(request_id: int, admin_user_id: int | None=None):
    ensure_ujaja_identity()
    with get_connection() as conn:
        request_row = conn.execute("SELECT * FROM ujaja_digital_ids WHERE id = ? AND status = 'Pending'", (request_id,)).fetchone()
        if request_row is None:
            raise ValueError('Request Digital ID tidak ditemukan atau bukan status Pending.')
        ca = conn.execute("SELECT * FROM ujaja_ca WHERE serial_number = ? AND status = 'Active'", (CA_SERIAL,)).fetchone()
        if ca is None or not ca['ca_private_key']:
            raise ValueError('Root CA Ujaja tidak aktif atau kunci privat tidak ditemukan.')
        employee = _fetch_employee(conn, request_row['employee_id'])
        if employee is None:
            raise ValueError('Data civitas/pegawai tidak ditemukan.')
        ca_private_key = _load_private_key(ca['ca_private_key'])
        ca_cert = _load_certificate(ca['ca_certificate'])
        emp_key = _generate_private_key()
        emp_private_pem = _private_key_pem(emp_key)
        subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, 'ID'), x509.NameAttribute(NameOID.ORGANIZATION_NAME, INSTITUTION_NAME), x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, employee['department']), x509.NameAttribute(NameOID.COMMON_NAME, employee['name']), x509.NameAttribute(NameOID.EMAIL_ADDRESS, employee['academic_email']), x509.NameAttribute(NameOID.SERIAL_NUMBER, employee['employee_id'])])
        emp_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(emp_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(_cert_not_before()).not_valid_after(_cert_not_after(DIGITAL_ID_VALIDITY_DAYS)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()), critical=False).add_extension(x509.SubjectKeyIdentifier.from_public_key(emp_key.public_key()), critical=False).sign(ca_private_key, hashes.SHA256())
        emp_cert_pem = _certificate_pem(emp_cert)
        key_path, cert_path = _write_employee_identity_files(employee['id'], emp_private_pem, emp_cert_pem)
        serial_number = _unique_digital_id_serial(conn, request_row['role'])
        expires = _expires_at()
        conn.execute("\n            UPDATE ujaja_digital_ids\n            SET status = 'Superseded'\n            WHERE employee_id = ? AND status = 'Active' AND id != ?\n            ", (employee['id'], request_row['id']))
        conn.execute("\n            UPDATE ujaja_digital_ids\n            SET serial_number = ?,\n                certificate_file_path = ?,\n                private_key = ?,\n                ca_serial_number = ?,\n                status = 'Active',\n                issued_at = ?,\n                expired_at = ?,\n                revoked_at = NULL,\n                certificate_pem = ?,\n                is_approved = 1,\n                is_ready = 1,\n                is_sent = 1,\n                is_revoked = 0\n            WHERE id = ?\n            ", (serial_number, str(cert_path), emp_private_pem, CA_SERIAL, _now(), expires, emp_cert_pem, request_row['id']))
    log_action(admin_user_id, 'APPROVE_DIGITAL_ID', f"Digital ID {serial_number} diterbitkan untuk {employee['name']} ({employee['employee_id']}).")
    with get_connection() as conn:
        return conn.execute('SELECT * FROM ujaja_digital_ids WHERE serial_number = ?', (serial_number,)).fetchone()

def reject_civitas_digital_id_request(request_id: int, reason: str, admin_user_id: int | None=None) -> None:
    reason = (reason or '').strip()
    if not reason:
        raise ValueError('Alasan penolakan tidak boleh kosong.')
    with get_connection() as conn:
        request_row = conn.execute("SELECT * FROM ujaja_digital_ids WHERE id = ? AND status = 'Pending'", (request_id,)).fetchone()
        if request_row is None:
            raise ValueError('Request Digital ID tidak ditemukan atau bukan status Pending.')
        conn.execute("\n            UPDATE ujaja_digital_ids\n            SET status = 'Rejected',\n                is_approved = 0,\n                is_ready = 0,\n                is_sent = 0\n            WHERE id = ?\n            ", (request_id,))
    log_action(admin_user_id, 'REJECT_DIGITAL_ID', f"Digital ID request {request_row['serial_number']} ditolak. Alasan: {reason}")

def get_latest_active_civitas_digital_id(employee_id: int):
    with get_connection() as conn:
        return conn.execute("\n            SELECT * FROM ujaja_digital_ids\n            WHERE employee_id = ? AND status = 'Active'\n            ORDER BY issued_at DESC, id DESC\n            LIMIT 1\n            ", (employee_id,)).fetchone()

def ensure_civitas_digital_id(employee_id: int):
    did = get_latest_active_civitas_digital_id(employee_id)
    if did is None:
        raise ValueError('Digital ID belum aktif. Ajukan request dan tunggu approval Dekanat/CA.')
    if did['private_key'] and did['certificate_pem']:
        _write_employee_identity_files(employee_id, did['private_key'], did['certificate_pem'])
    return did

def get_ujaja_employee_signer_key_path(employee_id: int) -> Path:
    return CA_DIR / f'ujaja_employee_{employee_id}_signer_key.pem'

def get_ujaja_employee_signer_certificate_path(employee_id: int) -> Path:
    return CA_DIR / f'ujaja_employee_{employee_id}_signer.crt'

def get_ujaja_ca():
    ensure_ujaja_identity()
    with get_connection() as conn:
        return conn.execute('SELECT * FROM ujaja_ca WHERE serial_number = ?', (CA_SERIAL,)).fetchone()

def get_ujaja_digital_id():
    ensure_ujaja_identity()
    with get_connection() as conn:
        return conn.execute('SELECT * FROM ujaja_digital_ids WHERE serial_number = ?', (DIGITAL_ID_SERIAL,)).fetchone()

def get_active_ujaja_ca():
    ca = get_ujaja_ca()
    return ca if ca and ca['status'] == 'Active' else None

def get_ca_health() -> dict:
    ensure_ujaja_identity()
    ca = get_ujaja_ca()
    if ca is None:
        return {'status': 'Missing', 'serial_number': None, 'expires_at': None, 'days_remaining': 0, 'auto_renew_window_days': CA_RENEWAL_WINDOW_DAYS, 'private_key_present': False}
    try:
        certificate = _load_certificate(ca['ca_certificate'])
        expires_at = certificate.not_valid_after_utc
        days_remaining = max(0, (expires_at - datetime.now(timezone.utc)).days)
        expires_text = expires_at.isoformat(timespec='seconds')
    except (ValueError, TypeError):
        days_remaining = 0
        expires_text = ca['expired_at']
    return {'status': ca['status'], 'serial_number': ca['serial_number'], 'expires_at': expires_text, 'days_remaining': days_remaining, 'auto_renew_window_days': CA_RENEWAL_WINDOW_DAYS, 'private_key_present': bool(ca['ca_private_key'])}

def check_certificate_expiration() -> dict:
    """Check if CA or SSL certificates are expired. Returns blocking status."""
    from web_runtime.web_ssl import LOCALHOST_CERT_FILE, _load_cert
    now = datetime.now(timezone.utc)
    ca_expired = True
    ca_expires_at = None
    ca = get_ujaja_ca()
    if ca:
        ca_dict = dict(ca)
        if ca_dict.get('ca_certificate'):
            try:
                cert = _load_certificate(ca_dict['ca_certificate'])
                ca_expires_at = cert.not_valid_after_utc.isoformat(timespec='seconds')
                ca_expired = cert.not_valid_after_utc <= now
            except (ValueError, TypeError):
                ca_expired = True
    ssl_expired = True
    ssl_expires_at = None
    ssl_cert = _load_cert(LOCALHOST_CERT_FILE) if LOCALHOST_CERT_FILE.exists() else None
    if ssl_cert is not None:
        ssl_expires_at = ssl_cert.not_valid_after_utc.isoformat(timespec='seconds')
        ssl_expired = ssl_cert.not_valid_after_utc <= now
    blocked = ca_expired or ssl_expired
    return {'ca_expired': ca_expired, 'ssl_expired': ssl_expired, 'ca_expires_at': ca_expires_at, 'ssl_expires_at': ssl_expires_at, 'blocked': blocked}

def check_digital_id_expiration(employee_id: int) -> dict:
    """Check if a civitas Digital ID certificate is expired."""
    now = datetime.now(timezone.utc)
    did = get_latest_active_civitas_digital_id(employee_id)
    if did is None:
        return {'expired': True, 'expires_at': None, 'reason': 'Digital ID tidak ditemukan.'}
    did_dict = dict(did)
    if did_dict.get('certificate_pem'):
        try:
            cert = _load_certificate(did_dict['certificate_pem'])
            expires_at = cert.not_valid_after_utc
            if expires_at <= now:
                return {'expired': True, 'expires_at': expires_at.isoformat(timespec='seconds'), 'reason': f"Sertifikat Digital ID kedaluwarsa sejak {expires_at.strftime('%d/%m/%Y %H:%M')} UTC."}
            return {'expired': False, 'expires_at': expires_at.isoformat(timespec='seconds'), 'reason': None}
        except (ValueError, TypeError):
            return {'expired': True, 'expires_at': None, 'reason': 'Sertifikat Digital ID tidak bisa dibaca.'}
    if did_dict.get('expired_at'):
        try:
            expires_at = datetime.fromisoformat(did_dict['expired_at'])
            if expires_at.tzinfo is None:
                from datetime import timezone as tz
                expires_at = expires_at.replace(tzinfo=tz.utc)
            if expires_at <= now:
                return {'expired': True, 'expires_at': did_dict['expired_at'], 'reason': f"Sertifikat Digital ID kedaluwarsa sejak {did_dict['expired_at']}."}
            return {'expired': False, 'expires_at': did_dict['expired_at'], 'reason': None}
        except (ValueError, TypeError):
            pass
    return {'expired': False, 'expires_at': None, 'reason': None}

def get_active_ujaja_digital_id():
    digital_id = get_ujaja_digital_id()
    return digital_id if digital_id and digital_id['status'] == 'Active' else None

def get_ujaja_ca_certificate_path() -> Path:
    ensure_ujaja_identity()
    return CA_CERT_FILE

def get_ujaja_signer_certificate_path() -> Path:
    ensure_ujaja_identity()
    return SIGNER_CERT_FILE

def get_ujaja_signer_key_path() -> Path:
    ensure_ujaja_identity()
    return SIGNER_KEY_FILE

def get_ujaja_digital_id_public_key_pem() -> str:
    ensure_ujaja_identity()
    certificate_pem = SIGNER_CERT_FILE.read_text(encoding='ascii')
    return _public_key_from_certificate_pem(certificate_pem)

def get_ujaja_employee_public_key_pem(employee_id: int, serial_number: str | None=None) -> str:
    with get_connection() as conn:
        if serial_number:
            did = conn.execute('\n                SELECT certificate_pem FROM ujaja_digital_ids\n                WHERE employee_id = ? AND serial_number = ?\n                ', (employee_id, serial_number)).fetchone()
            if did and did['certificate_pem']:
                return _public_key_from_certificate_pem(did['certificate_pem'])
        did = conn.execute("\n            SELECT certificate_pem FROM ujaja_digital_ids\n            WHERE employee_id = ? AND status = 'Active'\n            ORDER BY issued_at DESC, id DESC\n            LIMIT 1\n            ", (employee_id,)).fetchone()
        if did and did['certificate_pem']:
            return _public_key_from_certificate_pem(did['certificate_pem'])
    return ''

def sign_payload(signature_payload_hash: str, verification_code: str, ca_serial: str, digital_id_serial: str, employee_code: str='', employee_id: int=None) -> str:
    if employee_id is not None:
        with get_connection() as conn:
            digital_id = conn.execute("\n                SELECT * FROM ujaja_digital_ids\n                WHERE employee_id = ? AND status = 'Active'\n                ORDER BY issued_at DESC, id DESC\n                LIMIT 1\n                ", (employee_id,)).fetchone()
    else:
        digital_id = get_active_ujaja_digital_id()
    if digital_id is None:
        raise ValueError('Digital ID Ujaja tidak aktif.')
    private_key = _load_private_key(digital_id['private_key'])
    signature = private_key.sign(make_signature_payload(signature_payload_hash, verification_code, ca_serial, digital_id_serial, employee_code), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return b64encode(signature).decode('ascii')

def verify_payload_signature(signature_payload_hash: str, verification_code: str, ca_serial: str, digital_id_serial: str, signature_value: str, public_key_pem: str, employee_code: str='') -> bool:
    try:
        public_key = _load_public_key(public_key_pem)
        public_key.verify(b64decode(signature_value), make_signature_payload(signature_payload_hash, verification_code, ca_serial, digital_id_serial, employee_code), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True

def export_ujaja_employee_p12(employee_id: int, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.serialization import pkcs12
    with get_connection() as conn:
        did = conn.execute("\n            SELECT * FROM ujaja_digital_ids\n            WHERE employee_id = ? AND status = 'Active'\n            ORDER BY issued_at DESC, id DESC\n            LIMIT 1\n            ", (employee_id,)).fetchone()
        ca = conn.execute('SELECT * FROM ujaja_ca WHERE serial_number = ?', (CA_SERIAL,)).fetchone()
    if did is None or ca is None:
        raise ValueError('Digital ID atau CA tidak aktif.')
    private_key = _load_private_key(did['private_key'])
    certificate = _load_certificate(did['certificate_pem'])
    ca_certificate = _load_certificate(ca['ca_certificate'])
    p12_bytes = pkcs12.serialize_key_and_certificates(name=did['digital_id_name'].encode('utf-8'), key=private_key, cert=certificate, cas=[ca_certificate], encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8')))
    return p12_bytes