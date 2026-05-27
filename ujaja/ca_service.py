from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from PIL import Image, ImageDraw, ImageFont

from core.database import (
    BUNDLED_SOURCE_ASSETS_DIR,
    CA_DIR,
    SOURCE_ASSETS_DIR,
    UJAJA_DIR,
    get_connection,
)


INSTITUTION_NAME = "Universitas Jaya Jaya"
CA_NAME = "Ujaja Root CA"
CA_SERIAL = "Ujaja-CA-ROOT-0001"
DIGITAL_ID_NAME = "Universitas Jaya Jaya"
DIGITAL_ID_SERIAL = "Ujaja-DID-0001"
SOURCE_SIGNATURE_FILE = SOURCE_ASSETS_DIR / "ttdreval.png"
BUNDLED_SIGNATURE_FILE = BUNDLED_SOURCE_ASSETS_DIR / "ttdreval.png"
CA_CERT_FILE = CA_DIR / "ujaja_root_ca.crt"
SIGNER_KEY_FILE = CA_DIR / "ujaja_academic_signer_key.pem"
SIGNER_CERT_FILE = CA_DIR / "ujaja_academic_signer.crt"
CA_FILE = CA_CERT_FILE
UJAJA_SIGNATURE_FILE = UJAJA_DIR / "ujaja_signature.png"


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _expires_at() -> str:
    return (datetime.now() + timedelta(days=365 * 3)).isoformat(timespec="seconds")


def _cert_not_before():
    return datetime.now(timezone.utc) - timedelta(minutes=5)


def _cert_not_after():
    return datetime.now(timezone.utc) + timedelta(days=365 * 3)


def _generate_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _private_key_pem(private_key) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _public_key_pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _certificate_pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _load_private_key(private_key_pem: str):
    return serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)


def _load_public_key(public_key_pem: str):
    return serialization.load_pem_public_key(public_key_pem.encode("ascii"))


def _load_certificate(certificate_pem: str):
    return x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))


def _public_key_from_certificate_pem(certificate_pem: str) -> str:
    certificate = _load_certificate(certificate_pem)
    return certificate.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _certificate_file_ready(path: Path) -> bool:
    try:
        content = path.read_text(encoding="ascii")
        _load_certificate(content)
    except (OSError, ValueError):
        return False
    return True


def _private_key_file_ready(path: Path) -> bool:
    try:
        _load_private_key(path.read_text(encoding="ascii"))
    except (OSError, ValueError, TypeError):
        return False
    return True


def _build_root_certificate(root_key) -> x509.Certificate:
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, INSTITUTION_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_cert_not_before())
        .not_valid_after(_cert_not_after())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )


def _build_signer_certificate(root_key, root_certificate, signer_key) -> x509.Certificate:
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, INSTITUTION_NAME),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Academic Services"),
            x509.NameAttribute(NameOID.COMMON_NAME, DIGITAL_ID_NAME),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_certificate.subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_cert_not_before())
        .not_valid_after(_cert_not_after())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(signer_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )


def _identity_files_ready(ca, digital_id) -> bool:
    if ca is None or digital_id is None:
        return False
    certificate_path = Path(digital_id["certificate_file_path"] or SIGNER_CERT_FILE)
    return (
        _certificate_file_ready(CA_CERT_FILE)
        and _certificate_file_ready(certificate_path)
        and _private_key_file_ready(SIGNER_KEY_FILE)
    )


def make_signature_payload(
    signature_payload_hash: str,
    verification_code: str,
    ca_serial: str,
    digital_id_serial: str,
) -> bytes:
    payload = "|".join(
        [
            signature_payload_hash,
            verification_code,
            ca_serial,
            digital_id_serial,
        ]
    )
    return payload.encode("utf-8")


def ensure_ujaja_signature_asset() -> Path:
    UJAJA_DIR.mkdir(parents=True, exist_ok=True)
    source_path = SOURCE_SIGNATURE_FILE if SOURCE_SIGNATURE_FILE.exists() else BUNDLED_SIGNATURE_FILE
    if source_path.exists():
        source = Image.open(source_path).convert("RGBA")
        padding = 18
        image = Image.new(
            "RGBA",
            (source.width + padding * 2, source.height + padding * 2),
            (255, 255, 255, 0),
        )
        image.alpha_composite(source, (padding, padding))
        image.save(UJAJA_SIGNATURE_FILE, format="PNG")
        return UJAJA_SIGNATURE_FILE

    if UJAJA_SIGNATURE_FILE.exists():
        return UJAJA_SIGNATURE_FILE

    image = Image.new("RGBA", (760, 260), (255, 255, 255, 0))
    draw = ImageDraw.Draw(image)
    blue = (37, 99, 235, 255)
    red = (185, 28, 28, 255)
    dark = (17, 24, 39, 255)

    draw.rounded_rectangle((26, 26, 734, 234), radius=18, outline=blue, width=7)
    draw.line((80, 154, 250, 82, 355, 172, 520, 90), fill=dark, width=10)
    draw.line((98, 192, 525, 192), fill=dark, width=4)
    draw.ellipse((565, 54, 690, 179), outline=red, width=7)
    draw.text((584, 92), "Ujaja", fill=red)
    draw.text((584, 128), "CA", fill=red)

    try:
        font = ImageFont.truetype("arial.ttf", 30)
        small_font = ImageFont.truetype("arial.ttf", 18)
    except OSError:
        font = ImageFont.load_default()
        small_font = ImageFont.load_default()

    draw.text((70, 42), "Universitas Jaya Jaya", fill=blue, font=font)
    draw.text((70, 214), "Academic Digital Signature", fill=blue, font=small_font)
    image.save(UJAJA_SIGNATURE_FILE, format="PNG")
    return UJAJA_SIGNATURE_FILE


def get_ujaja_signature_path() -> Path:
    return ensure_ujaja_signature_asset()


def ensure_ujaja_identity() -> None:
    CA_DIR.mkdir(parents=True, exist_ok=True)
    UJAJA_DIR.mkdir(parents=True, exist_ok=True)
    ensure_ujaja_signature_asset()

    with get_connection() as conn:
        ca = conn.execute(
            "SELECT * FROM ujaja_ca WHERE serial_number = ?",
            (CA_SERIAL,),
        ).fetchone()
        digital_id = conn.execute(
            "SELECT * FROM ujaja_digital_ids WHERE serial_number = ?",
            (DIGITAL_ID_SERIAL,),
        ).fetchone()

        if _identity_files_ready(ca, digital_id):
            private_key_pem = digital_id["private_key"]
            if not SIGNER_KEY_FILE.exists():
                SIGNER_KEY_FILE.write_text(private_key_pem, encoding="ascii")
            return

        root_key = _generate_private_key()
        signer_key = _generate_private_key()
        root_certificate = _build_root_certificate(root_key)
        signer_certificate = _build_signer_certificate(root_key, root_certificate, signer_key)
        root_certificate_pem = _certificate_pem(root_certificate)
        signer_certificate_pem = _certificate_pem(signer_certificate)
        private_pem = _private_key_pem(signer_key)
        public_pem = _public_key_from_certificate_pem(signer_certificate_pem)

        CA_CERT_FILE.write_text(root_certificate_pem, encoding="ascii")
        SIGNER_CERT_FILE.write_text(signer_certificate_pem, encoding="ascii")
        SIGNER_KEY_FILE.write_text(private_pem, encoding="ascii")

        if ca:
            conn.execute(
                """
                UPDATE ujaja_ca
                SET institution_name = ?,
                    ca_name = ?,
                    public_key = ?,
                    ca_file_path = ?,
                    status = 'Active',
                    expired_at = ?,
                    revoked_at = NULL
                WHERE serial_number = ?
                """,
                (INSTITUTION_NAME, CA_NAME, public_pem, str(CA_CERT_FILE), _expires_at(), CA_SERIAL),
            )
        else:
            conn.execute(
                """
                INSERT INTO ujaja_ca (
                    institution_name, ca_name, serial_number, public_key,
                    ca_file_path, status, issued_at, expired_at
                )
                VALUES (?, ?, ?, ?, ?, 'Active', ?, ?)
                """,
                (INSTITUTION_NAME, CA_NAME, CA_SERIAL, public_pem, str(CA_CERT_FILE), _now(), _expires_at()),
            )

        if digital_id:
            conn.execute(
                """
                UPDATE ujaja_digital_ids
                SET institution_name = ?,
                    digital_id_name = ?,
                    certificate_file_path = ?,
                    private_key = ?,
                    ca_serial_number = ?,
                    status = 'Active',
                    expired_at = ?,
                    revoked_at = NULL
                WHERE serial_number = ?
                """,
                (
                    INSTITUTION_NAME,
                    DIGITAL_ID_NAME,
                    str(SIGNER_CERT_FILE),
                    private_pem,
                    CA_SERIAL,
                    _expires_at(),
                    DIGITAL_ID_SERIAL,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO ujaja_digital_ids (
                    institution_name, digital_id_name, serial_number,
                    certificate_file_path, private_key, ca_serial_number,
                    status, issued_at, expired_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 'Active', ?, ?)
                """,
                (
                    INSTITUTION_NAME,
                    DIGITAL_ID_NAME,
                    DIGITAL_ID_SERIAL,
                    str(SIGNER_CERT_FILE),
                    private_pem,
                    CA_SERIAL,
                    _now(),
                    _expires_at(),
                ),
            )


def get_ujaja_ca():
    ensure_ujaja_identity()
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM ujaja_ca WHERE serial_number = ?",
            (CA_SERIAL,),
        ).fetchone()


def get_ujaja_digital_id():
    ensure_ujaja_identity()
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM ujaja_digital_ids WHERE serial_number = ?",
            (DIGITAL_ID_SERIAL,),
        ).fetchone()


def get_active_ujaja_ca():
    ca = get_ujaja_ca()
    return ca if ca and ca["status"] == "Active" else None


def get_active_ujaja_digital_id():
    digital_id = get_ujaja_digital_id()
    return digital_id if digital_id and digital_id["status"] == "Active" else None


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
    certificate_pem = SIGNER_CERT_FILE.read_text(encoding="ascii")
    return _public_key_from_certificate_pem(certificate_pem)


def sign_payload(
    signature_payload_hash: str,
    verification_code: str,
    ca_serial: str,
    digital_id_serial: str,
) -> str:
    digital_id = get_active_ujaja_digital_id()
    if digital_id is None:
        raise ValueError("Digital ID Ujaja tidak aktif.")

    private_key = _load_private_key(digital_id["private_key"])
    signature = private_key.sign(
        make_signature_payload(signature_payload_hash, verification_code, ca_serial, digital_id_serial),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return b64encode(signature).decode("ascii")


def verify_payload_signature(
    signature_payload_hash: str,
    verification_code: str,
    ca_serial: str,
    digital_id_serial: str,
    signature_value: str,
    public_key_pem: str,
) -> bool:
    try:
        public_key = _load_public_key(public_key_pem)
        public_key.verify(
            b64decode(signature_value),
            make_signature_payload(signature_payload_hash, verification_code, ca_serial, digital_id_serial),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
