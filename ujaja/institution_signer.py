from datetime import datetime
from io import BytesIO
from pathlib import Path
import re
import uuid

import qrcode
from pypdf import PdfReader, PdfWriter
from reportlab.lib.colors import HexColor, white
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from core.audit import log_action
from ujaja.acrobat_signature import apply_acrobat_signature
from ujaja.ca_service import (
    CA_SERIAL,
    INSTITUTION_NAME,
    DIGITAL_ID_SERIAL,
    ensure_ujaja_identity,
    get_active_ujaja_ca,
    get_active_ujaja_digital_id,
    get_ujaja_digital_id_public_key_pem,
    get_ujaja_digital_id,
    get_ujaja_signature_path,
    sign_payload,
    verify_payload_signature,
)
from core.database import SIGNED_DOCS_DIR, TEMP_DIR, get_connection
from ujaja.civitas_service import validate_active_civitas
from core.otp_service import verify_code
from self_signed.pdf_signer import file_sha256


CODE_PATTERN = re.compile(r"Ujaja-[A-F0-9]{12}")
POSITION_OPTIONS = {
    "kanan bawah": "kanan bawah",
    "kiri bawah": "kiri bawah",
    "kanan atas": "kanan atas",
    "kiri atas": "kiri atas",
}


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._")
    return cleaned or "document"


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _unique_verification_code() -> str:
    with get_connection() as conn:
        while True:
            code = f"Ujaja-{uuid.uuid4().hex[:12].upper()}"
            exists = conn.execute(
                "SELECT 1 FROM ujaja_sign_requests WHERE verification_code = ?",
                (code,),
            ).fetchone()
            if not exists:
                return code


def _qr_image_reader(verification_code: str) -> ImageReader:
    img = qrcode.make(f"Ujaja Academic Verification: {verification_code}")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return ImageReader(buffer)


def _block_position(
    page_width: float,
    page_height: float,
    block_width: float,
    block_height: float,
    position: str,
):
    margin = 36
    if position == "kiri bawah":
        return margin, margin
    if position == "kanan atas":
        return page_width - margin - block_width, page_height - margin - block_height
    if position == "kiri atas":
        return margin, page_height - margin - block_height
    return page_width - margin - block_width, margin


def _build_overlay(
    page_width: float,
    page_height: float,
    civitas,
    verification_code: str,
    signed_at: str,
    position: str,
) -> BytesIO:
    packet = BytesIO()
    c = canvas.Canvas(packet, pagesize=(page_width, page_height))

    block_width = min(340, max(260, page_width - 72))
    block_height = 144
    x, y = _block_position(page_width, page_height, block_width, block_height, position)

    c.setFillColor(white)
    c.setStrokeColor(HexColor("#1d4ed8"))
    c.roundRect(x, y, block_width, block_height, 6, stroke=1, fill=1)

    signature_reader = ImageReader(str(get_ujaja_signature_path()))
    c.drawImage(
        signature_reader,
        x + 10,
        y + 72,
        width=150,
        height=52,
        preserveAspectRatio=True,
        mask="auto",
    )

    qr_size = 66
    c.drawImage(
        _qr_image_reader(verification_code),
        x + block_width - qr_size - 10,
        y + 24,
        width=qr_size,
        height=qr_size,
        mask="auto",
    )

    text_x = x + 10
    c.setFillColor(HexColor("#111827"))
    c.setFont("Helvetica-Bold", 8)
    c.drawString(text_x, y + 62, "Digitally Signed by:")

    c.setFont("Helvetica-Bold", 10)
    c.drawString(text_x, y + 49, _truncate(INSTITUTION_NAME, 29))

    c.setFont("Helvetica", 8)
    c.drawString(text_x, y + 38, f"Operator: {_truncate(civitas['name'], 27)}")
    c.drawString(text_x, y + 27, f"Civitas ID: {civitas['employee_id']}")
    c.drawString(text_x, y + 16, f"Role: {_truncate(civitas['position'], 32)}")
    c.drawString(text_x, y + 5, f"Verification Code: {verification_code}")
    c.drawString(x + block_width - 134, y + 7, f"Date: {signed_at[:19]}")

    c.save()
    packet.seek(0)
    return packet


def _write_institution_pdf(
    source: Path,
    output_path: Path,
    civitas,
    verification_code: str,
    signed_at: str,
    position: str,
    metadata_extra: dict[str, str],
) -> None:
    reader = PdfReader(str(source))
    if reader.is_encrypted:
        raise ValueError("PDF terenkripsi tidak didukung untuk MVP.")
    if not reader.pages:
        raise ValueError("PDF tidak memiliki halaman.")

    last_page = reader.pages[-1]
    page_width = float(last_page.mediabox.width)
    page_height = float(last_page.mediabox.height)
    overlay_reader = PdfReader(
        _build_overlay(page_width, page_height, civitas, verification_code, signed_at, position)
    )

    writer = PdfWriter()
    for index, page in enumerate(reader.pages):
        if index == len(reader.pages) - 1:
            page.merge_page(overlay_reader.pages[0])
        writer.add_page(page)

    metadata = {
        "/Producer": "Ujaja Sign",
        "/UjajaSignMode": "institution",
        "/UjajaSignInstitution": INSTITUTION_NAME,
        "/UjajaSignSigner": INSTITUTION_NAME,
        "/UjajaSignOperator": civitas["name"],
        "/UjajaSignOperatorEmail": civitas["email"],
        "/UjajaSignCode": verification_code,
        "/UjajaSignCivitasId": civitas["employee_id"],
        "/UjajaSignCASerial": CA_SERIAL,
        "/UjajaSignDigitalIdSerial": DIGITAL_ID_SERIAL,
        "/UjajaSignSignedAt": signed_at,
    }
    metadata.update(metadata_extra)
    writer.add_metadata(metadata)

    with open(output_path, "wb") as output_file:
        writer.write(output_file)


def sign_institution_pdf(
    user,
    input_pdf_path: str,
    otp_code: str,
    position: str = "kanan bawah",
) -> dict:
    ensure_ujaja_identity()
    source = Path(input_pdf_path)
    position = POSITION_OPTIONS.get(position, "kanan bawah")

    if not source.exists():
        raise ValueError("File PDF tidak ditemukan.")
    if source.suffix.lower() != ".pdf":
        raise ValueError("File input harus PDF.")
    if not verify_code(user["id"], otp_code):
        raise ValueError("Kode OTP salah atau kedaluwarsa.")

    civitas = validate_active_civitas(user["id"])
    ca = get_active_ujaja_ca()
    if ca is None:
        raise ValueError("CA Ujaja tidak aktif.")

    digital_id = get_active_ujaja_digital_id()
    if digital_id is None:
        raise ValueError("Digital ID Ujaja tidak aktif.")

    original_hash = file_sha256(source)
    verification_code = _unique_verification_code()
    signed_at = datetime.now().isoformat(timespec="seconds")

    SIGNED_DOCS_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    output_name = f"{_safe_name(source.stem)}_{verification_code}_institution.pdf"
    output_path = SIGNED_DOCS_DIR / output_name
    unsigned_path = TEMP_DIR / f"{verification_code}_payload.pdf"
    prepared_path = TEMP_DIR / f"{verification_code}_prepared.pdf"

    try:
        _write_institution_pdf(
            source,
            unsigned_path,
            civitas,
            verification_code,
            signed_at,
            position,
            metadata_extra={},
        )
        signature_payload_hash = file_sha256(unsigned_path)
        signature_value = sign_payload(
            signature_payload_hash,
            verification_code,
            ca["serial_number"],
            digital_id["serial_number"],
        )
        _write_institution_pdf(
            source,
            prepared_path,
            civitas,
            verification_code,
            signed_at,
            position,
            metadata_extra={
                "/UjajaSignPayloadHash": signature_payload_hash,
                "/UjajaSignSignatureValue": signature_value,
            },
        )
        apply_acrobat_signature(prepared_path, output_path, verification_code)
    finally:
        if unsigned_path.exists():
            unsigned_path.unlink()
        if prepared_path.exists():
            prepared_path.unlink()

    signed_hash = file_sha256(output_path)
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO ujaja_sign_requests (
                employee_id, original_file_path, signed_file_path,
                original_hash, signature_payload_hash, signed_hash,
                verification_code, signature_position, ca_serial_number,
                ujaja_digital_id_serial, signature_value, status, signed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Signed', ?)
            """,
            (
                civitas["id"],
                str(source),
                str(output_path),
                original_hash,
                signature_payload_hash,
                signed_hash,
                verification_code,
                position,
                ca["serial_number"],
                digital_id["serial_number"],
                signature_value,
                signed_at,
            ),
        )

    log_action(
        user["id"],
        "INSTITUTION_SIGN_PDF",
        f"Dokumen {source.name} ditandatangani oleh {INSTITUTION_NAME}; operator {user['name']} ({verification_code}).",
    )
    return {
        "output_path": output_path,
        "verification_code": verification_code,
        "signed_at": signed_at,
        "signed_hash": signed_hash,
        "signature_value": signature_value,
    }


def extract_institution_verification_code(pdf_path: str | Path) -> str | None:
    path = Path(pdf_path)
    if not path.exists() or path.suffix.lower() != ".pdf":
        return None

    try:
        reader = PdfReader(str(path))
    except Exception:
        return None

    metadata = reader.metadata or {}
    for key in ("/UjajaSignCode", "UjajaSignCode"):
        value = metadata.get(key)
        if value:
            match = CODE_PATTERN.search(str(value))
            if match:
                return match.group(0)

    for page in reader.pages:
        try:
            text = page.extract_text() or ""
        except Exception:
            continue
        match = CODE_PATTERN.search(text)
        if match:
            return match.group(0)
    return None


def _read_metadata(pdf_path: Path) -> dict:
    try:
        reader = PdfReader(str(pdf_path))
    except Exception:
        return {}
    metadata = reader.metadata or {}
    return {str(key).lstrip("/"): str(value) for key, value in metadata.items()}


def _log_institution_verification(code: str | None, result: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO verification_logs (document_id, verification_code, result)
            VALUES (NULL, ?, ?)
            """,
            (code, result),
        )


def verify_institution_pdf(pdf_path: str | Path) -> dict:
    path = Path(pdf_path)
    if not path.exists():
        return {"valid": False, "reason": "File tidak ditemukan.", "code": None}
    if path.suffix.lower() != ".pdf":
        return {"valid": False, "reason": "File harus PDF.", "code": None}

    code = extract_institution_verification_code(path)
    if not code:
        _log_institution_verification(None, "invalid:no_code")
        return {
            "valid": False,
            "reason": "Kode verifikasi akademik tidak ditemukan.",
            "code": None,
        }

    metadata = _read_metadata(path)
    if metadata.get("UjajaSignMode") != "institution":
        _log_institution_verification(code, "invalid:not_institution")
        return {
            "valid": False,
            "reason": "Dokumen bukan institution-issued signature.",
            "code": code,
        }

    with get_connection() as conn:
        document = conn.execute(
            """
            SELECT
                ujaja_sign_requests.*,
                employees.employee_id AS employee_code,
                employees.department,
                employees.position,
                employees.employee_status,
                users.id AS user_id,
                users.name AS employee_name,
                users.email AS employee_email
            FROM ujaja_sign_requests
            JOIN employees ON employees.id = ujaja_sign_requests.employee_id
            JOIN users ON users.id = employees.user_id
            WHERE ujaja_sign_requests.verification_code = ?
            """,
            (code,),
        ).fetchone()

    if document is None:
        _log_institution_verification(code, "invalid:not_found")
        return {
            "valid": False,
            "reason": "Dokumen akademik tidak terdaftar di database lokal.",
            "code": code,
        }

    ca = get_active_ujaja_ca()
    if ca is None:
        _log_institution_verification(code, "invalid:ca_inactive")
        return {"valid": False, "reason": "CA Ujaja tidak aktif.", "code": code}

    digital_id = get_ujaja_digital_id()
    if digital_id is None or digital_id["status"] != "Active":
        _log_institution_verification(code, "invalid:digital_id_inactive")
        return {"valid": False, "reason": "Digital ID Ujaja tidak aktif.", "code": code}

    current_hash = file_sha256(path)
    hash_match = current_hash == document["signed_hash"]
    ca_match = document["ca_serial_number"] == ca["serial_number"] == metadata.get("UjajaSignCASerial")
    digital_id_match = (
        document["ujaja_digital_id_serial"]
        == digital_id["serial_number"]
        == metadata.get("UjajaSignDigitalIdSerial")
    )
    employee_active = document["employee_status"] == "Active"
    metadata_signature = metadata.get("UjajaSignSignatureValue")
    signature_metadata_match = metadata_signature == document["signature_value"]
    signature_valid = verify_payload_signature(
        document["signature_payload_hash"],
        document["verification_code"],
        document["ca_serial_number"],
        document["ujaja_digital_id_serial"],
        document["signature_value"],
        get_ujaja_digital_id_public_key_pem(),
    )

    valid = (
        hash_match
        and ca_match
        and digital_id_match
        and employee_active
        and signature_metadata_match
        and signature_valid
        and document["status"] == "Signed"
    )

    if valid:
        result = "valid"
        reason = "Dokumen valid menurut sistem Ujaja Sign."
    elif not hash_match:
        result = "invalid:hash_mismatch"
        reason = "Hash tidak cocok. Dokumen kemungkinan sudah berubah."
    elif not ca_match:
        result = "invalid:ca_mismatch"
        reason = "CA dokumen tidak cocok dengan CA aktif Ujaja."
    elif not digital_id_match:
        result = "invalid:digital_id_mismatch"
        reason = "Digital ID dokumen tidak cocok dengan Digital ID Ujaja."
    elif not employee_active:
        result = "invalid:employee_inactive"
        reason = "Status civitas penandatangan tidak aktif."
    elif not signature_metadata_match:
        result = "invalid:signature_metadata_mismatch"
        reason = "Signature value pada PDF tidak cocok dengan database."
    elif not signature_valid:
        result = "invalid:signature_value"
        reason = "Signature value gagal diverifikasi dengan public key CA."
    else:
        result = "invalid:document_status"
        reason = "Status dokumen tidak aktif."

    _log_institution_verification(code, result)
    log_action(document["user_id"], "VERIFY_INSTITUTION_PDF", f"Verifikasi akademik {code}: {result}.")

    return {
        "valid": valid,
        "reason": reason,
        "code": code,
        "hash_match": hash_match,
        "ca_match": ca_match,
        "digital_id_match": digital_id_match,
        "employee_active": employee_active,
        "signature_valid": signature_valid,
        "current_hash": current_hash,
        "stored_hash": document["signed_hash"],
        "signer_name": INSTITUTION_NAME,
        "institution_name": INSTITUTION_NAME,
        "operator_name": document["employee_name"],
        "operator_email": document["employee_email"],
        "employee_name": document["employee_name"],
        "employee_email": document["employee_email"],
        "employee_id": document["employee_code"],
        "department": document["department"],
        "position": document["position"],
        "signed_at": document["signed_at"],
        "ca_serial": document["ca_serial_number"],
        "digital_id_serial": document["ujaja_digital_id_serial"],
        "signed_file_path": document["signed_file_path"],
    }
