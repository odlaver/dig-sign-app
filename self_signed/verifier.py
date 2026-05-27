from pathlib import Path
import re

from pypdf import PdfReader

from core.audit import log_action
from core.database import get_connection
from self_signed.pdf_signer import file_sha256


CODE_PATTERN = re.compile(r"SS-[A-F0-9]{12}")


def extract_verification_code(pdf_path: str | Path) -> str | None:
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


def _log_verification(document_id: int | None, code: str | None, result: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO verification_logs (document_id, verification_code, result)
            VALUES (?, ?, ?)
            """,
            (document_id, code, result),
        )


def verify_pdf(pdf_path: str | Path) -> dict:
    path = Path(pdf_path)
    if not path.exists():
        return {"valid": False, "reason": "File tidak ditemukan.", "code": None}
    if path.suffix.lower() != ".pdf":
        return {"valid": False, "reason": "File harus PDF.", "code": None}

    code = extract_verification_code(path)
    if not code:
        _log_verification(None, None, "invalid:no_code")
        return {
            "valid": False,
            "reason": "Kode verifikasi tidak ditemukan di PDF.",
            "code": None,
        }

    with get_connection() as conn:
        document = conn.execute(
            """
            SELECT
                documents.*,
                users.name AS signer_name,
                users.email AS signer_email,
                digital_ids.role_title,
                digital_ids.status AS digital_id_status,
                digital_ids.serial_number
            FROM documents
            JOIN users ON users.id = documents.user_id
            LEFT JOIN digital_ids ON digital_ids.user_id = users.id
            WHERE documents.verification_code = ?
            """,
            (code,),
        ).fetchone()

    if document is None:
        _log_verification(None, code, "invalid:not_found")
        return {
            "valid": False,
            "reason": "Dokumen tidak terdaftar di database lokal.",
            "code": code,
        }

    try:
        current_hash = file_sha256(path)
    except OSError:
        _log_verification(document["id"], code, "invalid:hash_error")
        return {
            "valid": False,
            "reason": "Hash dokumen tidak bisa dihitung.",
            "code": code,
        }

    hash_match = current_hash == document["signed_hash"]
    digital_id_active = document["digital_id_status"] == "active"
    document_active = document["status"] == "signed"
    valid = hash_match and digital_id_active and document_active

    if valid:
        result = "valid"
        reason = "Dokumen valid dan hash cocok."
    elif not hash_match:
        result = "invalid:hash_mismatch"
        reason = "Hash tidak cocok. Dokumen kemungkinan sudah berubah."
    elif not digital_id_active:
        result = "invalid:digital_id_inactive"
        reason = "Digital ID penandatangan tidak aktif."
    else:
        result = "invalid:document_status"
        reason = "Status dokumen tidak aktif."

    _log_verification(document["id"], code, result)
    log_action(document["user_id"], "VERIFY_PDF", f"Verifikasi {code}: {result}.")

    return {
        "valid": valid,
        "reason": reason,
        "code": code,
        "hash_match": hash_match,
        "current_hash": current_hash,
        "stored_hash": document["signed_hash"],
        "signer_name": document["signer_name"],
        "signer_email": document["signer_email"],
        "role_title": document["role_title"],
        "signed_at": document["signed_at"],
        "digital_id_status": document["digital_id_status"],
        "serial_number": document["serial_number"],
        "signed_file_path": document["signed_file_path"],
    }
