from datetime import datetime
from io import BytesIO
from pathlib import Path
import hashlib
import re
import uuid

import qrcode
from pypdf import PdfReader, PdfWriter
from reportlab.lib.colors import HexColor, white
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from core.audit import log_action
from core.database import SIGNED_DOCS_DIR, get_connection


APP_NAME = "Ujaja Sign"


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
            code = f"SS-{uuid.uuid4().hex[:12].upper()}"
            exists = conn.execute(
                "SELECT 1 FROM documents WHERE verification_code = ?",
                (code,),
            ).fetchone()
            if not exists:
                return code


def _qr_image_reader(verification_code: str) -> ImageReader:
    img = qrcode.make(f"{APP_NAME} Verification Code: {verification_code}")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return ImageReader(buffer)


def _build_overlay(
    page_width: float,
    page_height: float,
    user,
    digital_id,
    signature_path: str | Path,
    verification_code: str,
    signed_at: str,
) -> BytesIO:
    packet = BytesIO()
    c = canvas.Canvas(packet, pagesize=(page_width, page_height))

    margin = 36
    block_width = min(280, max(220, page_width - (margin * 2)))
    block_height = 124
    x = max(margin, page_width - margin - block_width)
    y = max(margin, 28)

    c.setFillColor(white)
    c.setStrokeColor(HexColor("#4b5563"))
    c.roundRect(x, y, block_width, block_height, 6, stroke=1, fill=1)

    signature_reader = ImageReader(str(signature_path))
    c.drawImage(
        signature_reader,
        x + 10,
        y + 62,
        width=125,
        height=42,
        preserveAspectRatio=True,
        mask="auto",
    )

    qr_size = 60
    c.drawImage(
        _qr_image_reader(verification_code),
        x + block_width - qr_size - 10,
        y + 17,
        width=qr_size,
        height=qr_size,
        mask="auto",
    )

    text_x = x + 10
    c.setFillColor(HexColor("#111827"))
    c.setFont("Helvetica-Bold", 8)
    c.drawString(text_x, y + 51, "Digitally Signed by:")

    c.setFont("Helvetica-Bold", 10)
    c.drawString(text_x, y + 38, _truncate(user["name"], 29))

    c.setFont("Helvetica", 8)
    c.drawString(text_x, y + 27, f"Role: {_truncate(digital_id['role_title'], 24)}")
    c.drawString(text_x, y + 16, f"Date: {signed_at}")
    c.drawString(text_x, y + 5, f"Verification Code: {verification_code}")

    c.save()
    packet.seek(0)
    return packet


def create_signed_pdf(user, digital_id, input_pdf_path: str, signature_path: str):
    source = Path(input_pdf_path)
    signature = Path(signature_path)

    if not source.exists():
        raise ValueError("File PDF tidak ditemukan.")
    if source.suffix.lower() != ".pdf":
        raise ValueError("File input harus PDF.")
    if not signature.exists():
        raise ValueError("Gambar tanda tangan tidak ditemukan.")

    try:
        reader = PdfReader(str(source))
    except Exception as exc:
        raise ValueError("File PDF tidak bisa dibuka.") from exc

    if reader.is_encrypted:
        raise ValueError("PDF terenkripsi tidak didukung untuk MVP.")
    if not reader.pages:
        raise ValueError("PDF tidak memiliki halaman.")

    original_hash = file_sha256(source)
    verification_code = _unique_verification_code()
    signed_at = datetime.now().isoformat(timespec="seconds")

    last_page = reader.pages[-1]
    page_width = float(last_page.mediabox.width)
    page_height = float(last_page.mediabox.height)
    overlay_pdf = PdfReader(
        _build_overlay(
            page_width,
            page_height,
            user,
            digital_id,
            signature,
            verification_code,
            signed_at,
        )
    )

    writer = PdfWriter()
    for index, page in enumerate(reader.pages):
        if index == len(reader.pages) - 1:
            page.merge_page(overlay_pdf.pages[0])
        writer.add_page(page)

    writer.add_metadata(
        {
            "/Producer": APP_NAME,
            "/UjajaSignCode": verification_code,
            "/UjajaSignSigner": user["name"],
            "/UjajaSignSignedAt": signed_at,
        }
    )

    SIGNED_DOCS_DIR.mkdir(parents=True, exist_ok=True)
    output_name = f"{_safe_name(source.stem)}_{verification_code}.pdf"
    output_path = SIGNED_DOCS_DIR / output_name
    with open(output_path, "wb") as output_file:
        writer.write(output_file)

    signed_hash = file_sha256(output_path)
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO documents (
                user_id, original_file_path, signed_file_path,
                original_hash, signed_hash, verification_code,
                signed_at, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'signed')
            """,
            (
                user["id"],
                str(source),
                str(output_path),
                original_hash,
                signed_hash,
                verification_code,
                signed_at,
            ),
        )

    log_action(
        user["id"],
        "SIGN_PDF",
        f"Dokumen {source.name} ditandatangani dengan kode {verification_code}.",
    )
    return {
        "output_path": output_path,
        "verification_code": verification_code,
        "signed_at": signed_at,
        "original_hash": original_hash,
        "signed_hash": signed_hash,
    }
