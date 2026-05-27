from pathlib import Path
import shutil
import sys
import uuid

import pyotp
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator.context import ValidationContext
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import auth, database, otp_service
from ujaja import ca_service, civitas_service, institution_signer


def count_pdf_signatures(path: Path) -> int:
    with open(path, "rb") as file:
        reader = PdfFileReader(file)
        return len(reader.embedded_regular_signatures)


def assert_pdf_signature_valid(path: Path) -> None:
    with open(path, "rb") as file:
        reader = PdfFileReader(file)
        root = load_cert_from_pemder(str(ca_service.get_ujaja_ca_certificate_path()))
        validation_context = ValidationContext(trust_roots=[root], allow_fetching=False)
        status = validate_pdf_signature(
            reader.embedded_regular_signatures[0],
            signer_validation_context=validation_context,
            skip_diff=True,
        )
        assert status.intact, status.summary()
        assert status.valid, status.summary()
        assert status.trusted, status.summary()


def make_pdf(path: Path) -> None:
    pdf = canvas.Canvas(str(path))
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(72, 740, "Ujaja Smoke Test")
    pdf.setFont("Helvetica", 11)
    pdf.drawString(72, 710, "PDF ini dibuat untuk menguji alur tanda tangan Universitas Jaya Jaya.")
    pdf.save()


def cleanup(user_id: int | None, paths: list[Path | None], verification_code: str | None = None) -> None:
    with database.get_connection() as conn:
        if verification_code:
            conn.execute(
                "DELETE FROM verification_logs WHERE verification_code = ?",
                (verification_code,),
            )
            conn.execute(
                "DELETE FROM ujaja_sign_requests WHERE verification_code = ?",
                (verification_code,),
            )
        if user_id is not None:
            conn.execute("DELETE FROM audit_logs WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    for path in paths:
        if path and path.exists():
            path.unlink()


def main() -> None:
    database.init_db()
    civitas_service.ensure_institution_seed_data()
    temp_dir = database.TEMP_DIR
    temp_dir.mkdir(parents=True, exist_ok=True)

    suffix = uuid.uuid4().hex[:8]
    email = f"ujaja-smoke-{suffix}@ujaja.ac.id"
    password = "password123"
    employee_id = f"Ujaja-SMOKE-{suffix.upper()}"
    user_id = None
    verification_code = None
    signed_path = None

    source_pdf = temp_dir / "ujaja_smoke_source.pdf"
    tampered_pdf = temp_dir / "ujaja_smoke_tampered.pdf"

    try:
        user_id = civitas_service.create_civitas(
            "Ujaja Smoke User",
            email,
            password,
            employee_id,
            "Fakultas Teknik",
            "Dosen",
        )
        secret = otp_service.get_or_create_secret(user_id)
        assert not otp_service.enable_otp(user_id, "000000")
        assert otp_service.enable_otp(user_id, pyotp.TOTP(secret).now())

        user = auth.get_user(user_id)
        make_pdf(source_pdf)
        result = institution_signer.sign_institution_pdf(
            user,
            str(source_pdf),
            pyotp.TOTP(secret).now(),
            "kanan bawah",
        )
        signed_path = Path(result["output_path"])
        verification_code = result["verification_code"]
        assert signed_path.exists()
        assert result["signature_value"]
        assert count_pdf_signatures(signed_path) >= 1
        assert_pdf_signature_valid(signed_path)

        valid_result = institution_signer.verify_institution_pdf(signed_path)
        assert valid_result["valid"], valid_result
        assert valid_result["signature_valid"], valid_result

        shutil.copyfile(signed_path, tampered_pdf)
        with open(tampered_pdf, "ab") as file:
            file.write(b"\n% ujaja smoke tamper")

        tampered_result = institution_signer.verify_institution_pdf(tampered_pdf)
        assert not tampered_result["valid"], tampered_result
        assert tampered_result["code"] == verification_code

        print("ujaja smoke test ok")
    finally:
        cleanup(user_id, [source_pdf, tampered_pdf, signed_path], verification_code)


if __name__ == "__main__":
    main()
