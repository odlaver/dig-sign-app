from pathlib import Path
import shutil
import sys
import uuid

import pyotp
from PIL import Image, ImageDraw
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import auth, database, otp_service
from self_signed import digital_id, pdf_signer, signature_manager, verifier


def make_signature(path: Path) -> None:
    image = Image.new("RGBA", (420, 160), (255, 255, 255, 0))
    draw = ImageDraw.Draw(image)
    draw.line((30, 90, 120, 45, 210, 110, 330, 55), fill=(20, 20, 20, 255), width=8)
    draw.line((60, 118, 360, 118), fill=(20, 20, 20, 180), width=3)
    image.save(path)


def make_pdf(path: Path) -> None:
    pdf = canvas.Canvas(str(path))
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(72, 740, "Smoke Test Ujaja Sign")
    pdf.setFont("Helvetica", 11)
    pdf.drawString(72, 710, "PDF ini dibuat otomatis untuk menguji alur signing dan verification.")
    pdf.save()


def cleanup(user_id: int | None, paths: list[Path | None], verification_code: str | None = None) -> None:
    if user_id is not None:
        with database.get_connection() as conn:
            if verification_code:
                conn.execute(
                    "DELETE FROM verification_logs WHERE verification_code = ?",
                    (verification_code,),
                )
            conn.execute("DELETE FROM audit_logs WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    for path in paths:
        if path and path.exists():
            path.unlink()


def main() -> None:
    database.init_db()
    temp_dir = database.TEMP_DIR
    temp_dir.mkdir(parents=True, exist_ok=True)

    email = f"smoke-{uuid.uuid4().hex[:8]}@test.sign"
    password = "password123"
    passphrase = "passphrase123"
    user_id = None
    verification_code = None
    signed_path = None

    signature_source = temp_dir / "smoke_signature.png"
    source_pdf = temp_dir / "smoke_source.pdf"
    tampered_pdf = temp_dir / "smoke_tampered.pdf"

    try:
        user_id = auth.register_user("Smoke User", email, password)
        assert auth.authenticate(email, "wrong-password") is None

        try:
            auth.register_user("Duplicate", email, password)
            raise AssertionError("Email duplicate seharusnya ditolak.")
        except ValueError:
            pass

        secret = otp_service.get_or_create_secret(user_id)
        assert not otp_service.enable_otp(user_id, "000000")
        assert otp_service.enable_otp(user_id, pyotp.TOTP(secret).now())

        user = auth.get_user(user_id)
        did = digital_id.create_or_update_digital_id(user_id, "Mahasiswa", passphrase)
        assert digital_id.verify_passphrase(user_id, passphrase)
        assert not digital_id.verify_passphrase(user_id, "wrong-passphrase")

        make_signature(signature_source)
        profile = signature_manager.save_signature_image(user_id, str(signature_source))
        assert Path(profile["signature_image_path"]).exists()

        make_pdf(source_pdf)
        result = pdf_signer.create_signed_pdf(
            user,
            did,
            str(source_pdf),
            profile["signature_image_path"],
        )
        signed_path = Path(result["output_path"])
        verification_code = result["verification_code"]
        assert signed_path.exists()

        valid_result = verifier.verify_pdf(signed_path)
        assert valid_result["valid"], valid_result

        shutil.copyfile(signed_path, tampered_pdf)
        with open(tampered_pdf, "ab") as file:
            file.write(b"\n% smoke tamper")

        tampered_result = verifier.verify_pdf(tampered_pdf)
        assert not tampered_result["valid"], tampered_result
        assert tampered_result["code"] == verification_code

        print("self-signed smoke test ok")
    finally:
        cleanup(
            user_id,
            [
                signature_source,
                source_pdf,
                tampered_pdf,
                signed_path,
                database.SIGNATURES_DIR / f"user_{user_id}_signature.png" if user_id else None,
                database.QRCODES_DIR / f"otp_user_{user_id}.png" if user_id else None,
            ],
            verification_code,
        )


if __name__ == "__main__":
    main()
