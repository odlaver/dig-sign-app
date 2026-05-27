from datetime import datetime
from pathlib import Path

from PIL import Image

from core.audit import log_action
from core.database import SIGNATURES_DIR, get_connection


ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}


def get_signature_profile(user_id: int):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT *
            FROM signature_profiles
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()


def save_signature_image(user_id: int, source_path: str):
    source = Path(source_path)
    if not source.exists():
        raise ValueError("File tanda tangan tidak ditemukan.")
    if source.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("Format tanda tangan harus PNG, JPG, atau JPEG.")

    SIGNATURES_DIR.mkdir(parents=True, exist_ok=True)
    target = SIGNATURES_DIR / f"user_{user_id}_signature.png"

    try:
        image = Image.open(source).convert("RGBA")
    except OSError as exc:
        raise ValueError("File gambar tidak bisa dibuka.") from exc

    image.thumbnail((900, 300))
    image.save(target, format="PNG")

    now = datetime.now().isoformat(timespec="seconds")
    with get_connection() as conn:
        existing = conn.execute(
            "SELECT id FROM signature_profiles WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE signature_profiles
                SET signature_image_path = ?, updated_at = ?
                WHERE user_id = ?
                """,
                (str(target), now, user_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO signature_profiles (
                    user_id, signature_image_path, created_at, updated_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (user_id, str(target), now, now),
            )

    log_action(user_id, "UPLOAD_SIGNATURE", "Gambar tanda tangan disimpan.")
    return get_signature_profile(user_id)
