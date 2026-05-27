from datetime import datetime
import uuid

from core.audit import log_action
from core.auth import get_user
from core.database import get_connection
from core.security import hash_secret, verify_secret


ROLE_OPTIONS = ["Mahasiswa", "Dosen", "Staff", "Anggota Organisasi", "User"]


def get_digital_id(user_id: int):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT *
            FROM digital_ids
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()


def get_active_digital_id(user_id: int):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT *
            FROM digital_ids
            WHERE user_id = ? AND status = 'active'
            """,
            (user_id,),
        ).fetchone()


def create_or_update_digital_id(user_id: int, role_title: str, passphrase: str):
    user = get_user(user_id)
    if user is None:
        raise ValueError("User tidak ditemukan.")
    if not user["otp_enabled"]:
        raise ValueError("Aktifkan OTP sebelum membuat Digital ID.")
    if role_title not in ROLE_OPTIONS:
        raise ValueError("Role Digital ID tidak valid.")
    if len(passphrase.strip()) < 6:
        raise ValueError("Passphrase minimal 6 karakter.")

    serial_number = f"TSID-{uuid.uuid4().hex[:12].upper()}"
    issued_at = datetime.now().isoformat(timespec="seconds")
    passphrase_hash = hash_secret(passphrase)

    with get_connection() as conn:
        existing = conn.execute(
            "SELECT id FROM digital_ids WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE digital_ids
                SET role_title = ?,
                    passphrase_hash = ?,
                    status = 'active',
                    serial_number = ?,
                    issued_at = ?,
                    expired_at = NULL,
                    revoked_at = NULL
                WHERE user_id = ?
                """,
                (role_title, passphrase_hash, serial_number, issued_at, user_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO digital_ids (
                    user_id, role_title, passphrase_hash, status,
                    serial_number, issued_at
                )
                VALUES (?, ?, ?, 'active', ?, ?)
                """,
                (user_id, role_title, passphrase_hash, serial_number, issued_at),
            )

    log_action(user_id, "DIGITAL_ID_ACTIVE", f"Digital ID aktif sebagai {role_title}.")
    return get_active_digital_id(user_id)


def verify_passphrase(user_id: int, passphrase: str) -> bool:
    digital_id = get_active_digital_id(user_id)
    if digital_id is None:
        return False
    return verify_secret(passphrase, digital_id["passphrase_hash"])
