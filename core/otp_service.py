from pathlib import Path
import pyotp
from core.audit import log_action
from core.auth import get_user
from core.database import QRCODES_DIR, get_connection
from core.qr_utils import transparent_qr_image
ISSUER_NAME = 'Ujaja Sign'

def _clean_code(code: str) -> str:
    return (code or '').strip().replace(' ', '')

def get_or_create_secret(user_id: int) -> str:
    user = get_user(user_id)
    if user is None:
        raise ValueError('User tidak ditemukan.')
    if user['otp_secret']:
        return user['otp_secret']
    secret = pyotp.random_base32()
    with get_connection() as conn:
        conn.execute('UPDATE users SET otp_secret = ? WHERE id = ?', (secret, user_id))
    log_action(user_id, 'OTP_SECRET_CREATED', 'OTP secret dibuat.')
    return secret

def provisioning_uri(user_id: int) -> str:
    user = get_user(user_id)
    if user is None:
        raise ValueError('User tidak ditemukan.')
    secret = get_or_create_secret(user_id)
    return pyotp.TOTP(secret).provisioning_uri(name=user['email'], issuer_name=ISSUER_NAME)

def generate_qr_code(user_id: int) -> Path:
    QRCODES_DIR.mkdir(parents=True, exist_ok=True)
    image_path = QRCODES_DIR / f'otp_user_{user_id}.png'
    img = transparent_qr_image(provisioning_uri(user_id))
    img.save(image_path)
    return image_path

def verify_code(user_id: int, code: str) -> bool:
    user = get_user(user_id)
    if user is None or not user['otp_secret']:
        return False
    cleaned = _clean_code(code)
    if not cleaned:
        return False
    return bool(pyotp.TOTP(user['otp_secret']).verify(cleaned, valid_window=0))

def enable_otp(user_id: int, code: str) -> bool:
    if not verify_code(user_id, code):
        return False
    with get_connection() as conn:
        conn.execute('UPDATE users SET otp_enabled = 1 WHERE id = ?', (user_id,))
    log_action(user_id, 'SETUP_OTP', 'OTP berhasil diaktifkan.')
    return True

def reset_otp(user_id: int) -> None:
    with get_connection() as conn:
        conn.execute('UPDATE users SET otp_secret = NULL, otp_enabled = 0 WHERE id = ?', (user_id,))
    log_action(user_id, 'RESET_OTP', 'OTP berhasil di-reset.')