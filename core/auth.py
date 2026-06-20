import sqlite3
from core.audit import log_action
from core.database import get_connection
from core.security import hash_secret, verify_secret

def register_user(name: str, email: str, password: str) -> int:
    name = name.strip()
    email = email.strip().lower()
    if not name:
        raise ValueError('Nama wajib diisi.')
    if '@' not in email:
        raise ValueError('Email tidak valid.')
    if len(password) < 6:
        raise ValueError('Password minimal 6 karakter.')
    try:
        with get_connection() as conn:
            cursor = conn.execute('\n                INSERT INTO users (name, email, password_hash)\n                VALUES (?, ?, ?)\n                ', (name, email, hash_secret(password)))
            user_id = int(cursor.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise ValueError('Email sudah terdaftar.') from exc
    log_action(user_id, 'REGISTER', f'Akun dibuat untuk {email}.')
    return user_id

def authenticate(email: str, password: str):
    email = email.strip().lower()
    with get_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if user is None or not verify_secret(password, user['password_hash']):
        return None
    log_action(user['id'], 'LOGIN', 'User login.')
    return user

def get_user(user_id: int):
    with get_connection() as conn:
        return conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

def count_signed_documents(user_id: int) -> int:
    with get_connection() as conn:
        row = conn.execute('\n            SELECT COUNT(*) AS total\n            FROM documents\n            WHERE user_id = ?\n            ', (user_id,)).fetchone()
        return int(row['total'])