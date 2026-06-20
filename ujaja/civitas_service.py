import sqlite3
from core.auth import authenticate
from core.database import get_connection
from core.security import hash_secret
from ujaja.ca_service import ensure_ujaja_identity
BASELINE_PASSWORD = 'password123'
BASELINE_USERS = [{'name': 'Admin Ujaja', 'email': 'admin@ujaja.ac.id', 'password': BASELINE_PASSWORD, 'role': 'admin'}, {'name': 'Dr. Satria Wiratama', 'email': 'dosen@ujaja.ac.id', 'password': BASELINE_PASSWORD, 'employee_id': 'Ujaja-DSN-0001', 'department': 'Fakultas Ilmu Komputer', 'position': 'Dosen', 'role': 'dosen', 'status': 'Active'}, {'name': 'Raka Aditya', 'email': 'mahasiswa@ujaja.ac.id', 'password': BASELINE_PASSWORD, 'employee_id': 'Ujaja-MHS-0001', 'department': 'Fakultas Ilmu Komputer', 'position': 'Mahasiswa', 'role': 'mahasiswa', 'status': 'Active'}, {'name': 'Maya Pradipta', 'email': 'dekanat@ujaja.ac.id', 'password': BASELINE_PASSWORD, 'employee_id': 'Ujaja-DKN-0001', 'department': 'Dekanat Fakultas Ilmu Komputer', 'position': 'Dekanat', 'role': 'dekanat', 'status': 'Active'}]

def ensure_institution_baseline_data() -> None:
    ensure_ujaja_identity()
    with get_connection() as conn:
        for seed in BASELINE_USERS:
            user = conn.execute('SELECT id FROM users WHERE email = ?', (seed['email'],)).fetchone()
            if user:
                user_id = int(user['id'])
                conn.execute('\n                    UPDATE users\n                    SET name = ?, role = ?\n                    WHERE id = ?\n                    ', (seed['name'], seed['role'], user_id))
            else:
                cursor = conn.execute('\n                    INSERT INTO users (name, email, password_hash, role)\n                    VALUES (?, ?, ?, ?)\n                    ', (seed['name'], seed['email'], hash_secret(seed['password']), seed['role']))
                user_id = int(cursor.lastrowid)
            if seed['role'] == 'admin':
                continue
            employee = conn.execute('SELECT id FROM employees WHERE user_id = ?', (user_id,)).fetchone()
            if employee:
                conn.execute('\n                    UPDATE employees\n                    SET employee_id = ?,\n                        department = ?,\n                        position = ?,\n                        academic_email = ?,\n                        employee_status = ?,\n                        updated_at = CURRENT_TIMESTAMP\n                    WHERE user_id = ?\n                    ', (seed['employee_id'], seed['department'], seed['position'], seed['email'], seed['status'], user_id))
            else:
                conn.execute('\n                    INSERT INTO employees (\n                        user_id, employee_id, department, position,\n                        academic_email, employee_status\n                    )\n                    VALUES (?, ?, ?, ?, ?, ?)\n                    ', (user_id, seed['employee_id'], seed['department'], seed['position'], seed['email'], seed['status']))

def create_civitas(name: str, email: str, password: str, employee_id: str, department: str, position: str, role: str='employee', status: str='Active') -> int:
    email = email.strip().lower()
    with get_connection() as conn:
        try:
            cursor = conn.execute('\n                INSERT INTO users (name, email, password_hash, role)\n                VALUES (?, ?, ?, ?)\n                ', (name, email, hash_secret(password), role))
            user_id = int(cursor.lastrowid)
            conn.execute('\n                INSERT INTO employees (\n                    user_id, employee_id, department, position,\n                    academic_email, employee_status\n                )\n                VALUES (?, ?, ?, ?, ?, ?)\n                ', (user_id, employee_id, department, position, email, status))
        except sqlite3.IntegrityError as exc:
            raise ValueError('Email atau Civitas ID sudah terdaftar.') from exc
    return user_id

def get_civitas_for_user(user_id: int):
    with get_connection() as conn:
        return conn.execute('\n            SELECT employees.*, users.name, users.email\n            FROM employees\n            JOIN users ON users.id = employees.user_id\n            WHERE employees.user_id = ?\n            ', (user_id,)).fetchone()

def validate_active_civitas(user_id: int):
    civitas = get_civitas_for_user(user_id)
    if civitas is None:
        raise ValueError('Akun ini bukan civitas Ujaja.')
    if civitas['employee_status'] != 'Active':
        raise ValueError('Status civitas tidak aktif.')
    return civitas

def authenticate_civitas(email: str, password: str):
    user = authenticate(email, password)
    if user is None:
        return (None, 'Email atau password salah.')
    if user['role'] == 'admin':
        return ({'user': user, 'civitas': None}, None)
    civitas = get_civitas_for_user(user['id'])
    if civitas is None:
        return (None, 'Akun ini bukan civitas Ujaja.')
    if civitas['employee_status'] != 'Active':
        return (None, 'Status civitas tidak aktif.')
    return ({'user': user, 'civitas': civitas}, None)

def count_institution_signed_documents(user_id: int) -> int:
    with get_connection() as conn:
        row = conn.execute('\n            SELECT COUNT(*) AS total\n            FROM ujaja_sign_requests\n            JOIN employees ON employees.id = ujaja_sign_requests.employee_id\n            WHERE employees.user_id = ?\n            ', (user_id,)).fetchone()
        return int(row['total'])

def list_institution_sign_requests(user_id: int):
    with get_connection() as conn:
        return conn.execute('\n            SELECT ujaja_sign_requests.*\n            FROM ujaja_sign_requests\n            JOIN employees ON employees.id = ujaja_sign_requests.employee_id\n            WHERE employees.user_id = ?\n            ORDER BY ujaja_sign_requests.signed_at DESC, ujaja_sign_requests.id DESC\n            ', (user_id,)).fetchall()

def save_signature_profile(user_id: int, image_path: str) -> None:
    with get_connection() as conn:
        conn.execute('\n            INSERT INTO signature_profiles (user_id, signature_image_path)\n            VALUES (?, ?)\n            ON CONFLICT(user_id) DO UPDATE SET\n                signature_image_path = excluded.signature_image_path,\n                updated_at = CURRENT_TIMESTAMP\n            ', (user_id, image_path))

def get_signature_profile(user_id: int) -> str | None:
    with get_connection() as conn:
        row = conn.execute('SELECT signature_image_path FROM signature_profiles WHERE user_id = ?', (user_id,)).fetchone()
        return row['signature_image_path'] if row else None