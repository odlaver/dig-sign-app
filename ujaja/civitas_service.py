import sqlite3

from core.auth import authenticate
from ujaja.ca_service import ensure_ujaja_identity
from core.database import get_connection
from core.security import hash_secret


DEFAULT_CIVITAS = {
    "name": "Reval",
    "email": "reval@ujaja.ac.id",
    "password": "password123",
    "employee_id": "Ujaja-0001",
    "department": "Fakultas Ilmu Komputer",
    "position": "Dosen",
    "status": "Active",
}


def ensure_default_civitas() -> None:
    ensure_ujaja_identity()
    with get_connection() as conn:
        existing_civitas = conn.execute(
            """
            SELECT employees.user_id
            FROM employees
            WHERE employees.employee_id = ?
            """,
            (DEFAULT_CIVITAS["employee_id"],),
        ).fetchone()
        user = None
        if existing_civitas:
            user = conn.execute(
                "SELECT * FROM users WHERE id = ?",
                (existing_civitas["user_id"],),
            ).fetchone()
        if user is None:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (DEFAULT_CIVITAS["email"],),
            ).fetchone()

        if user:
            user_id = user["id"]
            other_user = conn.execute(
                "SELECT id FROM users WHERE email = ? AND id != ?",
                (DEFAULT_CIVITAS["email"], user_id),
            ).fetchone()
            if other_user:
                conn.execute("DELETE FROM users WHERE id = ?", (other_user["id"],))
            conn.execute(
                """
                UPDATE users
                SET name = ?, email = ?, role = 'employee', password_hash = ?
                WHERE id = ?
                """,
                (
                    DEFAULT_CIVITAS["name"],
                    DEFAULT_CIVITAS["email"],
                    hash_secret(DEFAULT_CIVITAS["password"]),
                    user_id,
                ),
            )
        else:
            cursor = conn.execute(
                """
                INSERT INTO users (name, email, password_hash, role)
                VALUES (?, ?, ?, 'employee')
                """,
                (
                    DEFAULT_CIVITAS["name"],
                    DEFAULT_CIVITAS["email"],
                    hash_secret(DEFAULT_CIVITAS["password"]),
                ),
            )
            user_id = int(cursor.lastrowid)

        employee = conn.execute(
            "SELECT id FROM employees WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if employee:
            conn.execute(
                """
                UPDATE employees
                SET employee_id = ?,
                    department = ?,
                    position = ?,
                    academic_email = ?,
                    employee_status = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
                """,
                (
                    DEFAULT_CIVITAS["employee_id"],
                    DEFAULT_CIVITAS["department"],
                    DEFAULT_CIVITAS["position"],
                    DEFAULT_CIVITAS["email"],
                    DEFAULT_CIVITAS["status"],
                    user_id,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO employees (
                    user_id, employee_id, department, position,
                    academic_email, employee_status
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    DEFAULT_CIVITAS["employee_id"],
                    DEFAULT_CIVITAS["department"],
                    DEFAULT_CIVITAS["position"],
                    DEFAULT_CIVITAS["email"],
                    DEFAULT_CIVITAS["status"],
                ),
            )


def ensure_institution_seed_data() -> None:
    ensure_default_civitas()


def create_civitas(
    name: str,
    email: str,
    password: str,
    employee_id: str,
    department: str,
    position: str,
    status: str = "Active",
) -> int:
    email = email.strip().lower()
    with get_connection() as conn:
        try:
            cursor = conn.execute(
                """
                INSERT INTO users (name, email, password_hash, role)
                VALUES (?, ?, ?, 'employee')
                """,
                (name, email, hash_secret(password)),
            )
            user_id = int(cursor.lastrowid)
            conn.execute(
                """
                INSERT INTO employees (
                    user_id, employee_id, department, position,
                    academic_email, employee_status
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, employee_id, department, position, email, status),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Email atau Civitas ID sudah terdaftar.") from exc
    return user_id


def get_civitas_for_user(user_id: int):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT employees.*, users.name, users.email
            FROM employees
            JOIN users ON users.id = employees.user_id
            WHERE employees.user_id = ?
            """,
            (user_id,),
        ).fetchone()


def validate_active_civitas(user_id: int):
    civitas = get_civitas_for_user(user_id)
    if civitas is None:
        raise ValueError("Akun ini bukan civitas Ujaja.")
    if civitas["employee_status"] != "Active":
        raise ValueError("Status civitas tidak aktif.")
    return civitas


def authenticate_civitas(email: str, password: str):
    user = authenticate(email, password)
    if user is None:
        return None, "Email atau password salah."

    civitas = get_civitas_for_user(user["id"])
    if civitas is None:
        return None, "Akun ini bukan civitas Ujaja."
    if civitas["employee_status"] != "Active":
        return None, "Status civitas tidak aktif."

    return {"user": user, "civitas": civitas}, None


def count_institution_signed_documents(user_id: int) -> int:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM ujaja_sign_requests
            JOIN employees ON employees.id = ujaja_sign_requests.employee_id
            WHERE employees.user_id = ?
            """,
            (user_id,),
        ).fetchone()
        return int(row["total"])


def list_institution_sign_requests(user_id: int):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT ujaja_sign_requests.*
            FROM ujaja_sign_requests
            JOIN employees ON employees.id = ujaja_sign_requests.employee_id
            WHERE employees.user_id = ?
            ORDER BY ujaja_sign_requests.signed_at DESC, ujaja_sign_requests.id DESC
            """,
            (user_id,),
        ).fetchall()
