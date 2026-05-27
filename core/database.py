from pathlib import Path
import sqlite3


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
ASSETS_DIR = PROJECT_ROOT / "assets"
SOURCE_ASSETS_DIR = ASSETS_DIR / "source"
SIGNATURES_DIR = ASSETS_DIR / "signatures"
QRCODES_DIR = ASSETS_DIR / "qrcodes"
SIGNED_DOCS_DIR = ASSETS_DIR / "signed_docs"
TEMP_DIR = ASSETS_DIR / "temp"
UJAJA_DIR = ASSETS_DIR / "ujaja"
CA_DIR = ASSETS_DIR / "ca"
DB_PATH = DATA_DIR / "ujaja_sign.db"


def ensure_directories() -> None:
    for directory in (
        DATA_DIR,
        ASSETS_DIR,
        SOURCE_ASSETS_DIR,
        SIGNATURES_DIR,
        QRCODES_DIR,
        SIGNED_DOCS_DIR,
        TEMP_DIR,
        UJAJA_DIR,
        CA_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    ensure_directories()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    ensure_directories()
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                otp_secret TEXT,
                otp_enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS digital_ids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                role_title TEXT NOT NULL,
                passphrase_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                serial_number TEXT NOT NULL UNIQUE,
                issued_at TEXT NOT NULL,
                expired_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS signature_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                signature_image_path TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_file_path TEXT NOT NULL,
                signed_file_path TEXT NOT NULL,
                original_hash TEXT NOT NULL,
                signed_hash TEXT NOT NULL,
                verification_code TEXT NOT NULL UNIQUE,
                signed_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'signed',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS verification_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER,
                verification_code TEXT,
                result TEXT NOT NULL,
                checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                employee_id TEXT NOT NULL UNIQUE,
                department TEXT NOT NULL,
                position TEXT NOT NULL,
                academic_email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                employee_status TEXT NOT NULL DEFAULT 'Active',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS ujaja_ca (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                institution_name TEXT NOT NULL,
                ca_name TEXT NOT NULL,
                serial_number TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                ca_file_path TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active',
                issued_at TEXT NOT NULL,
                expired_at TEXT,
                revoked_at TEXT
            );

            CREATE TABLE IF NOT EXISTS ujaja_digital_ids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                institution_name TEXT NOT NULL,
                digital_id_name TEXT NOT NULL,
                serial_number TEXT NOT NULL UNIQUE,
                certificate_file_path TEXT,
                private_key TEXT NOT NULL,
                ca_serial_number TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active',
                issued_at TEXT NOT NULL,
                expired_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY (ca_serial_number) REFERENCES ujaja_ca(serial_number)
            );

            CREATE TABLE IF NOT EXISTS ujaja_sign_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                original_file_path TEXT NOT NULL,
                signed_file_path TEXT NOT NULL,
                original_hash TEXT NOT NULL,
                signature_payload_hash TEXT NOT NULL,
                signed_hash TEXT NOT NULL,
                verification_code TEXT NOT NULL UNIQUE,
                signature_position TEXT NOT NULL,
                ca_serial_number TEXT NOT NULL,
                ujaja_digital_id_serial TEXT NOT NULL,
                signature_value TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Signed',
                signed_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
                FOREIGN KEY (ca_serial_number) REFERENCES ujaja_ca(serial_number),
                FOREIGN KEY (ujaja_digital_id_serial) REFERENCES ujaja_digital_ids(serial_number)
            );
            """
        )
