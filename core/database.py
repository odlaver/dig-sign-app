from pathlib import Path
import sqlite3
import sys
from core.file_security import restrict_private_path

def _project_root() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]
PROJECT_ROOT = _project_root()
BUNDLED_ROOT = Path(getattr(sys, '_MEIPASS', PROJECT_ROOT))
DATA_DIR = PROJECT_ROOT / 'data'
ASSETS_DIR = PROJECT_ROOT / 'assets'
SOURCE_ASSETS_DIR = ASSETS_DIR / 'source'
BUNDLED_SOURCE_ASSETS_DIR = BUNDLED_ROOT / 'assets' / 'source'
SIGNATURES_DIR = ASSETS_DIR / 'signatures'
QRCODES_DIR = ASSETS_DIR / 'qrcodes'
SIGNED_DOCS_DIR = ASSETS_DIR / 'signed_docs'
TEMP_DIR = ASSETS_DIR / 'temp'
UJAJA_DIR = ASSETS_DIR / 'ujaja'
CA_DIR = ASSETS_DIR / 'ca'
DB_PATH = DATA_DIR / 'ujaja_sign.db'

def ensure_directories() -> None:
    for directory in (DATA_DIR, ASSETS_DIR, SOURCE_ASSETS_DIR, SIGNATURES_DIR, QRCODES_DIR, SIGNED_DOCS_DIR, TEMP_DIR, UJAJA_DIR, CA_DIR):
        directory.mkdir(parents=True, exist_ok=True)
    for private_directory in (DATA_DIR, CA_DIR):
        restrict_private_path(private_directory)

def get_connection() -> sqlite3.Connection:
    ensure_directories()
    conn = sqlite3.connect(DB_PATH)
    restrict_private_path(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def init_db() -> None:
    ensure_directories()
    with get_connection() as conn:
        conn.executescript("\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                name TEXT NOT NULL,\n                email TEXT NOT NULL UNIQUE COLLATE NOCASE,\n                password_hash TEXT NOT NULL,\n                role TEXT NOT NULL DEFAULT 'user',\n                otp_secret TEXT,\n                otp_enabled INTEGER NOT NULL DEFAULT 0,\n                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP\n            );\n\n            CREATE TABLE IF NOT EXISTS digital_ids (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                user_id INTEGER NOT NULL UNIQUE,\n                role_title TEXT NOT NULL,\n                passphrase_hash TEXT NOT NULL,\n                status TEXT NOT NULL DEFAULT 'active',\n                serial_number TEXT NOT NULL UNIQUE,\n                issued_at TEXT NOT NULL,\n                expired_at TEXT,\n                revoked_at TEXT,\n                certificate_file_path TEXT,\n                private_key TEXT,\n                public_key TEXT,\n                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE\n            );\n\n            CREATE TABLE IF NOT EXISTS signature_profiles (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                user_id INTEGER NOT NULL UNIQUE,\n                signature_image_path TEXT NOT NULL,\n                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,\n                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,\n                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE\n            );\n\n            CREATE TABLE IF NOT EXISTS documents (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                user_id INTEGER NOT NULL,\n                original_file_path TEXT NOT NULL,\n                signed_file_path TEXT NOT NULL,\n                original_hash TEXT NOT NULL,\n                signed_hash TEXT NOT NULL,\n                verification_code TEXT NOT NULL UNIQUE,\n                signed_at TEXT NOT NULL,\n                status TEXT NOT NULL DEFAULT 'signed',\n                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE\n            );\n\n            CREATE TABLE IF NOT EXISTS verification_logs (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                document_id INTEGER,\n                verification_code TEXT,\n                result TEXT NOT NULL,\n                checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,\n                FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL\n            );\n\n            CREATE TABLE IF NOT EXISTS audit_logs (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                user_id INTEGER,\n                action TEXT NOT NULL,\n                description TEXT NOT NULL,\n                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,\n                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL\n            );\n\n            CREATE TABLE IF NOT EXISTS employees (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                user_id INTEGER NOT NULL UNIQUE,\n                employee_id TEXT NOT NULL UNIQUE,\n                department TEXT NOT NULL,\n                position TEXT NOT NULL,\n                academic_email TEXT NOT NULL UNIQUE COLLATE NOCASE,\n                employee_status TEXT NOT NULL DEFAULT 'Active',\n                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,\n                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,\n                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE\n            );\n\n            CREATE TABLE IF NOT EXISTS ujaja_ca (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                institution_name TEXT NOT NULL,\n                ca_name TEXT NOT NULL,\n                serial_number TEXT NOT NULL UNIQUE,\n                public_key TEXT NOT NULL,\n                ca_file_path TEXT NOT NULL,\n                status TEXT NOT NULL DEFAULT 'Active',\n                issued_at TEXT NOT NULL,\n                expired_at TEXT,\n                revoked_at TEXT,\n                ca_certificate TEXT\n            );\n\n            CREATE TABLE IF NOT EXISTS ujaja_digital_ids (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                institution_name TEXT NOT NULL,\n                digital_id_name TEXT NOT NULL,\n                serial_number TEXT NOT NULL UNIQUE,\n                certificate_file_path TEXT,\n                private_key TEXT NOT NULL,\n                ca_serial_number TEXT NOT NULL,\n                status TEXT NOT NULL DEFAULT 'Active',\n                issued_at TEXT NOT NULL,\n                expired_at TEXT,\n                revoked_at TEXT,\n                certificate_pem TEXT,\n                FOREIGN KEY (ca_serial_number) REFERENCES ujaja_ca(serial_number)\n            );\n\n            CREATE TABLE IF NOT EXISTS ujaja_sign_requests (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                employee_id INTEGER NOT NULL,\n                original_file_path TEXT NOT NULL,\n                signed_file_path TEXT NOT NULL,\n                original_hash TEXT NOT NULL,\n                signature_payload_hash TEXT NOT NULL,\n                signed_hash TEXT NOT NULL,\n                verification_code TEXT NOT NULL UNIQUE,\n                signature_position TEXT NOT NULL,\n                ca_serial_number TEXT NOT NULL,\n                ujaja_digital_id_serial TEXT NOT NULL,\n                signature_value TEXT NOT NULL,\n                status TEXT NOT NULL DEFAULT 'Signed',\n                signed_at TEXT NOT NULL,\n                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,\n                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,\n                FOREIGN KEY (ca_serial_number) REFERENCES ujaja_ca(serial_number),\n                FOREIGN KEY (ujaja_digital_id_serial) REFERENCES ujaja_digital_ids(serial_number)\n            );\n            ")
        cursor = conn.cursor()
        cursor.execute('PRAGMA table_info(digital_ids)')
        columns = [row['name'] for row in cursor.fetchall()]
        if 'certificate_file_path' not in columns:
            conn.execute('ALTER TABLE digital_ids ADD COLUMN certificate_file_path TEXT')
        if 'private_key' not in columns:
            conn.execute('ALTER TABLE digital_ids ADD COLUMN private_key TEXT')
        if 'public_key' not in columns:
            conn.execute('ALTER TABLE digital_ids ADD COLUMN public_key TEXT')
        cursor.execute('PRAGMA table_info(ujaja_ca)')
        ca_columns = [row['name'] for row in cursor.fetchall()]
        if 'ca_certificate' not in ca_columns:
            conn.execute('ALTER TABLE ujaja_ca ADD COLUMN ca_certificate TEXT')
        if 'ca_private_key' not in ca_columns:
            conn.execute('ALTER TABLE ujaja_ca ADD COLUMN ca_private_key TEXT')
        cursor.execute('PRAGMA table_info(ujaja_digital_ids)')
        did_columns = [row['name'] for row in cursor.fetchall()]
        if 'certificate_pem' not in did_columns:
            conn.execute('ALTER TABLE ujaja_digital_ids ADD COLUMN certificate_pem TEXT')
        if 'employee_id' not in did_columns:
            conn.execute('ALTER TABLE ujaja_digital_ids ADD COLUMN employee_id INTEGER REFERENCES employees(id) ON DELETE CASCADE')
        if 'is_approved' not in did_columns:
            conn.execute('ALTER TABLE ujaja_digital_ids ADD COLUMN is_approved INTEGER DEFAULT 0')
        if 'is_ready' not in did_columns:
            conn.execute('ALTER TABLE ujaja_digital_ids ADD COLUMN is_ready INTEGER DEFAULT 0')
        if 'is_sent' not in did_columns:
            conn.execute('ALTER TABLE ujaja_digital_ids ADD COLUMN is_sent INTEGER DEFAULT 0')
        if 'is_revoked' not in did_columns:
            conn.execute('ALTER TABLE ujaja_digital_ids ADD COLUMN is_revoked INTEGER DEFAULT 0')
        if 'passphrase' not in did_columns:
            conn.execute('ALTER TABLE ujaja_digital_ids ADD COLUMN passphrase TEXT')
        if 'passphrase_hash' not in did_columns:
            conn.execute('ALTER TABLE ujaja_digital_ids ADD COLUMN passphrase_hash TEXT')
        if 'role' not in did_columns:
            conn.execute("ALTER TABLE ujaja_digital_ids ADD COLUMN role TEXT DEFAULT 'Dosen'")
        cursor.execute('PRAGMA table_info(ujaja_sign_requests)')
        sign_columns = [row['name'] for row in cursor.fetchall()]
        if 'download_token' not in sign_columns:
            conn.execute('ALTER TABLE ujaja_sign_requests ADD COLUMN download_token TEXT')
        if 'signer_ip_address' not in sign_columns:
            conn.execute('ALTER TABLE ujaja_sign_requests ADD COLUMN signer_ip_address TEXT')
        if 'signer_user_agent' not in sign_columns:
            conn.execute('ALTER TABLE ujaja_sign_requests ADD COLUMN signer_user_agent TEXT')
        if 'server_ssl_expires_at' not in sign_columns:
            conn.execute('ALTER TABLE ujaja_sign_requests ADD COLUMN server_ssl_expires_at TEXT')
        cursor.execute('PRAGMA table_info(audit_logs)')
        audit_columns = [row['name'] for row in cursor.fetchall()]
        if 'ip_address' not in audit_columns:
            conn.execute('ALTER TABLE audit_logs ADD COLUMN ip_address TEXT')
        if 'user_agent' not in audit_columns:
            conn.execute('ALTER TABLE audit_logs ADD COLUMN user_agent TEXT')
        if 'status' not in audit_columns:
            conn.execute('ALTER TABLE audit_logs ADD COLUMN status TEXT')