import logging
from pathlib import Path
from core.database import get_connection, DATA_DIR
siem_logger = logging.getLogger('siem_audit')
siem_logger.setLevel(logging.INFO)
siem_log_path = DATA_DIR / 'external_audit.log'
if not siem_logger.handlers:
    handler = logging.FileHandler(siem_log_path, mode='a', encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s - USER_ID:%(user_id)s - ACTION:%(action)s - %(message)s')
    handler.setFormatter(formatter)
    siem_logger.addHandler(handler)

def log_action(user_id: int | None, action: str, description: str, status: str='SUCCESS', ip_address: str=None, user_agent: str=None) -> None:
    if not ip_address or not user_agent:
        try:
            from flask import request
            if request:
                ip_address = ip_address or request.remote_addr
                user_agent = user_agent or request.user_agent.string
        except Exception:
            pass
    siem_logger.info(f'[STATUS:{status}] [IP:{ip_address}] [UA:{user_agent}] {description}', extra={'user_id': user_id or 'SYSTEM', 'action': action})
    with get_connection() as conn:
        conn.execute('\n            INSERT INTO audit_logs (user_id, action, description, ip_address, user_agent, status)\n            VALUES (?, ?, ?, ?, ?, ?)\n            ', (user_id, action, description, ip_address, user_agent, status))

def list_recent_logs(limit: int=100):
    with get_connection() as conn:
        return conn.execute('\n            SELECT audit_logs.*, users.name AS user_name, users.email AS user_email\n            FROM audit_logs\n            LEFT JOIN users ON users.id = audit_logs.user_id\n            ORDER BY audit_logs.created_at DESC, audit_logs.id DESC\n            LIMIT ?\n            ', (limit,)).fetchall()