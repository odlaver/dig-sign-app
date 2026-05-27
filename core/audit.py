from core.database import get_connection


def log_action(user_id: int | None, action: str, description: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (user_id, action, description)
            VALUES (?, ?, ?)
            """,
            (user_id, action, description),
        )


def list_recent_logs(limit: int = 100):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT audit_logs.*, users.name AS user_name, users.email AS user_email
            FROM audit_logs
            LEFT JOIN users ON users.id = audit_logs.user_id
            ORDER BY audit_logs.created_at DESC, audit_logs.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
