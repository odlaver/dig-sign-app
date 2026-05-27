import base64
import hashlib
import hmac
import os


HASH_NAME = "sha256"
ITERATIONS = 260_000
SALT_BYTES = 16


def hash_secret(secret: str) -> str:
    if not secret:
        raise ValueError("Secret tidak boleh kosong.")

    salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        HASH_NAME,
        secret.encode("utf-8"),
        salt,
        ITERATIONS,
    )
    return "pbkdf2_sha256${}${}${}".format(
        ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_secret(secret: str, stored_hash: str | None) -> bool:
    if not secret or not stored_hash:
        return False

    try:
        algorithm, iterations, salt_b64, digest_b64 = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected_digest = base64.b64decode(digest_b64)
        actual_digest = hashlib.pbkdf2_hmac(
            HASH_NAME,
            secret.encode("utf-8"),
            salt,
            int(iterations),
        )
    except (ValueError, TypeError):
        return False

    return hmac.compare_digest(actual_digest, expected_digest)
