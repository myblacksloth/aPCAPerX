"""
PostgreSQL-backed user, session, MFA, and passkey storage.

The functions are intentionally thin and explicit so the auth surface remains
auditable and can evolve into a richer user-management module later.
"""

import base64
import hashlib
import hmac
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import psycopg
from psycopg.rows import dict_row

from config import (
    DATABASE_URL,
    DEFAULT_DEMO_PASSWORD,
    DEFAULT_DEMO_USER_ENABLED,
    DEFAULT_DEMO_USERNAME,
    SESSION_SECRET,
    SESSION_TTL_HOURS,
)

try:
    import crypt  # type: ignore
except ImportError:  # pragma: no cover - Linux container provides crypt.
    crypt = None


def _conn():
    """Open a PostgreSQL connection using dict rows for simple JSON shaping."""
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def _utc_now() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(timezone.utc)


def _unix_hash(secret: str) -> str:
    """Hash secrets with a Unix-style SHA-512 crypt hash."""
    if crypt is None:
        raise RuntimeError("Unix crypt hashing is unavailable on this platform.")
    salt = "$6$" + secrets.token_urlsafe(16)[:16]
    return crypt.crypt(secret, salt)


def _verify_unix_hash(secret: str, secret_hash: str) -> bool:
    """Verify a plaintext secret against a stored Unix crypt hash."""
    if crypt is None or not secret_hash:
        return False
    return hmac.compare_digest(crypt.crypt(secret, secret_hash), secret_hash)


def _session_hash(token: str) -> str:
    """Store only a keyed hash of session tokens in the database."""
    return hmac.new(SESSION_SECRET.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_recovery_codes(count: int = 10) -> List[str]:
    """Create human-typable recovery codes."""
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(count)]


def _totp_code(secret: str, step: int) -> str:
    """Generate one RFC 6238 TOTP code for a time step."""
    key = base64.b32decode(secret, casefold=True)
    msg = step.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Verify a TOTP code allowing a small clock-skew window."""
    normalized = "".join(char for char in code if char.isdigit())
    if len(normalized) != 6:
        return False
    current_step = int(time.time() // 30)
    for step in range(current_step - window, current_step + window + 1):
        if hmac.compare_digest(_totp_code(secret, step), normalized):
            return True
    return False


def generate_totp_secret() -> str:
    """Create a base32 TOTP secret compatible with authenticator apps."""
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def init_auth_db() -> None:
    """Create auth tables and seed the demo user if configured."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    totp_secret TEXT,
                    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_recovery_codes (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    code TEXT NOT NULL,
                    code_hash TEXT NOT NULL,
                    used_at TIMESTAMPTZ
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    expires_at TIMESTAMPTZ NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS webauthn_challenges (
                    id UUID PRIMARY KEY,
                    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                    username TEXT,
                    challenge TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_passkeys (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    credential_id TEXT NOT NULL UNIQUE,
                    public_key TEXT NOT NULL,
                    sign_count BIGINT NOT NULL DEFAULT 0,
                    label TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    last_used_at TIMESTAMPTZ
                )
            """)
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT")
            cur.execute("UPDATE users SET display_name = username WHERE display_name IS NULL")
            cur.execute("ALTER TABLE users ALTER COLUMN display_name SET NOT NULL")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE")
        # Commit schema changes before opening the separate seed-user connection.
        conn.commit()

        if DEFAULT_DEMO_USER_ENABLED:
            ensure_user(DEFAULT_DEMO_USERNAME, DEFAULT_DEMO_PASSWORD, "Demo")


def ensure_user(username: str, password: str, display_name: Optional[str] = None) -> Dict[str, Any]:
    """Create a user with recovery codes if it does not already exist."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            existing = cur.fetchone()
            if existing:
                return existing
            user_id = uuid.uuid4()
            cur.execute(
                "INSERT INTO users (id, username, password_hash, display_name) VALUES (%s, %s, %s, %s) RETURNING *",
                (user_id, username, _unix_hash(password), display_name or username),
            )
            user = cur.fetchone()
            for code in generate_recovery_codes():
                cur.execute(
                    "INSERT INTO user_recovery_codes (id, user_id, code, code_hash) VALUES (%s, %s, %s, %s)",
                    (uuid.uuid4(), user_id, code, _unix_hash(code)),
                )
            return user


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Return one user by username."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        return cur.fetchone()


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Return one user by id."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        return cur.fetchone()


def verify_password(user: Dict[str, Any], password: str) -> bool:
    """Verify a user password."""
    return _verify_unix_hash(password, user["password_hash"])


def verify_recovery_code(user_id: str, code: str) -> bool:
    """Consume one recovery code if it matches."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM user_recovery_codes WHERE user_id = %s AND used_at IS NULL", (user_id,))
        for row in cur.fetchall():
            if _verify_unix_hash(code, row["code_hash"]):
                cur.execute("UPDATE user_recovery_codes SET used_at = now() WHERE id = %s", (row["id"],))
                return True
    return False


def create_session(user_id: str) -> str:
    """Create a new opaque session token."""
    token = secrets.token_urlsafe(32)
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (%s, %s, %s, %s)",
            (uuid.uuid4(), user_id, _session_hash(token), _utc_now() + timedelta(hours=SESSION_TTL_HOURS)),
        )
    return token


def get_user_by_session(token: str) -> Optional[Dict[str, Any]]:
    """Resolve a session token to its user."""
    if not token:
        return None
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT users.* FROM user_sessions
            JOIN users ON users.id = user_sessions.user_id
            WHERE user_sessions.token_hash = %s AND user_sessions.expires_at > now()
            """,
            (_session_hash(token),),
        )
        return cur.fetchone()


def delete_session(token: str) -> None:
    """Delete one session token."""
    if not token:
        return
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM user_sessions WHERE token_hash = %s", (_session_hash(token),))


def user_profile(user: Dict[str, Any]) -> Dict[str, Any]:
    """Return profile data including recovery codes and passkey metadata."""
    user_id = str(user["id"])
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT code, used_at FROM user_recovery_codes WHERE user_id = %s ORDER BY id",
            (user_id,),
        )
        recovery_codes = cur.fetchall()
        cur.execute(
            "SELECT id, label, created_at, last_used_at FROM user_passkeys WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,),
        )
        passkeys = cur.fetchall()
    return {
        "id": user_id,
        "username": user["username"],
        "display_name": user["display_name"],
        "totp_enabled": bool(user["totp_enabled"]),
        "recovery_codes": recovery_codes,
        "passkeys": passkeys,
    }


def start_totp_setup(user_id: str) -> str:
    """Create and store a pending TOTP secret."""
    secret = generate_totp_secret()
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("UPDATE users SET totp_secret = %s, totp_enabled = FALSE WHERE id = %s", (secret, user_id))
    return secret


def enable_totp(user_id: str, code: str) -> bool:
    """Enable TOTP after validating the first code."""
    user = get_user_by_id(user_id)
    if not user or not user.get("totp_secret"):
        return False
    if not verify_totp(user["totp_secret"], code):
        return False
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("UPDATE users SET totp_enabled = TRUE WHERE id = %s", (user_id,))
    return True


def disable_totp(user_id: str) -> None:
    """Disable TOTP for the current user."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = %s", (user_id,))


def save_challenge(challenge: str, purpose: str, user_id: Optional[str] = None, username: Optional[str] = None) -> None:
    """Persist a WebAuthn challenge for one registration or login flow."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO webauthn_challenges (id, user_id, username, challenge, purpose) VALUES (%s, %s, %s, %s, %s)",
            (uuid.uuid4(), user_id, username, challenge, purpose),
        )


def pop_challenge(challenge: str, purpose: str) -> Optional[Dict[str, Any]]:
    """Load and delete a WebAuthn challenge after use."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM webauthn_challenges WHERE challenge = %s AND purpose = %s RETURNING *",
            (challenge, purpose),
        )
        return cur.fetchone()


def pop_latest_challenge(purpose: str, user_id: Optional[str] = None, username: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Load and delete the latest WebAuthn challenge for one user flow."""
    with _conn() as conn, conn.cursor() as cur:
        if user_id:
            cur.execute(
                """
                DELETE FROM webauthn_challenges
                WHERE id = (
                    SELECT id FROM webauthn_challenges
                    WHERE purpose = %s AND user_id = %s
                    ORDER BY created_at DESC
                    LIMIT 1
                )
                RETURNING *
                """,
                (purpose, user_id),
            )
        else:
            cur.execute(
                """
                DELETE FROM webauthn_challenges
                WHERE id = (
                    SELECT id FROM webauthn_challenges
                    WHERE purpose = %s AND username = %s
                    ORDER BY created_at DESC
                    LIMIT 1
                )
                RETURNING *
                """,
                (purpose, username),
            )
        return cur.fetchone()


def add_passkey(user_id: str, credential_id: str, public_key: str, sign_count: int, label: str) -> None:
    """Store a verified passkey credential."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO user_passkeys (id, user_id, credential_id, public_key, sign_count, label)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (credential_id) DO UPDATE
            SET public_key = EXCLUDED.public_key, sign_count = EXCLUDED.sign_count, label = EXCLUDED.label
            """,
            (uuid.uuid4(), user_id, credential_id, public_key, sign_count, label),
        )


def get_passkey_by_credential(credential_id: str) -> Optional[Dict[str, Any]]:
    """Return one passkey by credential id."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM user_passkeys WHERE credential_id = %s", (credential_id,))
        return cur.fetchone()


def list_user_passkeys(user_id: str) -> List[Dict[str, Any]]:
    """Return passkeys registered by one user."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM user_passkeys WHERE user_id = %s", (user_id,))
        return cur.fetchall()


def update_passkey_usage(credential_id: str, sign_count: int) -> None:
    """Update sign count and last-used timestamp after passkey login."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE user_passkeys SET sign_count = %s, last_used_at = now() WHERE credential_id = %s",
            (sign_count, credential_id),
        )
