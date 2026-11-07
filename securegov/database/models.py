# securegov/database/models.py
"""
SQLite Database Models & Repository Layer
==========================================
Provides:
  * ``init_db``        — creates all tables (safe to call multiple times).
  * ``UserRepository`` — CRUD for the ``users`` table with encrypted columns.
  * ``DocumentRepository`` — stores document metadata with encrypted notes.
  * ``MessageRepository``  — stores super-encrypted message tokens.

All sensitive text columns are encrypted at the application layer with
:class:`~securegov.database.db_crypto.DBColumnCrypto` before being handed
to SQLite, so the database file is not plaintext-readable even if stolen.

Schema overview
---------------
    users(id, username, password_hash, full_name_enc, email_enc,
          role, created_at, is_active)

    documents(id, owner_id, filename, file_hash, encrypted_path,
              notes_enc, uploaded_at)

    messages(id, sender_id, recipient_id, subject_enc, body_token,
             sent_at, is_read)

    audit_log(id, actor_id, action, detail, timestamp)
"""

import os
import sqlite3
import hashlib
import time
from contextlib import contextmanager
from typing import Optional, Iterator

from securegov.database.db_crypto import DBColumnCrypto
from securegov.utils.config import DB_PATH
from securegov.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# DB connection helper
# ---------------------------------------------------------------------------

def _get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    """Context manager that opens a connection and auto-commits / rolls back."""
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    UNIQUE NOT NULL,
    password_hash   TEXT    NOT NULL,
    full_name_enc   TEXT,                    -- AES-GCM encrypted
    email_enc       TEXT,                    -- AES-GCM encrypted
    registered_vsn  TEXT,                    -- USB Dongle Volume Serial Number
    face_registered INTEGER NOT NULL DEFAULT 0, -- 1 if face template enrolled
    role            TEXT    NOT NULL DEFAULT 'user',
    created_at      REAL    NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS documents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id       INTEGER NOT NULL REFERENCES users(id),
    filename       TEXT    NOT NULL,
    file_hash      TEXT    NOT NULL,       -- SHA-256 of original file
    encrypted_path TEXT    NOT NULL,       -- path to .sgvault / .fen file
    notes_enc      TEXT,                   -- AES-GCM encrypted notes
    uploaded_at    REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    subject_enc  TEXT    NOT NULL,         -- AES-GCM encrypted subject
    body_token   TEXT    NOT NULL,         -- super-encrypted body token
    sent_at      REAL    NOT NULL,
    is_read      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id  INTEGER,
    action    TEXT    NOT NULL,
    detail    TEXT,
    timestamp REAL    NOT NULL
);
"""


def init_db() -> None:
    """Create all tables and perform necessary column migrations."""
    with db_session() as conn:
        conn.executescript(_DDL)
        # Migrate columns if existing database had older schema
        try:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
            if "registered_vsn" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN registered_vsn TEXT")
            if "face_registered" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN face_registered INTEGER NOT NULL DEFAULT 0")
        except Exception as exc:
            logger.debug("Column migration notice: %s", exc)
    logger.info("Database initialised at '%s'.", DB_PATH)


# ---------------------------------------------------------------------------
# User Repository
# ---------------------------------------------------------------------------

class UserRepository:
    """CRUD operations for the ``users`` table."""

    def __init__(self, crypto: Optional[DBColumnCrypto] = None) -> None:
        self._cc = crypto or DBColumnCrypto()

    def create(
        self,
        username: str,
        password_hash: str,
        full_name: Optional[str] = None,
        email: Optional[str] = None,
        role: str = "user",
    ) -> int:
        """Insert a new user and return the new row ID."""
        full_name_enc = self._cc.encrypt_or_null(full_name)
        email_enc     = self._cc.encrypt_or_null(email)
        with db_session() as conn:
            cur = conn.execute(
                """INSERT INTO users
                   (username, password_hash, full_name_enc, email_enc, role, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (username, password_hash, full_name_enc, email_enc, role, time.time()),
            )
            uid = cur.lastrowid
        logger.info("User '%s' created (id=%d, role=%s).", username, uid, role)
        return uid

    def get_by_username(self, username: str) -> Optional[dict]:
        """Fetch a user by username, decrypting encrypted columns."""
        with db_session() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = 1",
                (username,),
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["full_name"] = self._cc.decrypt_or_null(d.pop("full_name_enc"))
        d["email"]     = self._cc.decrypt_or_null(d.pop("email_enc"))
        return d

    def update_dongle_vsn(self, user_id_or_name: str | int, vsn: str) -> None:
        """Associate a hardware USB Dongle VSN with a user."""
        with db_session() as conn:
            if isinstance(user_id_or_name, int):
                conn.execute("UPDATE users SET registered_vsn = ? WHERE id = ?", (vsn, user_id_or_name))
            else:
                conn.execute("UPDATE users SET registered_vsn = ? WHERE username = ?", (vsn, str(user_id_or_name)))
        logger.info("Updated registered_vsn for user %s -> %s", user_id_or_name, vsn)

    def update_face_status(self, user_id_or_name: str | int, status: int = 1) -> None:
        """Mark face biometric enrollment status for a user."""
        with db_session() as conn:
            if isinstance(user_id_or_name, int):
                conn.execute("UPDATE users SET face_registered = ? WHERE id = ?", (status, user_id_or_name))
            else:
                conn.execute("UPDATE users SET face_registered = ? WHERE username = ?", (status, str(user_id_or_name)))
        logger.info("Updated face_registered for user %s -> %s", user_id_or_name, status)

    def get_by_id(self, user_id: int) -> Optional[dict]:
        with db_session() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["full_name"] = self._cc.decrypt_or_null(d.pop("full_name_enc"))
        d["email"]     = self._cc.decrypt_or_null(d.pop("email_enc"))
        return d

    def deactivate(self, user_id: int) -> None:
        with db_session() as conn:
            conn.execute(
                "UPDATE users SET is_active = 0 WHERE id = ?", (user_id,)
            )
        logger.info("User id=%d deactivated.", user_id)

    def delete(self, user_id: int) -> None:
        """Permanently delete a user record from the database."""
        with db_session() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        logger.info("User id=%d permanently deleted.", user_id)

    def list_all_active(self) -> list[dict]:
        """Return all active users (for admin delete picker)."""
        with db_session() as conn:
            rows = conn.execute(
                "SELECT id, username, role, is_active FROM users WHERE is_active = 1 ORDER BY id ASC"
            ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Document Repository
# ---------------------------------------------------------------------------

class DocumentRepository:
    """CRUD operations for the ``documents`` table."""

    def __init__(self, crypto: Optional[DBColumnCrypto] = None) -> None:
        self._cc = crypto or DBColumnCrypto()

    @staticmethod
    def _hash_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def add_document(
        self,
        owner_id: int,
        filename: str,
        original_path: str,
        encrypted_path: str,
        notes: Optional[str] = None,
    ) -> int:
        file_hash = self._hash_file(original_path)
        notes_enc = self._cc.encrypt_or_null(notes)
        with db_session() as conn:
            cur = conn.execute(
                """INSERT INTO documents
                   (owner_id, filename, file_hash, encrypted_path, notes_enc, uploaded_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (owner_id, filename, file_hash, encrypted_path, notes_enc, time.time()),
            )
            doc_id = cur.lastrowid
        logger.info("Document '%s' stored (id=%d, sha256=%s…).", filename, doc_id, file_hash[:12])
        return doc_id

    def get_document(self, doc_id: int) -> Optional[dict]:
        with db_session() as conn:
            row = conn.execute(
                "SELECT * FROM documents WHERE id = ?", (doc_id,)
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["notes"] = self._cc.decrypt_or_null(d.pop("notes_enc"))
        return d

    def get_by_encrypted_path(self, encrypted_path: str) -> Optional[dict]:
        """Fetch document metadata by the path of its encrypted vault file."""
        with db_session() as conn:
            row = conn.execute(
                "SELECT * FROM documents WHERE encrypted_path = ? ORDER BY uploaded_at DESC LIMIT 1",
                (encrypted_path,),
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["notes"] = self._cc.decrypt_or_null(d.pop("notes_enc"))
        return d

    def list_by_owner(self, owner_id: int) -> list[dict]:
        with db_session() as conn:
            rows = conn.execute(
                "SELECT * FROM documents WHERE owner_id = ? ORDER BY uploaded_at DESC",
                (owner_id,),
            ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["notes"] = self._cc.decrypt_or_null(d.pop("notes_enc"))
            result.append(d)
        return result


# ---------------------------------------------------------------------------
# Message Repository
# ---------------------------------------------------------------------------

class MessageRepository:
    """Stores and retrieves super-encrypted messages."""

    def __init__(self, crypto: Optional[DBColumnCrypto] = None) -> None:
        self._cc = crypto or DBColumnCrypto()

    def send_message(
        self,
        sender_id: int,
        recipient_id: int,
        subject: str,
        body_token: str,  # already super-encrypted by the caller
    ) -> int:
        subject_enc = self._cc.encrypt(subject)
        with db_session() as conn:
            cur = conn.execute(
                """INSERT INTO messages
                   (sender_id, recipient_id, subject_enc, body_token, sent_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (sender_id, recipient_id, subject_enc, body_token, time.time()),
            )
            msg_id = cur.lastrowid
        logger.info("Message id=%d sent %d→%d.", msg_id, sender_id, recipient_id)
        return msg_id

    def get_inbox(self, recipient_id: int) -> list[dict]:
        with db_session() as conn:
            rows = conn.execute(
                "SELECT * FROM messages WHERE recipient_id = ? ORDER BY sent_at DESC",
                (recipient_id,),
            ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["subject"] = self._cc.decrypt(d.pop("subject_enc"))
            result.append(d)
        return result

    def mark_read(self, msg_id: int) -> None:
        with db_session() as conn:
            conn.execute("UPDATE messages SET is_read = 1 WHERE id = ?", (msg_id,))


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------

def log_audit(actor_id: Optional[int], action: str, detail: str = "") -> None:
    """Append an immutable audit record to the ``audit_log`` table."""
    with db_session() as conn:
        conn.execute(
            "INSERT INTO audit_log (actor_id, action, detail, timestamp) VALUES (?,?,?,?)",
            (actor_id, action, detail, time.time()),
        )
    logger.debug("Audit: actor=%s action=%s", actor_id, action)

