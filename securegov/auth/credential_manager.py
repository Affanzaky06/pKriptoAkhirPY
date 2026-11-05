# securegov/auth/credential_manager.py
"""
Login & Credential Cryptography
================================
Handles:
  * Password hashing / verification via **Argon2id** (with bcrypt fallback).
  * Encrypted session-token issuance and validation using **AES-128-CBC**.

Dependencies
------------
    pip install argon2-cffi bcrypt cryptography

Argon2id is the OWASP-recommended algorithm for password hashing (2024).
bcrypt is provided as a compatibility fallback.
"""

import os
import base64
import json
import time
import secrets
import hashlib
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from securegov.utils.config import SESSION_AES_KEY
from securegov.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Try to import Argon2; fall back to bcrypt if unavailable
# ---------------------------------------------------------------------------
try:
    from argon2 import PasswordHasher as _Argon2Hasher
    from argon2.exceptions import VerifyMismatchError as _ArgonMismatch

    _HASH_BACKEND = "argon2"
    _argon2 = _Argon2Hasher(
        time_cost=3,       # iterations
        memory_cost=65536, # 64 MiB
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )
    logger.debug("Password hashing backend: Argon2id")

except ImportError:
    try:
        import bcrypt as _bcrypt  # type: ignore
        _HASH_BACKEND = "bcrypt"
        logger.debug("Password hashing backend: bcrypt (Argon2 not installed)")
    except ImportError:
        _HASH_BACKEND = "sha256"
        logger.warning(
            "Neither argon2-cffi nor bcrypt is installed. "
            "Falling back to SHA-256+salt (NOT suitable for production)."
        )


# ===========================================================================
# Password Hashing
# ===========================================================================

def hash_password(password: str) -> str:
    """
    Hash *password* using the best available algorithm.

    Returns
    -------
    str
        A self-contained hash string (includes algorithm id, params, and salt)
        that can be stored directly in the database.
    """
    if _HASH_BACKEND == "argon2":
        hashed = _argon2.hash(password)
        logger.debug("Password hashed with Argon2id.")
        return hashed

    if _HASH_BACKEND == "bcrypt":
        salt = _bcrypt.gensalt(rounds=12)
        hashed = _bcrypt.hashpw(password.encode(), salt).decode()
        logger.debug("Password hashed with bcrypt.")
        return hashed

    # Fallback: SHA-256 + 16-byte hex salt
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"sha256${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify *password* against *stored_hash* produced by :func:`hash_password`.

    Returns
    -------
    bool  ``True`` if the password matches, ``False`` otherwise.
    """
    try:
        if stored_hash.startswith("$argon2"):
            _argon2.verify(stored_hash, password)
            return True

        if stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
            return _bcrypt.checkpw(password.encode(), stored_hash.encode())

        if stored_hash.startswith("sha256$"):
            _, salt, digest = stored_hash.split("$", 2)
            expected = hashlib.sha256((salt + password).encode()).hexdigest()
            return secrets.compare_digest(expected, digest)

    except Exception as exc:  # noqa: BLE001
        logger.warning("Password verification error: %s", exc)

    return False


# ===========================================================================
# Session Token (AES-128-CBC)
# ===========================================================================

class SessionManager:
    """
    Issues and validates AES-encrypted session tokens.

    Token payload (JSON, then AES-CBC encrypted + base64-encoded):
        {
            "user_id"  : str,
            "issued_at": float,   # Unix timestamp
            "expires_at": float,  # Unix timestamp
            "jti"      : str,     # random nonce (JWT ID analogue)
        }

    The first 16 bytes of the ciphertext are the IV (prepended before base64).
    """

    _KEY_SIZE = 16   # 128-bit AES key (first 16 bytes of SESSION_AES_KEY)

    def __init__(
        self,
        aes_key: bytes = SESSION_AES_KEY,
        token_ttl_seconds: int = 3600,
    ) -> None:
        # Use only the first 16 bytes for AES-128 (extend to 32 for AES-256)
        self._key = aes_key[: self._KEY_SIZE]
        self._ttl = token_ttl_seconds

    # --- internal helpers --------------------------------------------------

    @staticmethod
    def _pad(data: bytes) -> bytes:
        """PKCS7 pad *data* to a 16-byte block boundary."""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """Remove PKCS7 padding from *data*."""
        pad_len = data[-1]
        return data[:-pad_len]

    def _encrypt(self, plaintext: bytes) -> bytes:
        iv = secrets.token_bytes(16)
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ct = encryptor.update(self._pad(plaintext)) + encryptor.finalize()
        return iv + ct   # prepend IV

    def _decrypt(self, ciphertext: bytes) -> bytes:
        iv, ct = ciphertext[:16], ciphertext[16:]
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        return self._unpad(padded)

    # --- public API --------------------------------------------------------

    def issue_token(self, user_id: str) -> str:
        """
        Create and return a base64-encoded encrypted session token for *user_id*.
        """
        now = time.time()
        payload = json.dumps({
            "user_id":    user_id,
            "issued_at":  now,
            "expires_at": now + self._ttl,
            "jti":        secrets.token_hex(16),
        }).encode()

        token_bytes = self._encrypt(payload)
        token = base64.urlsafe_b64encode(token_bytes).decode()
        logger.info("Session token issued for user '%s' (TTL=%ds).", user_id, self._ttl)
        return token

    def validate_token(self, token: str) -> Optional[dict]:
        """
        Validate and decrypt *token*.

        Returns
        -------
        dict  The decoded payload if the token is valid and not expired.
        None  If the token is invalid or expired.
        """
        try:
            raw = base64.urlsafe_b64decode(token.encode())
            payload = json.loads(self._decrypt(raw))

            if time.time() > payload["expires_at"]:
                logger.warning("Session token for '%s' has expired.", payload.get("user_id"))
                return None

            logger.debug("Session token valid for '%s'.", payload.get("user_id"))
            return payload

        except Exception as exc:  # noqa: BLE001
            logger.warning("Token validation failed: %s", exc)
            return None

    def revoke_token(self, token: str) -> None:
        """
        Mark a token as revoked.

        A production implementation would store the ``jti`` in a Redis set or
        a DB blacklist table and check it in :meth:`validate_token`.
        This placeholder just logs the intent.
        """
        payload = self.validate_token(token)
        if payload:
            logger.info("Token jti=%s revoked for user '%s'.", payload["jti"], payload["user_id"])
        else:
            logger.warning("Attempted to revoke an invalid/expired token.")

