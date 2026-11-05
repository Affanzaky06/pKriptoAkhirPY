# securegov/database/db_crypto.py
"""
Database Column Encryption (AES-256-GCM)
==========================================
Helper functions and a context-manager wrapper for encrypting sensitive
SQLite column values before storage and decrypting them on retrieval.

Why AES-GCM?
------------
* **Confidentiality** — data is encrypted.
* **Integrity / Authenticity** — the GCM tag detects any tampering with
  the stored ciphertext (column-level protection against in-place edits).
* **Non-deterministic** — a fresh 12-byte nonce per encryption means two
  encryptions of the same value produce different ciphertexts, preventing
  frequency analysis.

Storage format (single base64 string)
--------------------------------------
  base64( nonce[12] || ciphertext || tag[16] )

The tag is appended by ``AESGCM.encrypt``; the nonce is prepended manually.

Usage
-----
    from securegov.database.db_crypto import DBColumnCrypto

    cc = DBColumnCrypto()   # uses DB_AES_KEY from config
    blob   = cc.encrypt("John Doe")          # store this in SQLite
    plain  = cc.decrypt(blob)                 # "John Doe"
    assert plain == "John Doe"
"""

import base64
import os
import secrets
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securegov.utils.config import DB_AES_KEY
from securegov.utils.logger import get_logger

logger = get_logger(__name__)


class DBColumnCrypto:
    """
    Encrypts / decrypts individual database column values using AES-256-GCM.

    Parameters
    ----------
    key : bytes, optional
        32-byte AES key.  Defaults to ``DB_AES_KEY`` from config.
    aad : bytes, optional
        Additional authenticated data (e.g. table name + column name) to bind
        ciphertext to its intended location, preventing copy-paste attacks
        across columns.  Defaults to ``b"SecureGov-DB-v1"``.
    """

    def __init__(
        self,
        key: bytes = DB_AES_KEY,
        aad: bytes = b"SecureGov-DB-v1",
    ) -> None:
        if len(key) != 32:
            raise ValueError("DB_AES_KEY must be exactly 32 bytes.")
        self._aes = AESGCM(key)
        self._aad = aad

    # --- public API --------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt *plaintext* and return a base64-encoded string safe for
        storage in a SQLite TEXT column.
        """
        nonce = secrets.token_bytes(12)
        # AESGCM.encrypt returns ciphertext‖tag
        ct_with_tag = self._aes.encrypt(nonce, plaintext.encode("utf-8"), self._aad)
        blob = base64.b64encode(nonce + ct_with_tag).decode("ascii")
        logger.debug("DBColumn encrypted %d chars → %d-char blob.", len(plaintext), len(blob))
        return blob

    def decrypt(self, blob: str) -> str:
        """
        Decrypt a *blob* produced by :meth:`encrypt`.

        Raises
        ------
        cryptography.exceptions.InvalidTag
            If the ciphertext or tag has been tampered with.
        ValueError
            If *blob* is malformed.
        """
        try:
            raw   = base64.b64decode(blob.encode("ascii"))
            nonce = raw[:12]
            ct    = raw[12:]
            pt    = self._aes.decrypt(nonce, ct, self._aad)
            return pt.decode("utf-8")
        except (ValueError, Exception) as exc:
            logger.error("DBColumn decryption failed: %s", exc)
            raise

    def encrypt_or_null(self, value: Optional[str]) -> Optional[str]:
        """Encrypt *value* if not ``None``; return ``None`` otherwise."""
        return self.encrypt(value) if value is not None else None

    def decrypt_or_null(self, blob: Optional[str]) -> Optional[str]:
        """Decrypt *blob* if not ``None``; return ``None`` otherwise."""
        return self.decrypt(blob) if blob is not None else None

