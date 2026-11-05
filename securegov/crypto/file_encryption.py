# securegov/crypto/file_encryption.py
"""
File Encryption Module
========================
Encrypts and decrypts documents (PDF, DOCX, etc.) using two independent
strategies:

  1. **RSA + AES-256-GCM hybrid encryption** (``RSAHybridFileEncryptor``)
     Recommended for sharing encrypted files between parties:
       * A fresh AES-256 key is generated for each file.
       * The file body is encrypted with AES-256-GCM.
       * The AES key is encrypted with the recipient's RSA-2048 public key.
       * Both parts are written into a single ``.sgvault`` container file.

  2. **Fernet symmetric encryption** (``FernetFileEncryptor``)
     Simpler — good for single-party at-rest encryption:
       * Uses ``cryptography.fernet.Fernet`` (AES-128-CBC + HMAC-SHA256).
       * Encrypted file is written with a ``.fen`` extension.

Both classes expose a uniform ``encrypt_file`` / ``decrypt_file`` interface.

Usage
-----
    # --- RSA hybrid ---
    from securegov.crypto.file_encryption import RSAHybridFileEncryptor
    from securegov.utils.key_manager import KeyManager

    km = KeyManager()
    km.generate_rsa_keypair()

    enc = RSAHybridFileEncryptor(km.load_public_key(), km.load_private_key())
    enc.encrypt_file("report.pdf", "report.sgvault")
    enc.decrypt_file("report.sgvault", "report_decrypted.pdf")

    # --- Fernet ---
    from securegov.crypto.file_encryption import FernetFileEncryptor
    enc = FernetFileEncryptor()          # auto-generates key
    enc.encrypt_file("report.pdf", "report.fen")
    enc.decrypt_file("report.fen", "report_decrypted.pdf")
"""

import os
import struct
import secrets
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet

from securegov.utils.logger import get_logger

logger = get_logger(__name__)

# ===========================================================================
# RSA + AES-256-GCM Hybrid Encryptor
# ===========================================================================

class RSAHybridFileEncryptor:
    """
    Hybrid file encryptor: RSA-OAEP wraps a per-file AES-256-GCM key.

    Container format (.sgvault)
    ---------------------------
    Bytes  0–3   : magic  b"SGVT"
    Bytes  4–7   : version uint32-LE = 1
    Bytes  8–11  : encrypted_key_len (uint32-LE)
    Bytes 12–23  : AES nonce (12 bytes)
    Bytes 24–(24+ekl-1) : RSA-OAEP encrypted AES key
    Remaining    : AES-GCM ciphertext (body + 16-byte tag)
    """

    _MAGIC   = b"SGVT"
    _VERSION = 1
    _AAD     = b"SecureGov-FileVault-v1"

    def __init__(self, public_key=None, private_key=None) -> None:
        """
        Parameters
        ----------
        public_key  : RSA public key object (from ``cryptography`` library).
                      Required for encryption.
        private_key : RSA private key object.
                      Required for decryption.
        """
        self._pub  = public_key
        self._priv = private_key

    # --- internal ----------------------------------------------------------

    def _rsa_encrypt_key(self, aes_key: bytes) -> bytes:
        return self._pub.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def _rsa_decrypt_key(self, encrypted_key: bytes) -> bytes:
        return self._priv.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    # --- public API --------------------------------------------------------

    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Encrypt the file at *input_path* and write the vault container to
        *output_path*.
        """
        if self._pub is None:
            raise RuntimeError("Public key required for encryption.")

        with open(input_path, "rb") as f:
            plaintext = f.read()

        # Generate fresh AES-256 key and nonce
        aes_key    = secrets.token_bytes(32)
        nonce      = secrets.token_bytes(12)
        aes        = AESGCM(aes_key)
        ciphertext = aes.encrypt(nonce, plaintext, self._AAD)

        # RSA-OAEP wrap the AES key
        encrypted_aes_key = self._rsa_encrypt_key(aes_key)
        ekl = len(encrypted_aes_key)

        # Write container
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(self._MAGIC)
            f.write(struct.pack("<I", self._VERSION))
            f.write(struct.pack("<I", ekl))
            f.write(nonce)
            f.write(encrypted_aes_key)
            f.write(ciphertext)

        logger.info(
            "RSAHybrid: '%s' (%d bytes) → '%s' (%d bytes).",
            input_path, len(plaintext), output_path, os.path.getsize(output_path)
        )

    def decrypt_file(self, vault_path: str, output_path: str) -> None:
        """Decrypt a ``.sgvault`` container and write the original file."""
        if self._priv is None:
            raise RuntimeError("Private key required for decryption.")

        with open(vault_path, "rb") as f:
            magic   = f.read(4)
            if magic != self._MAGIC:
                raise ValueError(f"Not a valid SecureGov vault file: {vault_path}")
            _version = struct.unpack("<I", f.read(4))[0]
            ekl      = struct.unpack("<I", f.read(4))[0]
            nonce    = f.read(12)
            enc_aes  = f.read(ekl)
            body     = f.read()

        aes_key   = self._rsa_decrypt_key(enc_aes)
        aes       = AESGCM(aes_key)
        plaintext = aes.decrypt(nonce, body, self._AAD)

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(plaintext)

        logger.info(
            "RSAHybrid: '%s' decrypted → '%s' (%d bytes).",
            vault_path, output_path, len(plaintext)
        )


# ===========================================================================
# Fernet Symmetric File Encryptor
# ===========================================================================

class FernetFileEncryptor:
    """
    Simple symmetric file encryptor using Fernet (AES-128-CBC + HMAC-SHA256).

    Good for single-party at-rest encryption where key distribution is not
    a concern.  Store the ``key`` attribute securely (e.g. in a HSM or KMS).

    Parameters
    ----------
    key : bytes, optional
        A URL-safe base64-encoded 32-byte Fernet key.  If ``None``, a new
        key is generated and stored in ``self.key``.
    """

    def __init__(self, key: Optional[bytes] = None) -> None:
        self.key = key or Fernet.generate_key()
        self._fernet = Fernet(self.key)
        logger.debug("FernetFileEncryptor ready (key=%s…).", self.key[:8].decode())

    def save_key(self, path: str) -> None:
        """Persist the Fernet key to *path* (protect this file!)."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(self.key)
        logger.info("Fernet key saved to '%s'.", path)

    @classmethod
    def from_key_file(cls, path: str) -> "FernetFileEncryptor":
        """Load a previously saved key and return a new instance."""
        with open(path, "rb") as f:
            key = f.read().strip()
        return cls(key=key)

    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """Encrypt *input_path* and write Fernet token to *output_path*."""
        with open(input_path, "rb") as f:
            data = f.read()
        token = self._fernet.encrypt(data)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(token)
        logger.info("Fernet: '%s' → '%s'.", input_path, output_path)

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Decrypt a Fernet-encrypted file and restore original content."""
        with open(input_path, "rb") as f:
            token = f.read()
        data = self._fernet.decrypt(token)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(data)
        logger.info("Fernet: '%s' decrypted → '%s'.", input_path, output_path)

