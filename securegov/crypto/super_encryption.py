# securegov/crypto/super_encryption.py
"""
Super Encryption for Text Messages
=====================================
Implements a **two-layer** encryption pipeline for secure text messaging:

  Layer 1 (Classic)  — Vigenère or Playfair cipher
  Layer 2 (Modern)   — AES-256-GCM (authenticated encryption)

Encryption flow:
    plaintext  →  [Classic Cipher]  →  intermediate_ciphertext
               →  [AES-256-GCM]    →  final_ciphertext  (base64-encoded)

Decryption reverses the layers:
    final_ciphertext  →  [AES-256-GCM decrypt]  →  intermediate_ciphertext
                      →  [Classic Cipher decrypt] →  plaintext

The final ciphertext is a base64 JSON object that bundles the AES-GCM
components (nonce, tag, ciphertext) so only one opaque string needs to be
stored or transmitted.

Usage
-----
    from securegov.crypto.super_encryption import SuperEncryptor

    se = SuperEncryptor(
        aes_key    = b"<32-byte key>",    # 256-bit
        classic_key= "MYSECRET",          # Vigenère key
        classic_algo= "vigenere",         # or "playfair"
    )

    ciphertext = se.encrypt("Top secret government memo")
    plaintext  = se.decrypt(ciphertext)
"""

import base64
import json
import os
import secrets
from typing import Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securegov.crypto.classic_ciphers import VigenereCipher, PlayfairCipher
from securegov.utils.logger import get_logger

logger = get_logger(__name__)

ClassicAlgo = Literal["vigenere", "playfair"]


class SuperEncryptor:
    """
    Two-layer text encryptor: Classic cipher → AES-256-GCM.

    Parameters
    ----------
    aes_key      : bytes
        A 32-byte (256-bit) key for AES-GCM.
    classic_key  : str
        Keyword for the chosen classic cipher.
    classic_algo : str
        ``"vigenere"`` (default) or ``"playfair"``.
    aad          : bytes, optional
        Additional authenticated data passed to AES-GCM (not encrypted, but
        integrity-protected).  Useful for binding ciphertext to a user ID or
        document ID.
    """

    def __init__(
        self,
        aes_key: bytes,
        classic_key: str,
        classic_algo: ClassicAlgo = "vigenere",
        aad: bytes = b"SecureGov-SuperEncrypt-v1",
    ) -> None:
        if len(aes_key) != 32:
            raise ValueError("aes_key must be exactly 32 bytes (AES-256).")

        self._aes    = AESGCM(aes_key)
        self._aad    = aad
        self._classic = self._build_classic(classic_key, classic_algo)
        self._algo    = classic_algo
        logger.debug("SuperEncryptor ready: classic=%s, AES-256-GCM.", classic_algo)

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _build_classic(key: str, algo: ClassicAlgo):
        if algo == "vigenere":
            return VigenereCipher(key)
        if algo == "playfair":
            return PlayfairCipher(key)
        raise ValueError(f"Unknown classic algorithm: {algo!r}. Choose 'vigenere' or 'playfair'.")

    # --- public API --------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt *plaintext* through Classic → AES-256-GCM.

        Returns
        -------
        str
            Base64-encoded JSON token containing the nonce, GCM tag,
            and AES ciphertext.  Safe for storage in a database column.
        """
        # Layer 1: Classic cipher
        classic_ct = self._classic.encrypt(plaintext)
        logger.debug("Layer-1 (%s) produced %d chars.", self._algo, len(classic_ct))

        # Layer 2: AES-256-GCM
        nonce = secrets.token_bytes(12)   # 96-bit nonce recommended for GCM
        # AESGCM.encrypt returns ciphertext || tag (last 16 bytes)
        aes_ct_with_tag = self._aes.encrypt(nonce, classic_ct.encode(), self._aad)

        # Bundle into a single base64 JSON token
        bundle = {
            "v":   1,
            "alg": f"{self._algo}+aes256gcm",
            "n":   base64.b64encode(nonce).decode(),
            "c":   base64.b64encode(aes_ct_with_tag).decode(),
        }
        token = base64.urlsafe_b64encode(json.dumps(bundle).encode()).decode()
        logger.info("SuperEncrypt: %d-char plaintext → %d-char token.", len(plaintext), len(token))
        return token

    def decrypt(self, token: str) -> str:
        """
        Decrypt a token produced by :meth:`encrypt`.

        Returns
        -------
        str  The original plaintext.

        Raises
        ------
        ValueError  If the token is malformed or the AES-GCM tag is invalid.
        """
        try:
            bundle  = json.loads(base64.urlsafe_b64decode(token.encode()))
            nonce   = base64.b64decode(bundle["n"])
            aes_ct  = base64.b64decode(bundle["c"])
        except Exception as exc:
            raise ValueError(f"Malformed super-encryption token: {exc}") from exc

        # Layer 2 reverse: AES-256-GCM decrypt (raises InvalidTag on tamper)
        classic_ct_bytes = self._aes.decrypt(nonce, aes_ct, self._aad)
        classic_ct = classic_ct_bytes.decode()
        logger.debug("Layer-2 (AES-GCM) decrypted %d bytes.", len(classic_ct))

        # Layer 1 reverse: Classic cipher
        plaintext = self._classic.decrypt(classic_ct)
        logger.info("SuperDecrypt: %d-char token → %d-char plaintext.", len(token), len(plaintext))
        return plaintext


# ---------------------------------------------------------------------------
# Convenience functions using a default key (dev/demo only)
# ---------------------------------------------------------------------------

_DEFAULT_AES_KEY    = os.environ.get(
    "SUPER_ENC_AES_KEY", "SuperEncr32ByteKeyForDevOnly!!!!").encode()[:32]
_DEFAULT_CLASSIC_KEY = os.environ.get("SUPER_ENC_CLASSIC_KEY", "SECUREGOV")


def quick_encrypt(plaintext: str, classic_algo: ClassicAlgo = "vigenere") -> str:
    """Encrypt with default dev keys — do NOT use in production."""
    se = SuperEncryptor(_DEFAULT_AES_KEY, _DEFAULT_CLASSIC_KEY, classic_algo)
    return se.encrypt(plaintext)


def quick_decrypt(token: str, classic_algo: ClassicAlgo = "vigenere") -> str:
    """Decrypt with default dev keys — do NOT use in production."""
    se = SuperEncryptor(_DEFAULT_AES_KEY, _DEFAULT_CLASSIC_KEY, classic_algo)
    return se.decrypt(token)

