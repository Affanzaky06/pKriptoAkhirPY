# securegov/utils/key_manager.py
"""
RSA key-pair generation and persistence helper.

Usage
-----
    from securegov.utils.key_manager import KeyManager
    km = KeyManager()
    km.generate_rsa_keypair()          # writes PEM files to data/
    pub  = km.load_public_key()
    priv = km.load_private_key()
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from securegov.utils.config import RSA_PRIVATE_KEY_PATH, RSA_PUBLIC_KEY_PATH
from securegov.utils.logger import get_logger

logger = get_logger(__name__)


class KeyManager:
    """Manages RSA-2048 key-pair generation, storage, and loading."""

    def __init__(
        self,
        private_key_path: str = RSA_PRIVATE_KEY_PATH,
        public_key_path: str  = RSA_PUBLIC_KEY_PATH,
    ) -> None:
        self.private_key_path = private_key_path
        self.public_key_path  = public_key_path
        os.makedirs(os.path.dirname(private_key_path) or ".", exist_ok=True)

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------
    def generate_rsa_keypair(self, key_size: int = 2048) -> None:
        """Generate an RSA key-pair and persist both keys as PEM files."""
        logger.info("Generating RSA-%d key-pair …", key_size)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        # Serialise private key (PKCS8, unencrypted — encrypt in production!)
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Serialise public key (SubjectPublicKeyInfo)
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(self.private_key_path, "wb") as f:
            f.write(priv_pem)
        with open(self.public_key_path, "wb") as f:
            f.write(pub_pem)
        logger.info("Key-pair written to %s / %s", self.private_key_path, self.public_key_path)

    # ------------------------------------------------------------------
    # Key loading
    # ------------------------------------------------------------------
    def load_private_key(self):
        """Load the RSA private key from disk."""
        with open(self.private_key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def load_public_key(self):
        """Load the RSA public key from disk."""
        with open(self.public_key_path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

