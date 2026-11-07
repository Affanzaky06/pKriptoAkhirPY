# securegov/utils/config.py
"""
Global configuration constants for SecureGov.
Sensitive values (keys, paths) are loaded from environment variables
or fall back to safe defaults for local development.
"""

import os

# ---------------------------------------------------------------------------
# USB Dongle settings
# ---------------------------------------------------------------------------
# The secret file that must exist on the plugged-in USB drive to be recognised
# as a valid dongle.  The file should contain exactly the bytes in DONGLE_SECRET.
DONGLE_SECRET_FILENAME: str = ".securegov_dongle.key"
DONGLE_SECRET_VALUE: bytes  = b"SECUREGOV_DONGLE_v1_2024"

# ---------------------------------------------------------------------------
# Session / AES settings
# ---------------------------------------------------------------------------
# 32-byte key used to encrypt session tokens (AES-256).
# In production this MUST come from a secure key-management service.
SESSION_AES_KEY: bytes = os.environ.get(
    "SESSION_AES_KEY",
    "SecureGovSess32ByteKey!!12345678"   # exactly 32 ASCII chars
).encode()[:32]

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DB_PATH: str = os.environ.get("SECUREGOV_DB", "data/securegov.db")

# AES-GCM key for encrypting sensitive DB columns (32 bytes / 256-bit).
DB_AES_KEY: bytes = os.environ.get(
    "DB_AES_KEY",
    "DBSecureGov32ByteAESGCMKey!!9999"
).encode()[:32]

# ---------------------------------------------------------------------------
# RSA key paths (file encryption module)
# ---------------------------------------------------------------------------
RSA_PRIVATE_KEY_PATH: str = os.environ.get("RSA_PRIVATE_KEY", "data/rsa_private.pem")
RSA_PUBLIC_KEY_PATH:  str = os.environ.get("RSA_PUBLIC_KEY",  "data/rsa_public.pem")
FERNET_KEY_PATH:      str = os.environ.get("FERNET_KEY",      "data/fernet.key")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
LOG_FILE:  str = os.environ.get("LOG_FILE",  "data/securegov.log")

