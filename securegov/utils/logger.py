# securegov/utils/logger.py
"""
Centralised logging setup for SecureGov.
Call `get_logger(__name__)` in every module to obtain a configured logger.
"""

import logging
import logging.handlers
import os
from securegov.utils.config import LOG_LEVEL, LOG_FILE


def get_logger(name: str) -> logging.Logger:
    """
    Return a module-level logger that writes to both the console and a
    rotating log file (max 5 MB × 3 backups).
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers when the same module is imported twice
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    try:
        ch = logging.StreamHandler(sys.stdout)
    except Exception:
        ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler (rotating)
    os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger

