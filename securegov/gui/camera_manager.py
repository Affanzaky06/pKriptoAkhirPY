# securegov/gui/camera_manager.py
"""
Hardware Camera Manager & Device Enumerator
===========================================
Provides resilient webcam initialization, multi-camera index enumeration,
reconnect logic with DirectShow/MSMF fallback, and safe resource disposal.
"""

import sys
import time
from typing import Optional, List
import cv2
import numpy as np

from securegov.utils.logger import get_logger

logger = get_logger(__name__)


def list_available_cameras(max_tested: int = 3) -> List[int]:
    """
    Probe video device indices [0..max_tested-1] to discover connected webcams.
    Returns a list of integer camera indices that successfully opened.
    """
    available_indices = []
    for idx in range(max_tested):
        cap = None
        try:
            backend = cv2.CAP_DSHOW if sys.platform == "win32" else cv2.CAP_ANY
            cap = cv2.VideoCapture(idx, backend)
            if cap is not None and cap.isOpened():
                available_indices.append(idx)
        except Exception as exc:
            logger.debug("Probe camera index %d failed: %s", idx, exc)
        finally:
            if cap is not None:
                try:
                    cap.release()
                except Exception:
                    pass

    # Fallback to at least index 0 if detection returns empty
    if not available_indices:
        available_indices = [0]

    return available_indices


def open_camera(index: int = 0, retry_count: int = 2) -> Optional[cv2.VideoCapture]:
    """
    Open camera with fallback backends and retry attempts to avoid 'busy resource' errors.

    Parameters
    ----------
    index : int
        Camera device index (0, 1, ...).
    retry_count : int
        Number of retry attempts if device initially fails.

    Returns
    -------
    cv2.VideoCapture or None
    """
    for attempt in range(1, retry_count + 1):
        try:
            # On Windows, try DirectShow first as it provides fast locking and native resolution
            if sys.platform == "win32":
                cap = cv2.VideoCapture(index, cv2.CAP_DSHOW)
                if cap.isOpened():
                    ret, frame = cap.read()
                    if ret and frame is not None:
                        logger.info("Camera %d opened via CAP_DSHOW (attempt %d)", index, attempt)
                        return cap
                    cap.release()

            # Fallback to default backend
            cap = cv2.VideoCapture(index)
            if cap.isOpened():
                ret, frame = cap.read()
                if ret and frame is not None:
                    logger.info("Camera %d opened via DEFAULT backend (attempt %d)", index, attempt)
                    return cap
                cap.release()

        except Exception as exc:
            logger.warning("Attempt %d to open camera %d failed: %s", attempt, index, exc)

        time.sleep(0.2)

    logger.error("Unable to open camera at index %d after %d attempts", index, retry_count)
    return None


def safe_release_camera(cap: Optional[cv2.VideoCapture]) -> None:
    """Safely release a VideoCapture resource without throwing exceptions."""
    if cap is not None:
        try:
            cap.release()
        except Exception as exc:
            logger.debug("Exception while releasing camera: %s", exc)
