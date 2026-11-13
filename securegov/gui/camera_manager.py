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


def open_camera(index: int = 0, retry_count: int = 3) -> Optional[cv2.VideoCapture]:
    """
    Open camera with fallback backends, sensor warm-up, and retry attempts to avoid
    'busy resource' errors during rapid hardware toggle.

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
            # On Windows, DirectShow is fastest, avoids MSMF pipeline lockups, and captures native frames
            if sys.platform == "win32":
                cap = cv2.VideoCapture(index, cv2.CAP_DSHOW)
                if cap.isOpened():
                    # Warm-up loop: Give the hardware sensor up to 5 attempts (50ms interval)
                    # to deliver the first valid frame buffer
                    for _ in range(5):
                        ret, frame = cap.read()
                        if ret and frame is not None:
                            logger.info("Camera %d opened via CAP_DSHOW (attempt %d)", index, attempt)
                            return cap
                        time.sleep(0.05)
                    cap.release()

            else:
                cap = cv2.VideoCapture(index)
                if cap.isOpened():
                    for _ in range(5):
                        ret, frame = cap.read()
                        if ret and frame is not None:
                            logger.info("Camera %d opened via DEFAULT backend (attempt %d)", index, attempt)
                            return cap
                        time.sleep(0.05)
                    cap.release()

        except Exception as exc:
            logger.warning("Attempt %d to open camera %d failed: %s", attempt, index, exc)

        # Brief back-off before next attempt to allow hardware pins to settle
        if attempt < retry_count:
            time.sleep(0.15)

    # Secondary fallback on Windows: default backend (MSMF) only if DirectShow failed completely
    if sys.platform == "win32":
        try:
            cap = cv2.VideoCapture(index)
            if cap.isOpened():
                for _ in range(5):
                    ret, frame = cap.read()
                    if ret and frame is not None:
                        logger.info("Camera %d opened via MSMF fallback", index)
                        return cap
                    time.sleep(0.05)
                cap.release()
        except Exception as exc:
            logger.warning("MSMF fallback for camera %d failed: %s", index, exc)

    logger.error("Unable to open camera at index %d after %d attempts", index, retry_count)
    return None


def safe_release_camera(cap: Optional[cv2.VideoCapture]) -> None:
    """Safely release a VideoCapture resource without throwing exceptions."""
    if cap is not None:
        try:
            cap.release()
        except Exception as exc:
            logger.debug("Exception while releasing camera: %s", exc)
