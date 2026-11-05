# securegov/auth/biometric.py
"""
Real Camera Face Biometric & Hardware Authentication Module
============================================================
Implements:
  1. Real OpenCV Webcam Capture and Face Detection using Haar Cascade.
  2. Real Facial Feature Extraction & Matching using OpenCV LBPH (Local Binary Patterns Histograms).
  3. Legacy biometric simulators for backward compatibility with unit tests.
"""

import os
import time
import secrets
import hashlib
from typing import Optional, List, Tuple

import cv2
import numpy as np

from securegov.utils.logger import get_logger

logger = get_logger(__name__)

# Template directory
_TEMPLATE_DIR = os.path.join("data", "biometric_templates")
os.makedirs(_TEMPLATE_DIR, exist_ok=True)

# Default Haar Cascade path
_DEFAULT_CASCADE_PATH = os.path.join("data", "haarcascade_frontalface_default.xml")


# ===========================================================================
# Real OpenCV Face Biometric Engine (No Mocks)
# ===========================================================================

class RealFaceBiometric:
    """
    Production-grade biometric module using OpenCV Haar Cascade Face Detection
    and OpenCV LBPHFaceRecognizer for real facial verification.
    """

    def __init__(self, cascade_path: str = _DEFAULT_CASCADE_PATH) -> None:
        self.cascade_path = cascade_path
        self._cascade = None
        self._load_cascade()

    def _load_cascade(self) -> None:
        """Load the Haar Cascade classifier from disk."""
        if os.path.isfile(self.cascade_path):
            self._cascade = cv2.CascadeClassifier(self.cascade_path)
            if self._cascade.empty():
                logger.warning("Failed to initialize CascadeClassifier from %s", self.cascade_path)
                self._cascade = None
        else:
            logger.warning("Cascade file not found at %s", self.cascade_path)

    def is_detector_ready(self) -> bool:
        return self._cascade is not None and not self._cascade.empty()

    def get_model_path(self, username: str) -> str:
        safe_user = hashlib.sha256(username.encode("utf-8")).hexdigest()[:16]
        return os.path.join(_TEMPLATE_DIR, f"{safe_user}_lbph.xml")

    def get_reference_img_path(self, username: str) -> str:
        safe_user = hashlib.sha256(username.encode("utf-8")).hexdigest()[:16]
        return os.path.join(_TEMPLATE_DIR, f"{safe_user}_reference.jpg")

    def is_user_enrolled(self, username: str) -> bool:
        return os.path.isfile(self.get_model_path(username))

    # --- Real-Time Face Detection ---

    def detect_faces(self, frame_bgr: np.ndarray) -> List[Tuple[int, int, int, int]]:
        """
        Detect face bounding boxes (x, y, w, h) in a BGR frame.
        """
        if self._cascade is None or frame_bgr is None:
            return []
        gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
        gray = cv2.equalizeHist(gray)
        faces = self._cascade.detectMultiScale(
            gray,
            scaleFactor=1.15,
            minNeighbors=4,
            minSize=(60, 60),
            flags=cv2.CASCADE_SCALE_IMAGE
        )
        return [(int(x), int(y), int(w), int(h)) for (x, y, w, h) in faces]

    def extract_face_crop(
        self,
        frame_bgr: np.ndarray,
        bbox: Tuple[int, int, int, int],
        target_size: Tuple[int, int] = (160, 160)
    ) -> np.ndarray:
        """
        Crop face region, equalize histogram for lighting invariance, and resize.
        """
        x, y, w, h = bbox
        gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
        face_roi = gray[y:y + h, x:x + w]
        equalized = cv2.equalizeHist(face_roi)
        return cv2.resize(equalized, target_size, interpolation=cv2.INTER_AREA)

    # --- Real Face Enrollment ---

    def enroll_user(
        self,
        username: str,
        face_samples: List[np.ndarray],
        preview_frame: Optional[np.ndarray] = None
    ) -> bool:
        """
        Train an LBPH model on captured face crop samples and save to disk.
        """
        if not face_samples:
            logger.error("Cannot enroll: face_samples list is empty.")
            return False

        try:
            recognizer = cv2.face.LBPHFaceRecognizer_create(
                radius=1,
                neighbors=8,
                grid_x=8,
                grid_y=8
            )
            labels = np.zeros(len(face_samples), dtype=np.int32)
            recognizer.train(face_samples, labels)

            model_path = self.get_model_path(username)
            recognizer.write(model_path)

            if preview_frame is not None:
                ref_path = self.get_reference_img_path(username)
                cv2.imwrite(ref_path, preview_frame)

            logger.info("Real Face Enrollment SUCCESS for user '%s' (%d samples saved to %s)",
                        username, len(face_samples), model_path)
            return True

        except Exception as exc:
            logger.error("Real Face Enrollment failed: %s", exc)
            return False

    # --- Real Face Verification ---

    def verify_face(
        self,
        username: str,
        probe_frame: np.ndarray,
        confidence_threshold: float = 75.0
    ) -> Tuple[bool, float, Optional[Tuple[int, int, int, int]], str]:
        """
        Detect face in probe_frame, run LBPH prediction against enrolled template.

        Returns:
          (is_verified: bool, match_percentage: float, bbox: (x,y,w,h)|None, message: str)
        """
        model_path = self.get_model_path(username)
        if not os.path.isfile(model_path):
            return False, 0.0, None, f"User '{username}' belum mendaftarkan biometrik wajah."

        faces = self.detect_faces(probe_frame)
        if not faces:
            return False, 0.0, None, "Tidak ada wajah terdeteksi di kamera."

        # Pick the largest face in frame
        faces_sorted = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)
        best_bbox = faces_sorted[0]
        face_crop = self.extract_face_crop(probe_frame, best_bbox)

        try:
            recognizer = cv2.face.LBPHFaceRecognizer_create()
            recognizer.read(model_path)
            pred_label, distance = recognizer.predict(face_crop)

            # In LBPH: lower distance = better match. 0 = exact.
            # Normalize distance into a 0-100% human-readable match score
            match_score = max(0.0, min(100.0, 100.0 - (distance * 0.9)))

            if distance <= confidence_threshold:
                msg = f"✓ Wajah Terverifikasi (Kecocokan: {match_score:.1f}%, Jarak: {distance:.1f})"
                logger.info("Real Face Auth MATCH for '%s' (dist=%.2f, score=%.1f%%)",
                            username, distance, match_score)
                return True, match_score, best_bbox, msg
            else:
                msg = f"✗ Wajah Tidak Cocok (Kecocokan: {match_score:.1f}%, Jarak: {distance:.1f} > {confidence_threshold})"
                logger.warning("Real Face Auth MISMATCH for '%s' (dist=%.2f)", username, distance)
                return False, match_score, best_bbox, msg

        except Exception as exc:
            logger.error("Face prediction error: %s", exc)
            return False, 0.0, best_bbox, f"Error pengenalan wajah: {exc}"


# ===========================================================================
# Legacy Biometric Interfaces (Preserved for compatibility)
# ===========================================================================

class BiometricAuthenticator:
    def enroll(self, user_id: str) -> bool:
        raise NotImplementedError
    def verify(self, user_id: str) -> bool:
        raise NotImplementedError
    def delete_template(self, user_id: str) -> bool:
        raise NotImplementedError


class FingerprintSimulator(BiometricAuthenticator):
    def __init__(self, simulate_match_probability: float = 1.0) -> None:
        self.match_probability = simulate_match_probability

    def _template_path(self, user_id: str) -> str:
        safe = hashlib.sha256(user_id.encode()).hexdigest()
        return os.path.join(_TEMPLATE_DIR, f"fp_{safe}.bin")

    def enroll(self, user_id: str) -> bool:
        with open(self._template_path(user_id), "wb") as f:
            f.write(secrets.token_bytes(32))
        return True

    def verify(self, user_id: str) -> bool:
        if not os.path.isfile(self._template_path(user_id)):
            return False
        import random
        return random.random() < self.match_probability

    def delete_template(self, user_id: str) -> bool:
        path = self._template_path(user_id)
        if os.path.isfile(path):
            os.remove(path)
            return True
        return False


class FaceRecognitionSimulator(BiometricAuthenticator):
    def __init__(
        self,
        camera_index: int = 0,
        simulate_match_probability: float = 1.0,
        enable_real_camera: bool = True
    ) -> None:
        self.camera_index = camera_index
        self.match_probability = simulate_match_probability
        self.enable_real_camera = enable_real_camera
        self.real_engine = RealFaceBiometric()

    def enroll(self, user_id: str) -> bool:
        safe = hashlib.sha256(user_id.encode()).hexdigest()
        path = os.path.join(_TEMPLATE_DIR, f"face_{safe}.bin")
        with open(path, "wb") as f:
            f.write(secrets.token_bytes(32))
        return True

    def verify(self, user_id: str) -> bool:
        safe = hashlib.sha256(user_id.encode()).hexdigest()
        path = os.path.join(_TEMPLATE_DIR, f"face_{safe}.bin")
        if not os.path.isfile(path):
            return False
        import random
        return random.random() < self.match_probability


def dual_factor_auth(
    user_id: str,
    biometric: Optional[BiometricAuthenticator] = None,
    require_dongle: bool = True,
) -> bool:
    from securegov.auth.usb_dongle import verify_dongle
    d_ok = verify_dongle() if require_dongle else True
    bio = biometric or FingerprintSimulator()
    b_ok = bio.verify(user_id)
    return d_ok and b_ok
