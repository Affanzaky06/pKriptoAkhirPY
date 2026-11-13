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
        # 1. Normalized lower-case lookup
        norm_user = username.strip().lower()
        norm_hash = hashlib.sha256(norm_user.encode("utf-8")).hexdigest()[:16]
        norm_path = os.path.join(_TEMPLATE_DIR, f"{norm_hash}_lbph.xml")
        if os.path.isfile(norm_path):
            return norm_path

        # 2. Raw case fallback (for models saved prior to normalization)
        raw_hash = hashlib.sha256(username.strip().encode("utf-8")).hexdigest()[:16]
        raw_path = os.path.join(_TEMPLATE_DIR, f"{raw_hash}_lbph.xml")
        if os.path.isfile(raw_path):
            return raw_path

        return norm_path

    def get_reference_img_path(self, username: str) -> str:
        norm_user = username.strip().lower()
        norm_hash = hashlib.sha256(norm_user.encode("utf-8")).hexdigest()[:16]
        norm_path = os.path.join(_TEMPLATE_DIR, f"{norm_hash}_reference.jpg")
        if os.path.isfile(norm_path):
            return norm_path

        raw_hash = hashlib.sha256(username.strip().encode("utf-8")).hexdigest()[:16]
        raw_path = os.path.join(_TEMPLATE_DIR, f"{raw_hash}_reference.jpg")
        if os.path.isfile(raw_path):
            return raw_path

        return norm_path

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
        Crop face region with dynamic margin, apply bilateral smoothing and CLAHE
        (Contrast Limited Adaptive Histogram Equalization) for lighting invariance, and resize.
        """
        x, y, w, h = bbox
        h_frame, w_frame = frame_bgr.shape[:2]

        # Add 8% padding to avoid clipping forehead/chin and reduce boundary artifacts
        pad_w = int(w * 0.08)
        pad_h = int(h * 0.08)
        x1 = max(0, x - pad_w)
        y1 = max(0, y - pad_h)
        x2 = min(w_frame, x + w + pad_w)
        y2 = min(h_frame, y + h + pad_h)

        face_roi = frame_bgr[y1:y2, x1:x2]
        gray = cv2.cvtColor(face_roi, cv2.COLOR_BGR2GRAY)

        # 1. Bilateral filter removes camera sensor grain while preserving crisp facial edges
        smoothed = cv2.bilateralFilter(gray, d=5, sigmaColor=25, sigmaSpace=25)

        # 2. CLAHE normalizes illumination across shadows and highlights without over-amplifying noise
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(smoothed)

        return cv2.resize(enhanced, target_size, interpolation=cv2.INTER_AREA)

    # --- Real Face Enrollment ---

    def enroll_user(
        self,
        username: str,
        face_samples: List[np.ndarray],
        preview_frame: Optional[np.ndarray] = None
    ) -> bool:
        """
        Train an LBPH model on captured face crop samples with multi-factor
        data augmentation (flips, rotations, illumination shifts, and scaling) and save to disk.
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

            # Rich intra-class data augmentation to boost model robustness
            all_samples = []
            for s in face_samples:
                h, w = s.shape[:2]
                center = (w // 2, h // 2)

                # Base & horizontal flip
                all_samples.append(s)
                flipped = cv2.flip(s, 1)
                all_samples.append(flipped)

                # Subtle rotation variations (+-4 degrees)
                for angle in (-4, 4):
                    M_rot = cv2.getRotationMatrix2D(center, angle, 1.0)
                    rot = cv2.warpAffine(s, M_rot, (w, h), borderMode=cv2.BORDER_REFLECT)
                    all_samples.append(rot)
                    all_samples.append(cv2.flip(rot, 1))

                # Illumination scaling (darker and brighter)
                for factor in (0.88, 1.12):
                    scaled = np.clip(s.astype(np.float32) * factor, 0, 255).astype(np.uint8)
                    all_samples.append(scaled)

                # Subtle zoom/scale (1.05x)
                M_zoom = cv2.getRotationMatrix2D(center, 0, 1.05)
                zoomed = cv2.warpAffine(s, M_zoom, (w, h), borderMode=cv2.BORDER_REFLECT)
                all_samples.append(zoomed)

            labels = np.zeros(len(all_samples), dtype=np.int32)
            recognizer.train(all_samples, labels)

            # Write model to normalized path
            norm_user = username.strip().lower()
            norm_hash = hashlib.sha256(norm_user.encode("utf-8")).hexdigest()[:16]
            model_path = os.path.join(_TEMPLATE_DIR, f"{norm_hash}_lbph.xml")
            recognizer.write(model_path)

            # Also write to raw case path if username differs in casing
            raw_hash = hashlib.sha256(username.strip().encode("utf-8")).hexdigest()[:16]
            if raw_hash != norm_hash:
                raw_path = os.path.join(_TEMPLATE_DIR, f"{raw_hash}_lbph.xml")
                recognizer.write(raw_path)

            if preview_frame is not None:
                ref_path = os.path.join(_TEMPLATE_DIR, f"{norm_hash}_reference.jpg")
                cv2.imwrite(ref_path, preview_frame)
                if raw_hash != norm_hash:
                    raw_ref_path = os.path.join(_TEMPLATE_DIR, f"{raw_hash}_reference.jpg")
                    cv2.imwrite(raw_ref_path, preview_frame)

            logger.info("Real Face Enrollment SUCCESS for user '%s' (%d samples saved to %s)",
                        username, len(all_samples), model_path)
            return True

        except Exception as exc:
            logger.error("Real Face Enrollment failed: %s", exc)
            return False

    # --- Real Face Verification ---

    def verify_face(
        self,
        username: str,
        probe_frame: np.ndarray,
        confidence_threshold: float = 55.0
    ) -> Tuple[bool, float, Optional[Tuple[int, int, int, int]], str]:
        """
        Detect face in probe_frame, run LBPH prediction against enrolled template.

        Uses calibrated Chi-square distance mapping to match percentage:
          - distance <= 30.0    -> 85% - 100% (High match)
          - 30.0 < dist <= 55.0 -> 65% - 85%  (Valid verification zone)
          - 55.0 < dist <= 80.0 -> 30% - 65%  (Rejection zone / different person)
          - dist > 80.0         -> < 30%      (Completely different face)

        Returns:
          (is_verified: bool, match_percentage: float, bbox: (x,y,w,h)|None, message: str)
        """
        model_path = self.get_model_path(username)
        if not os.path.isfile(model_path):
            return False, 0.0, None, f"User '{username}' belum mendaftarkan biometrik wajah."

        faces = self.detect_faces(probe_frame)
        if not faces:
            return False, 0.0, None, "Tidak ada wajah terdeteksi di kamera. Posisikan wajah di tengah."

        # Pick the largest face in frame
        faces_sorted = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)
        best_bbox = faces_sorted[0]
        face_crop = self.extract_face_crop(probe_frame, best_bbox)

        try:
            recognizer = cv2.face.LBPHFaceRecognizer_create()
            recognizer.read(model_path)
            pred_label, distance = recognizer.predict(face_crop)

            # Calibrated piecewise nonlinear mapping from LBPH Chi-Square distance to confidence score
            if distance <= 30.0:
                match_score = 100.0 - (distance / 30.0) * 15.0
            elif distance <= 55.0:
                match_score = 85.0 - ((distance - 30.0) / 25.0) * 20.0
            elif distance <= 80.0:
                match_score = 65.0 - ((distance - 55.0) / 25.0) * 35.0
            else:
                match_score = max(5.0, 30.0 - ((distance - 80.0) / 20.0) * 25.0)

            match_score = round(max(0.0, min(100.0, match_score)), 1)

            # Strict verification criteria: both distance within threshold and confidence >= 65%
            is_verified = bool(distance <= confidence_threshold and match_score >= 65.0)

            if is_verified:
                msg = f"✓ Wajah Terverifikasi (Kecocokan: {match_score:.1f}%, Jarak: {distance:.1f} / Batas: {confidence_threshold:.0f})"
                logger.info("Real Face Auth MATCH for '%s' (dist=%.2f, score=%.1f%%)",
                            username, distance, match_score)
                return True, match_score, best_bbox, msg
            else:
                msg = f"✗ Wajah Belum Cocok (Jarak: {distance:.1f} > Batas: {confidence_threshold:.0f}, Skor: {match_score:.1f}%)"
                logger.warning("Real Face Auth MISMATCH for '%s' (dist=%.2f, score=%.1f%%)", username, distance, match_score)
                return False, match_score, best_bbox, msg

        except Exception as exc:
            logger.error("Face prediction error: %s", exc)
            return False, 0.0, best_bbox, f"Error pengenalan wajah: {exc}"


# # ===========================================================================
# # Legacy Biometric Interfaces (Preserved for compatibility)
# # ===========================================================================

# class BiometricAuthenticator:
#     def enroll(self, user_id: str) -> bool:
#         raise NotImplementedError
#     def verify(self, user_id: str) -> bool:
#         raise NotImplementedError
#     def delete_template(self, user_id: str) -> bool:
#         raise NotImplementedError


# class FingerprintSimulator(BiometricAuthenticator):
#     def __init__(self, simulate_match_probability: float = 1.0) -> None:
#         self.match_probability = simulate_match_probability

#     def _template_path(self, user_id: str) -> str:
#         safe = hashlib.sha256(user_id.encode()).hexdigest()
#         return os.path.join(_TEMPLATE_DIR, f"fp_{safe}.bin")

#     def enroll(self, user_id: str) -> bool:
#         with open(self._template_path(user_id), "wb") as f:
#             f.write(secrets.token_bytes(32))
#         return True

#     def verify(self, user_id: str) -> bool:
#         if not os.path.isfile(self._template_path(user_id)):
#             return False
#         import random
#         return random.random() < self.match_probability

#     def delete_template(self, user_id: str) -> bool:
#         path = self._template_path(user_id)
#         if os.path.isfile(path):
#             os.remove(path)
#             return True
#         return False


# class FaceRecognitionSimulator(BiometricAuthenticator):
#     def __init__(
#         self,
#         camera_index: int = 0,
#         simulate_match_probability: float = 1.0,
#         enable_real_camera: bool = True
#     ) -> None:
#         self.camera_index = camera_index
#         self.match_probability = simulate_match_probability
#         self.enable_real_camera = enable_real_camera
#         self.real_engine = RealFaceBiometric()

#     def enroll(self, user_id: str) -> bool:
#         safe = hashlib.sha256(user_id.encode()).hexdigest()
#         path = os.path.join(_TEMPLATE_DIR, f"face_{safe}.bin")
#         with open(path, "wb") as f:
#             f.write(secrets.token_bytes(32))
#         return True

#     def verify(self, user_id: str) -> bool:
#         safe = hashlib.sha256(user_id.encode()).hexdigest()
#         path = os.path.join(_TEMPLATE_DIR, f"face_{safe}.bin")
#         if not os.path.isfile(path):
#             return False
#         import random
#         return random.random() < self.match_probability


# def dual_factor_auth(
#     user_id: str,
#     biometric: Optional[BiometricAuthenticator] = None,
#     require_dongle: bool = True,
# ) -> bool:
#     from securegov.auth.usb_dongle import verify_dongle
#     d_ok = verify_dongle() if require_dongle else True
#     bio = biometric or FingerprintSimulator()
#     b_ok = bio.verify(user_id)
#     return d_ok and b_ok
