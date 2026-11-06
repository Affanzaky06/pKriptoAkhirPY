# securegov/gui/auth_view.py
"""
Authentication & Hardware Access Control Gate View
===================================================
Implements strict dual-factor hardware security:
  Factor 1: Real physical USB Dongle scanning (psutil + ctypes VSN check).
  Factor 2: Real live webcam face recognition (OpenCV Haar + LBPH).

Note on Role-Based Access Control (RBAC):
  Unauthenticated / non-logged-in users cannot access user enrollment.
  User provisioning and role assignment are strictly restricted to
  authenticated Admin sessions inside the User Management Console.
"""

import os
import threading
import time
from typing import Callable, Optional

import cv2
import numpy as np
from PIL import Image
import customtkinter as ctk

from securegov.auth.credential_manager import hash_password, verify_password
from securegov.auth.usb_dongle import (
    scan_physical_usb_drives,
    verify_dongle_for_user,
)
from securegov.auth.biometric import RealFaceBiometric
from securegov.database.models import UserRepository, log_audit
from securegov.gui.camera_manager import list_available_cameras, open_camera, safe_release_camera
from securegov.gui.styles import (
    BG_CARD,
    BG_INPUT,
    BG_HOVER,
    COLOR_PRIMARY,
    COLOR_CYAN,
    COLOR_SUCCESS,
    COLOR_DANGER,
    COLOR_WARNING,
    TEXT_TITLE,
    TEXT_BODY,
    TEXT_MUTED,
    BORDER_CARD,
    FONT_FAMILY,
)
from securegov.utils.logger import get_logger

logger = get_logger(__name__)


class AuthView(ctk.CTkFrame):
    """
    Main Security Gate view providing login with strict dual-factor
    hardware verification. Enrollment is strictly restricted to logged-in Admins.
    """

    def __init__(self, master, on_login_success: Callable[[dict], None], default_username: str = "", **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.on_login_success = on_login_success
        self.default_username = default_username
        self.user_repo = UserRepository()
        self.face_engine = RealFaceBiometric()

        # State tracking
        self.cap: Optional[cv2.VideoCapture] = None
        self.camera_running = False
        self.current_frame_bgr: Optional[np.ndarray] = None
        self._cam_after_ids: list = []   # track ALL pending after() IDs
        self._cam_after_id: Optional[str] = None
        self._current_ctk_img: Optional[ctk.CTkImage] = None
        self._is_destroyed: bool = False

        self.dongle_verified = False
        self.verified_vsn: Optional[str] = None
        self.face_verified = False
        self.authenticated_user: Optional[dict] = None

        self._build_ui()

    def _get_registered_usernames(self) -> list[str]:
        try:
            import sqlite3
            from securegov.utils.config import DB_PATH
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute("SELECT username FROM users WHERE is_active = 1 ORDER BY id ASC").fetchall()
            conn.close()
            names = [r[0] for r in rows] if rows else ["alice"]
            return names
        except Exception:
            return ["alice"]

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12, border_width=1, border_color=BORDER_CARD)
        header.pack(fill="x", padx=16, pady=(16, 10))

        title = ctk.CTkLabel(
            header,
            text="🔒 SECUREGOV ACCESS CONTROL & DUAL-FACTOR GATE",
            font=(FONT_FAMILY, 18, "bold"),
            text_color=COLOR_CYAN,
        )
        title.pack(side="left", padx=20, pady=12)

        subtitle = ctk.CTkLabel(
            header,
            text="Physical USB Dongle & Live Facial Biometrics Required",
            font=(FONT_FAMILY, 12),
            text_color=TEXT_MUTED,
        )
        subtitle.pack(side="right", padx=20, pady=12)

        # RBAC Info Notice
        info_bar = ctk.CTkFrame(self, fg_color="#0F172A", corner_radius=8, border_width=1, border_color="#1E293B")
        info_bar.pack(fill="x", padx=16, pady=(0, 10))

        lbl_rbac_hint = ctk.CTkLabel(
            info_bar,
            text="ℹ️ KEBIJAKAN AKSES KETAT (RBAC): Portal ini hanya untuk pengguna terdaftar. Pendaftaran akun baru dikelola secara terpusat oleh Administrator.",
            font=(FONT_FAMILY, 10, "bold"),
            text_color=COLOR_CYAN,
        )
        lbl_rbac_hint.pack(padx=16, pady=6, anchor="w")

        # Main Dual-Factor Container
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # ===================================================================
        # LEFT COLUMN: Credentials + USB Dongle
        # ===================================================================
        left_col = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 8), pady=0)

        # Step 1: Credentials with Account Selector
        users_list = self._get_registered_usernames()
        initial_user = (
            self.default_username if (self.default_username and self.default_username in users_list)
            else (users_list[0] if users_list else "alice")
        )

        lbl_s1 = ctk.CTkLabel(left_col, text="STEP 1: PILIH AKUN & KREDENSIAL", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl_s1.pack(anchor="w", padx=16, pady=(16, 4))

        row_user_select = ctk.CTkFrame(left_col, fg_color="transparent")
        row_user_select.pack(fill="x", padx=16, pady=2)

        lbl_sel = ctk.CTkLabel(row_user_select, text="Pilih Akun:", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_sel.pack(side="left", padx=(0, 6))

        self.combo_users = ctk.CTkComboBox(
            row_user_select,
            values=users_list,
            height=32,
            command=self._on_user_selected,
        )
        self.combo_users.set(initial_user)
        self.combo_users.pack(side="left", fill="x", expand=True)

        self.entry_user = ctk.CTkEntry(left_col, placeholder_text="Username", height=38, font=(FONT_FAMILY, 12))
        self.entry_user.pack(fill="x", padx=16, pady=4)
        self.entry_user.insert(0, initial_user)

        self.entry_pass = ctk.CTkEntry(left_col, placeholder_text="Password", show="•", height=38, font=(FONT_FAMILY, 12))
        self.entry_pass.pack(fill="x", padx=16, pady=4)
        if initial_user in ("alice", "Affan"):
            self.entry_pass.insert(0, "P@ssw0rd!")

        # Step 2: Physical USB Dongle
        lbl_s2 = ctk.CTkLabel(left_col, text="STEP 2: PHYSICAL USB DONGLE", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl_s2.pack(anchor="w", padx=16, pady=(16, 6))

        dongle_row = ctk.CTkFrame(left_col, fg_color="transparent")
        dongle_row.pack(fill="x", padx=16, pady=4)

        self.btn_scan_dongle = ctk.CTkButton(
            dongle_row,
            text="🔍 Scan Connected USB Drives",
            command=self._on_scan_and_verify_dongle,
            height=36,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_CYAN,
        )
        self.btn_scan_dongle.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.badge_dongle = ctk.CTkLabel(
            left_col,
            text="[ DONGLE WAITING ]",
            font=(FONT_FAMILY, 11, "bold"),
            text_color=COLOR_WARNING,
        )
        self.badge_dongle.pack(anchor="w", padx=16, pady=2)

        self.txt_dongle_info = ctk.CTkLabel(
            left_col,
            text="Tancapkan flashdisk USB resmi lalu klik 'Scan Connected USB Drives'.",
            font=(FONT_FAMILY, 11),
            text_color=TEXT_MUTED,
            justify="left",
            wraplength=340,
        )
        self.txt_dongle_info.pack(anchor="w", padx=16, pady=(2, 10))

        # Big Unlock Button at the bottom of left column
        self.btn_unlock = ctk.CTkButton(
            left_col,
            text="🔓 UNLOCK SECURE VAULT",
            font=(FONT_FAMILY, 14, "bold"),
            height=46,
            fg_color=BG_HOVER,
            hover_color=COLOR_SUCCESS,
            state="disabled",
            command=self._on_unlock_clicked,
        )
        self.btn_unlock.pack(fill="x", padx=16, pady=(16, 16))

        # ===================================================================
        # RIGHT COLUMN: Real Live Camera & Face Recognition
        # ===================================================================
        right_col = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        right_col.pack(side="right", fill="both", expand=True, padx=(8, 0), pady=0)

        row_cam_header = ctk.CTkFrame(right_col, fg_color="transparent")
        row_cam_header.pack(fill="x", padx=16, pady=(16, 6))

        lbl_s3 = ctk.CTkLabel(row_cam_header, text="STEP 3: LIVE WEBCAM FACE BIOMETRIC", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl_s3.pack(side="left")

        # Camera Device Selector
        self.combo_cam_idx = ctk.CTkComboBox(
            row_cam_header,
            values=["Camera 0"],
            width=110,
            height=28,
            font=(FONT_FAMILY, 10),
            dropdown_font=(FONT_FAMILY, 10),
            command=self._on_camera_device_changed,
        )
        self.combo_cam_idx.pack(side="right", padx=(4, 0))

        btn_refresh_cam = ctk.CTkButton(
            row_cam_header,
            text="🔄",
            width=30,
            height=28,
            font=(FONT_FAMILY, 11),
            fg_color=BG_HOVER,
            command=self._refresh_camera_devices,
        )
        btn_refresh_cam.pack(side="right")

        # Camera preview frame
        self.cam_preview = ctk.CTkLabel(
            right_col,
            text="[ Kamera Siap ]\nKlik 'Nyalakan Kamera' di bawah untuk verifikasi wajah.",
            font=(FONT_FAMILY, 12),
            text_color=TEXT_MUTED,
            fg_color="#000000",
            corner_radius=8,
            width=360,
            height=240,
        )
        self.cam_preview.pack(fill="both", expand=True, padx=16, pady=6)

        cam_btn_row = ctk.CTkFrame(right_col, fg_color="transparent")
        cam_btn_row.pack(fill="x", padx=16, pady=(6, 4))

        self.btn_cam_toggle = ctk.CTkButton(
            cam_btn_row,
            text="📷 Nyalakan Kamera",
            command=self._toggle_camera,
            height=36,
            fg_color=COLOR_PRIMARY,
        )
        self.btn_cam_toggle.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.btn_verify_face = ctk.CTkButton(
            cam_btn_row,
            text="👤 Verifikasi Wajah",
            command=self._on_verify_face,
            height=36,
            fg_color=COLOR_CYAN,
            hover_color=COLOR_PRIMARY,
        )
        self.btn_verify_face.pack(side="right", fill="x", expand=True, padx=(6, 0))

        self.badge_face = ctk.CTkLabel(
            right_col,
            text="[ BIOMETRIK WAJAH MENUNGGU ]",
            font=(FONT_FAMILY, 11, "bold"),
            text_color=COLOR_WARNING,
        )
        self.badge_face.pack(anchor="w", padx=16, pady=(4, 14))

        # Initialize camera devices list
        self._refresh_camera_devices()

    # =======================================================================
    # Camera Device Management & Frame Loop
    # =======================================================================

    def _refresh_camera_devices(self):
        try:
            cams = list_available_cameras(max_tested=3)
        except Exception:
            cams = []
        # Always guarantee at least Camera 0 is listed as a fallback
        if not cams:
            cams = [0]
        cam_labels = [f"Camera {idx}" for idx in cams]
        self.combo_cam_idx.configure(values=cam_labels)
        self.combo_cam_idx.set(cam_labels[0])

    def _get_selected_camera_idx(self) -> int:
        val = self.combo_cam_idx.get()
        try:
            return int(val.replace("Camera", "").strip())
        except Exception:
            return 0

    def _on_camera_device_changed(self, choice: str):
        if self.camera_running:
            self._stop_camera()
            self._start_camera()

    def _toggle_camera(self):
        if self.camera_running:
            self._stop_camera()
        else:
            self._start_camera()

    def _start_camera(self):
        if self.camera_running:
            return

        cam_idx = self._get_selected_camera_idx()
        try:
            self.cap = open_camera(index=cam_idx, retry_count=2)
            if not self.cap or not self.cap.isOpened():
                if self.winfo_exists():
                    self.cam_preview.configure(
                        text=f"[ Kamera {cam_idx} Tidak Merespon ]\nPastikan webcam tidak sedang digunakan oleh aplikasi lain.",
                        image=None,
                    )
                return

            self.camera_running = True
            if self.winfo_exists():
                self.btn_cam_toggle.configure(text="⏹ Matikan Kamera", fg_color=COLOR_DANGER)
            self._update_camera_frame()

        except Exception as exc:
            logger.error("Camera open error: %s", exc)
            if self.winfo_exists():
                self.cam_preview.configure(text=f"Error Kamera: {exc}", image=None)

    def _stop_camera(self):
        self.camera_running = False
        # Cancel ALL pending after() callbacks registered by this view
        for aid in list(self._cam_after_ids):
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        self._cam_after_ids.clear()
        self._cam_after_id = None

        safe_release_camera(self.cap)
        self.cap = None
        self._current_ctk_img = None

        try:
            if not self._is_destroyed and self.winfo_exists():
                self.btn_cam_toggle.configure(text="📷 Nyalakan Kamera", fg_color=COLOR_PRIMARY)
                self.cam_preview.configure(text="[ Kamera Mati ]\nKlik 'Nyalakan Kamera' untuk mengaktifkan.", image=None)
        except Exception:
            pass

    def _update_camera_frame(self):
        # Stop immediately if this view has been destroyed
        if self._is_destroyed or not self.camera_running or not self.cap:
            return
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return

        try:
            ret, frame = self.cap.read()
            if ret and frame is not None:
                self.current_frame_bgr = frame.copy()

                # Detect faces and draw clean cyberpunk HUD bounding box
                display_frame = frame.copy()
                faces = self.face_engine.detect_faces(display_frame)
                for (x, y, w, h) in faces:
                    cv2.rectangle(display_frame, (x, y), (x + w, y + h), (0, 255, 128), 2)
                    cv2.putText(
                        display_frame,
                        "TARGET FACE DETECTED",
                        (x, max(15, y - 8)),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        0.5,
                        (0, 255, 128),
                        1,
                        cv2.LINE_AA,
                    )

                # Convert to PIL Image for CustomTkinter
                rgb = cv2.cvtColor(display_frame, cv2.COLOR_BGR2RGB)
                pil_img = Image.fromarray(rgb)
                self._current_ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(360, 240))
                self.cam_preview.configure(image=self._current_ctk_img, text="")

        except Exception as exc:
            logger.debug("Frame capture warning: %s", exc)

        # Schedule next frame in 30ms (~33 FPS) safely
        if not self._is_destroyed and self.camera_running:
            try:
                if self.winfo_exists():
                    aid = self.after(30, self._update_camera_frame)
                    self._cam_after_ids.append(aid)
                    self._cam_after_id = aid
            except Exception:
                pass

    # =======================================================================
    # Dongle Scanning & Verification
    # =======================================================================

    def _on_scan_and_verify_dongle(self):
        username = self.entry_user.get().strip()
        user = self.user_repo.get_by_username(username)
        expected_vsn = user.get("registered_vsn") if user else None

        ok, msg, d_info = verify_dongle_for_user(expected_vsn)
        if ok:
            self.dongle_verified = True
            if d_info and d_info.get("vsn") and d_info.get("vsn") != "N/A":
                self.verified_vsn = d_info.get("vsn")
            self.badge_dongle.configure(text="[ USB DONGLE TERVERIFIKASI ✓ ]", text_color=COLOR_SUCCESS)
            self.txt_dongle_info.configure(text=msg, text_color=COLOR_SUCCESS)
        else:
            self.dongle_verified = False
            self.verified_vsn = None
            self.badge_dongle.configure(text="[ DONGLE TIDAK VALID ✗ ]", text_color=COLOR_DANGER)
            self.txt_dongle_info.configure(text=msg, text_color=COLOR_DANGER)

        self._check_all_factors()

    # =======================================================================
    # Face Verification & User Selection
    # =======================================================================

    def _on_user_selected(self, selected_username: str):
        self.entry_user.delete(0, "end")
        self.entry_user.insert(0, selected_username)
        self.entry_pass.delete(0, "end")
        # Auto-fill known demo credentials for convenience
        if selected_username in ("alice", "Affan"):
            self.entry_pass.insert(0, "P@ssw0rd!")

        # Reset ALL factor states when switching account
        self.dongle_verified = False
        self.verified_vsn = None
        self.face_verified = False
        self.authenticated_user = None
        self.badge_dongle.configure(text="[ DONGLE WAITING ]", text_color=COLOR_WARNING)
        self.badge_face.configure(text="[ BIOMETRIK WAJAH MENUNGGU ]", text_color=COLOR_WARNING)
        self.txt_dongle_info.configure(
            text=f"Akun aktif: {selected_username}. Tancapkan dongle & klik scan.",
            text_color=TEXT_MUTED,
        )
        self._check_all_factors()

    def _on_verify_face(self):
        username = self.entry_user.get().strip()
        if not username:
            self.badge_face.configure(text="[ MASUKKAN USERNAME DULU ]", text_color=COLOR_DANGER)
            return

        if not self.camera_running:
            self._start_camera()
            time.sleep(0.3)

        if self.current_frame_bgr is None:
            self.badge_face.configure(text="[ KAMERA TIDAK AKTIF ]", text_color=COLOR_DANGER)
            return

        # Check across 3 successive frames to account for minor movement/blinking
        best_ok = False
        best_score = 0.0
        best_msg = ""

        for _ in range(3):
            if self.current_frame_bgr is not None:
                ok, score, bbox, msg = self.face_engine.verify_face(
                    username,
                    self.current_frame_bgr,
                    confidence_threshold=85.0
                )
                if ok:
                    best_ok = True
                    best_score = score
                    best_msg = msg
                    break
                elif score > best_score:
                    best_score = score
                    best_msg = msg
            time.sleep(0.1)

        if best_ok:
            self.face_verified = True
            self.badge_face.configure(text=f"[ WAJAH TERVERIFIKASI ✓ ({best_score:.1f}%) ]", text_color=COLOR_SUCCESS)
        else:
            self.face_verified = False
            self.badge_face.configure(text=f"[ WAJAH BELUM COCOK ✗ ({best_score:.1f}%) ]", text_color=COLOR_DANGER)

        self._check_all_factors()

    # =======================================================================
    # Factor Aggregator & Vault Unlock
    # =======================================================================

    def _check_all_factors(self):
        """Enable the Unlock button only when Credentials, Dongle, and Face match."""
        username = self.entry_user.get().strip()
        password = self.entry_pass.get()

        user = self.user_repo.get_by_username(username)
        creds_ok = False
        if user and verify_password(password, user["password_hash"]):
            creds_ok = True
            self.authenticated_user = user
            # Auto-bind the verified dongle VSN to the session & database if unassigned
            if hasattr(self, "verified_vsn") and self.verified_vsn:
                if not self.authenticated_user.get("registered_vsn"):
                    self.authenticated_user["registered_vsn"] = self.verified_vsn
                    try:
                        self.user_repo.update_dongle_vsn(self.authenticated_user["id"], self.verified_vsn)
                    except Exception as exc:
                        logger.debug("Auto-bind VSN error: %s", exc)

        all_ok = creds_ok and self.dongle_verified and self.face_verified
        if all_ok:
            self.btn_unlock.configure(state="normal", fg_color=COLOR_SUCCESS)
        else:
            self.btn_unlock.configure(state="disabled", fg_color=BG_HOVER)

    def _on_unlock_clicked(self):
        if self.authenticated_user:
            self._stop_camera()
            log_audit(self.authenticated_user["id"], "LOGIN_SUCCESS", "Dual-factor USB Dongle + Face Authenticated")
            self.on_login_success(self.authenticated_user)

    def cleanup(self):
        """Release camera and timers cleanly."""
        self._is_destroyed = True
        self._stop_camera()

    def destroy(self):
        self._is_destroyed = True
        self.cleanup()
        try:
            super().destroy()
        except Exception:
            pass
