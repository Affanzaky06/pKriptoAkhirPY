# securegov/gui/auth_view.py
"""
Authentication & Hardware Enrollment Gate View
===============================================
Implements strict dual-factor hardware security:
  Factor 1: Real physical USB Dongle scanning (psutil + ctypes VSN check).
  Factor 2: Real live webcam face recognition (OpenCV Haar + LBPH).
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
    register_usb_dongle,
    verify_dongle_for_user,
)
from securegov.auth.biometric import RealFaceBiometric
from securegov.database.models import UserRepository, log_audit
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
    hardware verification, and registration for new users, USB dongles, and faces.
    """

    def __init__(self, master, on_login_success: Callable[[dict], None], **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.on_login_success = on_login_success
        self.user_repo = UserRepository()
        self.face_engine = RealFaceBiometric()

        # State tracking
        self.cap: Optional[cv2.VideoCapture] = None
        self.camera_running = False
        self.current_frame_bgr: Optional[np.ndarray] = None
        self.captured_samples: list[np.ndarray] = []

        self.dongle_verified = False
        self.face_verified = False
        self.authenticated_user: Optional[dict] = None

        self._build_ui()

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

        # Tabview switching between Login Gate and Registration
        self.tabview = ctk.CTkTabview(
            self,
            fg_color=BG_CARD,
            segmented_button_fg_color=BG_INPUT,
            segmented_button_selected_color=COLOR_PRIMARY,
            segmented_button_selected_hover_color=COLOR_CYAN,
        )
        self.tabview.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self.tab_login = self.tabview.add("🔐 Dual-Factor Login Gate")
        self.tab_register = self.tabview.add("📝 User & Hardware Enrollment")

        self._build_login_tab()
        self._build_register_tab()

    # =======================================================================
    # 1. DUAL-FACTOR LOGIN GATE
    # =======================================================================

    def _build_login_tab(self):
        container = ctk.CTkFrame(self.tab_login, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=12, pady=12)

        # Left Column: Credentials + USB Dongle
        left_col = ctk.CTkFrame(container, fg_color=BG_INPUT, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 8), pady=0)

        # Step 1: Credentials
        lbl_s1 = ctk.CTkLabel(left_col, text="STEP 1: USER CREDENTIALS", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl_s1.pack(anchor="w", padx=16, pady=(16, 6))

        self.entry_user = ctk.CTkEntry(left_col, placeholder_text="Username", height=38, font=(FONT_FAMILY, 12))
        self.entry_user.pack(fill="x", padx=16, pady=4)
        self.entry_user.insert(0, "alice")  # convenient default

        self.entry_pass = ctk.CTkEntry(left_col, placeholder_text="Password", show="•", height=38, font=(FONT_FAMILY, 12))
        self.entry_pass.pack(fill="x", padx=16, pady=4)
        self.entry_pass.insert(0, "P@ssw0rd!")

        # Step 2: Physical USB Dongle
        lbl_s2 = ctk.CTkLabel(left_col, text="STEP 2: PHYSICAL USB DONGLE", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl_s2.pack(anchor="w", padx=16, pady=(18, 6))

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
        self.btn_unlock.pack(fill="x", padx=16, pady=(20, 16))

        # Right Column: Real Live Camera & Face Recognition
        right_col = ctk.CTkFrame(container, fg_color=BG_INPUT, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        right_col.pack(side="right", fill="both", expand=True, padx=(8, 0), pady=0)

        lbl_s3 = ctk.CTkLabel(right_col, text="STEP 3: LIVE WEBCAM FACE BIOMETRIC", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl_s3.pack(anchor="w", padx=16, pady=(16, 6))

        # Camera preview frame
        self.cam_preview = ctk.CTkLabel(
            right_col,
            text="[ Kamera Siap ]\nKlik 'Nyalakan Kamera Webcam' di bawah.",
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
            height=34,
            fg_color=COLOR_PRIMARY,
        )
        self.btn_cam_toggle.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.btn_verify_face = ctk.CTkButton(
            cam_btn_row,
            text="👤 Verifikasi Wajah",
            command=self._on_verify_face,
            height=34,
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
        self.badge_face.pack(anchor="w", padx=16, pady=(4, 12))

    # =======================================================================
    # 2. USER & HARDWARE ENROLLMENT
    # =======================================================================

    def _build_register_tab(self):
        container = ctk.CTkScrollableFrame(self.tab_register, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=12, pady=12)

        # 1. New Account Info
        sec1 = ctk.CTkFrame(container, fg_color=BG_INPUT, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        sec1.pack(fill="x", pady=(0, 12))

        lbl1 = ctk.CTkLabel(sec1, text="1. DAFTAR PENGGUNA BARU", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_CYAN)
        lbl1.pack(anchor="w", padx=16, pady=(12, 6))

        row1 = ctk.CTkFrame(sec1, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=4)
        self.reg_user = ctk.CTkEntry(row1, placeholder_text="Username unik", height=36)
        self.reg_user.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.reg_pass = ctk.CTkEntry(row1, placeholder_text="Password aman", show="•", height=36)
        self.reg_pass.pack(side="right", fill="x", expand=True, padx=(6, 0))

        row2 = ctk.CTkFrame(sec1, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=(4, 12))
        self.reg_name = ctk.CTkEntry(row2, placeholder_text="Nama Lengkap (akan dienkripsi AES-GCM)", height=36)
        self.reg_name.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.reg_email = ctk.CTkEntry(row2, placeholder_text="Email Dinas (akan dienkripsi AES-GCM)", height=36)
        self.reg_email.pack(side="right", fill="x", expand=True, padx=(6, 0))

        # 2. Register Physical USB Dongle
        sec2 = ctk.CTkFrame(container, fg_color=BG_INPUT, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        sec2.pack(fill="x", pady=(0, 12))

        lbl2 = ctk.CTkLabel(sec2, text="2. DAFTARKAN PHYSICAL USB DONGLE", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_CYAN)
        lbl2.pack(anchor="w", padx=16, pady=(12, 6))

        d_row = ctk.CTkFrame(sec2, fg_color="transparent")
        d_row.pack(fill="x", padx=16, pady=4)

        self.combo_drives = ctk.CTkComboBox(d_row, values=["(Klik Refresh Drive)"], height=36, width=320)
        self.combo_drives.pack(side="left", padx=(0, 8))

        btn_refresh = ctk.CTkButton(d_row, text="🔄 Refresh", width=90, height=36, command=self._refresh_drive_list)
        btn_refresh.pack(side="left", padx=4)

        self.btn_deploy_dongle = ctk.CTkButton(
            d_row,
            text="🏷️ Format & Jadikan Dongle Resmi",
            height=36,
            fg_color=COLOR_PRIMARY,
            command=self._on_register_dongle_device,
        )
        self.btn_deploy_dongle.pack(side="right", padx=(8, 0))

        self.lbl_reg_dongle_status = ctk.CTkLabel(
            sec2,
            text="Pilih drive flashdisk Anda lalu klik 'Format & Jadikan Dongle Resmi'.",
            font=(FONT_FAMILY, 11),
            text_color=TEXT_MUTED,
        )
        self.lbl_reg_dongle_status.pack(anchor="w", padx=16, pady=(4, 12))

        # 3. Enroll Face Biometrics
        sec3 = ctk.CTkFrame(container, fg_color=BG_INPUT, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        sec3.pack(fill="x", pady=(0, 12))

        lbl3 = ctk.CTkLabel(sec3, text="3. REKAM BIOMETRIK WAJAH (KAMERA LIVE)", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_CYAN)
        lbl3.pack(anchor="w", padx=16, pady=(12, 6))

        face_btn_row = ctk.CTkFrame(sec3, fg_color="transparent")
        face_btn_row.pack(fill="x", padx=16, pady=4)

        self.btn_capture_faces = ctk.CTkButton(
            face_btn_row,
            text="📸 Rekam 5 Sampel Wajah Live & Latih Model",
            height=38,
            fg_color=COLOR_PRIMARY,
            command=self._on_capture_enroll_faces,
        )
        self.btn_capture_faces.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.lbl_face_enroll_status = ctk.CTkLabel(
            sec3,
            text="Pastikan kamera menyala dan wajah terlihat jelas di layar.",
            font=(FONT_FAMILY, 11),
            text_color=TEXT_MUTED,
        )
        self.lbl_face_enroll_status.pack(anchor="w", padx=16, pady=(4, 12))

        # Final Submit Button
        self.btn_save_user = ctk.CTkButton(
            container,
            text="💾 SIMPAN PENDAFTARAN LENGKAP PENGGUNA",
            font=(FONT_FAMILY, 14, "bold"),
            height=46,
            fg_color=COLOR_SUCCESS,
            command=self._on_complete_registration,
        )
        self.btn_save_user.pack(fill="x", pady=(8, 16))

        # Auto-populate drives dropdown on startup
        self._refresh_drive_list()

    # =======================================================================
    # Real-Time Camera Loop
    # =======================================================================

    def _toggle_camera(self):
        if self.camera_running:
            self._stop_camera()
        else:
            self._start_camera()

    def _start_camera(self):
        if self.camera_running:
            return

        try:
            # Try DirectShow on Windows first
            self.cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
            if not self.cap or not self.cap.isOpened():
                self.cap = cv2.VideoCapture(0)

            if not self.cap.isOpened():
                self.cam_preview.configure(
                    text="[ Kamera Fisik Tidak Ditemukan ]\nPastikan webcam Anda terpasang.",
                    image=None,
                )
                return

            self.camera_running = True
            self.btn_cam_toggle.configure(text="⏹ Matikan Kamera", fg_color=COLOR_DANGER)
            self._update_camera_frame()

        except Exception as exc:
            logger.error("Camera open error: %s", exc)
            self.cam_preview.configure(text=f"Error Kamera: {exc}", image=None)

    def _stop_camera(self):
        self.camera_running = False
        if self.cap:
            try:
                self.cap.release()
            except Exception:
                pass
            self.cap = None
        self.btn_cam_toggle.configure(text="📷 Nyalakan Kamera", fg_color=COLOR_PRIMARY)
        self.cam_preview.configure(text="[ Kamera Mati ]\nKlik 'Nyalakan Kamera' untuk mengaktifkan.", image=None)

    def _update_camera_frame(self):
        if not self.camera_running or not self.cap:
            return

        ret, frame = self.cap.read()
        if ret and frame is not None:
            self.current_frame_bgr = frame.copy()

            # Detect faces and draw a clean cyberpunk bounding box
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
            ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(360, 240))
            self.cam_preview.configure(image=ctk_img, text="")

        # Schedule next frame in 30ms (~33 FPS)
        if self.camera_running:
            self.after(30, self._update_camera_frame)

    # =======================================================================
    # Dongle Scanning & Verification
    # =======================================================================

    def _refresh_drive_list(self):
        drives = scan_physical_usb_drives()
        items = []
        for d in drives:
            tag = " [REMOVABLE]" if d["is_removable"] else ""
            items.append(f"{d['mount']} - {d['vol_name']} (VSN: {d['vsn']}){tag}")
        if not items:
            items = ["(Tidak ada drive terdeteksi)"]
        self.combo_drives.configure(values=items)
        self.combo_drives.set(items[0])

    def _on_scan_and_verify_dongle(self):
        username = self.entry_user.get().strip()
        user = self.user_repo.get_by_username(username)
        expected_vsn = user.get("registered_vsn") if user else None

        ok, msg, d_info = verify_dongle_for_user(expected_vsn)
        if ok:
            self.dongle_verified = True
            self.badge_dongle.configure(text="[ USB DONGLE TERVERIFIKASI ✓ ]", text_color=COLOR_SUCCESS)
            self.txt_dongle_info.configure(text=msg, text_color=COLOR_SUCCESS)
        else:
            self.dongle_verified = False
            self.badge_dongle.configure(text="[ DONGLE TIDAK VALID ✗ ]", text_color=COLOR_DANGER)
            self.txt_dongle_info.configure(text=msg, text_color=COLOR_DANGER)

        self._check_all_factors()

    def _on_register_dongle_device(self):
        selected = self.combo_drives.get()
        if not selected or selected.startswith("("):
            self.lbl_reg_dongle_status.configure(text="Pilih drive yang valid terlebih dahulu.", text_color=COLOR_DANGER)
            return

        drive_letter = selected.split()[0]
        username = self.reg_user.get().strip() or "default"

        try:
            res = register_usb_dongle(drive_letter, username)
            self.lbl_reg_dongle_status.configure(
                text=f"✓ Drive {res['mount']} sukses didaftarkan sebagai Dongle! (VSN: {res['vsn']})",
                text_color=COLOR_SUCCESS,
            )
            self.reg_vsn_cache = res["vsn"]
        except Exception as exc:
            self.lbl_reg_dongle_status.configure(text=f"Gagal mendaftarkan dongle: {exc}", text_color=COLOR_DANGER)

    # =======================================================================
    # Face Biometric Capture & Verification
    # =======================================================================

    def _on_capture_enroll_faces(self):
        username = self.reg_user.get().strip()
        if not username:
            self.lbl_face_enroll_status.configure(text="Isi username terlebih dahulu sebelum merekam wajah.", text_color=COLOR_DANGER)
            return

        if not self.camera_running:
            self._start_camera()

        self.lbl_face_enroll_status.configure(text="Sedang merekam 5 frame wajah... Harap menghadap kamera.", text_color=COLOR_WARNING)

        # Threaded capture to avoid freezing UI
        def _capture_thread():
            samples = []
            for i in range(5):
                time.sleep(0.4)
                if self.current_frame_bgr is not None:
                    faces = self.face_engine.detect_faces(self.current_frame_bgr)
                    if faces:
                        crop = self.face_engine.extract_face_crop(self.current_frame_bgr, faces[0])
                        samples.append(crop)

            if len(samples) >= 3:
                success = self.face_engine.enroll_user(username, samples, preview_frame=self.current_frame_bgr)
                if success:
                    self.after(
                        0,
                        lambda: self.lbl_face_enroll_status.configure(
                            text=f"✓ Sukses merekam {len(samples)} sampel wajah & melatih model biometrik!",
                            text_color=COLOR_SUCCESS,
                        ),
                    )
                else:
                    self.after(
                        0,
                        lambda: self.lbl_face_enroll_status.configure(
                            text="Gagal melatih model pengenalan wajah.", text_color=COLOR_DANGER
                        ),
                    )
            else:
                self.after(
                    0,
                    lambda: self.lbl_face_enroll_status.configure(
                        text="Wajah tidak terdeteksi secara stabil (dapat < 3 frame). Coba lagi.", text_color=COLOR_DANGER
                    ),
                )

        threading.Thread(target=_capture_thread, daemon=True).start()

    def _on_verify_face(self):
        username = self.entry_user.get().strip()
        if not username:
            self.badge_face.configure(text="[ MASUKKAN USERNAME DULU ]", text_color=COLOR_DANGER)
            return

        if not self.camera_running:
            self._start_camera()
            time.sleep(0.2)

        if self.current_frame_bgr is None:
            self.badge_face.configure(text="[ TIDAK ADA FRAME KAMERA ]", text_color=COLOR_DANGER)
            return

        ok, score, bbox, msg = self.face_engine.verify_face(username, self.current_frame_bgr)
        if ok:
            self.face_verified = True
            self.badge_face.configure(text=f"[ WAJAH TERVERIFIKASI ✓ ({score:.1f}%) ]", text_color=COLOR_SUCCESS)
        else:
            self.face_verified = False
            self.badge_face.configure(text=f"[ WAJAH DITOLAK ✗ ({score:.1f}%) ]", text_color=COLOR_DANGER)

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

    def _on_complete_registration(self):
        u = self.reg_user.get().strip()
        p = self.reg_pass.get()
        name = self.reg_name.get().strip()
        email = self.reg_email.get().strip()

        if not u or not p:
            self.lbl_face_enroll_status.configure(text="Username dan Password wajib diisi!", text_color=COLOR_DANGER)
            return

        try:
            pw_hash = hash_password(p)
            uid = self.user_repo.create(username=u, password_hash=pw_hash, full_name=name, email=email)

            if hasattr(self, "reg_vsn_cache"):
                self.user_repo.update_dongle_vsn(uid, self.reg_vsn_cache)

            if self.face_engine.is_user_enrolled(u):
                self.user_repo.update_face_status(uid, 1)

            log_audit(uid, "USER_REGISTERED", f"Username={u}")
            self.lbl_face_enroll_status.configure(
                text=f"✓ Pengguna '{u}' berhasil didaftarkan ke SQLite (AES-GCM encrypted)! Silakan login.",
                text_color=COLOR_SUCCESS,
            )
            # Switch back to login tab
            self.tabview.set("🔐 Dual-Factor Login Gate")
            self.entry_user.delete(0, "end")
            self.entry_user.insert(0, u)
            self.entry_pass.delete(0, "end")
            self.entry_pass.insert(0, p)

        except Exception as exc:
            self.lbl_face_enroll_status.configure(text=f"Pendaftaran gagal: {exc}", text_color=COLOR_DANGER)

