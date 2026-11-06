# securegov/gui/admin_view.py
"""
Role-Based Access Control (RBAC) & User Administration Console
==============================================================
Restricted exclusively to authenticated Administrator accounts (role == 'admin').
Provides:
  1. Real-time audit of all registered accounts, roles, dongles, and biometrics.
  2. Provisioning of new regular 'User' accounts and new 'Admin' accounts.
  3. Hardware USB Dongle key formatting and VSN association.
  4. Live Facial Biometric Capture (Haar Cascade + LBPH training).
  5. Automatic anchoring of every provisioning action into the Blockchain Audit Ledger.
"""

import os
import sqlite3
import threading
import time
from typing import Optional

import cv2
import numpy as np
from PIL import Image
import customtkinter as ctk

from securegov.auth.credential_manager import hash_password
from securegov.auth.usb_dongle import scan_physical_usb_drives, register_usb_dongle
from securegov.auth.biometric import RealFaceBiometric
from securegov.database.models import UserRepository, log_audit
from securegov.blockchain.chain import Blockchain
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


class AdminUserManagementView(ctk.CTkFrame):
    """Admin-only console for user lifecycle management and biometric provisioning."""

    def __init__(
        self,
        master,
        current_user: dict,
        blockchain: Blockchain,
        on_action_check=None,
        **kwargs,
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.current_user = current_user
        self.blockchain = blockchain
        self.on_action_check = on_action_check

        self.user_repo = UserRepository()
        self.face_engine = RealFaceBiometric()

        # Camera state
        self.cap: Optional[cv2.VideoCapture] = None
        self.camera_running = False
        self.current_frame_bgr: Optional[np.ndarray] = None
        self._cam_after_ids: list = []
        self._cam_after_id: Optional[str] = None
        self._current_ctk_img: Optional[ctk.CTkImage] = None
        self._is_destroyed: bool = False

        self.reg_vsn_cache: Optional[str] = None

        self._build_ui()

    def _build_ui(self):
        # Strict RBAC verification gate
        user_role = (self.current_user.get("role") or "").lower()
        if user_role != "admin":
            self._render_access_denied()
            return

        container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=16, pady=16)

        # Header Title
        header = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        header.pack(fill="x", pady=(0, 14))

        lbl_head = ctk.CTkLabel(
            header,
            text="👥 USER & BIOMETRIC PROVISIONING CONSOLE (ADMIN ONLY)",
            font=(FONT_FAMILY, 16, "bold"),
            text_color=COLOR_CYAN,
        )
        lbl_head.pack(side="left", padx=16, pady=12)

        lbl_admin_badge = ctk.CTkLabel(
            header,
            text=f"👑 Authorized Admin: {self.current_user.get('username')}",
            font=(FONT_FAMILY, 11, "bold"),
            text_color=COLOR_SUCCESS,
        )
        lbl_admin_badge.pack(side="right", padx=16, pady=12)

        # -------------------------------------------------------------------
        # SECTION 1: Registered Accounts Directory
        # -------------------------------------------------------------------
        sec_dir = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        sec_dir.pack(fill="x", pady=(0, 14))

        row_dir_title = ctk.CTkFrame(sec_dir, fg_color="transparent")
        row_dir_title.pack(fill="x", padx=16, pady=(12, 6))

        lbl_dir = ctk.CTkLabel(
            row_dir_title,
            text="1. DIREKTORI PENGGUNA TERDAFTAR (RBAC LEDGER)",
            font=(FONT_FAMILY, 13, "bold"),
            text_color=COLOR_PRIMARY,
        )
        lbl_dir.pack(side="left")

        btn_refresh_table = ctk.CTkButton(
            row_dir_title,
            text="🔄 Refresh Direktori",
            width=140,
            height=30,
            font=(FONT_FAMILY, 11),
            command=self._refresh_users_table,
        )
        btn_refresh_table.pack(side="right")

        self.table_container = ctk.CTkFrame(sec_dir, fg_color=BG_INPUT, corner_radius=8)
        self.table_container.pack(fill="x", padx=16, pady=(4, 16))

        # -------------------------------------------------------------------
        # SECTION 2: Provision New User / Admin Account
        # -------------------------------------------------------------------
        sec_prov = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        sec_prov.pack(fill="x", pady=(0, 14))

        lbl_prov = ctk.CTkLabel(
            sec_prov,
            text="2. PROVISIONING AKUN & PENETAPAN HAK AKSES BARU",
            font=(FONT_FAMILY, 13, "bold"),
            text_color=COLOR_CYAN,
        )
        lbl_prov.pack(anchor="w", padx=16, pady=(14, 6))

        # Account Details Row 1 (Role, Username, Password)
        row1 = ctk.CTkFrame(sec_prov, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=4)

        lbl_role = ctk.CTkLabel(row1, text="Role:", font=(FONT_FAMILY, 11, "bold"), text_color=TEXT_MUTED)
        lbl_role.pack(side="left", padx=(0, 6))

        self.combo_role = ctk.CTkComboBox(
            row1,
            values=["User", "Admin"],
            width=110,
            height=36,
            font=(FONT_FAMILY, 11, "bold"),
        )
        self.combo_role.set("User")
        self.combo_role.pack(side="left", padx=(0, 12))

        self.entry_user = ctk.CTkEntry(row1, placeholder_text="Username unik", height=36, font=(FONT_FAMILY, 12))
        self.entry_user.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.entry_pass = ctk.CTkEntry(row1, placeholder_text="Password aman", show="•", height=36, font=(FONT_FAMILY, 12))
        self.entry_pass.pack(side="right", fill="x", expand=True, padx=(6, 0))

        # Account Details Row 2 (Full Name, Email)
        row2 = ctk.CTkFrame(sec_prov, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=4)

        self.entry_name = ctk.CTkEntry(row2, placeholder_text="Nama Lengkap (dienkripsi AES-256-GCM)", height=36)
        self.entry_name.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.entry_email = ctk.CTkEntry(row2, placeholder_text="Email Dinas (dienkripsi AES-256-GCM)", height=36)
        self.entry_email.pack(side="right", fill="x", expand=True, padx=(6, 0))

        # Hardware USB Dongle Provisioning Sub-Box
        box_dongle = ctk.CTkFrame(sec_prov, fg_color=BG_INPUT, corner_radius=8)
        box_dongle.pack(fill="x", padx=16, pady=(8, 8))

        lbl_dongle_h = ctk.CTkLabel(box_dongle, text="🔑 HARDWARE DONGLE PROVISIONING", font=(FONT_FAMILY, 11, "bold"), text_color=COLOR_PRIMARY)
        lbl_dongle_h.pack(anchor="w", padx=12, pady=(8, 4))

        row_d = ctk.CTkFrame(box_dongle, fg_color="transparent")
        row_d.pack(fill="x", padx=12, pady=4)

        self.combo_drives = ctk.CTkComboBox(row_d, values=["(Klik Refresh)"], height=34, width=320)
        self.combo_drives.pack(side="left", padx=(0, 8))

        btn_refresh_drv = ctk.CTkButton(row_d, text="🔄 Scan Drive", width=95, height=34, command=self._refresh_drive_list)
        btn_refresh_drv.pack(side="left", padx=4)

        self.btn_deploy_dongle = ctk.CTkButton(
            row_d,
            text="🏷️ Format & Jadikan Dongle Resmi",
            height=34,
            fg_color=COLOR_PRIMARY,
            command=self._on_format_and_deploy_dongle,
        )
        self.btn_deploy_dongle.pack(side="right", padx=(8, 0))

        self.lbl_dongle_status = ctk.CTkLabel(
            box_dongle,
            text="Tancapkan flashdisk USB calon pengguna lalu klik 'Format & Jadikan Dongle Resmi'.",
            font=(FONT_FAMILY, 10),
            text_color=TEXT_MUTED,
        )
        self.lbl_dongle_status.pack(anchor="w", padx=12, pady=(2, 8))

        # Facial Biometrics Sub-Box
        box_face = ctk.CTkFrame(sec_prov, fg_color=BG_INPUT, corner_radius=8)
        box_face.pack(fill="x", padx=16, pady=(4, 12))

        row_face_h = ctk.CTkFrame(box_face, fg_color="transparent")
        row_face_h.pack(fill="x", padx=12, pady=(8, 4))

        lbl_face_h = ctk.CTkLabel(row_face_h, text="👤 WEBCAM FACIAL BIOMETRIC ENROLLMENT", font=(FONT_FAMILY, 11, "bold"), text_color=COLOR_PRIMARY)
        lbl_face_h.pack(side="left")

        # Camera index selector
        self.combo_cam_idx = ctk.CTkComboBox(
            row_face_h,
            values=["Camera 0"],
            width=110,
            height=28,
            font=(FONT_FAMILY, 10),
            dropdown_font=(FONT_FAMILY, 10),
            command=self._on_camera_device_changed,
        )
        self.combo_cam_idx.pack(side="right", padx=(4, 0))

        btn_refresh_cam = ctk.CTkButton(
            row_face_h,
            text="🔄",
            width=30,
            height=28,
            font=(FONT_FAMILY, 11),
            fg_color=BG_HOVER,
            command=self._refresh_camera_devices,
        )
        btn_refresh_cam.pack(side="right")

        # Camera Preview & Control
        preview_row = ctk.CTkFrame(box_face, fg_color="transparent")
        preview_row.pack(fill="x", padx=12, pady=4)

        self.cam_preview = ctk.CTkLabel(
            preview_row,
            text="[ Kamera Mati ]\nNyalakan kamera untuk merekam wajah pengguna.",
            font=(FONT_FAMILY, 11),
            text_color=TEXT_MUTED,
            fg_color="#000000",
            corner_radius=6,
            width=280,
            height=180,
        )
        self.cam_preview.pack(side="left", padx=(0, 12))

        ctrl_col = ctk.CTkFrame(preview_row, fg_color="transparent")
        ctrl_col.pack(side="left", fill="both", expand=True)

        self.btn_cam_toggle = ctk.CTkButton(
            ctrl_col,
            text="📷 Nyalakan Kamera",
            height=34,
            fg_color=COLOR_PRIMARY,
            command=self._toggle_camera,
        )
        self.btn_cam_toggle.pack(fill="x", pady=4)

        self.btn_capture_faces = ctk.CTkButton(
            ctrl_col,
            text="📸 Rekam 5 Sampel Wajah & Latih Model LBPH",
            height=38,
            fg_color=COLOR_CYAN,
            hover_color=COLOR_PRIMARY,
            command=self._on_capture_enroll_faces,
        )
        self.btn_capture_faces.pack(fill="x", pady=4)

        self.lbl_face_status = ctk.CTkLabel(
            ctrl_col,
            text="Pastikan pengguna menghadap lurus ke webcam saat merekam.",
            font=(FONT_FAMILY, 10),
            text_color=TEXT_MUTED,
            wraplength=320,
            justify="left",
        )
        self.lbl_face_status.pack(anchor="w", pady=(4, 4))

        # Save & Provision Button
        self.btn_save_account = ctk.CTkButton(
            sec_prov,
            text="💾 SIMPAN PENDAFTARAN & ANCHOR KE BLOCKCHAIN",
            font=(FONT_FAMILY, 13, "bold"),
            height=44,
            fg_color=COLOR_SUCCESS,
            command=self._on_submit_new_account,
        )
        self.btn_save_account.pack(fill="x", padx=16, pady=(8, 16))

        # Initial data loading
        self._refresh_users_table()
        self._refresh_drive_list()
        self._refresh_camera_devices()

    def _render_access_denied(self):
        banner = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12, border_width=2, border_color=COLOR_DANGER)
        banner.pack(fill="both", expand=True, padx=40, pady=40)

        lbl_icon = ctk.CTkLabel(banner, text="⛔ AKSES DITOLAK: HANYA ADMINISTRATOR", font=(FONT_FAMILY, 18, "bold"), text_color=COLOR_DANGER)
        lbl_icon.pack(pady=(40, 10))

        lbl_desc = ctk.CTkLabel(
            banner,
            text=(
                f"Sesi pengguna aktif '{self.current_user.get('username')}' memiliki peran "
                f"'{self.current_user.get('role', 'user')}'.\n\n"
                "Sesuai prinsip Role-Based Access Control (RBAC), pendaftaran akun baru, "
                "pemberian wewenang Admin, dan provisioning dongle perangkat keras "
                "hanya dapat diakses oleh Administrator resmi."
            ),
            font=(FONT_FAMILY, 12),
            text_color=TEXT_BODY,
            justify="center",
            wraplength=520,
        )
        lbl_desc.pack(pady=10, padx=20)

    # =======================================================================
    # Users Directory Table
    # =======================================================================

    def _refresh_users_table(self):
        for w in self.table_container.winfo_children():
            w.destroy()

        try:
            from securegov.utils.config import DB_PATH
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, username, role, registered_vsn, face_registered, created_at, is_active "
                "FROM users ORDER BY id ASC"
            ).fetchall()
            conn.close()

            # Table Header
            h_row = ctk.CTkFrame(self.table_container, fg_color="#1E293B", corner_radius=4)
            h_row.pack(fill="x", padx=6, pady=4)

            for col_name, width in [("ID", 40), ("Username", 140), ("Role", 80), ("USB VSN", 130), ("Biometrik", 100), ("Status", 80)]:
                lbl = ctk.CTkLabel(h_row, text=col_name, font=(FONT_FAMILY, 10, "bold"), text_color=COLOR_CYAN, width=width, anchor="w")
                lbl.pack(side="left", padx=6, pady=4)

            # Table Rows
            for r in rows:
                item_row = ctk.CTkFrame(self.table_container, fg_color="transparent")
                item_row.pack(fill="x", padx=6, pady=2)

                is_admin = (r["role"] == "admin")
                role_color = "#F59E0B" if is_admin else COLOR_CYAN
                role_text = "👑 Admin" if is_admin else "👤 User"

                face_text = "✓ Terdaftar" if r["face_registered"] else "—"
                face_color = COLOR_SUCCESS if r["face_registered"] else TEXT_MUTED

                vsn_text = r["registered_vsn"] or "(Belum ada)"

                ctk.CTkLabel(item_row, text=str(r["id"]), font=(FONT_FAMILY, 10), width=40, anchor="w", text_color=TEXT_MUTED).pack(side="left", padx=6)
                ctk.CTkLabel(item_row, text=r["username"], font=(FONT_FAMILY, 11, "bold"), width=140, anchor="w", text_color=TEXT_TITLE).pack(side="left", padx=6)
                ctk.CTkLabel(item_row, text=role_text, font=(FONT_FAMILY, 10, "bold"), width=80, anchor="w", text_color=role_color).pack(side="left", padx=6)
                ctk.CTkLabel(item_row, text=vsn_text, font=("Consolas", 10), width=130, anchor="w", text_color=TEXT_BODY).pack(side="left", padx=6)
                ctk.CTkLabel(item_row, text=face_text, font=(FONT_FAMILY, 10), width=100, anchor="w", text_color=face_color).pack(side="left", padx=6)
                ctk.CTkLabel(item_row, text="Aktif" if r["is_active"] else "Nonaktif", font=(FONT_FAMILY, 10), width=80, anchor="w", text_color=COLOR_SUCCESS).pack(side="left", padx=6)

        except Exception as exc:
            logger.error("Error refreshing users table: %s", exc)

    # =======================================================================
    # Camera Device Management & Frame Loop
    # =======================================================================

    def _refresh_camera_devices(self):
        try:
            cams = list_available_cameras(max_tested=3)
        except Exception:
            cams = []
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
                        text=f"[ Kamera {cam_idx} Gagal Dibuka ]\nPastikan webcam tidak sedang digunakan oleh aplikasi lain.",
                        image=None,
                    )
                return

            self.camera_running = True
            if self.winfo_exists():
                self.btn_cam_toggle.configure(text="⏹ Matikan Kamera", fg_color=COLOR_DANGER)
            self._update_camera_frame()

        except Exception as exc:
            logger.error("Admin camera open error: %s", exc)
            if self.winfo_exists():
                self.cam_preview.configure(text=f"Error Kamera: {exc}", image=None)

    def _stop_camera(self):
        self.camera_running = False
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
                self.cam_preview.configure(text="[ Kamera Mati ]\nNyalakan kamera untuk merekam wajah.", image=None)
        except Exception:
            pass

    def _update_camera_frame(self):
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

                display_frame = frame.copy()
                faces = self.face_engine.detect_faces(display_frame)
                for (x, y, w, h) in faces:
                    cv2.rectangle(display_frame, (x, y), (x + w, y + h), (0, 255, 128), 2)
                    cv2.putText(
                        display_frame,
                        "FACE DETECTED",
                        (x, max(15, y - 6)),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        0.5,
                        (0, 255, 128),
                        1,
                        cv2.LINE_AA,
                    )

                rgb = cv2.cvtColor(display_frame, cv2.COLOR_BGR2RGB)
                pil_img = Image.fromarray(rgb)
                self._current_ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(280, 180))
                self.cam_preview.configure(image=self._current_ctk_img, text="")

        except Exception as exc:
            logger.debug("Admin frame loop warning: %s", exc)

        if not self._is_destroyed and self.camera_running:
            try:
                if self.winfo_exists():
                    aid = self.after(30, self._update_camera_frame)
                    self._cam_after_ids.append(aid)
                    self._cam_after_id = aid
            except Exception:
                pass

    # =======================================================================
    # Dongle Provisioning
    # =======================================================================

    def _refresh_drive_list(self):
        drives = scan_physical_usb_drives()
        items = []
        for d in drives:
            tag = " [REMOVABLE]" if d["is_removable"] else ""
            items.append(f"{d['mount']} - {d['vol_name']} (VSN: {d['vsn']}){tag}")
        if not items:
            items = ["(Tidak ada flashdisk USB terdeteksi)"]
        self.combo_drives.configure(values=items)
        self.combo_drives.set(items[0])

    def _on_format_and_deploy_dongle(self):
        if self.on_action_check and not self.on_action_check():
            return

        selected = self.combo_drives.get()
        if not selected or selected.startswith("("):
            self.lbl_dongle_status.configure(text="Pilih drive flashdisk yang valid terlebih dahulu.", text_color=COLOR_DANGER)
            return

        drive_letter = selected.split()[0]
        target_user = self.entry_user.get().strip()
        if not target_user:
            self.lbl_dongle_status.configure(text="Masukkan Username akun terlebih dahulu sebelum memformat dongle.", text_color=COLOR_DANGER)
            return

        try:
            res = register_usb_dongle(drive_letter, target_user)
            self.reg_vsn_cache = res["vsn"]
            self.lbl_dongle_status.configure(
                text=f"✓ Drive {res['mount']} sukses diformat sebagai Dongle Resmi! (VSN: {res['vsn']})",
                text_color=COLOR_SUCCESS,
            )
        except Exception as exc:
            self.lbl_dongle_status.configure(text=f"Gagal memformat dongle: {exc}", text_color=COLOR_DANGER)

    # =======================================================================
    # Face Enrollment
    # =======================================================================

    def _on_capture_enroll_faces(self):
        if self.on_action_check and not self.on_action_check():
            return

        target_user = self.entry_user.get().strip()
        if not target_user:
            self.lbl_face_status.configure(text="Isi username terlebih dahulu sebelum merekam wajah.", text_color=COLOR_DANGER)
            return

        if not self.camera_running:
            self._start_camera()

        self.lbl_face_status.configure(text="Sedang merekam 5 frame wajah... Harap menghadap ke webcam.", text_color=COLOR_WARNING)

        def _capture_thread():
            samples = []
            for _ in range(5):
                time.sleep(0.4)
                if self.current_frame_bgr is not None:
                    faces = self.face_engine.detect_faces(self.current_frame_bgr)
                    if faces:
                        crop = self.face_engine.extract_face_crop(self.current_frame_bgr, faces[0])
                        samples.append(crop)

            if len(samples) >= 3:
                success = self.face_engine.enroll_user(target_user, samples, preview_frame=self.current_frame_bgr)
                if success:
                    self.after(
                        0,
                        lambda: self.lbl_face_status.configure(
                            text=f"✓ Sukses merekam {len(samples)} sampel wajah & melatih model biometrik LBPH!",
                            text_color=COLOR_SUCCESS,
                        ),
                    )
                else:
                    self.after(
                        0,
                        lambda: self.lbl_face_status.configure(
                            text="Gagal melatih model pengenalan wajah LBPH.", text_color=COLOR_DANGER
                        ),
                    )
            else:
                self.after(
                    0,
                    lambda: self.lbl_face_status.configure(
                        text="Wajah tidak terdeteksi stabil (<3 frame). Coba lagi menghadap kamera.", text_color=COLOR_DANGER
                    ),
                )

        threading.Thread(target=_capture_thread, daemon=True).start()

    # =======================================================================
    # Account Submission & Blockchain Logging
    # =======================================================================

    def _on_submit_new_account(self):
        if self.on_action_check and not self.on_action_check():
            return

        target_role = self.combo_role.get().strip().lower()
        u = self.entry_user.get().strip()
        p = self.entry_pass.get()
        name = self.entry_name.get().strip()
        email = self.entry_email.get().strip()

        if not u or not p:
            self.lbl_face_status.configure(text="Username dan Password wajib diisi!", text_color=COLOR_DANGER)
            return

        # Check existing user
        if self.user_repo.get_by_username(u):
            self.lbl_face_status.configure(text=f"Username '{u}' sudah terdaftar! Pilih username lain.", text_color=COLOR_DANGER)
            return

        try:
            pw_hash = hash_password(p)
            uid = self.user_repo.create(
                username=u,
                password_hash=pw_hash,
                full_name=name,
                email=email,
                role=target_role,
            )

            vsn_saved = self.reg_vsn_cache
            if vsn_saved:
                self.user_repo.update_dongle_vsn(uid, vsn_saved)

            face_enrolled = self.face_engine.is_user_enrolled(u)
            if face_enrolled:
                self.user_repo.update_face_status(uid, 1)

            # Record to Blockchain Audit Ledger
            self.blockchain.add_block({
                "event": "USER_PROVISIONED_BY_ADMIN",
                "admin_actor": self.current_user["username"],
                "new_user": u,
                "assigned_role": target_role,
                "dongle_vsn": vsn_saved or "UNASSIGNED",
                "face_enrolled": bool(face_enrolled),
            })

            log_audit(
                self.current_user["id"],
                "ADMIN_USER_PROVISIONED",
                f"Created user={u} role={target_role} vsn={vsn_saved}",
            )

            self.lbl_face_status.configure(
                text=f"✓ Akun '{u}' (Role: {target_role.upper()}) berhasil dibuat & dicatat ke Blockchain!",
                text_color=COLOR_SUCCESS,
            )

            # Clear inputs and refresh directory
            self.entry_user.delete(0, "end")
            self.entry_pass.delete(0, "end")
            self.entry_name.delete(0, "end")
            self.entry_email.delete(0, "end")
            self.reg_vsn_cache = None
            self.lbl_dongle_status.configure(text="Siap untuk provisioning berikutnya.", text_color=TEXT_MUTED)

            self._refresh_users_table()

        except Exception as exc:
            logger.error("Failed to provision account: %s", exc)
            self.lbl_face_status.configure(text=f"Pendaftaran gagal: {exc}", text_color=COLOR_DANGER)

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
