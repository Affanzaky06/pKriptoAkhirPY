# app.py
"""
SecureGov / Enterprise DocVault — Desktop Application
======================================================
Desktop GUI Architecture implementing strict dual-factor hardware security:
  - Factor 1: Real physical USB Dongle scanning (psutil + ctypes kernel32).
  - Factor 2: Real live webcam face recognition (OpenCV Haar + LBPH).
  - Multi-Role RBAC:
      * Unauthenticated: Login Gate only (no registration available).
      * Role 'User': Access to Super-Encryption, File Vault, Stegano Suite, Blockchain Audit.
      * Role 'Admin': Exclusive access to User Administration & Biometric Provisioning.
  - Dead-Man's Switch: Continuous USB Dongle presence monitoring.
"""

import os
import sys
from typing import Optional

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import customtkinter as ctk

from securegov.database.models import init_db
from securegov.blockchain.chain import Blockchain
from securegov.utils.key_manager import KeyManager
from securegov.gui.styles import (
    BG_MAIN,
    BG_SIDEBAR,
    BG_CARD,
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
from securegov.gui.auth_view import AuthView
from securegov.gui.super_crypto_view import SuperCryptoView
from securegov.gui.file_crypto_view import FileCryptoView
from securegov.gui.stego_view import StegoView
from securegov.gui.blockchain_view import BlockchainView
from securegov.gui.admin_view import AdminUserManagementView
from securegov.utils.logger import get_logger

logger = get_logger("app")


class SecureGovApp(ctk.CTk):
    """Main Desktop Application Window."""

    def __init__(self):
        super().__init__()

        # Window Configuration
        self.title("SecureGov / Enterprise DocVault — Defense Cryptosystem")
        self.geometry("1200x750")
        self.minsize(1050, 680)
        self.configure(fg_color=BG_MAIN)

        # Handle window closing to ensure clean resource disposal (cameras, timers)
        self.protocol("WM_DELETE_WINDOW", self._on_close_app)

        # Initialize core cryptographic services
        init_db()
        self.blockchain = Blockchain(difficulty=0)
        self.key_manager = KeyManager()
        if not os.path.isfile(self.key_manager.private_key_path):
            self.key_manager.generate_rsa_keypair()

        # Session state
        self.current_user: Optional[dict] = None
        self.is_unlocked: bool = False
        self.last_username: str = "Affan"
        self._dongle_miss_count: int = 0

        self._build_layout()
        self._show_auth_view()

    def _build_layout(self):
        # ----------------- SIDEBAR -----------------
        self.sidebar = ctk.CTkFrame(
            self,
            width=250,
            fg_color=BG_SIDEBAR,
            corner_radius=0,
            border_width=1,
            border_color=BORDER_CARD,
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # App Brand Header
        lbl_brand = ctk.CTkLabel(
            self.sidebar,
            text="🛡️ SECUREGOV",
            font=(FONT_FAMILY, 20, "bold"),
            text_color=COLOR_CYAN,
        )
        lbl_brand.pack(anchor="w", padx=20, pady=(24, 2))

        lbl_sub = ctk.CTkLabel(
            self.sidebar,
            text="Enterprise DocVault v1.0",
            font=(FONT_FAMILY, 11),
            text_color=TEXT_MUTED,
        )
        lbl_sub.pack(anchor="w", padx=20, pady=(0, 20))

        # Clearance Status Badge Card
        self.status_card = ctk.CTkFrame(self.sidebar, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_CARD)
        self.status_card.pack(fill="x", padx=16, pady=(0, 20))

        self.lbl_status_icon = ctk.CTkLabel(
            self.status_card,
            text="🔒 VAULT LOCKED",
            font=(FONT_FAMILY, 12, "bold"),
            text_color=COLOR_DANGER,
        )
        self.lbl_status_icon.pack(padx=12, pady=(10, 2))

        self.lbl_status_desc = ctk.CTkLabel(
            self.status_card,
            text="Dual-Factor (USB + Wajah) Diperlukan",
            font=(FONT_FAMILY, 10),
            text_color=TEXT_MUTED,
            wraplength=190,
        )
        self.lbl_status_desc.pack(padx=12, pady=(0, 4))

        self.lbl_dongle_watcher = ctk.CTkLabel(
            self.status_card,
            text="🛡️ Dongle Watcher: INACTIVE",
            font=(FONT_FAMILY, 9, "bold"),
            text_color=TEXT_MUTED,
        )
        self.lbl_dongle_watcher.pack(padx=12, pady=(0, 8))

        # Nav Buttons
        self.nav_buttons = {}

        nav_items = [
            ("gate", "🔒 Access Control Gate", self._show_auth_view),
            ("super", "🔐 Super-Encryption", self._show_super_crypto_view),
            ("file", "📁 File Vault", self._show_file_crypto_view),
            ("stego", "🖼️ Stego Suite", self._show_stego_view),
            ("chain", "⛓️ Blockchain Audit", self._show_blockchain_view),
            ("admin", "👥 User Management (Admin)", self._show_admin_view),
        ]

        for key, text, cmd in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=text,
                anchor="w",
                font=(FONT_FAMILY, 12),
                height=40,
                fg_color="transparent",
                hover_color=BG_HOVER,
                text_color=TEXT_BODY,
                command=cmd,
            )
            btn.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[key] = btn

        # Auto-Lock on Dongle Removal Switch (Dead-Man's Switch)
        self.auto_lock_var = ctk.BooleanVar(value=True)
        self.switch_auto_lock = ctk.CTkSwitch(
            self.sidebar,
            text="Auto-Lock saat Dongle Dicabut",
            font=(FONT_FAMILY, 10),
            variable=self.auto_lock_var,
            onvalue=True,
            offvalue=False,
            text_color=TEXT_MUTED,
            progress_color=COLOR_SUCCESS,
        )
        self.switch_auto_lock.pack(side="bottom", fill="x", padx=16, pady=(0, 8))

        # Logout / Lock Button
        self.btn_lock = ctk.CTkButton(
            self.sidebar,
            text="🔒 Kunci Kembali Vault",
            font=(FONT_FAMILY, 11, "bold"),
            height=36,
            fg_color=BG_CARD,
            hover_color=COLOR_DANGER,
            text_color=TEXT_MUTED,
            command=self._lock_vault,
        )
        self.btn_lock.pack(side="bottom", fill="x", padx=16, pady=(0, 16))

        # Initial Locked State: disable feature tabs & hide admin tab
        self._apply_locked_state(locked=True)

        # ----------------- MAIN WORKSPACE -----------------
        self.workspace = ctk.CTkFrame(self, fg_color="transparent")
        self.workspace.pack(side="right", fill="both", expand=True)

    def _apply_locked_state(self, locked: bool):
        self.is_unlocked = not locked
        if locked:
            self.lbl_status_icon.configure(text="🔒 VAULT LOCKED", text_color=COLOR_DANGER)
            self.lbl_status_desc.configure(text="Dual-Factor (USB + Wajah) Diperlukan")
            self.lbl_dongle_watcher.configure(text="🛡️ Dongle Watcher: INACTIVE", text_color=TEXT_MUTED)
            # Disable all feature nav buttons — login required first
            for k in ["super", "file", "stego", "chain"]:
                if k in self.nav_buttons:
                    self.nav_buttons[k].configure(state="disabled", text_color=TEXT_MUTED)
            # Hide admin button entirely when locked
            if "admin" in self.nav_buttons:
                self.nav_buttons["admin"].pack_forget()
            self.btn_lock.configure(state="disabled")
        else:
            uname = self.current_user["username"] if self.current_user else "User"
            role = (self.current_user.get("role") or "user").lower() if self.current_user else "user"
            role_display = role.upper()
            self.lbl_status_icon.configure(text="✓ ACCESS GRANTED", text_color=COLOR_SUCCESS)
            self.lbl_status_desc.configure(text=f"Cleared: {uname} [{role_display}]")
            self.lbl_dongle_watcher.configure(text="🛡️ Dongle Watcher: ACTIVE", text_color=COLOR_SUCCESS)

            # Enable standard operational feature tabs
            for k in ["super", "file", "stego", "chain"]:
                self.nav_buttons[k].configure(state="normal", text_color=TEXT_TITLE)

            # Show admin tab only for admin role
            if role == "admin":
                self.nav_buttons["admin"].pack(fill="x", padx=12, pady=3, before=self.switch_auto_lock)
                self.nav_buttons["admin"].configure(state="normal", text_color="#F59E0B")
            else:
                self.nav_buttons["admin"].pack_forget()

            self.btn_lock.configure(state="normal")

    def _clear_workspace(self):
        """Safely clean up any camera/timer resources on children before destroying."""
        for widget in list(self.workspace.winfo_children()):
            if hasattr(widget, "cleanup") and callable(widget.cleanup):
                try:
                    widget.cleanup()
                except Exception as exc:
                    logger.debug("Widget cleanup error: %s", exc)
            try:
                widget.destroy()
            except Exception as exc:
                logger.debug("Widget destroy error: %s", exc)
        # Force Tkinter to process all pending events/destructions before building new view
        try:
            self.update_idletasks()
        except Exception:
            pass

    def _set_active_nav(self, active_key: str):
        for k, btn in self.nav_buttons.items():
            if k == active_key:
                btn.configure(fg_color=COLOR_PRIMARY, text_color=TEXT_TITLE)
            else:
                default_color = "#F59E0B" if k == "admin" else TEXT_BODY
                btn.configure(fg_color="transparent", text_color=default_color)

    # ----------------- VIEW SWITCHERS -----------------

    def _show_auth_view(self):
        self._clear_workspace()
        self._set_active_nav("gate")
        view = AuthView(
            self.workspace,
            on_login_success=self._on_login_cleared,
            default_username=self.last_username,
        )
        view.pack(fill="both", expand=True)

    def _show_super_crypto_view(self):
        if not self.is_unlocked:
            self._show_login_required_dialog()
            return
        self._clear_workspace()
        self._set_active_nav("super")
        view = SuperCryptoView(
            self.workspace,
            current_user=self.current_user,
            blockchain=self.blockchain,
            on_action_check=self._assert_dongle_still_present,
        )
        view.pack(fill="both", expand=True)

    def _show_file_crypto_view(self):
        if not self.is_unlocked:
            self._show_login_required_dialog()
            return
        self._clear_workspace()
        self._set_active_nav("file")
        view = FileCryptoView(
            self.workspace,
            current_user=self.current_user,
            blockchain=self.blockchain,
            on_action_check=self._assert_dongle_still_present,
        )
        view.pack(fill="both", expand=True)

    def _show_stego_view(self):
        if not self.is_unlocked:
            self._show_login_required_dialog()
            return
        self._clear_workspace()
        self._set_active_nav("stego")
        view = StegoView(
            self.workspace,
            current_user=self.current_user,
            blockchain=self.blockchain,
            on_action_check=self._assert_dongle_still_present,
        )
        view.pack(fill="both", expand=True)

    def _show_blockchain_view(self):
        if not self.is_unlocked:
            self._show_login_required_dialog()
            return
        self._clear_workspace()
        self._set_active_nav("chain")
        view = BlockchainView(
            self.workspace,
            current_user=self.current_user,
            blockchain=self.blockchain,
        )
        view.pack(fill="both", expand=True)

    def _show_admin_view(self):
        if not self.is_unlocked:
            self._show_login_required_dialog()
            return
        self._clear_workspace()
        self._set_active_nav("admin")
        view = AdminUserManagementView(
            self.workspace,
            current_user=self.current_user,
            blockchain=self.blockchain,
            on_action_check=self._assert_dongle_still_present,
        )
        view.pack(fill="both", expand=True)

    # ----------------- SESSION CONTROLS -----------------

    def _on_login_cleared(self, user_dict: dict):
        """Called when Dual-Factor authentication succeeds."""
        self.current_user = user_dict
        self.last_username = user_dict.get("username", self.last_username)
        self._dongle_miss_count = 0
        self._apply_locked_state(locked=False)

        # Automatically record to Blockchain
        self.blockchain.add_block({
            "event": "USER_SESSION_UNLOCKED",
            "user": user_dict["username"],
            "role": user_dict.get("role", "user"),
            "auth_method": "DUAL_FACTOR_PHYSICAL_USB_AND_FACE_BIOMETRIC",
        })

        # Start continuous hardware dongle watcher (Dead-Man's Switch)
        self.after(1000, self._check_dongle_presence)

        # Switch to main view — _clear_workspace handles safe destruction via update_idletasks
        self._show_super_crypto_view()

    def _get_active_dongle_vsn(self) -> Optional[str]:
        """Resolve the registered hardware VSN for the current session."""
        if not self.current_user:
            return None
        vsn = (
            self.current_user.get("registered_vsn")
            or self.current_user.get("usb_serial")
            or self.current_user.get("active_vsn")
        )
        if not vsn and self.current_user.get("username"):
            try:
                from securegov.database.models import UserRepository
                user_row = UserRepository().get_by_username(self.current_user["username"])
                if user_row:
                    vsn = user_row.get("registered_vsn")
            except Exception:
                pass
        return vsn

    def _assert_dongle_still_present(self) -> bool:
        """
        Instant hardware check triggered before sensitive cryptographic operations
        (e.g. encrypting/decrypting files or messages).
        Includes rapid retry tolerance to prevent false positive lockouts from transient Windows USB bus delays.
        """
        if not self.is_unlocked or not self.current_user:
            self._show_login_required_dialog()
            return False

        if self.auto_lock_var.get():
            expected_vsn = self._get_active_dongle_vsn()
            from securegov.auth.usb_dongle import verify_dongle_for_user
            import time
            ok = False
            for _ in range(3):
                ok, msg, _ = verify_dongle_for_user(expected_vsn)
                if ok:
                    break
                time.sleep(0.1)

            if not ok:
                uname = self.current_user.get("username", "User")
                vsn_display = expected_vsn or "AUTHORIZED_DONGLE"
                logger.warning("PHYSICAL BREACH: Dongle unplugged on action! Revoking vault.")
                self.blockchain.add_block({
                    "event": "DONGLE_PHYSICALLY_REMOVED_AUTO_LOCK",
                    "user": uname,
                    "vsn": vsn_display,
                    "action": "ACTION_INTERCEPTED_AND_LOCKED",
                })
                self._on_dongle_unplugged_emergency(uname, vsn_display)
                return False
        return True

    def _show_login_required_dialog(self):
        """Show informative dialog when user attempts cryptographic actions without logging in."""
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("🔐 AUTENTIKASI DIPERLUKAN")
        dialog.geometry("460x240")
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)
        dialog.configure(fg_color=BG_CARD)

        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 460) // 2
        y = self.winfo_y() + (self.winfo_height() - 240) // 2
        dialog.geometry(f"+{x}+{y}")

        lbl_t = ctk.CTkLabel(
            dialog,
            text="🔒 VAULT SEDANG TERKUNCI",
            font=(FONT_FAMILY, 15, "bold"),
            text_color=COLOR_WARNING,
        )
        lbl_t.pack(pady=(22, 8))

        lbl_m = ctk.CTkLabel(
            dialog,
            text=(
                "Fitur kriptografi ini (enkripsi dokumen, steganografi, & dekripsi) "
                "dilindungi oleh Dual-Factor Authentication.\n\n"
                "Harap lakukan otentikasi (Password + USB Dongle + Biometrik Wajah) "
                "di tab Access Control Gate untuk membuka akses penuh."
            ),
            font=(FONT_FAMILY, 11),
            text_color=TEXT_TITLE,
            wraplength=400,
            justify="center",
        )
        lbl_m.pack(pady=4, padx=20)

        row_btn = ctk.CTkFrame(dialog, fg_color="transparent")
        row_btn.pack(pady=(16, 12))

        btn_go = ctk.CTkButton(
            row_btn,
            text="👉 Buka Access Control Gate",
            font=(FONT_FAMILY, 11, "bold"),
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_CYAN,
            command=lambda: (dialog.destroy(), self._show_auth_view()),
        )
        btn_go.pack(side="left", padx=6)

        btn_close = ctk.CTkButton(
            row_btn,
            text="Tutup",
            font=(FONT_FAMILY, 11),
            fg_color=BG_HOVER,
            text_color=TEXT_MUTED,
            command=dialog.destroy,
        )
        btn_close.pack(side="left", padx=6)

    def _check_dongle_presence(self):
        """
        Continuous Hardware Presence Enforcement (Dead-Man's Switch).
        If the registered USB Dongle is physically removed during an active session,
        the vault automatically revokes access and immediately locks itself.
        Requires 3 consecutive misses (~3 seconds) to prevent false positives from transient USB bus contention.
        """
        # Safety guard: if window no longer exists, stop polling
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return

        if not self.is_unlocked or not self.current_user:
            self._dongle_miss_count = 0
            return

        try:
            if self.auto_lock_var.get():
                expected_vsn = self._get_active_dongle_vsn()
                from securegov.auth.usb_dongle import verify_dongle_for_user
                ok, msg, _ = verify_dongle_for_user(expected_vsn)
                if not ok:
                    self._dongle_miss_count = getattr(self, "_dongle_miss_count", 0) + 1
                    logger.debug("Dongle presence check missed (%d/3)", self._dongle_miss_count)
                    # Require 3 consecutive misses (3 seconds) to avoid transient false positives
                    if self._dongle_miss_count >= 3:
                        uname = self.current_user.get("username", "User")
                        vsn_display = expected_vsn or "AUTHORIZED_DONGLE"
                        logger.warning(
                            "PHYSICAL BREACH: Dongle VSN '%s' for '%s' unplugged! Locking vault.",
                            vsn_display, uname
                        )

                        # Record emergency lock in Blockchain
                        self.blockchain.add_block({
                            "event": "DONGLE_PHYSICALLY_REMOVED_AUTO_LOCK",
                            "user": uname,
                            "vsn": vsn_display,
                            "action": "SESSION_REVOKED_AND_VAULT_LOCKED",
                        })

                        self._on_dongle_unplugged_emergency(uname, vsn_display)
                        return
                else:
                    self._dongle_miss_count = 0
                    short_vsn = expected_vsn if expected_vsn else "OK"
                    self.lbl_dongle_watcher.configure(
                        text=f"🟢 Dongle Active ({short_vsn})",
                        text_color=COLOR_SUCCESS
                    )
        except Exception as exc:
            logger.error("Error in _check_dongle_presence: %s", exc)

        # Reschedule next polling check in 1000 ms (1 second) with safety guard
        try:
            if self.is_unlocked and self.winfo_exists():
                self.after(1000, self._check_dongle_presence)
        except Exception:
            pass

    def _on_dongle_unplugged_emergency(self, username: str, vsn: str):
        """Handle sudden physical removal of the authorized dongle."""
        self._lock_vault()

        # Safety: don't show dialog if window is being destroyed
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return

        # Display high-visibility warning dialog
        dialog = ctk.CTkToplevel(self)
        dialog.title("⚠️ HARDWARE SECURITY ALERT")
        dialog.geometry("480x240")
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)
        dialog.configure(fg_color=BG_CARD)

        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 480) // 2
        y = self.winfo_y() + (self.winfo_height() - 240) // 2
        dialog.geometry(f"+{x}+{y}")

        lbl_t = ctk.CTkLabel(
            dialog,
            text="🚨 USB DONGLE FISIK DICABUT!",
            font=(FONT_FAMILY, 15, "bold"),
            text_color=COLOR_DANGER,
        )
        lbl_t.pack(pady=(22, 10))

        lbl_m = ctk.CTkLabel(
            dialog,
            text=(
                f"Flashdisk USB resmi (VSN: {vsn}) milik '{username}' tidak lagi terdeteksi.\n\n"
                "Sesuai protokol keamanan tingkat tinggi (Dead-Man's Switch), "
                "seluruh sesi kerja telah dicabut dan aplikasi langsung dikunci kembali secara otomatis."
            ),
            font=(FONT_FAMILY, 11),
            text_color=TEXT_TITLE,
            wraplength=420,
            justify="center",
        )
        lbl_m.pack(pady=6, padx=20)

        btn_ok = ctk.CTkButton(
            dialog,
            text="Kembali ke Login Gate",
            width=160,
            height=36,
            font=(FONT_FAMILY, 11, "bold"),
            fg_color=COLOR_PRIMARY,
            command=dialog.destroy,
        )
        btn_ok.pack(pady=(16, 16))

    def _lock_vault(self):
        """Lock the vault and return to access control gate."""
        if self.current_user:
            self.blockchain.add_block({
                "event": "USER_SESSION_LOCKED",
                "user": self.current_user["username"],
            })
        self.current_user = None
        self._apply_locked_state(locked=True)
        self._show_auth_view()

    def _on_close_app(self):
        """Clean shutdown hook to release camera feeds and terminate timers."""
        logger.info("Application exit requested: releasing hardware devices and views...")
        # Stop dongle watcher immediately to prevent race condition
        self.is_unlocked = False
        self.current_user = None
        try:
            self._clear_workspace()
        except Exception as exc:
            logger.error("Error during workspace cleanup on close: %s", exc)
        try:
            self.destroy()
        except Exception as exc:
            logger.error("Error during destroy on close: %s", exc)
        # Force-terminate the process if destroy hangs (e.g. blocked camera release)
        import sys
        sys.exit(0)


def main():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = SecureGovApp()
    app.mainloop()


if __name__ == "__main__":
    main()
