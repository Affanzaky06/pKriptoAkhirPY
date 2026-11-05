# app.py
"""
SecureGov / Enterprise DocVault — Desktop Application
======================================================
Desktop GUI Architecture implementing strict dual-factor hardware security:
  - Factor 1: Real physical USB Dongle scanning (psutil + ctypes kernel32).
  - Factor 2: Real live webcam face recognition (OpenCV Haar + LBPH).
  - All main features (Super-Encryption, File Vault, Steganography, Blockchain)
    are strictly LOCKED and disabled until dual-factor clearance is passed.
"""

import os
import sys

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

        # Initialize core cryptographic services
        init_db()
        self.blockchain = Blockchain(difficulty=0)
        self.key_manager = KeyManager()
        if not os.path.isfile(self.key_manager.private_key_path):
            self.key_manager.generate_rsa_keypair()

        # Session state
        self.current_user = None
        self.is_unlocked = False
        self.last_username = "Affan"

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
        self.lbl_status_desc.pack(padx=12, pady=(0, 10))

        # Nav Buttons (LOCKED by default!)
        self.nav_buttons = {}

        nav_items = [
            ("gate", "🔒 Access Control Gate", self._show_auth_view),
            ("super", "🔐 Super-Encryption", self._show_super_crypto_view),
            ("file", "📁 File Vault", self._show_file_crypto_view),
            ("stego", "🖼️ Stego Suite", self._show_stego_view),
            ("chain", "⛓️ Blockchain Audit", self._show_blockchain_view),
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

        # Initial Locked State: disable all feature tabs!
        self._apply_locked_state(locked=True)

        # ----------------- MAIN WORKSPACE -----------------
        self.workspace = ctk.CTkFrame(self, fg_color="transparent")
        self.workspace.pack(side="right", fill="both", expand=True)

    def _apply_locked_state(self, locked: bool):
        self.is_unlocked = not locked
        if locked:
            self.lbl_status_icon.configure(text="🔒 VAULT LOCKED", text_color=COLOR_DANGER)
            self.lbl_status_desc.configure(text="Dual-Factor (USB + Wajah) Diperlukan")
            # Disable feature tabs
            for k in ["super", "file", "stego", "chain"]:
                self.nav_buttons[k].configure(state="disabled", text_color=TEXT_MUTED)
            self.btn_lock.configure(state="disabled")
        else:
            uname = self.current_user["username"] if self.current_user else "User"
            self.lbl_status_icon.configure(text=f"✓ ACCESS GRANTED", text_color=COLOR_SUCCESS)
            self.lbl_status_desc.configure(text=f"Cleared: {uname} (Active Session)")
            # Enable feature tabs
            for k in ["super", "file", "stego", "chain"]:
                self.nav_buttons[k].configure(state="normal", text_color=TEXT_TITLE)
            self.btn_lock.configure(state="normal")

    def _clear_workspace(self):
        for widget in self.workspace.winfo_children():
            widget.destroy()

    def _set_active_nav(self, active_key: str):
        for k, btn in self.nav_buttons.items():
            if k == active_key:
                btn.configure(fg_color=COLOR_PRIMARY, text_color=TEXT_TITLE)
            else:
                btn.configure(fg_color="transparent")

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
            return
        self._clear_workspace()
        self._set_active_nav("super")
        view = SuperCryptoView(self.workspace, current_user=self.current_user, blockchain=self.blockchain)
        view.pack(fill="both", expand=True)

    def _show_file_crypto_view(self):
        if not self.is_unlocked:
            return
        self._clear_workspace()
        self._set_active_nav("file")
        view = FileCryptoView(self.workspace, current_user=self.current_user, blockchain=self.blockchain)
        view.pack(fill="both", expand=True)

    def _show_stego_view(self):
        if not self.is_unlocked:
            return
        self._clear_workspace()
        self._set_active_nav("stego")
        view = StegoView(self.workspace, current_user=self.current_user, blockchain=self.blockchain)
        view.pack(fill="both", expand=True)

    def _show_blockchain_view(self):
        if not self.is_unlocked:
            return
        self._clear_workspace()
        self._set_active_nav("chain")
        view = BlockchainView(self.workspace, current_user=self.current_user, blockchain=self.blockchain)
        view.pack(fill="both", expand=True)

    # ----------------- SESSION CONTROLS -----------------

    def _on_login_cleared(self, user_dict: dict):
        """Called when Dual-Factor authentication succeeds."""
        self.current_user = user_dict
        self.last_username = user_dict.get("username", self.last_username)
        self._apply_locked_state(locked=False)

        # Automatically record to Blockchain
        self.blockchain.add_block({
            "event": "USER_SESSION_UNLOCKED",
            "user": user_dict["username"],
            "role": user_dict.get("role", "user"),
            "auth_method": "DUAL_FACTOR_PHYSICAL_USB_AND_FACE_BIOMETRIC",
        })

        # Transition to Super-Encryption as default landing tab
        self._show_super_crypto_view()

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


def main():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = SecureGovApp()
    app.mainloop()


if __name__ == "__main__":
    main()

