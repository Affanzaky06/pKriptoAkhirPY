# securegov/gui/super_crypto_view.py
"""
Super-Encryption for Text Messages (Classic + Modern)
======================================================
Provides a graphical interface to:
  Layer 1: Classic Cipher (Vigenère or Playfair).
  Layer 2: Modern Cipher (AES-256-GCM Authenticated Encryption).
"""

import customtkinter as ctk

from securegov.crypto.super_encryption import SuperEncryptor
from securegov.blockchain.chain import Blockchain
from securegov.database.models import log_audit
from securegov.gui.styles import (
    BG_CARD,
    BG_INPUT,
    COLOR_PRIMARY,
    COLOR_CYAN,
    COLOR_SUCCESS,
    COLOR_DANGER,
    TEXT_TITLE,
    TEXT_BODY,
    TEXT_MUTED,
    BORDER_CARD,
    FONT_FAMILY,
)
from securegov.utils.logger import get_logger

logger = get_logger(__name__)


class SuperCryptoView(ctk.CTkFrame):
    """View tab for two-layer Super Encryption of text messages."""

    def __init__(self, master, current_user: dict, blockchain: Blockchain, on_action_check=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.current_user = current_user
        self.blockchain = blockchain
        self.on_action_check = on_action_check
        self._build_ui()

    def _build_ui(self):
        container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=16, pady=16)

        # Header Title
        lbl_head = ctk.CTkLabel(
            container,
            text="🔐 SUPER-ENCRYPTION SUITE (CLASSIC + MODERN AES-256)",
            font=(FONT_FAMILY, 18, "bold"),
            text_color=COLOR_CYAN,
        )
        lbl_head.pack(anchor="w", pady=(0, 12))

        # Config Panel (Keys & Algorithm)
        cfg_frame = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        cfg_frame.pack(fill="x", pady=(0, 14))

        cfg_title = ctk.CTkLabel(cfg_frame, text="KUNCI & ALGORITMA KRIPTOGRAFI", font=(FONT_FAMILY, 12, "bold"), text_color=COLOR_PRIMARY)
        cfg_title.pack(anchor="w", padx=16, pady=(12, 6))

        row_cfg = ctk.CTkFrame(cfg_frame, fg_color="transparent")
        row_cfg.pack(fill="x", padx=16, pady=(0, 12))

        lbl_algo = ctk.CTkLabel(row_cfg, text="Classic Cipher:", font=(FONT_FAMILY, 11))
        lbl_algo.pack(side="left", padx=(0, 6))

        self.combo_algo = ctk.CTkComboBox(row_cfg, values=["vigenere", "playfair"], width=130)
        self.combo_algo.set("vigenere")
        self.combo_algo.pack(side="left", padx=(0, 16))

        lbl_k1 = ctk.CTkLabel(row_cfg, text="Key Classic:", font=(FONT_FAMILY, 11))
        lbl_k1.pack(side="left", padx=(0, 6))

        self.entry_classic_key = ctk.CTkEntry(row_cfg, placeholder_text="Contoh: SECRETKEY", width=160)
        self.entry_classic_key.insert(0, "SECUREGOV")
        self.entry_classic_key.pack(side="left", padx=(0, 16))

        lbl_k2 = ctk.CTkLabel(row_cfg, text="Key AES (32 bytes):", font=(FONT_FAMILY, 11))
        lbl_k2.pack(side="left", padx=(0, 6))

        self.entry_aes_key = ctk.CTkEntry(row_cfg, placeholder_text="32 karakter untuk AES-256", width=240)
        self.entry_aes_key.insert(0, "SuperEncr32ByteKeyForDevOnly!!!!")
        self.entry_aes_key.pack(side="left", fill="x", expand=True)

        # Two Columns: Encryption (Left) and Decryption (Right)
        cols_frame = ctk.CTkFrame(container, fg_color="transparent")
        cols_frame.pack(fill="both", expand=True)

        # ----------------- LEFT: ENCRYPTION -----------------
        left_box = ctk.CTkFrame(cols_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        left_box.pack(side="left", fill="both", expand=True, padx=(0, 8))

        lbl_enc_title = ctk.CTkLabel(left_box, text="1. ENKRIPSI PESAN (SUPER-ENCRYPT)", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_SUCCESS)
        lbl_enc_title.pack(anchor="w", padx=16, pady=(14, 6))

        lbl_pt = ctk.CTkLabel(left_box, text="Pesan Teks Asli (Plaintext):", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_pt.pack(anchor="w", padx=16)

        self.txt_plaintext = ctk.CTkTextbox(left_box, height=100, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_plaintext.pack(fill="x", padx=16, pady=4)
        self.txt_plaintext.insert("1.0", "CLASSIFIED: Dokumen Rencana Strategis Negara Tahun 2026.")

        btn_run_enc = ctk.CTkButton(
            left_box,
            text="⚡ Jalankan Super-Encryption (Classic → AES-256-GCM)",
            height=38,
            fg_color=COLOR_PRIMARY,
            command=self._do_encrypt,
        )
        btn_run_enc.pack(fill="x", padx=16, pady=8)

        lbl_out1 = ctk.CTkLabel(left_box, text="Hasil Layer-1 (Classic Ciphertext):", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_out1.pack(anchor="w", padx=16)
        self.txt_classic_ct = ctk.CTkEntry(left_box, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_classic_ct.pack(fill="x", padx=16, pady=4)

        lbl_out2 = ctk.CTkLabel(left_box, text="Hasil Final Super-Cipher Token (AES-256-GCM Base64):", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_out2.pack(anchor="w", padx=16)
        self.txt_final_token = ctk.CTkTextbox(left_box, height=110, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_final_token.pack(fill="x", padx=16, pady=(4, 16))

        # ----------------- RIGHT: DECRYPTION -----------------
        right_box = ctk.CTkFrame(cols_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        right_box.pack(side="right", fill="both", expand=True, padx=(8, 0))

        lbl_dec_title = ctk.CTkLabel(right_box, text="2. DEKRIPSI PESAN (SUPER-DECRYPT)", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_CYAN)
        lbl_dec_title.pack(anchor="w", padx=16, pady=(14, 6))

        lbl_in_token = ctk.CTkLabel(right_box, text="Masukkan Token Terenkripsi (Base64 JSON):", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_in_token.pack(anchor="w", padx=16)

        self.txt_in_token = ctk.CTkTextbox(right_box, height=100, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_in_token.pack(fill="x", padx=16, pady=4)

        btn_run_dec = ctk.CTkButton(
            right_box,
            text="🔓 Jalankan Super-Decryption (AES-256-GCM → Classic)",
            height=38,
            fg_color=COLOR_CYAN,
            hover_color=COLOR_PRIMARY,
            command=self._do_decrypt,
        )
        btn_run_dec.pack(fill="x", padx=16, pady=8)

        lbl_rec_pt = ctk.CTkLabel(right_box, text="Pesan Asli yang Berhasil Dipulihkan:", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_rec_pt.pack(anchor="w", padx=16)

        self.txt_recovered_pt = ctk.CTkTextbox(right_box, height=135, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_recovered_pt.pack(fill="x", padx=16, pady=(4, 16))

    def _get_encryptor(self) -> SuperEncryptor:
        classic_key = self.entry_classic_key.get().strip()
        algo = self.combo_algo.get()
        aes_key_raw = self.entry_aes_key.get().encode("utf-8")
        if len(aes_key_raw) < 32:
            aes_key_raw = aes_key_raw.ljust(32, b"!")
        else:
            aes_key_raw = aes_key_raw[:32]
        return SuperEncryptor(aes_key=aes_key_raw, classic_key=classic_key, classic_algo=algo)

    def _do_encrypt(self):
        if self.on_action_check and not self.on_action_check():
            return
        pt = self.txt_plaintext.get("1.0", "end").strip()
        if not pt:
            return

        try:
            se = self._get_encryptor()
            # Show layer 1
            classic_ct = se._classic.encrypt(pt)
            self.txt_classic_ct.delete(0, "end")
            self.txt_classic_ct.insert(0, classic_ct)

            # Show final token
            token = se.encrypt(pt)
            self.txt_final_token.delete("1.0", "end")
            self.txt_final_token.insert("1.0", token)

            # Auto-paste to decrypt box for convenience
            self.txt_in_token.delete("1.0", "end")
            self.txt_in_token.insert("1.0", token)

            # Log to Blockchain & Audit DB
            self.blockchain.add_block({
                "event": "SUPER_ENCRYPTION_PERFORMED",
                "user": self.current_user["username"],
                "algo": se._algo,
                "msg_len": len(pt),
            })
            log_audit(self.current_user["id"], "SUPER_ENCRYPT", f"algo={se._algo}")

        except Exception as exc:
            self.txt_final_token.delete("1.0", "end")
            self.txt_final_token.insert("1.0", f"Error Enkripsi: {exc}")

    def _do_decrypt(self):
        if self.on_action_check and not self.on_action_check():
            return
        token = self.txt_in_token.get("1.0", "end").strip()
        if not token:
            return

        try:
            se = self._get_encryptor()
            rec = se.decrypt(token)
            self.txt_recovered_pt.delete("1.0", "end")
            self.txt_recovered_pt.insert("1.0", rec)

            self.blockchain.add_block({
                "event": "SUPER_DECRYPTION_PERFORMED",
                "user": self.current_user["username"],
                "algo": se._algo,
                "status": "AUTHENTICATED_OK",
            })
            log_audit(self.current_user["id"], "SUPER_DECRYPT", "Success")

        except Exception as exc:
            self.txt_recovered_pt.delete("1.0", "end")
            self.txt_recovered_pt.insert("1.0", f"✗ DEKRIPSI GAGAL / TAMPER DETECTED: {exc}")

