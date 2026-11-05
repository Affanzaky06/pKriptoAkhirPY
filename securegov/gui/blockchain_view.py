# securegov/gui/blockchain_view.py
"""
Blockchain Audit Trail & Integrity Ledger View
===============================================
Displays the immutable audit ledger tracking document encryptions, logins,
and cryptographic operations, with full cryptographic integrity verification.
"""

import json
import time
from datetime import datetime
import customtkinter as ctk

from securegov.blockchain.chain import Blockchain
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


class BlockchainView(ctk.CTkFrame):
    """View tab for the Blockchain Audit Ledger & Tamper Detection Suite."""

    def __init__(self, master, current_user: dict, blockchain: Blockchain, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.current_user = current_user
        self.blockchain = blockchain
        self._build_ui()

    def _build_ui(self):
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=16, pady=16)

        # Header Title & Status Bar
        header = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        header.pack(fill="x", pady=(0, 12))

        lbl_head = ctk.CTkLabel(
            header,
            text="⛓️ IMMUTABLE BLOCKCHAIN AUDIT LEDGER (SHA-256)",
            font=(FONT_FAMILY, 17, "bold"),
            text_color=COLOR_CYAN,
        )
        lbl_head.pack(side="left", padx=16, pady=12)

        self.lbl_chain_status = ctk.CTkLabel(
            header,
            text="[ CHAIN STATUS: UNVERIFIED ]",
            font=(FONT_FAMILY, 12, "bold"),
            text_color=COLOR_WARNING,
        )
        self.lbl_chain_status.pack(side="right", padx=16, pady=12)

        # Action Buttons Row
        bar = ctk.CTkFrame(container, fg_color="transparent")
        bar.pack(fill="x", pady=(0, 10))

        btn_verify = ctk.CTkButton(
            bar,
            text="🛡️ Verifikasi Integritas Seluruh Blockchain",
            fg_color=COLOR_SUCCESS,
            height=38,
            font=(FONT_FAMILY, 12, "bold"),
            command=self._verify_chain,
        )
        btn_verify.pack(side="left", padx=(0, 8))

        btn_refresh = ctk.CTkButton(
            bar,
            text="🔄 Refresh Ledger",
            width=120,
            height=38,
            fg_color=COLOR_PRIMARY,
            command=self._refresh_table,
        )
        btn_refresh.pack(side="left", padx=4)

        btn_tamper = ctk.CTkButton(
            bar,
            text="⚠️ Simulasikan Tampering (Uji Dosen/Penguji)",
            height=38,
            fg_color=COLOR_DANGER,
            command=self._simulate_tamper,
        )
        btn_tamper.pack(side="right", padx=(8, 0))

        btn_restore = ctk.CTkButton(
            bar,
            text="♻️ Pulihkan Ledger",
            height=38,
            fg_color=BG_HOVER,
            command=self._restore_chain,
        )
        btn_restore.pack(side="right", padx=4)

        # Scrollable Blocks Display
        self.blocks_container = ctk.CTkScrollableFrame(
            container,
            fg_color=BG_INPUT,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_CARD,
        )
        self.blocks_container.pack(fill="both", expand=True)

        self._refresh_table()
        self._verify_chain()

    def _format_time(self, ts: float) -> str:
        try:
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)

    def _refresh_table(self):
        # Clear existing cards
        for widget in self.blocks_container.winfo_children():
            widget.destroy()

        blocks = self.blockchain.chain
        if not blocks:
            lbl_empty = ctk.CTkLabel(
                self.blocks_container,
                text="Blockchain masih kosong.",
                font=(FONT_FAMILY, 12),
                text_color=TEXT_MUTED,
            )
            lbl_empty.pack(pady=40)
            return

        # Render each block as an informative card
        for b in reversed(blocks):  # newest first
            b_card = ctk.CTkFrame(
                self.blocks_container,
                fg_color=BG_CARD,
                corner_radius=8,
                border_width=1,
                border_color=BORDER_CARD,
            )
            b_card.pack(fill="x", padx=10, pady=6)

            # Top header row of block
            row_top = ctk.CTkFrame(b_card, fg_color="transparent")
            row_top.pack(fill="x", padx=12, pady=(8, 4))

            idx_lbl = ctk.CTkLabel(
                row_top,
                text=f"BLOCK #{b.index}",
                font=(FONT_FAMILY, 13, "bold"),
                text_color=COLOR_PRIMARY if b.index > 0 else COLOR_CYAN,
            )
            idx_lbl.pack(side="left")

            time_lbl = ctk.CTkLabel(
                row_top,
                text=f"🕒 {self._format_time(b.timestamp)} UTC",
                font=(FONT_FAMILY, 11),
                text_color=TEXT_MUTED,
            )
            time_lbl.pack(side="right")

            # Data payload formatted
            data_str = json.dumps(b.data, ensure_ascii=False)
            data_lbl = ctk.CTkLabel(
                b_card,
                text=f"Data Event: {data_str}",
                font=(FONT_FAMILY, 11),
                text_color=TEXT_BODY,
                justify="left",
                wraplength=760,
            )
            data_lbl.pack(anchor="w", padx=12, pady=2)

            # Hash row
            hash_box = ctk.CTkFrame(b_card, fg_color=BG_INPUT, corner_radius=6)
            hash_box.pack(fill="x", padx=12, pady=(4, 8))

            prev_lbl = ctk.CTkLabel(
                hash_box,
                text=f"Previous Hash: {b.previous_hash}",
                font=("Consolas", 10),
                text_color=TEXT_MUTED,
                anchor="w",
            )
            prev_lbl.pack(fill="x", padx=8, pady=(4, 1))

            cur_lbl = ctk.CTkLabel(
                hash_box,
                text=f"Current Hash:  {b.hash}",
                font=("Consolas", 10, "bold"),
                text_color=COLOR_SUCCESS,
                anchor="w",
            )
            cur_lbl.pack(fill="x", padx=8, pady=(1, 4))

    def _verify_chain(self):
        is_intact = self.blockchain.is_valid()
        if is_intact:
            self.lbl_chain_status.configure(
                text=f"✓ BLOCKCHAIN INTACT ({len(self.blockchain.chain)} BLOCKS TAMPER-PROOF)",
                text_color=COLOR_SUCCESS,
            )
        else:
            self.lbl_chain_status.configure(
                text="✗ INTEGRITY VIOLATION: TAMPERING DETECTED IN CHAIN!",
                text_color=COLOR_DANGER,
            )

    def _simulate_tamper(self):
        """Intentionally modify block data to demonstrate cryptographic detection."""
        if len(self.blockchain.chain) >= 2:
            self.blockchain.chain[1].data["TAMPERED_BY"] = "MALICIOUS_ADVERSARY_ATTACK"
            self._verify_chain()
            self._refresh_table()
            logger.warning("Tamper simulation executed on Block #1")
        elif len(self.blockchain.chain) == 1:
            self.blockchain.chain[0].data["event"] = "CORRUPTED_GENESIS"
            self._verify_chain()
            self._refresh_table()

    def _restore_chain(self):
        """Re-read valid chain from disk."""
        try:
            self.blockchain._load()
            self._verify_chain()
            self._refresh_table()
        except Exception as exc:
            logger.error("Restore chain error: %s", exc)

