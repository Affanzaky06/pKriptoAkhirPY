# securegov/gui/blockchain_view.py
"""
Blockchain Audit Trail & Integrity Ledger View
===============================================
Displays the immutable audit ledger tracking document encryptions, logins,
user/admin provisioning, and cryptographic operations, with full cryptographic
integrity verification, multi-block dynamic tampering simulation, and instantaneous rollback/repair.
"""

import json
import random
import time
from datetime import datetime
from typing import Optional
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
    """Interactive GUI tab for the Blockchain Audit Ledger & Tamper Detection Suite."""

    def __init__(self, master, current_user: dict, blockchain: Blockchain, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.current_user = current_user
        self.blockchain = blockchain
        self._block_options: dict[str, int] = {}
        self._build_ui()

    def _build_ui(self):
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=16, pady=16)

        # Header Title & Status Bar
        header = ctk.CTkFrame(
            container, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD
        )
        header.pack(fill="x", pady=(0, 10))

        lbl_head = ctk.CTkLabel(
            header,
            text="⛓️ IMMUTABLE BLOCKCHAIN AUDIT LEDGER (SHA-256)",
            font=(FONT_FAMILY, 16, "bold"),
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

        # Control Panel with 2 Rows: Ledger Operations & Interactive Tamper Lab
        ctrl_panel = ctk.CTkFrame(
            container, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD
        )
        ctrl_panel.pack(fill="x", pady=(0, 10), padx=0)

        # --- Row 1: Ledger Management ---
        row1 = ctk.CTkFrame(ctrl_panel, fg_color="transparent")
        row1.pack(fill="x", padx=12, pady=(10, 6))

        btn_verify = ctk.CTkButton(
            row1,
            text="🛡️ Verifikasi Integritas Chain",
            fg_color=COLOR_SUCCESS,
            height=34,
            font=(FONT_FAMILY, 11, "bold"),
            command=self._on_user_click_verify,
        )
        btn_verify.pack(side="left", padx=(0, 8))

        btn_refresh = ctk.CTkButton(
            row1,
            text="🔄 Refresh",
            width=90,
            height=34,
            fg_color=COLOR_PRIMARY,
            command=self._refresh_table,
        )
        btn_refresh.pack(side="left", padx=(0, 8))

        self.lbl_block_count = ctk.CTkLabel(
            row1,
            text=f"Total Blok: {len(self.blockchain.chain)}",
            font=(FONT_FAMILY, 11, "bold"),
            text_color=COLOR_CYAN,
        )
        self.lbl_block_count.pack(side="left", padx=(8, 0))

        btn_restore = ctk.CTkButton(
            row1,
            text="♻️ Kembalikan Data Asli (Undo Tamper)",
            height=34,
            fg_color="#D97706",
            hover_color="#B45309",
            font=(FONT_FAMILY, 11, "bold"),
            command=self._restore_chain,
        )
        btn_restore.pack(side="right", padx=(8, 0))

        btn_repair = ctk.CTkButton(
            row1,
            text="🛠️ Re-Hash Chain (Simulasi Rewrite)",
            height=34,
            fg_color=BG_HOVER,
            command=self._repair_chain,
        )
        btn_repair.pack(side="right", padx=4)

        # --- Row 2: Dynamic Tampering Simulator ---
        row2 = ctk.CTkFrame(ctrl_panel, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=(0, 10))

        lbl_tamper_hint = ctk.CTkLabel(
            row2,
            text="🧪 Simulasi Serangan Tamper:",
            font=(FONT_FAMILY, 11, "bold"),
            text_color=COLOR_WARNING,
        )
        lbl_tamper_hint.pack(side="left", padx=(0, 8))

        self.combo_target_block = ctk.CTkComboBox(
            row2,
            values=["Blok #1"],
            width=280,
            height=32,
            font=(FONT_FAMILY, 11),
            dropdown_font=(FONT_FAMILY, 11),
            fg_color=BG_INPUT,
            border_color=BORDER_CARD,
        )
        self.combo_target_block.pack(side="left", padx=(0, 8))

        btn_tamper_selected = ctk.CTkButton(
            row2,
            text="⚠️ Inject Tamper ke Blok Terpilih",
            height=32,
            fg_color=COLOR_DANGER,
            hover_color="#991B1B",
            font=(FONT_FAMILY, 11, "bold"),
            command=self._simulate_tamper_selected,
        )
        btn_tamper_selected.pack(side="left", padx=(0, 8))

        btn_tamper_random = ctk.CTkButton(
            row2,
            text="🎲 Tamper Blok Acak",
            height=32,
            fg_color="#7C3AED",
            hover_color="#6D28D9",
            font=(FONT_FAMILY, 11),
            command=self._simulate_tamper_random,
        )
        btn_tamper_random.pack(side="left", padx=4)

        # Scrollable Blocks Display Container
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

    def _update_combobox_options(self):
        """Update dropdown list of blocks available for tampering."""
        options = []
        self._block_options.clear()
        for b in self.blockchain.chain:
            event = b.data.get("event", "DATA") if isinstance(b.data, dict) else "DATA"
            label = f"Blok #{b.index}: {event}"
            options.append(label)
            self._block_options[label] = b.index

        if options:
            self.combo_target_block.configure(values=options)
            default_label = options[1] if len(options) > 1 else options[0]
            self.combo_target_block.set(default_label)

    def _refresh_table(self):
        """Render all blocks with cryptographic integrity indicators."""
        for widget in self.blocks_container.winfo_children():
            widget.destroy()

        blocks = self.blockchain.chain
        self.lbl_block_count.configure(text=f"Total Blok: {len(blocks)}")

        if not blocks:
            lbl_empty = ctk.CTkLabel(
                self.blocks_container,
                text="Blockchain masih kosong.",
                font=(FONT_FAMILY, 12),
                text_color=TEXT_MUTED,
            )
            lbl_empty.pack(pady=40)
            return

        self._update_combobox_options()

        # Detailed mathematical verification across every block in the ledger
        _, error_map = self.blockchain.validate_chain_detailed()

        # Render each block card (newest first)
        for b in reversed(blocks):
            has_hash_mismatch = (error_map.get(b.index) == "HASH_MISMATCH")
            has_prev_mismatch = (error_map.get(b.index) == "PREV_HASH_MISMATCH")

            if has_hash_mismatch:
                card_border = COLOR_DANGER
                border_w = 2
            elif has_prev_mismatch:
                card_border = COLOR_WARNING
                border_w = 2
            else:
                card_border = BORDER_CARD
                border_w = 1

            b_card = ctk.CTkFrame(
                self.blocks_container,
                fg_color=BG_CARD,
                corner_radius=8,
                border_width=border_w,
                border_color=card_border,
            )
            b_card.pack(fill="x", padx=10, pady=6)

            # Header row of block card
            row_top = ctk.CTkFrame(b_card, fg_color="transparent")
            row_top.pack(fill="x", padx=12, pady=(8, 4))

            idx_lbl = ctk.CTkLabel(
                row_top,
                text=f"BLOCK #{b.index}",
                font=(FONT_FAMILY, 13, "bold"),
                text_color=COLOR_PRIMARY if b.index > 0 else COLOR_CYAN,
            )
            idx_lbl.pack(side="left")

            # Integrity Badge
            if has_hash_mismatch:
                badge = ctk.CTkLabel(
                    row_top,
                    text="❌ [ CORRUPTED: STORED HASH ≠ COMPUTED HASH ]",
                    font=(FONT_FAMILY, 11, "bold"),
                    text_color=COLOR_DANGER,
                )
                badge.pack(side="left", padx=12)
            elif has_prev_mismatch:
                badge = ctk.CTkLabel(
                    row_top,
                    text="⚠️ [ BROKEN LINK: PREVIOUS HASH MISMATCH ]",
                    font=(FONT_FAMILY, 11, "bold"),
                    text_color=COLOR_WARNING,
                )
                badge.pack(side="left", padx=12)
            else:
                badge = ctk.CTkLabel(
                    row_top,
                    text="✓ [ INTACT & VERIFIED ]",
                    font=(FONT_FAMILY, 10, "bold"),
                    text_color=COLOR_SUCCESS,
                )
                badge.pack(side="left", padx=12)

            # Quick button to tamper this specific block
            btn_tamper_this = ctk.CTkButton(
                row_top,
                text="⚠️ Tamper Blok Ini",
                width=110,
                height=24,
                font=(FONT_FAMILY, 10),
                fg_color=COLOR_DANGER if not has_hash_mismatch else BG_HOVER,
                hover_color="#991B1B",
                command=lambda idx=b.index: self._simulate_tamper(idx),
            )
            btn_tamper_this.pack(side="right", padx=(8, 0))

            time_lbl = ctk.CTkLabel(
                row_top,
                text=f"🕒 {self._format_time(b.timestamp)} UTC",
                font=(FONT_FAMILY, 10),
                text_color=TEXT_MUTED,
            )
            time_lbl.pack(side="right")

            # Data payload formatted
            data_str = json.dumps(b.data, ensure_ascii=False)
            data_lbl = ctk.CTkLabel(
                b_card,
                text=f"Data Event: {data_str}",
                font=(FONT_FAMILY, 11),
                text_color=TEXT_BODY if not has_hash_mismatch else COLOR_DANGER,
                justify="left",
                wraplength=760,
            )
            data_lbl.pack(anchor="w", padx=12, pady=2)

            # Hash Information Box
            hash_box = ctk.CTkFrame(b_card, fg_color=BG_INPUT, corner_radius=6)
            hash_box.pack(fill="x", padx=12, pady=(4, 8))

            prev_lbl = ctk.CTkLabel(
                hash_box,
                text=f"Previous Hash: {b.previous_hash}",
                font=("Consolas", 10),
                text_color=TEXT_MUTED if not has_prev_mismatch else COLOR_WARNING,
                anchor="w",
            )
            prev_lbl.pack(fill="x", padx=8, pady=(4, 1))

            cur_lbl = ctk.CTkLabel(
                hash_box,
                text=f"Stored Hash:   {b.hash}",
                font=("Consolas", 10, "bold"),
                text_color=COLOR_SUCCESS if not has_hash_mismatch else COLOR_DANGER,
                anchor="w",
            )
            cur_lbl.pack(fill="x", padx=8, pady=(1, 1))

            # If tampered, also show the recomputed hash to clearly demonstrate cryptographic breakdown!
            if has_hash_mismatch:
                computed_h = b.compute_hash()
                comp_lbl = ctk.CTkLabel(
                    hash_box,
                    text=f"Computed Hash: {computed_h} (MISMATCH!)",
                    font=("Consolas", 10, "bold"),
                    text_color=COLOR_WARNING,
                    anchor="w",
                )
                comp_lbl.pack(fill="x", padx=8, pady=(1, 4))

    def _verify_chain(self) -> tuple[bool, dict[int, str]]:
        """Run cryptographic verification and update status banner."""
        is_intact, errors = self.blockchain.validate_chain_detailed()
        if is_intact:
            self.lbl_chain_status.configure(
                text=f"✓ BLOCKCHAIN INTACT ({len(self.blockchain.chain)} BLOCKS TAMPER-PROOF)",
                text_color=COLOR_SUCCESS,
            )
        else:
            broken_indices = sorted(errors.keys())
            indices_str = ", ".join(f"#{i}" for i in broken_indices)
            self.lbl_chain_status.configure(
                text=f"❌ INTEGRITY VIOLATION DETECTED: BLOK {indices_str} CORRUPTED!",
                text_color=COLOR_DANGER,
            )
        return is_intact, errors

    def _on_user_click_verify(self):
        """Perform manual mathematical validation and trigger explicit visual notification."""
        self._refresh_table()
        is_intact, errors = self._verify_chain()

        dialog = ctk.CTkToplevel(self)
        dialog.title("Hasil Validasi Integritas Blockchain")
        dialog.geometry("460x220")
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)
        dialog.configure(fg_color=BG_CARD)

        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 460) // 2
        y = self.winfo_y() + (self.winfo_height() - 220) // 2
        dialog.geometry(f"+{x}+{y}")

        if is_intact:
            title_text = "🛡️ SEMUA BLOK TERVERIFIKASI SAH!"
            title_color = COLOR_SUCCESS
            body_text = (
                f"Seluruh {len(self.blockchain.chain)} blok audit telah dihitung ulang secara matematis.\n\n"
                "Semua nilai SHA-256 Digest dan Pointer Hash Rantai (Previous Hash) "
                "cocok 100% dan tidak ada manipulasi data yang terdeteksi."
            )
        else:
            title_text = "🚨 PERINGATAN INTEGRITAS BLOCKCHAIN!"
            title_color = COLOR_DANGER
            indices_str = ", ".join(f"#{i}" for i in sorted(errors.keys()))
            body_text = (
                f"Terdeteksi manipulasi data ilegal pada Blok {indices_str}!\n\n"
                "Stored SHA-256 Hash tidak lagi cocok dengan hasil komputasi data kanonikal.\n"
                "Audit trail telah dirusak atau dimutasi."
            )

        lbl_t = ctk.CTkLabel(dialog, text=title_text, font=(FONT_FAMILY, 14, "bold"), text_color=title_color)
        lbl_t.pack(pady=(20, 8))

        lbl_b = ctk.CTkLabel(dialog, text=body_text, font=(FONT_FAMILY, 11), text_color=TEXT_BODY, justify="center", wraplength=400)
        lbl_b.pack(pady=6, padx=16)

        btn_ok = ctk.CTkButton(dialog, text="Tutup", width=120, height=32, font=(FONT_FAMILY, 11, "bold"), fg_color=COLOR_PRIMARY, command=dialog.destroy)
        btn_ok.pack(pady=(12, 16))

    def _simulate_tamper(self, block_index: int):
        """Mutate block data dynamically in memory without saving to disk."""
        if self.blockchain.tamper_block(block_index):
            self._verify_chain()
            self._refresh_table()
            logger.warning("Tamper simulation successfully executed on Block #%d", block_index)

    def _simulate_tamper_selected(self):
        """Tamper the block currently chosen in the dropdown."""
        selected_text = self.combo_target_block.get()
        target_idx = self._block_options.get(selected_text)
        if target_idx is None:
            target_idx = 1 if len(self.blockchain.chain) > 1 else 0
        self._simulate_tamper(target_idx)

    def _simulate_tamper_random(self):
        """Tamper a random non-genesis block."""
        if len(self.blockchain.chain) > 1:
            idx = random.randint(1, len(self.blockchain.chain) - 1)
        else:
            idx = 0
        self._simulate_tamper(idx)

    def _restore_chain(self):
        """Revert in-memory chain back to pristine untampered state."""
        try:
            self.blockchain.restore_pristine()
            self._verify_chain()
            self._refresh_table()
            logger.info("Blockchain pristine state restored.")
        except Exception as exc:
            logger.error("Restore chain error: %s", exc)

    def _repair_chain(self):
        """
        Re-hash all blocks starting from genesis to forge the chain (simulate 51% consensus rewrite).
        """
        try:
            self.blockchain.repair_chain()
            self._verify_chain()
            self._refresh_table()
            logger.info("Blockchain repaired and re-hashed.")
        except Exception as exc:
            logger.error("Repair chain error: %s", exc)
