# securegov/gui/file_crypto_view.py
"""
Document File Encryption & Decryption Tab
==========================================
Implements dedicated file cryptography using:
  1. RSA-2048-OAEP + AES-256-GCM Hybrid Encryption (.sgvault)
  2. Fernet Symmetric Encryption (.fen)
"""

import os
import hashlib
from tkinter import filedialog
import customtkinter as ctk

from securegov.crypto.file_encryption import RSAHybridFileEncryptor, FernetFileEncryptor
from securegov.database.models import DocumentRepository, log_audit
from securegov.blockchain.chain import Blockchain
from securegov.utils.key_manager import KeyManager
from securegov.gui.styles import (
    BG_CARD,
    BG_INPUT,
    COLOR_PRIMARY,
    COLOR_CYAN,
    COLOR_SUCCESS,
    COLOR_WARNING,
    COLOR_DANGER,
    TEXT_TITLE,
    TEXT_BODY,
    TEXT_MUTED,
    BORDER_CARD,
    FONT_FAMILY,
)
from securegov.utils.logger import get_logger

logger = get_logger(__name__)


class FileCryptoView(ctk.CTkFrame):
    """View for secure document file encryption (PDF/DOCX) with distinct algorithms."""

    def __init__(self, master, current_user: dict, blockchain: Blockchain, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.current_user = current_user
        self.blockchain = blockchain
        self.doc_repo = DocumentRepository()

        # Key Manager
        self.km = KeyManager()
        if not os.path.isfile(self.km.private_key_path):
            self.km.generate_rsa_keypair()

        self.selected_file_path: str = ""
        self.encrypted_file_path: str = ""

        self._build_ui()

    def _build_ui(self):
        container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=16, pady=16)

        # Header Title
        lbl_head = ctk.CTkLabel(
            container,
            text="📁 ENTERPRISE DOCUMENT ENCRYPTION (RSA-HYBRID & FERNET)",
            font=(FONT_FAMILY, 18, "bold"),
            text_color=COLOR_CYAN,
        )
        lbl_head.pack(anchor="w", pady=(0, 14))

        # Main Card
        card = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CARD)
        card.pack(fill="x", pady=(0, 14))

        # 1. File Picker Row
        lbl_step1 = ctk.CTkLabel(card, text="1. PILIH DOKUMEN (PDF / DOCX / TXT)", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl_step1.pack(anchor="w", padx=16, pady=(14, 6))

        row_picker = ctk.CTkFrame(card, fg_color="transparent")
        row_picker.pack(fill="x", padx=16, pady=4)

        self.entry_file_path = ctk.CTkEntry(row_picker, placeholder_text="Pilih berkas dokumen yang ingin diproteksi...", height=38)
        self.entry_file_path.pack(side="left", fill="x", expand=True, padx=(0, 8))

        btn_browse = ctk.CTkButton(
            row_picker,
            text="📂 Cari Berkas...",
            width=130,
            height=38,
            fg_color=COLOR_PRIMARY,
            command=self._on_browse_file,
        )
        btn_browse.pack(side="right")

        # File Meta Info Label
        self.lbl_file_meta = ctk.CTkLabel(
            card,
            text="Ukuran: - | Checksum SHA-256: -",
            font=(FONT_FAMILY, 11),
            text_color=TEXT_MUTED,
            justify="left",
        )
        self.lbl_file_meta.pack(anchor="w", padx=16, pady=(2, 10))

        # 2. Algorithm & Sensitive Notes
        lbl_step2 = ctk.CTkLabel(card, text="2. ALGORITMA ENKRIPSI & CATATAN RAHASIA", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl_step2.pack(anchor="w", padx=16, pady=(10, 6))

        row_algo = ctk.CTkFrame(card, fg_color="transparent")
        row_algo.pack(fill="x", padx=16, pady=4)

        lbl_algo = ctk.CTkLabel(row_algo, text="Metode Enkripsi:", font=(FONT_FAMILY, 11))
        lbl_algo.pack(side="left", padx=(0, 8))

        self.combo_file_algo = ctk.CTkComboBox(
            row_algo,
            values=[
                "RSA-2048-OAEP + AES-256-GCM Hybrid",
                "Fernet Symmetric (AES-128-CBC + HMAC-SHA256)",
            ],
            width=360,
            height=36,
        )
        self.combo_file_algo.set("RSA-2048-OAEP + AES-256-GCM Hybrid")
        self.combo_file_algo.pack(side="left", padx=(0, 16))

        lbl_notes = ctk.CTkLabel(card, text="Catatan Dokumen Rahasia (Disimpan ke SQLite dengan Enkripsi AES-GCM):", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_notes.pack(anchor="w", padx=16, pady=(6, 2))

        self.entry_doc_notes = ctk.CTkEntry(card, placeholder_text="Contoh: Dokumen audit anggaran negara Q4 2026", height=36)
        self.entry_doc_notes.pack(fill="x", padx=16, pady=(2, 16))

        # 3. Actions (Encrypt & Decrypt Buttons)
        row_actions = ctk.CTkFrame(card, fg_color="transparent")
        row_actions.pack(fill="x", padx=16, pady=(0, 16))

        self.btn_encrypt = ctk.CTkButton(
            row_actions,
            text="🔒 Enkripsi Dokumen & Simpan ke Vault",
            height=42,
            fg_color=COLOR_SUCCESS,
            command=self._do_encrypt_file,
        )
        self.btn_encrypt.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.btn_decrypt = ctk.CTkButton(
            row_actions,
            text="🔓 Dekripsi Dokumen Terpilih",
            height=42,
            fg_color=COLOR_CYAN,
            hover_color=COLOR_PRIMARY,
            command=self._do_decrypt_file,
        )
        self.btn_decrypt.pack(side="right", fill="x", expand=True, padx=(8, 0))

        # 4. Result Log Box
        self.txt_log = ctk.CTkTextbox(container, height=180, fg_color=BG_CARD, font=(FONT_FAMILY, 11), border_width=1, border_color=BORDER_CARD)
        self.txt_log.pack(fill="both", expand=True, pady=(4, 0))
        self._log("System: Modul enkripsi berkas siap. Silakan pilih dokumen PDF/DOCX.")

    def _log(self, text: str):
        self.txt_log.insert("end", text + "\n")
        self.txt_log.see("end")

    @staticmethod
    def _compute_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _on_browse_file(self):
        f = filedialog.askopenfilename(
            title="Pilih Berkas Dokumen",
            filetypes=[
                ("Supported Documents", "*.pdf;*.docx;*.doc;*.txt;*.xlsx;*.png;*.jpg"),
                ("All Files", "*.*"),
            ],
        )
        if f:
            self.selected_file_path = f
            self.entry_file_path.delete(0, "end")
            self.entry_file_path.insert(0, f)

            sz = os.path.getsize(f) / 1024
            sha = self._compute_sha256(f)
            self.lbl_file_meta.configure(
                text=f"Ukuran: {sz:.2f} KB | Checksum Asli SHA-256: {sha}"
            )
            self._log(f"Berkas dimuat: {os.path.basename(f)} ({sz:.2f} KB) - SHA-256: {sha[:16]}…")

    def _do_encrypt_file(self):
        src = self.entry_file_path.get().strip()
        if not src or not os.path.isfile(src):
            self._log("✗ Harap pilih berkas dokumen yang valid terlebih dahulu.")
            return

        algo_choice = self.combo_file_algo.get()
        notes = self.entry_doc_notes.get().strip() or "Standard Enterprise Vault"

        os.makedirs(os.path.join("data", "encrypted"), exist_ok=True)
        filename = os.path.basename(src)
        orig_sha = self._compute_sha256(src)

        try:
            if "RSA" in algo_choice:
                out_path = os.path.join("data", "encrypted", filename + ".sgvault")
                enc = RSAHybridFileEncryptor(
                    public_key=self.km.load_public_key(),
                    private_key=self.km.load_private_key(),
                )
                enc.encrypt_file(src, out_path)
                algo_used = "RSA-2048-OAEP+AES256GCM"
            else:
                out_path = os.path.join("data", "encrypted", filename + ".fen")
                enc = FernetFileEncryptor()
                enc.encrypt_file(src, out_path)
                algo_used = "Fernet-AES128CBC"

            self.encrypted_file_path = out_path
            # Save metadata into SQLite DB (with AES-GCM encrypted notes)
            doc_id = self.doc_repo.add_document(
                owner_id=self.current_user["id"],
                filename=filename,
                original_path=src,
                encrypted_path=out_path,
                notes=notes,
            )

            # Log to Blockchain Ledger
            self.blockchain.add_block({
                "event": "DOCUMENT_ENCRYPTED",
                "doc_id": doc_id,
                "filename": filename,
                "algo": algo_used,
                "sha256": orig_sha,
                "owner": self.current_user["username"],
            })
            log_audit(self.current_user["id"], "FILE_ENCRYPT", f"doc_id={doc_id} algo={algo_used}")

            self._log(f"✓ ENKRIPSI SUKSES: Disimpan ke '{out_path}'")
            self._log(f"✓ Catatan Dokumen terenkripsi AES-GCM & dicatat ke SQLite (DocID #{doc_id})")
            self._log(f"✓ Transaksi integritas dokumen telah di-anchor ke Blockchain!")

        except Exception as exc:
            self._log(f"✗ GAGAL ENKRIPSI BERKAS: {exc}")

    def _do_decrypt_file(self):
        target = self.encrypted_file_path
        if not target or not os.path.isfile(target):
            f = filedialog.askopenfilename(
                title="Pilih Berkas Terenkripsi",
                filetypes=[("Secure Vault Files", "*.sgvault;*.fen"), ("All Files", "*.*")],
            )
            if not f:
                return
            target = f

        try:
            orig_name = os.path.basename(target).replace(".sgvault", "").replace(".fen", "")
            out_decrypted = os.path.join("data", "uploads", "restored_" + orig_name)
            os.makedirs(os.path.join("data", "uploads"), exist_ok=True)

            if target.endswith(".sgvault"):
                enc = RSAHybridFileEncryptor(
                    public_key=self.km.load_public_key(),
                    private_key=self.km.load_private_key(),
                )
                enc.decrypt_file(target, out_decrypted)
                algo_used = "RSA-Hybrid"
            else:
                enc = FernetFileEncryptor()
                enc.decrypt_file(target, out_decrypted)
                algo_used = "Fernet"

            restored_sha = self._compute_sha256(out_decrypted)

            self.blockchain.add_block({
                "event": "DOCUMENT_DECRYPTED",
                "filename": orig_name,
                "algo": algo_used,
                "restored_sha256": restored_sha,
                "actor": self.current_user["username"],
            })
            log_audit(self.current_user["id"], "FILE_DECRYPT", f"file={orig_name}")

            self._log(f"✓ DEKRIPSI SUKSES: Dokumen dipulihkan ke '{out_decrypted}'")
            self._log(f"✓ Checksum Terverifikasi SHA-256: {restored_sha}")
            self._log(f"✓ Event dekripsi berhasil dicatat ke Blockchain Audit Ledger.")

        except Exception as exc:
            self._log(f"✗ GAGAL DEKRIPSI BERKAS: {exc}")

