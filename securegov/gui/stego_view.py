# securegov/gui/stego_view.py
"""
Multimedia Steganography Suite View
====================================
Sub-tabs for Image (Pillow), Audio (WAV PCM), and Video (OpenCV FFV1) LSB Steganography.
"""

import os
from tkinter import filedialog
import customtkinter as ctk

from securegov.steganography.image_steg import ImageSteganography
from securegov.steganography.audio_steg import AudioSteganography
from securegov.steganography.video_steg import VideoSteganography
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


class StegoView(ctk.CTkFrame):
    """Multimedia Steganography Suite tab with Image, Audio, and Video sub-tabs."""

    def __init__(self, master, current_user: dict, blockchain: Blockchain, on_action_check=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.current_user = current_user
        self.blockchain = blockchain
        self.on_action_check = on_action_check

        self.img_steg = ImageSteganography()
        self.audio_steg = AudioSteganography()
        self.video_steg = VideoSteganography()

        self._build_ui()

    def _build_ui(self):
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=16, pady=16)

        # Header Title
        lbl_head = ctk.CTkLabel(
            container,
            text="🖼️ MULTIMEDIA STEGANOGRAPHY SUITE (IMAGE, AUDIO & VIDEO)",
            font=(FONT_FAMILY, 18, "bold"),
            text_color=COLOR_CYAN,
        )
        lbl_head.pack(anchor="w", pady=(0, 10))

        # Sub-tabview
        self.tabs = ctk.CTkTabview(
            container,
            fg_color=BG_CARD,
            segmented_button_fg_color=BG_INPUT,
            segmented_button_selected_color=COLOR_PRIMARY,
        )
        self.tabs.pack(fill="both", expand=True)

        self.tab_img = self.tabs.add("📷 Image Steganography (PNG/JPG)")
        self.tab_aud = self.tabs.add("🎙️ Audio Steganography (WAV PCM)")
        self.tab_vid = self.tabs.add("🎥 Video Steganography (AVI/MP4/MKV)")

        self._build_image_tab()
        self._build_audio_tab()
        self._build_video_tab()

    # =======================================================================
    # 1. IMAGE STEGANOGRAPHY SUB-TAB
    # =======================================================================

    def _build_image_tab(self):
        f = ctk.CTkScrollableFrame(self.tab_img, fg_color="transparent")
        f.pack(fill="both", expand=True, padx=12, pady=12)

        lbl = ctk.CTkLabel(f, text="PENYISIPAN & EKSTRAKSI PESAN PADA CITRA (LSB PILLOW)", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl.pack(anchor="w", pady=(0, 8))

        # Cover picker
        row_cover = ctk.CTkFrame(f, fg_color="transparent")
        row_cover.pack(fill="x", pady=4)
        self.entry_img_cover = ctk.CTkEntry(row_cover, placeholder_text="Pilih citra sampul (PNG atau JPG)...", height=36)
        self.entry_img_cover.pack(side="left", fill="x", expand=True, padx=(0, 8))
        btn_br_img = ctk.CTkButton(row_cover, text="📂 Pilih Citra", width=120, height=36, command=lambda: self._browse_file(self.entry_img_cover, [("Images", "*.png;*.jpg;*.jpeg")]))
        btn_br_img.pack(side="right")

        lbl_sec = ctk.CTkLabel(f, text="Pesan Rahasia yang Ingin Disisipkan:", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_sec.pack(anchor="w", pady=(8, 2))

        self.txt_img_secret = ctk.CTkTextbox(f, height=80, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_img_secret.pack(fill="x", pady=4)
        self.txt_img_secret.insert("1.0", "Top secret: Operasi CyberGuard Garuda 2026.")

        row_act = ctk.CTkFrame(f, fg_color="transparent")
        row_act.pack(fill="x", pady=8)

        btn_embed = ctk.CTkButton(row_act, text="📥 Sisipkan Pesan ke Gambar (Embed LSB)", height=38, fg_color=COLOR_SUCCESS, command=self._do_embed_image)
        btn_embed.pack(side="left", fill="x", expand=True, padx=(0, 6))

        btn_extract = ctk.CTkButton(row_act, text="📤 Ekstrak Pesan dari Gambar (Extract LSB)", height=38, fg_color=COLOR_CYAN, hover_color=COLOR_PRIMARY, command=self._do_extract_image)
        btn_extract.pack(side="right", fill="x", expand=True, padx=(6, 0))

        lbl_res = ctk.CTkLabel(f, text="Hasil Ekstraksi Pesan:", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_res.pack(anchor="w", pady=(8, 2))

        self.txt_img_result = ctk.CTkTextbox(f, height=80, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_img_result.pack(fill="x", pady=4)

    def _do_embed_image(self):
        if self.on_action_check and not self.on_action_check():
            return
        src = self.entry_img_cover.get().strip()
        msg = self.txt_img_secret.get("1.0", "end").strip()
        if not src or not os.path.isfile(src) or not msg:
            self.txt_img_result.delete("1.0", "end")
            self.txt_img_result.insert("1.0", "Pilih citra sampul dan masukkan pesan rahasia.")
            return

        out_path = os.path.splitext(src)[0] + "_stego.png"
        try:
            self.img_steg.embed(src, msg, out_path)
            self.entry_img_cover.delete(0, "end")
            self.entry_img_cover.insert(0, out_path)
            self.txt_img_result.delete("1.0", "end")
            self.txt_img_result.insert("1.0", f"✓ SUKSES EMBED: Disimpan ke '{out_path}'\n(Target input otomatis diarahkan ke berkas stego di atas — Anda dapat langsung klik 'Ekstrak')")
            self.blockchain.add_block({
                "event": "IMAGE_STEGO_EMBED",
                "cover": os.path.basename(src),
                "msg_len": len(msg),
                "user": self.current_user["username"],
            })
        except Exception as exc:
            self.txt_img_result.delete("1.0", "end")
            self.txt_img_result.insert("1.0", f"Error Embed Citra: {exc}")

    def _do_extract_image(self):
        if self.on_action_check and not self.on_action_check():
            return
        src = self.entry_img_cover.get().strip()
        if not src or not os.path.isfile(src):
            src = filedialog.askopenfilename(title="Pilih Citra Stego", filetypes=[("PNG Images", "*.png")])
            if not src:
                return

        try:
            msg = self.img_steg.extract(src)
            self.txt_img_result.delete("1.0", "end")
            self.txt_img_result.insert("1.0", f"✓ PESAN BERHASIL DIEKSTRAK DARI {os.path.basename(src)}:\n\n{msg}")
            self.blockchain.add_block({
                "event": "IMAGE_STEGO_EXTRACT",
                "stego_file": os.path.basename(src),
                "user": self.current_user["username"],
            })
        except Exception as exc:
            self.txt_img_result.delete("1.0", "end")
            self.txt_img_result.insert("1.0", f"✗ GAGAL EKSTRAK CITRA: {exc}")

    # =======================================================================
    # 2. AUDIO STEGANOGRAPHY SUB-TAB
    # =======================================================================

    def _build_audio_tab(self):
        f = ctk.CTkScrollableFrame(self.tab_aud, fg_color="transparent")
        f.pack(fill="both", expand=True, padx=12, pady=12)

        lbl = ctk.CTkLabel(f, text="PENYISIPAN & EKSTRAKSI DATA PADA AUDIO (PCM WAV LSB)", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl.pack(anchor="w", pady=(0, 2))

        lbl_note = ctk.CTkLabel(
            f,
            text="ℹ️ Catatan: Hanya format WAV PCM (uncompressed) yang didukung untuk teknik LSB audio. File MP3/FLAC harus dikonversi ke WAV terlebih dahulu.",
            font=(FONT_FAMILY, 10),
            text_color=TEXT_MUTED,
            wraplength=680,
            justify="left",
        )
        lbl_note.pack(anchor="w", pady=(0, 8))

        row_cover = ctk.CTkFrame(f, fg_color="transparent")
        row_cover.pack(fill="x", pady=4)
        self.entry_aud_cover = ctk.CTkEntry(row_cover, placeholder_text="Pilih berkas audio (format .wav uncompressed PCM)...", height=36)
        self.entry_aud_cover.pack(side="left", fill="x", expand=True, padx=(0, 8))
        btn_br_aud = ctk.CTkButton(
            row_cover, text="📂 Pilih Audio", width=120, height=36,
            command=lambda: self._browse_file(
                self.entry_aud_cover,
                [("WAV Audio (PCM Lossless)", "*.wav"), ("Semua File Audio", "*.wav;*.wave"), ("All Files", "*.*")],
            )
        )
        btn_br_aud.pack(side="right")

        lbl_sec = ctk.CTkLabel(f, text="Payload Rahasia yang Ingin Disisipkan ke Sampel Audio:", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_sec.pack(anchor="w", pady=(8, 2))

        self.txt_aud_secret = ctk.CTkTextbox(f, height=80, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_aud_secret.pack(fill="x", pady=4)
        self.txt_aud_secret.insert("1.0", "Secret Key: SG-ALPHA-992-DELTA.")

        row_act = ctk.CTkFrame(f, fg_color="transparent")
        row_act.pack(fill="x", pady=8)

        btn_embed = ctk.CTkButton(row_act, text="📥 Sisipkan ke Audio (Embed PCM LSB)", height=38, fg_color=COLOR_SUCCESS, command=self._do_embed_audio)
        btn_embed.pack(side="left", fill="x", expand=True, padx=(0, 6))

        btn_extract = ctk.CTkButton(row_act, text="📤 Ekstrak dari Audio (Extract PCM LSB)", height=38, fg_color=COLOR_CYAN, hover_color=COLOR_PRIMARY, command=self._do_extract_audio)
        btn_extract.pack(side="right", fill="x", expand=True, padx=(6, 0))

        lbl_res = ctk.CTkLabel(f, text="Hasil Ekstraksi Payload Audio:", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_res.pack(anchor="w", pady=(8, 2))

        self.txt_aud_result = ctk.CTkTextbox(f, height=80, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_aud_result.pack(fill="x", pady=4)

    def _do_embed_audio(self):
        if self.on_action_check and not self.on_action_check():
            return
        src = self.entry_aud_cover.get().strip()
        msg = self.txt_aud_secret.get("1.0", "end").strip()
        if not src or not os.path.isfile(src) or not msg:
            self.txt_aud_result.delete("1.0", "end")
            self.txt_aud_result.insert("1.0", "Pilih berkas cover WAV dan masukkan pesan.")
            return

        out_path = os.path.splitext(src)[0] + "_stego.wav"
        try:
            self.audio_steg.embed(src, msg, out_path)
            self.entry_aud_cover.delete(0, "end")
            self.entry_aud_cover.insert(0, out_path)
            self.txt_aud_result.delete("1.0", "end")
            self.txt_aud_result.insert("1.0", f"✓ SUKSES EMBED AUDIO: Disimpan ke '{out_path}'\n(Target input otomatis diarahkan ke berkas stego di atas — Anda dapat langsung klik 'Ekstrak')")
            self.blockchain.add_block({
                "event": "AUDIO_STEGO_EMBED",
                "cover": os.path.basename(src),
                "user": self.current_user["username"],
            })
        except Exception as exc:
            self.txt_aud_result.delete("1.0", "end")
            self.txt_aud_result.insert("1.0", f"Error Embed Audio: {exc}")

    def _do_extract_audio(self):
        if self.on_action_check and not self.on_action_check():
            return
        src = self.entry_aud_cover.get().strip()
        if not src or not os.path.isfile(src):
            src = filedialog.askopenfilename(
                title="Pilih Berkas WAV Stego",
                filetypes=[("WAV Audio (PCM)", "*.wav"), ("All Files", "*.*")],
            )
            if not src:
                return

        try:
            msg = self.audio_steg.extract(src)
            self.txt_aud_result.delete("1.0", "end")
            self.txt_aud_result.insert("1.0", f"✓ PAYLOAD BERHASIL DIEKSTRAK DARI AUDIO:\n\n{msg}")
            self.blockchain.add_block({
                "event": "AUDIO_STEGO_EXTRACT",
                "audio_file": os.path.basename(src),
                "user": self.current_user["username"],
            })
        except Exception as exc:
            self.txt_aud_result.delete("1.0", "end")
            self.txt_aud_result.insert("1.0", f"✗ GAGAL EKSTRAK AUDIO: {exc}")

    # =======================================================================
    # 3. VIDEO STEGANOGRAPHY SUB-TAB
    # =======================================================================

    def _build_video_tab(self):
        f = ctk.CTkScrollableFrame(self.tab_vid, fg_color="transparent")
        f.pack(fill="both", expand=True, padx=12, pady=12)

        lbl = ctk.CTkLabel(f, text="PENYISIPAN & EKSTRAKSI PESAN PADA FRAME VIDEO (OPENCV LSB — LOSSLESS AVI OUTPUT)", font=(FONT_FAMILY, 13, "bold"), text_color=COLOR_PRIMARY)
        lbl.pack(anchor="w", pady=(0, 2))

        lbl_note = ctk.CTkLabel(
            f,
            text="ℹ️ Catatan teknis: Input video dapat berupa AVI, MP4, MKV, dsb. Output selalu disimpan sebagai .AVI dengan codec FFV1 (lossless) untuk menjaga integritas bit LSB yang disisipkan.",
            font=(FONT_FAMILY, 10),
            text_color=TEXT_MUTED,
            wraplength=680,
            justify="left",
        )
        lbl_note.pack(anchor="w", pady=(0, 8))

        row_cover = ctk.CTkFrame(f, fg_color="transparent")
        row_cover.pack(fill="x", pady=4)
        self.entry_vid_cover = ctk.CTkEntry(row_cover, placeholder_text="Pilih berkas video (AVI, MP4, MKV, dsb.)...", height=36)
        self.entry_vid_cover.pack(side="left", fill="x", expand=True, padx=(0, 8))
        btn_br_vid = ctk.CTkButton(
            row_cover, text="📂 Pilih Video", width=120, height=36,
            command=lambda: self._browse_file(
                self.entry_vid_cover,
                [
                    ("Semua Format Video", "*.avi;*.mp4;*.mkv;*.mov;*.wmv;*.flv;*.webm"),
                    ("AVI Video (Recommended)", "*.avi"),
                    ("MP4 Video", "*.mp4"),
                    ("MKV Video", "*.mkv"),
                    ("All Files", "*.*"),
                ],
            )
        )
        btn_br_vid.pack(side="right")

        lbl_sec = ctk.CTkLabel(f, text="Pesan Rahasia yang Ingin Disisipkan ke Frame Video:", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_sec.pack(anchor="w", pady=(8, 2))

        self.txt_vid_secret = ctk.CTkTextbox(f, height=80, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_vid_secret.pack(fill="x", pady=4)
        self.txt_vid_secret.insert("1.0", "CONFIDENTIAL: Video surveillance mission log 2026.")

        row_act = ctk.CTkFrame(f, fg_color="transparent")
        row_act.pack(fill="x", pady=8)

        btn_embed = ctk.CTkButton(row_act, text="📥 Sisipkan ke Frame Video (Embed Video LSB)", height=38, fg_color=COLOR_SUCCESS, command=self._do_embed_video)
        btn_embed.pack(side="left", fill="x", expand=True, padx=(0, 6))

        btn_extract = ctk.CTkButton(row_act, text="📤 Ekstrak dari Video (Extract Video LSB)", height=38, fg_color=COLOR_CYAN, hover_color=COLOR_PRIMARY, command=self._do_extract_video)
        btn_extract.pack(side="right", fill="x", expand=True, padx=(6, 0))

        lbl_res = ctk.CTkLabel(f, text="Hasil Ekstraksi Pesan Video:", font=(FONT_FAMILY, 11), text_color=TEXT_MUTED)
        lbl_res.pack(anchor="w", pady=(8, 2))

        self.txt_vid_result = ctk.CTkTextbox(f, height=80, fg_color=BG_INPUT, font=(FONT_FAMILY, 11))
        self.txt_vid_result.pack(fill="x", pady=4)

    def _do_embed_video(self):
        if self.on_action_check and not self.on_action_check():
            return
        src = self.entry_vid_cover.get().strip()
        msg = self.txt_vid_secret.get("1.0", "end").strip()
        if not src or not os.path.isfile(src) or not msg:
            self.txt_vid_result.delete("1.0", "end")
            self.txt_vid_result.insert("1.0", "Pilih berkas video cover dan masukkan pesan.")
            return

        # Output always saved as lossless AVI (FFV1 codec) regardless of input format
        base_name = os.path.splitext(os.path.basename(src))[0]
        out_dir = os.path.dirname(src)
        out_path = os.path.join(out_dir, base_name + "_stego.avi")
        try:
            self.video_steg.embed(src, msg, out_path)
            self.entry_vid_cover.delete(0, "end")
            self.entry_vid_cover.insert(0, out_path)
            self.txt_vid_result.delete("1.0", "end")
            self.txt_vid_result.insert("1.0", f"✓ SUKSES EMBED VIDEO: Disimpan ke '{out_path}'\n(Target input otomatis diarahkan ke berkas stego di atas — Anda dapat langsung klik 'Ekstrak')")
            self.blockchain.add_block({
                "event": "VIDEO_STEGO_EMBED",
                "cover": os.path.basename(src),
                "output": os.path.basename(out_path),
                "user": self.current_user["username"],
            })
        except Exception as exc:
            self.txt_vid_result.delete("1.0", "end")
            self.txt_vid_result.insert("1.0", f"Error Embed Video: {exc}")

    def _do_extract_video(self):
        if self.on_action_check and not self.on_action_check():
            return
        src = self.entry_vid_cover.get().strip()
        if not src or not os.path.isfile(src):
            src = filedialog.askopenfilename(
                title="Pilih Berkas Video Stego",
                filetypes=[
                    ("Semua Format Video", "*.avi;*.mp4;*.mkv;*.mov;*.wmv"),
                    ("AVI Video (FFV1 Lossless)", "*.avi"),
                    ("All Files", "*.*"),
                ],
            )
            if not src:
                return

        try:
            msg = self.video_steg.extract(src)
            self.txt_vid_result.delete("1.0", "end")
            self.txt_vid_result.insert("1.0", f"✓ PESAN BERHASIL DIEKSTRAK DARI VIDEO:\n\n{msg}")
            self.blockchain.add_block({
                "event": "VIDEO_STEGO_EXTRACT",
                "video_file": os.path.basename(src),
                "user": self.current_user["username"],
            })
        except Exception as exc:
            self.txt_vid_result.delete("1.0", "end")
            self.txt_vid_result.insert("1.0", f"✗ GAGAL EKSTRAK VIDEO: {exc}")

    def _browse_file(self, entry_widget, filetypes):
        f = filedialog.askopenfilename(filetypes=filetypes)
        if f:
            entry_widget.delete(0, "end")
            entry_widget.insert(0, f)

