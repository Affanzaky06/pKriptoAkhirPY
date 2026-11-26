"""
Image Steganography — Optimized LSB via Pillow + NumPy
======================================================
Hides and extracts UTF-8 text inside RGB pixel LSBs.

Features:
- LSB steganography on RGB channels.
- 32-bit little-endian message length header.
- NumPy vectorization for faster processing.
- PNG lossless output to preserve hidden data.
- Maximum PNG compression.
"""

import os
import struct
import numpy as np

from PIL import Image

from securegov.utils.logger import get_logger

logger = get_logger(__name__)


class ImageSteganography:
    """Optimized LSB image steganography."""

    _HEADER_SIZE = 32

    # --------------------------------------------------
    # HELPER FUNCTIONS
    # --------------------------------------------------

    @staticmethod
    def _text_to_bits(text: str) -> np.ndarray:
        """Convert UTF-8 text into bits (MSB first)."""

        data = text.encode("utf-8")

        return np.unpackbits(
            np.frombuffer(data, dtype=np.uint8)
        )

    @staticmethod
    def _bits_to_text(bits: np.ndarray) -> str:
        """Convert bits back into UTF-8 text."""

        if len(bits) % 8 != 0:
            raise ValueError("Jumlah bit pesan tidak valid.")

        data = np.packbits(bits).tobytes()

        return data.decode("utf-8", errors="strict")

    @staticmethod
    def _length_to_bits(length: int) -> np.ndarray:
        """Encode message bit length into a 32-bit header."""

        header = struct.pack("<I", length)

        return np.unpackbits(
            np.frombuffer(header, dtype=np.uint8)
        )

    @staticmethod
    def _bits_to_length(bits: np.ndarray) -> int:
        """Decode the 32-bit header."""

        header = np.packbits(bits[:32]).tobytes()

        return struct.unpack("<I", header)[0]

    # --------------------------------------------------
    # EMBED MESSAGE
    # --------------------------------------------------

    def embed(
        self,
        cover_path: str,
        message: str,
        output_path: str
    ) -> str:

        if not os.path.isfile(cover_path):
            raise FileNotFoundError(
                f"Gambar tidak ditemukan: {cover_path}"
            )

        if os.path.abspath(cover_path) == os.path.abspath(output_path):
            raise ValueError(
                "Output tidak boleh menimpa gambar asli."
            )

        # Output harus PNG agar LSB tidak rusak
        if not output_path.lower().endswith(".png"):
            output_path = (
                os.path.splitext(output_path)[0] + ".png"
            )

        output_dir = os.path.dirname(
            os.path.abspath(output_path)
        )

        os.makedirs(output_dir, exist_ok=True)

        if not message:
            raise ValueError(
                "Pesan rahasia tidak boleh kosong."
            )

        # ----------------------------------------------
        # 1. BUKA GAMBAR
        # ----------------------------------------------

        with Image.open(cover_path) as img:
            image = img.convert("RGB")

        width, height = image.size

        # Ubah gambar menjadi array NumPy
        pixels = np.array(image, dtype=np.uint8)

        # Flatten RGB menjadi satu dimensi
        flat_pixels = pixels.reshape(-1)

        # ----------------------------------------------
        # 2. KONVERSI PESAN KE BIT
        # ----------------------------------------------

        message_bits = self._text_to_bits(message)

        length_bits = self._length_to_bits(
            len(message_bits)
        )

        full_bits = np.concatenate(
            (length_bits, message_bits)
        )

        # ----------------------------------------------
        # 3. CEK KAPASITAS GAMBAR
        # ----------------------------------------------

        capacity = width * height * 3

        if len(full_bits) > capacity:
            max_bytes = max(
                0, (capacity - self._HEADER_SIZE) // 8
            )

            raise ValueError(
                f"Pesan terlalu besar. "
                f"Kapasitas maksimum sekitar {max_bytes} byte."
            )

        # ----------------------------------------------
        # 4. PROSES LSB MENGGUNAKAN NUMPY
        # ----------------------------------------------

        count = len(full_bits)

        flat_pixels[:count] = (
            (flat_pixels[:count] & 0xFE)
            | full_bits
        )

        # Kembalikan ke bentuk gambar
        stego_pixels = flat_pixels.reshape(
            height, width, 3
        )

        stego_image = Image.fromarray(
            stego_pixels, mode="RGB"
        )

        # ----------------------------------------------
        # 5. SIMPAN PNG LOSSLESS
        # ----------------------------------------------

        stego_image.save(
            output_path,
            format="PNG",
            optimize=True,
            compress_level=9
        )

        logger.info(
            "Image steg: embedded %d characters into '%s' -> '%s'.",
            len(message),
            cover_path,
            output_path
        )

        return output_path

    # --------------------------------------------------
    # EXTRACT MESSAGE
    # --------------------------------------------------

    def extract(self, stego_path: str) -> str:

        if not os.path.isfile(stego_path):
            raise FileNotFoundError(
                f"Gambar tidak ditemukan: {stego_path}"
            )

        # ----------------------------------------------
        # 1. BUKA GAMBAR
        # ----------------------------------------------

        with Image.open(stego_path) as img:
            image = img.convert("RGB")

        pixels = np.array(image, dtype=np.uint8)

        flat_pixels = pixels.reshape(-1)

        # ----------------------------------------------
        # 2. CEK KAPASITAS MINIMUM
        # ----------------------------------------------

        if len(flat_pixels) < self._HEADER_SIZE:
            raise ValueError(
                "Gambar terlalu kecil untuk menyimpan pesan."
            )

        # ----------------------------------------------
        # 3. BACA HEADER
        # ----------------------------------------------

        header_bits = flat_pixels[:32] & 1

        message_length = self._bits_to_length(
            header_bits
        )

        if (
            message_length == 0
            or message_length % 8 != 0
            or message_length > len(flat_pixels) - 32
        ):
            raise ValueError(
                "Tidak ditemukan pesan valid. "
                "Header rusak atau gambar bukan gambar stego."
            )

        # ----------------------------------------------
        # 4. EKSTRAKSI PESAN
        # ----------------------------------------------

        message_bits = (
            flat_pixels[32:32 + message_length] & 1
        )

        try:
            message = self._bits_to_text(
                message_bits
            )

        except UnicodeDecodeError as e:
            raise ValueError(
                "Pesan gagal dibaca. "
                "Data LSB mungkin telah berubah atau rusak."
            ) from e

        logger.info(
            "Image steg: extracted message (%d bytes) from '%s'.",
            message_length // 8,
            stego_path
        )

        return message