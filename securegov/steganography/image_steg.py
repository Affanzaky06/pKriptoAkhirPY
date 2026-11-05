# securegov/steganography/image_steg.py
"""
Image Steganography — LSB (Least Significant Bit) via Pillow
=============================================================
Hides and extracts arbitrary UTF-8 text inside the least-significant bits
of the RGB pixel channels of a PNG or JPEG image.

Algorithm
---------
  * Each character of the secret message is encoded as 8 bits.
  * A 32-bit little-endian length prefix is prepended to the bit stream so
    the extractor knows when to stop reading.
  * Bits are spread across the LSBs of R, G, B channels sequentially
    (3 bits per pixel; the alpha channel is not modified).
  * The output image is always saved as PNG to avoid JPEG re-compression
    artefacts destroying the hidden data.

Capacity
--------
  max_chars ≈ (width × height × 3) // 8  −  4   (minus length field)

Usage
-----
    from securegov.steganography.image_steg import ImageSteganography

    steg = ImageSteganography()
    steg.embed("cover.png", "Top secret meeting at noon.", "stego.png")
    msg  = steg.extract("stego.png")
    assert msg == "Top secret meeting at noon."
"""

import struct
from typing import Optional

from securegov.utils.logger import get_logger

logger = get_logger(__name__)

try:
    from PIL import Image
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False
    logger.warning("Pillow not installed — ImageSteganography will not work. "
                   "Run: pip install Pillow")


class ImageSteganography:
    """LSB image steganography using Pillow."""

    _DELIMITER_BITS = 32   # 4-byte (uint32-LE) length prefix

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _text_to_bits(text: str) -> list[int]:
        """Convert UTF-8 text to a flat list of bits (MSB first per byte)."""
        bits: list[int] = []
        for byte in text.encode("utf-8"):
            for shift in range(7, -1, -1):
                bits.append((byte >> shift) & 1)
        return bits

    @staticmethod
    def _bits_to_text(bits: list[int]) -> str:
        """Reconstruct UTF-8 text from a flat list of bits."""
        chars: list[int] = []
        for i in range(0, len(bits), 8):
            byte = 0
            for bit in bits[i:i + 8]:
                byte = (byte << 1) | bit
            chars.append(byte)
        return bytes(chars).decode("utf-8", errors="replace")

    @staticmethod
    def _int_to_bits_32(n: int) -> list[int]:
        """Encode *n* as 32 bits (little-endian byte order, MSB-first within byte)."""
        packed = struct.pack("<I", n)
        bits: list[int] = []
        for byte in packed:
            for shift in range(7, -1, -1):
                bits.append((byte >> shift) & 1)
        return bits

    @staticmethod
    def _bits_32_to_int(bits: list[int]) -> int:
        """Decode 32 bits (little-endian byte order) back to int."""
        bs = bytes(
            sum(bits[i + shift] << (7 - shift) for shift in range(8))
            for i in range(0, 32, 8)
        )
        return struct.unpack("<I", bs)[0]

    # --- public API --------------------------------------------------------

    def embed(self, cover_path: str, message: str, output_path: str) -> None:
        """
        Embed *message* into the cover image at *cover_path* and save to
        *output_path*.

        Parameters
        ----------
        cover_path  : Path to the cover image (PNG or JPEG).
        message     : The secret UTF-8 text to hide.
        output_path : Destination PNG file path.

        Raises
        ------
        RuntimeError  If Pillow is not installed.
        ValueError    If the message is too long for the image.
        """
        if not _PIL_AVAILABLE:
            raise RuntimeError("Install Pillow: pip install Pillow")

        img  = Image.open(cover_path).convert("RGB")
        width, height = img.size
        pixels = list(img.getdata())   # list of (R,G,B) tuples

        msg_bits    = self._text_to_bits(message)
        length_bits = self._int_to_bits_32(len(msg_bits))
        full_bits   = length_bits + msg_bits

        # Capacity check: 3 bits per pixel (R, G, B)
        capacity = width * height * 3
        if len(full_bits) > capacity:
            raise ValueError(
                f"Message too large ({len(full_bits)} bits) for image capacity ({capacity} bits). "
                f"Use an image with at least {len(full_bits) // 3} pixels."
            )

        # Embed bits into LSBs of R, G, B channels
        bit_idx  = 0
        new_pixels: list[tuple] = []
        for pixel in pixels:
            r, g, b = pixel
            channels = [r, g, b]
            for i in range(3):
                if bit_idx < len(full_bits):
                    channels[i] = (channels[i] & ~1) | full_bits[bit_idx]
                    bit_idx += 1
            new_pixels.append(tuple(channels))

        # Reconstruct and save as PNG
        stego = Image.new("RGB", (width, height))
        stego.putdata(new_pixels)
        stego.save(output_path, format="PNG")
        logger.info(
            "Image steg: embedded %d chars into '%s' → '%s'.",
            len(message), cover_path, output_path
        )

    def extract(self, stego_path: str) -> str:
        """
        Extract a hidden message from the stego image at *stego_path*.

        Returns
        -------
        str  The extracted UTF-8 message.
        """
        if not _PIL_AVAILABLE:
            raise RuntimeError("Install Pillow: pip install Pillow")

        img    = Image.open(stego_path).convert("RGB")
        pixels = list(img.getdata())

        # Collect all LSBs from R, G, B channels
        all_bits: list[int] = []
        for pixel in pixels:
            for channel in pixel:
                all_bits.append(channel & 1)

        # Read length prefix (first 32 bits)
        msg_len_bits = self._bits_32_to_int(all_bits[:32])
        if msg_len_bits == 0 or msg_len_bits > len(all_bits) - 32:
            raise ValueError("No valid hidden message found (bad length prefix).")

        # Extract the message bits
        msg_bits = all_bits[32: 32 + msg_len_bits]
        message  = self._bits_to_text(msg_bits)
        logger.info(
            "Image steg: extracted %d chars from '%s'.",
            len(message), stego_path
        )
        return message
