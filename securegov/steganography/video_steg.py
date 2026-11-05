# securegov/steganography/video_steg.py
"""
Video Steganography — Frame-based LSB using OpenCV
====================================================
Hides and extracts arbitrary UTF-8 text by modifying the least-significant
bits (LSBs) of pixel channel values across consecutive video frames.

Lossless Video Encoding
-----------------------
Standard video codecs like H.264/XVID are lossy and alter pixel values during
quantization, corrupting LSB data. This implementation uses the lossless FFV1
(or HFYU) codec to ensure bit-exact fidelity of embedded secrets.

Capacity
--------
  max_bytes ≈ (n_frames × width × height) // 8  −  4

Usage
-----
    from securegov.steganography.video_steg import VideoSteganography

    steg = VideoSteganography()
    steg.embed("cover.avi", "Classified briefing notes.", "stego.avi")
    msg  = steg.extract("stego.avi")
    assert msg == "Classified briefing notes."
"""

import struct
from securegov.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import cv2
    import numpy as np
    _CV2_AVAILABLE = True
except ImportError:
    _CV2_AVAILABLE = False
    logger.warning(
        "opencv-python not installed — VideoSteganography will not work. "
        "Run: pip install opencv-python"
    )


class VideoSteganography:
    """Frame-based LSB video steganography using OpenCV."""

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _text_to_bits(message: str) -> list[int]:
        payload = message.encode("utf-8")
        header  = struct.pack("<I", len(payload))
        full    = header + payload
        bits: list[int] = []
        for byte in full:
            for shift in range(7, -1, -1):
                bits.append((byte >> shift) & 1)
        return bits

    @staticmethod
    def _bits_to_text(bits: list[int]) -> str:
        raw = bytes(
            sum(bits[i + j] << (7 - j) for j in range(8))
            for i in range(0, len(bits), 8)
        )
        if len(raw) < 4:
            raise ValueError("Bit stream too short.")
        msg_len = struct.unpack("<I", raw[:4])[0]
        return raw[4: 4 + msg_len].decode("utf-8", errors="replace")

    # --- public API --------------------------------------------------------

    def embed(
        self,
        cover_path: str,
        message: str,
        output_path: str,
        lossless_codec: str = "FFV1",
    ) -> None:
        """
        Embed *message* into the video at *cover_path* and save to *output_path*.

        Parameters
        ----------
        cover_path     : Path to the input video file.
        message        : Secret UTF-8 text to embed.
        output_path    : Destination video path (.avi container recommended).
        lossless_codec : 4-char FourCC codec string ('FFV1' default for lossless).
        """
        if not _CV2_AVAILABLE:
            raise RuntimeError("Install OpenCV: pip install opencv-python")

        cap = cv2.VideoCapture(cover_path)
        if not cap.isOpened():
            raise IOError(f"Cannot open video: {cover_path}")

        fps    = cap.get(cv2.CAP_PROP_FPS) or 24.0
        width  = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

        frames: list[np.ndarray] = []
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            frames.append(frame)
        cap.release()

        if not frames:
            raise ValueError("Video contains no readable frames.")

        bits = self._text_to_bits(message)
        total_capacity = sum(f.shape[0] * f.shape[1] for f in frames)
        if len(bits) > total_capacity:
            raise ValueError(
                f"Message too large ({len(bits)} bits) for video capacity "
                f"({total_capacity} bits). Use a longer / higher-resolution video."
            )

        # Embed bits into the blue channel (index 0 in BGR)
        bit_idx = 0
        for frame in frames:
            if bit_idx >= len(bits):
                break
            rows, cols, _ = frame.shape
            for r in range(rows):
                for c in range(cols):
                    if bit_idx >= len(bits):
                        break
                    frame[r, c, 0] = (int(frame[r, c, 0]) & ~1) | bits[bit_idx]
                    bit_idx += 1

        # Use lossless codec (FFV1) to prevent pixel corruption
        fourcc = cv2.VideoWriter_fourcc(*lossless_codec)
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        for frame in frames:
            out.write(frame)
        out.release()

        logger.info(
            "Video steg: embedded %d chars across %d frames of '%s' → '%s' (codec=%s).",
            len(message), len(frames), cover_path, output_path, lossless_codec
        )

    def extract(self, stego_path: str) -> str:
        """
        Extract the hidden message from *stego_path*.

        Returns
        -------
        str  The extracted UTF-8 message.
        """
        if not _CV2_AVAILABLE:
            raise RuntimeError("Install OpenCV: pip install opencv-python")

        cap = cv2.VideoCapture(stego_path)
        if not cap.isOpened():
            raise IOError(f"Cannot open video: {stego_path}")

        all_bits: list[int] = []
        header_bits = 32
        expected_total_bits = None

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            rows, cols, _ = frame.shape
            for r in range(rows):
                for c in range(cols):
                    all_bits.append(int(frame[r, c, 0]) & 1)

                    # Once we have 32 bits, determine message length
                    if expected_total_bits is None and len(all_bits) >= header_bits:
                        len_bytes = bytes(
                            sum(all_bits[i + j] << (7 - j) for j in range(8))
                            for i in range(0, 32, 8)
                        )
                        msg_byte_len = struct.unpack("<I", len_bytes)[0]
                        expected_total_bits = header_bits + (msg_byte_len * 8)

                    if expected_total_bits is not None and len(all_bits) >= expected_total_bits:
                        break
                if expected_total_bits is not None and len(all_bits) >= expected_total_bits:
                    break
            if expected_total_bits is not None and len(all_bits) >= expected_total_bits:
                break

        cap.release()

        if expected_total_bits is None or len(all_bits) < expected_total_bits:
            raise ValueError("Incomplete video or no valid hidden message found.")

        message = self._bits_to_text(all_bits[:expected_total_bits])
        logger.info(
            "Video steg: extracted %d chars from '%s'.",
            len(message), stego_path
        )
        return message
