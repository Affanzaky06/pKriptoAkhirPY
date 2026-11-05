# securegov/steganography/audio_steg.py
"""
Audio Steganography — LSB in WAV PCM Samples
==============================================
Hides and extracts arbitrary UTF-8 text inside the least-significant bits
of the PCM audio samples of a standard WAV file (8-bit or 16-bit, mono or
stereo).

Algorithm
---------
  * The secret message bytes are prefixed with a 4-byte (uint32-LE) length
    field (byte count, not bit count), then converted to a bit stream.
  * Each bit replaces the least-significant bit of one audio sample.
  * For 16-bit samples the sample is treated as a signed integer; the LSB is
    the least-significant bit of the raw ``int`` representation.
  * The output file is a new WAV with identical headers and audio quality
    indistinguishable to human hearing.

Capacity (16-bit stereo, 44 100 Hz)
------------------------------------
  max_bytes ≈ total_samples // 8  −  4   (~5.5 KB per second of audio)

Usage
-----
    from securegov.steganography.audio_steg import AudioSteganography

    steg = AudioSteganography()
    steg.embed("cover.wav", "Secret payload", "stego.wav")
    msg  = steg.extract("stego.wav")
    assert msg == "Secret payload"
"""

import struct
import wave
import array
from typing import Sequence

from securegov.utils.logger import get_logger

logger = get_logger(__name__)


class AudioSteganography:
    """LSB steganography for WAV PCM audio files using the ``wave`` stdlib."""

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _read_wav(path: str) -> tuple[wave.Wave_read, bytes, int, int, int]:
        """
        Open *path* and return
        (wave_reader, raw_frames, n_channels, sampwidth, framerate).
        """
        with wave.open(path, "rb") as wf:
            params     = wf.getparams()
            raw_frames = wf.readframes(params.nframes)
        return raw_frames, params.nchannels, params.sampwidth, params.framerate, params.nframes

    @staticmethod
    def _frames_to_samples(raw: bytes, sampwidth: int) -> list[int]:
        """Convert raw WAV bytes to a list of integer sample values."""
        if sampwidth == 1:
            # Unsigned 8-bit
            return list(raw)
        elif sampwidth == 2:
            # Signed 16-bit little-endian
            return list(array.array("h", raw))
        elif sampwidth == 3:
            # Signed 24-bit (3 bytes each — read as int via struct)
            samples = []
            for i in range(0, len(raw), 3):
                val = struct.unpack("<i", raw[i:i+3] + b'\x00')[0] >> 8
                samples.append(val)
            return samples
        elif sampwidth == 4:
            return list(array.array("i", raw))
        else:
            raise ValueError(f"Unsupported sample width: {sampwidth} bytes.")

    @staticmethod
    def _samples_to_frames(samples: list[int], sampwidth: int) -> bytes:
        """Convert integer samples back to raw WAV bytes."""
        if sampwidth == 1:
            return bytes(samples)
        elif sampwidth == 2:
            return array.array("h", samples).tobytes()
        elif sampwidth == 3:
            parts = []
            for s in samples:
                parts.append(struct.pack("<i", s << 8)[:3])
            return b"".join(parts)
        elif sampwidth == 4:
            return array.array("i", samples).tobytes()
        else:
            raise ValueError(f"Unsupported sample width: {sampwidth} bytes.")

    @staticmethod
    def _text_to_bits(message: str) -> list[int]:
        payload = message.encode("utf-8")
        length  = struct.pack("<I", len(payload))  # 4-byte length prefix
        full    = length + payload
        bits: list[int] = []
        for byte in full:
            for shift in range(7, -1, -1):
                bits.append((byte >> shift) & 1)
        return bits

    @staticmethod
    def _bits_to_text(bits: list[int]) -> str:
        """Decode raw bits → length prefix → payload → str."""
        # Reconstruct bytes
        raw_bytes = bytes(
            sum(bits[i + j] << (7 - j) for j in range(8))
            for i in range(0, len(bits), 8)
        )
        if len(raw_bytes) < 4:
            raise ValueError("Bit stream too short to contain a length prefix.")
        msg_len = struct.unpack("<I", raw_bytes[:4])[0]
        return raw_bytes[4: 4 + msg_len].decode("utf-8", errors="replace")

    # --- public API --------------------------------------------------------

    def embed(self, cover_path: str, message: str, output_path: str) -> None:
        """
        Hide *message* inside *cover_path* (WAV) and save to *output_path*.

        Raises
        ------
        ValueError  If the message is too large for the audio file.
        """
        raw, nchannels, sampwidth, framerate, nframes = self._read_wav(cover_path)
        samples = self._frames_to_samples(raw, sampwidth)

        bits = self._text_to_bits(message)

        if len(bits) > len(samples):
            raise ValueError(
                f"Message too large ({len(bits)} bits) for audio capacity "
                f"({len(samples)} samples). Use a longer audio file."
            )

        # Embed each bit into the LSB of successive samples
        for idx, bit in enumerate(bits):
            samples[idx] = (samples[idx] & ~1) | bit

        new_frames = self._samples_to_frames(samples, sampwidth)

        with wave.open(output_path, "wb") as wf:
            wf.setnchannels(nchannels)
            wf.setsampwidth(sampwidth)
            wf.setframerate(framerate)
            wf.writeframes(new_frames)

        logger.info(
            "Audio steg: embedded %d chars into '%s' → '%s'.",
            len(message), cover_path, output_path
        )

    def extract(self, stego_path: str) -> str:
        """
        Extract the hidden message from *stego_path*.

        Returns
        -------
        str  The original hidden UTF-8 message.
        """
        raw, _nc, sampwidth, _fr, _nf = self._read_wav(stego_path)
        samples = self._frames_to_samples(raw, sampwidth)

        # Read enough bits: 32 bits for length + at most all remaining
        bits = [s & 1 for s in samples]

        # Determine actual message length from first 32 bits
        if len(bits) < 32:
            raise ValueError("Audio file too short to contain a hidden message.")

        length_bytes = bytes(
            sum(bits[i + j] << (7 - j) for j in range(8))
            for i in range(0, 32, 8)
        )
        msg_len = struct.unpack("<I", length_bytes)[0]

        # Validate
        total_bits_needed = 32 + msg_len * 8
        if total_bits_needed > len(bits):
            raise ValueError("Encoded length exceeds audio capacity — no valid message.")

        message = self._bits_to_text(bits[:total_bits_needed])
        logger.info(
            "Audio steg: extracted %d chars from '%s'.",
            len(message), stego_path
        )
        return message

