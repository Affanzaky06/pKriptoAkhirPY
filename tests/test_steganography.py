# tests/test_steganography.py
"""Unit tests for image, audio, and video steganography modules."""

import os
import wave
import struct
import math
import tempfile
import pytest


# ===========================================================================
# Image Steganography
# ===========================================================================

class TestImageSteganography:

    @pytest.fixture()
    def cover_image(self, tmp_path):
        """Create a 256×256 blue PNG cover image."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("Pillow not installed")
        img = Image.new("RGB", (256, 256), (0, 0, 200))
        p   = str(tmp_path / "cover.png")
        img.save(p)
        return p

    def test_embed_and_extract(self, tmp_path, cover_image):
        from securegov.steganography.image_steg import ImageSteganography
        steg   = ImageSteganography()
        secret = "Hidden government message #42!"
        stego  = str(tmp_path / "stego.png")
        steg.embed(cover_image, secret, stego)
        assert steg.extract(stego) == secret

    def test_message_too_large_raises(self, tmp_path, cover_image):
        from securegov.steganography.image_steg import ImageSteganography
        steg  = ImageSteganography()
        big   = "X" * 100_000   # far too large for a 256×256 image
        stego = str(tmp_path / "stego_big.png")
        with pytest.raises(ValueError, match="too large"):
            steg.embed(cover_image, big, stego)

    def test_no_message_raises(self, tmp_path, cover_image):
        """Extracting from an unmodified image should raise ValueError."""
        from securegov.steganography.image_steg import ImageSteganography
        steg = ImageSteganography()
        with pytest.raises(ValueError):
            steg.extract(cover_image)


# ===========================================================================
# Audio Steganography
# ===========================================================================

class TestAudioSteganography:

    @pytest.fixture()
    def cover_wav(self, tmp_path):
        """Create a 2-second silent 16-bit mono WAV file."""
        p        = str(tmp_path / "cover.wav")
        n_frames = 44100 * 2
        with wave.open(p, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(44100)
            wf.writeframes(b"\x00\x00" * n_frames)
        return p

    def test_embed_and_extract(self, tmp_path, cover_wav):
        from securegov.steganography.audio_steg import AudioSteganography
        steg   = AudioSteganography()
        secret = "Audio secret payload — test run."
        stego  = str(tmp_path / "stego.wav")
        steg.embed(cover_wav, secret, stego)
        assert steg.extract(stego) == secret

    def test_message_too_large_raises(self, tmp_path, cover_wav):
        from securegov.steganography.audio_steg import AudioSteganography
        steg  = AudioSteganography()
        big   = "Z" * 1_000_000
        stego = str(tmp_path / "stego_big.wav")
        with pytest.raises(ValueError, match="too large"):
            steg.embed(cover_wav, big, stego)


# ===========================================================================
# Video Steganography (skipped when OpenCV unavailable)
# ===========================================================================

class TestVideoSteganography:

    @pytest.fixture()
    def cover_video(self, tmp_path):
        """Create a small synthetic AVI video with OpenCV."""
        try:
            import cv2
            import numpy as np
        except ImportError:
            pytest.skip("opencv-python not installed")

        path   = str(tmp_path / "cover.avi")
        fourcc = cv2.VideoWriter_fourcc(*"FFV1")
        out    = cv2.VideoWriter(path, fourcc, 10.0, (64, 64))
        for _ in range(30):   # 3 seconds at 10 fps
            frame = np.zeros((64, 64, 3), dtype=np.uint8)
            frame[:, :, 2] = 128   # red channel
            out.write(frame)
        out.release()
        return path

    def test_embed_and_extract(self, tmp_path, cover_video):
        from securegov.steganography.video_steg import VideoSteganography
        steg   = VideoSteganography()
        secret = "Video stego secret!"
        stego  = str(tmp_path / "stego.avi")
        steg.embed(cover_video, secret, stego)
        assert steg.extract(stego) == secret

