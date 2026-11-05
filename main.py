# main.py
"""
SecureGov / Enterprise DocVault — Application Entry Point
==========================================================
Demonstrates every security subsystem in a cohesive, runnable workflow.

Run
---
    python main.py

What it does
------------
  1. Initialises the SQLite database.
  2. Demonstrates password hashing and session-token issuance.
  3. Simulates USB-dongle and biometric dual authentication.
  4. Performs super-encryption on a text message.
  5. Encrypts a sample document with RSA-hybrid and Fernet methods.
  6. Encrypts a database column value and reads it back.
  7. Demonstrates image, audio, and video steganography.
  8. Logs all events to the blockchain audit ledger.
  9. Verifies and prints the blockchain.
"""

import os
import sys

# Ensure safe UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Ensure the project root is on the path when running from the repo root
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from securegov.utils.logger import get_logger
from securegov.utils.key_manager import KeyManager

logger = get_logger("main")


def banner(title: str) -> None:
    width = 65
    logger.info("=" * width)
    logger.info(f"  {title}")
    logger.info("=" * width)


# ===========================================================================
# 1. Database initialisation
# ===========================================================================
def demo_database() -> None:
    banner("DATABASE INITIALISATION")
    from securegov.database.models import (
        init_db, UserRepository, DocumentRepository, MessageRepository, log_audit
    )
    from securegov.auth.credential_manager import hash_password

    init_db()

    user_repo = UserRepository()
    existing_user = user_repo.get_by_username("alice")
    if existing_user is None:
        uid = user_repo.create(
            username      = "alice",
            password_hash = hash_password("P@ssw0rd!"),
            full_name     = "Alice Anderson",
            email         = "alice@securegov.local",
            role          = "admin",
        )
        logger.info("Created user: id=%d", uid)
    else:
        uid = existing_user["id"]
        logger.info("User 'alice' already exists (id=%d).", uid)

    user = user_repo.get_by_username("alice")
    logger.info("Retrieved user: %s <%s>", user["full_name"], user["email"])
    log_audit(uid, "USER_ACCESSED", "username=alice role=admin")


# ===========================================================================
# 2. Credential cryptography
# ===========================================================================
def demo_credentials() -> None:
    banner("CREDENTIAL CRYPTOGRAPHY (Argon2 / bcrypt + AES session tokens)")
    from securegov.auth.credential_manager import hash_password, verify_password, SessionManager

    pw_hash = hash_password("My$ecretP@ss")
    logger.info("Hash: %s…", pw_hash[:40])
    logger.info("Verify correct pw : %s", verify_password("My$ecretP@ss", pw_hash))
    logger.info("Verify wrong pw   : %s", verify_password("WrongPassword", pw_hash))

    sm    = SessionManager()
    token = sm.issue_token("alice")
    logger.info("Token (first 60): %s…", token[:60])
    payload = sm.validate_token(token)
    logger.info("Decoded payload: user_id=%s", payload["user_id"] if payload else "INVALID")


# ===========================================================================
# 3. Dual authentication (USB Dongle & Biometrics)
# ===========================================================================
def demo_dual_auth() -> None:
    banner("DUAL AUTHENTICATION (USB Dongle + Biometrics)")
    from securegov.auth.biometric import (
        FingerprintSimulator,
        FaceRecognitionSimulator,
        dual_factor_auth
    )
    from securegov.auth.usb_dongle import (
        verify_dongle,
        list_connected_drives,
        check_secret_file,
        setup_dongle
    )
    import tempfile

    # --- Step 3A: USB Dongle Detection ---
    logger.info("--- 1. USB Dongle Hardware Scan ---")
    drives = list_connected_drives()
    for d in drives:
        logger.info(
            "Drive: %s | VSN: %s | Key File: %s | Valid Dongle: %s",
            d["drive"], d["vsn"], d["has_key_file"], d["is_valid_dongle"]
        )

    dongle_present = verify_dongle()
    if dongle_present:
        logger.info("✓ Physical USB Dongle detected on system!")
    else:
        logger.info("ℹ No physical USB Dongle plugged in. Testing virtual dongle workflow …")
        with tempfile.TemporaryDirectory() as tmp_drive:
            # Demonstrate how a USB drive is turned into a dongle
            setup_info = setup_dongle(tmp_drive, register_volume_serial=False)
            logger.info("Simulated Dongle setup: %s", setup_info["key_file"])
            # Verify secret key
            assert check_secret_file(tmp_drive), "Virtual dongle verification failed!"
            logger.info("✓ Virtual USB Dongle key verified successfully.")

    # --- Step 3B: Biometric Verification (Fingerprint & Camera Face) ---
    logger.info("\n--- 2. Biometric Authentication ---")
    # 1. Fingerprint
    fp = FingerprintSimulator(simulate_match_probability=1.0)
    fp.enroll("alice")
    fp_ok = fp.verify("alice")
    logger.info("Fingerprint verification: %s", "✓ MATCH" if fp_ok else "✗ FAIL")

    # 2. Camera Face Recognition (tries real webcam via OpenCV, fallback to template)
    face_auth = FaceRecognitionSimulator(camera_index=0, enable_real_camera=True)
    face_auth.enroll("alice")
    face_ok = face_auth.verify("alice")
    logger.info("Face recognition verification: %s", "✓ MATCH" if face_ok else "✗ FAIL")

    # Combined dual-factor check
    df_ok = dual_factor_auth("alice", biometric=fp, require_dongle=dongle_present)
    logger.info("Overall Dual-Factor Authentication: %s", "✓ GRANTED" if df_ok else "✗ DENIED")


# ===========================================================================
# 4. Super-encryption
# ===========================================================================
def demo_super_encryption() -> None:
    banner("SUPER ENCRYPTION (Vigenère → AES-256-GCM)")
    from securegov.crypto.super_encryption import SuperEncryptor

    key     = b"SuperEncryptKey32BytesExactly!!!"
    message = "CLASSIFIED: Operation BlackSwan departs at 0300 hrs."
    se      = SuperEncryptor(aes_key=key, classic_key="GOVKEY", classic_algo="vigenere")

    token     = se.encrypt(message)
    recovered = se.decrypt(token)

    logger.info("Original  : %s", message)
    logger.info("Token     : %s…", token[:60])
    logger.info("Recovered : %s", recovered)
    assert recovered == message, "Super-encryption round-trip FAILED!"
    logger.info("✓ Round-trip verified.")


# ===========================================================================
# 5. File encryption
# ===========================================================================
def demo_file_encryption() -> None:
    banner("FILE ENCRYPTION (RSA-Hybrid + Fernet)")
    import tempfile

    # Create a dummy "document"
    sample_data = b"%PDF-1.4 -- This is a fake government report payload.\n" * 50
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(sample_data)
        orig_path = tmp.name

    # --- RSA Hybrid ---
    km = KeyManager()
    km.generate_rsa_keypair()

    from securegov.crypto.file_encryption import RSAHybridFileEncryptor
    enc = RSAHybridFileEncryptor(km.load_public_key(), km.load_private_key())
    vault_path   = orig_path.replace(".pdf", ".sgvault")
    decrypt_path = orig_path.replace(".pdf", "_rsa_decrypted.pdf")
    enc.encrypt_file(orig_path, vault_path)
    enc.decrypt_file(vault_path, decrypt_path)
    with open(decrypt_path, "rb") as f:
        assert f.read() == sample_data, "RSA-hybrid round-trip FAILED!"
    logger.info("✓ RSA-Hybrid file encryption round-trip verified.")

    # --- Fernet ---
    from securegov.crypto.file_encryption import FernetFileEncryptor
    fen_enc   = FernetFileEncryptor()
    fen_path  = orig_path.replace(".pdf", ".fen")
    fen_dec   = orig_path.replace(".pdf", "_fen_decrypted.pdf")
    fen_enc.encrypt_file(orig_path, fen_path)
    fen_enc.decrypt_file(fen_path, fen_dec)
    with open(fen_dec, "rb") as f:
        assert f.read() == sample_data, "Fernet round-trip FAILED!"
    logger.info("✓ Fernet file encryption round-trip verified.")

    # Cleanup
    for p in [orig_path, vault_path, decrypt_path, fen_path, fen_dec]:
        try:
            os.unlink(p)
        except OSError:
            pass


# ===========================================================================
# 6. Database column encryption
# ===========================================================================
def demo_db_crypto() -> None:
    banner("DATABASE COLUMN ENCRYPTION (AES-256-GCM)")
    from securegov.database.db_crypto import DBColumnCrypto

    cc     = DBColumnCrypto()
    secret = "Minister of Finance: John Reeves, DOB 1972-04-15"
    blob   = cc.encrypt(secret)
    plain  = cc.decrypt(blob)
    logger.info("Plaintext : %s", secret)
    logger.info("Encrypted : %s…", blob[:60])
    logger.info("Decrypted : %s", plain)
    assert plain == secret, "DB column crypto round-trip FAILED!"
    logger.info("✓ DB column AES-GCM round-trip verified.")


# ===========================================================================
# 7. Image steganography
# ===========================================================================
def demo_image_steg() -> None:
    banner("IMAGE STEGANOGRAPHY (LSB — Pillow)")
    try:
        from PIL import Image
    except ImportError:
        logger.warning("Pillow not installed, skipping image steg demo.")
        return

    from securegov.steganography.image_steg import ImageSteganography
    import tempfile

    # Create a solid-colour cover image (512×512 red)
    img = Image.new("RGB", (512, 512), color=(180, 50, 50))
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        img.save(tmp.name)
        cover_path = tmp.name

    stego_path = cover_path.replace(".png", "_stego.png")
    secret     = "EYES ONLY: Rendezvous at the embassy at midnight."

    steg = ImageSteganography()
    steg.embed(cover_path, secret, stego_path)
    extracted = steg.extract(stego_path)

    logger.info("Original  : %s", secret)
    logger.info("Extracted : %s", extracted)
    assert extracted == secret, "Image steg round-trip FAILED!"
    logger.info("✓ Image LSB steganography round-trip verified.")

    for p in [cover_path, stego_path]:
        try:
            os.unlink(p)
        except OSError:
            pass


# ===========================================================================
# 8. Audio steganography
# ===========================================================================
def demo_audio_steg() -> None:
    banner("AUDIO STEGANOGRAPHY (LSB — wave)")
    import wave, struct, tempfile

    # Generate a 1-second 16-bit mono sine-wave WAV
    framerate = 44100
    n_frames  = framerate
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
        cover_path = tmp.name

    with wave.open(cover_path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(framerate)
        import math
        samples = b"".join(
            struct.pack("<h", int(32767 * math.sin(2 * math.pi * 440 * i / framerate)))
            for i in range(n_frames)
        )
        wf.writeframes(samples)

    stego_path = cover_path.replace(".wav", "_stego.wav")
    secret     = "Audio steg test: Operation NightOwl confirmed."

    from securegov.steganography.audio_steg import AudioSteganography
    steg = AudioSteganography()
    steg.embed(cover_path, secret, stego_path)
    extracted = steg.extract(stego_path)

    logger.info("Original  : %s", secret)
    logger.info("Extracted : %s", extracted)
    assert extracted == secret, "Audio steg round-trip FAILED!"
    logger.info("✓ Audio LSB steganography round-trip verified.")

    for p in [cover_path, stego_path]:
        try:
            os.unlink(p)
        except OSError:
            pass


# ===========================================================================
# 8B. Video steganography
# ===========================================================================
def demo_video_steg() -> None:
    banner("VIDEO STEGANOGRAPHY (Frame-based LSB — OpenCV)")
    try:
        import cv2
        import numpy as np
    except ImportError:
        logger.warning("opencv-python not installed, skipping video steg demo.")
        return

    import tempfile
    from securegov.steganography.video_steg import VideoSteganography

    # Create a synthetic 20-frame AVI video clip
    with tempfile.NamedTemporaryFile(suffix=".avi", delete=False) as tmp:
        cover_path = tmp.name

    fourcc = cv2.VideoWriter_fourcc(*"FFV1")
    out = cv2.VideoWriter(cover_path, fourcc, 10.0, (64, 64))
    for _ in range(20):
        frame = np.zeros((64, 64, 3), dtype=np.uint8)
        frame[:, :, 0] = 120  # Blue base
        out.write(frame)
    out.release()

    stego_path = cover_path.replace(".avi", "_stego.avi")
    secret     = "TopSecret VideoPayload #2026!"

    steg = VideoSteganography()
    steg.embed(cover_path, secret, stego_path)
    extracted = steg.extract(stego_path)

    logger.info("Original  : %s", secret)
    logger.info("Extracted : %s", extracted)
    assert extracted == secret, "Video steg round-trip FAILED!"
    logger.info("✓ Video frame LSB steganography round-trip verified.")

    for p in [cover_path, stego_path]:
        try:
            os.unlink(p)
        except OSError:
            pass


# ===========================================================================
# 9. Blockchain audit trail
# ===========================================================================
def demo_blockchain() -> None:
    banner("BLOCKCHAIN AUDIT TRAIL (SHA-256)")
    import tempfile, os

    with tempfile.TemporaryDirectory() as tmpdir:
        from securegov.blockchain.chain import Blockchain

        bc = Blockchain(storage_path=os.path.join(tmpdir, "audit.json"), difficulty=0)

        bc.add_block({"event": "LOGIN_SUCCESS",        "user": "alice", "ip": "10.0.0.1"})
        bc.add_block({"event": "DOCUMENT_UPLOADED",    "user": "alice", "doc_id": 1})
        bc.add_block({"event": "MESSAGE_SENT",         "from": "alice", "to": "bob"})
        bc.add_block({"event": "FILE_DECRYPTED",       "user": "alice", "doc_id": 1})
        bc.add_block({"event": "LOGOUT",               "user": "alice"})

        bc.print_chain()
        logger.info("Chain valid: %s", bc.is_valid())

        # Tamper simulation
        logger.info("Simulating block tampering …")
        bc.chain[2].data["user"] = "HACKER"
        logger.info("Chain valid after tamper: %s", bc.is_valid())
        assert not bc.is_valid(), "Chain should be INVALID after tamper!"
        logger.info("✓ Tamper detected correctly.")


# ===========================================================================
# MAIN
# ===========================================================================
if __name__ == "__main__":
    logger.info("\n\n  ╔══════════════════════════════════════╗")
    logger.info(   "  ║  SecureGov / Enterprise DocVault     ║")
    logger.info(   "  ║  Cryptography Demonstration Suite    ║")
    logger.info(   "  ╚══════════════════════════════════════╝\n")

    demo_database()
    demo_credentials()
    demo_dual_auth()
    demo_super_encryption()
    demo_file_encryption()
    demo_db_crypto()
    demo_image_steg()
    demo_audio_steg()
    demo_video_steg()
    demo_blockchain()

    logger.info("\n  ✓ All demonstrations completed successfully.\n")

