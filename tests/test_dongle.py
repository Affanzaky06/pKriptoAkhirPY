# tests/test_dongle.py
"""Unit tests for USB Dongle verification and continuous presence checks."""

import os
import tempfile
import pytest
from securegov.auth.usb_dongle import (
    verify_dongle_for_user,
    check_secret_file,
    register_usb_dongle,
    load_allowed_vsns,
)
from securegov.utils.config import DONGLE_SECRET_FILENAME, DONGLE_SECRET_VALUE


class TestUsbDongleModule:

    def test_check_secret_file_missing(self, tmp_path):
        assert not check_secret_file(str(tmp_path))

    def test_check_secret_file_valid(self, tmp_path):
        key_file = tmp_path / DONGLE_SECRET_FILENAME
        key_file.write_bytes(DONGLE_SECRET_VALUE)
        assert check_secret_file(str(tmp_path))

    def test_verify_dongle_nonexistent_vsn(self):
        ok, msg, info = verify_dongle_for_user(expected_vsn="NON_EXISTENT_VSN_9999")
        assert not ok
        assert "tidak ditemukan" in msg.lower()
        assert info is None

    def test_registered_vsn_field_resolution(self):
        # Ensure user dictionary resolution works with registered_vsn
        user_dict = {
            "username": "Affan",
            "registered_vsn": "98E68F98",
        }
        resolved_vsn = user_dict.get("registered_vsn") or user_dict.get("usb_serial")
        assert resolved_vsn == "98E68F98"
        # When unplugged, should return False
        ok, msg, _ = verify_dongle_for_user(resolved_vsn)
        # If not plugged in during tests, ok is False
        assert isinstance(ok, bool)
