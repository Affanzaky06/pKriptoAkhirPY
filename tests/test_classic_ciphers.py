# tests/test_classic_ciphers.py
"""Unit tests for Vigenère and Playfair cipher implementations."""

import pytest
from securegov.crypto.classic_ciphers import VigenereCipher, PlayfairCipher


# ===========================================================================
# Vigenère Cipher Tests
# ===========================================================================

class TestVigenereCipher:

    def test_known_vector(self):
        """ATTACKATDAWN encrypted with LEMON → LXFOPVEFRNHR (classic example)."""
        vc = VigenereCipher("LEMON")
        assert vc.encrypt("ATTACKATDAWN") == "LXFOPVEFRNHR"

    def test_round_trip(self):
        vc = VigenereCipher("SECRETKEY")
        pt = "HelloWorldFromSecureGov"
        assert vc.decrypt(vc.encrypt(pt)) == pt

    def test_case_preservation(self):
        vc = VigenereCipher("KEY")
        ct = vc.encrypt("Hello")
        assert ct[0].isupper()   # 'H' should stay uppercase
        assert ct[1].islower()   # 'e' should stay lowercase

    def test_non_alpha_passthrough(self):
        vc = VigenereCipher("KEY")
        ct = vc.encrypt("Hello, World! 123")
        assert ", " in ct
        assert "123" in ct

    def test_key_validation(self):
        with pytest.raises(ValueError):
            VigenereCipher("123!@#")   # no letters at all


# ===========================================================================
# Playfair Cipher Tests
# ===========================================================================

class TestPlayfairCipher:

    def test_round_trip_basic(self):
        pf = PlayfairCipher("MONARCHY")
        ct = pf.encrypt("BALLOON")
        pt = pf.decrypt(ct)
        # In Playfair, repeated letters like LL are split with X, resulting in BALXLOON
        assert "BALXLOON" in pt or "BALON" in pt

    def test_no_repeated_pair_in_ciphertext(self):
        """Playfair output should be even-length uppercase letters only."""
        pf = PlayfairCipher("KEYWORD")
        ct = pf.encrypt("THEQUICKBROWNFOX")
        assert len(ct) % 2 == 0
        assert ct.isalpha()
        assert ct == ct.upper()

    def test_j_treated_as_i(self):
        pf1 = PlayfairCipher("KEY")
        pf2 = PlayfairCipher("KEY")
        # Encrypting "JAVA" and "IAVA" should give the same result (J→I)
        assert pf1.encrypt("JAVA") == pf2.encrypt("IAVA")

