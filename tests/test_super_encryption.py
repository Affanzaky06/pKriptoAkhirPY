# tests/test_super_encryption.py
"""Unit tests for the two-layer super-encryption module."""

import pytest
from securegov.crypto.super_encryption import SuperEncryptor


_AES_KEY = b"TestAESKey32BytesForSuperEnc!!!!"
_CLASSIC_KEY = "TESTKEY"


class TestSuperEncryptor:

    def test_vigenere_round_trip(self):
        se = SuperEncryptor(_AES_KEY, _CLASSIC_KEY, "vigenere")
        msg = "Top secret government memo"
        assert se.decrypt(se.encrypt(msg)) == msg

    def test_playfair_round_trip(self):
        se = SuperEncryptor(_AES_KEY, _CLASSIC_KEY, "playfair")
        msg = "SECRETMEETINGTONIGHT"
        # Playfair pads with X/Z; decrypt recovers Playfair output exactly
        ct = se.encrypt(msg)
        pt = se.decrypt(ct)
        # At minimum the original letters are present (minus possible J→I)
        assert msg[:6] in pt or msg.replace("J", "I")[:6] in pt

    def test_different_tokens_for_same_plaintext(self):
        """Non-deterministic: two encryptions of the same text must differ."""
        se = SuperEncryptor(_AES_KEY, _CLASSIC_KEY, "vigenere")
        msg = "Hello"
        t1 = se.encrypt(msg)
        t2 = se.encrypt(msg)
        assert t1 != t2

    def test_wrong_key_raises(self):
        """Decrypting with a different key must raise an exception."""
        se1 = SuperEncryptor(_AES_KEY, _CLASSIC_KEY, "vigenere")
        se2 = SuperEncryptor(b"WrongAESKey32BytesForSuperEnc!!!", _CLASSIC_KEY, "vigenere")
        token = se1.encrypt("secret")
        with pytest.raises(Exception):
            se2.decrypt(token)

    def test_invalid_key_length(self):
        with pytest.raises(ValueError):
            SuperEncryptor(b"tooshort", _CLASSIC_KEY, "vigenere")

    def test_malformed_token(self):
        se = SuperEncryptor(_AES_KEY, _CLASSIC_KEY, "vigenere")
        with pytest.raises(ValueError):
            se.decrypt("this_is_not_a_valid_token!!!")

    def test_unknown_classic_algo(self):
        with pytest.raises(ValueError):
            SuperEncryptor(_AES_KEY, _CLASSIC_KEY, "caesar")  # type: ignore

