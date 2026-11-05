# tests/test_db_crypto.py
"""Unit tests for AES-GCM database column encryption."""

import pytest
from securegov.database.db_crypto import DBColumnCrypto


_KEY = b"DBTestKey32BytesAESGCM!!!!!!!!xx"


class TestDBColumnCrypto:

    def test_round_trip(self):
        cc = DBColumnCrypto(key=_KEY)
        plain = "Sensitive personal data — Иван Иванов"
        assert cc.decrypt(cc.encrypt(plain)) == plain

    def test_non_deterministic(self):
        cc = DBColumnCrypto(key=_KEY)
        b1 = cc.encrypt("same value")
        b2 = cc.encrypt("same value")
        assert b1 != b2   # different nonces → different ciphertexts

    def test_tamper_raises(self):
        cc = DBColumnCrypto(key=_KEY)
        blob = cc.encrypt("legit data")
        # Corrupt a byte near the end (tag area)
        raw  = list(blob)
        raw[-5] = "X" if raw[-5] != "X" else "Y"
        corrupted = "".join(raw)
        with pytest.raises(Exception):
            cc.decrypt(corrupted)

    def test_null_handling(self):
        cc = DBColumnCrypto(key=_KEY)
        assert cc.encrypt_or_null(None)  is None
        assert cc.decrypt_or_null(None)  is None

    def test_empty_string(self):
        cc = DBColumnCrypto(key=_KEY)
        assert cc.decrypt(cc.encrypt("")) == ""

    def test_unicode(self):
        cc = DBColumnCrypto(key=_KEY)
        uni = "数据加密测试 🔐 Ω∑≈π"
        assert cc.decrypt(cc.encrypt(uni)) == uni

    def test_wrong_key_size_raises(self):
        with pytest.raises(ValueError):
            DBColumnCrypto(key=b"tooshort")

