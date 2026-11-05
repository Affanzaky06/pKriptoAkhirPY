# tests/test_credentials.py
"""Unit tests for password hashing and session token management."""

import time
import pytest
from securegov.auth.credential_manager import hash_password, verify_password, SessionManager


class TestPasswordHashing:

    def test_hash_is_string(self):
        h = hash_password("correct-horse-battery-staple")
        assert isinstance(h, str)
        assert len(h) > 20

    def test_correct_password_verifies(self):
        pw = "My$ecretP@ssword123"
        assert verify_password(pw, hash_password(pw))

    def test_wrong_password_fails(self):
        pw = "correct_password"
        assert not verify_password("wrong_password", hash_password(pw))

    def test_different_hashes_for_same_password(self):
        """Due to random salting, two hashes of the same pw must differ."""
        pw = "same_password"
        assert hash_password(pw) != hash_password(pw)

    def test_empty_password(self):
        h = hash_password("")
        assert verify_password("", h)
        assert not verify_password("notempty", h)


class TestSessionManager:

    def test_issue_and_validate(self):
        sm    = SessionManager()
        token = sm.issue_token("alice")
        payload = sm.validate_token(token)
        assert payload is not None
        assert payload["user_id"] == "alice"

    def test_expired_token(self):
        sm    = SessionManager(token_ttl_seconds=0)   # expires immediately
        token = sm.issue_token("alice")
        time.sleep(0.05)
        assert sm.validate_token(token) is None

    def test_tampered_token_invalid(self):
        sm    = SessionManager()
        token = sm.issue_token("alice")
        # Flip a character in the middle of the token
        idx   = len(token) // 2
        bad   = token[:idx] + ("A" if token[idx] != "A" else "B") + token[idx+1:]
        assert sm.validate_token(bad) is None

    def test_garbage_token_invalid(self):
        sm = SessionManager()
        assert sm.validate_token("not_a_real_token") is None

