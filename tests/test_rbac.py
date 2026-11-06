# tests/test_rbac.py
"""
Unit Tests for Role-Based Access Control (RBAC) & Admin User Provisioning
========================================================================
Tests:
  - Strict distinction between 'admin' and 'user' roles in SQLite.
  - Admin ability to provision new regular users and new admins.
  - Automatic blockchain block creation on user provisioning.
  - Camera enumeration & safe release resilience.
"""

import os
import tempfile
import pytest

from securegov.auth.credential_manager import hash_password, verify_password
from securegov.database.models import UserRepository, init_db
from securegov.blockchain.chain import Blockchain
from securegov.gui.camera_manager import list_available_cameras, safe_release_camera


class TestRBACAndProvisioning:
    @pytest.fixture(autouse=True)
    def setup_db(self, tmp_path, monkeypatch):
        test_db = tmp_path / "test_rbac.db"
        monkeypatch.setattr("securegov.utils.config.DB_PATH", str(test_db))
        monkeypatch.setattr("securegov.database.models.DB_PATH", str(test_db))
        init_db()
        self.repo = UserRepository()
        self.blockchain = Blockchain(difficulty=0, storage_path=str(tmp_path / "test_chain.json"))

    def test_create_regular_user(self):
        pw_hash = hash_password("UserPass123!")
        uid = self.repo.create(
            username="budi_operator",
            password_hash=pw_hash,
            full_name="Budi Santoso",
            email="budi@securegov.id",
            role="user",
        )
        assert uid > 0

        user = self.repo.get_by_username("budi_operator")
        assert user is not None
        assert user["role"] == "user"
        assert user["full_name"] == "Budi Santoso"
        assert user["email"] == "budi@securegov.id"
        assert verify_password("UserPass123!", user["password_hash"])

    def test_create_admin_user(self):
        pw_hash = hash_password("AdminRoot999!")
        uid = self.repo.create(
            username="charlie_admin",
            password_hash=pw_hash,
            full_name="Charlie Officer",
            email="charlie@defense.gov",
            role="admin",
        )
        assert uid > 0

        admin = self.repo.get_by_username("charlie_admin")
        assert admin is not None
        assert admin["role"] == "admin"
        assert admin["full_name"] == "Charlie Officer"

    def test_blockchain_block_created_on_user_provisioning(self):
        initial_blocks = len(self.blockchain.chain)

        # Admin registers new user
        admin_actor = "alice"
        new_username = "dani_analyst"
        new_role = "user"

        pw_hash = hash_password("SecureKey#2026")
        uid = self.repo.create(
            username=new_username,
            password_hash=pw_hash,
            role=new_role,
        )
        self.repo.update_dongle_vsn(uid, "4A21D99C")

        # Blockchain entry created
        new_block = self.blockchain.add_block({
            "event": "USER_PROVISIONED_BY_ADMIN",
            "admin_actor": admin_actor,
            "new_user": new_username,
            "assigned_role": new_role,
            "dongle_vsn": "4A21D99C",
            "face_enrolled": False,
        })

        assert len(self.blockchain.chain) == initial_blocks + 1
        assert new_block.data["event"] == "USER_PROVISIONED_BY_ADMIN"
        assert new_block.data["admin_actor"] == "alice"
        assert new_block.data["new_user"] == "dani_analyst"
        assert new_block.data["assigned_role"] == "user"

        # Verify integrity holds
        is_intact, errors = self.blockchain.validate_chain_detailed()
        assert is_intact
        assert len(errors) == 0


class TestCameraManager:
    def test_list_cameras_returns_valid_list(self):
        cams = list_available_cameras(max_tested=2)
        assert isinstance(cams, list)
        assert len(cams) >= 1
        assert all(isinstance(i, int) for i in cams)

    def test_safe_release_camera_handles_none_gracefully(self):
        # Should not raise any exception
        safe_release_camera(None)
