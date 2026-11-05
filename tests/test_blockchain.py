# tests/test_blockchain.py
"""Unit tests for the SecureGov blockchain implementation."""

import os
import tempfile
import pytest
from securegov.blockchain.chain import Block, Blockchain


class TestBlock:

    def test_hash_deterministic(self):
        b = Block(0, 1234567890.0, {"event": "GENESIS"}, "0" * 64)
        h1 = b.compute_hash()
        h2 = b.compute_hash()
        assert h1 == h2

    def test_hash_changes_on_data_mutation(self):
        b = Block(1, 1234567890.0, {"event": "LOGIN"}, "aabbcc")
        original = b.hash
        b.data["event"] = "TAMPERED"
        new_hash = b.compute_hash()
        assert original != new_hash    # stored hash ≠ recomputed hash → tamper detected

    def test_serialisation_round_trip(self):
        b = Block(2, 9999.9, {"key": "value"}, "deadbeef")
        b2 = Block.from_dict(b.to_dict())
        assert b.hash          == b2.hash
        assert b.previous_hash == b2.previous_hash
        assert b.data          == b2.data


class TestBlockchain:

    def _new_chain(self, tmpdir) -> Blockchain:
        return Blockchain(storage_path=os.path.join(tmpdir, "chain.json"), difficulty=0)

    def test_genesis_block_created(self, tmp_path):
        bc = self._new_chain(str(tmp_path))
        assert len(bc.chain) == 1
        assert bc.chain[0].index == 0
        assert bc.chain[0].previous_hash == "0" * 64

    def test_add_blocks(self, tmp_path):
        bc = self._new_chain(str(tmp_path))
        bc.add_block({"event": "LOGIN"})
        bc.add_block({"event": "LOGOUT"})
        assert len(bc.chain) == 3   # genesis + 2

    def test_chain_valid_after_additions(self, tmp_path):
        bc = self._new_chain(str(tmp_path))
        bc.add_block({"event": "A"})
        bc.add_block({"event": "B"})
        assert bc.is_valid()

    def test_tamper_detection(self, tmp_path):
        bc = self._new_chain(str(tmp_path))
        bc.add_block({"event": "LOGIN", "user": "alice"})
        bc.add_block({"event": "UPLOAD"})
        # Tamper block 1
        bc.chain[1].data["user"] = "HACKER"
        assert not bc.is_valid()

    def test_persistence_and_reload(self, tmp_path):
        path = os.path.join(str(tmp_path), "chain.json")
        bc1 = Blockchain(storage_path=path, difficulty=0)
        bc1.add_block({"event": "PERSISTED"})
        # Reload
        bc2 = Blockchain(storage_path=path, difficulty=0)
        assert len(bc2.chain) == 2
        assert bc2.chain[1].data["event"] == "PERSISTED"
        assert bc2.is_valid()

    def test_find_blocks(self, tmp_path):
        bc = self._new_chain(str(tmp_path))
        bc.add_block({"event": "LOGIN", "user": "alice"})
        bc.add_block({"event": "LOGIN", "user": "bob"})
        bc.add_block({"event": "LOGOUT", "user": "alice"})
        logins = bc.find_blocks("event", "LOGIN")
        assert len(logins) == 2

    def test_repeated_tamper_and_restore(self, tmp_path):
        bc = self._new_chain(str(tmp_path))
        bc.add_block({"event": "DOC_UPLOAD", "doc": "memo.pdf"})
        bc.add_block({"event": "DOC_SIGN", "doc": "memo.pdf"})
        assert bc.is_valid()

        # Tamper block 1 once
        assert bc.tamper_block(1)
        is_val, errs = bc.validate_chain_detailed()
        assert not is_val
        assert 1 in errs

        # Tamper block 1 again (should mutate with new payload and still be detected)
        assert bc.tamper_block(1)
        assert not bc.is_valid()

        # Tamper block 2 as well
        assert bc.tamper_block(2)
        is_val, errs = bc.validate_chain_detailed()
        assert not is_val
        assert 1 in errs and 2 in errs

        # Restore pristine state
        assert bc.restore_pristine()
        assert bc.is_valid()
        is_val, errs = bc.validate_chain_detailed()
        assert is_val
        assert len(errs) == 0

