# securegov/blockchain/chain.py
"""
Simple Blockchain for Audit Trail & Document Integrity
=======================================================
Implements a lightweight, in-process blockchain to create an **immutable
audit ledger** for SecureGov.  Every important event (document upload,
message sent, login attempt, key rotation, etc.) is appended as a block.
Once a block is added, any retrospective modification of its data breaks
every subsequent block's hash, making tampering immediately detectable.

Structure
---------
  Block
  -----
  index          : int         — position in the chain (0 = genesis)
  timestamp      : float       — UTC Unix time of creation
  data           : dict        — arbitrary payload (event details)
  previous_hash  : str         — SHA-256 hex of the preceding block
  nonce          : int         — Proof-of-Work nonce (optional; default 0)
  hash           : str         — SHA-256 hex of this block's content

  Blockchain
  ----------
  chain          : list[Block] — ordered list of all blocks

The chain is persisted as a JSON file so it survives process restarts.
On load, full integrity is verified before use.

Usage
-----
    from securegov.blockchain.chain import Blockchain

    bc = Blockchain(storage_path="data/audit_chain.json")

    bc.add_block({
        "event":   "DOCUMENT_UPLOADED",
        "user_id": 42,
        "doc_id":  7,
        "sha256":  "abc123…",
    })

    bc.add_block({
        "event":   "LOGIN_SUCCESS",
        "user_id": 42,
        "ip":      "192.168.1.10",
    })

    print(bc.is_valid())   # True
    bc.print_chain()
"""

import copy
import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from securegov.utils.logger import get_logger

logger = get_logger(__name__)


# ===========================================================================
# Block
# ===========================================================================

@dataclass
class Block:
    """A single block in the SecureGov audit blockchain."""

    index         : int
    timestamp     : float
    data          : dict[str, Any]
    previous_hash : str
    nonce         : int  = 0
    hash          : str  = field(default="", init=False)

    def __post_init__(self) -> None:
        self.hash = self.compute_hash()

    # --- hashing -----------------------------------------------------------

    def compute_hash(self) -> str:
        """
        Compute the SHA-256 hash of this block's canonical representation.

        The canonical string is a deterministic JSON dump of:
            index | timestamp | data | previous_hash | nonce
        (the ``hash`` field itself is excluded to avoid circularity).
        """
        block_dict = {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "data":          self.data,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
        }
        # sort_keys=True ensures deterministic serialisation
        raw = json.dumps(block_dict, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # --- Proof-of-Work (optional) -----------------------------------------

    def mine(self, difficulty: int) -> None:
        """
        Find a nonce such that the block hash starts with *difficulty* zeros.
        Increases tamper-resistance; skip (difficulty=0) for fast audit logs.
        """
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash   = self.compute_hash()
        logger.debug(
            "Block %d mined (nonce=%d, difficulty=%d): %s…",
            self.index, self.nonce, difficulty, self.hash[:12]
        )

    # --- serialisation -----------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "data":          self.data,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
            "hash":          self.hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        blk = cls(
            index         = d["index"],
            timestamp     = d["timestamp"],
            data          = d["data"],
            previous_hash = d["previous_hash"],
            nonce         = d.get("nonce", 0),
        )
        blk.hash = d["hash"]
        return blk

    def __repr__(self) -> str:
        return (
            f"Block(index={self.index}, ts={self.timestamp:.2f}, "
            f"hash={self.hash[:12]}…, prev={self.previous_hash[:12]}…)"
        )


# ===========================================================================
# Blockchain
# ===========================================================================

class Blockchain:
    """
    An append-only blockchain for SecureGov audit trails.

    Parameters
    ----------
    storage_path : str
        Path to the JSON persistence file.  Loaded on init if it exists;
        created on first :meth:`add_block` call.
    difficulty : int
        Number of leading zeros required for Proof-of-Work.
        Set to ``0`` (default) to skip PoW (fastest for audit logs).
    """

    _GENESIS_PREV_HASH = "0" * 64

    def __init__(
        self,
        storage_path: str = os.path.join("data", "audit_chain.json"),
        difficulty: int = 0,
    ) -> None:
        self._storage    = storage_path
        self._difficulty = difficulty
        self.chain: list[Block] = []
        self.is_tampered = False
        self._pristine_backup: list[dict] = []

        if os.path.isfile(storage_path):
            self._load()
            if not self.is_valid():
                self.is_tampered = True
                logger.error(
                    "BLOCKCHAIN INTEGRITY WARNING: The loaded audit chain has integrity violations or tampering!"
                )
            else:
                logger.info(
                    "Blockchain loaded from '%s' (%d blocks, valid).",
                    storage_path, len(self.chain)
                )
        else:
            self._create_genesis()
            logger.info("New blockchain created at '%s'.", storage_path)

    # --- genesis -----------------------------------------------------------

    def _create_genesis(self) -> None:
        genesis = Block(
            index         = 0,
            timestamp     = time.time(),
            data          = {"event": "GENESIS", "system": "SecureGov DocVault"},
            previous_hash = self._GENESIS_PREV_HASH,
        )
        if self._difficulty:
            genesis.mine(self._difficulty)
        self.chain.append(genesis)
        self._pristine_backup = [copy.deepcopy(b.to_dict()) for b in self.chain]
        self._save()

    # --- public API --------------------------------------------------------

    @property
    def latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, data: dict[str, Any]) -> Block:
        """
        Append a new block containing *data* and persist the chain.

        Parameters
        ----------
        data : dict
            Arbitrary JSON-serialisable event payload.

        Returns
        -------
        Block  The newly created block.
        """
        new_block = Block(
            index         = len(self.chain),
            timestamp     = time.time(),
            data          = data,
            previous_hash = self.latest_block.hash,
        )
        if self._difficulty:
            new_block.mine(self._difficulty)
        self.chain.append(new_block)
        self._pristine_backup = [copy.deepcopy(b.to_dict()) for b in self.chain]
        self._save()
        logger.info(
            "Block %d added → hash=%s…",
            new_block.index, new_block.hash[:16]
        )
        return new_block

    def is_valid(self) -> bool:
        """
        Verify the full chain integrity:
          1. Each block's stored ``hash`` matches its recomputed hash.
          2. Each block's ``previous_hash`` matches the hash of the prior block.

        Returns
        -------
        bool  ``True`` if the chain is intact, ``False`` if tampered.
        """
        if not self.chain:
            return True

        # Also verify genesis block's own hash
        if self.chain[0].hash != self.chain[0].compute_hash():
            logger.error("Chain broken at genesis block 0: stored hash ≠ computed hash.")
            return False

        for i in range(1, len(self.chain)):
            current  = self.chain[i]
            previous = self.chain[i - 1]

            # Recompute and compare
            if current.hash != current.compute_hash():
                logger.error(
                    "Chain broken at block %d: stored hash ≠ computed hash.", i
                )
                return False

            if current.previous_hash != previous.hash:
                logger.error(
                    "Chain broken at block %d: previous_hash mismatch.", i
                )
                return False

        return True

    def get_block(self, index: int) -> Optional[Block]:
        """Return the block at *index*, or ``None`` if out of range."""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None

    def find_blocks(self, key: str, value: Any) -> list[Block]:
        """Return all blocks whose ``data[key] == value``."""
        return [b for b in self.chain if b.data.get(key) == value]

    def print_chain(self) -> None:
        """Pretty-print the entire chain to stdout."""
        print(f"\n{'='*70}")
        print(f"  SecureGov Audit Blockchain  ({len(self.chain)} blocks)")
        print(f"{'='*70}")
        for blk in self.chain:
            print(f"\n  Block #{blk.index}")
            print(f"    Timestamp     : {blk.timestamp}")
            print(f"    Data          : {json.dumps(blk.data, indent=6)}")
            print(f"    Previous Hash : {blk.previous_hash}")
            print(f"    Hash          : {blk.hash}")
            print(f"    Nonce         : {blk.nonce}")
        print(f"{'='*70}\n")
        print(f"  Chain valid: {self.is_valid()}")
        print(f"{'='*70}\n")

    def repair_chain(self) -> None:
        """
        Recalculate previous_hash and current hash for all blocks starting from block 1.
        Restores chain consistency after intentional tampering or test demonstrations.
        """
        for i in range(1, len(self.chain)):
            self.chain[i].previous_hash = self.chain[i - 1].hash
            self.chain[i].hash = self.chain[i].compute_hash()
        self._save()
        self._pristine_backup = [copy.deepcopy(b.to_dict()) for b in self.chain]
        self.is_tampered = False
        logger.info("Blockchain repaired and re-hashed successfully (%d blocks).", len(self.chain))

    def reset_to_genesis(self) -> None:
        """Clear all blocks and start with a fresh genesis block."""
        self.chain = []
        self._create_genesis()
        self.is_tampered = False
        logger.info("Blockchain reset to initial genesis block.")

    def validate_chain_detailed(self) -> tuple[bool, dict[int, str]]:
        """
        Validate the full chain and return detailed verification results.

        Returns
        -------
        tuple[bool, dict[int, str]]
            (is_valid, errors_dict)
            errors_dict maps block_index -> "HASH_MISMATCH" | "PREV_HASH_MISMATCH"
        """
        errors: dict[int, str] = {}
        if not self.chain:
            return True, errors

        # Genesis block validation
        if self.chain[0].hash != self.chain[0].compute_hash():
            errors[0] = "HASH_MISMATCH"

        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.compute_hash():
                errors[i] = "HASH_MISMATCH"
            elif current.previous_hash != previous.hash:
                errors[i] = "PREV_HASH_MISMATCH"

        return len(errors) == 0, errors

    def tamper_block(self, index: int, custom_data: Optional[dict[str, Any]] = None) -> bool:
        """
        Mutate a specific block's data in memory to demonstrate cryptographic tamper detection.
        Guarantees that every call introduces a new mutation (dynamic timestamp and nonce).
        Does NOT save to disk, allowing repeatable undo/redo.

        Parameters
        ----------
        index : int
            The block index to tamper.
        custom_data : dict, optional
            Custom dictionary data to merge. If None, auto-generates attack payload.

        Returns
        -------
        bool : True if block was found and mutated, False otherwise.
        """
        if index < 0 or index >= len(self.chain):
            logger.warning("tamper_block: invalid index %d", index)
            return False

        if not self._pristine_backup:
            self._pristine_backup = [copy.deepcopy(b.to_dict()) for b in self.chain]

        target = self.chain[index]
        t_now = time.time()
        mutation_id = f"ATTACK_{int(t_now * 1000) % 100000}"

        if custom_data:
            target.data.update(custom_data)
        else:
            target.data["TAMPERED_BY"] = mutation_id
            target.data["_tamper_time"] = t_now
            if "user" in target.data:
                target.data["user"] = f"HACKER_{target.data['user']}"

        self.is_tampered = True
        logger.warning(
            "Tamper mutation '%s' injected into Block #%d in memory (stored=%s, computed=%s)",
            mutation_id, index, target.hash[:12], target.compute_hash()[:12]
        )
        return True

    def restore_pristine(self) -> bool:
        """
        Revert in-memory chain back to untampered clean state from backup or disk.
        Always falls back to the saved JSON file as the ground-truth source.
        """
        # Always reload from the saved file on disk — it is never written during
        # a tamper simulation (tamper_block does NOT call _save), so the file
        # always holds the last known-good state.
        if os.path.isfile(self._storage):
            self._load()
        elif self._pristine_backup:
            self.chain = [Block.from_dict(d) for d in self._pristine_backup]

        # Refresh backup to match the just-restored clean state
        self._pristine_backup = [copy.deepcopy(b.to_dict()) for b in self.chain]
        self.is_tampered = not self.is_valid()
        logger.info("Chain restored to pristine state (%d blocks).", len(self.chain))
        return True

    # --- persistence -------------------------------------------------------

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._storage) or ".", exist_ok=True)
        with open(self._storage, "w", encoding="utf-8") as f:
            json.dump(
                [blk.to_dict() for blk in self.chain],
                f,
                indent=2,
                ensure_ascii=False,
            )

    def _load(self) -> None:
        with open(self._storage, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self.chain = [Block.from_dict(d) for d in raw]
        self._pristine_backup = [copy.deepcopy(b.to_dict()) for b in self.chain]

