# securegov/crypto/classic_ciphers.py
"""
Classic Cipher Implementations
================================
Provides two classic cipher classes used as the first layer of super-encryption:

  * ``VigenereCipher``  – polyalphabetic substitution cipher.
  * ``PlayfairCipher``  – digraph substitution cipher on a 5×5 key-square.

Both classes expose a uniform ``encrypt(plaintext) -> str`` and
``decrypt(ciphertext) -> str`` interface so they can be swapped in the
super-encryption pipeline.

Usage
-----
    from securegov.crypto.classic_ciphers import VigenereCipher, PlayfairCipher

    vc = VigenereCipher(key="SECRETKEY")
    ct = vc.encrypt("HELLO WORLD")
    pt = vc.decrypt(ct)

    pf = PlayfairCipher(key="MONARCHY")
    ct = pf.encrypt("HIDE THE GOLD")
    pt = pf.decrypt(ct)
"""

import re
from securegov.utils.logger import get_logger

logger = get_logger(__name__)

# ===========================================================================
# Vigenère Cipher
# ===========================================================================

class VigenereCipher:
    """
    Vigenère polyalphabetic cipher (A-Z only; digits and symbols are
    preserved unchanged by default; set ``strip_non_alpha=True`` to remove
    them before encryption).

    Parameters
    ----------
    key : str
        The keyword (letters only).  Case-insensitive.
    strip_non_alpha : bool
        If ``True``, non-alphabetic characters are stripped before processing.
        If ``False`` (default), they are passed through unchanged.
    """

    def __init__(self, key: str, strip_non_alpha: bool = False) -> None:
        self._key = self._sanitise_key(key)
        self.strip_non_alpha = strip_non_alpha
        if not self._key:
            raise ValueError("VigenereCipher key must contain at least one letter.")
        logger.debug("VigenereCipher initialised with key of length %d.", len(self._key))

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _sanitise_key(key: str) -> str:
        return re.sub(r"[^A-Za-z]", "", key).upper()

    def _process(self, text: str, mode: str) -> str:
        """Core Vigenère operation shared by encrypt and decrypt."""
        if self.strip_non_alpha:
            text = re.sub(r"[^A-Za-z]", "", text)

        result: list[str] = []
        key_len = len(self._key)
        key_idx = 0

        for ch in text:
            if ch.isalpha():
                offset = ord("A") if ch.isupper() else ord("a")
                k = ord(self._key[key_idx % key_len]) - ord("A")
                if mode == "encrypt":
                    shifted = (ord(ch) - offset + k) % 26
                else:
                    shifted = (ord(ch) - offset - k) % 26
                result.append(chr(offset + shifted))
                key_idx += 1
            else:
                result.append(ch)   # pass non-alpha through

        return "".join(result)

    # --- public API --------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """Return the Vigenère ciphertext for *plaintext*."""
        ct = self._process(plaintext, "encrypt")
        logger.debug("Vigenère encrypt: %d chars → %d chars.", len(plaintext), len(ct))
        return ct

    def decrypt(self, ciphertext: str) -> str:
        """Return the Vigenère plaintext for *ciphertext*."""
        pt = self._process(ciphertext, "decrypt")
        logger.debug("Vigenère decrypt: %d chars.", len(pt))
        return pt


# ===========================================================================
# Playfair Cipher
# ===========================================================================

class PlayfairCipher:
    """
    Playfair cipher on a 5×5 key-square (I and J are merged).

    Rules implemented
    -----------------
    * Non-alpha characters are stripped before encryption.
    * Repeated letters in a digraph are separated by 'X'.
    * If the final plaintext has an odd length, 'Z' is appended.
    * Decryption reverses all padding; trailing 'X' and 'Z' may remain
      (standard Playfair behaviour).

    Parameters
    ----------
    key : str
        The keyword used to build the 5×5 key-square.
    """

    _ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"   # 25 letters (I=J merged)

    def __init__(self, key: str) -> None:
        self._key   = re.sub(r"[^A-Za-z]", "", key).upper().replace("J", "I")
        self._square, self._pos = self._build_square()
        logger.debug("PlayfairCipher square built from key '%s'.", self._key[:8] + "…")

    # --- key-square construction -------------------------------------------

    def _build_square(self) -> tuple[list[list[str]], dict[str, tuple[int, int]]]:
        seen: set[str] = set()
        order: list[str] = []
        for ch in self._key + self._ALPHABET:
            ch = ch.replace("J", "I")
            if ch not in seen:
                seen.add(ch)
                order.append(ch)

        square = [order[i * 5:(i + 1) * 5] for i in range(5)]
        pos    = {ch: (r, c) for r, row in enumerate(square) for c, ch in enumerate(row)}
        return square, pos

    # --- text pre-processing -----------------------------------------------

    def _prepare(self, text: str) -> list[str]:
        """Clean, merge I/J, split into digraphs with padding."""
        clean = re.sub(r"[^A-Za-z]", "", text).upper().replace("J", "I")
        pairs: list[str] = []
        i = 0
        while i < len(clean):
            a = clean[i]
            if i + 1 < len(clean):
                b = clean[i + 1]
                if a == b:
                    pairs.append(a + "X")
                    i += 1
                else:
                    pairs.append(a + b)
                    i += 2
            else:
                pairs.append(a + "Z")
                i += 1
        return pairs

    # --- Playfair rules ----------------------------------------------------

    def _encode_pair(self, a: str, b: str, shift: int) -> str:
        ra, ca = self._pos[a]
        rb, cb = self._pos[b]

        if ra == rb:                            # same row → shift columns
            return (self._square[ra][(ca + shift) % 5] +
                    self._square[rb][(cb + shift) % 5])
        if ca == cb:                            # same column → shift rows
            return (self._square[(ra + shift) % 5][ca] +
                    self._square[(rb + shift) % 5][cb])
        # rectangle → swap columns
        return self._square[ra][cb] + self._square[rb][ca]

    # --- public API --------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        pairs = self._prepare(plaintext)
        ct = "".join(self._encode_pair(pair[0], pair[1], +1) for pair in pairs)
        logger.debug("Playfair encrypt: %d digraphs.", len(pairs))
        return ct

    def decrypt(self, ciphertext: str) -> str:
        # Ciphertext should already be clean uppercase pairs
        clean = re.sub(r"[^A-Za-z]", "", ciphertext).upper()
        pairs = [clean[i:i + 2] for i in range(0, len(clean), 2)]
        pt = "".join(
            self._encode_pair(pair[0], pair[1], -1)
            for pair in pairs
            if len(pair) == 2
        )
        logger.debug("Playfair decrypt: %d digraphs.", len(pairs))
        return pt
