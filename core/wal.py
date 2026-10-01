"""HELIOS-NET :: core/wal.py
Encrypted Transactional Write-Ahead Log (Secure Enterprise WAL).

Features:
  - At-rest encryption for WAL records using Python stdlib crypto primitives (HMAC-SHA256 & Stream Cipher).
  - Atomic transactions (BEGIN / COMMIT / ROLLBACK).
  - Automatic crash recovery and integrity verification.
"""

from __future__ import annotations

from typing import Any

import hashlib
import hmac
import json
import os
import struct
import threading
import logging
from pathlib import Path

log = logging.getLogger(__name__)


class TransactionalWAL:
    """Secure encrypted transactional WAL.

    Key handling: the master key is never hardcoded. It is resolved in this
    order: an explicit `master_key` argument, then the `HELIOS_WAL_MASTER_KEY`
    environment variable (hex), then a key file kept beside the log.

    The key file is what makes the log recoverable. An earlier version minted a
    fresh random key per instance and never stored it, so every record was
    encrypted under a key that died with the process: `replay()` on a later run
    failed its HMAC check and returned an empty list, and the log sequence
    number restarted at zero. The log was write-only in practice.

    Threat model, stated plainly: storing the key beside the log means at-rest
    protection now rests on filesystem permissions (the key file is created
    0600 and a warning is logged if it is group- or world-accessible). Operators
    who cannot accept that should supply the key through the environment
    variable and keep it out of the state directory.
    """

    KEY_ENV_VAR = "HELIOS_WAL_MASTER_KEY"
    MIN_KEY_BYTES = 16

    def __init__(self, wal_path: str | Path, master_key: bytes | None = None):
        self.path = Path(wal_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = self._resolve_key(master_key)
        self._lsn = 0
        self._active_txn = False
        self._txn_buffer: list[bytes] = []
        self._lock = threading.Lock()
        self._init_lsn()

    @property
    def key_path(self) -> Path:
        """The key file that pairs with this log."""
        return self.path.with_name(self.path.name + ".key")

    def _resolve_key(self, master_key: bytes | None) -> bytes:
        if master_key is not None:
            if len(master_key) < self.MIN_KEY_BYTES:
                raise ValueError(
                    f"master_key must be at least {self.MIN_KEY_BYTES} bytes, "
                    f"got {len(master_key)}"
                )
            return master_key

        from_env = os.environ.get(self.KEY_ENV_VAR)
        if from_env:
            try:
                return bytes.fromhex(from_env.strip())
            except ValueError:
                raise ValueError(
                    f"{self.KEY_ENV_VAR} must be hex-encoded bytes"
                ) from None

        return self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        if not self.key_path.exists():
            fresh = os.urandom(32)
            try:
                self._write_key(fresh, exclusive=True)
            except FileExistsError:
                return self._adopt_concurrent_key()
            self._restrict_key_file()
            return fresh

        # Read verbatim. A binary key is never stripped: os.urandom can put a
        # byte that bytes.strip() considers whitespace (space, tab, CR, LF) at
        # either end, and stripping it would silently shorten the key, so the
        # next run would fail its HMAC and the log would become unreadable.
        existing = self.key_path.read_bytes()
        if len(existing) >= self.MIN_KEY_BYTES:
            self._restrict_key_file()
            return existing
        if self.path.exists() and self.path.stat().st_size > 0:
            raise ValueError(
                f"key file {self.key_path} is unusable but {self.path} already "
                "holds records. Refusing to mint a new key, which would leave "
                "the existing log permanently unreadable. Restore the key file "
                f"or point {self.KEY_ENV_VAR} at the original key."
            )
        # An unusable key with an empty log: nothing can be lost, so the key
        # file is replaced rather than left to fail every subsequent start.
        replacement = os.urandom(32)
        self._write_key(replacement, exclusive=False)
        self._restrict_key_file()
        return replacement

    def _write_key(self, key: bytes, exclusive: bool) -> None:
        mode = "xb" if exclusive else "wb"
        with self.key_path.open(mode) as handle:
            handle.write(key)

    def _adopt_concurrent_key(self) -> bytes:
        raced = self.key_path.read_bytes()      # verbatim, never stripped
        if len(raced) < self.MIN_KEY_BYTES:
            raise ValueError(
                f"key file {self.key_path} was created concurrently but is "
                "unusable; refusing to overwrite a key another process may "
                "already be writing with"
            )
        self._restrict_key_file()
        return raced

    def _restrict_key_file(self) -> None:
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            return
        if os.name != "posix":
            return
        mode = self.key_path.stat().st_mode & 0o077
        if mode:
            log.warning(
                "key file %s is readable by group/other (mode %o); at-rest "
                "protection of %s depends on that being tightened",
                self.key_path, mode, self.path,
            )

    def _generate_keystream(self, derived_key: bytes, salt: bytes, length: int) -> bytes:
        """Generates a cryptographic keystream of arbitrary length using counter-mode SHA-256 (no repeating keystream vulnerability)."""
        keystream = bytearray()
        counter = 0
        while len(keystream) < length:
            block = hashlib.sha256(derived_key + salt + struct.pack("!I", counter)).digest()
            keystream.extend(block)
            counter += 1
        return bytes(keystream[:length])

    def _encrypt(self, plaintext: bytes) -> bytes:
        """Authenticated encryption using HMAC-SHA256, PBKDF2 (100,000 iterations), and counter-mode stream cipher."""
        salt = os.urandom(16)
        derived_key = hashlib.pbkdf2_hmac("sha256", self._key, salt, 100000, 32)
        
        # Cryptographic stream cipher with full-length keystream expansion
        stream = self._generate_keystream(derived_key, salt, len(plaintext))
        ciphertext = bytearray(b ^ stream[i] for i, b in enumerate(plaintext))
        
        # Calculate HMAC signature for integrity
        sig = hmac.new(derived_key, salt + bytes(ciphertext), hashlib.sha256).digest()
        
        return sig + salt + bytes(ciphertext)

    def _decrypt(self, raw_data: bytes) -> bytes | None:
        """Verifies HMAC and decrypts record securely."""
        if len(raw_data) < 48:
            return None
        sig = raw_data[:32]
        salt = raw_data[32:48]
        ciphertext = raw_data[48:]

        derived_key = hashlib.pbkdf2_hmac("sha256", self._key, salt, 100000, 32)
        expected_sig = hmac.new(derived_key, salt + ciphertext, hashlib.sha256).digest()
        
        if not hmac.compare_digest(sig, expected_sig):
            return None  # Tampered or corrupted data

        stream = self._generate_keystream(derived_key, salt, len(ciphertext))
        plaintext = bytes(b ^ stream[i] for i, b in enumerate(ciphertext))
        return plaintext

    def _init_lsn(self) -> None:
        if self.path.exists():
            records = self.replay()
            if records:
                self._lsn = max(r.get("lsn", 0) for r in records)

    def begin(self) -> None:
        with self._lock:
            self._active_txn = True
            self._txn_buffer = []

    def append(self, op: str, data: dict[str, Any]) -> int:
        with self._lock:
            self._lsn += 1
            payload = {"lsn": self._lsn, "op": op, "data": data}
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            encrypted_payload = self._encrypt(raw)
            
            header = struct.pack("!I", len(encrypted_payload))
            
            if self._active_txn:
                self._txn_buffer.append(header + encrypted_payload)
            else:
                self._write_disk([header + encrypted_payload])
            return self._lsn

    def commit(self) -> None:
        with self._lock:
            if not self._active_txn:
                return
            self._write_disk(self._txn_buffer)
            self._active_txn = False
            self._txn_buffer = []

    def rollback(self) -> None:
        with self._lock:
            self._active_txn = False
            self._txn_buffer = []

    def _write_disk(self, items: list[bytes]) -> None:
        with self.path.open("ab") as fh:
            for item in items:
                fh.write(item)
            fh.flush()
            os.fsync(fh.fileno())

    def replay(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []

        valid_records = []
        with self._lock:
            with self.path.open("rb") as fh:
                while True:
                    header = fh.read(4)
                    if len(header) < 4:
                        break
                    length = struct.unpack("!I", header)[0]
                    encrypted_payload = fh.read(length)
                    if len(encrypted_payload) < length:
                        break
                    
                    plain = self._decrypt(encrypted_payload)
                    if plain:
                        try:
                            record = json.loads(plain.decode("utf-8"))
                            valid_records.append(record)
                        except json.JSONDecodeError:
                            continue
        return valid_records
