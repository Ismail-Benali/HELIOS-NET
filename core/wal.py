"""HELIOS-NET :: core/wal.py
Encrypted Transactional Write-Ahead Log (Secure Enterprise WAL).

Features:
  - At-rest encryption for WAL records using Python stdlib crypto primitives (HMAC-SHA256 & Stream Cipher).
  - Atomic transactions (BEGIN / COMMIT / ROLLBACK).
  - Automatic crash recovery and integrity verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import struct
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

#: Marks the v2 record layout so legacy records remain readable.
_MAGIC = b"HWL2"
_KEYSTREAM_LABEL = b"helios-wal-v2-keystream"

#: v3 keeps one salt per log file, so PBKDF2 runs once per process instead of
#: once per record. Each record still gets a fresh nonce.
_MAGIC_V3 = b"HWL3"
_V3_HEADER_LEN = 20
_KEYSTREAM_LABEL_V3 = b"helios-wal-v3-keystream"
_MAX_RECORD_BYTES = 64 * 1024 * 1024


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
        self._salt: bytes | None = None
        self._enc_key: bytes | None = None
        self._mac_key: bytes | None = None
        self._v3 = False
        self._legacy = False
        self._load_v3_header()
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
        raced = self.key_path.read_bytes()  # verbatim, never stripped
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
                self.key_path,
                mode,
                self.path,
            )

    def _derive_keys(self, salt: bytes) -> tuple[bytes, bytes]:
        """Splits one PBKDF2 stretch into independent encryption and MAC keys."""
        material = hashlib.pbkdf2_hmac("sha256", self._key, salt, 100000, 64)
        return material[:32], material[32:]

    def _install_salt(self, salt: bytes) -> None:
        self._salt = salt
        self._enc_key, self._mac_key = self._derive_keys(salt)

    def _load_v3_header(self) -> None:
        """Reads the per-file salt from an existing v3 log.

        Doing this once at construction means every record in the file shares a
        single key derivation instead of paying PBKDF2 per record.
        """
        if not self.path.exists() or self.path.stat().st_size < _V3_HEADER_LEN:
            return
        with self.path.open("rb") as handle:
            header = handle.read(_V3_HEADER_LEN)
        if len(header) == _V3_HEADER_LEN and header[:4] == _MAGIC_V3:
            self._install_salt(header[4:])
            self._v3 = True
        else:
            self._legacy = True

    def _start_v3(self) -> None:
        """Creates the v3 header and derives the log's keys exactly once."""
        salt = os.urandom(16)
        self._install_salt(salt)
        self._v3 = True
        with self.path.open("ab") as handle:
            handle.write(_MAGIC_V3 + salt)
            handle.flush()
            os.fsync(handle.fileno())

    def _generate_v3_keystream(self, nonce: bytes, length: int) -> bytes:
        if self._enc_key is None:
            raise RuntimeError("WAL keys are not initialized")
        keystream = bytearray()
        counter = 0
        while len(keystream) < length:
            block = hmac.new(
                self._enc_key,
                _KEYSTREAM_LABEL_V3 + nonce + struct.pack("!Q", counter),
                hashlib.sha256,
            ).digest()
            keystream.extend(block)
            counter += 1
        return bytes(keystream[:length])

    def _generate_keystream(self, enc_key: bytes, salt: bytes, length: int) -> bytes:
        """Expands an HMAC-SHA256 counter-mode keystream.

        The previous construction hashed ``key || salt || counter``, which is a
        plain hash of a known prefix and therefore a weaker PRF than HMAC; it
        also reused one derived key for both encryption and authentication.
        """
        keystream = bytearray()
        counter = 0
        while len(keystream) < length:
            block = hmac.new(
                enc_key,
                _KEYSTREAM_LABEL + salt + struct.pack("!Q", counter),
                hashlib.sha256,
            ).digest()
            keystream.extend(block)
            counter += 1
        return bytes(keystream[:length])

    def _encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts one record under the log's single derived key.

        Layout: ``nonce(16) | mac(32) | ciphertext``. The file header holds the
        salt, so the derived keys are reused; the nonce makes every record's
        keystream unique. A log created by an older version keeps the v2 record
        layout so its records stay readable in place.
        """
        if self._legacy:
            return self._encrypt_v2(plaintext)
        if not self._v3:
            if self.path.exists() and self.path.stat().st_size:
                # A short or corrupt pre-v3 file must not receive a header in
                # the middle of its record stream; keep appending v2 records.
                self._legacy = True
                return self._encrypt_v2(plaintext)
            self._start_v3()
        if self._mac_key is None:
            raise RuntimeError("WAL keys are not initialized")
        nonce = os.urandom(16)
        stream = self._generate_v3_keystream(nonce, len(plaintext))
        ciphertext = bytes(b ^ stream[i] for i, b in enumerate(plaintext))
        sig = hmac.new(
            self._mac_key, _MAGIC_V3 + nonce + ciphertext, hashlib.sha256
        ).digest()
        return nonce + sig + ciphertext

    def _encrypt_v2(self, plaintext: bytes) -> bytes:
        """Legacy record layout, kept only for appending to an old log."""
        salt = os.urandom(16)
        enc_key, mac_key = self._derive_keys(salt)
        stream = self._generate_keystream(enc_key, salt, len(plaintext))
        ciphertext = bytes(b ^ stream[i] for i, b in enumerate(plaintext))
        sig = hmac.new(mac_key, _MAGIC + salt + ciphertext, hashlib.sha256).digest()
        return _MAGIC + sig + salt + ciphertext

    def _decrypt(self, raw_data: bytes) -> bytes | None:
        """Verifies and decrypts a legacy (v1/v2) record."""
        if raw_data.startswith(_MAGIC):
            return self._decrypt_v2(raw_data)
        return self._decrypt_legacy(raw_data)

    def _decrypt_v3(self, raw_data: bytes) -> bytes | None:
        if self._mac_key is None or self._enc_key is None or len(raw_data) < 48:
            return None
        nonce = raw_data[:16]
        sig = raw_data[16:48]
        ciphertext = raw_data[48:]
        expected_sig = hmac.new(
            self._mac_key, _MAGIC_V3 + nonce + ciphertext, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        stream = self._generate_v3_keystream(nonce, len(ciphertext))
        return bytes(b ^ stream[i] for i, b in enumerate(ciphertext))

    def _decrypt_v2(self, raw_data: bytes) -> bytes | None:
        body = raw_data[len(_MAGIC) :]
        if len(body) < 48:
            return None
        sig = body[:32]
        salt = body[32:48]
        ciphertext = body[48:]

        enc_key, mac_key = self._derive_keys(salt)
        expected_sig = hmac.new(
            mac_key, _MAGIC + salt + ciphertext, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(sig, expected_sig):
            return None

        stream = self._generate_keystream(enc_key, salt, len(ciphertext))
        return bytes(b ^ stream[i] for i, b in enumerate(ciphertext))

    def _decrypt_legacy(self, raw_data: bytes) -> bytes | None:
        """Reads records written before the v2 PRF change.

        Removing this would make existing journals unreadable, so the old
        single-key construction is kept for verification only.
        """
        if len(raw_data) < 48:
            return None
        sig = raw_data[:32]
        salt = raw_data[32:48]
        ciphertext = raw_data[48:]

        derived_key = hashlib.pbkdf2_hmac("sha256", self._key, salt, 100000, 32)
        expected_sig = hmac.new(derived_key, salt + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected_sig):
            return None

        keystream = bytearray()
        counter = 0
        while len(keystream) < len(ciphertext):
            keystream.extend(
                hashlib.sha256(derived_key + salt + struct.pack("!I", counter)).digest()
            )
            counter += 1
        stream = bytes(keystream[: len(ciphertext)])
        return bytes(b ^ stream[i] for i, b in enumerate(ciphertext))

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
        with self._lock, self.path.open("rb") as fh:
            head = fh.read(_V3_HEADER_LEN)
            v3 = len(head) == _V3_HEADER_LEN and head[:4] == _MAGIC_V3
            if v3:
                salt = head[4:]
                if self._salt != salt:
                    self._install_salt(salt)
                self._v3 = True
            else:
                fh.seek(0)

            while True:
                header = fh.read(4)
                if len(header) < 4:
                    break
                length = struct.unpack("!I", header)[0]
                if length == 0 or length > _MAX_RECORD_BYTES:
                    break
                encrypted_payload = fh.read(length)
                if len(encrypted_payload) < length:
                    break

                plain = (
                    self._decrypt_v3(encrypted_payload)
                    if v3
                    else self._decrypt(encrypted_payload)
                )
                if plain:
                    try:
                        record = json.loads(plain.decode("utf-8"))
                        valid_records.append(record)
                    except json.JSONDecodeError:
                        continue
        return valid_records
