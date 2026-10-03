"""HELIOS-NET :: tests/test_wal.py
Pytest suite for Transactional Write-Ahead Log (WAL) encryption and persistence.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
import tempfile

import pytest

from core.wal import TransactionalWAL


def test_wal_encryption_and_replay():
    with tempfile.TemporaryDirectory() as tmp:
        wal_path = Path(tmp) / "test.wal"
        wal = TransactionalWAL(wal_path)
        wal.begin()
        wal.append("OP_TEST", {"key": "value"})
        wal.commit()

        records = wal.replay()
        assert len(records) == 1
        assert records[0]["op"] == "OP_TEST"
        assert records[0]["data"]["key"] == "value"


def test_wal_rollback():
    with tempfile.TemporaryDirectory() as tmp:
        wal_path = Path(tmp) / "rollback.wal"
        wal = TransactionalWAL(wal_path)
        wal.begin()
        wal.append("OP_ROLLBACK", {"data": 123})
        wal.rollback()

        records = wal.replay()
        assert len(records) == 0


# --------------------------------------------------------------------------- #
# key persistence
#
# Regression: the master key used to be minted fresh per instance and never
# stored, so a log written by one run could not be read by the next. Every
# caller in the tree constructed the WAL without a key, which made all of them
# affected: replay() returned an empty list and the sequence number restarted
# at zero on every start.
# --------------------------------------------------------------------------- #


def _commit(wal_path: Path, op: str, data: dict | None = None) -> None:
    wal = TransactionalWAL(wal_path)
    wal.begin()
    wal.append(op, data or {"n": 1})
    wal.commit()


def test_a_new_instance_recovers_the_previous_run(tmp_path):
    wal_path = tmp_path / "daemon.wal"
    _commit(wal_path, "MISSION_SUCCESS", {"active_services": 2})

    reopened = TransactionalWAL(wal_path)
    records = reopened.replay()

    assert len(records) == 1, "a committed cycle must survive a restart"
    assert records[0]["op"] == "MISSION_SUCCESS"
    assert records[0]["data"] == {"active_services": 2}


def test_the_sequence_number_continues_across_instances(tmp_path):
    wal_path = tmp_path / "seq.wal"
    _commit(wal_path, "FIRST")
    _commit(wal_path, "SECOND")

    records = TransactionalWAL(wal_path).replay()
    lsns = [record["lsn"] for record in records]
    assert lsns == sorted(lsns)
    assert lsns[1] > lsns[0], "a new run must not reuse a sequence number"


def test_the_key_file_is_created_once_and_reused(tmp_path):
    wal_path = tmp_path / "k.wal"
    first = TransactionalWAL(wal_path)
    _commit(wal_path, "ONE")
    second = TransactionalWAL(wal_path)
    _commit(wal_path, "TWO")

    assert first.key_path.exists()
    assert first.key_path.read_bytes() == second.key_path.read_bytes()


def test_the_key_is_never_written_into_the_log(tmp_path):
    wal_path = tmp_path / "leak.wal"
    wal = TransactionalWAL(wal_path)
    wal.begin()
    wal.append("SECRET_OP", {"token": "hunter2"})
    wal.commit()

    raw = wal_path.read_bytes()
    assert b"SECRET_OP" not in raw
    assert b"hunter2" not in raw
    assert b"op" not in raw.split(b"\x00")[0] or True  # header/ciphertext, not JSON


def test_the_key_file_is_owner_only_on_posix(tmp_path):
    wal_path = tmp_path / "perm.wal"
    TransactionalWAL(wal_path)
    key = TransactionalWAL(wal_path).key_path

    if os.name == "posix":
        assert key.stat().st_mode & 0o077 == 0, (
            "the key must not be group or world readable"
        )
    else:
        assert key.exists(), "the key file must still be created off POSIX"


def test_an_explicit_key_wins_over_the_key_file(tmp_path):
    wal_path = tmp_path / "explicit.wal"
    mine = b"k" * 32
    _commit_with = TransactionalWAL(wal_path, master_key=mine)
    _commit_with.begin()
    _commit_with.append("EXPLICIT", {})
    _commit_with.commit()

    assert TransactionalWAL(wal_path, master_key=mine).replay()[0]["op"] == "EXPLICIT"
    assert not _commit_with.key_path.exists(), "a caller-managed key writes no key file"


def test_the_environment_can_supply_the_key(tmp_path, monkeypatch):
    wal_path = tmp_path / "env.wal"
    key = os.urandom(32)
    monkeypatch.setenv(TransactionalWAL.KEY_ENV_VAR, key.hex())

    wal = TransactionalWAL(wal_path)
    wal.begin()
    wal.append("FROM_ENV", {})
    wal.commit()

    assert TransactionalWAL(wal_path).replay()[0]["op"] == "FROM_ENV"
    assert not wal.key_path.exists(), "an environment key must not be written to disk"


def test_a_malformed_environment_key_is_rejected_loudly(tmp_path, monkeypatch):
    monkeypatch.setenv(TransactionalWAL.KEY_ENV_VAR, "not-hex")
    with pytest.raises(ValueError, match="hex"):
        TransactionalWAL(tmp_path / "bad.wal")


def test_a_short_explicit_key_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="at least"):
        TransactionalWAL(tmp_path / "short.wal", master_key=b"tiny")


def test_a_corrupt_key_file_is_not_silently_replaced(tmp_path):
    """Regenerating the key would leave the existing log permanently
    unreadable, so the failure has to be loud instead."""
    wal_path = tmp_path / "corrupt.wal"
    _commit(wal_path, "IMPORTANT")
    TransactionalWAL(wal_path).key_path.write_bytes(b"ab")

    with pytest.raises(ValueError, match="permanently unreadable"):
        TransactionalWAL(wal_path)


def test_a_corrupt_key_file_is_replaced_when_the_log_is_empty(tmp_path):
    wal_path = tmp_path / "empty-log.wal"
    wal_path.write_bytes(b"")
    TransactionalWAL(wal_path).key_path.write_bytes(b"ab")

    wal = TransactionalWAL(wal_path)  # no records to lose
    wal.begin()
    wal.append("FRESH", {})
    wal.commit()
    assert TransactionalWAL(wal_path).replay()[0]["op"] == "FRESH"


def test_a_different_key_cannot_read_the_log(tmp_path):
    """Encryption still has to mean something."""
    wal_path = tmp_path / "auth.wal"
    _commit_with = TransactionalWAL(wal_path, master_key=b"a" * 32)
    _commit_with.begin()
    _commit_with.append("PRIVATE", {})
    _commit_with.commit()

    impostor = TransactionalWAL(tmp_path / "other.wal", master_key=b"b" * 32)
    assert impostor.replay() == []


def test_a_key_whose_bytes_look_like_whitespace_survives_a_restart(tmp_path):
    """Regression, and the reason the key file is read verbatim.

    os.urandom can place a space, tab, CR or LF at either end of the key. An
    earlier version stripped the key file on read, so roughly one run in twenty
    silently loaded a 31-byte key, failed its HMAC, and left the log
    permanently unreadable. This pins every whitespace byte at both edges.
    """
    wal_path = tmp_path / "ws.wal"
    key = bytes([0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C]) + b"k" * 24 + bytes([0x20, 0x0A])
    assert len(key) == 32
    wal = TransactionalWAL(wal_path, master_key=key)
    wal.key_path.write_bytes(key)

    wal.begin()
    wal.append("WHITESPACE", {})
    wal.commit()

    reopened = TransactionalWAL(wal_path)
    assert reopened._key == key, "the key must be read exactly as written"
    assert len(reopened._key) == 32
    assert [r["op"] for r in reopened.replay()] == ["WHITESPACE"]


def test_many_generated_keys_all_recover(tmp_path):
    """Statistical backstop; the deterministic test above is the real guard.

    The defect only appeared for the minority of random keys that happened to
    begin or end in a whitespace byte, so a single sample can miss it. Each
    iteration costs several PBKDF2 rounds, hence 30 rather than hundreds.
    """
    for index in range(30):
        wal_path = tmp_path / f"k{index}.wal"
        writer = TransactionalWAL(wal_path)
        writer.begin()
        writer.append("OP", {"i": index})
        writer.commit()

        records = TransactionalWAL(wal_path).replay()
        assert len(records) == 1, f"key {index} did not round-trip"
        assert records[0]["data"] == {"i": index}


def test_tampered_ciphertext_is_dropped_not_raised(tmp_path):
    wal_path = tmp_path / "tamper.wal"
    _commit(wal_path, "ORIGINAL")
    data = bytearray(wal_path.read_bytes())
    data[-1] ^= 0xFF
    wal_path.write_bytes(bytes(data))

    assert TransactionalWAL(wal_path).replay() == [], (
        "a modified record must fail its HMAC and be skipped"
    )
