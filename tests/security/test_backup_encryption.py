"""Encrypted backups decrypt only with their own key and fail on any change, reordering or truncation."""

import io
import os
import struct

import pytest

from socify.backup_crypto import (
    HEADER_SIZE,
    NONCE_SIZE,
    BackupDecryptionError,
    decrypt_file,
    decrypt_stream,
    encrypt_file,
    encrypt_stream,
)

KEY = "k" * 40
OTHER_KEY = "o" * 40
SMALL = 1024


def _sealed(plain: bytes, chunk_size: int = SMALL, key: str = KEY) -> bytes:
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(plain), out, key, chunk_size)
    return out.getvalue()


def _open(sealed: bytes, chunk_size: int = SMALL, key: str = KEY) -> bytes:
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(sealed), out, key, chunk_size)
    return out.getvalue()


def _frames(sealed: bytes) -> tuple[bytes, list[bytes]]:
    header, rest, frames = sealed[:HEADER_SIZE], sealed[HEADER_SIZE:], []
    while rest:
        length = struct.unpack(">I", rest[NONCE_SIZE : NONCE_SIZE + 4])[0]
        frames.append(rest[: NONCE_SIZE + 4 + length])
        rest = rest[NONCE_SIZE + 4 + length :]
    return header, frames


@pytest.mark.parametrize("size", [0, 1, SMALL - 1, SMALL, SMALL + 1, 5 * SMALL + 17])
def test_round_trip_for_every_chunk_boundary(size):
    plain = os.urandom(size)
    sealed = _sealed(plain)
    assert sealed.startswith(b"SOCIFYBK1")
    if size >= 32:
        assert plain[:32] not in sealed
    assert _open(sealed) == plain


def test_each_backup_uses_a_fresh_salt_and_nonces():
    plain = b"same content" * 200
    assert _sealed(plain) != _sealed(plain)


def test_a_different_key_is_refused_before_any_output():
    with pytest.raises(BackupDecryptionError, match="different SOCIFY_BACKUP_KEY"):
        _open(_sealed(b"secret evidence"), key=OTHER_KEY)


def test_a_changed_byte_fails():
    sealed = bytearray(_sealed(os.urandom(3 * SMALL)))
    sealed[HEADER_SIZE + NONCE_SIZE + 4 + 10] ^= 1
    with pytest.raises(BackupDecryptionError):
        _open(bytes(sealed))


def test_a_changed_header_fails():
    sealed = bytearray(_sealed(os.urandom(SMALL)))
    sealed[HEADER_SIZE - 1] ^= 1
    with pytest.raises(BackupDecryptionError):
        _open(bytes(sealed))


def test_reordered_frames_fail():
    header, frames = _frames(_sealed(os.urandom(3 * SMALL + 5)))
    assert len(frames) == 4
    with pytest.raises(BackupDecryptionError):
        _open(header + frames[1] + frames[0] + frames[2] + frames[3])


def test_a_dropped_final_frame_and_a_cut_frame_fail():
    header, frames = _frames(_sealed(os.urandom(3 * SMALL + 5)))
    with pytest.raises(BackupDecryptionError, match="truncated"):
        _open(header + b"".join(frames[:-1]))
    with pytest.raises(BackupDecryptionError, match="truncated"):
        _open(header + b"".join(frames)[:-7])


def test_extra_bytes_after_the_final_frame_fail():
    with pytest.raises(BackupDecryptionError, match="after its final frame"):
        _open(_sealed(os.urandom(SMALL)) + b"\x00")


def test_a_frame_from_another_backup_fails():
    first_header, first = _frames(_sealed(os.urandom(2 * SMALL)))
    _, second = _frames(_sealed(os.urandom(2 * SMALL)))
    with pytest.raises(BackupDecryptionError):
        _open(first_header + first[0] + second[1])


def test_short_keys_and_foreign_files_are_refused():
    with pytest.raises(ValueError, match="at least 32"):
        _sealed(b"x", key="short")
    with pytest.raises(BackupDecryptionError, match="not a SOCify encrypted backup"):
        _open(b"SQLite format 3\x00" + b"\x00" * 64)


def test_files_are_written_through_temporary_names_and_never_overwrite(tmp_path):
    source = tmp_path / "plain.db"
    source.write_bytes(os.urandom(10_000))
    sealed = tmp_path / "plain.db.enc"
    assert encrypt_file(source, sealed, KEY) == 10_000
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["plain.db", "plain.db.enc"]
    restored = tmp_path / "restored.db"
    assert decrypt_file(sealed, restored, KEY) == 10_000 and restored.read_bytes() == source.read_bytes()
    with pytest.raises(FileExistsError):
        decrypt_file(sealed, restored, KEY)
    assert restored.read_bytes() == source.read_bytes()
    damaged = tmp_path / "damaged.db.enc"
    damaged.write_bytes(sealed.read_bytes()[:-3])
    with pytest.raises(BackupDecryptionError):
        decrypt_file(damaged, tmp_path / "never.db", KEY)
    assert not (tmp_path / "never.db").exists()
