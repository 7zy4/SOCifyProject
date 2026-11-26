"""Streaming encryption for backup files, with a key kept apart from the credential key.

Layout: a header, then frames of at most CHUNK_SIZE plaintext bytes.

    header = MAGIC (9 bytes) | version (1) | key id (8) | salt (16)
    frame  = nonce (12) | ciphertext length (4, big-endian) | AES-256-GCM ciphertext with its 16-byte tag

Each frame is authenticated together with the whole header, its index and a final-frame flag, so a frame moved to
another position, taken from another backup, dropped from the end or followed by extra bytes fails decryption.
The AES key is derived with HKDF-SHA256 from SOCIFY_BACKUP_KEY and the file's random salt; the key id is a short
hash that tells which key a file needs without revealing it.
"""

import hashlib
import os
import secrets
import struct
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SOCIFYBK1"
VERSION = 1
CHUNK_SIZE = 4 * 1024 * 1024
HEADER_SIZE = len(MAGIC) + 1 + 8 + 16
NONCE_SIZE = 12
TAG_SIZE = 16
MINIMUM_KEY_LENGTH = 32


class BackupDecryptionError(ValueError):
    """The file is not a SOCify encrypted backup, needs another key, or was changed or cut short."""


def key_id(secret: str) -> bytes:
    return hashlib.sha256(b"socify-backup-key-id\x00" + secret.encode()).digest()[:8]


def _check_secret(secret: str) -> None:
    if not isinstance(secret, str) or len(secret) < MINIMUM_KEY_LENGTH:
        raise ValueError(f"SOCIFY_BACKUP_KEY must be at least {MINIMUM_KEY_LENGTH} characters")


def _derive(secret: str, salt: bytes) -> AESGCM:
    material = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"socify-backup-v1").derive(secret.encode())
    return AESGCM(material)


def _associated(header: bytes, index: int, final: bool) -> bytes:
    return header + struct.pack(">QB", index, 1 if final else 0)


def encrypt_stream(source: BinaryIO, destination: BinaryIO, secret: str, chunk_size: int = CHUNK_SIZE) -> int:
    """Encrypt everything readable from source into destination; returns the number of plaintext bytes."""
    _check_secret(secret)
    salt = secrets.token_bytes(16)
    header = MAGIC + bytes([VERSION]) + key_id(secret) + salt
    cipher = _derive(secret, salt)
    destination.write(header)
    total, index = 0, 0
    current = source.read(chunk_size)
    while True:
        following = source.read(chunk_size) if current else b""
        final = not following
        nonce = secrets.token_bytes(NONCE_SIZE)
        sealed = cipher.encrypt(nonce, current, _associated(header, index, final))
        destination.write(nonce + struct.pack(">I", len(sealed)) + sealed)
        total += len(current)
        if final:
            return total
        current, index = following, index + 1


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise BackupDecryptionError("the backup is truncated")
    return data


def decrypt_stream(source: BinaryIO, destination: BinaryIO, secret: str, chunk_size: int = CHUNK_SIZE) -> int:
    """Decrypt a backup written by encrypt_stream; raises BackupDecryptionError on any mismatch or damage."""
    _check_secret(secret)
    header = source.read(HEADER_SIZE)
    if len(header) != HEADER_SIZE or not header.startswith(MAGIC):
        raise BackupDecryptionError("not a SOCify encrypted backup")
    if header[len(MAGIC)] != VERSION:
        raise BackupDecryptionError("unsupported backup format version")
    if not secrets.compare_digest(header[len(MAGIC) + 1 : len(MAGIC) + 9], key_id(secret)):
        raise BackupDecryptionError("the backup was encrypted with a different SOCIFY_BACKUP_KEY")
    cipher = _derive(secret, header[-16:])
    total, index = 0, 0
    while True:
        prefix = _read_exact(source, NONCE_SIZE + 4)
        length = struct.unpack(">I", prefix[NONCE_SIZE:])[0]
        if not TAG_SIZE <= length <= chunk_size + TAG_SIZE:
            raise BackupDecryptionError("the backup has a damaged frame")
        sealed = _read_exact(source, length)
        plain = None
        for final in (False, True):
            try:
                plain = cipher.decrypt(prefix[:NONCE_SIZE], sealed, _associated(header, index, final))
            except InvalidTag:
                continue
            break
        if plain is None:
            raise BackupDecryptionError("the backup was changed, reordered or encrypted with another key")
        destination.write(plain)
        total += len(plain)
        if final:
            if source.read(1):
                raise BackupDecryptionError("the backup has data after its final frame")
            return total
        index += 1


def encrypt_file(source: str | Path, destination: str | Path, secret: str) -> int:
    """Encrypt a file to destination through a temporary name, so a partial file never carries the final name."""
    target = Path(destination)
    partial = target.with_name(target.name + ".partial")
    try:
        with open(source, "rb") as plain, open(partial, "xb") as sealed:
            total = encrypt_stream(plain, sealed, secret)
            sealed.flush()
            os.fsync(sealed.fileno())
        os.replace(partial, target)
        return total
    finally:
        partial.unlink(missing_ok=True)


def decrypt_file(source: str | Path, destination: str | Path, secret: str) -> int:
    """Decrypt to a new file; an existing destination is never overwritten, and a failed decryption leaves nothing behind."""
    target = Path(destination)
    with open(source, "rb") as sealed, open(target, "xb") as plain:
        try:
            return decrypt_stream(sealed, plain, secret)
        except (BackupDecryptionError, OSError):
            plain.close()
            target.unlink(missing_ok=True)
            raise
