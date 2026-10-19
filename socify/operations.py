import os
import sqlite3
import tempfile
from pathlib import Path

from .db import connect_path
from .schema import ensure_schema


def verify_database(path: str) -> dict[str, object]:
    connection = connect_path(path, True)
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = list(connection.execute("PRAGMA foreign_key_check").fetchall())
        version = connection.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
        return {"integrity": integrity, "foreign_key_violations": len(foreign_keys), "schema_version": version["value"] if version else None}
    finally:
        connection.close()


def backup_database(source: str, destination: str) -> dict[str, object]:
    source_path = Path(source).resolve()
    destination_path = Path(destination).resolve()
    if not source_path.is_file() or source_path == destination_path:
        raise ValueError("source must be an existing database distinct from destination")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    source_connection = connect_path(str(source_path), True)
    destination_connection = sqlite3.connect(str(destination_path))
    try:
        source_connection.backup(destination_connection)
        destination_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        destination_connection.close()
        source_connection.close()
    result = verify_database(str(destination_path))
    if result["integrity"] != "ok" or result["foreign_key_violations"]:
        raise RuntimeError("backup verification failed")
    return result


def restore_database(backup: str, destination: str) -> dict[str, object]:
    backup_path = Path(backup).resolve()
    destination_path = Path(destination).resolve()
    if not backup_path.is_file() or backup_path == destination_path:
        raise ValueError("backup must be an existing database distinct from destination")
    source_result = verify_database(str(backup_path))
    if source_result["integrity"] != "ok" or source_result["foreign_key_violations"]:
        raise RuntimeError("backup is not safe to restore")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix="socify-restore-", suffix=".db", dir=destination_path.parent)
    os.close(descriptor)
    try:
        backup_connection = connect_path(str(backup_path), True)
        restored_connection = sqlite3.connect(temporary_name)
        try:
            backup_connection.backup(restored_connection)
        finally:
            restored_connection.close()
            backup_connection.close()
        result = verify_database(temporary_name)
        if result["integrity"] != "ok" or result["foreign_key_violations"]:
            raise RuntimeError("restored database verification failed")
        os.replace(temporary_name, destination_path)
        return result
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def migration_dry_run(source: str) -> dict[str, object]:
    source_path = Path(source).resolve()
    if not source_path.is_file():
        raise ValueError("source database does not exist")
    descriptor, temporary_name = tempfile.mkstemp(prefix="socify-migration-", suffix=".db")
    os.close(descriptor)
    try:
        backup_database(str(source_path), temporary_name)
        connection = connect_path(temporary_name, True)
        try:
            ensure_schema(connection)
        finally:
            connection.close()
        return verify_database(temporary_name)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
