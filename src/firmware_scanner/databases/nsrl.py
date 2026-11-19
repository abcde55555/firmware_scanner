"""Read-only exact-file lookup against an NSRL RDSv3 SQLite database."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .manifest import DatabaseManifest


class NSRLDatabase:
    def __init__(
        self,
        path: Path,
        manifest: DatabaseManifest,
        *,
        verify_hash: bool = True,
    ):
        if manifest.kind != "nsrl":
            raise ValueError("NSRLDatabase requires an nsrl manifest")
        if verify_hash:
            from .manifest import load_database_manifest

            verified = load_database_manifest("nsrl", path)
            if verified.database_sha256 != manifest.database_sha256:
                raise ValueError("NSRL manifest changed during verification")
        self.path = path
        self.manifest = manifest
        self._connection = self._connect()
        tables = {
            row[0]
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not {"FILE", "PKG"}.issubset(tables):
            self.close()
            raise ValueError("NSRL database lacks FILE or PKG tables")
        file_columns = {
            row[1] for row in self._connection.execute("PRAGMA table_info(FILE)")
        }
        package_columns = {
            row[1] for row in self._connection.execute("PRAGMA table_info(PKG)")
        }
        if not {"sha256", "file_size", "package_id"}.issubset(file_columns):
            self.close()
            raise ValueError("NSRL FILE table lacks required columns")
        if not {"package_id", "name", "version"}.issubset(package_columns):
            self.close()
            raise ValueError("NSRL PKG table lacks required columns")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path.resolve().as_uri() + "?mode=ro&immutable=1",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA cache_size=-32768")
        return connection

    def lookup(self, sha256: str, size: int) -> list[dict]:
        digest = sha256.lower()
        rows = self._connection.execute(
            "SELECT f.file_name, f.file_size, f.package_id, "
            "p.name AS package_name, p.version AS package_version "
            "FROM FILE AS f LEFT JOIN PKG AS p ON f.package_id=p.package_id "
            "WHERE f.sha256 IN (?, ?) AND f.file_size=? LIMIT 101",
            (digest, digest.upper(), size),
        )
        result = [dict(row) for row in rows.fetchmany(100)]
        for row in result:
            row["version_semantics"] = "distribution-package-not-upstream-library"
        return result

    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            connection.close()
            self._connection = None
