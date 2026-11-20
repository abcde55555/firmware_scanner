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
        integrity_verified: bool | None = None,
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
        self.integrity_verified = (
            bool(verify_hash) if integrity_verified is None else bool(integrity_verified)
        )
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

    def lookup_with_metadata(self, sha256: str, size: int, *, limit: int = 100) -> dict:
        digest = sha256.lower()
        if limit < 1 or limit > 1000:
            raise ValueError("NSRL lookup limit must be between 1 and 1000")
        where = "f.sha256 IN (?, ?) AND f.file_size=?"
        parameters = (digest, digest.upper(), size)
        total = int(
            self._connection.execute(
                f"SELECT COUNT(*) FROM FILE AS f WHERE {where}",
                parameters,
            ).fetchone()[0]
        )
        rows = self._connection.execute(
            "SELECT f.file_name, f.file_size, f.package_id, "
            "p.name AS package_name, p.version AS package_version "
            "FROM FILE AS f LEFT JOIN PKG AS p ON f.package_id=p.package_id "
            f"WHERE {where} ORDER BY f.file_name, p.name, p.version LIMIT ?",
            (*parameters, limit),
        )
        result = [dict(row) for row in rows.fetchmany(limit)]
        for row in result:
            row["version_semantics"] = "distribution-package-not-upstream-library"
        return {
            "matches": result,
            "returned_matches": len(result),
            "total_matches": total,
            "truncated": total > len(result),
        }

    def lookup(self, sha256: str, size: int) -> list[dict]:
        return self.lookup_with_metadata(sha256, size)["matches"]

    def self_check(self) -> dict:
        """Prove the exact-file query path against one immutable database row."""
        row = self._connection.execute(
            "SELECT sha256, file_size, file_name FROM FILE "
            "WHERE sha256 IS NOT NULL AND length(sha256)=64 "
            "ORDER BY sha256 LIMIT 1"
        ).fetchone()
        if row is None:
            return {
                "passed": False,
                "reason": "database has no SHA-256 rows",
                "database_release": self.manifest.release,
                "database_sha256": self.manifest.database_sha256,
            }
        digest = str(row["sha256"]).lower()
        size = int(row["file_size"])
        lookup = self.lookup_with_metadata(digest, size, limit=10)
        matched = any(
            str(item.get("file_name", "")) == str(row["file_name"])
            for item in lookup["matches"]
        )
        return {
            "passed": matched,
            "query_sha256": digest,
            "query_file_size": size,
            "expected_file_name": str(row["file_name"]),
            "returned_matches": lookup["returned_matches"],
            "total_matches": lookup["total_matches"],
            "truncated": lookup["truncated"],
            "database_release": self.manifest.release,
            "database_sha256": self.manifest.database_sha256,
        }

    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            connection.close()
            self._connection = None
