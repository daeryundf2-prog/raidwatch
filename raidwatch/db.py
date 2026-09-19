"""SQLite inventory store for filesystem snapshots."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
  path TEXT PRIMARY KEY,
  size INTEGER NOT NULL,
  mtime_ns INTEGER NOT NULL,
  ctime_ns INTEGER NOT NULL,
  atime_ns INTEGER NOT NULL,
  sha256 TEXT,
  kind TEXT NOT NULL,
  status TEXT NOT NULL
);
"""

INSERT_SQL = (
    "INSERT OR REPLACE INTO files"
    " (path, size, mtime_ns, ctime_ns, atime_ns, sha256, kind, status)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
)


@dataclass
class FileRecord:
    path: str
    size: int
    mtime_ns: int
    ctime_ns: int
    atime_ns: int
    sha256: str | None
    kind: str
    status: str

    @classmethod
    def from_row(cls, row: tuple) -> "FileRecord":
        return cls(
            path=row[0],
            size=row[1],
            mtime_ns=row[2],
            ctime_ns=row[3],
            atime_ns=row[4],
            sha256=row[5],
            kind=row[6],
            status=row[7],
        )

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "ctime_ns": self.ctime_ns,
            "atime_ns": self.atime_ns,
            "sha256": self.sha256,
            "kind": self.kind,
            "status": self.status,
        }


class Inventory:
    def __init__(self, db_path: Path | str, *, create: bool = False) -> None:
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path))
        if create:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def set_meta(self, key: str, value) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (key, json.dumps(value, ensure_ascii=False)),
        )

    def get_meta(self, key: str):
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def all_meta(self) -> dict:
        return {
            key: json.loads(value)
            for key, value in self.conn.execute("SELECT key, value FROM meta")
        }

    def upsert(self, rec: FileRecord) -> None:
        self.conn.execute(
            INSERT_SQL,
            (
                rec.path,
                rec.size,
                rec.mtime_ns,
                rec.ctime_ns,
                rec.atime_ns,
                rec.sha256,
                rec.kind,
                rec.status,
            ),
        )

    def commit(self) -> None:
        self.conn.commit()

    def iter_records(self) -> Iterator[FileRecord]:
        cursor = self.conn.execute(
            "SELECT path, size, mtime_ns, ctime_ns, atime_ns, sha256, kind, status"
            " FROM files ORDER BY path"
        )
        for row in cursor:
            yield FileRecord.from_row(row)

    def get(self, path: str) -> FileRecord | None:
        row = self.conn.execute(
            "SELECT path, size, mtime_ns, ctime_ns, atime_ns, sha256, kind, status"
            " FROM files WHERE path = ?",
            (path,),
        ).fetchone()
        return FileRecord.from_row(row) if row else None

    def paths(self) -> set[str]:
        return {
            row[0] for row in self.conn.execute("SELECT path FROM files")
        }

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()
