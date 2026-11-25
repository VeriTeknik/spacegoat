# SPDX-License-Identifier: AGPL-3.0-or-later
"""What a hub remembers beside its outbox.

Two things, kept apart from the outbox on purpose, so that losing the queue does not lose them:

- `confirmed`: the last sequence number the service confirmed. With it, a hub whose outbox is gone can still say
  truthfully where it stood (`site_source.reset`), instead of guessing or starting over.
- the pseudonyms: which random `deviceRef` stands for which device, and whether that device has been announced.
  They are what lets the service see "the same device" tomorrow. They are random (UUID v4), never derived from the
  device, and they stay on the hub.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .keystore import fsync_directory, private_file


def write_atomic(path: Path, text: str) -> None:
    """Replace `path` so that a reader, or a power cut, sees the old content or the new, never half of one."""
    # mkstemp: an unpredictable name, created exclusively and 0600; never an existing file, never through a link.
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    fsync_directory(path.parent)


class Confirmed:
    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> int:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))["lastAckedSeq"]
        except (FileNotFoundError, ValueError, KeyError, TypeError):
            return 0
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    def write(self, last_acked_seq: int) -> None:
        if last_acked_seq > self.read():
            write_atomic(self.path, json.dumps({"lastAckedSeq": last_acked_seq}))


class Pseudonyms:
    """identity (how the hub recognises a device or a segment locally) -> the random reference it reports."""

    def __init__(self, path: Path) -> None:
        private_file(path)
        self._db = sqlite3.connect(path, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS refs (scope TEXT NOT NULL, identity TEXT NOT NULL, ref TEXT NOT NULL,"
            " facts TEXT NOT NULL DEFAULT '{}', PRIMARY KEY (scope, identity)) WITHOUT ROWID"
        )

    def close(self) -> None:
        self._db.close()

    def ref(self, scope: str, identity: str) -> str:
        """The reference of `identity`, created on first use: a fresh random UUID v4, never a function of it."""
        row = self._db.execute("SELECT ref FROM refs WHERE scope = ? AND identity = ?", (scope, identity)).fetchone()
        if row:
            return row[0]
        fresh = str(uuid.uuid4())
        self._db.execute("INSERT INTO refs (scope, identity, ref) VALUES (?, ?, ?)", (scope, identity, fresh))
        return fresh

    def facts(self, scope: str, identity: str) -> dict[str, Any]:
        """What the hub last reported about `identity` (empty before its first report)."""
        row = self._db.execute("SELECT facts FROM refs WHERE scope = ? AND identity = ?", (scope, identity)).fetchone()
        return json.loads(row[0]) if row else {}

    def forget_facts(self) -> None:
        """
        Forget what was reported, keep the references. After a lost queue the hub cannot know which of its reports
        reached the service: it reports every device again (the service takes a repeated report as an update of
        the same device, because the reference is the same) rather than stay silent about one that never arrived.
        """
        self._db.execute("UPDATE refs SET facts = '{}'")

    def remember(self, scope: str, identity: str, facts: dict[str, Any]) -> None:
        self.ref(scope, identity)
        text = json.dumps(facts, sort_keys=True)
        self._db.execute("UPDATE refs SET facts = ? WHERE scope = ? AND identity = ?", (text, scope, identity))
