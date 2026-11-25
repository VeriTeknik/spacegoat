# SPDX-License-Identifier: AGPL-3.0-or-later
"""The outbox: the hub's durable, ordered queue of signed events.

An observation becomes an event here, in one transaction: it takes the next sequence number, its personal data gets a
fresh nonce and a commitment, it is signed, and the exact JSON that will be sent is stored. From then on the event
never changes: a delivery that fails is tried again with the same number and the same signature, and the service
recognises it. Nothing is signed twice and no number is used twice.

If the process dies before the transaction commits, neither the event nor its number exists. If it dies after, the
event is on disk and will be sent. There is no state in between.

The file belongs to one source. It also remembers what the service last confirmed, so a hub that lost everything
else can still say truthfully where it stood (`declare_reset`).
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import clock, signing
from .canonical import canonical_json
from .keystore import fsync_directory

RESET_REASONS = ("queue_lost", "reinstall")


class OutboxError(Exception):
    pass


class Outbox:
    def __init__(self, path: Path | str, *, source_id: str, key_id: str, private_key: Ed25519PrivateKey) -> None:
        self.path = Path(path)
        self.source_id = source_id
        self.key_id = key_id
        self._key = private_key
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.path.exists():
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            fsync_directory(self.path.parent)
        # isolation_level=None: transactions are opened and closed here, explicitly.
        self._db = sqlite3.connect(self.path, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        # FULL: a committed event survives power loss, which is the whole point of the file.
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID")
        self._db.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, body TEXT NOT NULL)")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            owner = self._meta("source_id")
            if owner is None:
                self._set_meta("source_id", source_id)
                self._set_meta("last_assigned", "0")
                self._set_meta("last_acked", "0")
            elif owner != source_id:
                raise OutboxError("this outbox belongs to another source")
            self._db.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise

    def close(self) -> None:
        self._db.close()

    def _rollback(self) -> None:
        # If the failure was the COMMIT itself, SQLite may already have rolled back; a second ROLLBACK then fails
        # and would hide the error that matters.
        try:
            self._db.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    @staticmethod
    def read_counters(path: Path | str) -> tuple[int, int]:
        """(last assigned, last confirmed) of the outbox at `path`, read-only; (0, 0) when there is none.

        For `status`: it must not create the file (an empty outbox is how a lost one is recognised), take a write
        lock away from the running agent, or need the private key.
        """
        if not Path(path).exists():
            return 0, 0
        connection = sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True)
        try:
            rows = dict(connection.execute("SELECT key, value FROM meta").fetchall())
        except sqlite3.Error:
            return 0, 0
        finally:
            connection.close()
        return int(rows.get("last_assigned", 0)), int(rows.get("last_acked", 0))

    def oldest_pending_observed_at(self) -> str | None:
        row = self._db.execute("SELECT body FROM events ORDER BY seq LIMIT 1").fetchone()
        return None if row is None else json.loads(row[0])["observedAt"]

    def _meta(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else row[0]

    def _set_meta(self, key: str, value: str) -> None:
        self._db.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def last_assigned(self) -> int:
        return int(self._meta("last_assigned") or 0)

    def last_acked(self) -> int:
        return int(self._meta("last_acked") or 0)

    def _append(
        self, seq: int, kind: str, observed_at: str, attributes: dict[str, Any], pii: dict[str, Any] | None
    ) -> None:
        event: dict[str, Any] = {"sourceSeq": seq, "kind": kind, "observedAt": observed_at, "attributes": attributes}
        commitment = None
        if pii is not None:
            nonce = secrets.token_hex(32)
            commitment = signing.pii_commitment(nonce, pii)
            event.update(pii=pii, piiNonce=nonce, piiCommitment=commitment)
        message = signing.event_signing_message(
            source_id=self.source_id, source_seq=seq, kind=kind, observed_at=observed_at, attributes=attributes,
            pii_commitment=commitment,
        )
        event["signature"] = signing.stored_signature(self.key_id, signing.sign(self._key, message))
        self._db.execute("INSERT INTO events (seq, body) VALUES (?, ?)", (seq, canonical_json(event)))
        self._set_meta("last_assigned", str(seq))

    def append(self, kind: str, observed_at: str, attributes: dict[str, Any], pii: dict[str, Any] | None = None) -> int:
        """Give an observation its place in the sequence and its signature. Returns the sequence number."""
        self._db.execute("BEGIN IMMEDIATE")
        try:
            seq = self.last_assigned() + 1
            self._append(seq, kind, observed_at, attributes, pii)
            self._db.execute("COMMIT")
            return seq
        except BaseException:
            self._rollback()
            raise

    def declare_reset(self, *, last_acked_seq: int, reason: str) -> int:
        """
        Start an empty outbox after a loss: the next event is `site_source.reset`, numbered right after the last
        sequence the SERVICE holds (the service accepts a reset only there, so the number is asked of the service,
        never taken from the hub's own memory). Only an outbox that has never assigned a number may do this; a hub
        does not rewrite a sequence it still holds.
        """
        if reason not in RESET_REASONS:
            raise OutboxError("unknown reset reason")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            if self.last_assigned() != 0:
                raise OutboxError("a reset is declared on an empty outbox only")
            self._set_meta("last_acked", str(last_acked_seq))
            seq = last_acked_seq + 1
            attributes = {"trustOrigin": "hub", "lastAckedSeq": last_acked_seq, "reason": reason}
            self._append(seq, "site_source.reset", clock.observed_at_text(clock.now()), attributes, None)
            self._db.execute("COMMIT")
            return seq
        except BaseException:
            self._rollback()
            raise

    def pending(self, limit: int, from_seq: int | None = None) -> list[dict[str, Any]]:
        """Undelivered events in order, exactly as they were stored."""
        start = self.last_acked() + 1 if from_seq is None else from_seq
        query = "SELECT body FROM events WHERE seq >= ? ORDER BY seq LIMIT ?"
        rows = self._db.execute(query, (start, limit)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def ack(self, last_seq: int) -> None:
        """The service confirmed everything up to `last_seq`. Never moves back; never past what was assigned."""
        self._db.execute("BEGIN IMMEDIATE")
        try:
            if last_seq > self.last_assigned():
                raise OutboxError("the service confirmed a sequence ahead of anything this hub assigned")
            if last_seq > self.last_acked():
                self._db.execute("DELETE FROM events WHERE seq <= ?", (last_seq,))
                self._set_meta("last_acked", str(last_seq))
            self._db.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise

