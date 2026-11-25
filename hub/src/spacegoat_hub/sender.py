# SPDX-License-Identifier: AGPL-3.0-or-later
"""The sender: delivers what the outbox holds, in order, and says honestly what happened (spec/protocol.md §10).

One call to `step()` makes at most one request. It never sleeps and never loops: the agent's loop decides when to
call it again, from the outcome it returns. That keeps every decision here testable against a real service.

What it guarantees:
- an event is forgotten only after the service confirmed it (`200` with `lastSeq`);
- a failed or unanswered request is sent again with the same bytes, so the service counts duplicates, never gaps;
- a refusal no retry can fix (a rejected schema, an unknown key, a conflicting replay) HALTS the sender. A halted
  sender makes no request at all: knocking for ever with the same refused batch only buries the fault. A person
  looks, the fault is fixed, the agent is started again and continues from where it stood.
"""
from __future__ import annotations

import gzip
import json
import math
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import signing
from .canonical import canonical_json
from .outbox import Outbox, OutboxError

INGEST_PATH = "/api/ops/evidence/ingest"
# The service expects a sign of life every 300 seconds and alerts after three missed ones.
HEARTBEAT_SECONDS = 240
MAX_EVENTS = 500
MAX_COMPRESSED_BYTES = 512 * 1024
BACKOFF_FIRST_SECONDS = 5
BACKOFF_MAX_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 30
HALT_ERRORS = {"schema", "unauthorized", "replay_conflict"}


@dataclass(frozen=True)
class SendOutcome:
    """`sent` (detail: how many events), `idle`, `retry_now`, `retry_later` (wait_seconds), `halted` (detail: why)."""

    kind: str
    detail: str = ""
    wait_seconds: int = 0


class Sender:
    def __init__(
        self,
        *,
        base_url: str,
        source_id: str,
        key_id: str,
        private_key: Ed25519PrivateKey,
        outbox: Outbox,
        now: Callable[[], float] = time.time,
        max_compressed_bytes: int = MAX_COMPRESSED_BYTES,
    ) -> None:
        if not base_url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise ValueError("the hub service is reached over https")
        self._url = base_url.rstrip("/") + INGEST_PATH
        self._principal = f"source:{source_id}"
        self._key_id = key_id
        self._key = private_key
        self._outbox = outbox
        self._now = now
        self._max_bytes = max_compressed_bytes
        self._batch_limit = MAX_EVENTS
        self._resend_from: int | None = None
        self._failures = 0
        self._not_before = 0.0
        self._last_contact: float | None = None
        self.halted: str | None = None
        self.last_success: float | None = None

    def step(self) -> SendOutcome:
        if self.halted:
            return SendOutcome("halted", self.halted)
        now = self._now()
        if now < self._not_before:
            return SendOutcome("retry_later", wait_seconds=math.ceil(self._not_before - now))
        events = self._outbox.pending(self._batch_limit, from_seq=self._resend_from)
        if not events and self._last_contact is not None and now - self._last_contact < HEARTBEAT_SECONDS:
            return SendOutcome("idle")
        body, events = self._fit(events)
        if body is None:
            return self._halt("too_large")
        status, answer, headers = self._post(body, now)
        if status is None:
            return self._back_off()
        self._last_contact = now
        error = answer.get("error")
        if status == 200:
            return self._confirmed(answer, len(events), now)
        if status == 409 and error == "seq_gap":
            return self._seq_gap(answer)
        if status == 413:
            if len(events) <= 1:
                return self._halt("too_large")
            self._batch_limit = max(1, len(events) // 2)
            return SendOutcome("retry_now")
        if status == 429:
            return self._wait(_retry_after(headers))
        if error in HALT_ERRORS and status in (400, 401, 409):
            return self._halt(str(error))
        # 5xx and anything this version does not know: the service's trouble, not a reason to stop for good.
        return self._back_off()

    def _fit(self, events: list[dict]) -> tuple[bytes | None, list[dict]]:
        """The largest prefix of `events` whose compressed body is within the limit. One event that is not: None."""
        while True:
            body = gzip.compress(canonical_json({"schemaVersion": 1, "events": events}).encode("utf-8"), mtime=0)
            if len(body) <= self._max_bytes:
                return body, events
            if len(events) <= 1:
                return None, events
            events = events[: len(events) // 2]

    def _post(self, body: bytes, now: float) -> tuple[int | None, dict, dict]:
        timestamp = str(int(now))
        message = signing.request_signing_message(
            principal=self._principal, method="POST", path=INGEST_PATH, timestamp=timestamp, body=body
        )
        request = urllib.request.Request(  # noqa: S310 - the scheme is checked in __init__
            self._url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-VT-Principal": self._principal,
                "X-VT-Key-Id": self._key_id,
                "X-VT-Timestamp": timestamp,
                "X-VT-Signature": signing.sign(self._key, message),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
                return response.status, _json_object(response.read()), dict(response.headers)
        except urllib.error.HTTPError as error:
            return error.code, _json_object(error.read()), dict(error.headers)
        except (urllib.error.URLError, OSError, TimeoutError):
            # No answer: the request may or may not have arrived. Sending the same bytes again is always safe.
            return None, {}, {}

    def _confirmed(self, answer: dict, sent: int, now: float) -> SendOutcome:
        last_seq = answer.get("lastSeq")
        if not isinstance(last_seq, int) or isinstance(last_seq, bool):
            return self._back_off()
        try:
            self._outbox.ack(last_seq)
        except OutboxError:
            # The service holds events this hub never assigned: two hubs share one identity, or this one lost its
            # outbox. Either way it must not go on writing into that sequence.
            return self._halt("ahead")
        self._resend_from = None
        self._failures = 0
        self._batch_limit = min(MAX_EVENTS, self._batch_limit * 2)
        self.last_success = now
        return SendOutcome("sent", str(sent))

    def _seq_gap(self, answer: dict) -> SendOutcome:
        expected = answer.get("expectedSeq")
        if not isinstance(expected, int) or isinstance(expected, bool):
            return self._back_off()
        if expected <= self._outbox.last_acked() or expected > self._outbox.last_assigned() + 1:
            # It wants events this hub has already forgotten, or ones it never made. A hub does not invent a sequence.
            return self._halt("gap")
        self._resend_from = expected
        return SendOutcome("retry_now")

    def _halt(self, reason: str) -> SendOutcome:
        self.halted = reason
        return SendOutcome("halted", reason)

    def _wait(self, seconds: int) -> SendOutcome:
        self._not_before = self._now() + seconds
        return SendOutcome("retry_later", wait_seconds=seconds)

    def _back_off(self) -> SendOutcome:
        seconds = min(BACKOFF_MAX_SECONDS, BACKOFF_FIRST_SECONDS * 2 ** min(self._failures, 16))
        self._failures += 1
        return self._wait(seconds)


def _json_object(raw: bytes) -> dict:
    try:
        value = json.loads(raw)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _retry_after(headers: dict) -> int:
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), "")
    return max(1, min(3600, int(value))) if str(value).isdigit() else BACKOFF_FIRST_SECONDS
