# SPDX-License-Identifier: AGPL-3.0-or-later
"""The sender: delivers what the outbox holds, in order, and says honestly what happened (spec/protocol.md §10).

One call to `step()` makes at most one request. It never sleeps and never loops: the agent's loop decides when to
call it again, from the outcome it returns. That keeps every decision here testable against a real service.

What it guarantees:
- an event is forgotten only after the service confirmed it (`200` with `accepted`, `duplicates` and `lastSeq`);
- a failed or unanswered request is sent again with the same bytes, so the service counts duplicates, never gaps;
- a refusal no retry can fix (rejected content, a conflicting replay, a service that lost what it had confirmed)
  HALTS the sender. A halted sender makes no request at all: knocking for ever with the same refused batch only
  buries the fault. A person looks, the fault is fixed, the agent is started again and continues from there;
- `401` does not halt. The service gives the same answer for an unknown key and for a clock that is more than five
  minutes off, and a clock corrects itself: the sender says so (`problem`) and tries again, slowly;
- it talks to one host only: a redirect is never followed (the signed headers and the events would go with it).

It also reads two things off every answer for the agent: how far the hub's clock is from the service's (`Date`),
and the last sequence number the service holds (`lastSeq`).
"""
from __future__ import annotations

import gzip
import http.client
import json
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from email.utils import parsedate_to_datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import signing
from .canonical import canonical_json
from .outbox import Outbox, OutboxError

INGEST_PATH = "/api/ops/evidence/ingest"
# The service expects a sign of life every 300 seconds and alerts after three missed ones.
HEARTBEAT_SECONDS = 240
MAX_EVENTS = 500
MAX_COMPRESSED_BYTES = 512 * 1024
MAX_UNCOMPRESSED_BYTES = 4 * 1024 * 1024
MAX_WAIT_SECONDS = 3600
BACKOFF_FIRST_SECONDS = 5
BACKOFF_MAX_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 30
UNAUTHORIZED_RETRY_SECONDS = 300
MAX_ANSWER_BYTES = 64 * 1024
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
HALT_ERRORS = {"schema", "replay_conflict"}


@dataclass(frozen=True)
class SendOutcome:
    """
    `sent` (detail: how many events), `idle`, `retry_now`, `retry_later` (wait_seconds), `halted` (detail: why),
    `service_ahead` (detail: the service's last sequence; only from an outbox that has never assigned a number).
    """

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
        self._url = service_origin(base_url) + INGEST_PATH
        # No redirect handler: an answer that points elsewhere is an answer, not an instruction.
        self._opener = urllib.request.build_opener(_NoRedirect)
        self._principal = f"source:{source_id}"
        self._key_id = key_id
        self._key = private_key
        self._outbox = outbox
        self._now = now
        self._max_bytes = max_compressed_bytes
        self._batch_limit = MAX_EVENTS
        self._failures = 0
        self._not_before = 0.0
        self._last_contact: float | None = None
        self.halted: str | None = None
        self.last_success: float | None = None
        # Why delivery is not working although the sender keeps trying (today: "unauthorized").
        self.problem: str | None = None
        # Hub clock minus service clock, in seconds, from the last answer that carried a Date; None before any.
        self.clock_skew_seconds: float | None = None
        # The last sequence number the service said it holds; None before any confirmed answer.
        self.service_last_seq: int | None = None

    def step(self) -> SendOutcome:
        if self.halted:
            return SendOutcome("halted", self.halted)
        now = self._now()
        if now < self._not_before:
            return SendOutcome("retry_later", wait_seconds=math.ceil(self._not_before - now))
        events = self._outbox.pending(self._batch_limit)
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
            # The service expects a number this hub has already been told was confirmed, and has forgotten: the
            # service lost events. A hub cannot send what it no longer has, and it does not invent a sequence.
            return self._halt("gap")
        if status == 401:
            self.problem = "unauthorized"
            return self._wait(UNAUTHORIZED_RETRY_SECONDS)
        if status == 413:
            if len(events) <= 1:
                return self._halt("too_large")
            self._batch_limit = max(1, len(events) // 2)
            return SendOutcome("retry_now")
        if status == 429:
            return self._wait(_retry_after(headers, now))
        if error in HALT_ERRORS and status in (400, 409):
            return self._halt(str(error))
        # 5xx and anything this version does not know: the service's trouble, not a reason to stop for good.
        return self._back_off()

    def _fit(self, events: list[dict]) -> tuple[bytes | None, list[dict]]:
        """The largest prefix of `events` whose compressed body is within the limit. One event that is not: None."""
        while True:
            plain = canonical_json({"schemaVersion": 1, "events": events}).encode("utf-8")
            body = gzip.compress(plain, mtime=0)
            # Both limits: a batch that compresses well can be small on the wire and still too large once opened.
            if len(body) <= self._max_bytes and len(plain) <= MAX_UNCOMPRESSED_BYTES:
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
            with self._opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                status, raw, headers = response.status, response.read(MAX_ANSWER_BYTES), dict(response.headers)
        except urllib.error.HTTPError as error:
            status, raw, headers = error.code, error.read(MAX_ANSWER_BYTES), dict(error.headers)
        except (urllib.error.URLError, http.client.HTTPException, OSError, TimeoutError):
            # No answer, or half of one: the request may or may not have arrived. Sending the same bytes again is
            # always safe.
            return None, {}, {}
        self._read_clock(headers, now)
        return status, _json_object(raw), headers

    def _read_clock(self, headers: dict, now: float) -> None:
        value = next((v for k, v in headers.items() if k.lower() == "date"), None)
        try:
            self.clock_skew_seconds = now - parsedate_to_datetime(value).timestamp() if value else None
        except (TypeError, ValueError):
            self.clock_skew_seconds = None

    def _confirmed(self, answer: dict, sent: int, now: float) -> SendOutcome:
        fields = [answer.get(name) for name in ("accepted", "duplicates", "lastSeq")]
        if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in fields):
            # A 200 that is not the service's answer (a proxy, a portal page): nothing was confirmed.
            return self._back_off()
        last_seq = answer["lastSeq"]
        self.service_last_seq = last_seq
        self.problem = None
        if last_seq > self._outbox.last_assigned():
            if self._outbox.last_assigned() == 0:
                # This hub has no queue and the service has a history: the queue was lost, or this is a reinstall.
                # The agent declares it; nothing is confirmed here.
                return SendOutcome("service_ahead", str(last_seq))
            # The service holds events this hub never assigned: two hubs share one identity. It must not go on
            # writing into that sequence.
            return self._halt("ahead")
        try:
            self._outbox.ack(last_seq)
        except OutboxError:
            return self._halt("ahead")
        self._failures = 0
        self._batch_limit = min(MAX_EVENTS, self._batch_limit * 2)
        self.last_success = now
        return SendOutcome("sent", str(sent))

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


def _retry_after(headers: dict, now: float) -> int:
    """`Retry-After` as seconds or as an HTTP date. At most an hour: the hub owes a sign of life sooner than that."""
    value = str(next((v for k, v in headers.items() if k.lower() == "retry-after"), "")).strip()
    if value.isascii() and value.isdigit():
        seconds = int(value)
    else:
        try:
            seconds = math.ceil(parsedate_to_datetime(value).timestamp() - now)
        except (TypeError, ValueError):
            return BACKOFF_FIRST_SECONDS
    return max(1, min(MAX_WAIT_SECONDS, seconds))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def service_origin(base_url: str) -> str:
    """
    `scheme://host[:port]` of the hub service, or ValueError. https only; plain http is for a service on this very
    machine (development, tests) and nothing else. No path, query, fragment or credentials: the request path is
    part of what is signed, and a prefix check on the text would accept `http://localhost.evil.example`.
    """
    parts = urllib.parse.urlsplit(base_url)
    try:
        port = parts.port
    except ValueError:
        raise ValueError("base_url has a malformed port") from None
    host = parts.hostname or ""
    extras = parts.path not in ("", "/") or parts.query or parts.fragment
    if parts.username is not None or parts.password is not None or extras:
        raise ValueError("base_url is the service's origin only: no path, query, fragment or credentials")
    if not host or not (parts.scheme == "https" or (parts.scheme == "http" and host in LOCAL_HOSTS)):
        raise ValueError("base_url must be https")
    name = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{name}" + (f":{port}" if port else "")
