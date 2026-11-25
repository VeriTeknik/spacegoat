# SPDX-License-Identifier: AGPL-3.0-or-later
"""A hub service for tests: it checks what the real one checks (spec/protocol.md) and nothing is mocked in between.

It verifies the request signature against the registered public key, the timestamp window, the event signatures and
the sequence, and answers with the protocol's bodies. A test can script the next answers to stand for a service that
is down, busy or whose answer was lost on the way back.
"""
from __future__ import annotations

import base64
import gzip
import json
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from spacegoat_hub import signing
from spacegoat_hub.canonical import canonical_json

PATH = "/api/ops/evidence/ingest"


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class FakeService:
    def __init__(self, *, source_id: str, key_id: str, public_key: Ed25519PublicKey, last_seq: int = 0) -> None:
        self.source_id, self.key_id, self.public_key = source_id, key_id, public_key
        self.last_seq = last_seq
        self.accepted: list[dict] = []
        # What is on record, by sequence number: a replay is compared with it, never taken on trust.
        self._stored: dict[int, str] = {}   # sequence number -> the canonical text of the event on record
        self.requests: list[dict] = []
        # Each entry is consumed by one request: ("status", code, body, headers) answers without processing,
        # ("lose_answer",) processes the batch and then drops the connection, ("max_events", n) answers 413 above n.
        self.script: list[tuple] = []
        self.max_events = 500
        # The service's clock; a test that moves the hub's clock moves this one with it.
        self.now = time.time
        service = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):  # keep test output clean
                pass

            def date_time_string(self, timestamp=None):
                # The Date header follows the service's clock, which a test may move.
                return super().date_time_string(service.now() if timestamp is None else timestamp)

            def do_POST(self):  # noqa: N802
                service._handle(self)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _reply(self, handler, status: int, body: dict, headers: dict | None = None) -> None:
        payload = json.dumps(body).encode()
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(payload)))
        for name, value in (headers or {}).items():
            handler.send_header(name, value)
        handler.end_headers()
        handler.wfile.write(payload)

    def _handle(self, handler) -> None:
        raw = handler.rfile.read(int(handler.headers.get("Content-Length", "0")))
        record = {"headers": dict(handler.headers), "bytes": len(raw), "events": None}
        self.requests.append(record)
        step = self.script.pop(0) if self.script else None
        if step and step[0] == "truncate_error":
            handler.send_response(503)
            handler.send_header("Content-Length", "500")
            handler.end_headers()
            handler.wfile.write(b'{"error": "unav')
            handler.connection.close()
            return None
        if step and step[0] == "truncate":
            handler.send_response(200)
            handler.send_header("Content-Length", "500")
            handler.end_headers()
            handler.wfile.write(b'{"accepted": 1')
            handler.connection.close()
            return None
        if step and step[0] == "status":
            return self._reply(handler, step[1], step[2], step[3] if len(step) > 3 else None)
        headers = handler.headers
        well_formed = (handler.path == PATH and headers.get("Content-Encoding") == "gzip" and not headers.get("Origin")
                       and headers.get("Content-Type") == "application/json")
        if not well_formed:
            return self._reply(handler, 400, {"error": "schema"})
        principal = handler.headers.get("X-VT-Principal", "")
        timestamp = handler.headers.get("X-VT-Timestamp", "")
        message = signing.request_signing_message(principal=principal, method="POST", path=handler.path,
                                                  timestamp=timestamp, body=raw)
        try:
            if principal != f"source:{self.source_id}" or handler.headers.get("X-VT-Key-Id") != self.key_id:
                raise InvalidSignature
            if not (timestamp.isdigit() and len(timestamp) == 10) or abs(self.now() - int(timestamp)) > 300:
                raise InvalidSignature
            self.public_key.verify(_unb64(handler.headers.get("X-VT-Signature", "")), message)
        except (InvalidSignature, ValueError):
            return self._reply(handler, 401, {"error": "unauthorized"})
        if len(raw) > 512 * 1024:
            return self._reply(handler, 413, {"error": "too_large"})
        body = json.loads(gzip.decompress(raw))
        events = body.get("events")
        record["events"] = [event["sourceSeq"] for event in events]
        limit = step[1] if step and step[0] == "max_events" else self.max_events
        if body.get("schemaVersion") != 1 or len(events) > limit:
            return self._reply(handler, 413 if len(events) > limit else 400,
                               {"error": "too_large" if len(events) > limit else "schema"})
        fresh = [event for event in events if event["sourceSeq"] > self.last_seq]
        duplicates = len(events) - len(fresh)
        for event in events:
            # A sequence number already on record must be the very event on record.
            # The whole event, not only its signature: a changed event under a reused signature is a conflict too.
            if event["sourceSeq"] <= self.last_seq and self._stored.get(event["sourceSeq"]) != canonical_json(event):
                return self._reply(handler, 409, {"error": "replay_conflict", "sourceSeq": event["sourceSeq"]})
        if fresh:
            first = fresh[0]
            declares_gap = first["kind"] == "site_source.gap_declared"
            declared = declares_gap and first["attributes"]["fromSeq"] == self.last_seq + 1
            reset_ok = first["kind"] != "site_source.reset" or first["attributes"].get("lastAckedSeq") == self.last_seq
            if not reset_ok:
                return self._reply(handler, 400, {"error": "schema"})
            if not declared and first["sourceSeq"] != self.last_seq + 1:
                body = {"error": "seq_gap", "expectedSeq": self.last_seq + 1}
                return self._reply(handler, 409, body)
        expected = fresh[0]["sourceSeq"] if fresh else None
        for event in fresh:
            if event["sourceSeq"] != expected:
                return self._reply(handler, 400, {"error": "schema"})
            expected += 1
            scheme, key_id, signature = event["signature"].split(":")
            signed = signing.event_signing_message(
                source_id=self.source_id, source_seq=event["sourceSeq"], kind=event["kind"],
                observed_at=event["observedAt"], attributes=event["attributes"],
                pii_commitment=event.get("piiCommitment"))
            try:
                if (scheme, key_id) != ("ed25519", self.key_id) or event["attributes"].get("trustOrigin") != "hub":
                    raise InvalidSignature
                observed = datetime.strptime(event["observedAt"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
                # The service keeps the distance between observation and receipt in a signed 32-bit millisecond field.
                if abs(self.now() - observed.timestamp()) * 1000 > 2**31 - 1:
                    raise InvalidSignature
                self.public_key.verify(_unb64(signature), signed)
                if "pii" in event and signing.pii_commitment(event["piiNonce"], event["pii"]) != event["piiCommitment"]:
                    raise InvalidSignature
            except InvalidSignature:
                return self._reply(handler, 400, {"error": "schema"})
        self.accepted.extend(fresh)
        self._stored.update({event["sourceSeq"]: canonical_json(event) for event in fresh})
        if fresh:
            self.last_seq = fresh[-1]["sourceSeq"]
        if step and step[0] == "lose_answer":
            handler.connection.close()
            return None
        return self._reply(handler, 200, {"accepted": len(fresh), "duplicates": duplicates, "lastSeq": self.last_seq})
