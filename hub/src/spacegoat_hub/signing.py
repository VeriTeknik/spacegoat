# SPDX-License-Identifier: AGPL-3.0-or-later
"""What a hub signs (spec/protocol.md, "Event signature" and "Request signature").

Two signatures, two purposes:
- the EVENT signature binds one observation to its source, its place in the source's sequence and its content; it is
  stored with the event and verified again later, from the stored fields;
- the REQUEST signature binds one HTTP request to the hub, the endpoint, the moment and the exact body bytes.

Personal data is never in the signed event itself: the event carries a commitment to it (a hash over a random nonce
and the data), so the event still verifies after the personal data has been deleted.
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_json

EVENT_PREFIX = "vt-evidence-event/v1\n"
REQUEST_PREFIX = "vt-machine/v1\n"
# ASCII digits only: `\d` would also take digits of other scripts, which the service does not.
OBSERVED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,62}")
NONCE_HEX = re.compile(r"[0-9a-f]{64}")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def is_observed_at(text: str) -> bool:
    """The exact form, and a moment that exists: month 13 has the right shape and is still not a time."""
    if not isinstance(text, str) or not OBSERVED_AT.fullmatch(text):
        return False
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def pii_commitment(nonce_hex: str, pii: dict[str, Any]) -> str:
    """sha256 over the nonce (as its 64 hex characters), a `|`, and the canonical JSON of the personal data."""
    if not NONCE_HEX.fullmatch(nonce_hex):
        raise ValueError("nonce must be 64 lowercase hex characters")
    return hashlib.sha256(f"{nonce_hex}|{canonical_json(pii)}".encode()).hexdigest()


def event_signing_message(
    *,
    source_id: str,
    source_seq: int,
    kind: str,
    observed_at: str,
    attributes: dict[str, Any],
    pii_commitment: str | None,
) -> bytes:
    if not is_observed_at(observed_at):
        raise ValueError("observedAt must be a real UTC time with millisecond precision, like 2026-11-24T10:00:00.123Z")
    body = canonical_json({
        "sourceId": source_id,
        "sourceSeq": source_seq,
        "kind": kind,
        "observedAt": observed_at,
        "attributes": attributes,
        "piiCommitment": pii_commitment,
    })
    return (EVENT_PREFIX + body).encode("utf-8")


def request_signing_message(*, principal: str, method: str, path: str, timestamp: str, body: bytes) -> bytes:
    """`path` is the request path with its query string; `body` the exact bytes sent (after compression)."""
    digest = hashlib.sha256(body).hexdigest()
    return f"{REQUEST_PREFIX}{principal}\n{method} {path}\n{timestamp}\n{digest}".encode()


def sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return b64url(private_key.sign(message))


def public_key_text(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"ed25519:{b64url(raw)}"


def stored_signature(key_id: str, signature: str) -> str:
    """The form an event's signature travels and is stored in: it names the key that made it."""
    if not KEY_ID.fullmatch(key_id):
        raise ValueError("key id must be 3 to 63 characters of a-z, 0-9 and -")
    return f"ed25519:{key_id}:{signature}"
