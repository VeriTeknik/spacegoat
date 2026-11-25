# SPDX-License-Identifier: AGPL-3.0-or-later
"""The outbox: every event gets its place in the sequence and its signature once, on disk, before anything is sent."""
import base64
import sqlite3

import pytest

from spacegoat_hub import signing
from spacegoat_hub.outbox import Outbox, OutboxError

SOURCE = "01234567-89ab-4cde-8fab-0123456789ab"
DEVICE = "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b"
SEGMENT = "0c0c0c0c-0c0c-4c0c-8c0c-0c0c0c0c0c0c"
AT = "2026-11-25T10:00:00.000Z"
SEEN = {"trustOrigin": "hub", "deviceRef": DEVICE, "segmentRef": SEGMENT}


def open_outbox(tmp_path, key):
    return Outbox(tmp_path / "outbox.sqlite", source_id=SOURCE, key_id="vector-key-1", private_key=key)


def verify(key, event):
    scheme, key_id, signature = event["signature"].split(":")
    assert (scheme, key_id) == ("ed25519", "vector-key-1")
    message = signing.event_signing_message(
        source_id=SOURCE, source_seq=event["sourceSeq"], kind=event["kind"], observed_at=event["observedAt"],
        attributes=event["attributes"], pii_commitment=event.get("piiCommitment"),
    )
    key.public_key().verify(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), message)


def test_the_sequence_starts_at_one_and_has_no_gap(tmp_path, vector_key):
    outbox = open_outbox(tmp_path, vector_key)
    assert [outbox.append("site.device_seen", AT, SEEN) for _ in range(3)] == [1, 2, 3]
    events = outbox.pending(10)
    assert [event["sourceSeq"] for event in events] == [1, 2, 3]
    for event in events:
        verify(vector_key, event)
    assert (outbox.last_assigned(), outbox.last_acked()) == (3, 0)


def test_reopening_continues_the_sequence_and_returns_the_same_bytes(tmp_path, vector_key):
    first = open_outbox(tmp_path, vector_key)
    first.append("site.device_seen", AT, SEEN)
    stored = first.pending(10)
    first.close()
    second = open_outbox(tmp_path, vector_key)
    assert second.pending(10) == stored
    assert second.append("site.device_seen", AT, SEEN) == 2


def test_ack_forgets_delivered_events_and_only_moves_forward(tmp_path, vector_key):
    outbox = open_outbox(tmp_path, vector_key)
    for _ in range(4):
        outbox.append("site.device_seen", AT, SEEN)
    outbox.ack(2)
    assert [event["sourceSeq"] for event in outbox.pending(10)] == [3, 4]
    outbox.ack(1)
    assert outbox.last_acked() == 2
    with pytest.raises(OutboxError, match="ahead"):
        outbox.ack(9)
    assert outbox.last_acked() == 2


def test_pending_from_a_sequence_and_with_a_limit(tmp_path, vector_key):
    outbox = open_outbox(tmp_path, vector_key)
    for _ in range(5):
        outbox.append("site.device_seen", AT, SEEN)
    assert [event["sourceSeq"] for event in outbox.pending(2)] == [1, 2]
    assert [event["sourceSeq"] for event in outbox.pending(10, from_seq=4)] == [4, 5]


def test_personal_data_travels_as_the_triple_and_only_its_commitment_is_signed(tmp_path, vector_key):
    outbox = open_outbox(tmp_path, vector_key)
    pii = {"mac": "0200005e1001", "hostname": "printer.example", "ip": "192.0.2.10"}
    outbox.append("site.device_appeared", AT, {**SEEN, "deviceClass": "printer"}, pii=pii)
    outbox.append("site.device_appeared", AT, {**SEEN, "deviceClass": "printer"}, pii=pii)
    first, second = outbox.pending(10)
    assert first["pii"] == pii
    assert first["piiCommitment"] == signing.pii_commitment(first["piiNonce"], pii)
    assert first["piiNonce"] != second["piiNonce"]
    assert not set(pii) & set(first["attributes"])
    verify(vector_key, first)
    outbox.append("site.device_seen", AT, SEEN)
    assert not {"pii", "piiNonce", "piiCommitment"} & set(outbox.pending(10)[2])


def test_an_event_that_cannot_be_signed_takes_no_sequence_number(tmp_path, vector_key):
    outbox = open_outbox(tmp_path, vector_key)
    with pytest.raises(ValueError):
        outbox.append("site.device_seen", "2026-11-25 10:00", SEEN)
    with pytest.raises(ValueError):
        outbox.append("site.device_seen", AT, {**SEEN, "ratio": 0.5})
    assert outbox.last_assigned() == 0
    assert outbox.append("site.device_seen", AT, SEEN) == 1


def test_a_write_that_dies_before_commit_leaves_neither_event_nor_number(tmp_path, vector_key, monkeypatch):
    outbox = open_outbox(tmp_path, vector_key)
    outbox.append("site.device_seen", AT, SEEN)

    def die(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(signing, "sign", die)
    with pytest.raises(KeyboardInterrupt):
        outbox.append("site.device_seen", AT, SEEN)
    monkeypatch.undo()
    outbox.close()
    again = open_outbox(tmp_path, vector_key)
    assert again.last_assigned() == 1
    assert again.append("site.device_seen", AT, SEEN) == 2
    assert [event["sourceSeq"] for event in again.pending(10)] == [1, 2]


def test_an_outbox_belongs_to_one_source(tmp_path, vector_key):
    open_outbox(tmp_path, vector_key).close()
    with pytest.raises(OutboxError, match="another source"):
        Outbox(tmp_path / "outbox.sqlite", source_id="99999999-9999-4999-8999-999999999999", key_id="vector-key-1",
               private_key=vector_key)


def test_a_reset_is_declared_with_what_the_service_last_confirmed(tmp_path, vector_key):
    outbox = open_outbox(tmp_path, vector_key)
    seq = outbox.declare_reset(last_acked_seq=41, reason="queue_lost")
    assert seq == 42
    (event,) = outbox.pending(10)
    assert event["kind"] == "site_source.reset"
    assert event["attributes"] == {"trustOrigin": "hub", "lastAckedSeq": 41, "reason": "queue_lost"}
    verify(vector_key, event)
    assert outbox.append("site.device_seen", AT, SEEN) == 43
    with pytest.raises(OutboxError, match="empty"):
        outbox.declare_reset(last_acked_seq=50, reason="queue_lost")


def test_the_file_is_private_and_durable(tmp_path, vector_key):
    outbox = open_outbox(tmp_path, vector_key)
    outbox.append("site.device_seen", AT, SEEN)
    assert (tmp_path / "outbox.sqlite").stat().st_mode & 0o077 == 0
    connection = sqlite3.connect(tmp_path / "outbox.sqlite")
    assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
