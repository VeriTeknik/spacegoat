# SPDX-License-Identifier: AGPL-3.0-or-later
"""The sender against a service that checks signatures and sequence for real (tests/fake_service.py)."""
import pytest

from spacegoat_hub.outbox import Outbox
from spacegoat_hub.sender import HEARTBEAT_SECONDS, Sender

from .fake_service import FakeService

SOURCE = "01234567-89ab-4cde-8fab-0123456789ab"
AT = "2026-11-25T10:00:00.000Z"
SEEN = {"trustOrigin": "hub", "deviceRef": "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b",
        "segmentRef": "0c0c0c0c-0c0c-4c0c-8c0c-0c0c0c0c0c0c"}


class Clock:
    def __init__(self):
        import time
        self.offset = 0.0
        self._time = time.time

    def __call__(self):
        return self._time() + self.offset


@pytest.fixture
def service(vector_key):
    fake = FakeService(source_id=SOURCE, key_id="vector-key-1", public_key=vector_key.public_key())
    yield fake
    fake.close()


@pytest.fixture
def outbox(tmp_path, vector_key):
    return Outbox(tmp_path / "outbox.sqlite", source_id=SOURCE, key_id="vector-key-1", private_key=vector_key)


def make_sender(service, outbox, vector_key, clock=None, **kwargs):
    clock = clock or Clock()
    service.now = clock
    return Sender(base_url=service.base_url, source_id=SOURCE, key_id="vector-key-1", private_key=vector_key,
                  outbox=outbox, now=clock, **kwargs)


def fill(outbox, count):
    for _ in range(count):
        outbox.append("site.device_seen", AT, SEEN)


def test_a_batch_is_delivered_signed_and_forgotten(service, outbox, vector_key):
    fill(outbox, 3)
    outcome = make_sender(service, outbox, vector_key).step()
    assert (outcome.kind, outcome.detail) == ("sent", "3")
    assert [event["sourceSeq"] for event in service.accepted] == [1, 2, 3]
    assert outbox.last_acked() == 3 and outbox.pending(10) == []
    assert "Origin" not in service.requests[0]["headers"]


def test_nothing_to_send_is_idle_until_a_heartbeat_is_due(service, outbox, vector_key):
    clock = Clock()
    sender = make_sender(service, outbox, vector_key, clock)
    assert sender.step().kind == "sent"          # the first contact is a heartbeat: the hub says it is alive
    assert service.requests[-1]["events"] == []
    assert sender.step().kind == "idle"
    assert len(service.requests) == 1
    clock.offset += HEARTBEAT_SECONDS + 1
    assert sender.step().kind == "sent"
    assert service.requests[-1]["events"] == [] and len(service.requests) == 2


def test_a_lost_answer_is_sent_again_and_the_service_counts_duplicates(service, outbox, vector_key):
    fill(outbox, 2)
    service.script.append(("lose_answer",))
    clock = Clock()
    sender = make_sender(service, outbox, vector_key, clock)
    first = sender.step()
    assert first.kind == "retry_later"
    assert outbox.last_acked() == 0 and service.last_seq == 2
    clock.offset += first.wait_seconds + 1
    assert sender.step().kind == "sent"
    assert outbox.last_acked() == 2
    assert [event["sourceSeq"] for event in service.accepted] == [1, 2]   # each exactly once


def test_seq_gap_means_the_service_lost_events_and_halts(service, outbox, vector_key):
    # The service can only ask for a number at or below what it already confirmed: it lost events. The hub has
    # forgotten them, cannot send them again, and does not invent a sequence.
    fill(outbox, 3)
    outbox.ack(3)
    fill(outbox, 1)
    sender = make_sender(service, outbox, vector_key)
    service.script.append(("status", 409, {"error": "seq_gap", "expectedSeq": 2}))
    outcome = sender.step()
    assert (outcome.kind, outcome.detail) == ("halted", "gap")
    assert sender.step().kind == "halted"
    assert len(service.requests) == 1          # a halted hub does not keep knocking


def test_too_large_halves_the_batch_until_it_fits(service, outbox, vector_key):
    fill(outbox, 8)
    sender = make_sender(service, outbox, vector_key)
    service.script += [("max_events", 3), ("max_events", 3)]
    assert sender.step().kind == "retry_now"   # 8 refused
    assert sender.step().kind == "retry_now"   # 4 refused
    assert sender.step().kind == "sent"        # 2 fit
    assert service.requests[-1]["events"] == [1, 2]
    while sender.step().kind == "sent" and outbox.pending(1):
        pass
    assert outbox.last_acked() == 8


def test_one_event_that_never_fits_halts(service, outbox, vector_key):
    fill(outbox, 1)
    sender = make_sender(service, outbox, vector_key)
    service.script.append(("status", 413, {"error": "too_large"}))
    assert (sender.step().kind, sender.step().detail) == ("halted", "too_large")


def test_rate_limited_waits_as_long_as_it_is_told(service, outbox, vector_key):
    fill(outbox, 1)
    clock = Clock()
    sender = make_sender(service, outbox, vector_key, clock)
    service.script.append(("status", 429, {"error": "rate_limited"}, {"Retry-After": "42"}))
    outcome = sender.step()
    assert (outcome.kind, outcome.wait_seconds) == ("retry_later", 42)
    assert sender.step().kind == "retry_later" and len(service.requests) == 1   # still waiting
    clock.offset += 43
    assert sender.step().kind == "sent"


def test_unavailable_backs_off_longer_each_time_up_to_five_minutes(service, outbox, vector_key):
    fill(outbox, 1)
    clock = Clock()
    sender = make_sender(service, outbox, vector_key, clock)
    waits = []
    for _ in range(12):
        service.script.append(("status", 503, {"error": "unavailable"}))
        outcome = sender.step()
        assert outcome.kind == "retry_later"
        waits.append(outcome.wait_seconds)
        clock.offset += outcome.wait_seconds + 1
    assert waits == sorted(waits) and waits[0] <= 5 and waits[-1] == 300
    assert sender.step().kind == "sent"
    service.script.append(("status", 503, {"error": "unavailable"}))
    fill(outbox, 1)
    assert sender.step().wait_seconds == waits[0]   # a success resets the backoff


def test_a_service_that_is_not_there_is_a_retry_not_a_crash(outbox, vector_key):
    fill(outbox, 1)
    sender = Sender(base_url="http://127.0.0.1:9", source_id=SOURCE, key_id="vector-key-1", private_key=vector_key,
                    outbox=outbox, now=Clock())
    assert sender.step().kind == "retry_later"
    assert outbox.last_acked() == 0


@pytest.mark.parametrize(("status", "body", "reason"), [
    (400, {"error": "schema"}, "schema"),
    (409, {"error": "replay_conflict", "sourceSeq": 1}, "replay_conflict"),
])
def test_a_refusal_no_retry_can_fix_halts_and_keeps_the_events(service, outbox, vector_key, status, body, reason):
    fill(outbox, 2)
    sender = make_sender(service, outbox, vector_key)
    service.script.append(("status", status, body))
    outcome = sender.step()
    assert (outcome.kind, outcome.detail) == ("halted", reason)
    assert sender.step().kind == "halted" and len(service.requests) == 1
    assert len(outbox.pending(10)) == 2


def test_unauthorized_is_not_final_the_sender_says_so_and_tries_again_slowly(service, outbox):
    # The service gives one answer for an unknown key and for a clock that is five minutes off. A clock corrects
    # itself, so this must not stop the hub for good.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    clock = Clock()
    service.now = clock
    sender = Sender(base_url=service.base_url, source_id=SOURCE, key_id="vector-key-1",
                    private_key=Ed25519PrivateKey.generate(), outbox=outbox, now=clock)
    outcome = sender.step()
    assert (outcome.kind, outcome.wait_seconds) == ("retry_later", 300)
    assert (sender.halted, sender.problem) == (None, "unauthorized")
    assert sender.step().kind == "retry_later" and len(service.requests) == 1
    clock.offset += 301
    assert sender.step().kind == "retry_later" and len(service.requests) == 2


def test_a_clock_that_is_off_is_measured_from_the_answer_and_recovers(service, outbox, vector_key):
    hub_clock, service_clock = Clock(), Clock()
    hub_clock.offset = -600                     # the hub is ten minutes behind
    service.now = service_clock
    sender = Sender(base_url=service.base_url, source_id=SOURCE, key_id="vector-key-1", private_key=vector_key,
                    outbox=outbox, now=hub_clock)
    assert sender.step().kind == "retry_later" and sender.problem == "unauthorized"
    assert -602 <= sender.clock_skew_seconds <= -598
    hub_clock.offset = 301                      # the clock was set; the wait is over
    service_clock.offset = 301
    assert sender.step().kind == "sent"
    assert sender.problem is None and abs(sender.clock_skew_seconds) <= 2


def test_a_redirect_is_never_followed(service, outbox, vector_key):
    elsewhere = FakeService(source_id=SOURCE, key_id="vector-key-1", public_key=vector_key.public_key())
    try:
        fill(outbox, 2)
        sender = make_sender(service, outbox, vector_key)
        service.script.append(("status", 302, {}, {"Location": elsewhere.base_url + "/api/ops/evidence/ingest"}))
        assert sender.step().kind == "retry_later"
        assert elsewhere.requests == []          # the signed headers and the events went nowhere else
        assert outbox.last_acked() == 0 and sender.halted is None
    finally:
        elsewhere.close()


@pytest.mark.parametrize("body", [
    {"lastSeq": 2}, {"accepted": 2, "duplicates": 0}, {"accepted": "2", "duplicates": 0, "lastSeq": 2},
    {"accepted": 2, "duplicates": 0, "lastSeq": True}, {},
])
def test_a_200_that_is_not_the_services_answer_confirms_nothing(service, outbox, vector_key, body):
    fill(outbox, 2)
    sender = make_sender(service, outbox, vector_key)
    service.script.append(("status", 200, body))
    assert sender.step().kind == "retry_later"
    assert outbox.last_acked() == 0 and len(outbox.pending(10)) == 2


def test_an_answer_larger_than_the_cap_is_not_read_whole(service, outbox, vector_key):
    fill(outbox, 1)
    sender = make_sender(service, outbox, vector_key)
    service.script.append(("status", 200, {"accepted": 1, "duplicates": 0, "lastSeq": 1, "pad": "x" * 200_000}))
    assert sender.step().kind == "retry_later"   # cut off, so it is not valid JSON, so nothing is confirmed
    assert outbox.last_acked() == 0


def test_an_outbox_that_never_assigned_a_number_learns_where_the_service_stands(service, outbox, vector_key):
    service.last_seq = 41
    sender = make_sender(service, outbox, vector_key)
    outcome = sender.step()
    assert (outcome.kind, outcome.detail, sender.halted) == ("service_ahead", "41", None)
    assert sender.service_last_seq == 41 and outbox.last_assigned() == 0


@pytest.mark.parametrize("base_url", [
    "http://hub.example", "http://localhost.evil.example", "http://127.0.0.1.evil.example:8080", "http://localhost@evil.example",
    "https://user:pw@hub.example", "https://hub.example/prefix", "https://hub.example/?x=1", "https://hub.example/#f",
    "ftp://hub.example", "https://", "hub.example", "https://hub.example:notaport",
])
def test_the_service_address_is_an_https_origin_and_nothing_else(outbox, vector_key, base_url):
    with pytest.raises(ValueError):
        Sender(base_url=base_url, source_id=SOURCE, key_id="vector-key-1", private_key=vector_key, outbox=outbox)


@pytest.mark.parametrize("base_url", ["https://hub.example", "https://hub.example/", "https://hub.example:8443",
                                      "http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"])
def test_accepted_service_addresses(outbox, vector_key, base_url):
    Sender(base_url=base_url, source_id=SOURCE, key_id="vector-key-1", private_key=vector_key, outbox=outbox)


def test_a_confirmation_ahead_of_the_hub_halts(service, outbox, vector_key):
    fill(outbox, 1)
    sender = make_sender(service, outbox, vector_key)
    service.script.append(("status", 200, {"accepted": 1, "duplicates": 0, "lastSeq": 99}))
    assert (sender.step().kind, sender.halted) == ("halted", "ahead")
    assert outbox.last_acked() == 0


def test_a_batch_never_exceeds_500_events(service, outbox, vector_key):
    fill(outbox, 501)
    sender = make_sender(service, outbox, vector_key)
    assert sender.step().detail == "500"
    assert sender.step().detail == "1"
    assert len(service.accepted) == 501


def test_a_batch_stays_under_the_compressed_limit(service, outbox, vector_key):
    import secrets
    for _ in range(40):
        outbox.append("site.device_appeared", AT, {**SEEN, "deviceClass": "printer"},
                      pii={"hostname": secrets.token_hex(120)})
    sender = make_sender(service, outbox, vector_key, max_compressed_bytes=4096)
    while outbox.pending(1):
        assert sender.step().kind == "sent"
    assert max(request["bytes"] for request in service.requests) <= 4096
    assert len(service.accepted) == 40
