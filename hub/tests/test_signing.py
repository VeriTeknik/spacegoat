# SPDX-License-Identifier: AGPL-3.0-or-later
"""The signing code against the published vectors: the bytes signed and the signature, exactly."""
import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from spacegoat_hub import signing


def _event_message(event_input):
    return signing.event_signing_message(
        source_id=event_input["sourceId"], source_seq=event_input["sourceSeq"], kind=event_input["kind"],
        observed_at=event_input["observedAt"], attributes=event_input["attributes"],
        pii_commitment=event_input["piiCommitment"],
    )


def test_the_vector_key_is_the_published_test_key(vectors, vector_key):
    # The private bytes are 0, 1, ... 31 (spec/README.md); they are not written into the vector file itself, where a
    # secret scanner would take them for a leaked key.
    assert signing.public_key_text(vector_key) == vectors["publicKey"]


def test_every_event_vector_signs_to_the_same_bytes_and_signature(vectors, vector_key):
    for event in vectors["events"]:
        message = _event_message(event["input"])
        assert message.hex() == event["messageHex"], event["name"]
        assert signing.sign(vector_key, message) == event["signature"], event["name"]


def test_event_signatures_verify_with_the_public_key_alone(vectors, vector_key):
    public: Ed25519PublicKey = vector_key.public_key()
    for event in vectors["events"]:
        padded = event["signature"] + "=" * (-len(event["signature"]) % 4)
        public.verify(base64.urlsafe_b64decode(padded), bytes.fromhex(event["messageHex"]))


def test_the_request_vector(vectors, vector_key):
    request = vectors["request"]
    message = signing.request_signing_message(
        principal=request["principal"], method=request["method"], path=request["path"],
        timestamp=request["timestamp"], body=bytes.fromhex(request["bodyHex"]),
    )
    assert message.hex() == request["messageHex"]
    assert signing.sign(vector_key, message) == request["signature"]


def test_a_request_signature_is_bound_to_method_path_time_and_body(vectors):
    request = vectors["request"]
    base = dict(principal=request["principal"], method="POST", path=request["path"], timestamp=request["timestamp"],
                body=bytes.fromhex(request["bodyHex"]))
    original = signing.request_signing_message(**base)
    for change in ({"method": "GET"}, {"path": request["path"] + "?x=1"}, {"timestamp": "1"}, {"body": b"{}"},
                   {"principal": "source:00000000-0000-4000-8000-000000000000"}):
        assert signing.request_signing_message(**{**base, **change}) != original, change


def test_the_personal_data_commitment(vectors):
    pii = vectors["pii"]
    assert signing.pii_commitment(pii["nonceHex"], pii["payload"]) == pii["commitment"]
    with_pii = next(e for e in vectors["events"] if "with personal data" in e["name"])
    assert with_pii["input"]["piiCommitment"] == pii["commitment"]
    # The personal data itself is nowhere in what is signed.
    signed = bytes.fromhex(with_pii["messageHex"]).decode()
    for value in pii["payload"].values():
        assert value not in signed
    assert signing.pii_commitment("cd" * 32, pii["payload"]) != pii["commitment"]


@pytest.mark.parametrize("nonce", ["", "ab" * 31, "AB" * 32, "zz" * 32])
def test_a_malformed_nonce_is_refused(nonce):
    with pytest.raises(ValueError):
        signing.pii_commitment(nonce, {"ip": "192.0.2.1"})


@pytest.mark.parametrize(
    "observed_at", ["2026-11-24T10:00:00Z", "2026-11-24T13:00:00.000+03:00", "2026-11-24 10:00:00.000Z", ""]
)
def test_observed_at_is_utc_with_milliseconds(observed_at):
    with pytest.raises(ValueError):
        signing.event_signing_message(source_id="s", source_seq=1, kind="site.device_seen", observed_at=observed_at,
                                      attributes={}, pii_commitment=None)


def test_a_stored_signature_names_its_key():
    assert signing.stored_signature("hub-key-1", "abc") == "ed25519:hub-key-1:abc"
    for bad in ("K", "ab", "Hub-Key", "a" * 64):
        with pytest.raises(ValueError):
            signing.stored_signature(bad, "abc")
