# SPDX-License-Identifier: AGPL-3.0-or-later
"""The shared vectors every implementation of the protocol is checked against (spec/protocol.md)."""
import re


def test_vectors_carry_every_section(vectors):
    assert re.fullmatch(r"ed25519:[A-Za-z0-9_-]{43}", vectors["publicKey"])
    assert re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", vectors["keyId"])
    assert {"canonical", "events", "request", "pii"} <= set(vectors)
    assert len(vectors["canonical"]) >= 4
    names = [event["name"] for event in vectors["events"]]
    assert any("site device appeared" in name for name in names)
    assert any("with personal data" in name for name in names)
    for event in vectors["events"]:
        assert set(event) == {"name", "input", "messageHex", "signature"}
    assert vectors["request"]["principal"].startswith("source:")
    assert vectors["request"]["method"] == "POST"


def test_vectors_name_nothing_but_examples(vectors):
    text = repr(vectors)
    # Documentation ranges and reserved names only: a vector is public.
    assert "veriteknik" not in text.lower()
    assert "wazuh" not in text.lower()
