# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VECTORS_PATH = Path(__file__).resolve().parents[2] / "spec" / "vectors" / "signing.json"


@pytest.fixture(scope="session")
def vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def vector_key() -> Ed25519PrivateKey:
    """The published TEST key of the vectors: the 32 bytes 0, 1, ... 31. Never a real hub's key."""
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
