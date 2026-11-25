# SPDX-License-Identifier: AGPL-3.0-or-later
"""Where the hub's private key lives.

The key is what makes a hub that hub: whoever holds it can report as it. It is generated on the device, never
leaves it, and is never printed. This store keeps it in a file only its owner can read; a hardware key store (TPM)
is a later module behind the same two calls.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class KeyStoreError(Exception):
    """A key store fault. Its message never carries key material."""


class FileKeyStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def create(self) -> None:
        """Generate a key. Never replaces one: a hub's key is its identity, and overwriting it orphans the hub."""
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        pem = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        try:
            # O_EXCL: created by this call or not at all; 0600 from the first byte.
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise KeyStoreError(f"a key already exists at {self.path}") from None
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(pem)
            handle.flush()
            os.fsync(handle.fileno())

    def load(self) -> Ed25519PrivateKey:
        try:
            mode = stat.S_IMODE(os.stat(self.path).st_mode)
        except FileNotFoundError:
            raise KeyStoreError(f"no key at {self.path}; run `spacegoat-hub keygen` first") from None
        if mode & 0o077:
            raise KeyStoreError(f"the permissions of {self.path} let others read the key; it must be 0600")
        try:
            key = serialization.load_pem_private_key(self.path.read_bytes(), password=None)
        except Exception:
            # Never the parser's message: it can quote the file.
            raise KeyStoreError(f"{self.path} does not hold a readable key") from None
        if not isinstance(key, Ed25519PrivateKey):
            raise KeyStoreError(f"{self.path} does not hold an Ed25519 key")
        return key
