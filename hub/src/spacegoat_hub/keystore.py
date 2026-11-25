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


def fsync_directory(directory: Path) -> None:
    """Make a file's creation or replacement in `directory` survive a power cut, not only its content."""
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def private_file(path: Path) -> None:
    """
    Create `path` for its owner only, or, if it exists, make sure it still is: the hub's state files hold personal
    data (queued events, what was last seen of each device). A file of the hub's own that has become readable by
    others is closed again, not trusted as it is.
    """
    if path.exists():
        if stat.S_IMODE(os.stat(path).st_mode) & 0o077:
            os.chmod(path, 0o600)
        return
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    fsync_directory(path.parent)


class KeyStoreError(Exception):
    """A key store fault. Its message never carries key material."""


class FileKeyStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def create(self) -> None:
        """Generate a key. Never replaces one: a hub's key is its identity, and overwriting it orphans the hub."""
        directory = self.path.parent
        if directory.exists():
            # Never change a directory this call did not create: it may be shared (`/tmp`, `/var/lib`).
            if stat.S_IMODE(os.stat(directory).st_mode) & 0o077:
                raise KeyStoreError(f"{directory} is open to other users; use one only the hub's user can enter")
        else:
            directory.mkdir(parents=True, mode=0o700)
            os.chmod(directory, 0o700)
        pem = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        # Written whole to a temporary file first, then installed under its name in one step. `os.link` fails if the
        # name exists, so a key is still never replaced; and there is no moment at which a half-written key sits
        # under the real name, however the process ends.
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(pem)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, self.path)
            except FileExistsError:
                raise KeyStoreError(f"a key already exists at {self.path}") from None
            fsync_directory(directory)
        finally:
            temporary.unlink(missing_ok=True)

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
