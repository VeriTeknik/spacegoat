# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import stat

import pytest

from spacegoat_hub.keystore import FileKeyStore, KeyStoreError
from spacegoat_hub.signing import public_key_text


def test_create_writes_a_key_only_its_owner_can_read(tmp_path):
    store = FileKeyStore(tmp_path / "state" / "hub.key")
    store.create()
    mode = stat.S_IMODE(os.stat(store.path).st_mode)
    assert mode == 0o600
    assert stat.S_IMODE(os.stat(store.path.parent).st_mode) == 0o700
    assert public_key_text(store.load()).startswith("ed25519:")


def test_load_returns_the_key_that_was_created(tmp_path):
    store = FileKeyStore(tmp_path / "hub.key")
    store.create()
    assert public_key_text(store.load()) == public_key_text(FileKeyStore(store.path).load())


def test_create_never_replaces_an_existing_key(tmp_path):
    store = FileKeyStore(tmp_path / "hub.key")
    store.create()
    before = store.path.read_bytes()
    with pytest.raises(KeyStoreError, match="already exists"):
        store.create()
    assert store.path.read_bytes() == before


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660])
def test_a_key_others_can_read_is_not_loaded(tmp_path, mode):
    store = FileKeyStore(tmp_path / "hub.key")
    store.create()
    os.chmod(store.path, mode)
    with pytest.raises(KeyStoreError, match="permissions"):
        store.load()


def test_a_missing_or_damaged_key_says_so_without_printing_it(tmp_path):
    store = FileKeyStore(tmp_path / "hub.key")
    with pytest.raises(KeyStoreError, match="no key"):
        store.load()
    store.path.write_bytes(b"not a key at all")
    os.chmod(store.path, 0o600)
    with pytest.raises(KeyStoreError) as caught:
        store.load()
    assert "not a key at all" not in str(caught.value)
