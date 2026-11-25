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


def test_an_existing_directory_is_never_changed_and_a_shared_one_is_refused(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    with pytest.raises(KeyStoreError, match="open to other users"):
        FileKeyStore(shared / "hub.key").create()
    assert stat.S_IMODE(os.stat(shared).st_mode) == 0o1777
    assert not (shared / "hub.key").exists()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    FileKeyStore(private / "hub.key").create()
    assert stat.S_IMODE(os.stat(private).st_mode) == 0o700


def test_a_planted_link_at_the_old_temporary_name_is_not_followed(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    for name in (f".hub.key.{os.getpid()}.tmp", "hub.key.tmp"):
        os.symlink(victim, state / name)
    FileKeyStore(state / "hub.key").create()
    assert victim.read_text() == "untouched"
    assert not (state / "hub.key").is_symlink()


def test_a_directory_of_another_user_is_refused(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(state).st_uid + 1)
    with pytest.raises(KeyStoreError, match="another user"):
        FileKeyStore(state / "hub.key").create()


def test_a_key_is_never_under_its_name_half_written(tmp_path, monkeypatch):
    store = FileKeyStore(tmp_path / "hub.key")
    seen = []
    real_link = os.link

    def watch(source, target, **_kwargs):
        # At the moment of installing, the complete key is already on disk under the temporary name.
        seen.append((store.path.exists(), b"END PRIVATE KEY" in open(source, "rb").read()))
        real_link(source, target, **_kwargs)

    monkeypatch.setattr(os, "link", watch)
    store.create()
    assert seen == [(False, True)]


def test_a_failed_write_leaves_no_empty_key_behind(tmp_path, monkeypatch):
    store = FileKeyStore(tmp_path / "hub.key")

    def fail(_descriptor):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError):
        store.create()
    monkeypatch.undo()
    assert not store.path.exists()
    assert list(tmp_path.iterdir()) == []       # no temporary file left either
    store.create()
    store.load()


def test_every_directory_keygen_creates_is_synced_into_its_parent(tmp_path, monkeypatch):
    from spacegoat_hub import keystore
    synced = []
    real = keystore.fsync_directory
    monkeypatch.setattr(keystore, "fsync_directory", lambda directory: (synced.append(directory), real(directory))[1])
    FileKeyStore(tmp_path / "a" / "b" / "hub.key").create()
    assert {tmp_path, tmp_path / "a", tmp_path / "a" / "b"} <= set(synced)


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
