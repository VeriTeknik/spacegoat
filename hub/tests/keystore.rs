// SPDX-License-Identifier: AGPL-3.0-or-later
//! The key store: a hub's key is created once, readable by its owner only, and never replaced or followed through a link.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use spacegoat_hub::keystore::{FileKeyStore, KeyStoreError};
use spacegoat_hub::signing::public_key_text;
use support::{TempDir, mode, vector_key};

fn set_mode(path: &std::path::Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn names_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// The PKCS#8 PEM the Python agent wrote for the published test key (RFC 8410 private key, no public key part).
const VECTOR_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n\
-----END PRIVATE KEY-----\n";

#[test]
fn create_writes_a_key_only_its_owner_can_read() {
    let tmp = TempDir::new();
    let store = FileKeyStore::new(tmp.join("state").join("hub.key"));
    store.create().unwrap();
    assert_eq!(mode(store.path()), 0o600);
    assert_eq!(mode(&tmp.join("state")), 0o700);
    assert!(public_key_text(&store.load().unwrap()).starts_with("ed25519:"));
}

#[test]
fn an_existing_directory_is_never_changed_and_a_shared_one_is_refused() {
    let tmp = TempDir::new();
    let shared = tmp.join("shared");
    std::fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o1777);
    let error = FileKeyStore::new(shared.join("hub.key")).create().unwrap_err();
    assert!(matches!(error, KeyStoreError::DirectoryOpenToOthers(_)), "{error}");
    assert!(error.to_string().contains("open to other users"));
    assert_eq!(mode(&shared), 0o1777);
    assert!(!shared.join("hub.key").exists());
    assert!(names_in(&shared).is_empty());

    let private = tmp.join("private");
    std::fs::create_dir(&private).unwrap();
    set_mode(&private, 0o700);
    FileKeyStore::new(private.join("hub.key")).create().unwrap();
    assert_eq!(mode(&private), 0o700);
}

#[test]
fn a_directory_only_its_group_can_enter_is_refused_too() {
    let tmp = TempDir::new();
    for open in [0o750, 0o710, 0o701, 0o770] {
        let dir = tmp.join(&format!("d{open:o}"));
        std::fs::create_dir(&dir).unwrap();
        set_mode(&dir, open);
        let error = FileKeyStore::new(dir.join("hub.key")).create().unwrap_err();
        assert!(
            matches!(error, KeyStoreError::DirectoryOpenToOthers(_)),
            "{open:o}: {error}"
        );
        assert_eq!(mode(&dir), open);
    }
}

#[test]
fn a_planted_link_at_the_old_temporary_name_is_not_followed() {
    let tmp = TempDir::new();
    let victim = tmp.join("victim");
    std::fs::write(&victim, "untouched").unwrap();
    let state = tmp.join("state");
    std::fs::create_dir(&state).unwrap();
    set_mode(&state, 0o700);
    for name in [".hub.key.tmp", "hub.key.tmp", ".hub.key."] {
        std::os::unix::fs::symlink(&victim, state.join(name)).unwrap();
    }
    let store = FileKeyStore::new(state.join("hub.key"));
    store.create().unwrap();
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
    assert!(
        !std::fs::symlink_metadata(store.path())
            .unwrap()
            .file_type()
            .is_symlink()
    );
    store.load().unwrap();
}

#[test]
fn a_link_planted_at_the_key_name_is_neither_followed_nor_replaced() {
    let tmp = TempDir::new();
    let state = tmp.join("state");
    std::fs::create_dir(&state).unwrap();
    set_mode(&state, 0o700);
    // A dangling link: following it would create the key wherever it points.
    let elsewhere = tmp.join("elsewhere.key");
    std::os::unix::fs::symlink(&elsewhere, state.join("hub.key")).unwrap();
    let error = FileKeyStore::new(state.join("hub.key")).create().unwrap_err();
    assert!(matches!(error, KeyStoreError::AlreadyExists(_)), "{error}");
    assert!(!elsewhere.exists());
    assert_eq!(names_in(&state), vec!["hub.key".to_string()]);
}

#[test]
fn a_directory_of_another_user_is_refused() {
    let tmp = TempDir::new();
    let state = tmp.join("state");
    std::fs::create_dir(&state).unwrap();
    set_mode(&state, 0o700);
    let theirs = std::fs::metadata(&state).unwrap().uid() + 1;
    let error = FileKeyStore::new(state.join("hub.key"))
        .expecting_owner(theirs)
        .create()
        .unwrap_err();
    assert!(matches!(error, KeyStoreError::DirectoryOfAnotherUser(_)), "{error}");
    assert!(error.to_string().contains("another user"));
    // Nothing was left in it, not even the temporary file.
    assert!(names_in(&state).is_empty());
}

#[test]
fn a_failed_create_leaves_no_key_and_no_temporary_file_behind() {
    // Python failed `fsync` to get here; Rust cannot intercept a system call, so the failure after the temporary
    // file was written is the refusal to replace an existing key and the refusal of another user's directory above.
    let tmp = TempDir::new();
    let store = FileKeyStore::new(tmp.join("hub.key"));
    store.create().unwrap();
    store.create().unwrap_err();
    assert_eq!(names_in(tmp.path()), vec!["hub.key".to_string()]);
}

#[test]
fn every_missing_directory_is_created_and_the_state_directory_is_private() {
    let tmp = TempDir::new();
    let store = FileKeyStore::new(tmp.join("a").join("b").join("hub.key"));
    store.create().unwrap();
    assert!(tmp.join("a").is_dir());
    assert_eq!(mode(&tmp.join("a").join("b")), 0o700);
    store.load().unwrap();
}

#[test]
fn load_returns_the_key_that_was_created() {
    let tmp = TempDir::new();
    let store = FileKeyStore::new(tmp.join("hub.key"));
    store.create().unwrap();
    assert_eq!(
        public_key_text(&store.load().unwrap()),
        public_key_text(&FileKeyStore::new(store.path()).load().unwrap())
    );
}

#[test]
fn two_created_keys_differ() {
    let tmp = TempDir::new();
    let first = FileKeyStore::new(tmp.join("one.key"));
    let second = FileKeyStore::new(tmp.join("two.key"));
    first.create().unwrap();
    second.create().unwrap();
    assert_ne!(
        public_key_text(&first.load().unwrap()),
        public_key_text(&second.load().unwrap())
    );
}

#[test]
fn create_never_replaces_an_existing_key() {
    let tmp = TempDir::new();
    let store = FileKeyStore::new(tmp.join("hub.key"));
    store.create().unwrap();
    let before = std::fs::read(store.path()).unwrap();
    let error = store.create().unwrap_err();
    assert!(matches!(error, KeyStoreError::AlreadyExists(_)), "{error}");
    assert!(error.to_string().contains("already exists"));
    assert_eq!(std::fs::read(store.path()).unwrap(), before);
}

#[test]
fn a_key_others_can_read_is_not_loaded() {
    for loose in [0o640, 0o604, 0o644, 0o660, 0o610, 0o601] {
        let tmp = TempDir::new();
        let store = FileKeyStore::new(tmp.join("hub.key"));
        store.create().unwrap();
        set_mode(store.path(), loose);
        let error = store.load().unwrap_err();
        assert!(matches!(error, KeyStoreError::Permissions(_)), "{loose:o}: {error}");
        assert!(error.to_string().contains("permissions"));
    }
}

#[test]
fn a_key_only_its_owner_can_read_loads_whatever_the_owner_bits() {
    let tmp = TempDir::new();
    let store = FileKeyStore::new(tmp.join("hub.key"));
    store.create().unwrap();
    set_mode(store.path(), 0o400);
    store.load().unwrap();
}

#[test]
fn a_missing_or_damaged_key_says_so_without_printing_it() {
    let tmp = TempDir::new();
    let store = FileKeyStore::new(tmp.join("hub.key"));
    let error = store.load().unwrap_err();
    assert!(matches!(error, KeyStoreError::NoKey(_)), "{error}");
    assert!(error.to_string().contains("no key"));
    std::fs::write(store.path(), b"not a key at all").unwrap();
    set_mode(store.path(), 0o600);
    let error = store.load().unwrap_err();
    assert!(matches!(error, KeyStoreError::NotAKey(_)), "{error}");
    assert!(!error.to_string().contains("not a key at all"));
}

#[test]
fn a_key_reached_through_a_link_is_not_loaded() {
    let tmp = TempDir::new();
    let real = FileKeyStore::new(tmp.join("real.key"));
    real.create().unwrap();
    std::os::unix::fs::symlink(real.path(), tmp.join("hub.key")).unwrap();
    let error = FileKeyStore::new(tmp.join("hub.key")).load().unwrap_err();
    assert!(matches!(error, KeyStoreError::NotAFile(_)), "{error}");
}

#[test]
fn a_directory_at_the_key_name_is_not_a_key() {
    let tmp = TempDir::new();
    std::fs::create_dir(tmp.join("hub.key")).unwrap();
    set_mode(&tmp.join("hub.key"), 0o700);
    let error = FileKeyStore::new(tmp.join("hub.key")).load().unwrap_err();
    assert!(matches!(error, KeyStoreError::NotAFile(_)), "{error}");
}

#[test]
fn the_key_file_is_the_pkcs8_pem_the_python_agent_wrote() {
    let tmp = TempDir::new();
    let path = tmp.join("hub.key");
    std::fs::write(&path, VECTOR_KEY_PEM).unwrap();
    set_mode(&path, 0o600);
    let key = FileKeyStore::new(&path).load().unwrap();
    assert_eq!(public_key_text(&key), public_key_text(&vector_key()));

    // And a created key has exactly that layout: one 64-character base64 line between the armour lines.
    let created = FileKeyStore::new(tmp.join("new.key"));
    created.create().unwrap();
    let text = std::fs::read_to_string(created.path()).unwrap();
    let lines: Vec<&str> = text.split('\n').collect();
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert_eq!(lines[0], "-----BEGIN PRIVATE KEY-----");
    assert_eq!(lines[1].len(), 64);
    assert!(lines[1].starts_with("MC4CAQAwBQYDK2VwBCIEI"));
    assert_eq!(lines[2], "-----END PRIVATE KEY-----");
    assert_eq!(lines[3], "");
}

#[test]
fn a_key_of_the_wrong_length_or_kind_is_refused() {
    let tmp = TempDir::new();
    let path = tmp.join("hub.key");
    let body = |b64: &str| format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");
    let cases = [
        // 47 bytes: the seed is one byte short.
        body("MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4="),
        // 49 bytes: a byte too many.
        body("MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIA=="),
        // X25519 (OID 1.3.101.110), the same length: a key, but not one that signs.
        body("MC4CAQAwBQYDK2VuBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"),
        // Something after the armour.
        format!("{VECTOR_KEY_PEM}trailing\n"),
        // Another armour.
        VECTOR_KEY_PEM.replace("PRIVATE KEY", "ENCRYPTED PRIVATE KEY"),
        // An empty file.
        String::new(),
    ];
    for case in &cases {
        std::fs::write(&path, case).unwrap();
        set_mode(&path, 0o600);
        let error = FileKeyStore::new(&path).load().unwrap_err();
        assert!(matches!(error, KeyStoreError::NotAKey(_)), "{case:?}: {error}");
    }
}

#[test]
fn a_huge_file_is_not_read_whole() {
    let tmp = TempDir::new();
    let path = tmp.join("hub.key");
    std::fs::write(&path, vec![b'A'; 10 * 1024 * 1024]).unwrap();
    set_mode(&path, 0o600);
    let error = FileKeyStore::new(&path).load().unwrap_err();
    assert!(matches!(error, KeyStoreError::NotAKey(_)), "{error}");
}

#[test]
fn errors_never_carry_key_material() {
    let tmp = TempDir::new();
    let store = FileKeyStore::new(tmp.join("hub.key"));
    store.create().unwrap();
    let pem = std::fs::read_to_string(store.path()).unwrap();
    let secret_line = pem.lines().nth(1).unwrap().to_string();
    set_mode(store.path(), 0o644);
    let loose = store.load().unwrap_err();
    let exists = store.create().unwrap_err();
    for error in [loose, exists] {
        assert!(!error.to_string().contains(&secret_line));
        assert!(!format!("{error:?}").contains(&secret_line));
    }
}
