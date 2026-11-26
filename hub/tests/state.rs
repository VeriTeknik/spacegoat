// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a hub remembers beside its outbox (the last confirmed sequence, the pseudonyms), and the file primitives
//! everything the hub keeps is written through.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;

use serde_json::{Map, Value, json};
use spacegoat_hub::fsutil::{create_temporary, fsync_directory, private_file, write_atomic};
use spacegoat_hub::state::{Confirmed, Pseudonyms, uuid_v4};
use support::{TempDir, mode};

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

fn names_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn is_uuid_v4(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            14 => *b == b'4',
            19 => matches!(b, b'8' | b'9' | b'a' | b'b'),
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        })
}

// ---- fsutil ----

#[test]
fn write_atomic_writes_a_private_file_and_leaves_no_temporary_behind() {
    let tmp = TempDir::new();
    let path = tmp.join("confirmed.json");
    write_atomic(&path, b"first").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"first");
    assert_eq!(mode(&path), 0o600);
    write_atomic(&path, b"second").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"second");
    assert_eq!(names_in(tmp.path()), vec!["confirmed.json".to_string()]);
}

#[test]
fn write_atomic_replaces_a_link_and_never_writes_through_it() {
    let tmp = TempDir::new();
    let victim = tmp.join("victim");
    std::fs::write(&victim, "untouched").unwrap();
    let path = tmp.join("confirmed.json");
    std::os::unix::fs::symlink(&victim, &path).unwrap();
    write_atomic(&path, b"new").unwrap();
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
    assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
}

#[test]
fn a_failed_write_atomic_leaves_the_old_content_and_no_temporary() {
    let tmp = TempDir::new();
    let path = tmp.join("confirmed.json");
    write_atomic(&path, b"old").unwrap();
    // The rename fails: a directory cannot be replaced by a file. The temporary file was already written.
    let blocked = tmp.join("blocked");
    std::fs::create_dir(&blocked).unwrap();
    std::fs::write(blocked.join("inside"), "x").unwrap();
    write_atomic(&blocked, b"new").unwrap_err();
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
    assert_eq!(
        names_in(tmp.path()),
        vec!["blocked".to_string(), "confirmed.json".to_string()]
    );
}

#[test]
fn temporary_files_have_unpredictable_names_and_are_private() {
    let tmp = TempDir::new();
    let mut names = HashSet::new();
    for _ in 0..50 {
        let (_file, path) = create_temporary(tmp.path(), ".hub.key.").unwrap();
        assert_eq!(mode(&path), 0o600);
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        assert!(name.starts_with(".hub.key."));
        assert!(name.len() >= ".hub.key.".len() + 16, "{name}");
        assert!(names.insert(name));
    }
}

#[test]
fn a_temporary_file_is_created_exclusively() {
    // Whatever name it picks, it never opens something already there; with every name taken it fails, not reuses.
    let tmp = TempDir::new();
    let (_file, path) = create_temporary(tmp.path(), "x").unwrap();
    std::fs::write(&path, "theirs").unwrap();
    let (_other, second) = create_temporary(tmp.path(), "x").unwrap();
    assert_ne!(path, second);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "theirs");
}

#[test]
fn private_file_creates_a_file_only_its_owner_can_read() {
    let tmp = TempDir::new();
    let path = tmp.join("pseudonyms.sqlite");
    private_file(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    // An existing private file is left as it is, content and all.
    std::fs::write(&path, "kept").unwrap();
    private_file(&path).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "kept");
}

#[test]
fn private_file_closes_a_file_that_has_become_readable_by_others() {
    let tmp = TempDir::new();
    let path = tmp.join("outbox.sqlite");
    std::fs::write(&path, "data").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    private_file(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "data");
    // An owner-only mode stricter than 0600 is not loosened.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    private_file(&path).unwrap();
    assert_eq!(mode(&path), 0o400);
}

#[test]
fn private_file_refuses_a_link_and_leaves_its_target_alone() {
    let tmp = TempDir::new();
    let victim = tmp.join("victim");
    std::fs::write(&victim, "untouched").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    let path = tmp.join("outbox.sqlite");
    std::os::unix::fs::symlink(&victim, &path).unwrap();
    private_file(&path).unwrap_err();
    assert_eq!(mode(&victim), 0o644);
    // A dangling link is not followed to create the file elsewhere either.
    let dangling = tmp.join("dangling.sqlite");
    std::os::unix::fs::symlink(tmp.join("nowhere"), &dangling).unwrap();
    private_file(&dangling).unwrap_err();
    assert!(!tmp.join("nowhere").exists());
}

#[test]
fn private_file_refuses_a_directory() {
    let tmp = TempDir::new();
    let path = tmp.join("outbox.sqlite");
    std::fs::create_dir(&path).unwrap();
    private_file(&path).unwrap_err();
}

#[test]
fn a_directory_can_be_synced() {
    let tmp = TempDir::new();
    fsync_directory(tmp.path()).unwrap();
    fsync_directory(&tmp.join("missing")).unwrap_err();
}

// ---- Confirmed ----

#[test]
fn confirmed_is_zero_until_something_is_confirmed() {
    let tmp = TempDir::new();
    let confirmed = Confirmed::new(tmp.join("confirmed.json"));
    assert_eq!(confirmed.read().unwrap(), 0);
    confirmed.write(41).unwrap();
    assert_eq!(confirmed.read().unwrap(), 41);
    assert_eq!(Confirmed::new(tmp.join("confirmed.json")).read().unwrap(), 41);
}

#[test]
fn confirmed_only_moves_forward() {
    let tmp = TempDir::new();
    let confirmed = Confirmed::new(tmp.join("confirmed.json"));
    confirmed.write(41).unwrap();
    confirmed.write(7).unwrap();
    assert_eq!(confirmed.read().unwrap(), 41);
    confirmed.write(41).unwrap();
    confirmed.write(42).unwrap();
    assert_eq!(confirmed.read().unwrap(), 42);
}

#[test]
fn confirmed_is_written_as_the_python_agent_wrote_it_and_privately() {
    let tmp = TempDir::new();
    let path = tmp.join("confirmed.json");
    Confirmed::new(&path).write(41).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"lastAckedSeq": 41}"#);
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn a_damaged_confirmed_file_reads_as_nothing_confirmed() {
    let tmp = TempDir::new();
    let path = tmp.join("confirmed.json");
    for damaged in [
        "",
        "not json",
        "[]",
        "{}",
        r#"{"lastAckedSeq": -1}"#,
        r#"{"lastAckedSeq": 1.5}"#,
        r#"{"lastAckedSeq": 2.0}"#,
        r#"{"lastAckedSeq": true}"#,
        r#"{"lastAckedSeq": "41"}"#,
        r#"{"lastAckedSeq": null}"#,
        "\u{feff}{\"lastAckedSeq\": 41}",
    ] {
        std::fs::write(&path, damaged).unwrap();
        assert_eq!(Confirmed::new(&path).read().unwrap(), 0, "{damaged:?}");
    }
    // Then a write puts it right.
    Confirmed::new(&path).write(3).unwrap();
    assert_eq!(Confirmed::new(&path).read().unwrap(), 3);
}

#[test]
fn a_confirmed_file_the_hub_cannot_read_is_an_error_not_a_zero() {
    // Reading 0 would make the hub declare `reinstall` while it still knows where it stood.
    let tmp = TempDir::new();
    let path = tmp.join("confirmed.json");
    std::fs::create_dir(&path).unwrap();
    Confirmed::new(&path).read().unwrap_err();
}

// ---- Pseudonyms ----

#[test]
fn a_reference_is_a_random_uuid_v4_and_stays_the_same() {
    let tmp = TempDir::new();
    let mut pseudonyms = Pseudonyms::open(&tmp.join("pseudonyms.sqlite")).unwrap();
    let device = pseudonyms.reference("device", "00:00:5e:00:53:01").unwrap();
    assert!(is_uuid_v4(&device), "{device}");
    assert_eq!(pseudonyms.reference("device", "00:00:5e:00:53:01").unwrap(), device);
    let other = pseudonyms.reference("device", "00:00:5e:00:53:02").unwrap();
    assert_ne!(other, device);
    // The same identity in another scope is another reference.
    assert_ne!(pseudonyms.reference("segment", "00:00:5e:00:53:01").unwrap(), device);
    pseudonyms.close().unwrap();
    let mut reopened = Pseudonyms::open(&tmp.join("pseudonyms.sqlite")).unwrap();
    assert_eq!(reopened.reference("device", "00:00:5e:00:53:01").unwrap(), device);
}

#[test]
fn a_reference_is_never_a_function_of_the_identity() {
    let first = TempDir::new();
    let second = TempDir::new();
    let a = Pseudonyms::open(&first.join("p.sqlite"))
        .unwrap()
        .reference("device", "printer")
        .unwrap();
    let b = Pseudonyms::open(&second.join("p.sqlite"))
        .unwrap()
        .reference("device", "printer")
        .unwrap();
    assert_ne!(a, b);
}

#[test]
fn uuid_v4_has_its_version_and_variant_and_the_rest_is_random() {
    let mut seen = HashSet::new();
    let mut variants = HashSet::new();
    let mut ones = [0u32; 128];
    let rounds = 2_000;
    for _ in 0..rounds {
        let text = uuid_v4().unwrap();
        assert!(is_uuid_v4(&text), "{text}");
        variants.insert(text.as_bytes()[19]);
        let hex: String = text.chars().filter(|c| *c != '-').collect();
        let value = u128::from_str_radix(&hex, 16).unwrap();
        for (bit, count) in ones.iter_mut().enumerate() {
            *count += ((value >> bit) & 1) as u32;
        }
        assert!(seen.insert(text));
    }
    // All four variant characters occur: the two free bits there are random too.
    assert_eq!(variants.len(), 4);
    // Every one of the 122 random bits is set in roughly half the values; the 6 fixed bits always or never.
    let fixed: [(usize, u32); 6] = [(76, 0), (77, 0), (78, 1), (79, 0), (62, 0), (63, 1)];
    for (bit, count) in ones.iter().enumerate() {
        match fixed.iter().find(|(b, _)| *b == bit) {
            Some((_, 1)) => assert_eq!(*count, rounds, "bit {bit}"),
            Some(_) => assert_eq!(*count, 0, "bit {bit}"),
            None => assert!((800..1200).contains(count), "bit {bit}: {count}"),
        }
    }
}

#[test]
fn facts_are_empty_before_the_first_report_and_remembered_after() {
    let tmp = TempDir::new();
    let mut pseudonyms = Pseudonyms::open(&tmp.join("pseudonyms.sqlite")).unwrap();
    assert!(pseudonyms.facts("device", "printer").unwrap().is_empty());
    let facts = object(json!({"hostname": "printer.example", "toldAt": "2026-11-25T10:00:00+00:00"}));
    pseudonyms.remember("device", "printer", &facts).unwrap();
    assert_eq!(pseudonyms.facts("device", "printer").unwrap(), facts);
    // Remembering gave the identity a reference, and later calls keep it.
    let reference = pseudonyms.reference("device", "printer").unwrap();
    pseudonyms.remember("device", "printer", &Map::new()).unwrap();
    assert_eq!(pseudonyms.reference("device", "printer").unwrap(), reference);
    assert!(pseudonyms.facts("device", "printer").unwrap().is_empty());
}

#[test]
fn facts_are_stored_with_sorted_keys_as_the_python_agent_stored_them() {
    let tmp = TempDir::new();
    let path = tmp.join("pseudonyms.sqlite");
    let mut pseudonyms = Pseudonyms::open(&path).unwrap();
    pseudonyms
        .remember("device", "printer", &object(json!({"b": 1, "a": "x"})))
        .unwrap();
    pseudonyms.close().unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    let text: String = db
        .query_row(
            "SELECT facts FROM refs WHERE scope = 'device' AND identity = 'printer'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), json!({"a": "x", "b": 1}));
    assert!(text.find("\"a\"").unwrap() < text.find("\"b\"").unwrap());
}

#[test]
fn forget_facts_keeps_the_references() {
    let tmp = TempDir::new();
    let mut pseudonyms = Pseudonyms::open(&tmp.join("pseudonyms.sqlite")).unwrap();
    let printer = pseudonyms.reference("device", "printer").unwrap();
    let lan = pseudonyms.reference("segment", "lan").unwrap();
    pseudonyms
        .remember("device", "printer", &object(json!({"hostname": "printer.example"})))
        .unwrap();
    pseudonyms
        .remember("segment", "lan", &object(json!({"snapshotAt": "x"})))
        .unwrap();
    pseudonyms.forget_facts().unwrap();
    assert!(pseudonyms.facts("device", "printer").unwrap().is_empty());
    assert!(pseudonyms.facts("segment", "lan").unwrap().is_empty());
    assert_eq!(pseudonyms.reference("device", "printer").unwrap(), printer);
    assert_eq!(pseudonyms.reference("segment", "lan").unwrap(), lan);
}

#[test]
fn the_pseudonym_file_is_private_and_durable() {
    let tmp = TempDir::new();
    let path = tmp.join("pseudonyms.sqlite");
    let mut pseudonyms = Pseudonyms::open(&path).unwrap();
    pseudonyms.reference("device", "printer").unwrap();
    assert_eq!(mode(&path), 0o600);
    let db = rusqlite::Connection::open(&path).unwrap();
    let journal: String = db.query_row("PRAGMA journal_mode", [], |row| row.get(0)).unwrap();
    assert_eq!(journal, "wal");
    assert_eq!(pseudonyms.synchronous().unwrap(), 2);
}

#[test]
fn a_pseudonym_file_reached_through_a_link_is_refused() {
    let tmp = TempDir::new();
    let real = tmp.join("real.sqlite");
    Pseudonyms::open(&real).unwrap().close().unwrap();
    std::os::unix::fs::symlink(&real, tmp.join("pseudonyms.sqlite")).unwrap();
    assert!(Pseudonyms::open(&tmp.join("pseudonyms.sqlite")).is_err());
}
