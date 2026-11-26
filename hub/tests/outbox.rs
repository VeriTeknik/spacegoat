// SPDX-License-Identifier: AGPL-3.0-or-later
//! The outbox: every event gets its place in the sequence and its signature once, on disk, before anything is sent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, SigningKey, Verifier};
use serde_json::{Map, Value, json};
use spacegoat_hub::clock;
use spacegoat_hub::outbox::{Outbox, OutboxError, ResetReason, StoredEvent};
use spacegoat_hub::signing::{self, EventFields};
use support::{TempDir, mode, vector_key};

const SOURCE: &str = "01234567-89ab-4cde-8fab-0123456789ab";
const DEVICE: &str = "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b";
const SEGMENT: &str = "0c0c0c0c-0c0c-4c0c-8c0c-0c0c0c0c0c0c";
const AT: &str = "2026-11-25T10:00:00.000Z";
const KEY_ID: &str = "vector-key-1";

fn seen() -> Map<String, Value> {
    object(json!({"trustOrigin": "hub", "deviceRef": DEVICE, "segmentRef": SEGMENT}))
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

fn outbox_path(tmp: &TempDir) -> PathBuf {
    tmp.join("outbox.sqlite")
}

fn open_outbox(tmp: &TempDir, key: SigningKey) -> Outbox {
    Outbox::open(&outbox_path(tmp), SOURCE, KEY_ID, key).unwrap()
}

fn parsed(event: &StoredEvent) -> Value {
    serde_json::from_str(&event.json).unwrap()
}

fn seqs(events: &[StoredEvent]) -> Vec<u64> {
    events
        .iter()
        .map(|event| {
            let value = parsed(event);
            assert_eq!(value["sourceSeq"].as_u64(), Some(event.seq));
            event.seq
        })
        .collect()
}

/// The stored signature verifies against the fields the service will rebuild the message from.
fn verify(key: &SigningKey, event: &Value) {
    assert!(verifies(key, event), "{event}");
}

fn verifies(key: &SigningKey, event: &Value) -> bool {
    let parts: Vec<&str> = event["signature"].as_str().unwrap().split(':').collect();
    assert_eq!((parts[0], parts[1]), ("ed25519", KEY_ID));
    let message = signing::event_signing_message(&EventFields {
        source_id: SOURCE,
        source_seq: event["sourceSeq"].as_u64().unwrap(),
        kind: event["kind"].as_str().unwrap(),
        observed_at: event["observedAt"].as_str().unwrap(),
        attributes: &event["attributes"],
        pii_commitment: event.get("piiCommitment").and_then(Value::as_str),
    })
    .unwrap();
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    key.verifying_key().verify(&message, &signature).is_ok()
}

/// A fixed moment for the reset event, derived from the clock itself so it never has to be written as a date.
fn fixed_moment() -> i64 {
    clock::observed_at_millis(AT).unwrap() + 1_234
}

/// A trigger installed from a second connection makes the outbox's own update of `last_assigned` fail, inside the
/// transaction, after the event row has been inserted: the process "dies" between the insert and the commit.
fn make_the_counter_update_fail(path: &Path) {
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER die BEFORE UPDATE ON meta WHEN NEW.key = 'last_assigned' \
         BEGIN SELECT RAISE(ABORT, 'the process died here'); END",
    )
    .unwrap();
}

fn remove_the_failure(path: &Path) {
    rusqlite::Connection::open(path)
        .unwrap()
        .execute_batch("DROP TRIGGER die")
        .unwrap();
}

#[test]
fn the_sequence_starts_at_one_and_has_no_gap() {
    let tmp = TempDir::new();
    let key = vector_key();
    let mut outbox = open_outbox(&tmp, key.clone());
    let assigned: Vec<u64> = (0..3)
        .map(|_| outbox.append("site.device_seen", AT, &seen(), None).unwrap())
        .collect();
    assert_eq!(assigned, vec![1, 2, 3]);
    let events = outbox.pending(10, None).unwrap();
    assert_eq!(seqs(&events), vec![1, 2, 3]);
    for event in &events {
        verify(&key, &parsed(event));
    }
    assert_eq!((outbox.last_assigned().unwrap(), outbox.last_acked().unwrap()), (3, 0));
}

#[test]
fn reopening_continues_the_sequence_and_returns_the_same_bytes() {
    let tmp = TempDir::new();
    let mut first = open_outbox(&tmp, vector_key());
    first.append("site.device_seen", AT, &seen(), None).unwrap();
    let pii = object(json!({"mac": "00005e005301"}));
    first.append("site.device_appeared", AT, &seen(), Some(&pii)).unwrap();
    let stored = first.pending(10, None).unwrap();
    // Read twice from the same connection: the same bytes, the same nonce.
    assert_eq!(first.pending(10, None).unwrap(), stored);
    first.close().unwrap();
    let mut second = open_outbox(&tmp, vector_key());
    assert_eq!(second.pending(10, None).unwrap(), stored);
    assert_eq!(second.append("site.device_seen", AT, &seen(), None).unwrap(), 3);
}

#[test]
fn a_stored_event_is_never_signed_again() {
    // Reopened with another key (a key rotation, say), the queued events keep the signature they were given.
    let tmp = TempDir::new();
    let key = vector_key();
    let mut first = open_outbox(&tmp, key.clone());
    first.append("site.device_seen", AT, &seen(), None).unwrap();
    let stored = first.pending(10, None).unwrap();
    first.close().unwrap();
    let other = SigningKey::from_bytes(&[7u8; 32]);
    let mut second = open_outbox(&tmp, other.clone());
    assert_eq!(second.pending(10, None).unwrap(), stored);
    verify(&key, &parsed(&stored[0]));
    second.append("site.device_seen", AT, &seen(), None).unwrap();
    let events = second.pending(10, None).unwrap();
    verify(&key, &parsed(&events[0]));
    verify(&other, &parsed(&events[1]));
}

#[test]
fn the_stored_text_is_the_canonical_json_of_the_event() {
    let tmp = TempDir::new();
    let mut outbox = open_outbox(&tmp, vector_key());
    let pii = object(json!({"hostname": "printer.example", "mac": "00005e005301"}));
    outbox.append("site.device_appeared", AT, &seen(), Some(&pii)).unwrap();
    let event = &outbox.pending(1, None).unwrap()[0];
    assert_eq!(
        spacegoat_hub::canonical::canonical_json(&parsed(event)).unwrap(),
        event.json
    );
    let value = parsed(event);
    let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        vec![
            "attributes",
            "kind",
            "observedAt",
            "pii",
            "piiCommitment",
            "piiNonce",
            "signature",
            "sourceSeq"
        ]
    );
}

#[test]
fn ack_forgets_delivered_events_and_only_moves_forward() {
    let tmp = TempDir::new();
    let mut outbox = open_outbox(&tmp, vector_key());
    for _ in 0..4 {
        outbox.append("site.device_seen", AT, &seen(), None).unwrap();
    }
    outbox.ack(2).unwrap();
    assert_eq!(seqs(&outbox.pending(10, None).unwrap()), vec![3, 4]);
    outbox.ack(1).unwrap();
    assert_eq!(outbox.last_acked().unwrap(), 2);
    let error = outbox.ack(9).unwrap_err();
    assert!(matches!(error, OutboxError::AckAhead), "{error}");
    assert!(error.to_string().contains("ahead"));
    assert_eq!(outbox.last_acked().unwrap(), 2);
    assert_eq!(seqs(&outbox.pending(10, None).unwrap()), vec![3, 4]);
    // An ack of what was already confirmed, and of nothing, changes nothing.
    outbox.ack(2).unwrap();
    outbox.ack(0).unwrap();
    assert_eq!(outbox.last_acked().unwrap(), 2);
    outbox.ack(4).unwrap();
    assert!(outbox.pending(10, None).unwrap().is_empty());
    assert_eq!(outbox.last_acked().unwrap(), 4);
    outbox.close().unwrap();
    let reopened = open_outbox(&tmp, vector_key());
    assert_eq!(
        (reopened.last_assigned().unwrap(), reopened.last_acked().unwrap()),
        (4, 4)
    );
}

#[test]
fn pending_from_a_sequence_and_with_a_limit() {
    let tmp = TempDir::new();
    let mut outbox = open_outbox(&tmp, vector_key());
    for _ in 0..5 {
        outbox.append("site.device_seen", AT, &seen(), None).unwrap();
    }
    assert_eq!(seqs(&outbox.pending(2, None).unwrap()), vec![1, 2]);
    assert_eq!(seqs(&outbox.pending(10, Some(4)).unwrap()), vec![4, 5]);
    assert!(outbox.pending(0, None).unwrap().is_empty());
    assert!(outbox.pending(10, Some(6)).unwrap().is_empty());
    assert_eq!(seqs(&outbox.pending(usize::MAX, None).unwrap()), vec![1, 2, 3, 4, 5]);
    assert_eq!(seqs(&outbox.pending(10, Some(u64::MAX)).unwrap()), Vec::<u64>::new());
}

#[test]
fn personal_data_travels_as_the_triple_and_only_its_commitment_is_signed() {
    let tmp = TempDir::new();
    let key = vector_key();
    let mut outbox = open_outbox(&tmp, key.clone());
    let pii = object(json!({"mac": "00005e005301", "hostname": "printer.example", "ip": "192.0.2.10"}));
    let mut attributes = seen();
    attributes.insert("deviceClass".into(), json!("printer"));
    outbox
        .append("site.device_appeared", AT, &attributes, Some(&pii))
        .unwrap();
    outbox
        .append("site.device_appeared", AT, &attributes, Some(&pii))
        .unwrap();
    let events = outbox.pending(10, None).unwrap();
    let (first, second) = (parsed(&events[0]), parsed(&events[1]));
    assert_eq!(first["pii"], Value::Object(pii.clone()));
    let nonce = first["piiNonce"].as_str().unwrap();
    assert_eq!(nonce.len(), 64);
    assert!(nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert_eq!(
        first["piiCommitment"].as_str().unwrap(),
        signing::pii_commitment(nonce, &Value::Object(pii.clone())).unwrap()
    );
    assert_ne!(first["piiNonce"], second["piiNonce"]);
    assert_ne!(first["piiCommitment"], second["piiCommitment"]);
    for name in pii.keys() {
        assert!(!first["attributes"].as_object().unwrap().contains_key(name));
    }
    verify(&key, &first);
    verify(&key, &second);
    // The signature covers the commitment, not the personal data: change the commitment and it no longer verifies.
    let mut forged = first.clone();
    forged["piiCommitment"] = json!("0".repeat(64));
    assert!(!verifies(&key, &forged));

    outbox.append("site.device_seen", AT, &seen(), None).unwrap();
    let third = parsed(&outbox.pending(10, None).unwrap()[2]);
    for name in ["pii", "piiNonce", "piiCommitment"] {
        assert!(third.get(name).is_none(), "{name}");
    }
}

#[test]
fn an_event_that_cannot_be_signed_takes_no_sequence_number() {
    let tmp = TempDir::new();
    let mut outbox = open_outbox(&tmp, vector_key());
    let error = outbox
        .append("site.device_seen", "2026-11-25 10:00", &seen(), None)
        .unwrap_err();
    assert!(matches!(error, OutboxError::Signing(_)), "{error}");
    let mut with_float = seen();
    with_float.insert("ratio".into(), json!(0.5));
    let error = outbox.append("site.device_seen", AT, &with_float, None).unwrap_err();
    assert!(matches!(error, OutboxError::Signing(_)), "{error}");
    let float_pii = object(json!({"ratio": 0.5}));
    let error = outbox
        .append("site.device_seen", AT, &seen(), Some(&float_pii))
        .unwrap_err();
    assert!(matches!(error, OutboxError::Signing(_)), "{error}");
    assert_eq!(outbox.last_assigned().unwrap(), 0);
    assert!(outbox.pending(10, None).unwrap().is_empty());
    assert_eq!(outbox.append("site.device_seen", AT, &seen(), None).unwrap(), 1);
}

#[test]
fn a_write_that_dies_before_commit_leaves_neither_event_nor_number() {
    let tmp = TempDir::new();
    let path = outbox_path(&tmp);
    let mut outbox = open_outbox(&tmp, vector_key());
    outbox.append("site.device_seen", AT, &seen(), None).unwrap();
    make_the_counter_update_fail(&path);
    let error = outbox.append("site.device_seen", AT, &seen(), None).unwrap_err();
    assert!(matches!(error, OutboxError::Sqlite(_)), "{error}");
    // In the same connection: no event 2 was left behind by the failed transaction.
    assert_eq!(seqs(&outbox.pending(10, None).unwrap()), vec![1]);
    assert_eq!(outbox.last_assigned().unwrap(), 1);
    outbox.close().unwrap();
    remove_the_failure(&path);
    let mut again = open_outbox(&tmp, vector_key());
    assert_eq!(again.last_assigned().unwrap(), 1);
    assert_eq!(again.append("site.device_seen", AT, &seen(), None).unwrap(), 2);
    assert_eq!(seqs(&again.pending(10, None).unwrap()), vec![1, 2]);
}

#[test]
fn a_reset_that_dies_before_commit_leaves_the_outbox_empty() {
    let tmp = TempDir::new();
    let path = outbox_path(&tmp);
    let mut outbox = open_outbox(&tmp, vector_key());
    make_the_counter_update_fail(&path);
    outbox
        .declare_reset(41, ResetReason::QueueLost, fixed_moment())
        .unwrap_err();
    // `last_acked` was written first in that transaction; it went with the rest.
    assert_eq!((outbox.last_assigned().unwrap(), outbox.last_acked().unwrap()), (0, 0));
    assert!(outbox.pending(10, None).unwrap().is_empty());
    remove_the_failure(&path);
    assert_eq!(
        outbox
            .declare_reset(41, ResetReason::QueueLost, fixed_moment())
            .unwrap(),
        42
    );
}

#[test]
fn a_process_killed_while_appending_leaves_a_gapless_verifiable_queue() {
    // The child is this test binary, running only the helper below, appending until it is killed (SIGKILL).
    let tmp = TempDir::new();
    let path = outbox_path(&tmp);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "append_until_killed",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SPACEGOAT_TEST_OUTBOX", &path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let (assigned, _) = Outbox::read_counters(&path).unwrap_or((0, 0));
        if assigned >= 50 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "the child never appended");
        assert!(child.try_wait().unwrap().is_none(), "the child ended by itself");
        std::thread::sleep(Duration::from_millis(5));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    let key = vector_key();
    let outbox = open_outbox(&tmp, key.clone());
    let assigned = outbox.last_assigned().unwrap();
    assert!(assigned >= 50);
    let events = outbox.pending(usize::MAX, None).unwrap();
    assert_eq!(seqs(&events), (1..=assigned).collect::<Vec<_>>());
    for event in &events {
        verify(&key, &parsed(event));
    }
}

/// Not a test on its own: the child process of the test above.
#[test]
#[ignore = "run by a_process_killed_while_appending_leaves_a_gapless_verifiable_queue"]
fn append_until_killed() {
    let Some(path) = std::env::var_os("SPACEGOAT_TEST_OUTBOX") else {
        return;
    };
    let mut outbox = Outbox::open(Path::new(&path), SOURCE, KEY_ID, vector_key()).unwrap();
    let pii = object(json!({"mac": "00005e005301"}));
    for _ in 0..1_000_000 {
        outbox.append("site.device_appeared", AT, &seen(), Some(&pii)).unwrap();
    }
}

#[test]
fn an_outbox_belongs_to_one_source() {
    let tmp = TempDir::new();
    open_outbox(&tmp, vector_key()).close().unwrap();
    let error = Outbox::open(
        &outbox_path(&tmp),
        "99999999-9999-4999-8999-999999999999",
        KEY_ID,
        vector_key(),
    )
    .unwrap_err();
    assert!(matches!(error, OutboxError::AnotherSource), "{error}");
    assert!(error.to_string().contains("another source"));
}

#[test]
fn an_outbox_is_not_opened_with_a_key_id_it_could_not_sign_with() {
    let tmp = TempDir::new();
    let error = Outbox::open(&outbox_path(&tmp), SOURCE, "Not A Key Id", vector_key()).unwrap_err();
    assert!(
        matches!(error, OutboxError::Signing(signing::SigningError::KeyId)),
        "{error}"
    );
}

#[test]
fn a_reset_is_declared_with_what_the_service_last_confirmed() {
    let tmp = TempDir::new();
    let key = vector_key();
    let mut outbox = open_outbox(&tmp, key.clone());
    let seq = outbox
        .declare_reset(41, ResetReason::QueueLost, fixed_moment())
        .unwrap();
    assert_eq!(seq, 42);
    let events = outbox.pending(10, None).unwrap();
    assert_eq!(events.len(), 1);
    let event = parsed(&events[0]);
    assert_eq!(event["kind"], "site_source.reset");
    assert_eq!(
        event["attributes"],
        json!({"trustOrigin": "hub", "lastAckedSeq": 41, "reason": "queue_lost"})
    );
    assert_eq!(event["observedAt"], clock::observed_at_text(fixed_moment()).unwrap());
    verify(&key, &event);
    assert_eq!(
        (outbox.last_assigned().unwrap(), outbox.last_acked().unwrap()),
        (42, 41)
    );
    assert_eq!(outbox.append("site.device_seen", AT, &seen(), None).unwrap(), 43);
    let error = outbox
        .declare_reset(50, ResetReason::QueueLost, fixed_moment())
        .unwrap_err();
    assert!(matches!(error, OutboxError::ResetOnNonEmpty), "{error}");
    assert!(error.to_string().contains("empty"));
}

#[test]
fn a_reinstall_reset_from_nothing_is_number_one() {
    let tmp = TempDir::new();
    let mut outbox = open_outbox(&tmp, vector_key());
    assert_eq!(
        outbox.declare_reset(0, ResetReason::Reinstall, fixed_moment()).unwrap(),
        1
    );
    let event = parsed(&outbox.pending(10, None).unwrap()[0]);
    assert_eq!(event["attributes"]["reason"], "reinstall");
    assert_eq!(event["attributes"]["lastAckedSeq"], 0);
}

#[test]
fn a_reset_at_a_moment_the_protocol_cannot_write_takes_nothing() {
    let tmp = TempDir::new();
    let mut outbox = open_outbox(&tmp, vector_key());
    outbox.declare_reset(41, ResetReason::QueueLost, i64::MAX).unwrap_err();
    // A sequence number past the safe integer range cannot be signed either.
    outbox
        .declare_reset(9_007_199_254_740_991, ResetReason::QueueLost, fixed_moment())
        .unwrap_err();
    assert_eq!((outbox.last_assigned().unwrap(), outbox.last_acked().unwrap()), (0, 0));
}

#[test]
fn the_oldest_pending_observation_time_follows_the_acks() {
    let tmp = TempDir::new();
    let mut outbox = open_outbox(&tmp, vector_key());
    assert_eq!(outbox.oldest_pending_observed_at().unwrap(), None);
    let base = clock::observed_at_millis(AT).unwrap();
    for offset in [0, 1_000, 2_000] {
        let at = clock::observed_at_text(base + offset).unwrap();
        outbox.append("site.device_seen", &at, &seen(), None).unwrap();
    }
    assert_eq!(outbox.oldest_pending_observed_at().unwrap().as_deref(), Some(AT));
    outbox.ack(1).unwrap();
    assert_eq!(
        outbox.oldest_pending_observed_at().unwrap(),
        clock::observed_at_text(base + 1_000)
    );
    outbox.ack(3).unwrap();
    assert_eq!(outbox.oldest_pending_observed_at().unwrap(), None);
}

#[test]
fn the_counters_are_read_without_creating_or_holding_the_outbox() {
    let tmp = TempDir::new();
    let path = outbox_path(&tmp);
    assert_eq!(Outbox::read_counters(&path).unwrap(), (0, 0));
    assert!(!path.exists(), "reading the counters created the file");
    let mut outbox = open_outbox(&tmp, vector_key());
    for _ in 0..3 {
        outbox.append("site.device_seen", AT, &seen(), None).unwrap();
    }
    outbox.ack(2).unwrap();
    // While the agent holds it open, and after.
    assert_eq!(Outbox::read_counters(&path).unwrap(), (3, 2));
    outbox.append("site.device_seen", AT, &seen(), None).unwrap();
    assert_eq!(Outbox::read_counters(&path).unwrap(), (4, 2));
    outbox.close().unwrap();
    assert_eq!(Outbox::read_counters(&path).unwrap(), (4, 2));
}

#[test]
fn an_outbox_file_that_never_got_its_tables_reads_as_empty() {
    // The file is created (private) before SQLite writes anything into it; a crash in between leaves it empty.
    let tmp = TempDir::new();
    let path = outbox_path(&tmp);
    spacegoat_hub::fsutil::private_file(&path).unwrap();
    assert_eq!(Outbox::read_counters(&path).unwrap(), (0, 0));
}

#[test]
fn a_damaged_counter_is_an_error_not_a_zero() {
    let tmp = TempDir::new();
    let path = outbox_path(&tmp);
    open_outbox(&tmp, vector_key()).close().unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("UPDATE meta SET value = 'x' WHERE key = 'last_assigned'", [])
        .unwrap();
    assert!(Outbox::read_counters(&path).is_err());
    let mut outbox = open_outbox(&tmp, vector_key());
    assert!(outbox.last_assigned().is_err());
    assert!(outbox.append("site.device_seen", AT, &seen(), None).is_err());
}

#[test]
fn the_file_is_private_and_durable() {
    let tmp = TempDir::new();
    let path = outbox_path(&tmp);
    let mut outbox = open_outbox(&tmp, vector_key());
    outbox.append("site.device_seen", AT, &seen(), None).unwrap();
    assert_eq!(mode(&path) & 0o077, 0);
    // SQLite gives its WAL file the database file's permissions.
    assert_eq!(mode(&path.with_extension("sqlite-wal")) & 0o077, 0);
    let db = rusqlite::Connection::open(&path).unwrap();
    let journal: String = db.query_row("PRAGMA journal_mode", [], |row| row.get(0)).unwrap();
    assert_eq!(journal, "wal");
    // FULL = 2: a committed event survives a power cut. (A per-connection setting: asked of the outbox itself.)
    assert_eq!(outbox.synchronous().unwrap(), 2);
}

#[test]
fn a_loose_outbox_file_is_closed_again() {
    let tmp = TempDir::new();
    let path = outbox_path(&tmp);
    open_outbox(&tmp, vector_key()).close().unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    open_outbox(&tmp, vector_key()).close().unwrap();
    assert_eq!(mode(&path), 0o600);
}
