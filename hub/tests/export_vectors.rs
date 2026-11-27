// SPDX-License-Identifier: AGPL-3.0-or-later
//! The export vectors (spec/vectors/export/, format in spec/export.md): built here from fixed values with the published
//! test keys, so every file can be rebuilt byte for byte. `write_export_vectors` writes them (run with `--ignored`);
//! `export_vectors_are_reproducible` fails when a file on disk differs from what this code builds.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use serde_json::{Map, Value, json};
use spacegoat_hub::signing::{self, EventFields};

const SOURCE_ID: &str = "01234567-89ab-4cde-8fab-0123456789ab";
const KEY_ID: &str = "vector-key-1";
const OTHER_KEY_ID: &str = "vector-key-2";
const SEGMENT: &str = "5b8d3e2f-6a1c-4b7d-9e0f-1a2b3c4d5e6f";
const PRINTER: &str = "3f2a5c1e-8b4d-4e6f-9a1b-2c3d4e5f6a7b";
const SERVER: &str = "7c9e2b4a-1d3f-4a5b-8c6d-9e0f1a2b3c4d";

const CHECKS: [&str; 5] = ["form", "key", "signature", "sequence", "commitment"];

fn dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors/export"))
}

/// A published test key whose 32 private bytes are `first`, `first + 1`, ... (spec/README.md).
fn key_from(first: u8) -> SigningKey {
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = first + i as u8;
    }
    SigningKey::from_bytes(&seed)
}

/// The published test key: private bytes 0, 1, ... 31.
fn test_key() -> SigningKey {
    key_from(0)
}

/// The second published test key, used only to sign an event with a key the header does not list: 32, 33, ... 63.
fn other_key() -> SigningKey {
    key_from(32)
}

struct Spec {
    seq: u64,
    kind: &'static str,
    observed_at: &'static str,
    attributes: Value,
    pii: Option<(&'static str, Value)>,
}

fn at(seq: u64) -> &'static str {
    match seq {
        1 => "2026-11-24T10:00:00.120Z",
        2 => "2026-11-24T10:05:00.000Z",
        3 => "2026-11-24T10:12:30.457Z",
        4 => "2026-11-24T11:00:00.000Z",
        5 => "2026-11-24T11:12:30.500Z",
        6 => "2026-11-24T19:00:00.000Z",
        7 => "2026-11-24T19:30:00.000Z",
        _ => panic!("no fixed time for {seq}"),
    }
}

/// The seven events of `valid.jsonl`; the other files are built from them.
fn base_specs() -> Vec<Spec> {
    vec![
        Spec {
            seq: 1,
            kind: "site.device_appeared",
            observed_at: at(1),
            attributes: json!({"trustOrigin": "hub", "deviceRef": PRINTER, "segmentRef": SEGMENT, "deviceClass": "printer"}),
            pii: Some((
                "1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988",
                json!({"mac": "00005e005301", "hostname": "printer.example", "ip": "192.0.2.10"}),
            )),
        },
        Spec {
            seq: 2,
            kind: "site.device_seen",
            observed_at: at(2),
            attributes: json!({"trustOrigin": "hub", "deviceRef": PRINTER, "segmentRef": SEGMENT}),
            pii: None,
        },
        Spec {
            seq: 3,
            kind: "site.device_appeared",
            observed_at: at(3),
            attributes: json!({"trustOrigin": "hub", "deviceRef": SERVER, "segmentRef": SEGMENT, "deviceClass": "server"}),
            pii: Some((
                "a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f",
                json!({"mac": "00005e005302", "hostname": "files.example", "ip": "192.0.2.20"}),
            )),
        },
        Spec {
            seq: 4,
            kind: "site.inventory_snapshot",
            observed_at: at(4),
            attributes: json!({
                "trustOrigin": "hub",
                "segmentRef": SEGMENT,
                "counts": {"ot": 0, "printer": 1, "user_device": 0, "server": 1, "network": 0, "iot": 0, "unknown": 0},
                "ephemeral": 2,
            }),
            pii: None,
        },
        Spec {
            seq: 5,
            kind: "site.device_seen",
            observed_at: at(5),
            attributes: json!({"trustOrigin": "hub", "deviceRef": SERVER, "segmentRef": SEGMENT}),
            pii: None,
        },
        Spec {
            seq: 6,
            kind: "site.device_gone",
            observed_at: at(6),
            attributes: json!({"trustOrigin": "hub", "deviceRef": PRINTER, "segmentRef": SEGMENT, "lastSeenAt": at(2)}),
            pii: None,
        },
        Spec {
            seq: 7,
            kind: "site_source.input_lost",
            observed_at: at(7),
            attributes: json!({
                "trustOrigin": "hub",
                "reason": "capture_stopped",
                "fromTime": "2026-11-24T19:10:00.000Z",
                "toTime": "2026-11-24T19:25:00.000Z",
            }),
            pii: None,
        },
    ]
}

/// One signed event in the wire form of protocol section 7.
fn signed(spec: &Spec, key: &SigningKey, key_id: &str) -> Map<String, Value> {
    let mut event = Map::new();
    event.insert("sourceSeq".into(), json!(spec.seq));
    event.insert("kind".into(), json!(spec.kind));
    event.insert("observedAt".into(), json!(spec.observed_at));
    let mut commitment = None;
    if let Some((nonce, pii)) = &spec.pii {
        let committed = signing::pii_commitment(nonce, pii).unwrap();
        event.insert("pii".into(), pii.clone());
        event.insert("piiNonce".into(), json!(nonce));
        event.insert("piiCommitment".into(), json!(committed));
        commitment = Some(committed);
    }
    let message = signing::event_signing_message(&EventFields {
        source_id: SOURCE_ID,
        source_seq: spec.seq,
        kind: spec.kind,
        observed_at: spec.observed_at,
        attributes: &spec.attributes,
        pii_commitment: commitment.as_deref(),
    })
    .unwrap();
    event.insert("attributes".into(), spec.attributes.clone());
    event.insert(
        "signature".into(),
        json!(signing::stored_signature(key_id, &signing::sign(key, &message)).unwrap()),
    );
    event
}

fn sign_all(specs: &[Spec]) -> Vec<Map<String, Value>> {
    specs.iter().map(|spec| signed(spec, &test_key(), KEY_ID)).collect()
}

/// The export text: a header line naming only `vector-key-1`, then one line per event, each ended by LF.
fn export(from_seq: u64, to_seq: u64, events: &[Map<String, Value>]) -> String {
    let header = json!({
        "format": "spacegoat-export/v1",
        "sourceId": SOURCE_ID,
        "fromSeq": from_seq,
        "toSeq": to_seq,
        "keys": [{"keyId": KEY_ID, "publicKey": signing::public_key_text(&test_key())}],
    });
    let mut text = serde_json::to_string(&header).unwrap();
    text.push('\n');
    for event in events {
        text.push_str(&serde_json::to_string(event).unwrap());
        text.push('\n');
    }
    text
}

fn valid() -> Vec<Map<String, Value>> {
    sign_all(&base_specs())
}

/// Events 1..3 of `valid`, then one event that speaks about the source's own sequence.
fn first_three_then(spec: Spec) -> Vec<Map<String, Value>> {
    let mut specs: Vec<Spec> = base_specs().into_iter().take(3).collect();
    specs.push(spec);
    sign_all(&specs)
}

fn position(events: &[Map<String, Value>], seq: u64) -> usize {
    events.iter().position(|e| e["sourceSeq"] == json!(seq)).unwrap()
}

struct Vector {
    name: &'static str,
    text: String,
    exit: u8,
    failed: &'static [&'static str],
    redacted: u64,
    first_failed_seq: Option<u64>,
}

fn vectors() -> Vec<Vector> {
    let mut out = Vec::new();

    out.push(Vector {
        name: "valid",
        text: export(1, 7, &valid()),
        exit: 0,
        failed: &[],
        redacted: 0,
        first_failed_seq: None,
    });

    out.push(Vector {
        name: "declared-gap",
        text: export(
            1,
            6,
            &first_three_then(Spec {
                seq: 6,
                kind: "site_source.gap_declared",
                observed_at: at(6),
                attributes: json!({"trustOrigin": "hub", "fromSeq": 4, "toSeq": 5, "reason": "operator"}),
                pii: None,
            }),
        ),
        exit: 0,
        failed: &[],
        redacted: 0,
        first_failed_seq: None,
    });

    out.push(Vector {
        name: "reset",
        text: export(
            1,
            4,
            &first_three_then(Spec {
                seq: 4,
                kind: "site_source.reset",
                observed_at: at(4),
                attributes: json!({"trustOrigin": "hub", "lastAckedSeq": 3, "reason": "queue_lost"}),
                pii: None,
            }),
        ),
        exit: 0,
        failed: &[],
        redacted: 0,
        first_failed_seq: None,
    });

    // The personal data of event 3 was deleted after its retention period: only the signed commitment is left.
    let mut redacted = valid();
    let i = position(&redacted, 3);
    redacted[i].remove("pii").unwrap();
    redacted[i].remove("piiNonce").unwrap();
    out.push(Vector {
        name: "redacted-pii",
        text: export(1, 7, &redacted),
        exit: 0,
        failed: &[],
        redacted: 1,
        first_failed_seq: None,
    });

    let mut deleted = valid();
    deleted.remove(position(&deleted, 4));
    out.push(Vector {
        name: "deleted-event",
        text: export(1, 7, &deleted),
        exit: 1,
        failed: &["sequence"],
        redacted: 0,
        first_failed_seq: Some(5),
    });

    let mut altered = valid();
    let i = position(&altered, 3);
    altered[i]["attributes"]["deviceClass"] = json!("user_device");
    out.push(Vector {
        name: "altered-event",
        text: export(1, 7, &altered),
        exit: 1,
        failed: &["signature"],
        redacted: 0,
        first_failed_seq: Some(3),
    });

    let mut reordered = valid();
    let (five, six) = (position(&reordered, 5), position(&reordered, 6));
    reordered.swap(five, six);
    out.push(Vector {
        name: "reordered",
        text: export(1, 7, &reordered),
        exit: 1,
        failed: &["sequence"],
        redacted: 0,
        first_failed_seq: Some(6),
    });

    // Event 5 is signed, correctly, by the second test key, which the header does not list.
    let mut unknown = valid();
    let specs = base_specs();
    let i = position(&unknown, 5);
    unknown[i] = signed(&specs[i], &other_key(), OTHER_KEY_ID);
    out.push(Vector {
        name: "unknown-key",
        text: export(1, 7, &unknown),
        exit: 1,
        failed: &["key"],
        redacted: 0,
        first_failed_seq: Some(5),
    });

    // The personal data of event 3 was changed after signing; the signed commitment still names the old data.
    let mut bad = valid();
    let i = position(&bad, 3);
    bad[i]["pii"]["ip"] = json!("192.0.2.21");
    out.push(Vector {
        name: "bad-commitment",
        text: export(1, 7, &bad),
        exit: 1,
        failed: &["commitment"],
        redacted: 0,
        first_failed_seq: Some(3),
    });

    // A floating-point attribute has no canonical form (protocol section 2); the line is valid JSON all the same.
    let mut float = valid();
    let i = position(&float, 4);
    float[i]["attributes"]["ephemeral"] = json!(1.5);
    out.push(Vector {
        name: "float-attribute",
        text: export(1, 7, &float),
        exit: 1,
        failed: &["form"],
        redacted: 0,
        first_failed_seq: Some(4),
    });

    out
}

fn expected_json(vectors: &[Vector]) -> String {
    let mut all = BTreeMap::new();
    for v in vectors {
        let checks: Map<String, Value> = CHECKS
            .iter()
            .map(|c| {
                let state = if v.failed.contains(c) { "failed" } else { "ok" };
                ((*c).to_string(), json!(state))
            })
            .collect();
        all.insert(
            v.name,
            json!({"exit": v.exit, "checks": checks, "redacted": v.redacted, "firstFailedSeq": v.first_failed_seq}),
        );
    }
    let mut text = serde_json::to_string_pretty(&all).unwrap();
    text.push('\n');
    text
}

fn files() -> Vec<(String, String)> {
    let vectors = vectors();
    let mut files: Vec<(String, String)> = vectors
        .iter()
        .map(|v| (format!("{}.jsonl", v.name), v.text.clone()))
        .collect();
    files.push(("expected.json".into(), expected_json(&vectors)));
    files
}

#[test]
#[ignore = "writes spec/vectors/export/; run with --ignored after a deliberate change"]
fn write_export_vectors() {
    std::fs::create_dir_all(dir()).unwrap();
    for (name, text) in files() {
        std::fs::write(dir().join(name), text).unwrap();
    }
}

#[test]
fn export_vectors_are_reproducible() {
    for (name, text) in files() {
        let path = dir().join(&name);
        let on_disk = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(on_disk == text.as_bytes(), "{name} differs from what this test builds");
    }
}

#[test]
fn expected_json_names_exactly_the_ten_files() {
    let path = dir().join("expected.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let expected: Value = serde_json::from_str(&text).unwrap();
    let mut names: Vec<&str> = expected.as_object().unwrap().keys().map(String::as_str).collect();
    names.sort_unstable();
    let mut want = vec![
        "altered-event",
        "bad-commitment",
        "declared-gap",
        "deleted-event",
        "float-attribute",
        "redacted-pii",
        "reordered",
        "reset",
        "unknown-key",
        "valid",
    ];
    want.sort_unstable();
    assert_eq!(names, want);
    for name in want {
        let entry = &expected[name];
        assert!(dir().join(format!("{name}.jsonl")).is_file(), "{name}.jsonl");
        assert!(entry["exit"] == json!(0) || entry["exit"] == json!(1), "{name}");
        let checks = entry["checks"].as_object().unwrap();
        assert_eq!(checks.len(), CHECKS.len(), "{name}");
        for check in CHECKS {
            assert!(
                checks[check] == json!("ok") || checks[check] == json!("failed"),
                "{name} {check}"
            );
        }
        let any_failed = checks.values().any(|v| v == "failed");
        assert_eq!(entry["exit"] == json!(1), any_failed, "{name}");
        assert_eq!(entry["firstFailedSeq"].is_null(), !any_failed, "{name}");
        assert!(entry["redacted"].is_u64(), "{name}");
    }
}

#[test]
fn the_second_test_key_is_not_the_first() {
    assert_ne!(
        signing::public_key_text(&test_key()),
        signing::public_key_text(&other_key())
    );
}
