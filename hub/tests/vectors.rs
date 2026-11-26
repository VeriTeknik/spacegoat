// SPDX-License-Identifier: AGPL-3.0-or-later
//! The published vectors (spec/vectors/signing.json): this implementation must reproduce every byte and signature.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use spacegoat_hub::canonical::{CanonicalError, canonical_json};
use spacegoat_hub::signing::{self, EventFields, SigningError};

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors/signing.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The published test key: its 32 private bytes are 0, 1, 2, ... 31 (spec/README.md).
fn test_key() -> SigningKey {
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = i as u8;
    }
    SigningKey::from_bytes(&seed)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

#[test]
fn the_vector_file_has_every_section() {
    let v = vectors();
    assert_eq!(v["keyId"], "vector-key-1");
    assert!(v["canonical"].as_array().unwrap().len() >= 9);
    assert!(v["events"].as_array().unwrap().len() >= 7);
    assert!(v["request"].is_object());
    assert!(v["pii"].is_object());
}

#[test]
fn the_test_key_has_the_published_public_key() {
    assert_eq!(signing::public_key_text(&test_key()), text(&vectors()["publicKey"]));
}

#[test]
fn every_canonical_vector_is_reproduced_exactly() {
    for case in vectors()["canonical"].as_array().unwrap() {
        assert_eq!(
            canonical_json(&case["value"]).unwrap(),
            text(&case["text"]),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn every_event_vector_gives_the_same_message_and_signature() {
    let key = test_key();
    for case in vectors()["events"].as_array().unwrap() {
        let input = &case["input"];
        let message = signing::event_signing_message(&EventFields {
            source_id: text(&input["sourceId"]),
            source_seq: input["sourceSeq"].as_u64().unwrap(),
            kind: text(&input["kind"]),
            observed_at: text(&input["observedAt"]),
            attributes: &input["attributes"],
            pii_commitment: input["piiCommitment"].as_str(),
        })
        .unwrap();
        assert_eq!(hex(&message), text(&case["messageHex"]), "{}", case["name"]);
        assert_eq!(
            signing::sign(&key, &message),
            text(&case["signature"]),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn the_request_vector_gives_the_same_message_and_signature() {
    let v = vectors();
    let r = &v["request"];
    let message = signing::request_signing_message(
        text(&r["principal"]),
        text(&r["method"]),
        text(&r["path"]),
        text(&r["timestamp"]),
        &unhex(text(&r["bodyHex"])),
    );
    assert_eq!(hex(&message), text(&r["messageHex"]));
    assert_eq!(signing::sign(&test_key(), &message), text(&r["signature"]));
}

#[test]
fn the_personal_data_commitment_matches() {
    let v = vectors();
    let p = &v["pii"];
    assert_eq!(
        signing::pii_commitment(text(&p["nonceHex"]), &p["payload"]).unwrap(),
        text(&p["commitment"])
    );
}

#[test]
fn a_commitment_needs_a_64_character_lowercase_hex_nonce() {
    let pii = json!({"mac": "00005e005301"});
    for nonce in ["", "ab", &"AB".repeat(32), &"zz".repeat(32), &"ab".repeat(33)] {
        assert_eq!(
            signing::pii_commitment(nonce, &pii),
            Err(SigningError::Nonce),
            "{nonce}"
        );
    }
}

#[test]
fn canonical_json_refuses_what_has_no_single_spelling() {
    assert_eq!(canonical_json(&json!({"a": 1.5})), Err(CanonicalError::Float));
    assert_eq!(
        canonical_json(&serde_json::from_str("[1e3]").unwrap()),
        Err(CanonicalError::Float)
    );
    assert_eq!(
        canonical_json(&serde_json::from_str("[1.0]").unwrap()),
        Err(CanonicalError::Float)
    );
    assert_eq!(
        canonical_json(&json!(9_007_199_254_740_992u64)),
        Err(CanonicalError::IntegerOutOfRange)
    );
    assert_eq!(
        canonical_json(&json!(-9_007_199_254_740_992i64)),
        Err(CanonicalError::IntegerOutOfRange)
    );
    assert_eq!(canonical_json(&json!(u64::MAX)), Err(CanonicalError::IntegerOutOfRange));
    assert_eq!(
        canonical_json(&json!(9_007_199_254_740_991u64)).unwrap(),
        "9007199254740991"
    );
    assert_eq!(
        canonical_json(&json!(-9_007_199_254_740_991i64)).unwrap(),
        "-9007199254740991"
    );
    for key in ["", "ş", "a\nb", "a\u{7f}"] {
        assert_eq!(canonical_json(&json!({key: 1})), Err(CanonicalError::Key), "{key:?}");
    }
    assert_eq!(canonical_json(&json!({"a b~": 1})).unwrap(), "{\"a b~\":1}");
}

#[test]
fn canonical_json_refuses_a_value_nested_beyond_any_real_payload() {
    let mut value = json!(1);
    for _ in 0..200 {
        value = json!([value]);
    }
    assert_eq!(canonical_json(&value), Err(CanonicalError::TooDeep));
}

#[test]
fn every_control_character_below_space_is_escaped() {
    let all: String = (0u8..0x20).map(char::from).collect();
    let expected = "\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f\
                    \\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\"";
    assert_eq!(canonical_json(&json!(all)).unwrap(), expected);
}

#[test]
fn observed_at_is_the_exact_form_and_a_moment_that_exists() {
    for good in [
        "2026-11-24T10:00:00.123Z",
        "2028-02-29T23:59:59.999Z",
        "2026-01-01T00:00:00.000Z",
    ] {
        assert!(signing::is_observed_at(good), "{good}");
    }
    for bad in [
        "2026-11-24T10:00:00Z",
        "2026-11-24T10:00:00.123",
        "2026-11-24T10:00:00.123+03:00",
        "2026-11-24 10:00:00.123Z",
        "2026-13-01T00:00:00.000Z",
        "2026-00-10T00:00:00.000Z",
        "2026-02-29T00:00:00.000Z",
        "2026-04-31T00:00:00.000Z",
        "2026-11-00T00:00:00.000Z",
        "2026-11-24T24:00:00.000Z",
        "2026-11-24T10:60:00.000Z",
        "2026-11-24T10:00:60.000Z",
        "2026-11-24T10:00:00.1234Z",
        "٢٠٢٦-11-24T10:00:00.123Z",
        " 2026-11-24T10:00:00.123Z",
        "",
    ] {
        assert!(!signing::is_observed_at(bad), "{bad}");
    }
}

#[test]
fn an_event_with_a_malformed_time_is_not_signed() {
    let attributes = json!({});
    let fields = EventFields {
        source_id: "01234567-89ab-4cde-8fab-0123456789ab",
        source_seq: 1,
        kind: "site.device_seen",
        observed_at: "2026-11-24T10:00:00Z",
        attributes: &attributes,
        pii_commitment: None,
    };
    assert_eq!(signing::event_signing_message(&fields), Err(SigningError::ObservedAt));
}

#[test]
fn an_event_whose_attributes_cannot_be_canonical_is_not_signed() {
    let attributes = json!({"ratio": 0.5});
    let fields = EventFields {
        source_id: "01234567-89ab-4cde-8fab-0123456789ab",
        source_seq: 1,
        kind: "site.device_seen",
        observed_at: "2026-11-24T10:00:00.000Z",
        attributes: &attributes,
        pii_commitment: None,
    };
    assert_eq!(
        signing::event_signing_message(&fields),
        Err(SigningError::Canonical(CanonicalError::Float))
    );
}

#[test]
fn a_stored_signature_names_its_key() {
    assert_eq!(
        signing::stored_signature("hub-key-1", "abc").unwrap(),
        "ed25519:hub-key-1:abc"
    );
    for bad in [
        "",
        "ab",
        "-ab",
        "Hub-key",
        "hub key",
        "hub_key",
        &"a".repeat(64),
        "hub:key",
    ] {
        assert_eq!(signing::stored_signature(bad, "abc"), Err(SigningError::KeyId), "{bad}");
    }
    assert!(signing::stored_signature(&"a".repeat(63), "abc").is_ok());
}
