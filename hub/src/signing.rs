// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a hub signs (spec/protocol.md, "Event signature" and "Request signature").
//!
//! Two signatures, two purposes:
//! - the EVENT signature binds one observation to its source, its place in the source's sequence and its content;
//!   it is stored with the event and verified again later, from the stored fields;
//! - the REQUEST signature binds one HTTP request to the hub, the endpoint, the moment and the exact body bytes.
//!
//! Personal data is never in the signed event itself: the event carries a commitment to it (a hash over a random
//! nonce and the data), so the event still verifies after the personal data has been deleted.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::canonical::{CanonicalError, canonical_json};

const EVENT_PREFIX: &str = "vt-evidence-event/v1\n";
const REQUEST_PREFIX: &str = "vt-machine/v1\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningError {
    /// `observedAt` is not a real UTC time with millisecond precision, like `2026-11-24T10:00:00.123Z`.
    ObservedAt,
    /// The nonce is not 64 lowercase hex characters.
    Nonce,
    /// The key id is not 3 to 63 characters of a-z, 0-9 and `-`, starting with a letter or digit.
    KeyId,
    Canonical(CanonicalError),
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObservedAt => f.write_str("observedAt must be a real UTC time with millisecond precision"),
            Self::Nonce => f.write_str("nonce must be 64 lowercase hex characters"),
            Self::KeyId => f.write_str(KEY_ID_RULE),
            Self::Canonical(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SigningError {}

impl From<CanonicalError> for SigningError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

/// The fields an event signature covers.
#[derive(Debug, Clone, Copy)]
pub struct EventFields<'a> {
    pub source_id: &'a str,
    pub source_seq: u64,
    pub kind: &'a str,
    pub observed_at: &'a str,
    pub attributes: &'a Value,
    pub pii_commitment: Option<&'a str>,
}

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        for nibble in [byte >> 4, byte & 0xf] {
            out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    out
}

/// The exact form, and a moment that exists: month 13 has the right shape and is still not a time.
/// ASCII digits only; digits of other scripts are not digits here, as they are not for the service.
pub fn is_observed_at(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 24 {
        return false;
    }
    let shape = b"dddd-dd-ddTdd:dd:dd.dddZ";
    if !bytes
        .iter()
        .zip(shape)
        .all(|(b, s)| if *s == b'd' { b.is_ascii_digit() } else { b == s })
    {
        return false;
    }
    let number = |from: usize, to: usize| -> u32 {
        bytes
            .get(from..to)
            .unwrap_or_default()
            .iter()
            .fold(0, |n, b| n * 10 + u32::from(b - b'0'))
    };
    let (year, month, day) = (number(0, 4), number(5, 7), number(8, 10));
    let (hour, minute, second) = (number(11, 13), number(14, 16), number(17, 19));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

/// The rule `is_key_id` checks, as every refusal of a key id says it.
pub const KEY_ID_RULE: &str = "a key id is 3 to 63 characters of a-z, 0-9 and -, starting with a letter or digit";

/// 3 to 63 characters of a-z, 0-9 and `-`, starting with a letter or digit.
pub fn is_key_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    let plain = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    (3..=63).contains(&bytes.len()) && bytes.first().is_some_and(plain) && bytes.iter().all(|b| plain(b) || *b == b'-')
}

/// sha256 over the nonce (as its 64 hex characters), a `|`, and the canonical JSON of the personal data.
pub fn pii_commitment(nonce_hex: &str, pii: &Value) -> Result<String, SigningError> {
    let lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if nonce_hex.len() != 64 || !nonce_hex.bytes().all(lower_hex) {
        return Err(SigningError::Nonce);
    }
    let mut hasher = Sha256::new();
    hasher.update(nonce_hex.as_bytes());
    hasher.update(b"|");
    hasher.update(canonical_json(pii)?.as_bytes());
    Ok(hex(&hasher.finalize()))
}

pub fn event_signing_message(fields: &EventFields<'_>) -> Result<Vec<u8>, SigningError> {
    if !is_observed_at(fields.observed_at) {
        return Err(SigningError::ObservedAt);
    }
    let body = canonical_json(&json!({
        "sourceId": fields.source_id,
        "sourceSeq": fields.source_seq,
        "kind": fields.kind,
        "observedAt": fields.observed_at,
        "attributes": fields.attributes,
        "piiCommitment": fields.pii_commitment,
    }))?;
    Ok(format!("{EVENT_PREFIX}{body}").into_bytes())
}

/// `path` is the request path with its query string; `body` the exact bytes sent (after compression).
pub fn request_signing_message(principal: &str, method: &str, path: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let digest = hex(&Sha256::digest(body));
    format!("{REQUEST_PREFIX}{principal}\n{method} {path}\n{timestamp}\n{digest}").into_bytes()
}

pub fn sign(key: &SigningKey, message: &[u8]) -> String {
    b64url(&key.sign(message).to_bytes())
}

pub fn public_key_text(key: &SigningKey) -> String {
    format!("ed25519:{}", b64url(key.verifying_key().as_bytes()))
}

/// The form an event's signature travels and is stored in: it names the key that made it.
pub fn stored_signature(key_id: &str, signature: &str) -> Result<String, SigningError> {
    if !is_key_id(key_id) {
        return Err(SigningError::KeyId);
    }
    Ok(format!("ed25519:{key_id}:{signature}"))
}
