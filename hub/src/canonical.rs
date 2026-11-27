// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical JSON: the one byte form a signed payload has (spec/protocol.md, "Canonical JSON").
//!
//! Two implementations in two languages sign and verify the same bytes, so the form admits nothing either of them
//! could write differently: object keys sorted, no whitespace, text as UTF-8 (never escaped to ASCII), and only
//! strings, safe integers, booleans, null, objects and arrays. A float has more than one spelling; it is refused,
//! not rounded.

use serde_json::Value;

/// The largest integer every JSON implementation reads back exactly (2^53 - 1).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Nesting deeper than this is refused instead of risking the stack on a hostile value.
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// A number with a fraction or an exponent.
    Float,
    /// An integer outside ±(2^53 - 1).
    IntegerOutOfRange,
    /// An object key that is empty or not printable ASCII.
    Key,
    /// Nested deeper than any signed payload is.
    TooDeep,
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Float => "a floating-point number cannot be signed",
            Self::IntegerOutOfRange => "integer outside the safe range",
            Self::Key => "object key must be non-empty printable ASCII text",
            Self::TooDeep => "value is nested too deeply",
        })
    }
}

impl std::error::Error for CanonicalError {}

/// The canonical text of `value`, or the reason it has no single spelling.
pub fn canonical_json(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(value, &mut out, 0)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String, depth: usize) -> Result<(), CanonicalError> {
    if depth > MAX_DEPTH {
        return Err(CanonicalError::TooDeep);
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            let integer = match (number.as_i64(), number.as_u64()) {
                (Some(i), _) => i,
                // Only values above i64::MAX get here, and those are out of range anyway.
                (None, Some(_)) => return Err(CanonicalError::IntegerOutOfRange),
                (None, None) => return Err(CanonicalError::Float),
            };
            if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&integer) {
                return Err(CanonicalError::IntegerOutOfRange);
            }
            out.push_str(&integer.to_string());
        }
        Value::String(text) => write_text(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            for (key, _) in &entries {
                if key.is_empty() || !key.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                    return Err(CanonicalError::Key);
                }
            }
            // Keys are ASCII, so byte order is code point order.
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_text(key, out);
                out.push(':');
                write_value(item, out, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// `"` and `\` are escaped, control characters below U+0020 are escaped, everything else is written as it is.
fn write_text(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u00");
                for shift in [4u32, 0] {
                    let nibble = ((c as u32) >> shift) & 0xf;
                    out.push(char::from_digit(nibble, 16).unwrap_or('0'));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
