// SPDX-License-Identifier: AGPL-3.0-or-later
//! The hub's configuration file.
//!
//! Guarantee: a configuration the agent cannot run with is refused here, by name, before anything starts. Four keys,
//! all text, all required: `base_url` (the service's origin, see `sender::service_origin`), `source_id` (the UUID the
//! service assigned at registration), `key_id` (the id registered with the public key) and `state_dir` (an absolute
//! path). Any other key is refused, a table included. An error names the key or the line at fault and never repeats
//! a value from the file.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::sender::{OriginError, service_origin};
use crate::signing;

/// The keys a configuration holds, in the order they are checked.
pub const CONFIG_KEYS: [&str; 4] = ["base_url", "key_id", "source_id", "state_dir"];

/// The longest key name an error repeats; anything else is not echoed.
const MAX_ECHOED_KEY: usize = 64;

#[derive(Debug)]
pub enum ConfigError {
    /// The file cannot be read (or is not UTF-8).
    Read(PathBuf, io::Error),
    /// The file is not TOML; the line the parser stopped at, if it said.
    Syntax(Option<usize>),
    /// A key this version does not know; its name when that is plain text.
    UnknownKey(Option<String>),
    /// A required key is absent, empty or not text.
    Missing(&'static str),
    BaseUrl(OriginError),
    SourceId,
    KeyId,
    StateDir,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(path, error) => write!(f, "cannot read the configuration {}: {error}", path.display()),
            Self::Syntax(Some(line)) => write!(f, "the configuration is not valid TOML (line {line})"),
            Self::Syntax(None) => f.write_str("the configuration is not valid TOML"),
            Self::UnknownKey(Some(key)) => write!(f, "unknown configuration key: {key}"),
            Self::UnknownKey(None) => f.write_str("unknown configuration key"),
            Self::Missing(key) => write!(f, "configuration key {key} is missing"),
            Self::BaseUrl(error) => error.fmt(f),
            Self::SourceId => f.write_str("source_id must be the UUID the service assigned at registration"),
            Self::KeyId => write!(f, "key_id: {}", signing::KEY_ID_RULE),
            Self::StateDir => f.write_str("state_dir must be an absolute path"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(_, error) => Some(error),
            Self::BaseUrl(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub base_url: String,
    pub source_id: String,
    pub key_id: String,
    pub state_dir: PathBuf,
}

impl Config {
    /// A configuration built in code, validated exactly as one read from a file.
    pub fn new(base_url: &str, source_id: &str, key_id: &str, state_dir: &Path) -> Result<Self, ConfigError> {
        service_origin(base_url).map_err(ConfigError::BaseUrl)?;
        if !is_uuid(source_id) {
            return Err(ConfigError::SourceId);
        }
        if !signing::is_key_id(key_id) {
            return Err(ConfigError::KeyId);
        }
        if !state_dir.is_absolute() {
            return Err(ConfigError::StateDir);
        }
        Ok(Self {
            base_url: base_url.to_owned(),
            source_id: source_id.to_owned(),
            key_id: key_id.to_owned(),
            state_dir: state_dir.to_path_buf(),
        })
    }
}

/// Read and check the configuration at `path`.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|error| ConfigError::Read(path.to_path_buf(), error))?;
    parse(&text)
}

/// Check a configuration's text.
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let table: toml::Table = text.parse().map_err(|error: toml::de::Error| {
        // The parser's own message quotes the line; only where it stopped is kept.
        ConfigError::Syntax(error.span().map(|span| line_of(text, span.start)))
    })?;
    let mut unknown: Vec<&String> = table
        .keys()
        .filter(|key| !CONFIG_KEYS.contains(&key.as_str()))
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        let plain = key.len() <= MAX_ECHOED_KEY && key.bytes().all(|b| b.is_ascii_graphic());
        return Err(ConfigError::UnknownKey(plain.then(|| (*key).clone())));
    }
    let text_of = |key: &'static str| match table.get(key).and_then(toml::Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(ConfigError::Missing(key)),
    };
    let [base_url, key_id, source_id, state_dir] = CONFIG_KEYS;
    let (base_url, key_id) = (text_of(base_url)?, text_of(key_id)?);
    let (source_id, state_dir) = (text_of(source_id)?, text_of(state_dir)?);
    Config::new(base_url, source_id, key_id, Path::new(state_dir))
}

/// A lowercase UUID in its 8-4-4-4-12 form (any version: the service chose it).
pub fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
}

/// The 1-based line a byte offset is on.
fn line_of(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    text.as_bytes()
        .get(..end)
        .unwrap_or_default()
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}
