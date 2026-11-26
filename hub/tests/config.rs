// SPDX-License-Identifier: AGPL-3.0-or-later
//! The configuration file: what the agent cannot run with is refused by name, before anything starts, and an error
//! never repeats what the file holds.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::path::{Path, PathBuf};

use spacegoat_hub::config::{self, Config, ConfigError};
use support::TempDir;

const SOURCE: &str = "01234567-89ab-4cde-8fab-0123456789ab";

fn good() -> Vec<(&'static str, String)> {
    vec![
        ("base_url", "https://hub.example".to_owned()),
        ("source_id", SOURCE.to_owned()),
        ("key_id", "hub-key-1".to_owned()),
        ("state_dir", "/var/lib/spacegoat".to_owned()),
    ]
}

fn text_of(entries: &[(&str, String)]) -> String {
    entries
        .iter()
        .map(|(key, value)| format!("{key} = \"{value}\"\n"))
        .collect()
}

fn load_text(tmp: &TempDir, text: &str) -> Result<Config, ConfigError> {
    let path = tmp.join("hub.toml");
    std::fs::write(&path, text).unwrap();
    config::load(&path)
}

fn with(key: &'static str, value: &str) -> Vec<(&'static str, String)> {
    let mut entries: Vec<_> = good().into_iter().filter(|(k, _)| *k != key).collect();
    entries.push((key, value.to_owned()));
    entries
}

#[test]
fn a_complete_configuration_loads() {
    let tmp = TempDir::new();
    let config = load_text(&tmp, &text_of(&good())).unwrap();
    assert_eq!(config.state_dir, PathBuf::from("/var/lib/spacegoat"));
    assert_eq!(config.base_url, "https://hub.example");
    assert_eq!(config.source_id, SOURCE);
    assert_eq!(config.key_id, "hub-key-1");
}

#[test]
fn plain_http_is_accepted_for_this_machine_only() {
    let tmp = TempDir::new();
    assert!(load_text(&tmp, &text_of(&with("base_url", "http://127.0.0.1:8443"))).is_ok());
    assert!(load_text(&tmp, &text_of(&with("base_url", "http://localhost.evil.example"))).is_err());
}

#[test]
fn test_config_refuses_what_it_cannot_run_with() {
    let tmp = TempDir::new();
    let missing_key_id: Vec<_> = good().into_iter().filter(|(k, _)| *k != "key_id").collect();
    let mut extra = good();
    extra.push(("extra", "1".to_owned()));
    let cases = [
        with("base_url", "http://hub.example"),
        with("base_url", "https://hub.example/api"),
        with("source_id", "nope"),
        // The service assigns lowercase; nothing else is accepted.
        with("source_id", "01234567-89AB-4CDE-8FAB-0123456789AB"),
        with("key_id", "K"),
        with("state_dir", "relative"),
        with("state_dir", ""),
        extra,
        missing_key_id,
    ];
    for case in cases {
        let refused = load_text(&tmp, &text_of(&case));
        assert!(refused.is_err(), "accepted: {case:?}");
    }
}

#[test]
fn each_refusal_names_what_is_wrong() {
    let tmp = TempDir::new();
    let message = |entries: &[(&str, String)]| load_text(&tmp, &text_of(entries)).unwrap_err().to_string();
    let mut extra = good();
    extra.push(("profile", "pi4".to_owned()));
    assert_eq!(message(&extra), "unknown configuration key: profile");
    let missing: Vec<_> = good().into_iter().filter(|(k, _)| *k != "state_dir").collect();
    assert_eq!(message(&missing), "configuration key state_dir is missing");
    assert!(message(&with("source_id", "nope")).contains("source_id"));
    assert!(message(&with("key_id", "K")).contains("key_id"));
    assert!(message(&with("state_dir", "relative")).contains("absolute"));
    assert!(message(&with("base_url", "ftp://hub.example")).starts_with("base_url"));
}

#[test]
fn a_value_that_is_not_text_is_missing() {
    let tmp = TempDir::new();
    let mut text = text_of(&good().into_iter().filter(|(k, _)| *k != "key_id").collect::<Vec<_>>());
    text.push_str("key_id = 7\n");
    let error = load_text(&tmp, &text).unwrap_err();
    assert_eq!(error.to_string(), "configuration key key_id is missing");
}

#[test]
fn a_table_or_a_dotted_key_is_an_unknown_key() {
    let tmp = TempDir::new();
    let text = format!("{}[extra]\nvalue = \"x\"\n", text_of(&good()));
    assert_eq!(
        load_text(&tmp, &text).unwrap_err().to_string(),
        "unknown configuration key: extra"
    );
}

#[test]
fn an_unknown_key_that_is_not_plain_text_is_not_echoed() {
    let tmp = TempDir::new();
    let text = format!("{}\"\\u001b[31mred\" = \"x\"\n", text_of(&good()));
    let message = load_text(&tmp, &text).unwrap_err().to_string();
    assert_eq!(message, "unknown configuration key");
}

#[test]
fn a_file_that_is_not_toml_is_refused_without_quoting_it() {
    let tmp = TempDir::new();
    let text = format!("{}secret = hunter2-is-not-a-value\n", text_of(&good()));
    let message = load_text(&tmp, &text).unwrap_err().to_string();
    assert!(message.contains("not valid TOML"), "{message}");
    assert!(message.contains("line 5"), "{message}");
    assert!(!message.contains("hunter2"), "{message}");
}

#[test]
fn a_file_that_is_not_utf8_is_refused() {
    let tmp = TempDir::new();
    let path = tmp.join("hub.toml");
    let mut bytes = text_of(&good()).into_bytes();
    bytes.extend_from_slice(b"# \xff\n");
    std::fs::write(&path, bytes).unwrap();
    assert!(config::load(&path).is_err());
}

#[test]
fn a_missing_file_is_a_short_reason() {
    let tmp = TempDir::new();
    let error = config::load(&tmp.join("absent.toml")).unwrap_err();
    assert!(error.to_string().contains("absent.toml"), "{error}");
}

#[test]
fn a_config_built_in_code_is_validated_the_same_way() {
    let state = Path::new("/var/lib/spacegoat");
    assert!(Config::new("https://hub.example", SOURCE, "hub-key-1", state).is_ok());
    assert!(Config::new("https://hub.example", "nope", "hub-key-1", state).is_err());
    assert!(Config::new("https://hub.example", SOURCE, "K", state).is_err());
    assert!(Config::new("https://hub.example", SOURCE, "hub-key-1", Path::new("rel")).is_err());
    assert!(Config::new("http://hub.example", SOURCE, "hub-key-1", state).is_err());
}
