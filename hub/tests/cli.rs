// SPDX-License-Identifier: AGPL-3.0-or-later
//! The command line: most cases call `cli::run` directly; the last ones run the real binary against the fake service
//! (`--version`, SIGTERM and SIGINT, and a hub killed mid-run and started again).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::ffi::OsString;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use spacegoat_hub::cli;
use spacegoat_hub::keystore::FileKeyStore;
use spacegoat_hub::signing::public_key_text;
use support::TempDir;
use support::fake_service::Step;
use support::hub::{Hub, assert_no_personal_data};

const BINARY: &str = env!("CARGO_BIN_EXE_spacegoat-hub");

struct Ran {
    code: u8,
    out: String,
    err: String,
}

fn cli(args: &[&str]) -> Ran {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(args.iter().map(OsString::from), &mut out, &mut err);
    Ran {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn status_of(hub: &Hub) -> Value {
    let ran = cli(&["status", "--config", path(&hub.config_path)]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    serde_json::from_str(&ran.out).unwrap()
}

#[test]
fn test_keygen_prints_the_public_key_and_never_the_private_one() {
    let tmp = TempDir::new();
    let state = tmp.join("state");
    let ran = cli(&["keygen", "--state-dir", path(&state), "--key-id", "hub-key-1"]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    let public = ran
        .out
        .lines()
        .find(|line| line.contains("ed25519:"))
        .and_then(|line| line.split_whitespace().last())
        .unwrap();
    let bytes = URL_SAFE_NO_PAD
        .decode(public.strip_prefix("ed25519:").unwrap())
        .unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap();
    // It is the public half of the key that was written, not merely a well-formed key.
    assert_eq!(
        public,
        public_key_text(&FileKeyStore::new(state.join("hub.key")).load().unwrap())
    );
    assert_eq!(ran.out, format!("key id:     hub-key-1\npublic key: {public}\n"));
    let file = std::fs::read_to_string(state.join("hub.key")).unwrap();
    assert!(!ran.out.contains("PRIVATE") && !ran.out.contains(&file));
    let body = file.lines().nth(1).unwrap();
    assert!(!ran.out.contains(body) && !ran.err.contains(body));
    // A second keygen refuses: it would orphan a registered hub.
    let again = cli(&["keygen", "--state-dir", path(&state), "--key-id", "hub-key-1"]);
    assert_eq!(again.code, 1);
    assert!(again.err.contains("already exists"), "{}", again.err);
    assert!(again.out.is_empty());
}

#[test]
fn test_keygen_refuses_a_malformed_key_id() {
    let tmp = TempDir::new();
    let ran = cli(&["keygen", "--state-dir", path(&tmp.join("s")), "--key-id", "Bad Key"]);
    assert_eq!(ran.code, 2);
    assert!(!tmp.join("s").join("hub.key").exists());
}

#[test]
fn test_status_prints_counts_and_no_device() {
    let hub = Hub::new();
    hub.run(6).close().unwrap();
    let ran = cli(&["status", "--config", path(&hub.config_path)]);
    assert_eq!(ran.code, 0, "{}", ran.err);
    let status: Value = serde_json::from_str(&ran.out).unwrap();
    let keys: Vec<&String> = status.as_object().unwrap().keys().collect();
    let mut expected = [
        "sourceId",
        "keyId",
        "lastAssignedSeq",
        "lastAckedSeq",
        "pending",
        "halted",
        "haltedAt",
        "waitingFor",
        "problem",
        "resume",
    ];
    // The order, as printed (serde_json's map sorts, so check the text).
    let positions: Vec<usize> = expected
        .iter()
        .map(|key| ran.out.find(&format!("\"{key}\"")).unwrap())
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{}", ran.out);
    expected.sort_unstable();
    assert_eq!(keys, expected);
    assert_eq!(status["pending"], 0);
    assert!(status["lastAckedSeq"].as_u64().unwrap() > 0);
    assert!(!ran.out.contains("printer"));
    assert_no_personal_data(&ran.out, "status");
    assert!(
        ran.out.starts_with("{\n  \"sourceId\": "),
        "the Python's indent=2 form: {}",
        ran.out
    );
}

#[test]
fn test_status_never_creates_the_outbox_so_a_lost_one_is_still_recognised() {
    let hub = Hub::new();
    let first = hub.run(6);
    let confirmed = first.status().unwrap().last_acked_seq;
    first.close().unwrap();
    hub.lose_outbox();
    let status = status_of(&hub);
    assert!(!hub.state.join("outbox.sqlite").exists());
    assert_eq!(status["lastAssignedSeq"], 0);
    hub.run(4).close().unwrap();
    let reset = hub
        .service
        .accepted()
        .into_iter()
        .find(|event| event["kind"] == "site_source.reset")
        .unwrap();
    assert_eq!(reset["sourceSeq"], confirmed + 1);
}

#[test]
fn status_takes_no_lock_from_a_running_agent_and_reads_why_it_halted() {
    let hub = Hub::new();
    let mut agent = hub.run(2);
    hub.service.push(Step::status(
        409,
        serde_json::json!({"error": "replay_conflict", "sourceSeq": 1}),
    ));
    hub.clock.advance_seconds(3 * 3600);
    agent.tick().unwrap();
    let status = status_of(&hub);
    assert_eq!(status["halted"], "replay_conflict");
    assert_eq!(status["waitingFor"], Value::Null);
    assert!(status["pending"].as_u64().unwrap() > 0);
    agent.close().unwrap();
}

#[test]
fn status_of_a_hub_that_never_ran_is_all_zero() {
    let hub = Hub::new();
    let status = status_of(&hub);
    assert_eq!(
        (status["lastAssignedSeq"].clone(), status["pending"].clone()),
        (0.into(), 0.into())
    );
    assert_eq!(status["halted"], Value::Null);
    assert!(!hub.state.join("outbox.sqlite").exists());
    assert!(!hub.state.join("agent.lock").exists());
}

#[test]
fn run_without_simulate_refuses_to_start() {
    let hub = Hub::new();
    // A stop already set: if the refusal were missing, the agent would open and return at once instead of hanging.
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let args = ["run", "--config", path(&hub.config_path)].map(OsString::from);
    let code = cli::run_until(args, &mut out, &mut err, Arc::new(AtomicBool::new(true)));
    let err = String::from_utf8(err).unwrap();
    assert_eq!(code, 2);
    assert!(err.contains("--simulate"), "{err}");
    assert!(out.is_empty());
    assert!(hub.service.requests().is_empty());
    assert!(!hub.state.join("outbox.sqlite").exists());
    assert!(!hub.state.join("agent.lock").exists());
}

#[test]
fn run_on_a_directory_another_agent_holds_refuses_to_start() {
    let hub = Hub::new();
    let holding = hub.agent();
    let ran = cli(&["run", "--config", path(&hub.config_path), "--simulate"]);
    assert_eq!(ran.code, 2);
    assert!(ran.err.contains("already running"), "{}", ran.err);
    holding.close().unwrap();
}

#[test]
fn a_configuration_that_cannot_be_used_is_a_short_reason_with_status_2() {
    let tmp = TempDir::new();
    let config = tmp.join("hub.toml");
    std::fs::write(&config, "base_url = \"https://hub.example\"\nkey = hunter2\n").unwrap();
    for command in ["run", "status"] {
        let ran = cli(&[command, "--config", path(&config), "--simulate"][..if command == "run" { 4 } else { 3 }]);
        assert_eq!(ran.code, 2, "{command}");
        assert!(ran.err.contains("not valid TOML"), "{}", ran.err);
        assert!(!ran.err.contains("hunter2"), "{}", ran.err);
        assert_eq!(ran.err.lines().count(), 1, "one short line: {}", ran.err);
    }
    let missing = cli(&["status", "--config", path(&tmp.join("absent.toml"))]);
    assert_eq!(missing.code, 2);
    assert!(missing.err.contains("absent.toml"));
}

#[test]
fn usage_errors_exit_2_with_the_usage_text() {
    for args in [
        &[][..],
        &["frobnicate"],
        &["--frobnicate"],
        &["status"],
        &["status", "--config"],
        &["status", "--config", "a", "--verbose"],
        &["run", "--config", "a", "--simulate", "now"],
        &["keygen", "--state-dir", "/x"],
    ] {
        let ran = cli(args);
        assert_eq!(ran.code, 2, "{args:?}");
        assert!(ran.err.starts_with("usage: spacegoat-hub"), "{args:?}: {}", ran.err);
        assert!(ran.err.contains("spacegoat-hub: error: "), "{}", ran.err);
        assert!(ran.out.is_empty());
    }
}

#[test]
fn an_argument_that_is_not_plain_text_is_not_repeated() {
    let ran = cli(&["status", "--\u{1b}[2J"]);
    assert_eq!(ran.code, 2);
    assert!(!ran.err.contains('\u{1b}'));
}

#[test]
fn help_and_version_print_to_stdout_and_succeed() {
    let help = cli(&["--help"]);
    assert_eq!((help.code, help.out.as_str()), (0, cli::USAGE));
    assert_eq!(cli(&["run", "-h"]).out, cli::USAGE);
    let version = cli(&["--version"]);
    assert_eq!(version.code, 0);
    assert_eq!(version.out, format!("spacegoat-hub {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn run_until_stops_after_the_tick_in_progress_and_exits_0() {
    let hub = Hub::new();
    let stop = Arc::new(AtomicBool::new(false));
    let config = hub.config_path.clone();
    let worker = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let args = ["run", "--config", path(&config), "--simulate"].map(OsString::from);
            let code = cli::run_until(args, &mut out, &mut err, stop);
            (code, out, err)
        })
    };
    wait_until("the first batch", || hub.service.last_seq() >= 2);
    stop.store(true, Ordering::SeqCst);
    let (code, out, err) = worker.join().unwrap();
    assert_eq!(code, 0);
    assert!(out.is_empty() && err.is_empty());
    let status = status_of(&hub);
    assert_eq!(status["lastAckedSeq"], status["lastAssignedSeq"]);
}

// The real binary.

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn spawn_run(hub: &Hub) -> Child {
    Command::new(BINARY)
        .args(["run", "--config", path(&hub.config_path), "--simulate"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn signal(child: &Child, name: &str) {
    let sent = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(sent.success());
}

/// Wait for the child to end by itself; it must, within a few seconds.
fn exit_of(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the agent did not stop");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn output_of(child: Child) -> (String, String) {
    let output = child.wait_with_output().unwrap();
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn test_the_installed_command_runs() {
    let output = Command::new(BINARY).arg("--version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("spacegoat-hub {}\n", env!("CARGO_PKG_VERSION"))
    );
    let usage = Command::new(BINARY).arg("frobnicate").output().unwrap();
    assert_eq!(usage.status.code(), Some(2));
}

/// The binary stops on `signal` after its tick: exit 0, the agent closed, everything delivered, nothing personal said.
fn stops_cleanly_on(signal_name: &str) {
    let hub = Hub::new();
    let mut child = spawn_run(&hub);
    wait_until("the first batch", || hub.service.last_seq() >= 2);
    signal(&child, signal_name);
    let status = exit_of(&mut child);
    assert_eq!(status.code(), Some(0), "{status:?}");
    let (out, err) = output_of(child);
    assert_eq!((out.as_str(), err.as_str()), ("", ""));
    let status = status_of(&hub);
    assert_eq!(status["lastAckedSeq"], status["lastAssignedSeq"]);
    // Closed: the lock is free for the next agent.
    hub.agent().close().unwrap();
}

#[test]
fn sigterm_finishes_the_tick_closes_and_exits_0() {
    stops_cleanly_on("TERM");
}

#[test]
fn sigint_finishes_the_tick_closes_and_exits_0() {
    stops_cleanly_on("INT");
}

#[test]
fn a_second_binary_on_the_same_state_directory_refuses_and_says_nothing_personal() {
    let hub = Hub::new();
    let mut first = spawn_run(&hub);
    wait_until("the first batch", || hub.service.last_seq() >= 2);
    let second = Command::new(BINARY)
        .args(["run", "--config", path(&hub.config_path), "--simulate"])
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(2));
    let err = String::from_utf8(second.stderr).unwrap();
    assert!(err.contains("already running"), "{err}");
    assert_no_personal_data(&err, "stderr");
    signal(&first, "TERM");
    assert_eq!(exit_of(&mut first).code(), Some(0));
    let (out, err) = output_of(first);
    assert_no_personal_data(&out, "stdout");
    assert_no_personal_data(&err, "stderr");
}

#[test]
fn a_hub_killed_mid_run_starts_again_and_the_service_takes_each_number_once() {
    let hub = Hub::new();
    // The hello goes through; the first batch is taken, and its answer is still on its way when the hub is killed.
    hub.service.push(Step::Pass);
    hub.service.push(Step::Delay(Duration::from_secs(2)));
    let mut first = spawn_run(&hub);
    wait_until("the service to take the first batch", || hub.service.last_seq() >= 2);
    first.kill().unwrap(); // SIGKILL: no handler runs, nothing is closed
    first.wait().unwrap();
    let held = hub.service.last_seq();
    let killed = status_of(&hub);
    assert_eq!(
        killed["lastAssignedSeq"], held,
        "every event was in the outbox before it was sent"
    );
    assert_eq!(killed["lastAckedSeq"], 0, "the hub never heard the answer");

    // Started again: the first request is a heartbeat, and its answer confirms what the service already took.
    let mut second = spawn_run(&hub);
    wait_until("the replay to be confirmed", || status_of(&hub)["lastAckedSeq"] == held);
    second.kill().unwrap();
    second.wait().unwrap();

    // And once more, stopped properly this time.
    let mut third = spawn_run(&hub);
    let requests = hub.service.requests().len();
    wait_until("the third hello", || hub.service.requests().len() > requests);
    signal(&third, "TERM");
    assert_eq!(exit_of(&mut third).code(), Some(0));

    let seqs = hub.service.accepted_seqs();
    assert_eq!(
        seqs,
        (1..=seqs.len() as u64).collect::<Vec<_>>(),
        "gapless, each accepted once"
    );
    let sent_first = hub
        .service
        .requests()
        .iter()
        .filter(|record| record.events.as_ref().is_some_and(|events| events.contains(&1)))
        .count();
    // Sent once: the second run opened with a heartbeat, whose `lastSeq` confirmed the batch the first run never
    // heard back about. Nothing is sent again that the service already says it holds.
    assert_eq!(sent_first, 1, "sent once, confirmed by the next run's heartbeat");
    let status = status_of(&hub);
    assert_eq!(status["lastAckedSeq"], status["lastAssignedSeq"]);
    assert_eq!(status["lastAckedSeq"], hub.service.last_seq());
}

// ---- public-key, resume, and what status says about a halt ----

#[test]
fn public_key_prints_the_existing_keys_public_half_and_nothing_else() {
    let tmp = TempDir::new();
    let state = tmp.join("state");
    let made = cli(&["keygen", "--state-dir", path(&state), "--key-id", "hub-key-1"]);
    assert_eq!(made.code, 0);
    let key_file = std::fs::read(state.join("hub.key")).unwrap();
    let again = cli(&["public-key", "--state-dir", path(&state), "--key-id", "hub-key-1"]);
    assert_eq!(
        (again.code, again.out.as_str(), again.err.as_str()),
        (0, made.out.as_str(), "")
    );
    assert_eq!(
        std::fs::read(state.join("hub.key")).unwrap(),
        key_file,
        "nothing changed"
    );
    let body = String::from_utf8(key_file).unwrap().lines().nth(1).unwrap().to_owned();
    assert!(!again.out.contains(&body) && !again.out.contains("PRIVATE"));
    // A second keygen refuses, and says how to get the public key back.
    let refused = cli(&["keygen", "--state-dir", path(&state), "--key-id", "hub-key-1"]);
    assert_eq!(refused.code, 1);
    assert!(
        refused.err.contains("spacegoat-hub public-key --state-dir"),
        "{}",
        refused.err
    );
    // No key: a reason, exit 1; a malformed key id: usage, exit 2.
    let none = cli(&[
        "public-key",
        "--state-dir",
        path(&tmp.join("empty")),
        "--key-id",
        "hub-key-1",
    ]);
    assert_eq!(none.code, 1);
    assert!(none.err.contains("no key"), "{}", none.err);
    assert_eq!(
        cli(&["public-key", "--state-dir", path(&state), "--key-id", "Bad Id"]).code,
        2
    );
}

#[test]
fn status_shows_a_halt_with_its_time_and_names_resume_which_clears_it() {
    let hub = Hub::new();
    let mut agent = hub.run(2);
    hub.service
        .push(Step::status(400, serde_json::json!({"error": "schema"})));
    hub.clock.advance_seconds(2 * 3600);
    agent.tick().unwrap();
    // Refused while the agent holds the directory.
    let busy = cli(&["resume", "--config", path(&hub.config_path)]);
    assert_eq!(busy.code, 1);
    assert!(busy.err.contains("already running"), "{}", busy.err);
    agent.close().unwrap();
    let status = status_of(&hub);
    assert_eq!(status["halted"], "schema");
    assert!(status["haltedAt"].as_str().unwrap().ends_with('Z'));
    let resume = status["resume"].as_str().unwrap();
    assert_eq!(
        resume,
        format!("spacegoat-hub resume --config {}", path(&hub.config_path))
    );
    let cleared = cli(&["resume", "--config", path(&hub.config_path)]);
    assert_eq!(cleared.code, 0, "{}", cleared.err);
    assert!(cleared.out.contains("cleared the halt: schema"), "{}", cleared.out);
    let after = status_of(&hub);
    assert_eq!(
        (after["halted"].clone(), after["resume"].clone()),
        (Value::Null, Value::Null)
    );
    let saved = std::fs::read_to_string(hub.state.join("agent.json")).unwrap();
    assert!(saved.contains("\"halted\": null"), "{saved}");
    // Nothing left to clear.
    let nothing = cli(&["resume", "--config", path(&hub.config_path)]);
    assert_eq!(nothing.code, 1);
    assert!(nothing.err.contains("not halted"), "{}", nothing.err);
}

#[test]
fn a_damaged_outbox_is_said_once_on_stderr_without_its_contents() {
    let hub = Hub::new();
    hub.run(2).close().unwrap();
    hub.lose_outbox();
    std::fs::write(
        hub.state.join("outbox.sqlite"),
        "printer.example 00005e005301 192.0.2.10",
    )
    .unwrap();
    let mut child = spawn_run(&hub);
    wait_until("the reset", || {
        hub.service
            .accepted()
            .iter()
            .any(|event| event["kind"] == "site_source.reset")
    });
    signal(&child, "TERM");
    assert_eq!(exit_of(&mut child).code(), Some(0));
    let (out, err) = output_of(child);
    assert_eq!(out, "");
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.contains("outbox.sqlite.damaged"), "{err}");
    assert_no_personal_data(&err, "stderr");
    assert_eq!(status_of(&hub)["problem"], "outbox_replaced");
}
