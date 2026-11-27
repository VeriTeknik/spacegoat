// SPDX-License-Identifier: AGPL-3.0-or-later
//! The command line: most cases call `cli::run` directly; the last ones run the real binary against the fake service
//! (`--version`, SIGTERM and SIGINT, and a hub killed mid-run and started again).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
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

/// `run --simulate` that must refuse to start: with the stop already set, an agent that did start returns at once
/// (exit 0) instead of running until killed.
fn run_refused(config: &Path) -> Ran {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let args = ["run", "--config", path(config), "--simulate"].map(OsString::from);
    let code = cli::run_until(args, &mut out, &mut err, Arc::new(AtomicBool::new(true)));
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
        "service",
        "problem",
        "cause",
        "resume",
        "readOnly",
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
        "two-space indented JSON: {}",
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
    let ran = run_refused(&hub.config_path);
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
    let again = cli(&["public-key", "--state-dir", path(&state)]);
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
    assert!(!refused.err.contains("--key-id"), "the id is on disk: {}", refused.err);
    // No key: a reason, exit 1; a malformed key id: usage, exit 2.
    let none = cli(&[
        "public-key",
        "--state-dir",
        path(&tmp.join("empty")),
        "--key-id",
        "hub-key-1",
    ]);
    assert_eq!(none.code, 2, "could not start: no state directory, so no key");
    assert!(none.err.contains("missing; run keygen first"), "{}", none.err);
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
    assert_eq!(busy.code, 2);
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

// ---- What `run` says on stderr ----

#[test]
fn run_says_once_on_stderr_that_it_halted_and_how_to_resume() {
    let hub = Hub::new();
    hub.service.push(Step::Pass);
    hub.service
        .push(Step::status(400, serde_json::json!({"error": "schema"})));
    let mut child = spawn_run(&hub);
    wait_until("the halt", || hub.state.join("halt.json").exists());
    wait_until("the halt to be reported", || status_of(&hub)["halted"] == "schema");
    signal(&child, "TERM");
    assert_eq!(exit_of(&mut child).code(), Some(0));
    let (out, err) = output_of(child);
    assert_eq!(out, "");
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.contains("halted") && err.contains("schema"), "{err}");
    assert!(err.contains("spacegoat-hub resume --config"), "{err}");
    assert_no_personal_data(&err, "stderr");
}

// ---- Resume says what clearing means, per reason ----

fn halted_with(hub: &Hub, reason: &str) {
    std::fs::write(
        hub.state.join("halt.json"),
        format!("{{\"version\": 1, \"reason\": \"{reason}\", \"at\": null}}"),
    )
    .unwrap();
}

#[test]
fn resume_says_per_reason_what_clearing_it_means() {
    for (reason, said) in [
        ("schema", &["schema", "refused"][..]),
        ("replay_conflict", &["replay_conflict", "another"][..]),
        ("too_large", &["too_large", "larger"][..]),
        ("ahead", &["ahead", "does not fix", "register it anew"][..]),
        ("gap", &["gap", "halt again", "--from-service"][..]),
        ("unknown", &["unknown"][..]),
    ] {
        let hub = Hub::new();
        halted_with(&hub, if reason == "unknown" { "something new" } else { reason });
        let ran = cli(&["resume", "--config", path(&hub.config_path)]);
        assert_eq!(ran.code, 0, "{reason}: {}", ran.err);
        for words in said {
            assert!(ran.out.contains(words), "{reason}: {words:?} not in {}", ran.out);
        }
        assert!(!hub.state.join("halt.json").exists(), "{reason}");
    }
}

#[test]
fn resume_from_service_is_the_way_out_of_a_gap_also_when_the_service_holds_nothing() {
    for held in [3u64, 0] {
        let hub = Hub::new();
        std::fs::write(
            hub.state.join("confirmed.json"),
            format!(
                r#"{{"version": 1, "lastAckedSeq": 10, "sourceId": "{}"}}"#,
                support::hub::SOURCE
            ),
        )
        .unwrap();
        hub.service.set_last_seq(held);
        hub.run(2).close().unwrap();
        assert_eq!(status_of(&hub)["halted"], "gap", "{held}");
        // Plain resume clears it, and it comes back: the cause is still there.
        let plain = cli(&["resume", "--config", path(&hub.config_path)]);
        assert_eq!(plain.code, 0, "{}", plain.err);
        hub.run(2).close().unwrap();
        assert_eq!(status_of(&hub)["halted"], "gap", "{held}");
        let ran = cli(&["resume", "--config", path(&hub.config_path), "--from-service"]);
        assert_eq!(ran.code, 0, "{}", ran.err);
        assert!(ran.out.contains("queue_lost"), "{}", ran.out);
        let agent = hub.run(3);
        assert_eq!(agent.status().unwrap().halted, None, "{held}");
        let accepted = hub.service.accepted();
        let reset = accepted
            .iter()
            .find(|event| event["kind"] == "site_source.reset")
            .unwrap_or_else(|| panic!("{held}: no reset in {accepted:?}"));
        assert_eq!(reset["sourceSeq"], held + 1, "{held}");
        assert_eq!(
            reset["attributes"],
            serde_json::json!({"trustOrigin": "hub", "lastAckedSeq": held, "reason": "queue_lost"}),
            "{held}"
        );
    }
}

#[test]
fn resume_from_service_is_refused_for_any_other_halt_and_for_a_queue_that_holds_numbers() {
    let hub = Hub::new();
    halted_with(&hub, "schema");
    let ran = cli(&["resume", "--config", path(&hub.config_path), "--from-service"]);
    assert_eq!(ran.code, 1, "{}", ran.out);
    assert!(ran.err.contains("gap"), "{}", ran.err);
    assert!(hub.state.join("halt.json").exists(), "not cleared");
    // A gap met while delivering: the queue still holds numbers the service does not have.
    let hub = Hub::new();
    hub.run(2).close().unwrap();
    halted_with(&hub, "gap");
    let ran = cli(&["resume", "--config", path(&hub.config_path), "--from-service"]);
    assert_eq!(ran.code, 1, "{}", ran.out);
    assert!(ran.err.contains("outbox.sqlite"), "{}", ran.err);
    assert!(hub.state.join("halt.json").exists(), "not cleared");
    // Nothing halted: nothing to resume.
    let hub = Hub::new();
    let ran = cli(&["resume", "--config", path(&hub.config_path), "--from-service"]);
    assert_eq!(ran.code, 1);
    assert!(ran.err.contains("not halted"), "{}", ran.err);
}

// ---- Files of the hub's own that are not files ----

#[test]
fn status_and_resume_refuse_a_status_halt_or_confirmed_file_that_is_not_a_file() {
    for name in ["agent.json", "halt.json", "confirmed.json", "outbox.sqlite"] {
        let hub = Hub::new();
        std::fs::create_dir(hub.state.join(name)).unwrap();
        for command in ["status", "resume"] {
            let ran = cli(&[command, "--config", path(&hub.config_path)]);
            assert_eq!(ran.code, 2, "{command} {name}: {}", ran.err);
            assert!(
                ran.err.contains(name) && ran.err.contains("directory"),
                "{command}: {}",
                ran.err
            );
            assert!(ran.err.contains("by hand"), "{command}: {}", ran.err);
        }
        let ran = run_refused(&hub.config_path);
        assert_eq!(ran.code, 2, "run {name}: {}", ran.err);
        assert!(
            ran.err.contains(name) && ran.err.contains("directory"),
            "run: {}",
            ran.err
        );
    }
}

// ---- The key id on disk ----

#[test]
fn keygen_records_the_key_id_and_public_key_reads_it_back() {
    let tmp = TempDir::new();
    let state = tmp.join("state");
    let made = cli(&["keygen", "--state-dir", path(&state), "--key-id", "hub-key-1"]);
    assert_eq!(made.code, 0, "{}", made.err);
    assert_eq!(support::mode(&state.join("hub.key.id")), 0o600);
    let again = cli(&["public-key", "--state-dir", path(&state)]);
    assert_eq!((again.code, again.out.as_str()), (0, made.out.as_str()));
    let same = cli(&["public-key", "--state-dir", path(&state), "--key-id", "hub-key-1"]);
    assert_eq!((same.code, same.out.as_str()), (0, made.out.as_str()));
    let other = cli(&["public-key", "--state-dir", path(&state), "--key-id", "hub-key-2"]);
    assert_eq!(other.code, 2);
    assert!(
        other.err.contains("hub-key-1") && other.err.contains("hub-key-2"),
        "{}",
        other.err
    );
    assert!(other.out.is_empty());
}

#[test]
fn run_refuses_a_configuration_whose_key_id_is_not_the_one_the_key_was_made_with() {
    let hub = Hub::new();
    std::fs::write(hub.state.join("hub.key.id"), "hub-key-9\n").unwrap();
    std::fs::set_permissions(hub.state.join("hub.key.id"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let ran = run_refused(&hub.config_path);
    assert_eq!(ran.code, 2);
    assert!(
        ran.err.contains("hub-key-1") && ran.err.contains("hub-key-9"),
        "{}",
        ran.err
    );
    assert!(hub.service.requests().is_empty());
}

#[test]
fn a_key_whose_id_was_never_written_still_works_and_public_key_asks_for_the_id() {
    // The fixture makes its key without the id file, as a keygen does that stops between the two writes.
    let hub = Hub::new();
    assert!(!hub.state.join("hub.key.id").exists());
    hub.run(1).close().unwrap();
    let state = path(&hub.state);
    let given = cli(&["public-key", "--state-dir", state, "--key-id", "hub-key-1"]);
    assert_eq!(given.code, 0, "{}", given.err);
    let asked = cli(&["public-key", "--state-dir", state]);
    assert_eq!(asked.code, 2);
    assert!(asked.err.contains("--key-id"), "{}", asked.err);
}

// ---- The state directory: what status refuses, and the messages ----

#[test]
fn status_refuses_what_run_refuses_about_the_state_directory() {
    let hub = Hub::new();
    std::fs::set_permissions(&hub.state, std::fs::Permissions::from_mode(0o750)).unwrap();
    let ran = cli(&["status", "--config", path(&hub.config_path)]);
    assert_eq!(ran.code, 2, "{}", ran.out);
    assert!(ran.err.contains("open to other users"), "{}", ran.err);
    assert!(ran.out.is_empty());
    std::fs::set_permissions(&hub.state, std::fs::Permissions::from_mode(0o700)).unwrap();
    for broken in ["missing", "file"] {
        let hub = Hub::new();
        std::fs::remove_dir_all(&hub.state).unwrap();
        if broken == "file" {
            std::fs::write(&hub.state, "x").unwrap();
        }
        let ran = cli(&["status", "--config", path(&hub.config_path)]);
        assert_eq!(ran.code, 2, "{broken}: {}", ran.out);
        let said = if broken == "file" { "not a directory" } else { "missing" };
        assert!(ran.err.contains(said), "{broken}: {}", ran.err);
        assert!(ran.out.is_empty());
    }
}

#[test]
fn keygen_and_run_on_a_path_that_is_a_file_say_not_a_directory() {
    let tmp = TempDir::new();
    let file = tmp.join("state");
    std::fs::write(&file, "x").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let made = cli(&["keygen", "--state-dir", path(&file), "--key-id", "hub-key-1"]);
    assert_eq!(made.code, 2);
    assert!(made.err.contains("not a directory"), "{}", made.err);
    let hub = Hub::new();
    std::fs::remove_dir_all(&hub.state).unwrap();
    std::fs::write(&hub.state, "x").unwrap();
    let ran = run_refused(&hub.config_path);
    assert_eq!(ran.code, 2);
    assert!(ran.err.contains("not a directory"), "{}", ran.err);
}

#[test]
fn a_directory_the_user_owns_but_cannot_write_is_said_so() {
    if running_as_root() {
        eprintln!("skipped: root writes a directory whatever its mode says, so there is no unwritable one to meet");
        return;
    }
    let tmp = TempDir::new();
    let state = tmp.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o500)).unwrap();
    let made = cli(&["keygen", "--state-dir", path(&state), "--key-id", "hub-key-1"]);
    assert_eq!(made.code, 2);
    assert!(made.err.contains("cannot be written"), "{}", made.err);
    assert!(!made.err.contains("another user"), "{}", made.err);
    let hub = Hub::new();
    std::fs::set_permissions(&hub.state, std::fs::Permissions::from_mode(0o500)).unwrap();
    let ran = run_refused(&hub.config_path);
    std::fs::set_permissions(&hub.state, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(ran.code, 2);
    assert!(ran.err.contains("cannot be written"), "{}", ran.err);
    assert!(!ran.err.contains("another user"), "{}", ran.err);
}

#[test]
fn an_outbox_of_another_source_says_which_is_which_and_prints_neither() {
    let hub = Hub::new();
    hub.run(1).close().unwrap();
    let other = "fedcba98-7654-4321-8fed-cba987654321";
    let text = std::fs::read_to_string(&hub.config_path)
        .unwrap()
        .replace(support::hub::SOURCE, other);
    std::fs::write(&hub.config_path, text).unwrap();
    let ran = run_refused(&hub.config_path);
    assert_eq!(ran.code, 2);
    assert!(
        ran.err.contains("configuration") && ran.err.contains("outbox.sqlite"),
        "{}",
        ran.err
    );
    assert!(
        !ran.err.contains(other) && !ran.err.contains(support::hub::SOURCE),
        "{}",
        ran.err
    );
}

#[test]
fn the_resume_command_status_names_has_an_absolute_path() {
    let hub = Hub::new();
    halted_with(&hub, "schema");
    let output = Command::new(BINARY)
        .args(["status", "--config", "hub.toml"])
        .current_dir(hub.tmp.path())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    let absolute = std::fs::canonicalize(hub.tmp.path()).unwrap().join("hub.toml");
    let named = status["resume"].as_str().unwrap();
    let named_path = named.strip_prefix("spacegoat-hub resume --config ").unwrap();
    assert!(Path::new(named_path).is_absolute(), "{named}");
    assert_eq!(std::fs::canonicalize(named_path).unwrap(), absolute);
}

/// Whether this process runs as root (the owner of a file it creates): root writes where the mode says it may not.
fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    let tmp = TempDir::new();
    let probe = tmp.join("probe");
    std::fs::write(&probe, "").unwrap();
    std::fs::metadata(&probe).unwrap().uid() == 0
}

#[test]
fn exit_codes_are_the_same_in_every_command() {
    let code = |args: &[&str]| cli(args).code;
    let (tmp, hub) = (TempDir::new(), Hub::new());
    let config = path(&hub.config_path);
    let open = tmp.join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A configuration whose state directory others can enter.
    let open_config = tmp.join("open.toml");
    std::fs::write(
        &open_config,
        std::fs::read_to_string(&hub.config_path)
            .unwrap()
            .replace(path(&hub.state), path(&open)),
    )
    .unwrap();
    let open_config = path(&open_config);
    let fresh = tmp.join("fresh");

    // 2: it could not start. A usage error, the state directory, the key, the lock: in every command.
    for args in [
        &["keygen", "--state-dir", path(&fresh)][..],
        &["keygen", "--state-dir", path(&fresh), "--key-id", "Bad Id"],
        &["keygen", "--state-dir", path(&open), "--key-id", "hub-key-1"],
        &["public-key"],
        &["public-key", "--state-dir", path(&open)],
        &["public-key", "--state-dir", path(&fresh), "--key-id", "hub-key-1"],
        &["run", "--simulate"],
        &["run", "--config", config],
        &["status"],
        &["status", "--config", open_config],
        &["status", "--config", path(&tmp.join("absent.toml"))],
        &["resume"],
        &["resume", "--config", open_config],
        &["resume", "--config", path(&tmp.join("absent.toml"))],
    ] {
        assert_eq!(code(args), 2, "{args:?}");
    }
    assert_eq!(run_refused(Path::new(open_config)).code, 2, "run on an open directory");
    let holding = hub.agent();
    halted_with(&hub, "schema");
    assert_eq!(
        code(&["resume", "--config", config]),
        2,
        "resume while the lock is held"
    );
    assert_eq!(run_refused(&hub.config_path).code, 2, "run while the lock is held");
    holding.close().unwrap();

    // 1: it ran and failed.
    assert_eq!(
        code(&["keygen", "--state-dir", path(&hub.state), "--key-id", "hub-key-1"]),
        1,
        "a key exists"
    );
    std::fs::remove_file(hub.state.join("halt.json")).unwrap();
    assert_eq!(code(&["resume", "--config", config]), 1, "nothing to resume");
    let broken = Hub::new();
    std::fs::write(broken.state.join("outbox.sqlite"), "not a database").unwrap();
    assert_eq!(
        code(&["status", "--config", path(&broken.config_path)]),
        1,
        "an outbox that cannot be read"
    );
    // `public-key` and `run` have no way to fail once started that a test can bring about: `run` fails only when
    // the agent cannot be closed or the signal handlers cannot be installed.

    // 0: success.
    assert_eq!(
        code(&["keygen", "--state-dir", path(&fresh), "--key-id", "hub-key-1"]),
        0
    );
    assert_eq!(code(&["public-key", "--state-dir", path(&fresh)]), 0);
    assert_eq!(code(&["status", "--config", config]), 0);
    assert_eq!(run_refused(&hub.config_path).code, 0, "run, stopped at once");
    halted_with(&hub, "schema");
    assert_eq!(code(&["resume", "--config", config]), 0);
}

#[test]
fn every_command_works_without_a_usable_temporary_directory() {
    let hub = Hub::new();
    let nowhere = hub.tmp.join("no-such-directory");
    let binary = |args: &[&str]| {
        Command::new(BINARY)
            .args(args)
            .env("TMPDIR", &nowhere)
            .output()
            .unwrap()
    };
    let config = path(&hub.config_path);
    let state = hub.tmp.join("made-here");
    let made = binary(&["keygen", "--state-dir", path(&state), "--key-id", "hub-key-1"]);
    assert_eq!(made.status.code(), Some(0), "{}", String::from_utf8_lossy(&made.stderr));
    let shown = binary(&["public-key", "--state-dir", path(&state)]);
    assert_eq!(
        shown.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let status = binary(&["status", "--config", config]);
    assert_eq!(
        status.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    halted_with(&hub, "schema");
    let resumed = binary(&["resume", "--config", config]);
    assert_eq!(
        resumed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let mut child = Command::new(BINARY)
        .args(["run", "--config", config, "--simulate"])
        .env("TMPDIR", &nowhere)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_until("the first batch", || hub.service.last_seq() >= 2);
    signal(&child, "TERM");
    assert_eq!(exit_of(&mut child).code(), Some(0));
    let (_, err) = output_of(child);
    assert_eq!(err, "");
    assert!(!nowhere.exists());
}

#[test]
fn a_store_a_newer_version_wrote_is_refused_by_run_and_status_with_exit_2() {
    for name in ["outbox.sqlite", "pseudonyms.sqlite"] {
        let hub = Hub::new();
        hub.run(1).close().unwrap();
        let db = rusqlite::Connection::open(hub.state.join(name)).unwrap();
        db.execute_batch("PRAGMA user_version = 7").unwrap();
        drop(db);
        let ran = run_refused(&hub.config_path);
        assert_eq!(ran.code, 2, "{name}: {}", ran.err);
        assert!(ran.err.contains(name) && ran.err.contains("newer"), "{}", ran.err);
        if name == "outbox.sqlite" {
            let status = cli(&["status", "--config", path(&hub.config_path)]);
            assert_eq!(status.code, 2, "{}", status.err);
            assert!(
                status.err.contains(name) && status.err.contains("newer"),
                "{}",
                status.err
            );
        }
    }
}

// ---- A healthy queue is never set aside: a hot write-ahead log after a kill ----

#[test]
fn an_outbox_with_a_hot_write_ahead_log_after_a_kill_is_not_set_aside() {
    let hub = Hub::new();
    let mut child = spawn_run(&hub);
    wait_until("the first batch", || hub.service.last_seq() >= 2);
    child.kill().unwrap();
    child.wait().unwrap();
    let wal = hub.state.join("outbox.sqlite-wal");
    assert!(
        std::fs::metadata(&wal).unwrap().len() > 0,
        "the log the kill left behind"
    );
    let before = status_of(&hub);
    let agent = hub.agent();
    assert!(agent.notices().is_empty(), "{:?}", agent.notices());
    assert!(!hub.state.join("outbox.sqlite.damaged").exists());
    assert_eq!(
        agent.status().unwrap().last_assigned_seq,
        before["lastAssignedSeq"].as_u64().unwrap()
    );
}

// ---- Fourth review round ----

/// `status` with the real binary; its exit code, stdout and stderr.
fn binary_status(hub: &Hub) -> (Option<i32>, String, String) {
    let output = Command::new(BINARY)
        .args(["status", "--config", path(&hub.config_path)])
        .output()
        .unwrap();
    (
        output.status.code(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn status_on_a_state_directory_it_cannot_write_reads_the_last_written_figures_and_says_so() {
    if running_as_root() {
        eprintln!("skipped: root writes a directory whatever its mode says, so there is no unwritable one to meet");
        return;
    }
    let hub = Hub::new();
    let agent = hub.run(6);
    let before = agent.status().unwrap();
    agent.close().unwrap();
    let names = |hub: &Hub| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&hub.state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort_unstable();
        names
    };
    let present = names(&hub);
    // As a closed agent leaves it: the write-ahead log folded into the database and its side files gone.
    assert!(
        !present
            .iter()
            .any(|name| name.ends_with("-shm") || name.ends_with("-wal")),
        "{present:?}"
    );
    std::fs::set_permissions(&hub.state, std::fs::Permissions::from_mode(0o500)).unwrap();
    let (code, out, err) = binary_status(&hub);
    std::fs::set_permissions(&hub.state, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(err, "");
    let status: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(status["readOnly"], true, "{out}");
    let figures = |status: &Value| {
        (
            status["lastAssignedSeq"].as_u64(),
            status["lastAckedSeq"].as_u64(),
            status["pending"].as_u64(),
        )
    };
    assert_eq!(
        figures(&status),
        (
            Some(before.last_assigned_seq),
            Some(before.last_acked_seq),
            Some(before.pending)
        ),
        "{out}"
    );
    assert!(before.last_acked_seq > 0);
    assert_eq!(names(&hub), present, "nothing was written beside the queue");
    // Writable again: the field says so.
    assert_eq!(status_of(&hub)["readOnly"], false);
}

#[test]
fn status_refuses_a_confirmed_mark_or_a_pseudonym_store_a_newer_version_wrote_like_run() {
    // The pseudonym store.
    let hub = Hub::new();
    hub.run(1).close().unwrap();
    let db = rusqlite::Connection::open(hub.state.join("pseudonyms.sqlite")).unwrap();
    db.execute_batch("PRAGMA user_version = 7").unwrap();
    drop(db);
    let ran = run_refused(&hub.config_path);
    let status = cli(&["status", "--config", path(&hub.config_path)]);
    assert_eq!((status.code, ran.code), (2, 2), "{} / {}", status.err, ran.err);
    assert_eq!(status.err, ran.err);
    assert!(
        status.err.contains("pseudonyms.sqlite") && status.err.contains("newer"),
        "{}",
        status.err
    );
    assert!(status.out.is_empty());
    // The confirmed mark.
    let hub = Hub::new();
    hub.run(1).close().unwrap();
    std::fs::write(
        hub.state.join("confirmed.json"),
        format!(
            r#"{{"version": 2, "lastAckedSeq": 1, "sourceId": "{}"}}"#,
            support::hub::SOURCE
        ),
    )
    .unwrap();
    let ran = run_refused(&hub.config_path);
    let status = cli(&["status", "--config", path(&hub.config_path)]);
    assert_eq!((status.code, ran.code), (2, 2), "{} / {}", status.err, ran.err);
    assert_eq!(status.err, ran.err);
    assert!(
        status.err.contains("confirmed.json") && status.err.contains("newer"),
        "{}",
        status.err
    );
    assert!(status.out.is_empty());
}

#[test]
fn public_key_checks_the_state_directory_as_every_other_command_does() {
    let tmp = TempDir::new();
    let state = tmp.join("state");
    assert_eq!(
        cli(&["keygen", "--state-dir", path(&state), "--key-id", "hub-key-1"]).code,
        0
    );
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
    let open = cli(&["public-key", "--state-dir", path(&state)]);
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(open.code, 2, "{}", open.out);
    assert!(open.err.contains("open to other users"), "{}", open.err);
    assert!(open.out.is_empty());
    let file = tmp.join("file");
    std::fs::write(&file, "x").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let not_dir = cli(&["public-key", "--state-dir", path(&file), "--key-id", "hub-key-1"]);
    assert_eq!(not_dir.code, 2);
    assert!(not_dir.err.contains("not a directory"), "{}", not_dir.err);
}
