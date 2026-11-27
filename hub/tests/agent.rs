// SPDX-License-Identifier: AGPL-3.0-or-later
//! The whole agent with simulated observations, against a service that checks signatures and sequence for real
//! (`support/fake_service.rs`) over real sockets: an interruption, a lost answer, a lost outbox, a reinstall, the clock
//! gate, a halt, a second agent. The command-line cases are in `tests/cli.rs`, the configuration one in
//! `tests/config.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use spacegoat_hub::agent::{self, Agent, AgentError, Observer, Sighting};
use spacegoat_hub::canonical::canonical_json;
use spacegoat_hub::clock;
use spacegoat_hub::sender;
use spacegoat_hub::simulate::SimulatedObserver;
use support::fake_service::{Step, TestClock};
use support::hub::{Hub, assert_no_personal_data};
use support::mode;

fn of_kind(events: &[Value], kind: &str) -> Vec<Value> {
    events.iter().filter(|event| event["kind"] == kind).cloned().collect()
}

fn assert_gapless(hub: &Hub) {
    let seqs = hub.service.accepted_seqs();
    assert_eq!(seqs, (1..=seqs.len() as u64).collect::<Vec<_>>());
}

fn reset_of(hub: &Hub) -> Value {
    of_kind(&hub.service.accepted(), "site_source.reset")
        .into_iter()
        .next()
        .expect("no reset was declared")
}

/// How many requests carried event `seq` (a replay is a second one).
fn times_sent(hub: &Hub, seq: u64) -> usize {
    hub.service
        .requests()
        .iter()
        .filter(|record| record.events.as_ref().is_some_and(|events| events.contains(&seq)))
        .count()
}

/// An observer a test steers: it reports whatever the shared list holds.
#[derive(Clone, Default)]
struct Steered(Arc<Mutex<Vec<Sighting>>>);

impl Steered {
    fn set(&self, sightings: Vec<Sighting>) {
        *self.0.lock().unwrap() = sightings;
    }
}

impl Observer for Steered {
    fn poll(&mut self) -> Vec<Sighting> {
        self.0.lock().unwrap().clone()
    }
}

fn sighting(identity: &str, class: &str, mac: Option<&str>, hostname: Option<&str>, ip: Option<&str>) -> Sighting {
    Sighting {
        identity: identity.to_owned(),
        segment: "odd:lan".to_owned(),
        device_class: class.to_owned(),
        mac: mac.map(str::to_owned),
        hostname: hostname.map(str::to_owned),
        ip: ip.map(str::to_owned),
        ephemeral: false,
    }
}

#[test]
fn test_simulated_run_reports_devices_in_order_and_the_service_accepts_each_once() {
    // Six hours pass between rounds: a device joins at each of the first four, a device that is still there is
    // reported as seen once a day (not every round), a snapshot goes every round (each is more than an hour apart),
    // and the device whose address keeps changing is only ever counted.
    let hub = Hub::new();
    let mut agent = hub.agent();
    for _ in 0..12 {
        agent.tick().unwrap();
        hub.clock.advance_seconds(6 * 3600);
    }
    let accepted = hub.service.accepted();
    let kinds: Vec<&str> = accepted.iter().map(|event| event["kind"].as_str().unwrap()).collect();
    let mut expected = Vec::new();
    for round in 0..12 {
        expected.push(if round < 4 {
            "site.device_appeared"
        } else {
            "site.device_seen"
        });
        expected.push("site.inventory_snapshot");
    }
    assert_eq!(kinds, expected);
    assert_gapless(&hub);
    // The devices in the order they joined, and each one seen at 24 h and at 48 h after it was told: twice.
    let device_of = |event: &Value| event["attributes"]["deviceRef"].clone();
    let appeared: Vec<Value> = of_kind(&accepted, "site.device_appeared")
        .iter()
        .map(device_of)
        .collect();
    let classes: Vec<Value> = of_kind(&accepted, "site.device_appeared")
        .iter()
        .map(|event| event["attributes"]["deviceClass"].clone())
        .collect();
    assert_eq!(
        classes,
        [json!("printer"), json!("user_device"), json!("ot"), json!("network")]
    );
    assert_eq!(appeared.iter().collect::<HashSet<_>>().len(), 4);
    let seen: Vec<Value> = of_kind(&accepted, "site.device_seen").iter().map(device_of).collect();
    let twice: Vec<Value> = appeared.iter().chain(appeared.iter()).cloned().collect();
    assert_eq!(seen, twice);
    // Every snapshot counts the lasting devices present in its round, and the one ephemeral device.
    let snapshots = of_kind(&accepted, "site.inventory_snapshot");
    assert_eq!(snapshots.len(), 12);
    for (round, snapshot) in snapshots.iter().enumerate() {
        let counts = snapshot["attributes"]["counts"].as_object().unwrap();
        assert_eq!(counts.len(), 7);
        let present = (round + 1).min(4) as u64;
        assert_eq!(
            counts.values().map(|n| n.as_u64().unwrap()).sum::<u64>(),
            present,
            "{round}"
        );
        assert_eq!(snapshot["attributes"]["ephemeral"], 1, "{round}");
    }
    assert_eq!(
        snapshots.last().unwrap()["attributes"]["counts"],
        json!({"ot": 1, "printer": 1, "user_device": 1, "server": 0, "network": 1, "iot": 0, "unknown": 0})
    );
    assert!(accepted.iter().all(|event| event["attributes"]["trustOrigin"] == "hub"));
    let first = &of_kind(&accepted, "site.device_appeared")[0];
    assert_eq!(
        first["pii"],
        json!({"mac": "00005e005301", "hostname": "printer.example", "ip": "192.0.2.10"})
    );
    assert_eq!(
        first["attributes"].as_object().unwrap().keys().collect::<Vec<_>>(),
        ["deviceClass", "deviceRef", "segmentRef", "trustOrigin"]
    );
    // Nothing of the ephemeral device travelled.
    let everything = canonical_json(&Value::Array(accepted.clone())).unwrap();
    assert!(!everything.contains("00005e00538"), "an ephemeral address went out");
    assert_eq!(agent.status().unwrap().last_acked_seq, 24);
    assert_eq!(hub.service.last_seq(), 24);
}

#[test]
fn test_stopping_mid_run_and_starting_again_loses_and_repeats_nothing() {
    let hub = Hub::new();
    // The hello goes through; the answer to the first batch is lost on the way back.
    hub.service.push(Step::Pass);
    hub.service.push(Step::LoseAnswer);
    let first = hub.run(3);
    let before = first.status().unwrap();
    assert!(
        before.last_acked_seq < before.last_assigned_seq,
        "the lost answer left events unconfirmed"
    );
    first.close().unwrap(); // the process ends with events still unconfirmed
    let before_requests = hub.service.requests().len();
    let second = hub.run(40);
    assert_gapless(&hub);
    let after = second.status().unwrap();
    assert!(after.last_assigned_seq > before.last_assigned_seq);
    assert_eq!(after.last_acked_seq, after.last_assigned_seq);
    // The first event went twice: the restart's first request is an empty heartbeat, which confirms nothing queued;
    // the batch whose answer was lost went again, and the service counted it as a duplicate. Nothing accepted twice.
    assert_eq!(times_sent(&hub, 1), 2);
    assert!(
        hub.service.requests()[before_requests].events == Some(vec![]),
        "the restart opened with a heartbeat"
    );
    // The same simulated devices are the same pseudonyms after the restart.
    let appeared = of_kind(&hub.service.accepted(), "site.device_appeared");
    let refs: HashSet<&Value> = appeared.iter().map(|event| &event["attributes"]["deviceRef"]).collect();
    assert_eq!(refs.len(), appeared.len());
    assert_eq!(appeared.len(), 4);
}

#[test]
fn a_lost_answer_is_sent_again_and_accepted_once() {
    let hub = Hub::new();
    hub.service.push(Step::Pass);
    hub.service.push(Step::LoseAnswer);
    let mut agent = hub.run(1);
    assert_eq!(hub.service.last_seq(), 2, "the service took the batch");
    assert_eq!(agent.status().unwrap().last_acked_seq, 0, "the hub never heard so");
    hub.clock.advance_seconds(6); // the first back-off is five seconds
    agent.tick().unwrap();
    assert_eq!(times_sent(&hub, 1), 2);
    assert_gapless(&hub);
    let status = agent.status().unwrap();
    assert_eq!(status.last_acked_seq, status.last_assigned_seq);
    agent.close().unwrap();
}

#[test]
fn test_a_lost_outbox_is_declared_never_papered_over() {
    let hub = Hub::new();
    let first = hub.run(8);
    let confirmed = first.status().unwrap().last_acked_seq;
    assert_eq!(confirmed, hub.service.last_seq());
    first.close().unwrap();
    hub.lose_outbox();
    let second = hub.run(8);
    let reset = reset_of(&hub);
    assert_eq!(reset["sourceSeq"], confirmed + 1);
    assert_eq!(
        reset["attributes"],
        json!({"trustOrigin": "hub", "lastAckedSeq": confirmed, "reason": "queue_lost"})
    );
    assert_gapless(&hub);
    assert_eq!(second.status().unwrap().halted, None);
}

#[test]
fn test_a_hub_with_no_record_of_ever_being_confirmed_starts_at_one() {
    let hub = Hub::new();
    let agent = hub.run(4);
    let accepted = hub.service.accepted();
    assert_eq!(accepted[0]["sourceSeq"], 1);
    assert!(accepted.iter().all(|event| event["kind"] != "site_source.reset"));
    agent.close().unwrap();
}

#[test]
fn test_nothing_is_produced_while_the_clock_is_not_set() {
    let hub = Hub::new();
    let before_the_protocol = clock::observed_at_millis("2020-01-01T00:00:00.000Z").unwrap();
    let mut agent = Agent::open(
        &hub.config,
        Box::new(SimulatedObserver::new()),
        TestClock::at_wall(before_the_protocol).as_clock(),
    )
    .unwrap();
    for _ in 0..5 {
        agent.tick().unwrap();
    }
    let status = agent.status().unwrap();
    assert_eq!(status.last_assigned_seq, 0);
    assert!(
        hub.service.requests().is_empty(),
        "a hub that cannot tell the time asks nothing"
    );
    assert_eq!(status.waiting_for.as_deref(), Some("clock"));
    let saved = std::fs::read_to_string(hub.state.join("agent.json")).unwrap();
    assert_eq!(
        saved,
        r#"{"version": 1, "waitingFor": "clock", "service": null, "problem": null, "cause": null}"#
    );
}

#[test]
fn a_clock_at_the_epoch_is_not_set_either() {
    let hub = Hub::new();
    let mut agent = Agent::open(
        &hub.config,
        Box::new(SimulatedObserver::new()),
        TestClock::at_wall(0).as_clock(),
    )
    .unwrap();
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().waiting_for.as_deref(), Some("clock"));
    assert!(hub.service.requests().is_empty());
}

#[test]
fn test_a_halted_agent_says_why_makes_no_request_and_produces_nothing_more() {
    let hub = Hub::new();
    let mut agent = hub.run(2);
    hub.service.push(Step::status(400, json!({"error": "schema"})));
    hub.clock.advance_seconds(4 * 3600); // the next snapshot is due
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().halted.as_deref(), Some("schema"));
    let requests = hub.service.requests().len();
    let assigned = agent.status().unwrap().last_assigned_seq;
    for _ in 0..5 {
        hub.clock.advance_seconds(4 * 3600); // snapshots, sightings and heartbeats would all be due
        agent.tick().unwrap();
    }
    // No knocking, and no queue growing behind a fault nothing can deliver past.
    assert_eq!(hub.service.requests().len(), requests);
    assert_eq!(agent.status().unwrap().last_assigned_seq, assigned);
    let saved = std::fs::read_to_string(hub.state.join("agent.json")).unwrap();
    assert_eq!(
        saved,
        r#"{"version": 1, "waitingFor": null, "service": "http_400", "problem": null, "cause": null}"#
    );
}

#[test]
fn test_unauthorized_does_not_stop_the_agent_for_good() {
    let hub = Hub::new();
    hub.service.push(Step::status(401, json!({"error": "unauthorized"})));
    let mut agent = hub.run(3);
    let status = agent.status().unwrap();
    assert_eq!(status.halted, None);
    assert_eq!(status.waiting_for.as_deref(), Some("unauthorized"));
    assert_eq!(
        status.last_assigned_seq, 0,
        "nothing is produced before the service has answered"
    );
    assert_eq!(
        hub.service.requests().len(),
        1,
        "and it asks again only after five minutes"
    );
    hub.clock.advance_seconds(301);
    agent.tick().unwrap();
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().waiting_for, None);
    assert!(!hub.service.accepted().is_empty());
}

/// The hub's clock `offset` seconds from the service's; produces nothing, then everything once the clock is right.
fn a_clock_off_by(offset: i64) {
    let hub = Hub::new();
    let hub_clock = TestClock::new();
    hub_clock.set_offset_seconds(offset);
    let mut agent = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub_clock.as_clock()).unwrap();
    for _ in 0..3 {
        agent.tick().unwrap();
    }
    let status = agent.status().unwrap();
    assert_eq!(status.waiting_for.as_deref(), Some("clock"));
    assert_eq!((status.last_assigned_seq, status.halted), (0, None));
    assert!(hub.service.accepted().is_empty());
    assert_eq!(
        hub.service.requests().len(),
        1,
        "one greeting, then the wait after the 401"
    );
    // The clock is set right; the wait after the `401` is counted on the monotonic clock, so it is the same 240 s
    // whichever way the wall clock was off.
    hub_clock.set_offset_seconds(0);
    for clock in [&hub_clock, &hub.clock] {
        clock.advance_seconds(sender::UNAUTHORIZED_RETRY_SECONDS as i64);
    }
    for _ in 0..3 {
        agent.tick().unwrap();
    }
    assert_eq!(agent.status().unwrap().waiting_for, None);
    assert!(!hub.service.accepted().is_empty());
    assert_gapless(&hub);
}

#[test]
fn test_a_clock_more_than_four_minutes_off_produces_nothing_until_it_is_right() {
    a_clock_off_by(-1800); // restored from the last shutdown, half an hour behind
}

#[test]
fn a_clock_ahead_produces_nothing_either() {
    a_clock_off_by(1800);
}

#[test]
fn a_clock_off_within_the_service_window_but_beyond_four_minutes_still_produces_nothing() {
    // The service accepts the request (it is within its five minutes), but an event signed now could be refused
    // later: the hub keeps four minutes as its own limit.
    let hub = Hub::new();
    let hub_clock = TestClock::new();
    hub_clock.set_offset_seconds(270);
    let mut agent = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub_clock.as_clock()).unwrap();
    for _ in 0..3 {
        agent.tick().unwrap();
    }
    assert!(!hub.service.requests().is_empty(), "the hello went through");
    assert_eq!(agent.status().unwrap().waiting_for.as_deref(), Some("clock"));
    assert_eq!(agent.status().unwrap().last_assigned_seq, 0);
    assert!(hub.service.accepted().is_empty());
}

#[test]
fn test_the_reset_uses_the_number_the_service_holds_not_the_hubs_own_memory() {
    // The last answer was lost: the service is ahead of what the hub believes was confirmed.
    let hub = Hub::new();
    hub.run(3).close().unwrap();
    std::fs::write(
        hub.state.join("confirmed.json"),
        format!(
            r#"{{"version": 1, "lastAckedSeq": 1, "sourceId": "{}"}}"#,
            hub.config.source_id
        ),
    )
    .unwrap();
    hub.lose_outbox();
    let held = hub.service.last_seq();
    assert!(held > 1);
    let second = hub.run(4);
    let reset = reset_of(&hub);
    assert_eq!(
        (reset["sourceSeq"].clone(), reset["attributes"]["lastAckedSeq"].clone()),
        (json!(held + 1), json!(held))
    );
    assert_eq!(reset["attributes"]["reason"], "queue_lost");
    assert_eq!(second.status().unwrap().halted, None);
}

#[test]
fn test_after_a_lost_queue_every_device_is_reported_again_under_the_same_reference() {
    // Reports that sat in the lost queue never reached the service. The hub cannot know which, so it tells all again.
    let hub = Hub::new();
    hub.run(6).close().unwrap();
    let refs = |events: &[Value]| -> HashSet<Value> {
        of_kind(events, "site.device_appeared")
            .iter()
            .map(|event| event["attributes"]["deviceRef"].clone())
            .collect()
    };
    let before = refs(&hub.service.accepted());
    assert_eq!(before.len(), 4);
    hub.lose_outbox();
    let mark = hub.service.accepted().len();
    hub.run(6).close().unwrap();
    assert_eq!(refs(&hub.service.accepted()[mark..]), before);
}

#[test]
fn test_state_files_that_became_readable_by_others_are_closed_again() {
    let hub = Hub::new();
    hub.run(3).close().unwrap();
    for name in ["outbox.sqlite", "pseudonyms.sqlite"] {
        std::fs::set_permissions(hub.state.join(name), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    hub.run(1).close().unwrap();
    for name in [
        "outbox.sqlite",
        "pseudonyms.sqlite",
        "confirmed.json",
        "agent.json",
        "hub.key",
        "agent.lock",
    ] {
        assert_eq!(mode(&hub.state.join(name)) & 0o077, 0, "{name}");
    }
}

#[test]
fn test_a_second_agent_on_the_same_state_directory_refuses_to_start() {
    let hub = Hub::new();
    let first = hub.run(1);
    let refused = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub.clock.as_clock()).unwrap_err();
    assert!(matches!(refused, AgentError::AlreadyRunning(_)), "{refused:?}");
    assert!(refused.to_string().contains("already running"));
    let requests = hub.service.requests().len();
    first.close().unwrap();
    assert_eq!(
        hub.service.requests().len(),
        requests,
        "the refused agent asked nothing"
    );
    hub.agent().close().unwrap();
}

#[test]
fn test_everything_lost_is_declared_as_a_reinstall() {
    let hub = Hub::new();
    hub.run(5).close().unwrap();
    let held = hub.service.last_seq();
    hub.lose_outbox();
    std::fs::remove_file(hub.state.join("confirmed.json")).unwrap();
    let second = hub.run(4);
    assert_eq!(
        reset_of(&hub)["attributes"],
        json!({"trustOrigin": "hub", "lastAckedSeq": held, "reason": "reinstall"})
    );
    assert_eq!(second.status().unwrap().halted, None);
    assert_gapless(&hub);
}

#[test]
fn test_what_an_observer_hands_over_is_checked_before_it_is_signed() {
    let hub = Hub::new();
    let long_name = "x".repeat(300);
    let observer = Steered::default();
    observer.set(vec![
        sighting(
            "odd:1",
            "toaster",
            Some("02:00:5E:10:01:AA"),
            Some("bad\0name"),
            Some("999.1.1.1"),
        ),
        sighting(
            "odd:2",
            "printer",
            Some("00005e005302"),
            Some(&long_name),
            Some("2001:DB8::1"),
        ),
        // A name that is not plain ASCII (a lone surrogate, the other case, cannot be held by a Rust string).
        sighting("odd:3", "iot", None, Some("café"), None),
    ]);
    let mut agent = Agent::open(&hub.config, Box::new(observer), hub.clock.as_clock()).unwrap();
    for _ in 0..3 {
        agent.tick().unwrap();
    }
    let accepted = hub.service.accepted();
    let appeared = of_kind(&accepted, "site.device_appeared");
    let classes: Vec<&Value> = appeared
        .iter()
        .map(|event| &event["attributes"]["deviceClass"])
        .collect();
    assert_eq!(classes, [&json!("unknown"), &json!("printer"), &json!("iot")]);
    assert!(appeared[0].get("pii").is_none(), "nothing of it was fit to send");
    assert_eq!(appeared[1]["pii"], json!({"mac": "00005e005302", "ip": "2001:db8::1"}));
    assert!(appeared[2].get("pii").is_none());
    // The snapshot counts the class the event carried: the toaster is an `unknown`, not missing from the counts.
    let counts = &of_kind(&accepted, "site.inventory_snapshot")[0]["attributes"]["counts"];
    assert_eq!(counts["unknown"], 1);
    assert_eq!(counts["printer"], 1);
    assert_eq!(counts["iot"], 1);
    assert_eq!(agent.status().unwrap().halted, None);
}

#[test]
fn a_device_that_changes_is_reported_with_what_changed_and_only_once() {
    let hub = Hub::new();
    let observer = Steered::default();
    let printer = |name: &str, ip: &str| sighting("p", "printer", Some("00005e005301"), Some(name), Some(ip));
    observer.set(vec![printer("printer.example", "192.0.2.10")]);
    let mut agent = Agent::open(&hub.config, Box::new(observer.clone()), hub.clock.as_clock()).unwrap();
    agent.tick().unwrap();
    observer.set(vec![printer("printer2.example", "192.0.2.10")]);
    agent.tick().unwrap();
    agent.tick().unwrap();
    observer.set(vec![printer("printer2.example", "192.0.2.11")]);
    agent.tick().unwrap();
    let changed = of_kind(&hub.service.accepted(), "site.device_changed");
    assert_eq!(changed.len(), 2);
    assert_eq!(changed[0]["attributes"]["changed"], json!(["name"]));
    assert_eq!(changed[1]["attributes"]["changed"], json!(["address"]));
    assert_eq!(changed[1]["pii"]["ip"], "192.0.2.11");
    assert_gapless(&hub);
}

#[test]
fn a_state_directory_others_can_enter_is_refused_and_left_as_it_is() {
    let hub = Hub::new();
    std::fs::set_permissions(&hub.state, std::fs::Permissions::from_mode(0o750)).unwrap();
    let refused = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub.clock.as_clock()).unwrap_err();
    assert!(refused.to_string().contains("open to other users"), "{refused}");
    assert_eq!(mode(&hub.state), 0o750);
    assert!(!hub.state.join("outbox.sqlite").exists());
}

#[test]
fn personal_data_never_reaches_the_status_file_the_status_or_the_attributes() {
    let hub = Hub::new();
    let mut agent = hub.run(6);
    hub.service.push(Step::status(400, json!({"error": "schema"})));
    hub.clock.advance_seconds(2 * 86_400);
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().halted.as_deref(), Some("schema"));
    let saved = std::fs::read_to_string(hub.state.join("agent.json")).unwrap();
    assert_no_personal_data(&saved, "agent.json");
    assert_no_personal_data(&agent.status().unwrap().to_json_text(), "status");
    assert_no_personal_data(&format!("{agent:?}"), "the agent's debug form");
    for event in hub.service.accepted() {
        assert_no_personal_data(&canonical_json(&event["attributes"]).unwrap(), "attributes");
    }
    // And the personal data did travel, in its own part.
    let pii: Vec<Value> = hub
        .service
        .accepted()
        .iter()
        .filter_map(|event| event.get("pii").cloned())
        .collect();
    assert!(pii.iter().any(|pii| pii["hostname"] == "printer.example"));
}

#[test]
fn run_ticks_until_stopped_and_never_sleeps_for_real() {
    let hub = Hub::new();
    let stop = Arc::new(AtomicBool::new(false));
    let mut slept = Duration::ZERO;
    let started = Instant::now();
    let ticks_wanted = 5;
    agent::run(hub.agent(), Arc::clone(&stop), |pause| {
        slept += pause;
        hub.clock.advance_millis(pause.as_millis() as i64); // time passes only through the test's clock
        if slept >= Duration::from_secs(agent::TICK_SECONDS * ticks_wanted) {
            stop.store(true, Ordering::SeqCst);
        }
    })
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10), "it slept for real");
    assert_eq!(slept, Duration::from_secs(agent::TICK_SECONDS * ticks_wanted));
    // Five ticks: all four simulated devices appeared, and everything was confirmed.
    assert_eq!(of_kind(&hub.service.accepted(), "site.device_appeared").len(), 4);
    // The agent was closed: the lock is free again.
    let again = hub.agent();
    let status = again.status().unwrap();
    assert_eq!(status.last_acked_seq, status.last_assigned_seq);
}

#[test]
fn a_stop_set_before_the_first_tick_runs_no_tick() {
    let hub = Hub::new();
    let stop = Arc::new(AtomicBool::new(true));
    agent::run(hub.agent(), stop, |_| panic!("no wait either")).unwrap();
    assert!(hub.service.requests().is_empty());
}

// ---- Two clocks: what the hub trusts, and how it measures time ----

/// An agent on `hub`'s configuration with a clock of its own (the service keeps `hub.clock`).
fn agent_on(hub: &Hub, clock: &TestClock) -> Agent {
    Agent::open(&hub.config, Box::new(SimulatedObserver::new()), clock.as_clock()).unwrap()
}

/// Time passes for both sides.
fn pass(clocks: &[&TestClock], seconds: i64) {
    for clock in clocks {
        clock.advance_seconds(seconds);
    }
}

fn empty_answer(last_seq: u64) -> Value {
    json!({"accepted": 0, "duplicates": 0, "lastSeq": last_seq})
}

#[test]
fn a_first_answer_without_a_date_is_no_reading_and_nothing_is_produced() {
    // The hub's clock is half an hour ahead; the only answer it gets has no `Date`. No reading: not trusted.
    let hub = Hub::new();
    let hub_clock = TestClock::new();
    hub_clock.set_offset_seconds(1800);
    hub.service.push(Step::without_date(200, empty_answer(0)));
    let mut agent = agent_on(&hub, &hub_clock);
    for _ in 0..3 {
        agent.tick().unwrap();
    }
    let status = agent.status().unwrap();
    assert_eq!(status.waiting_for.as_deref(), Some("clock"));
    assert_eq!(status.last_assigned_seq, 0, "nothing was signed");
    assert_eq!(
        hub.service.requests().len(),
        1,
        "the next reading waits for the next heartbeat"
    );
    // When the heartbeat is due, the hub asks again; this answer has a `Date`, and it says the clock is off.
    pass(&[&hub_clock, &hub.clock], sender::HEARTBEAT_SECONDS);
    agent.tick().unwrap();
    assert_eq!(hub.service.requests().len(), 2);
    assert_eq!(agent.status().unwrap().last_assigned_seq, 0);
    assert!(hub.service.accepted().is_empty());
}

#[test]
fn an_answer_without_a_date_after_a_bad_reading_does_not_unblock() {
    let hub = Hub::new();
    let hub_clock = TestClock::new();
    hub_clock.set_offset_seconds(1800);
    let mut agent = agent_on(&hub, &hub_clock);
    agent.tick().unwrap(); // 401, with a `Date` that shows the half hour
    assert_eq!(agent.status().unwrap().waiting_for.as_deref(), Some("clock"));
    pass(&[&hub_clock, &hub.clock], sender::UNAUTHORIZED_RETRY_SECONDS as i64);
    hub.service
        .push(Step::without_date(503, json!({"error": "unavailable"})));
    agent.tick().unwrap();
    assert_eq!(hub.service.requests().len(), 2, "the heartbeat went and was answered");
    // The answer had no `Date`: the reading that showed the half hour still stands, so it is still the clock.
    assert_eq!(agent.status().unwrap().waiting_for.as_deref(), Some("clock"));
    pass(&[&hub_clock, &hub.clock], sender::BACKOFF_FIRST_SECONDS as i64);
    hub.service.push(Step::without_date(200, empty_answer(0)));
    for _ in 0..3 {
        agent.tick().unwrap();
    }
    assert_eq!(agent.status().unwrap().waiting_for.as_deref(), Some("clock"));
    assert_eq!(agent.status().unwrap().last_assigned_seq, 0);
    assert!(hub.service.accepted().is_empty());
}

#[test]
fn a_wall_clock_that_jumps_after_the_greeting_signs_nothing_with_the_jumped_time() {
    let hub = Hub::new();
    let hub_clock = TestClock::new();
    let mut agent = agent_on(&hub, &hub_clock);
    agent.tick().unwrap();
    let produced = agent.status().unwrap().last_assigned_seq;
    assert!(produced > 0);
    // The wall clock jumps an hour ahead; no time passes. A snapshot would be due by the jumped clock.
    hub_clock.step_wall_seconds(3600);
    let jumped = hub_clock.now();
    for _ in 0..3 {
        agent.tick().unwrap();
    }
    assert_eq!(agent.status().unwrap().waiting_for.as_deref(), Some("clock"));
    assert_eq!(
        agent.status().unwrap().last_assigned_seq,
        produced,
        "nothing new was signed"
    );
    // Heartbeats still go when due (the service refuses them: their timestamp is an hour off), and still nothing.
    pass(&[&hub_clock, &hub.clock], sender::HEARTBEAT_SECONDS);
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().last_assigned_seq, produced);
    for event in hub.service.accepted() {
        let at = clock::observed_at_millis(event["observedAt"].as_str().unwrap()).unwrap();
        assert!(at < jumped - 3_000_000, "{event}");
    }
}

#[test]
fn a_wall_clock_stepped_back_keeps_heartbeats_on_time_and_the_agent_recovers_by_itself() {
    let hub = Hub::new();
    let hub_clock = TestClock::new();
    let mut agent = agent_on(&hub, &hub_clock);
    agent.tick().unwrap();
    let produced = agent.status().unwrap().last_assigned_seq;
    let before = hub.service.requests().len();
    hub_clock.step_wall_seconds(-3 * 3600);
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().waiting_for.as_deref(), Some("clock"));
    // A clock that was trusted and is not any more takes a new reading at once.
    assert_eq!(hub.service.requests().len(), before + 1, "a new reading at once");
    assert_eq!(
        hub.service.requests().last().unwrap().events,
        None,
        "refused: three hours off"
    );
    // The wait after that `401` is 240 s of real time on the monotonic clock, whatever the wall clock says.
    pass(&[&hub_clock, &hub.clock], sender::UNAUTHORIZED_RETRY_SECONDS as i64 - 1);
    agent.tick().unwrap();
    assert_eq!(hub.service.requests().len(), before + 1, "still waiting out the 401");
    pass(&[&hub_clock, &hub.clock], 1);
    agent.tick().unwrap();
    assert_eq!(hub.service.requests().len(), before + 2, "the heartbeat went out");
    assert_eq!(agent.status().unwrap().last_assigned_seq, produced);
    // NTP puts the wall clock right. Nobody touches the hub.
    hub_clock.step_wall_seconds(3 * 3600);
    pass(&[&hub_clock, &hub.clock], sender::UNAUTHORIZED_RETRY_SECONDS as i64);
    agent.tick().unwrap();
    agent.tick().unwrap();
    let status = agent.status().unwrap();
    assert_eq!(status.waiting_for, None);
    assert!(status.last_assigned_seq > produced, "producing again");
    assert_eq!(status.last_acked_seq, status.last_assigned_seq);
    assert_gapless(&hub);
}

#[test]
fn a_time_kept_from_a_clock_that_was_ahead_counts_as_due() {
    // A first run on a clock two days ahead (the service's too, so everything is accepted); then the clocks are set
    // right. What was told "in two days" must not silence a device or a segment for two days.
    let hub = Hub::new();
    let ahead = TestClock::new();
    ahead.set_offset_seconds(2 * 86_400);
    hub.service.set_now(ahead.as_fn());
    let first = agent_on(&hub, &ahead);
    let mut first = first;
    first.tick().unwrap();
    first.close().unwrap();
    hub.service.set_now(hub.clock.as_fn());
    // The service still holds those events; their time is within its 24.8 days.
    let mark = hub.service.accepted().len();
    hub.run(1).close().unwrap();
    let kinds: Vec<Value> = hub.service.accepted()[mark..]
        .iter()
        .map(|e| e["kind"].clone())
        .collect();
    assert_eq!(kinds, [json!("site.device_seen"), json!("site.inventory_snapshot")]);
}

#[test]
fn the_first_request_of_a_run_is_an_empty_heartbeat_even_when_events_wait() {
    let hub = Hub::new();
    hub.service.push(Step::Pass);
    hub.service.push(Step::status(503, json!({"error": "unavailable"})));
    let first = hub.run(1);
    let waiting = first.status().unwrap();
    assert!(waiting.pending > 0);
    first.close().unwrap();
    let mark = hub.service.requests().len();
    hub.run(1).close().unwrap();
    let after: Vec<Option<Vec<u64>>> = hub.service.requests()[mark..]
        .iter()
        .map(|r| r.events.clone())
        .collect();
    assert_eq!(after[0], Some(vec![]), "the greeting carries no event");
    assert_eq!(
        after[1].as_ref().unwrap()[0],
        1,
        "the events follow in the next request"
    );
}

// ---- Where the sequence starts for an outbox that never assigned a number ----

#[test]
fn a_service_that_holds_less_than_this_hub_had_confirmed_halts_with_gap() {
    for held in [0, 3] {
        let hub = Hub::new();
        std::fs::write(
            hub.state.join("confirmed.json"),
            format!(
                r#"{{"version": 1, "lastAckedSeq": 10, "sourceId": "{}"}}"#,
                hub.config.source_id
            ),
        )
        .unwrap();
        hub.service.set_last_seq(held);
        let mut agent = hub.run(3);
        let status = agent.status().unwrap();
        assert_eq!(status.halted.as_deref(), Some("gap"), "{held}");
        assert_eq!(
            status.last_assigned_seq, 0,
            "{held}: nothing produced, no reset declared"
        );
        assert_eq!(hub.service.requests().len(), 1, "{held}: only the greeting");
        assert!(hub.service.accepted().is_empty());
        assert!(
            std::fs::read_to_string(hub.state.join("halt.json"))
                .unwrap()
                .contains("\"gap\"")
        );
        agent.tick().unwrap();
        assert_eq!(hub.service.requests().len(), 1);
    }
}

#[test]
fn a_new_queue_with_nothing_confirmed_anywhere_reports_every_device_again() {
    // The first run reports, but nothing reaches the service; the queue is then lost. Neither side holds anything:
    // the sequence starts at 1, and the devices whose reports sat in the lost queue are announced again.
    let hub = Hub::new();
    hub.service.push(Step::Pass);
    for _ in 0..8 {
        hub.service.push(Step::status(503, json!({"error": "unavailable"})));
    }
    let mut first = hub.agent();
    for _ in 0..4 {
        first.tick().unwrap();
        hub.clock.advance_seconds(1);
    }
    assert!(hub.service.accepted().is_empty());
    first.close().unwrap();
    hub.lose_outbox();
    let mut second = hub.agent();
    for _ in 0..12 {
        second.tick().unwrap();
        hub.clock.advance_seconds(sender::BACKOFF_MAX_SECONDS as i64); // past whatever back-off is left
    }
    let accepted = hub.service.accepted();
    assert_eq!(accepted[0]["sourceSeq"], 1);
    assert!(of_kind(&accepted, "site_source.reset").is_empty());
    assert_eq!(of_kind(&accepted, "site.device_appeared").len(), 4);
    assert_gapless(&hub);
}

#[test]
fn a_crash_after_the_facts_were_forgotten_comes_back_to_the_same_reset() {
    let hub = Hub::new();
    hub.run(4).close().unwrap();
    let confirmed = hub.service.last_seq();
    hub.lose_outbox();
    // The crash: facts forgotten, nothing else done.
    let mut pseudonyms = spacegoat_hub::state::Pseudonyms::open(&hub.state.join("pseudonyms.sqlite")).unwrap();
    pseudonyms.forget_facts().unwrap();
    pseudonyms.close().unwrap();
    hub.run(4).close().unwrap();
    let resets = of_kind(&hub.service.accepted(), "site_source.reset");
    assert_eq!(resets.len(), 1);
    assert_eq!(resets[0]["sourceSeq"], confirmed + 1);
    assert_eq!(resets[0]["attributes"]["reason"], "queue_lost");
    assert_gapless(&hub);
}

#[test]
fn a_crash_after_the_reset_was_declared_delivers_that_reset_and_declares_no_second() {
    let hub = Hub::new();
    hub.run(4).close().unwrap();
    let held = hub.service.last_seq();
    hub.lose_outbox();
    // The crash: facts forgotten and the reset declared, `confirmed.json` not yet written.
    let key = spacegoat_hub::keystore::FileKeyStore::new(hub.state.join("hub.key"))
        .load()
        .unwrap();
    let mut outbox = spacegoat_hub::outbox::Outbox::open(
        &hub.state.join("outbox.sqlite"),
        &hub.config.source_id,
        &hub.config.key_id,
        key,
    )
    .unwrap();
    outbox
        .declare_reset(held, spacegoat_hub::outbox::ResetReason::QueueLost, hub.clock.now())
        .unwrap();
    outbox.close().unwrap();
    let agent = hub.run(4);
    let resets = of_kind(&hub.service.accepted(), "site_source.reset");
    assert_eq!(resets.len(), 1);
    assert_eq!(resets[0]["sourceSeq"], held + 1);
    assert_gapless(&hub);
    let status = agent.status().unwrap();
    assert_eq!(status.last_acked_seq, status.last_assigned_seq);
    let written: Value =
        serde_json::from_str(&std::fs::read_to_string(hub.state.join("confirmed.json")).unwrap()).unwrap();
    assert_eq!(
        written,
        json!({"version": 1, "lastAckedSeq": status.last_acked_seq, "sourceId": hub.config.source_id})
    );
}

#[test]
fn a_service_that_moves_ahead_during_delivery_goes_through_the_same_decision() {
    // Nothing to report, so the outbox stays empty after a greeting that found the service at 0. Later the service
    // holds 5 (a reinstall elsewhere, a restored service): the next answer says so, and it is not ignored.
    let hub = Hub::new();
    let observer = Steered::default();
    let mut agent = Agent::open(&hub.config, Box::new(observer), hub.clock.as_clock()).unwrap();
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().last_assigned_seq, 0);
    hub.service.set_last_seq(5);
    hub.clock.advance_seconds(sender::HEARTBEAT_SECONDS);
    agent.tick().unwrap();
    let resets = of_kind(&hub.service.accepted(), "site_source.reset");
    assert_eq!(resets.len(), 1);
    assert_eq!(
        resets[0]["attributes"],
        json!({"trustOrigin": "hub", "lastAckedSeq": 5, "reason": "reinstall"})
    );
    assert_eq!(agent.status().unwrap().last_acked_seq, 6);
}

// ---- A halt survives a restart ----

#[test]
fn a_halt_survives_a_restart_until_it_is_cleared() {
    let hub = Hub::new();
    let mut agent = hub.run(2);
    hub.service.push(Step::status(400, json!({"error": "schema"})));
    hub.clock.advance_seconds(2 * 3600);
    agent.tick().unwrap();
    agent.close().unwrap();
    let halt: Value = serde_json::from_str(&std::fs::read_to_string(hub.state.join("halt.json")).unwrap()).unwrap();
    assert_eq!(halt["reason"], "schema");
    assert!(clock::observed_at_millis(halt["at"].as_str().unwrap()).is_some());
    assert_eq!(mode(&hub.state.join("halt.json")), 0o600);
    let requests = hub.service.requests().len();
    let mut reopened = hub.agent();
    for _ in 0..3 {
        hub.clock.advance_seconds(3600);
        reopened.tick().unwrap();
    }
    assert_eq!(hub.service.requests().len(), requests, "no request at all");
    let status = reopened.status().unwrap();
    assert_eq!(status.halted.as_deref(), Some("schema"));
    let assigned = status.last_assigned_seq;
    reopened.close().unwrap();
    let cleared = agent::resume(&hub.config, None).unwrap().unwrap();
    assert_eq!(cleared.reason, "schema");
    assert!(!hub.state.join("halt.json").exists());
    let resumed = hub.run(2);
    let status = resumed.status().unwrap();
    assert_eq!(status.halted, None);
    assert!(status.last_assigned_seq >= assigned);
    assert_eq!(
        status.last_acked_seq, status.last_assigned_seq,
        "it continued where it stood"
    );
    assert_gapless(&hub);
}

#[test]
fn resume_refuses_while_an_agent_holds_the_directory_and_says_when_nothing_is_halted() {
    let hub = Hub::new();
    let running = hub.agent();
    assert!(matches!(
        agent::resume(&hub.config, None),
        Err(AgentError::AlreadyRunning(_))
    ));
    running.close().unwrap();
    assert_eq!(agent::resume(&hub.config, None).unwrap(), None);
}

// ---- Damaged storage ----

#[test]
fn a_damaged_outbox_is_set_aside_and_declared_as_a_lost_queue() {
    let hub = Hub::new();
    hub.run(4).close().unwrap();
    let held = hub.service.last_seq();
    hub.lose_outbox();
    std::fs::write(
        hub.state.join("outbox.sqlite"),
        b"this is not a database, it is a small poem",
    )
    .unwrap();
    std::fs::write(hub.state.join("outbox.sqlite.damaged"), b"an earlier one").unwrap();
    let mut agent = hub.agent();
    assert_eq!(agent.notices().len(), 1);
    assert!(agent.notices()[0].contains("outbox.sqlite.damaged"));
    assert!(!agent.notices()[0].contains("poem"));
    assert_eq!(
        std::fs::read(hub.state.join("outbox.sqlite.damaged")).unwrap(),
        b"this is not a database, it is a small poem"
    );
    assert_eq!(mode(&hub.state.join("outbox.sqlite.damaged")), 0o600);
    for _ in 0..3 {
        agent.tick().unwrap();
    }
    assert_eq!(agent.status().unwrap().problem.as_deref(), Some("outbox_replaced"));
    let reset = reset_of(&hub);
    assert_eq!(reset["attributes"]["reason"], "queue_lost");
    assert_eq!(reset["attributes"]["lastAckedSeq"], held);
    assert_gapless(&hub);
    let saved = std::fs::read_to_string(hub.state.join("agent.json")).unwrap();
    assert!(saved.contains("\"problem\": \"outbox_replaced\""), "{saved}");
}

#[test]
fn a_truncated_outbox_fails_its_check_and_is_set_aside() {
    let hub = Hub::new();
    hub.run(3).close().unwrap();
    // Sound header, pages cut off.
    let path = hub.state.join("outbox.sqlite");
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.len() > 4096);
    std::fs::write(&path, &bytes[..bytes.len() / 2 + 100]).unwrap();
    let agent = hub.agent();
    assert!(hub.state.join("outbox.sqlite.damaged").exists());
    assert_eq!(agent.status().unwrap().last_assigned_seq, 0);
}

#[test]
fn a_damaged_pseudonym_store_is_set_aside_and_devices_get_new_references() {
    let hub = Hub::new();
    hub.run(4).close().unwrap();
    let before: HashSet<Value> = of_kind(&hub.service.accepted(), "site.device_appeared")
        .iter()
        .map(|event| event["attributes"]["deviceRef"].clone())
        .collect();
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(hub.state.join(format!("pseudonyms.sqlite{suffix}")));
    }
    std::fs::write(hub.state.join("pseudonyms.sqlite"), vec![0xA5u8; 8192]).unwrap();
    let mark = hub.service.accepted().len();
    let mut agent = hub.agent();
    assert!(agent.notices()[0].contains("new references"));
    for _ in 0..4 {
        agent.tick().unwrap();
    }
    assert_eq!(agent.status().unwrap().problem.as_deref(), Some("pseudonyms_replaced"));
    let after: HashSet<Value> = of_kind(&hub.service.accepted()[mark..], "site.device_appeared")
        .iter()
        .map(|event| event["attributes"]["deviceRef"].clone())
        .collect();
    assert_eq!(after.len(), 4);
    assert!(after.is_disjoint(&before));
}

#[test]
fn an_outbox_that_cannot_be_opened_for_another_reason_is_an_error_and_is_left_alone() {
    let hub = Hub::new();
    hub.run(2).close().unwrap();
    let path = hub.state.join("outbox.sqlite");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let refused = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub.clock.as_clock());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(refused.is_err());
    assert!(!hub.state.join("outbox.sqlite.damaged").exists());
}

// ---- A run that meets a storage error goes on ----

/// A trigger, installed from another connection, that makes every new reference fail: the pseudonym store's writes
/// fail while the agent runs, and nothing else does.
fn break_new_references(hub: &Hub, broken: bool) {
    let db = rusqlite::Connection::open(hub.state.join("pseudonyms.sqlite")).unwrap();
    if broken {
        db.execute_batch("CREATE TRIGGER broken BEFORE INSERT ON refs BEGIN SELECT RAISE(ABORT, 'disk on fire'); END")
            .unwrap();
    } else {
        db.execute_batch("DROP TRIGGER broken").unwrap();
    }
}

/// The `X-VT-Timestamp` of every request, in seconds.
fn request_times(hub: &Hub) -> Vec<i64> {
    hub.service
        .requests()
        .iter()
        .map(|record| record.header("X-VT-Timestamp").unwrap().parse().unwrap())
        .collect()
}

#[test]
fn run_records_a_storage_error_sends_no_heartbeat_while_it_lasts_and_recovers() {
    let hub = Hub::new();
    let agent = hub.agent();
    break_new_references(&hub, true);
    let stop = Arc::new(AtomicBool::new(false));
    let mut elapsed = 0i64;
    let mut problems = Vec::new();
    let state = hub.state.clone();
    let started = hub.clock.now() / 1000;
    agent::run(agent, Arc::clone(&stop), |pause| {
        elapsed += pause.as_millis() as i64;
        hub.clock.advance_millis(pause.as_millis() as i64);
        if elapsed % 10_000 == 0 {
            problems.push(agent::read_saved_status(&state).unwrap().problem);
        }
        if elapsed == 20 * 60_000 {
            break_new_references(&hub, false);
        }
        if elapsed >= 22 * 60_000 {
            stop.store(true, Ordering::SeqCst);
        }
    })
    .unwrap();
    assert!(problems.contains(&Some("pseudonyms_failed".to_owned())), "{problems:?}");
    assert_eq!(problems.last().unwrap(), &None, "recovered");
    // A heartbeat says "alive, nothing to report", which a hub that cannot capture cannot say: after the greeting
    // the service heard nothing until the store was repaired (its silence alert is the signal), then everything.
    let times = request_times(&hub);
    assert_eq!(hub.service.requests()[0].events, Some(vec![]), "the greeting");
    assert!(times[0] - started < 5, "{times:?}");
    assert!(
        times[1] - started >= 20 * 60,
        "a request while capture was failing: {times:?}"
    );
    assert_eq!(of_kind(&hub.service.accepted(), "site.device_appeared").len(), 4);
    // Twenty minutes without capture are said once capture resumed.
    let lost = of_kind(&hub.service.accepted(), "site_source.input_lost");
    assert_eq!(lost.len(), 1, "{lost:?}");
    assert_eq!(lost[0]["attributes"]["reason"], "capture_stopped");
    let from = clock::observed_at_millis(lost[0]["attributes"]["fromTime"].as_str().unwrap()).unwrap();
    assert!((from / 1000 - started).abs() < 5, "from when capture first failed");
    assert_gapless(&hub);
}

#[test]
fn a_confirmed_mark_or_status_file_that_cannot_be_written_does_not_stop_delivery() {
    let hub = Hub::new();
    hub.run(1).close().unwrap();
    let mut agent = hub.agent();
    // While it runs (at its start they are refused by name).
    for name in ["confirmed.json", "agent.json"] {
        let path = hub.state.join(name);
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("in-the-way"), "x").unwrap();
    }
    for _ in 0..4 {
        agent.tick().unwrap();
        hub.clock.advance_seconds(1);
    }
    let status = agent.status().unwrap();
    assert!(status.problem.is_some());
    assert_eq!(status.last_acked_seq, status.last_assigned_seq);
    assert_eq!(of_kind(&hub.service.accepted(), "site.device_appeared").len(), 4);
}

// ---- What the agent writes, and what it sweeps ----

#[test]
fn agent_json_is_written_only_when_it_changes() {
    use std::os::unix::fs::MetadataExt;
    let hub = Hub::new();
    let mut agent = hub.agent();
    agent.tick().unwrap();
    let inode = || std::fs::metadata(hub.state.join("agent.json")).unwrap().ino();
    let first = inode();
    for _ in 0..3 {
        agent.tick().unwrap();
    }
    assert_eq!(inode(), first, "rewritten although nothing changed");
    hub.service.push(Step::status(401, json!({"error": "unauthorized"})));
    hub.clock.advance_seconds(sender::HEARTBEAT_SECONDS);
    agent.tick().unwrap();
    assert_ne!(inode(), first, "a change is written");
}

#[test]
fn leftover_temporary_files_of_ours_are_removed_at_open_and_nothing_else() {
    let hub = Hub::new();
    let hex = "0123456789abcdef0123456789abcdef";
    let victim = hub.tmp.join("victim");
    std::fs::write(&victim, "untouched").unwrap();
    let file = hub.state.join(format!(".agent.json.{hex}"));
    std::fs::write(&file, "half").unwrap();
    let key_copy = hub.state.join(format!(".hub.key.{hex}"));
    std::fs::write(&key_copy, "a private key, half written").unwrap();
    let link = hub.state.join(format!(".confirmed.json.{hex}"));
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let directory = hub.state.join(format!(".halt.json.{hex}"));
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("inside"), "kept").unwrap();
    let not_ours = [
        hub.state.join(".agent.json.short"),
        hub.state.join(format!(".agent.json.{}", &hex[1..])),
        hub.state.join(format!(".agent.json.{hex}0")),
        hub.state.join("notes.txt"),
        hub.state.join(format!(".something.{hex}")),
    ];
    for path in &not_ours {
        std::fs::write(path, "someone's").unwrap();
    }
    hub.agent().close().unwrap();
    assert!(!file.exists());
    assert!(!key_copy.exists());
    assert!(std::fs::symlink_metadata(&link).is_err(), "the link itself is removed");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched", "never followed");
    assert!(directory.join("inside").exists(), "a directory is left alone");
    for path in &not_ours {
        assert!(path.exists(), "{}", path.display());
    }
}

#[test]
fn a_state_directory_of_another_user_is_refused() {
    use std::os::unix::fs::MetadataExt;
    let hub = Hub::new();
    let owner = std::fs::metadata(&hub.state).unwrap().uid();
    let settings = agent::AgentSettings {
        expected_owner: Some(owner + 1),
        ..agent::AgentSettings::default()
    };
    let refused = Agent::open_with(
        &hub.config,
        Box::new(SimulatedObserver::new()),
        hub.clock.as_clock(),
        settings,
    )
    .unwrap_err();
    assert!(refused.to_string().contains("belongs to another user"), "{refused}");
    assert!(!hub.state.join("outbox.sqlite").exists());
    assert!(!hub.state.join("agent.lock").exists());
}

#[test]
fn a_stop_between_the_requests_of_a_tick_is_heard() {
    let hub = Hub::new();
    let mut agent = hub.agent();
    agent.watch_stop(Arc::new(AtomicBool::new(true)));
    agent.tick().unwrap();
    assert_eq!(
        hub.service.requests().len(),
        1,
        "the greeting, and no delivery after the stop"
    );
    assert!(agent.status().unwrap().pending > 0);
}

// ---- The backlog cap ----

#[test]
fn a_full_backlog_stops_production_and_says_what_was_not_captured_once_it_drains() {
    let hub = Hub::new();
    let settings = agent::AgentSettings {
        backlog_cap: 4,
        ..agent::AgentSettings::default()
    };
    let mut agent = Agent::open_with(
        &hub.config,
        Box::new(SimulatedObserver::new()),
        hub.clock.as_clock(),
        settings,
    )
    .unwrap();
    hub.service.push(Step::Pass);
    for _ in 0..40 {
        hub.service.push(Step::status(503, json!({"error": "unavailable"})));
    }
    let mut waited = Vec::new();
    for _ in 0..6 {
        agent.tick().unwrap();
        waited.push(agent.status().unwrap().waiting_for);
        hub.clock.advance_seconds(3600);
    }
    let status = agent.status().unwrap();
    assert_eq!(status.pending, 4, "stopped at the cap");
    // What it waits for is the service that confirms nothing; the backlog is why it produces nothing meanwhile.
    assert_eq!(
        (status.waiting_for.as_deref(), status.service.as_deref()),
        (Some("service"), Some("http_503"))
    );
    assert!(waited.iter().filter(|w| w.as_deref() == Some("service")).count() >= 3);
    // A restart while it is full keeps it stopped: the mark lives in the outbox.
    agent.close().unwrap();
    let mut agent = Agent::open_with(
        &hub.config,
        Box::new(SimulatedObserver::new()),
        hub.clock.as_clock(),
        settings,
    )
    .unwrap();
    // The service is back.
    while hub.service.requests().len() < 41 {
        hub.service.push(Step::Pass);
        agent.tick().unwrap();
        hub.clock.advance_seconds(sender::BACKOFF_MAX_SECONDS as i64);
    }
    for _ in 0..3 {
        agent.tick().unwrap();
        hub.clock.advance_seconds(60);
    }
    let accepted = hub.service.accepted();
    let lost = of_kind(&accepted, "site_source.input_lost");
    assert_eq!(lost.len(), 1);
    let attributes = lost[0]["attributes"].as_object().unwrap();
    assert_eq!(attributes["reason"], "capture_stopped");
    assert_eq!(attributes["toTime"], lost[0]["observedAt"]);
    assert!(attributes["fromTime"].as_str().unwrap() < attributes["toTime"].as_str().unwrap());
    // It came right after the four that filled the queue, and production went on after it.
    assert_eq!(lost[0]["sourceSeq"], 5);
    assert!(accepted.len() > 5);
    assert_eq!(agent.status().unwrap().waiting_for, None);
    assert_gapless(&hub);
}

// ---- Ephemeral devices and emptied segments ----

#[test]
fn an_ephemeral_device_is_only_counted_and_gets_no_reference() {
    let hub = Hub::new();
    hub.run(3).close().unwrap();
    let accepted = hub.service.accepted();
    assert_eq!(of_kind(&accepted, "site.device_appeared").len(), 3);
    for snapshot in of_kind(&accepted, "site.inventory_snapshot") {
        assert_eq!(snapshot["attributes"]["ephemeral"], 1);
    }
    let db = rusqlite::Connection::open(hub.state.join("pseudonyms.sqlite")).unwrap();
    let devices: Vec<String> = db
        .prepare("SELECT identity FROM refs WHERE scope = 'device' ORDER BY identity")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(devices, ["sim:laptop", "sim:plc", "sim:printer"]);
}

#[test]
fn a_segment_that_emptied_still_gets_its_snapshot_when_due() {
    let hub = Hub::new();
    let observer = Steered::default();
    observer.set(vec![sighting("p", "printer", None, None, None)]);
    let mut agent = Agent::open(&hub.config, Box::new(observer.clone()), hub.clock.as_clock()).unwrap();
    agent.tick().unwrap();
    observer.set(vec![]);
    hub.clock.advance_seconds(1800);
    agent.tick().unwrap();
    assert_eq!(
        of_kind(&hub.service.accepted(), "site.inventory_snapshot").len(),
        1,
        "not due yet"
    );
    hub.clock.advance_seconds(1800);
    agent.tick().unwrap();
    let snapshots = of_kind(&hub.service.accepted(), "site.inventory_snapshot");
    assert_eq!(snapshots.len(), 2);
    assert_eq!(
        snapshots[1]["attributes"]["segmentRef"],
        snapshots[0]["attributes"]["segmentRef"]
    );
    assert_eq!(
        snapshots[1]["attributes"]["counts"],
        json!({"ot": 0, "printer": 0, "user_device": 0, "server": 0, "network": 0, "iot": 0, "unknown": 0})
    );
    assert_eq!(snapshots[1]["attributes"]["ephemeral"], 0);
}

// ---- What the status says about the service after the greeting ----

#[test]
fn after_the_greeting_the_status_says_when_the_service_confirms_nothing_and_which_kind() {
    let hub = Hub::new();
    let mut agent = hub.run(1);
    let status = agent.status().unwrap();
    assert_eq!((status.waiting_for, status.service), (None, None));
    hub.service.push(Step::status(503, json!({"error": "unavailable"})));
    hub.clock.advance_seconds(3600); // a snapshot is due: a batch goes
    agent.tick().unwrap();
    let status = agent.status().unwrap();
    assert_eq!(
        (status.waiting_for.as_deref(), status.service.as_deref()),
        (Some("service"), Some("http_503"))
    );
    let saved = std::fs::read_to_string(hub.state.join("agent.json")).unwrap();
    assert!(
        saved.contains(r#""waitingFor": "service", "service": "http_503""#),
        "{saved}"
    );
    hub.service.push(Step::status(200, json!({"hello": "a portal"})));
    hub.clock.advance_seconds(5);
    agent.tick().unwrap();
    let status = agent.status().unwrap();
    assert_eq!(
        (status.waiting_for.as_deref(), status.service.as_deref()),
        (Some("service"), Some("not_confirming"))
    );
    hub.clock.advance_seconds(10);
    agent.tick().unwrap();
    let status = agent.status().unwrap();
    assert_eq!(
        (status.waiting_for, status.service),
        (None, None),
        "cleared by a confirming answer"
    );
    assert_eq!(status.pending, 0);
}

// ---- One line per change, never per tick ----

#[test]
fn run_reports_one_line_per_change_and_none_per_tick() {
    let hub = Hub::new();
    hub.service.push(Step::Pass);
    for _ in 0..3 {
        hub.service.push(Step::status(503, json!({"error": "unavailable"})));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let mut lines = Vec::new();
    let mut elapsed = 0u128;
    agent::run_reporting(
        hub.agent(),
        Arc::clone(&stop),
        |pause| {
            elapsed += pause.as_millis();
            hub.clock.advance_millis(pause.as_millis() as i64);
            if elapsed >= 10 * 60_000 {
                stop.store(true, Ordering::SeqCst);
            }
        },
        |line| lines.push(line.to_owned()),
    )
    .unwrap();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[0].contains("waiting for the service") && lines[0].contains("http_503"),
        "{lines:?}"
    );
    assert!(lines[1].contains("running normally"), "{lines:?}");
    for line in &lines {
        assert_no_personal_data(line, "a reported line");
        assert_eq!(line.lines().count(), 1);
    }
}

// ---- What was reported is remembered for the run ----

/// A trigger, from another connection, that makes every update of the pseudonym store fail: what was reported cannot
/// be recorded, while new references can still be made.
fn break_updates(hub: &Hub, broken: bool) {
    let db = rusqlite::Connection::open(hub.state.join("pseudonyms.sqlite")).unwrap();
    if broken {
        db.execute_batch("CREATE TRIGGER broken BEFORE UPDATE ON refs BEGIN SELECT RAISE(ABORT, 'disk on fire'); END")
            .unwrap();
    } else {
        db.execute_batch("DROP TRIGGER broken").unwrap();
    }
}

#[test]
fn a_store_that_cannot_record_what_was_reported_reports_each_device_once_and_delivers_meanwhile() {
    let hub = Hub::new();
    let mut agent = hub.agent();
    agent.tick().unwrap();
    break_updates(&hub, true);
    for _ in 0..12 {
        hub.clock.advance_seconds(600);
        assert!(agent.tick().is_err(), "the store write fails");
        assert_eq!(agent.status().unwrap().problem.as_deref(), Some("pseudonyms_failed"));
        assert_eq!(agent.status().unwrap().pending, 0, "delivered meanwhile");
    }
    let accepted = hub.service.accepted();
    let appeared = of_kind(&accepted, "site.device_appeared");
    let refs: HashSet<&Value> = appeared.iter().map(|event| &event["attributes"]["deviceRef"]).collect();
    assert_eq!((appeared.len(), refs.len()), (4, 4), "one device_appeared per device");
    // A snapshot an hour, not one a tick.
    assert!(of_kind(&accepted, "site.inventory_snapshot").len() <= 3);
    assert!(
        of_kind(&accepted, "site_source.input_lost").is_empty(),
        "capture never stopped"
    );
    // Repaired: the store write is retried and succeeds; nothing is reported again.
    break_updates(&hub, false);
    let before = hub.service.accepted().len();
    hub.clock.advance_seconds(60);
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().problem, None);
    assert_eq!(hub.service.accepted().len(), before);
    agent.close().unwrap();
    let pseudonyms = spacegoat_hub::state::Pseudonyms::open(&hub.state.join("pseudonyms.sqlite")).unwrap();
    for identity in ["sim:printer", "sim:laptop", "sim:plc", "sim:switch"] {
        assert!(!pseudonyms.facts("device", identity).unwrap().is_empty(), "{identity}");
    }
}

// ---- An untrusted clock stops production only ----

#[test]
fn a_clock_that_is_not_trusted_stops_production_but_a_full_backlog_still_drains() {
    let hub = Hub::new();
    let settings = agent::AgentSettings {
        backlog_cap: 4,
        ..agent::AgentSettings::default()
    };
    let mut agent = Agent::open_with(
        &hub.config,
        Box::new(SimulatedObserver::new()),
        hub.clock.as_clock(),
        settings,
    )
    .unwrap();
    hub.service.push(Step::Pass);
    for _ in 0..40 {
        hub.service.push(Step::status(503, json!({"error": "unavailable"})));
    }
    for _ in 0..6 {
        agent.tick().unwrap();
        hub.clock.advance_seconds(3600);
    }
    let full = agent.status().unwrap();
    assert_eq!((full.pending, full.waiting_for.as_deref()), (4, Some("service")));
    agent.close().unwrap();
    // The service is back; this hub's wall clock is now 270 s ahead of it: inside the service's five minutes, beyond
    // the hub's own four.
    hub.service.clear_script();
    let ahead = TestClock::at_wall(hub.clock.now() + 270_000);
    let mut agent = Agent::open_with(
        &hub.config,
        Box::new(SimulatedObserver::new()),
        ahead.as_clock(),
        settings,
    )
    .unwrap();
    for _ in 0..3 {
        agent.tick().unwrap();
        pass(&[&ahead, &hub.clock], 10);
    }
    let status = agent.status().unwrap();
    assert_eq!(status.waiting_for.as_deref(), Some("clock"));
    assert_eq!(status.last_assigned_seq, full.last_assigned_seq, "nothing new signed");
    assert_eq!(status.pending, 0, "what was signed is delivered");
    assert_eq!(hub.service.last_seq(), full.last_assigned_seq);
}

// ---- A clock that jumps ----

#[test]
fn a_wall_clock_that_jumps_takes_a_new_reading_at_once() {
    let hub = Hub::new();
    let hub_clock = TestClock::new();
    let mut agent = agent_on(&hub, &hub_clock);
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().pending, 0);
    let before = hub.service.requests().len();
    hub_clock.step_wall_seconds(3600);
    agent.tick().unwrap();
    assert_eq!(
        hub.service.requests().len(),
        before + 1,
        "a new reading at once, not at the next heartbeat"
    );
    assert_eq!(agent.status().unwrap().waiting_for.as_deref(), Some("clock"));
}

#[test]
fn a_tick_reads_the_clocks_after_the_greeting() {
    let hub = Hub::new();
    // Every answer takes ten seconds of the hub's time: the service moves the shared clock as it answers.
    let shared = hub.clock.clone();
    hub.service.set_now(Arc::new(move || {
        shared.advance_seconds(10);
        shared.now()
    }));
    let before = hub.clock.now();
    hub.run(1).close().unwrap();
    let first = &hub.service.accepted()[0];
    let observed = clock::observed_at_millis(first["observedAt"].as_str().unwrap()).unwrap();
    assert!(
        observed >= before + 10_000,
        "observed before the greeting was answered: {first}"
    );
}

// ---- A stop in capture longer than five minutes is declared ----

#[test]
fn a_halt_is_declared_as_lost_input_once_capture_resumes() {
    let hub = Hub::new();
    let mut agent = hub.run(2);
    hub.service.push(Step::status(400, json!({"error": "schema"})));
    hub.clock.advance_seconds(3600);
    let halted_at = hub.clock.now();
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().halted.as_deref(), Some("schema"));
    for _ in 0..3 {
        hub.clock.advance_seconds(3600);
        agent.tick().unwrap();
    }
    agent.close().unwrap();
    agent::resume(&hub.config, None).unwrap().unwrap();
    hub.clock.advance_seconds(60);
    let resumed_at = hub.clock.now();
    hub.run(2).close().unwrap();
    let lost = of_kind(&hub.service.accepted(), "site_source.input_lost");
    assert_eq!(lost.len(), 1, "{lost:?}");
    let attributes = &lost[0]["attributes"];
    assert_eq!(attributes["reason"], "capture_stopped");
    let from = clock::observed_at_millis(attributes["fromTime"].as_str().unwrap()).unwrap();
    let to = clock::observed_at_millis(attributes["toTime"].as_str().unwrap()).unwrap();
    assert!(from >= halted_at && from - halted_at < 5_000, "from the halt");
    assert!(to >= resumed_at, "to when capture resumed");
    assert_gapless(&hub);
}

#[test]
fn a_clock_distrust_shorter_than_five_minutes_is_not_declared_and_a_longer_one_is() {
    for (seconds, declared) in [(241, false), (360, true)] {
        let hub = Hub::new();
        let hub_clock = TestClock::new();
        let mut agent = agent_on(&hub, &hub_clock);
        agent.tick().unwrap();
        hub_clock.step_wall_seconds(3600);
        agent.tick().unwrap();
        assert_eq!(agent.status().unwrap().waiting_for.as_deref(), Some("clock"));
        hub_clock.step_wall_seconds(-3600);
        pass(&[&hub_clock, &hub.clock], seconds);
        agent.tick().unwrap();
        agent.tick().unwrap();
        assert_eq!(agent.status().unwrap().waiting_for, None, "{seconds}");
        let lost = of_kind(&hub.service.accepted(), "site_source.input_lost");
        assert_eq!(lost.len(), usize::from(declared), "{seconds}: {lost:?}");
        if declared {
            // The stop began while the clock was not trusted: no `fromTime`.
            assert!(lost[0]["attributes"].get("fromTime").is_none(), "{}", lost[0]);
        }
        assert_gapless(&hub);
    }
}

// ---- A new pseudonym store beside a queue that assigned numbers ----

#[test]
fn a_new_or_empty_pseudonym_store_beside_a_queue_that_assigned_numbers_is_said() {
    for empty in [false, true] {
        let hub = Hub::new();
        hub.run(2).close().unwrap();
        if empty {
            let db = rusqlite::Connection::open(hub.state.join("pseudonyms.sqlite")).unwrap();
            db.execute("DELETE FROM refs", []).unwrap();
        } else {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(hub.state.join(format!("pseudonyms.sqlite{suffix}")));
            }
        }
        let mut agent = hub.agent();
        assert_eq!(agent.notices().len(), 1, "{empty}: {:?}", agent.notices());
        assert!(agent.notices()[0].contains("new references"), "{:?}", agent.notices());
        agent.tick().unwrap();
        assert_eq!(
            agent.status().unwrap().problem.as_deref(),
            Some("pseudonyms_new"),
            "{empty}"
        );
    }
    // A hub that has never assigned a number has nothing to say about it.
    let hub = Hub::new();
    let agent = hub.agent();
    assert!(agent.notices().is_empty());
}

// ---- What was confirmed ----

#[test]
fn an_unreadable_confirmed_mark_beside_a_queue_that_assigned_numbers_is_rewritten_from_the_queue() {
    let hub = Hub::new();
    let first = hub.run(3);
    let acked = first.status().unwrap().last_acked_seq;
    first.close().unwrap();
    std::fs::write(hub.state.join("confirmed.json"), "a page of something else").unwrap();
    let agent = hub.agent();
    assert!(
        agent.notices().iter().any(|notice| notice.contains("confirmed.json")),
        "{:?}",
        agent.notices()
    );
    assert!(agent.notices().iter().all(|notice| !notice.contains("something else")));
    let written: Value =
        serde_json::from_str(&std::fs::read_to_string(hub.state.join("confirmed.json")).unwrap()).unwrap();
    assert_eq!(
        written,
        json!({"version": 1, "lastAckedSeq": acked, "sourceId": hub.config.source_id})
    );
}

#[test]
fn an_unreadable_confirmed_mark_beside_a_queue_that_never_assigned_a_number_is_a_lost_queue_not_a_gap() {
    for held in [0u64, 5] {
        let hub = Hub::new();
        std::fs::write(hub.state.join("confirmed.json"), r#"{"lastAckedSeq": "many"}"#).unwrap();
        hub.service.set_last_seq(held);
        let agent = hub.agent();
        assert!(
            agent.notices().iter().any(|notice| notice.contains("confirmed.json")),
            "{held}: {:?}",
            agent.notices()
        );
        let mut agent = agent;
        for _ in 0..3 {
            agent.tick().unwrap();
        }
        assert_eq!(agent.status().unwrap().halted, None, "{held}");
        let resets = of_kind(&hub.service.accepted(), "site_source.reset");
        let seqs = hub.service.accepted_seqs();
        assert_eq!(
            seqs,
            (held + 1..=held + seqs.len() as u64).collect::<Vec<_>>(),
            "{held}"
        );
        if held == 0 {
            assert!(resets.is_empty());
        } else {
            assert_eq!(resets.len(), 1);
            assert_eq!(
                resets[0]["attributes"],
                json!({"trustOrigin": "hub", "lastAckedSeq": held, "reason": "queue_lost"})
            );
        }
    }
}

#[test]
fn a_confirmed_mark_of_another_source_counts_as_none() {
    let hub = Hub::new();
    std::fs::write(
        hub.state.join("confirmed.json"),
        r#"{"version": 1, "lastAckedSeq": 10, "sourceId": "fedcba98-7654-4321-8fed-cba987654321"}"#,
    )
    .unwrap();
    hub.service.set_last_seq(3);
    let agent = hub.run(3);
    assert_eq!(
        agent.status().unwrap().halted,
        None,
        "not a gap: that mark is another source's"
    );
    assert_eq!(
        reset_of(&hub)["attributes"],
        json!({"trustOrigin": "hub", "lastAckedSeq": 3, "reason": "reinstall"})
    );
}

// ---- Files of the hub's own that are not files ----

#[test]
fn a_status_halt_or_confirmed_file_that_is_a_link_or_a_directory_is_refused_by_name() {
    for name in ["agent.json", "halt.json", "confirmed.json"] {
        for kind in ["symbolic link", "directory"] {
            let hub = Hub::new();
            let victim = hub.tmp.join("victim");
            std::fs::write(&victim, "untouched").unwrap();
            let path = hub.state.join(name);
            if kind == "directory" {
                std::fs::create_dir(&path).unwrap();
            } else {
                std::os::unix::fs::symlink(&victim, &path).unwrap();
            }
            let refused = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub.clock.as_clock())
                .map(|_| ())
                .unwrap_err()
                .to_string();
            assert!(refused.contains(name), "{name} {kind}: {refused}");
            assert!(refused.contains(kind), "{name} {kind}: {refused}");
            assert!(refused.contains("by hand"), "{name} {kind}: {refused}");
            assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
            assert!(std::fs::symlink_metadata(&path).is_ok(), "left where it is");
            assert!(hub.service.requests().is_empty());
        }
    }
}

// ---- Resume ----

#[test]
fn resume_that_cannot_remove_the_halt_says_so_and_the_hub_stays_halted() {
    let hub = Hub::new();
    let mut agent = hub.run(2);
    hub.service.push(Step::status(400, json!({"error": "schema"})));
    hub.clock.advance_seconds(3600);
    agent.tick().unwrap();
    agent.close().unwrap();
    let saved_before = std::fs::read_to_string(hub.state.join("agent.json")).unwrap();
    let failed = agent::resume_with(&hub.config, agent::ResumeOptions::default(), &|_: &std::path::Path| {
        Err(std::io::Error::other("the disk said no"))
    })
    .unwrap_err();
    assert!(failed.to_string().contains("halt.json"), "{failed}");
    assert!(hub.state.join("halt.json").exists(), "still halted");
    assert_eq!(
        agent::read_halt(&hub.state).unwrap().unwrap().reason,
        "schema",
        "and the status still says so"
    );
    // `agent.json` carries no copy of the halt, so resuming has nothing to rewrite there.
    let saved = std::fs::read_to_string(hub.state.join("agent.json")).unwrap();
    assert_eq!(saved, saved_before);
    assert!(!saved.contains("halted"), "{saved}");
}

// ---- A healthy queue is never set aside ----

#[test]
fn an_outbox_locked_by_another_connection_is_not_set_aside() {
    let hub = Hub::new();
    hub.run(2).close().unwrap();
    let holder = rusqlite::Connection::open(hub.state.join("outbox.sqlite")).unwrap();
    holder
        .execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; SELECT count(*) FROM events;")
        .unwrap();
    let refused = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub.clock.as_clock());
    assert!(
        refused.is_err(),
        "busy is not damage, and not a queue to start anew either"
    );
    drop(holder);
    assert!(!hub.state.join("outbox.sqlite.damaged").exists());
    let agent = hub.agent();
    assert!(agent.status().unwrap().last_assigned_seq > 0);
    assert!(agent.notices().is_empty());
}

#[test]
fn a_read_only_outbox_is_an_error_and_is_not_set_aside() {
    let hub = Hub::new();
    hub.run(2).close().unwrap();
    let path = hub.state.join("outbox.sqlite");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    let refused = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub.clock.as_clock());
    assert!(
        refused.is_err(),
        "a queue that cannot be written is refused at the start"
    );
    assert!(!hub.state.join("outbox.sqlite.damaged").exists());
    // A person puts the permissions right (SQLite made its side files with the database's own mode).
    for suffix in ["", "-wal", "-shm"] {
        let side = hub.state.join(format!("outbox.sqlite{suffix}"));
        if side.exists() {
            std::fs::set_permissions(&side, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    assert!(hub.agent().status().unwrap().last_assigned_seq > 0);
}

// ---- Third review round ----

/// A trigger, from another connection, that makes every removal of a confirmed event fail: the queue can be read and
/// appended to, but a confirmation cannot be recorded.
fn break_confirmations(hub: &Hub, broken: bool) {
    let db = rusqlite::Connection::open(hub.state.join("outbox.sqlite")).unwrap();
    if broken {
        db.execute_batch("CREATE TRIGGER unforgettable BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'no'); END")
            .unwrap();
    } else {
        db.execute_batch("DROP TRIGGER unforgettable").unwrap();
    }
}

/// `agent.json` as JSON.
fn saved_json(hub: &Hub) -> Value {
    serde_json::from_str(&std::fs::read_to_string(hub.state.join("agent.json")).unwrap()).unwrap()
}

/// Run the agent for `minutes` of test time (no real sleeping), returning each reported line with the monotonic
/// moment it was reported at.
fn run_for(hub: &Hub, agent: Agent, minutes: i64, mut each: impl FnMut(i64)) -> Vec<(i64, String)> {
    let stop = Arc::new(AtomicBool::new(false));
    let lines = Arc::new(Mutex::new(Vec::new()));
    let mut elapsed = 0i64;
    let (clock, seen) = (hub.clock.clone(), Arc::clone(&lines));
    agent::run_reporting(
        agent,
        Arc::clone(&stop),
        |pause| {
            elapsed += pause.as_millis() as i64;
            hub.clock.advance_millis(pause.as_millis() as i64);
            each(elapsed);
            if elapsed >= minutes * 60_000 {
                stop.store(true, Ordering::SeqCst);
            }
        },
        move |line| seen.lock().unwrap().push((clock.mono(), line.to_owned())),
    )
    .unwrap();
    lines.lock().unwrap().clone()
}

#[test]
fn a_confirmation_the_hub_cannot_record_is_a_failure_with_a_back_off() {
    let hub = Hub::new();
    let agent = hub.agent();
    break_confirmations(&hub, true);
    let mut problems = Vec::new();
    run_for(&hub, agent, 30, |elapsed| {
        if elapsed % 60_000 == 0 {
            problems.push(saved_json(&hub)["problem"].clone());
        }
    });
    let times = request_times(&hub);
    let carrying: Vec<i64> = hub
        .service
        .requests()
        .iter()
        .zip(&times)
        .filter(|(record, _)| record.events.as_ref().is_some_and(|events| !events.is_empty()))
        .map(|(_, time)| *time)
        .collect();
    // The same batch goes again only as the back-off allows: 5 s, doubling, at most 240 s.
    for (index, pair) in carrying.windows(2).enumerate() {
        let allowed = (5i64 << index.min(16)).min(240);
        assert!(pair[1] - pair[0] >= allowed, "request {index}: {carrying:?}");
    }
    assert!(
        (10..=14).contains(&carrying.len()),
        "{} requests: {carrying:?}",
        carrying.len()
    );
    assert!(
        problems.iter().all(|problem| *problem == "outbox_failed"),
        "{problems:?}"
    );
    // Repaired: the confirmation is recorded and the queue empties.
    break_confirmations(&hub, false);
    hub.clock.advance_seconds(300);
    let mut agent = hub.agent();
    agent.tick().unwrap();
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().pending, 0);
}

/// An observer whose one device changes its name at every poll: every tick has an event to deliver.
struct Flipping(usize);

impl Observer for Flipping {
    fn poll(&mut self) -> Vec<Sighting> {
        self.0 += 1;
        let name = if self.0.is_multiple_of(2) {
            "even.example"
        } else {
            "odd.example"
        };
        vec![sighting("flip:1", "printer", None, Some(name), None)]
    }
}

#[test]
fn a_storage_failure_names_its_cause_in_the_status_and_in_the_reported_line() {
    let hub = Hub::new();
    let agent = hub.agent();
    let mut broken = false;
    let lines = run_for(&hub, agent, 3, |elapsed| {
        if !broken && elapsed >= 60_000 {
            // Something this code never writes, where a counter belongs.
            let db = rusqlite::Connection::open(hub.state.join("outbox.sqlite")).unwrap();
            db.execute("UPDATE meta SET value = 'seven' WHERE key = 'last_acked'", [])
                .unwrap();
            broken = true;
        }
    });
    let saved = saved_json(&hub);
    assert_eq!(
        (saved["problem"].as_str(), saved["cause"].as_str()),
        (Some("outbox_failed"), Some("damaged")),
        "{saved}"
    );
    let said: Vec<&String> = lines.iter().map(|(_, line)| line).collect();
    assert!(
        said.iter()
            .any(|line| line.contains("problem: outbox_failed (damaged)")),
        "{said:?}"
    );
}

#[test]
fn the_cause_of_a_storage_error_comes_from_its_code_never_its_text() {
    use rusqlite::ffi;
    use spacegoat_hub::storage::Cause;
    let sqlite = |code| rusqlite::Error::SqliteFailure(ffi::Error::new(code), Some("disk full of lies".to_owned()));
    for (code, cause) in [
        (ffi::SQLITE_FULL, Cause::DiskFull),
        (ffi::SQLITE_READONLY, Cause::ReadOnly),
        (ffi::SQLITE_PERM, Cause::ReadOnly),
        (ffi::SQLITE_IOERR, Cause::Io),
        (ffi::SQLITE_CANTOPEN, Cause::Io),
        (ffi::SQLITE_BUSY, Cause::Locked),
        (ffi::SQLITE_LOCKED, Cause::Locked),
        (ffi::SQLITE_CORRUPT, Cause::Damaged),
        (ffi::SQLITE_NOTADB, Cause::Damaged),
        (ffi::SQLITE_CONSTRAINT, Cause::Other),
    ] {
        assert_eq!(Cause::of_sqlite(&sqlite(code)), cause, "{code}");
    }
    let io = |kind| std::io::Error::new(kind, "read only, says the text");
    for (kind, cause) in [
        (std::io::ErrorKind::StorageFull, Cause::DiskFull),
        (std::io::ErrorKind::QuotaExceeded, Cause::DiskFull),
        (std::io::ErrorKind::ReadOnlyFilesystem, Cause::ReadOnly),
        (std::io::ErrorKind::PermissionDenied, Cause::ReadOnly),
        (std::io::ErrorKind::WouldBlock, Cause::Locked),
        (std::io::ErrorKind::InvalidData, Cause::Damaged),
        (std::io::ErrorKind::UnexpectedEof, Cause::Io),
        (std::io::ErrorKind::NotFound, Cause::Io),
    ] {
        assert_eq!(Cause::of_io(&io(kind)), cause, "{kind:?}");
    }
    let names: Vec<&str> = [
        Cause::DiskFull,
        Cause::ReadOnly,
        Cause::Io,
        Cause::Locked,
        Cause::Damaged,
        Cause::Other,
    ]
    .map(Cause::as_str)
    .to_vec();
    assert_eq!(names, ["disk_full", "read_only", "io", "locked", "damaged", "other"]);
}

#[test]
fn a_state_that_flaps_is_reported_at_most_once_per_five_minutes_per_kind() {
    let hub = Hub::new();
    let agent = Agent::open(&hub.config, Box::new(Flipping(0)), hub.clock.as_clock()).unwrap();
    hub.service.push(Step::Pass);
    for _ in 0..400 {
        hub.service.push(Step::status(503, json!({"error": "unavailable"})));
        hub.service.push(Step::Pass);
    }
    let lines = run_for(&hub, agent, 30, |_| {});
    assert!(lines.len() >= 2, "{lines:?}");
    for (index, (at, line)) in lines.iter().enumerate() {
        if let Some((before, _)) = lines[..index].iter().rev().find(|(_, earlier)| earlier == line) {
            assert!(
                at - before >= 300_000,
                "{line:?} again after {} ms: {lines:?}",
                at - before
            );
        }
    }
    assert!(lines.len() <= 14, "{} lines: {lines:?}", lines.len());
}

#[test]
fn a_halt_is_reported_at_once_even_right_after_another_line() {
    let hub = Hub::new();
    let mut agent = Agent::open(&hub.config, Box::new(Flipping(0)), hub.clock.as_clock()).unwrap();
    let taken = |agent: &mut Agent| std::iter::from_fn(|| agent.take_announcement()).collect::<Vec<String>>();
    agent.tick().unwrap();
    taken(&mut agent);
    hub.service.push(Step::status(400, json!({"error": "schema"})));
    hub.clock.advance_seconds(15);
    agent.tick().unwrap();
    let first = taken(&mut agent);
    assert!(first.iter().any(|line| line.contains("halted: schema")), "{first:?}");
    // Another line of the same kind (`halted`) one second after it: what the halt line says changed (here the command
    // that clears it; a halt is not cleared, nor its reason changed, while an agent runs). A halt line is never held
    // back by the five minutes a line of another kind waits after one of its own.
    hub.clock.advance_seconds(1);
    agent.set_resume_command("spacegoat-hub resume --config /elsewhere/hub.toml".to_owned());
    agent.tick().unwrap();
    let second = taken(&mut agent);
    assert!(
        second
            .iter()
            .any(|line| line.contains("halted: schema") && line.contains("/elsewhere/hub.toml")),
        "{second:?}"
    );
    agent.close().unwrap();
}

/// Keeps a file from being replaced (macOS: the owner's immutable flag) until dropped.
struct Immutable(std::path::PathBuf);

impl Drop for Immutable {
    fn drop(&mut self) {
        let _ = std::process::Command::new("chflags")
            .arg("nouchg")
            .arg(&self.0)
            .status();
    }
}

#[test]
fn a_confirmed_mark_that_can_be_read_but_not_replaced_is_a_problem_until_it_is_written() {
    if !cfg!(target_os = "macos") {
        eprintln!("skipped: needs a file its owner cannot replace without root (chflags uchg, macOS only)");
        return;
    }
    let hub = Hub::new();
    let agent = Agent::open(&hub.config, Box::new(Flipping(0)), hub.clock.as_clock()).unwrap();
    let mut agent = agent;
    agent.tick().unwrap();
    let path = hub.state.join("confirmed.json");
    assert!(
        std::process::Command::new("chflags")
            .arg("uchg")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let _guard = Immutable(path.clone());
    let mut problems = Vec::new();
    for round in 0..12 {
        // Every other tick moves the confirmed mark; the others deliver nothing.
        hub.clock.advance_seconds(if round % 2 == 0 { 15 } else { 1 });
        let _ = agent.tick();
        problems.push(agent.status().unwrap().problem);
    }
    assert!(
        problems
            .iter()
            .all(|problem| problem.as_deref() == Some("confirmed_failed")),
        "{problems:?}"
    );
}

// ---- resume --from-service leaves the confirmed mark alone when it cannot clear the halt ----

fn gap_halted(hub: &Hub, held: u64) {
    std::fs::write(
        hub.state.join("confirmed.json"),
        format!(
            r#"{{"version": 1, "lastAckedSeq": 10, "sourceId": "{}"}}"#,
            hub.config.source_id
        ),
    )
    .unwrap();
    hub.service.set_last_seq(held);
    let agent = hub.run(2);
    assert_eq!(agent.status().unwrap().halted.as_deref(), Some("gap"));
    agent.close().unwrap();
}

#[test]
fn resume_from_service_that_cannot_remove_the_halt_leaves_the_confirmed_mark_as_it_was() {
    let hub = Hub::new();
    gap_halted(&hub, 3);
    let before = std::fs::read_to_string(hub.state.join("confirmed.json")).unwrap();
    let options = agent::ResumeOptions {
        from_service: true,
        ..agent::ResumeOptions::default()
    };
    let failed = agent::resume_with(&hub.config, options, &|_: &std::path::Path| {
        Err(std::io::Error::other("the disk said no"))
    })
    .unwrap_err();
    assert!(failed.to_string().contains("halt.json"), "{failed}");
    assert_eq!(
        std::fs::read_to_string(hub.state.join("confirmed.json")).unwrap(),
        before
    );
    assert!(hub.state.join("halt.json").exists());
}

// ---- A confirmed mark without a source id ----

#[test]
fn a_confirmed_mark_without_a_source_id_is_not_understood() {
    let hub = Hub::new();
    std::fs::write(
        hub.state.join("confirmed.json"),
        r#"{"version": 1, "lastAckedSeq": 10}"#,
    )
    .unwrap();
    hub.service.set_last_seq(3);
    let agent = hub.run(2);
    assert_eq!(
        agent.status().unwrap().halted,
        None,
        "not this source's mark: not a gap"
    );
    assert_eq!(
        reset_of(&hub)["attributes"],
        json!({"trustOrigin": "hub", "lastAckedSeq": 3, "reason": "queue_lost"})
    );
}

// ---- The capture-stop mark ----

#[test]
fn a_short_halt_across_a_restart_is_not_declared() {
    let hub = Hub::new();
    let mut agent = hub.run(2);
    hub.service.push(Step::status(400, json!({"error": "schema"})));
    hub.clock.advance_seconds(3600);
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().halted.as_deref(), Some("schema"));
    agent.close().unwrap();
    agent::resume(&hub.config, None).unwrap().unwrap();
    hub.clock.advance_seconds(60);
    hub.run(2).close().unwrap();
    let lost = of_kind(&hub.service.accepted(), "site_source.input_lost");
    assert!(lost.is_empty(), "a minute without capture: {lost:?}");
    assert_gapless(&hub);
}

#[test]
fn a_backlog_below_its_cap_at_open_does_not_stop_capture() {
    let hub = Hub::new();
    let open = |cap| {
        let settings = agent::AgentSettings {
            backlog_cap: cap,
            ..agent::AgentSettings::default()
        };
        Agent::open_with(
            &hub.config,
            Box::new(SimulatedObserver::new()),
            hub.clock.as_clock(),
            settings,
        )
        .unwrap()
    };
    hub.service.push(Step::Pass);
    for _ in 0..40 {
        hub.service.push(Step::status(503, json!({"error": "unavailable"})));
    }
    let mut agent = open(4);
    for _ in 0..6 {
        agent.tick().unwrap();
        hub.clock.advance_seconds(3600);
    }
    let full = agent.status().unwrap();
    assert_eq!(full.pending, 4);
    agent.close().unwrap();
    // A larger cap: four waiting is more than half of it, but it is not full.
    hub.service.clear_script();
    hub.service.push(Step::Pass);
    for _ in 0..40 {
        hub.service.push(Step::status(503, json!({"error": "unavailable"})));
    }
    let mut agent = open(6);
    agent.tick().unwrap();
    let status = agent.status().unwrap();
    assert!(
        status.last_assigned_seq > full.last_assigned_seq,
        "it captured: {status:?}"
    );
    assert_ne!(status.waiting_for.as_deref(), Some("backlog"));
}

// ---- Storage format versions ----

fn user_version(path: &std::path::Path) -> i64 {
    let db = rusqlite::Connection::open(path).unwrap();
    db.query_row("PRAGMA user_version", [], |row| row.get(0)).unwrap()
}

#[test]
fn both_databases_record_their_format_version_and_the_small_files_theirs() {
    let hub = Hub::new();
    let mut agent = hub.run(2);
    hub.service.push(Step::status(400, json!({"error": "schema"})));
    hub.clock.advance_seconds(3600);
    agent.tick().unwrap();
    agent.close().unwrap();
    assert_eq!(user_version(&hub.state.join("outbox.sqlite")), 1);
    assert_eq!(user_version(&hub.state.join("pseudonyms.sqlite")), 1);
    for name in ["confirmed.json", "halt.json", "agent.json"] {
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(hub.state.join(name)).unwrap()).unwrap();
        assert_eq!(saved["version"], 1, "{name}: {saved}");
    }
}

#[test]
fn a_database_a_newer_version_wrote_or_one_of_no_known_format_is_refused() {
    for (name, version, said) in [
        ("outbox.sqlite", 2, "newer"),
        ("pseudonyms.sqlite", 2, "newer"),
        ("outbox.sqlite", 0, "format"),
    ] {
        let hub = Hub::new();
        hub.run(1).close().unwrap();
        let db = rusqlite::Connection::open(hub.state.join(name)).unwrap();
        db.execute_batch(&format!("PRAGMA user_version = {version}")).unwrap();
        drop(db);
        let refused = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub.clock.as_clock())
            .map(|_| ())
            .unwrap_err();
        let text = refused.to_string();
        assert!(text.contains(name) && text.contains(said), "{name} {version}: {text}");
        assert!(refused.could_not_start(), "{name} {version}");
        assert!(!hub.state.join(format!("{name}.damaged")).exists(), "not damage");
    }
}

#[test]
fn a_halt_or_confirmed_mark_a_newer_version_wrote_is_refused_and_agent_json_is_rewritten() {
    for name in ["halt.json", "confirmed.json"] {
        let hub = Hub::new();
        std::fs::write(
            hub.state.join(name),
            format!(
                r#"{{"version": 2, "reason": "gap", "at": null, "lastAckedSeq": 1, "sourceId": "{}"}}"#,
                hub.config.source_id
            ),
        )
        .unwrap();
        let refused = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub.clock.as_clock())
            .map(|_| ())
            .unwrap_err();
        assert!(
            refused.to_string().contains(name) && refused.to_string().contains("newer"),
            "{refused}"
        );
        assert!(hub.service.requests().is_empty());
    }
    let hub = Hub::new();
    std::fs::write(hub.state.join("agent.json"), r#"{"version": 2, "whatever": true}"#).unwrap();
    hub.run(1).close().unwrap();
    assert_eq!(saved_json(&hub)["version"], 1);
}

// ---- Nothing personal lingers in free pages ----

#[test]
fn a_confirmed_event_leaves_no_personal_data_in_the_queue_file() {
    let hub = Hub::new();
    hub.run(5).close().unwrap();
    assert_eq!(hub.service.last_seq(), {
        let status: Vec<u64> = hub.service.accepted_seqs();
        *status.last().unwrap()
    });
    let raw = std::fs::read(hub.state.join("outbox.sqlite")).unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert_no_personal_data(&text, "outbox.sqlite after every event was confirmed");
}

// ---- One unreadable record of facts ----

/// What a stored record of facts can be that this code never writes: valid text that is not a JSON object, text that
/// is not UTF-8, and a cell of another type.
const UNREADABLE_FACTS: [(&str, &str); 3] = [
    ("not an object", "'not an object'"),
    ("invalid UTF-8", "CAST(x'7bff7d' AS TEXT)"),
    ("a BLOB", "x'7b7d'"),
];

/// Make the stored facts of one subject unreadable in the way `value` (an SQL expression) says.
fn spoil_facts(hub: &Hub, scope: &str, identity: &str, value: &str) {
    let db = rusqlite::Connection::open(hub.state.join("pseudonyms.sqlite")).unwrap();
    let changed = db
        .execute(
            &format!("UPDATE refs SET facts = {value} WHERE scope = ?1 AND identity = ?2"),
            [scope, identity],
        )
        .unwrap();
    assert_eq!(changed, 1, "{scope} {identity}");
}

/// The lines that name the pseudonym store: one, and nothing personal in it.
fn said_once(lines: &[(i64, String)], what: &str) {
    let said: Vec<&(i64, String)> = lines
        .iter()
        .filter(|(_, line)| line.contains("pseudonyms.sqlite"))
        .collect();
    assert_eq!(said.len(), 1, "{what}: {lines:?}");
    assert_no_personal_data(&said[0].1, "the line");
}

#[test]
fn a_record_of_facts_that_cannot_be_read_is_reported_again_and_said_once() {
    for (what, value) in UNREADABLE_FACTS {
        let hub = Hub::new();
        hub.run(4).close().unwrap();
        spoil_facts(&hub, "device", "sim:printer", value);
        let printer = of_kind(&hub.service.accepted(), "site.device_appeared")[0]["attributes"]["deviceRef"].clone();
        let lines = run_for(&hub, hub.agent(), 2, |_| {});
        let again: Vec<Value> = of_kind(&hub.service.accepted(), "site.device_appeared")
            .into_iter()
            .filter(|event| event["attributes"]["deviceRef"] == printer)
            .collect();
        assert_eq!(again.len(), 2, "{what}: announced again, under the same reference");
        said_once(&lines, what);
        assert_eq!(saved_json(&hub)["problem"], Value::Null, "{what}");
        assert_gapless(&hub);
    }
}

#[test]
fn a_segments_record_of_facts_that_cannot_be_read_gets_its_snapshot_again_and_is_said_once() {
    for (what, value) in UNREADABLE_FACTS {
        let hub = Hub::new();
        hub.run(4).close().unwrap();
        assert_eq!(of_kind(&hub.service.accepted(), "site.inventory_snapshot").len(), 1);
        spoil_facts(&hub, "segment", "sim:lan", value);
        // Two minutes: no snapshot is due by the clock (one an hour), only because its record cannot be read.
        let lines = run_for(&hub, hub.agent(), 2, |_| {});
        let snapshots = of_kind(&hub.service.accepted(), "site.inventory_snapshot");
        assert_eq!(snapshots.len(), 2, "{what}");
        assert_eq!(
            snapshots[0]["attributes"]["segmentRef"], snapshots[1]["attributes"]["segmentRef"],
            "{what}: under the same reference"
        );
        said_once(&lines, what);
        assert_eq!(saved_json(&hub)["problem"], Value::Null, "{what}");
        assert_gapless(&hub);
    }
}

// ---- One transaction per chunk of `DEVICES_PER_COMMIT` devices ----

/// With at most `DEVICES_PER_COMMIT` devices a tick is one chunk: its device events go with its snapshots, or none
/// of them do.
#[test]
fn what_one_chunk_captures_is_stored_whole_or_not_at_all() {
    let hub = Hub::new();
    let mut agent = hub.agent();
    agent.tick().unwrap();
    let before = agent.status().unwrap().last_assigned_seq;
    let db = rusqlite::Connection::open(hub.state.join("outbox.sqlite")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER no_snapshots BEFORE INSERT ON events WHEN NEW.body LIKE '%inventory_snapshot%' \
         BEGIN SELECT RAISE(ABORT, 'no'); END",
    )
    .unwrap();
    hub.clock.advance_seconds(3600);
    assert!(agent.tick().is_err());
    assert_eq!(
        agent.status().unwrap().last_assigned_seq,
        before,
        "the device events of the tick went with the snapshot that failed"
    );
    db.execute_batch("DROP TRIGGER no_snapshots").unwrap();
    hub.clock.advance_seconds(1);
    agent.tick().unwrap();
    let accepted = hub.service.accepted();
    let appeared = of_kind(&accepted, "site.device_appeared");
    let refs: HashSet<&Value> = appeared.iter().map(|event| &event["attributes"]["deviceRef"]).collect();
    assert_eq!((appeared.len(), refs.len()), (3, 3), "each once");
    assert_gapless(&hub);
}

#[test]
fn when_a_later_chunk_fails_the_earlier_one_is_stored_and_delivered_once_and_nothing_is_repeated() {
    let devices = agent::DEVICES_PER_COMMIT + 50;
    let observer = Steered::default();
    observer.set(
        (0..devices)
            .map(|index| sighting(&format!("bulk:{index}"), "printer", None, None, None))
            .collect(),
    );
    let hub = Hub::new();
    let mut agent = Agent::open(&hub.config, Box::new(observer.clone()), hub.clock.as_clock()).unwrap();
    // The second chunk's first event cannot be stored: the first chunk is committed by then.
    let db = rusqlite::Connection::open(hub.state.join("outbox.sqlite")).unwrap();
    db.execute_batch(&format!(
        "CREATE TRIGGER no_second_chunk BEFORE INSERT ON events WHEN NEW.seq > {} \
         BEGIN SELECT RAISE(ABORT, 'no'); END",
        agent::DEVICES_PER_COMMIT
    ))
    .unwrap();
    assert!(agent.tick().is_err());
    let first = agent::DEVICES_PER_COMMIT as u64;
    assert_eq!(
        agent.status().unwrap().last_assigned_seq,
        first,
        "the first chunk is stored"
    );
    assert_eq!(
        hub.service.accepted_seqs(),
        (1..=first).collect::<Vec<_>>(),
        "and delivered"
    );
    // Repaired: the rest is captured, and nothing of the first chunk is told again.
    db.execute_batch("DROP TRIGGER no_second_chunk").unwrap();
    hub.clock.advance_seconds(15);
    agent.tick().unwrap();
    hub.clock.advance_seconds(15);
    agent.tick().unwrap();
    let accepted = hub.service.accepted();
    let appeared = of_kind(&accepted, "site.device_appeared");
    let refs: HashSet<&Value> = appeared.iter().map(|event| &event["attributes"]["deviceRef"]).collect();
    assert_eq!((appeared.len(), refs.len()), (devices, devices), "each device once");
    assert_eq!(of_kind(&accepted, "site.inventory_snapshot").len(), 1);
    for seq in 1..=first {
        assert_eq!(times_sent(&hub, seq), 1, "event {seq} of the first chunk went once");
    }
    assert_gapless(&hub);
    assert_eq!(agent.status().unwrap().pending, 0);
    agent.close().unwrap();
}

// ---- What the Debug form of a sighting shows ----

#[test]
fn a_sighting_debug_form_shows_nothing_personal() {
    for sighting in spacegoat_hub::simulate::devices() {
        let shown = format!("{sighting:?}");
        assert_no_personal_data(&shown, "Debug of a sighting");
        assert!(shown.contains(&sighting.device_class), "{shown}");
        let pretty = format!("{sighting:#?}");
        assert_no_personal_data(&pretty, "Debug of a sighting");
    }
}

// ---- A child process another thread starts does not keep the lock ----

#[test]
fn a_lock_a_child_process_holds_for_a_moment_does_not_make_a_second_agent() {
    // A process started meanwhile (by another thread of the same program: a test's `chflags`, the binary under test)
    // holds a copy of every open descriptor until it executes, and with it the lock just released. That is not
    // another agent.
    let hub = Hub::new();
    let stop = Arc::new(AtomicBool::new(false));
    let spawner = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let _ = std::process::Command::new("true").status();
            }
        })
    };
    let mut refused = 0;
    for _ in 0..2_000 {
        match agent::lock_state_dir(&hub.state) {
            Ok(lock) => drop(lock),
            Err(AgentError::AlreadyRunning(_)) => refused += 1,
            Err(error) => panic!("{error}"),
        }
    }
    stop.store(true, Ordering::SeqCst);
    spawner.join().unwrap();
    assert_eq!(refused, 0);
    // A lock that is really held is still refused.
    let held = agent::lock_state_dir(&hub.state).unwrap();
    assert!(matches!(
        agent::lock_state_dir(&hub.state),
        Err(AgentError::AlreadyRunning(_))
    ));
    drop(held);
}

// ---- Review round: settlement, capture stops, clock trust, what was reported ----

#[test]
fn a_settlement_that_failed_asks_the_service_again_before_it_tries_again() {
    // A lost queue; forgetting what was reported fails, so nothing is declared yet. Meanwhile the service comes to
    // hold more than it said at the greeting. The next attempt must not settle against the old answer.
    let hub = Hub::new();
    hub.run(4).close().unwrap();
    let confirmed = hub.service.last_seq();
    hub.lose_outbox();
    break_updates(&hub, true);
    let mut agent = hub.agent();
    assert!(agent.tick().is_err(), "forgetting what was reported fails");
    assert_eq!(agent.status().unwrap().last_assigned_seq, 0, "nothing declared yet");
    hub.service.set_last_seq(confirmed + 5);
    break_updates(&hub, false);
    hub.clock.advance_seconds(sender::BACKOFF_FIRST_SECONDS as i64);
    agent.tick().unwrap();
    agent.tick().unwrap();
    let status = agent.status().unwrap();
    assert_eq!(status.halted, None);
    let reset = reset_of(&hub);
    assert_eq!(
        reset["attributes"]["lastAckedSeq"],
        json!(confirmed + 5),
        "the number the service holds now"
    );
    assert_eq!(reset["sourceSeq"], json!(confirmed + 6));
}

#[test]
fn a_stop_is_declared_once_when_the_first_capture_after_it_fails() {
    // A halt stops capture at a trusted time. After `resume`, the first captures fail (a new device's reference
    // cannot be made) for longer than five minutes. It is one interruption, declared once, from the halt on.
    let hub = Hub::new();
    let observer = Steered::default();
    let printer = sighting(
        "odd:printer",
        "printer",
        Some("00005e005301"),
        Some("printer-a"),
        Some("192.0.2.10"),
    );
    observer.set(vec![printer.clone()]);
    let open = |hub: &Hub| Agent::open(&hub.config, Box::new(observer.clone()), hub.clock.as_clock()).unwrap();
    let mut agent = open(&hub);
    agent.tick().unwrap();
    hub.service.push(Step::status(400, json!({"error": "schema"})));
    hub.clock.advance_seconds(3600);
    let halted_at = hub.clock.now();
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().halted.as_deref(), Some("schema"));
    agent.close().unwrap();
    hub.clock.advance_seconds(3600);
    agent::resume(&hub.config, None).unwrap().unwrap();
    observer.set(vec![printer, sighting("odd:laptop", "user_device", None, None, None)]);
    break_new_references(&hub, true);
    let mut agent = open(&hub);
    for _ in 0..4 {
        assert!(agent.tick().is_err(), "the first captures fail");
        hub.clock.advance_seconds(120);
    }
    break_new_references(&hub, false);
    let resumed_at = hub.clock.now();
    agent.tick().unwrap();
    agent.tick().unwrap();
    let lost = of_kind(&hub.service.accepted(), "site_source.input_lost");
    assert_eq!(lost.len(), 1, "{lost:?}");
    let attributes = &lost[0]["attributes"];
    let from = clock::observed_at_millis(attributes["fromTime"].as_str().unwrap()).unwrap();
    let to = clock::observed_at_millis(attributes["toTime"].as_str().unwrap()).unwrap();
    assert!(from >= halted_at && from - halted_at < 5_000, "from the halt");
    assert!(to >= resumed_at, "to when capture really resumed");
    assert_gapless(&hub);
}

#[test]
fn a_reset_is_not_signed_with_a_wall_clock_that_jumped_during_the_request_that_called_for_it() {
    // Nothing to report, so the outbox has assigned nothing. The answer that says the service moved ahead is also
    // the one during which the hub's wall clock jumps an hour: the reset waits until the clock is trusted again.
    let hub = Hub::new();
    let hub_clock = TestClock::new();
    let armed = Arc::new(AtomicBool::new(false));
    {
        let (service_clock, hub_clock, armed) = (hub.clock.clone(), hub_clock.clone(), Arc::clone(&armed));
        hub.service.set_now(Arc::new(move || {
            if armed.swap(false, Ordering::SeqCst) {
                hub_clock.step_wall_seconds(3600);
            }
            service_clock.now()
        }));
    }
    let mut agent = Agent::open(&hub.config, Box::new(Steered::default()), hub_clock.as_clock()).unwrap();
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().last_assigned_seq, 0);
    hub.service.set_last_seq(5);
    pass(&[&hub_clock, &hub.clock], sender::HEARTBEAT_SECONDS);
    armed.store(true, Ordering::SeqCst);
    agent.tick().unwrap();
    assert_eq!(
        agent.status().unwrap().last_assigned_seq,
        0,
        "nothing signed with the jumped clock"
    );
    assert_eq!(
        agent.status().unwrap().waiting_for.as_deref(),
        Some("clock"),
        "and the status says why"
    );
    // The clock is put right: the reset is declared then, with a time the service takes.
    hub_clock.step_wall_seconds(-3600);
    agent.tick().unwrap();
    let reset = reset_of(&hub);
    assert_eq!(reset["attributes"]["lastAckedSeq"], 5);
    let observed = clock::observed_at_millis(reset["observedAt"].as_str().unwrap()).unwrap();
    assert!((observed - hub.clock.now()).abs() < 5_000, "{reset}");
}

#[test]
fn what_a_queued_event_reported_is_known_after_a_crash_before_the_store_took_it() {
    // A name changes: the event is queued (the service is down), the pseudonym store does not take the new name, and
    // the process dies. After the restart the device has its old name again: the service, which is about to receive
    // the new name, must also be told the old one came back.
    let hub = Hub::new();
    let observer = Steered::default();
    let named = |name: &str| {
        sighting(
            "odd:printer",
            "printer",
            Some("00005e005301"),
            Some(name),
            Some("192.0.2.10"),
        )
    };
    observer.set(vec![named("printer-a")]);
    let open = || Agent::open(&hub.config, Box::new(observer.clone()), hub.clock.as_clock()).unwrap();
    let mut agent = open();
    agent.tick().unwrap();
    observer.set(vec![named("printer-b")]);
    break_updates(&hub, true);
    hub.service.push(Step::status(503, json!({"error": "unavailable"})));
    hub.clock.advance_seconds(10);
    assert!(agent.tick().is_err(), "the store does not take the new name");
    assert_eq!(agent.status().unwrap().pending, 1, "the change is queued");
    // The process dies here: nothing closes it, nothing retries the store.
    drop(agent);
    break_updates(&hub, false);
    observer.set(vec![named("printer-a")]);
    hub.clock.advance_seconds(10);
    let mut agent = open();
    agent.tick().unwrap();
    agent.tick().unwrap();
    let names: Vec<Value> = of_kind(&hub.service.accepted(), "site.device_changed")
        .iter()
        .map(|event| event["pii"]["hostname"].clone())
        .collect();
    assert_eq!(names, [json!("printer-b"), json!("printer-a")]);
    agent.close().unwrap();
}

#[test]
fn a_queue_whose_events_differ_from_what_the_service_holds_halts_with_replay_conflict_at_start() {
    // Two hubs with one identity (a copied state directory): the first queues its events but the service is down for
    // its batch; the second delivers its own events under the same numbers. When the first starts again, the
    // greeting's `lastSeq` covers its queue, but that does not make its events the service's: they are sent, and the
    // service refuses them as a conflict instead of the hub forgetting them unseen.
    let hub = Hub::new();
    let twin = hub.tmp.join("twin");
    std::fs::create_dir(&twin).unwrap();
    std::fs::set_permissions(&twin, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["hub.key", "hub.key.id"] {
        if hub.state.join(name).exists() {
            std::fs::copy(hub.state.join(name), twin.join(name)).unwrap();
        }
    }
    hub.service.push(Step::Pass);
    hub.service.push(Step::status(503, json!({"error": "unavailable"})));
    let first = hub.run(1);
    let queued = first.status().unwrap();
    assert!(queued.pending > 0);
    first.close().unwrap();
    let mut config = hub.config.clone();
    config.state_dir = twin.clone();
    let mut second = Agent::open(&config, Box::new(SimulatedObserver::new()), hub.clock.as_clock()).unwrap();
    second.tick().unwrap();
    assert_eq!(
        hub.service.last_seq(),
        queued.last_assigned_seq,
        "the same numbers, other events"
    );
    second.close().unwrap();
    let mut first = hub.agent();
    first.tick().unwrap();
    let status = first.status().unwrap();
    assert_eq!(status.halted.as_deref(), Some("replay_conflict"));
    assert_eq!(status.pending, queued.pending, "nothing forgotten unseen");
}

#[test]
fn a_hub_that_cannot_settle_on_its_own_storage_sends_nothing_until_the_storage_works() {
    // A lost queue; forgetting what was reported fails. A heartbeat would say "alive, nothing to report", which a hub
    // that cannot settle cannot say: nothing goes out until its storage works, and then one fresh greeting comes
    // first, whose number the settlement uses.
    let hub = Hub::new();
    hub.run(4).close().unwrap();
    let confirmed = hub.service.last_seq();
    hub.lose_outbox();
    break_updates(&hub, true);
    let mut agent = hub.agent();
    assert!(agent.tick().is_err());
    let after_first = hub.service.requests().len();
    for _ in 0..5 {
        hub.clock.advance_seconds(60);
        assert!(agent.tick().is_err(), "the storage still fails");
    }
    assert_eq!(
        hub.service.requests().len(),
        after_first,
        "no request while it cannot settle"
    );
    hub.service.set_last_seq(confirmed + 5);
    break_updates(&hub, false);
    hub.clock.advance_seconds(60);
    agent.tick().unwrap();
    let requests = hub.service.requests();
    assert_eq!(requests[after_first].events, Some(vec![]), "one fresh greeting first");
    assert_eq!(requests[after_first + 1].events.as_ref().unwrap()[0], confirmed + 6);
    assert_eq!(reset_of(&hub)["attributes"]["lastAckedSeq"], json!(confirmed + 5));
    assert_eq!(agent.status().unwrap().halted, None);
}

#[test]
fn a_heartbeat_only_site_halts_with_gap_when_the_service_says_twice_it_holds_less() {
    // Nothing new to report, so only heartbeats go. The service loses what it had confirmed: the first answer that
    // shows it is a suspicion, the next one a halt, kept on disk and shown in the status.
    let hub = Hub::new();
    let observer = Steered::default();
    observer.set(vec![sighting("odd:printer", "printer", None, None, None)]);
    let open = || Agent::open(&hub.config, Box::new(observer.clone()), hub.clock.as_clock()).unwrap();
    let mut agent = open();
    agent.tick().unwrap();
    let confirmed = agent.status().unwrap().last_acked_seq;
    assert!(confirmed >= 2);
    hub.service.set_last_seq(1);
    hub.clock.advance_seconds(sender::HEARTBEAT_SECONDS);
    agent.tick().unwrap();
    let status = agent.status().unwrap();
    assert_eq!(status.halted, None, "once is a suspicion");
    assert_eq!(status.service.as_deref(), Some("not_confirming"));
    hub.clock.advance_seconds(sender::HEARTBEAT_SECONDS);
    agent.tick().unwrap();
    let status = agent.status().unwrap();
    assert_eq!(status.halted.as_deref(), Some("gap"));
    assert_eq!(status.last_acked_seq, confirmed, "nothing re-declared");
    assert!(
        std::fs::read_to_string(hub.state.join("halt.json"))
            .unwrap()
            .contains("\"gap\"")
    );
    agent.close().unwrap();
    let requests = hub.service.requests().len();
    let mut again = open();
    again.tick().unwrap();
    assert_eq!(
        again.status().unwrap().halted.as_deref(),
        Some("gap"),
        "after a restart too"
    );
    assert_eq!(hub.service.requests().len(), requests, "a halted hub asks nothing");
    again.close().unwrap();
}

#[test]
fn sidecars_left_beside_a_missing_outbox_are_set_aside_before_a_new_queue_is_started() {
    // `outbox.sqlite` moved aside without its log (a person recovering from a gap, or a set-aside of a damaged file
    // that stopped half way): the log, which holds events and personal data, is kept under the set-aside name, never
    // read into the new queue nor deleted, and it is said.
    let hub = Hub::new();
    hub.run(4).close().unwrap();
    let held = hub.service.last_seq();
    let path = hub.state.join("outbox.sqlite");
    std::fs::remove_file(&path).unwrap();
    let key = spacegoat_hub::keystore::FileKeyStore::new(hub.state.join("hub.key"))
        .load()
        .unwrap();
    let mut outbox =
        spacegoat_hub::outbox::Outbox::open(&path, &hub.config.source_id, &hub.config.key_id, key).unwrap();
    outbox
        .declare_reset(held, spacegoat_hub::outbox::ResetReason::QueueLost, hub.clock.now())
        .unwrap();
    let wal = std::fs::read(hub.state.join("outbox.sqlite-wal")).unwrap();
    let shm = std::fs::read(hub.state.join("outbox.sqlite-shm")).unwrap();
    outbox.close().unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(hub.state.join("outbox.sqlite-wal"), &wal).unwrap();
    std::fs::write(hub.state.join("outbox.sqlite-shm"), &shm).unwrap();
    let mut agent = hub.agent();
    assert_eq!(agent.status().unwrap().last_assigned_seq, 0, "a new queue");
    assert_eq!(
        std::fs::read(hub.state.join("outbox.sqlite.damaged-wal")).unwrap(),
        wal,
        "the old log, kept"
    );
    assert_eq!(mode(&hub.state.join("outbox.sqlite.damaged-wal")), 0o600);
    assert!(
        agent
            .notices()
            .iter()
            .any(|notice| notice.contains("outbox.sqlite.damaged-wal")),
        "{:?}",
        agent.notices()
    );
    agent.tick().unwrap();
    assert_eq!(agent.status().unwrap().problem.as_deref(), Some("outbox_replaced"));
    assert_eq!(reset_of(&hub)["attributes"]["lastAckedSeq"], held);
    agent.close().unwrap();
}
