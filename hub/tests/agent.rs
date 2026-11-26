// SPDX-License-Identifier: AGPL-3.0-or-later
//! The whole agent with simulated observations, against a service that checks signatures and sequence for real
//! (`support/fake_service.rs`) over real sockets: an interruption, a lost answer, a lost outbox, a reinstall, the clock
//! gate, a halt, a second agent. Every test of the Python `test_agent_simulated.py` that concerns the agent is here
//! under its name; the command-line ones are in `tests/cli.rs`, the configuration one in `tests/config.rs`.
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
    }
}

#[test]
fn test_simulated_run_reports_devices_in_order_and_the_service_accepts_each_once() {
    // Six hours pass between rounds: a device that is still there is reported as seen once a day, not every round.
    let hub = Hub::new();
    let mut agent = hub.agent();
    for _ in 0..12 {
        agent.tick().unwrap();
        hub.clock.advance_seconds(6 * 3600);
    }
    let accepted = hub.service.accepted();
    let seen = of_kind(&accepted, "site.device_seen");
    let refs: HashSet<&Value> = seen.iter().map(|event| &event["attributes"]["deviceRef"]).collect();
    assert!(!refs.is_empty());
    for device in refs {
        let count = seen
            .iter()
            .filter(|event| &event["attributes"]["deviceRef"] == device)
            .count();
        assert!(count <= 3, "twelve rounds are three days, seen {count} times");
    }
    let snapshots = of_kind(&accepted, "site.inventory_snapshot");
    let counts = snapshots.last().unwrap()["attributes"]["counts"].as_object().unwrap();
    assert_eq!(counts.values().map(|n| n.as_u64().unwrap()).sum::<u64>(), 4);
    assert_eq!(counts.len(), 7);
    assert_gapless(&hub);
    let kinds: HashSet<&str> = accepted.iter().map(|event| event["kind"].as_str().unwrap()).collect();
    for kind in ["site.device_appeared", "site.device_seen", "site.inventory_snapshot"] {
        assert!(kinds.contains(kind), "{kind} missing");
    }
    assert!(accepted.iter().all(|event| event["attributes"]["trustOrigin"] == "hub"));
    let appeared = &of_kind(&accepted, "site.device_appeared")[0];
    let pii = appeared["pii"].as_object().unwrap();
    let attributes = appeared["attributes"].as_object().unwrap();
    assert!(pii.keys().all(|key| ["mac", "hostname", "ip"].contains(&key.as_str())));
    assert!(pii.keys().all(|key| !attributes.contains_key(key)));
    assert_eq!(agent.status().unwrap().last_acked_seq, accepted.len() as u64);
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
    let second = hub.run(40);
    assert_gapless(&hub);
    let after = second.status().unwrap();
    assert!(after.last_assigned_seq > before.last_assigned_seq);
    assert_eq!(after.last_acked_seq, after.last_assigned_seq);
    // The service accepted the first event once, although it was sent twice.
    assert_eq!(times_sent(&hub, 1), 2);
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
        Arc::new(move || before_the_protocol),
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
    assert_eq!(saved, r#"{"halted": null, "waitingFor": "clock"}"#);
}

#[test]
fn a_clock_at_the_epoch_is_not_set_either() {
    let hub = Hub::new();
    let mut agent = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), Arc::new(|| 0)).unwrap();
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
    assert_eq!(saved, r#"{"halted": "schema", "waitingFor": null}"#);
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
    let mut agent = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub_clock.as_fn()).unwrap();
    for _ in 0..3 {
        agent.tick().unwrap();
    }
    let status = agent.status().unwrap();
    assert_eq!(status.waiting_for.as_deref(), Some("clock"));
    assert_eq!((status.last_assigned_seq, status.halted), (0, None));
    assert!(hub.service.accepted().is_empty());
    // The clock was set (and the slow retry is due). The five-minute retry after the `401` was counted on the hub's
    // own clock: a clock that was ahead and is set back waits out that much longer (a weakness kept from the Python).
    let later = 301 + offset.max(0);
    hub_clock.set_offset_seconds(later);
    hub.clock.set_offset_seconds(later);
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
    let mut agent = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub_clock.as_fn()).unwrap();
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
    std::fs::write(hub.state.join("confirmed.json"), r#"{"lastAckedSeq": 1}"#).unwrap();
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
    let refused = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub.clock.as_fn()).unwrap_err();
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
        // The Python case was a lone surrogate, which a Rust string cannot hold; this is the non-ASCII half of it.
        sighting("odd:3", "iot", None, Some("café"), None),
    ]);
    let mut agent = Agent::open(&hub.config, Box::new(observer), hub.clock.as_fn()).unwrap();
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
    let mut agent = Agent::open(&hub.config, Box::new(observer.clone()), hub.clock.as_fn()).unwrap();
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
    let refused = Agent::open(&hub.config, Box::new(SimulatedObserver::new()), hub.clock.as_fn()).unwrap_err();
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
    let stop = AtomicBool::new(false);
    let mut slept = Duration::ZERO;
    let started = Instant::now();
    let ticks_wanted = 5;
    agent::run(hub.agent(), &stop, |pause| {
        slept += pause;
        hub.clock.advance_seconds(0); // time passes only through the test's clock
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
    let stop = AtomicBool::new(true);
    agent::run(hub.agent(), &stop, |_| panic!("no wait either")).unwrap();
    assert!(hub.service.requests().is_empty());
}
