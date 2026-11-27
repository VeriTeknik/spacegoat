// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sender against a service that checks signatures and sequence for real (`support/fake_service.rs`), over real
//! sockets: nothing is mocked between the two.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::net::TcpListener;

use ed25519_dalek::SigningKey;
use serde_json::{Map, Value, json};
use spacegoat_hub::clock;
use spacegoat_hub::outbox::Outbox;
use spacegoat_hub::sender::{
    BACKOFF_FIRST_SECONDS, BACKOFF_MAX_SECONDS, HEARTBEAT_SECONDS, HaltReason, MAX_COMPRESSED_BYTES,
    MAX_UNCOMPRESSED_BYTES, Problem, SendOutcome, Sender, service_origin,
};
use support::fake_service::{FakeService, PATH, Step, TestClock, http_date};
use support::{TempDir, vector_key};

const SOURCE: &str = "01234567-89ab-4cde-8fab-0123456789ab";
const KEY_ID: &str = "vector-key-1";

fn seen() -> Map<String, Value> {
    object(
        json!({"trustOrigin": "hub", "deviceRef": "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b",
                  "segmentRef": "0c0c0c0c-0c0c-4c0c-8c0c-0c0c0c0c0c0c"}),
    )
}

fn appeared() -> Map<String, Value> {
    let mut attributes = seen();
    attributes.insert("deviceClass".into(), json!("printer"));
    attributes
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// Relative to the test's clock, never a fixed date: the service refuses an observation more than about 24.8 days
/// from its clock, so a literal date would make every test here fail a few weeks after it was written.
fn at(clock: &TestClock, seconds_ago: i64) -> String {
    clock::observed_at_text(clock.now() - seconds_ago * 1000).unwrap()
}

fn service() -> FakeService {
    FakeService::new(SOURCE, KEY_ID, vector_key().verifying_key())
}

fn open_outbox(tmp: &TempDir, name: &str) -> Outbox {
    Outbox::open(&tmp.join(name), SOURCE, KEY_ID, vector_key()).unwrap()
}

/// A sender for `service` on `clock`; the service's clock is the same one.
fn make_sender(service: &FakeService, outbox: Outbox, clock: &TestClock) -> Sender {
    service.set_now(clock.as_fn());
    sender_with_key(&service.base_url, outbox, clock, vector_key())
}

fn sender_with_key(base_url: &str, outbox: Outbox, clock: &TestClock, key: SigningKey) -> Sender {
    Sender::new(base_url, SOURCE, KEY_ID, key, outbox, clock.as_clock()).unwrap()
}

fn fill(outbox: &mut Outbox, clock: &TestClock, count: usize) {
    for _ in 0..count {
        outbox.append("site.device_seen", &at(clock, 0), &seen(), None).unwrap();
    }
}

fn step(sender: &mut Sender) -> SendOutcome {
    sender.step().unwrap()
}

fn wait_of(outcome: SendOutcome) -> u64 {
    match outcome {
        SendOutcome::RetryLater(seconds) => seconds,
        other => panic!("expected a wait, got {other:?}"),
    }
}

fn events_per_request(service: &FakeService) -> Vec<Option<Vec<u64>>> {
    service.requests().into_iter().map(|r| r.events).collect()
}

/// Send until the outbox is empty; every step must be a delivery.
fn drain(sender: &mut Sender) {
    while !sender.outbox().pending(1, None).unwrap().is_empty() {
        assert!(matches!(step(sender), SendOutcome::Sent(_)));
    }
}

fn random_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}

#[test]
fn a_batch_is_delivered_signed_and_forgotten() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 3);
    let mut sender = make_sender(&service, outbox, &clock);
    assert_eq!(step(&mut sender), SendOutcome::Sent(3));
    assert_eq!(service.accepted_seqs(), [1, 2, 3]);
    assert_eq!(sender.outbox().last_acked().unwrap(), 3);
    assert!(sender.outbox().pending(10, None).unwrap().is_empty());
    let request = &service.requests()[0];
    assert!(request.header("Origin").is_none());
    assert!(sender.last_success().is_some());
}

#[test]
fn nothing_to_send_is_idle_until_a_heartbeat_is_due() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    // The first contact is a heartbeat: the hub says it is alive.
    assert_eq!(step(&mut sender), SendOutcome::Sent(0));
    assert_eq!(events_per_request(&service), [Some(vec![])]);
    assert_eq!(step(&mut sender), SendOutcome::Idle);
    assert_eq!(service.requests().len(), 1);
    clock.advance_seconds(HEARTBEAT_SECONDS + 1);
    assert_eq!(step(&mut sender), SendOutcome::Sent(0));
    assert_eq!(events_per_request(&service), [Some(vec![]), Some(vec![])]);
}

#[test]
fn a_lost_answer_is_sent_again_and_the_service_counts_duplicates() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 2);
    service.push(Step::LoseAnswer);
    let mut sender = make_sender(&service, outbox, &clock);
    let wait = wait_of(step(&mut sender));
    assert_eq!(sender.outbox().last_acked().unwrap(), 0);
    assert_eq!(service.last_seq(), 2);
    clock.advance_seconds(wait as i64 + 1);
    assert_eq!(step(&mut sender), SendOutcome::Sent(2));
    // The very same two events went again (not an empty request that happens to be answered with lastSeq 2).
    assert_eq!(events_per_request(&service), [Some(vec![1, 2]), Some(vec![1, 2])]);
    assert_eq!(sender.outbox().last_acked().unwrap(), 2);
    assert_eq!(service.accepted_seqs(), [1, 2]); // each exactly once
}

#[test]
fn seq_gap_means_the_service_lost_events_and_halts() {
    // The service can only ask for a number at or below what it already confirmed: it lost events. The hub has
    // forgotten them, cannot send them again, and does not invent a sequence.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 3);
    outbox.ack(3).unwrap();
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::status(409, json!({"error": "seq_gap", "expectedSeq": 2})));
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::Gap));
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::Gap));
    assert_eq!(service.requests().len(), 1); // a halted hub does not keep knocking
}

#[test]
fn too_large_halves_the_batch_until_it_fits() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 8);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::MaxEvents(3));
    service.push(Step::MaxEvents(3));
    assert_eq!(step(&mut sender), SendOutcome::RetryNow); // 8 refused
    assert_eq!(step(&mut sender), SendOutcome::RetryNow); // 4 refused
    assert_eq!(step(&mut sender), SendOutcome::Sent(2)); // 2 fit
    assert_eq!(service.requests().last().unwrap().events, Some(vec![1, 2]));
    drain(&mut sender);
    assert_eq!(sender.outbox().last_acked().unwrap(), 8);
}

#[test]
fn one_event_that_never_fits_halts() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::status(413, json!({"error": "too_large"})));
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::TooLarge));
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::TooLarge));
    assert_eq!(sender.halted(), Some(HaltReason::TooLarge));
}

#[test]
fn rate_limited_waits_as_long_as_it_is_told() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::status_with(
        429,
        json!({"error": "rate_limited"}),
        &[("Retry-After", "42")],
    ));
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(42));
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_))); // still waiting
    assert_eq!(service.requests().len(), 1);
    clock.advance_seconds(43);
    assert_eq!(step(&mut sender), SendOutcome::Sent(1));
}

#[test]
fn retry_after_as_a_date_is_honoured_and_a_long_one_is_capped_at_240_seconds() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    let later = http_date(clock.now() + 90_000);
    service.push(Step::status_with(
        429,
        json!({"error": "rate_limited"}),
        &[("Retry-After", &later)],
    ));
    let wait = wait_of(step(&mut sender));
    assert!((88..=91).contains(&wait), "{wait}");
    clock.advance_seconds(100);
    service.push(Step::status_with(
        429,
        json!({"error": "rate_limited"}),
        &[("Retry-After", "86400")],
    ));
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(240));
    // A date further away than the cap is cut the same way.
    clock.advance_seconds(241);
    let far = http_date(clock.now() + 3_600_000);
    service.push(Step::status_with(
        429,
        json!({"error": "rate_limited"}),
        &[("Retry-After", &far)],
    ));
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(240));
}

#[test]
fn an_answer_cut_off_half_way_is_a_retry_not_a_crash() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::Truncate);
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert_eq!(sender.outbox().last_acked().unwrap(), 0);
}

#[test]
fn an_error_answer_cut_off_half_way_is_a_retry_too() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::TruncateError);
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert_eq!(sender.outbox().pending(10, None).unwrap().len(), 1);
    assert_eq!(sender.halted(), None);
}

#[test]
fn an_error_whose_body_cannot_be_read_is_a_retry() {
    // A real answer whose body cannot be decoded: a
    // chunked 503 whose chunk size is not a number.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::Raw(
        b"HTTP/1.1 503 Service Unavailable\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n{\"error\":\"unavailable\"}\r\n0\r\n\r\n"
            .to_vec(),
    ));
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert_eq!(sender.outbox().pending(10, None).unwrap().len(), 1);
    assert_eq!(sender.halted(), None);
    assert_eq!(service.requests().len(), 1);
}

#[test]
fn an_answer_that_is_not_http_is_a_retry() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::Raw(b"SSH-2.0-OpenSSH_9.9\r\n".to_vec()));
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert_eq!(sender.outbox().last_acked().unwrap(), 0);
    assert_eq!(sender.halted(), None);
}

#[test]
fn the_fixed_dates_in_this_file_would_have_expired() {
    // The guard behind `at` above: an observation a month old is refused, so no test here may carry a literal date.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    outbox
        .append("site.device_seen", &at(&clock, 30 * 86_400), &seen(), None)
        .unwrap();
    let mut sender = make_sender(&service, outbox, &clock);
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::Schema));
    assert_eq!(sender.halted(), Some(HaltReason::Schema));
}

fn a_different_event_under_a_number_already_on_record_is_refused_by_the_service(reuse_signature: bool) {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    assert_eq!(step(&mut make_sender(&service, outbox, &clock)), SendOutcome::Sent(1));
    // A second queue for the same source, as a cloned or restored hub would have: its number 1 is another event.
    let mut clone = open_outbox(&tmp, "clone.sqlite");
    clone
        .append("site.device_seen", &at(&clock, 3600), &seen(), None)
        .unwrap();
    if reuse_signature {
        let mut forged: Value = serde_json::from_str(&clone.pending(1, None).unwrap()[0].json).unwrap();
        forged["signature"] = service.accepted()[0]["signature"].clone();
        clone.close().unwrap();
        let db = rusqlite::Connection::open(tmp.join("clone.sqlite")).unwrap();
        db.execute(
            "UPDATE events SET body = ?1 WHERE seq = 1",
            [serde_json::to_string(&forged).unwrap()],
        )
        .unwrap();
        db.close().unwrap();
        clone = open_outbox(&tmp, "clone.sqlite");
    }
    let mut sender = make_sender(&service, clone, &clock);
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::ReplayConflict));
    assert_eq!(service.accepted().len(), 1);
    assert_eq!(sender.outbox().pending(10, None).unwrap().len(), 1);
}

#[test]
fn a_different_event_under_a_number_already_on_record_is_refused_by_the_service_new_signature() {
    a_different_event_under_a_number_already_on_record_is_refused_by_the_service(false);
}

#[test]
fn a_different_event_under_a_number_already_on_record_is_refused_by_the_service_reused_signature() {
    a_different_event_under_a_number_already_on_record_is_refused_by_the_service(true);
}

#[test]
fn a_batch_stays_under_the_uncompressed_limit_too() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    let pii = object(json!({"hostname": "a".repeat(200)}));
    for _ in 0..30 {
        outbox
            .append("site.device_appeared", &at(&clock, 0), &appeared(), Some(&pii))
            .unwrap();
    }
    let mut sender = make_sender(&service, outbox, &clock).with_limits(MAX_COMPRESSED_BYTES, 3000);
    drain(&mut sender);
    let largest = service
        .requests()
        .iter()
        .map(|r| r.events.as_ref().unwrap().len())
        .max();
    assert!(largest.unwrap() < 30);
    assert!(
        service
            .requests()
            .iter()
            .all(|r| r.plain.as_ref().unwrap().len() <= 3000)
    );
    assert_eq!(service.accepted().len(), 30);
}

#[test]
fn unavailable_backs_off_longer_each_time_up_to_four_minutes() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    let mut waits = Vec::new();
    for _ in 0..12 {
        service.push(Step::status(503, json!({"error": "unavailable"})));
        let wait = wait_of(step(&mut sender));
        waits.push(wait);
        clock.advance_seconds(wait as i64 + 1);
    }
    assert_eq!(waits, [5, 10, 20, 40, 80, 160, 240, 240, 240, 240, 240, 240]);
    assert_eq!(step(&mut sender), SendOutcome::Sent(1));
    service.push(Step::status(503, json!({"error": "unavailable"})));
    fill(sender.outbox_mut(), &clock, 1);
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(waits[0])); // a success resets the back-off
}

#[test]
fn a_service_that_is_not_there_is_a_retry_not_a_crash() {
    let (tmp, clock) = (TempDir::new(), TestClock::new());
    // A port that was free a moment ago and has no listener now.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = sender_with_key(&format!("http://127.0.0.1:{port}"), outbox, &clock, vector_key());
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert_eq!(sender.outbox().last_acked().unwrap(), 0);
}

fn a_refusal_no_retry_can_fix_halts_and_keeps_the_events(status: u16, body: Value, reason: HaltReason) {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 2);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::status(status, body));
    assert_eq!(step(&mut sender), SendOutcome::Halted(reason));
    assert_eq!(step(&mut sender), SendOutcome::Halted(reason));
    assert_eq!(service.requests().len(), 1);
    assert_eq!(sender.outbox().pending(10, None).unwrap().len(), 2);
}

#[test]
fn a_refusal_no_retry_can_fix_halts_and_keeps_the_events_schema() {
    a_refusal_no_retry_can_fix_halts_and_keeps_the_events(400, json!({"error": "schema"}), HaltReason::Schema);
}

#[test]
fn a_refusal_no_retry_can_fix_halts_and_keeps_the_events_replay_conflict() {
    a_refusal_no_retry_can_fix_halts_and_keeps_the_events(
        409,
        json!({"error": "replay_conflict", "sourceSeq": 1}),
        HaltReason::ReplayConflict,
    );
}

#[test]
fn unauthorized_is_not_final_the_sender_says_so_and_tries_again_slowly() {
    // The service gives one answer for an unknown key and for a clock that is five minutes off. A clock corrects
    // itself, so this must not stop the hub for good.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    service.set_now(clock.as_fn());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = sender_with_key(&service.base_url, outbox, &clock, random_key());
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(240));
    assert_eq!((sender.halted(), sender.problem()), (None, Some(Problem::Unauthorized)));
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert_eq!(service.requests().len(), 1);
    clock.advance_seconds(239);
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(1));
    assert_eq!(service.requests().len(), 1);
    clock.advance_seconds(1);
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert_eq!(service.requests().len(), 2);
}

#[test]
fn a_clock_that_is_off_is_measured_from_the_answer_and_recovers() {
    let (tmp, service) = (TempDir::new(), service());
    let (hub_clock, service_clock) = (TestClock::new(), TestClock::new());
    hub_clock.set_offset_seconds(-600); // the hub is ten minutes behind
    service.set_now(service_clock.as_fn());
    let mut sender = sender_with_key(
        &service.base_url,
        open_outbox(&tmp, "outbox.sqlite"),
        &hub_clock,
        vector_key(),
    );
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert_eq!(sender.problem(), Some(Problem::Unauthorized));
    let skew = sender.clock_skew_seconds().unwrap();
    assert!((-602.0..=-598.0).contains(&skew), "{skew}");
    hub_clock.set_offset_seconds(0); // the clock was set
    hub_clock.advance_seconds(240); // and the wait after the 401 is over
    service_clock.advance_seconds(240);
    assert_eq!(step(&mut sender), SendOutcome::Sent(0));
    assert_eq!(sender.problem(), None);
    assert!(sender.clock_skew_seconds().unwrap().abs() <= 2.0);
}

fn a_redirect_is_never_followed(status: u16) {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let elsewhere = self::service();
    elsewhere.set_now(clock.as_fn());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 2);
    let mut sender = make_sender(&service, outbox, &clock);
    let location = format!("{}{PATH}", elsewhere.base_url);
    service.push(Step::status_with(status, json!({}), &[("Location", &location)]));
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert!(elsewhere.requests().is_empty()); // the signed headers and the events went nowhere else
    assert_eq!(sender.outbox().last_acked().unwrap(), 0);
    assert_eq!(sender.halted(), None);
}

#[test]
fn a_redirect_is_never_followed_302() {
    a_redirect_is_never_followed(302);
}

/// 307 and 308 are the redirects that keep the method and the body: following one would replay the signed batch.
#[test]
fn a_redirect_that_keeps_the_method_and_body_is_never_followed_either() {
    a_redirect_is_never_followed(307);
    a_redirect_is_never_followed(308);
    a_redirect_is_never_followed(301);
    a_redirect_is_never_followed(303);
}

#[test]
fn a_200_that_is_not_the_services_answer_confirms_nothing() {
    for body in [
        json!({"lastSeq": 2}),
        json!({"accepted": 2, "duplicates": 0}),
        json!({"accepted": "2", "duplicates": 0, "lastSeq": 2}),
        json!({"accepted": 2, "duplicates": 0, "lastSeq": true}),
        json!({}),
        // A float, a negative number, and JSON that is not an object.
        json!({"accepted": 2, "duplicates": 0, "lastSeq": 2.0}),
        json!({"accepted": 2, "duplicates": 0, "lastSeq": -1}),
        json!([2, 0, 2]),
    ] {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        let mut outbox = open_outbox(&tmp, "outbox.sqlite");
        fill(&mut outbox, &clock, 2);
        let mut sender = make_sender(&service, outbox, &clock);
        service.push(Step::status(200, body.clone()));
        assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)), "{body}");
        assert_eq!(sender.outbox().last_acked().unwrap(), 0, "{body}");
        assert_eq!(sender.outbox().pending(10, None).unwrap().len(), 2, "{body}");
    }
}

#[test]
fn an_answer_larger_than_the_cap_is_not_read_whole() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::status(
        200,
        json!({"accepted": 1, "duplicates": 0, "lastSeq": 1, "pad": "x".repeat(200_000)}),
    ));
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert_eq!(sender.outbox().last_acked().unwrap(), 0);
}

/// The cap is 64 KiB exactly: an answer of 65536 bytes is read and confirms, one of 65537 is no answer.
#[test]
fn the_answer_cap_is_exactly_64_kib() {
    let answer = |length: usize| {
        let base = serde_json::to_vec(&json!({"accepted": 1, "duplicates": 0, "lastSeq": 1, "pad": ""})).unwrap();
        let body = json!({"accepted": 1, "duplicates": 0, "lastSeq": 1, "pad": "x".repeat(length - base.len())});
        assert_eq!(serde_json::to_vec(&body).unwrap().len(), length);
        body
    };
    for (length, confirmed) in [(65_536, true), (65_537, false)] {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        let mut outbox = open_outbox(&tmp, "outbox.sqlite");
        fill(&mut outbox, &clock, 1);
        let mut sender = make_sender(&service, outbox, &clock);
        service.push(Step::status(200, answer(length)));
        let outcome = step(&mut sender);
        assert_eq!(outcome == SendOutcome::Sent(1), confirmed, "{length}: {outcome:?}");
        assert_eq!(sender.outbox().last_acked().unwrap(), u64::from(confirmed), "{length}");
    }
}

#[test]
fn an_outbox_that_never_assigned_a_number_learns_where_the_service_stands() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    service.set_last_seq(41);
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    assert_eq!(step(&mut sender), SendOutcome::ServiceAhead(41));
    assert_eq!(sender.halted(), None);
    assert_eq!(sender.service_last_seq(), Some(41));
    assert_eq!(sender.outbox().last_assigned().unwrap(), 0);
}

#[test]
fn the_service_address_is_an_https_origin_and_nothing_else() {
    let (tmp, clock) = (TempDir::new(), TestClock::new());
    for base_url in [
        "http://hub.example",
        "http://localhost.evil.example",
        "http://127.0.0.1.evil.example:8080",
        "http://localhost@evil.example",
        "https://user:pw@hub.example",
        "https://hub.example/prefix",
        "https://hub.example/?x=1",
        "https://hub.example/#f",
        "ftp://hub.example",
        "https://",
        "hub.example",
        "https://hub.example:notaport",
        "https://hub.example:99999",
        "https://hub.example:",
        "https://hub.example?x=1",
        "https://hub.example#f",
        "https:/hub.example",
        " https://hub.example",
        "https://hub example",
        "https://[::1",
        "https://[not-an-address]",
        "http://[::2]:8080",
        "http://127.0.0.2:8080",
        "http://localhost:8080",
    ] {
        assert!(service_origin(base_url).is_err(), "{base_url}");
        let outbox = open_outbox(&tmp, "outbox.sqlite");
        assert!(
            Sender::new(base_url, SOURCE, KEY_ID, vector_key(), outbox, clock.as_clock()).is_err(),
            "{base_url}"
        );
    }
}

#[test]
fn accepted_service_addresses() {
    let (tmp, clock) = (TempDir::new(), TestClock::new());
    for (base_url, origin) in [
        ("https://hub.example", "https://hub.example"),
        ("https://hub.example/", "https://hub.example"),
        ("https://hub.example:8443", "https://hub.example:8443"),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("http://[::1]:8080", "http://[::1]:8080"),
        ("HTTPS://Hub.Example", "https://hub.example"),
    ] {
        assert_eq!(service_origin(base_url).unwrap(), origin);
        let outbox = open_outbox(&tmp, "outbox.sqlite");
        Sender::new(base_url, SOURCE, KEY_ID, vector_key(), outbox, clock.as_clock()).unwrap();
    }
}

#[test]
fn a_confirmation_ahead_of_the_hub_halts() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::status(
        200,
        json!({"accepted": 1, "duplicates": 0, "lastSeq": 99}),
    ));
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::Ahead));
    assert_eq!(sender.halted(), Some(HaltReason::Ahead));
    assert_eq!(sender.outbox().last_acked().unwrap(), 0);
}

#[test]
fn a_batch_never_exceeds_500_events() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 501);
    let mut sender = make_sender(&service, outbox, &clock);
    assert_eq!(step(&mut sender), SendOutcome::Sent(500));
    assert_eq!(step(&mut sender), SendOutcome::Sent(1));
    assert_eq!(service.accepted().len(), 501);
}

#[test]
fn a_batch_stays_under_the_compressed_limit() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    for _ in 0..40 {
        // Random text does not compress: 240 hex characters each.
        let mut random = [0u8; 120];
        getrandom::fill(&mut random).unwrap();
        let pii = object(json!({"hostname": spacegoat_hub::signing::hex(&random)}));
        outbox
            .append("site.device_appeared", &at(&clock, 0), &appeared(), Some(&pii))
            .unwrap();
    }
    let mut sender = make_sender(&service, outbox, &clock).with_limits(4096, MAX_UNCOMPRESSED_BYTES);
    drain(&mut sender);
    assert!(service.requests().iter().all(|r| r.bytes <= 4096));
    assert!(service.requests().len() > 1);
    assert_eq!(service.accepted().len(), 40);
}

// ---- What the Rust port makes newly possible to get wrong ----

/// The body is the stored event texts spliced in, byte for byte,
/// (`canonical_json({"schemaVersion": 1, "events": [...]})`): never the events parsed and written again.
#[test]
fn the_request_body_is_the_stored_events_spliced_byte_for_byte() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 2);
    let pii = object(json!({"hostname": "yazıcı.example", "mac": "00005e005301"}));
    outbox
        .append("site.device_appeared", &at(&clock, 0), &appeared(), Some(&pii))
        .unwrap();
    let stored: Vec<String> = outbox.pending(10, None).unwrap().into_iter().map(|e| e.json).collect();
    let mut sender = make_sender(&service, outbox, &clock);
    assert_eq!(step(&mut sender), SendOutcome::Sent(3));
    let expected = format!("{{\"events\":[{}],\"schemaVersion\":1}}", stored.join(","));
    let plain = service.requests()[0].plain.clone().unwrap();
    assert_eq!(String::from_utf8(plain).unwrap(), expected);
    // And it is the canonical form of itself.
    let parsed: Value = serde_json::from_str(&expected).unwrap();
    assert_eq!(spacegoat_hub::canonical::canonical_json(&parsed).unwrap(), expected);
}

#[test]
fn a_heartbeat_is_an_empty_events_array() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    assert_eq!(step(&mut sender), SendOutcome::Sent(0));
    let request = &service.requests()[0];
    assert_eq!(
        request.plain.as_deref(),
        Some(&b"{\"events\":[],\"schemaVersion\":1}"[..])
    );
    assert_eq!(request.header("Content-Encoding"), Some("gzip"));
    assert!(request.header("Cookie").is_none());
    assert!(request.header("Accept-Encoding").is_none_or(|v| !v.contains("gzip")));
}

#[test]
fn a_date_header_that_is_not_an_imf_fixdate_is_not_a_clock_reading() {
    for date in [
        "Tue, 24 Nov 2026 10:00:00 +0000",
        "Tuesday, 24-Nov-26 10:00:00 GMT",
        "Tue Nov 24 10:00:00 2026",
        "Wed, 24 Nov 2026 10:00:00 GMT", // the wrong weekday
        "not a date",
        "",
    ] {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
        service.push(Step::status_with(
            200,
            json!({"accepted": 0, "duplicates": 0, "lastSeq": 0}),
            &[("Date", date)],
        ));
        assert_eq!(step(&mut sender), SendOutcome::Sent(0), "{date}");
        assert_eq!(sender.clock_skew_seconds(), None, "{date}");
    }
}

#[test]
fn a_well_formed_date_header_is_read() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    let date = http_date(clock.now() - 3_600_000);
    service.push(Step::status_with(
        200,
        json!({"accepted": 0, "duplicates": 0, "lastSeq": 0}),
        &[("Date", &date)],
    ));
    assert_eq!(step(&mut sender), SendOutcome::Sent(0));
    let skew = sender.clock_skew_seconds().unwrap();
    assert!((3598.0..=3602.0).contains(&skew), "{skew}");
}

#[test]
fn a_rate_limit_without_a_readable_retry_after_waits_the_first_back_off() {
    for headers in [
        vec![],
        vec![("Retry-After", "soon")],
        vec![("Retry-After", "-5")],
        vec![("Retry-After", "0")],
    ] {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        let mut outbox = open_outbox(&tmp, "outbox.sqlite");
        fill(&mut outbox, &clock, 1);
        let mut sender = make_sender(&service, outbox, &clock);
        service.push(Step::status_with(429, json!({"error": "rate_limited"}), &headers));
        let expected = if headers == [("Retry-After", "0")] { 1 } else { 5 };
        assert_eq!(step(&mut sender), SendOutcome::RetryLater(expected), "{headers:?}");
    }
}

#[test]
fn a_huge_retry_after_is_capped_and_does_not_overflow() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::status_with(
        429,
        json!({"error": "rate_limited"}),
        &[("Retry-After", "99999999999999999999999999")],
    ));
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(240));
}

#[test]
fn an_unknown_error_answer_backs_off_and_does_not_halt() {
    for (status, body) in [
        (400, json!({"error": "something_new"})),
        (409, json!({"error": "something_new"})),
        (500, json!({})),
        (418, json!({"error": "schema"})),
    ] {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        let mut outbox = open_outbox(&tmp, "outbox.sqlite");
        fill(&mut outbox, &clock, 1);
        let mut sender = make_sender(&service, outbox, &clock);
        service.push(Step::status(status, body));
        assert_eq!(step(&mut sender), SendOutcome::RetryLater(5), "{status}");
        assert_eq!(sender.halted(), None, "{status}");
    }
}

// ---- The test service checks what the real one checks: these fail if it stops checking ----

/// Change one stored field of event 1 behind the outbox's back (as a damaged or forged queue would have it).
fn tamper(tmp: &TempDir, name: &str, change: impl FnOnce(&mut Value)) {
    let db = rusqlite::Connection::open(tmp.join(name)).unwrap();
    let body: String = db
        .query_row("SELECT body FROM events WHERE seq = 1", [], |row| row.get(0))
        .unwrap();
    let mut event: Value = serde_json::from_str(&body).unwrap();
    change(&mut event);
    db.execute(
        "UPDATE events SET body = ?1 WHERE seq = 1",
        [spacegoat_hub::canonical::canonical_json(&event).unwrap()],
    )
    .unwrap();
    db.close().unwrap();
}

#[test]
fn personal_data_that_does_not_match_its_commitment_is_refused_by_the_service() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    let pii = object(json!({"hostname": "printer.example"}));
    outbox
        .append("site.device_appeared", &at(&clock, 0), &appeared(), Some(&pii))
        .unwrap();
    outbox.close().unwrap();
    // The signature covers only the commitment, so it still verifies; the commitment no longer matches.
    tamper(&tmp, "outbox.sqlite", |event| {
        event["pii"]["hostname"] = json!("other.example")
    });
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::Schema));
    assert!(service.accepted().is_empty());
}

#[test]
fn an_event_whose_signature_does_not_cover_it_is_refused_by_the_service() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    outbox.close().unwrap();
    // Another moment, still of the right form: only the signature can tell.
    let other = at(&clock, 1);
    tamper(&tmp, "outbox.sqlite", |event| event["observedAt"] = json!(other));
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::Schema));
    assert!(service.accepted().is_empty());
}

#[test]
fn a_reset_at_the_number_the_service_holds_is_accepted_and_at_another_is_refused() {
    use spacegoat_hub::outbox::ResetReason;
    // (what the service holds when the hub asks, what the hub declares, what the service holds when it arrives)
    for (asked, declared, held, expected) in [
        (41, 41, 41, SendOutcome::Sent(1)),
        // Numbered 41, which the service already holds as something else.
        (41, 40, 41, SendOutcome::Halted(HaltReason::ReplayConflict)),
        // Numbered 42 and the next number too, but it names 41 as the service's last while the service holds 40:
        // the reset rule, not the sequence, refuses it (without the rule this would be a `seq_gap`).
        (41, 41, 40, SendOutcome::Halted(HaltReason::Schema)),
    ] {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        service.set_last_seq(asked);
        let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
        assert_eq!(step(&mut sender), SendOutcome::ServiceAhead(asked));
        sender
            .outbox_mut()
            .declare_reset(declared, ResetReason::QueueLost, clock.now())
            .unwrap();
        service.set_last_seq(held);
        assert_eq!(step(&mut sender), expected, "{declared} {held}");
        let after = if expected == SendOutcome::Sent(1) {
            held + 1
        } else {
            held
        };
        assert_eq!(service.last_seq(), after);
    }
}

/// A peer that takes one connection and reads its first `bytes` bytes, then answers in plain HTTP. It waits at most
/// ten seconds for the connection and as long for the bytes: a sender that never connects, or never says a word,
/// fails the test with a reason instead of leaving it waiting in `accept` for ever.
fn plain_peer(listener: TcpListener, bytes: usize) -> std::thread::JoinHandle<Result<Vec<u8>, String>> {
    use std::io::{ErrorKind, Read, Write};
    use std::time::{Duration, Instant};
    const PATIENCE: Duration = Duration::from_secs(10);
    std::thread::spawn(move || {
        listener.set_nonblocking(true).map_err(|error| error.to_string())?;
        let deadline = Instant::now() + PATIENCE;
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(format!("no connection within {PATIENCE:?}: {error}")),
            }
        };
        stream.set_nonblocking(false).map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(PATIENCE))
            .map_err(|error| error.to_string())?;
        let mut first = vec![0u8; bytes];
        stream
            .read_exact(&mut first)
            .map_err(|error| format!("no ClientHello: {error}"))?;
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        Ok(first)
    })
}

/// The tests run the service over plain http on loopback, so the TLS path is exercised here only as far as it goes
/// without a certificate: an `https` origin really starts a TLS handshake (a ClientHello goes out), and a peer that
/// does not speak TLS is a retry, not a crash and not a confirmation.
#[test]
fn an_https_origin_speaks_tls_and_a_peer_that_does_not_is_a_retry() {
    let (tmp, clock) = (TempDir::new(), TestClock::new());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = plain_peer(listener, 3);
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = sender_with_key(&format!("https://127.0.0.1:{port}"), outbox, &clock, vector_key());
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    // A TLS record: handshake (22), protocol version 3.x.
    let first = peer.join().unwrap().unwrap();
    assert_eq!(first[..2], [22, 3]);
    assert_eq!(sender.outbox().last_acked().unwrap(), 0);
}

// ---- Two clocks ----

#[test]
fn intervals_are_measured_on_the_monotonic_clock_not_the_wall() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let hub_clock = TestClock::new();
    service.set_now(clock.as_fn());
    let mut sender = sender_with_key(&service.base_url, outbox, &hub_clock, vector_key());
    service.push(Step::status(503, json!({"error": "unavailable"})));
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(5));
    // A wall clock set a day ahead does not end the back-off; one set back an hour does not lengthen it.
    hub_clock.step_wall_seconds(86_400);
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(5));
    hub_clock.step_wall_seconds(-86_400 - 3600);
    hub_clock.advance_mono_seconds(5);
    assert!(
        matches!(step(&mut sender), SendOutcome::RetryLater(_)),
        "sent (refused: an hour off)"
    );
    assert_eq!(service.requests().len(), 2);
    // Heartbeats too: due after 240 s of monotonic time, whatever the wall clock did.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), self::service());
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    assert_eq!(step(&mut sender), SendOutcome::Sent(0));
    clock.step_wall_seconds(-3 * 3600);
    clock.advance_mono_seconds(HEARTBEAT_SECONDS - 1);
    assert_eq!(step(&mut sender), SendOutcome::Idle);
    clock.advance_mono_seconds(1);
    assert!(sender.heartbeat_due());
}

#[test]
fn an_answer_without_a_date_keeps_the_last_reading() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    service.push(Step::status_with(
        200,
        json!({"accepted": 0, "duplicates": 0, "lastSeq": 0}),
        &[("Date", &http_date(clock.now() - 600_000))],
    ));
    assert_eq!(sender.heartbeat().unwrap(), SendOutcome::Sent(0));
    let reading = sender.clock_reading().unwrap();
    service.push(Step::without_date(
        200,
        json!({"accepted": 0, "duplicates": 0, "lastSeq": 0}),
    ));
    assert_eq!(sender.heartbeat().unwrap(), SendOutcome::Sent(0));
    assert_eq!(sender.clock_reading(), Some(reading));
    // And with no reading at all, there is none.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), self::service());
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    service.push(Step::without_date(
        200,
        json!({"accepted": 0, "duplicates": 0, "lastSeq": 0}),
    ));
    assert_eq!(sender.heartbeat().unwrap(), SendOutcome::Sent(0));
    assert_eq!(sender.clock_reading(), None);
    assert_eq!(sender.clock_skew_millis(), None);
}

#[test]
fn the_skew_now_follows_a_jump_of_the_wall_clock_after_the_reading() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let hub_clock = TestClock::new();
    service.set_now(clock.as_fn());
    let mut sender = sender_with_key(
        &service.base_url,
        open_outbox(&tmp, "outbox.sqlite"),
        &hub_clock,
        vector_key(),
    );
    assert_eq!(sender.heartbeat().unwrap(), SendOutcome::Sent(0));
    assert!(sender.clock_skew_millis().unwrap().abs() <= 1_000);
    hub_clock.step_wall_seconds(3600);
    let skew = sender.clock_skew_millis().unwrap();
    assert!((3_599_000..=3_601_000).contains(&skew), "{skew}");
    // Time passing on both clocks is no jump.
    hub_clock.advance_seconds(600);
    assert!((3_599_000..=3_601_000).contains(&sender.clock_skew_millis().unwrap()));
}

#[test]
fn heartbeat_sends_an_empty_request_even_when_events_wait() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 3);
    let mut sender = make_sender(&service, outbox, &clock);
    assert_eq!(sender.heartbeat().unwrap(), SendOutcome::Sent(0));
    assert_eq!(events_per_request(&service), [Some(vec![])]);
    assert_eq!(sender.service_last_seq(), Some(0));
    assert_eq!(step(&mut sender), SendOutcome::Sent(3));
    // `step_events` never sends a heartbeat, however long it has been.
    clock.advance_seconds(HEARTBEAT_SECONDS);
    assert_eq!(sender.step_events().unwrap(), SendOutcome::Idle);
    assert_eq!(service.requests().len(), 2);
}

// ---- 413 ----

#[test]
fn a_413_to_a_heartbeat_backs_off() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    service.push(Step::status(413, json!({"error": "too_large"})));
    assert_eq!(sender.heartbeat().unwrap(), SendOutcome::RetryLater(5));
    assert_eq!(sender.halted(), None);
}

#[test]
fn a_413_to_one_event_that_is_not_the_services_answer_backs_off() {
    for body in [
        json!({}),
        json!({"error": "request_entity_too_large"}),
        json!("too_large"),
    ] {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        let mut outbox = open_outbox(&tmp, "outbox.sqlite");
        fill(&mut outbox, &clock, 1);
        let mut sender = make_sender(&service, outbox, &clock);
        service.push(Step::status(413, body.clone()));
        assert_eq!(step(&mut sender), SendOutcome::RetryLater(5), "{body}");
        assert_eq!(sender.halted(), None, "{body}");
    }
    // Nor a proxy's page that is not JSON at all.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::Raw(
        b"HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>"
            .to_vec(),
    ));
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(5));
    assert_eq!(sender.halted(), None);
}

#[test]
fn a_413_to_several_events_halves_the_batch_whatever_its_body() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 4);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::Raw(
        b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 5\r\n\r\nnope!".to_vec(),
    ));
    assert_eq!(step(&mut sender), SendOutcome::RetryNow);
    assert_eq!(step(&mut sender), SendOutcome::Sent(2));
}

// ---- A 200 that confirms nothing, and numbers no JSON can carry ----

#[test]
fn a_200_that_does_not_move_the_confirmed_mark_for_a_batch_is_a_failure() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 2);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::status(200, json!({"accepted": 0, "duplicates": 0, "lastSeq": 0})));
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(5));
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(5), "not again at once");
    assert_eq!(service.requests().len(), 1);
    // A second one in a row backs off longer: it is a failure like any other.
    clock.advance_seconds(5);
    service.push(Step::status(200, json!({"accepted": 0, "duplicates": 0, "lastSeq": 0})));
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(10));
    clock.advance_seconds(10);
    assert_eq!(step(&mut sender), SendOutcome::Sent(2));
}

#[test]
fn counts_beyond_what_json_carries_exactly_are_no_answer() {
    let too_big = 1u64 << 53;
    for (name, body) in [
        ("lastSeq", json!({"accepted": 0, "duplicates": 0, "lastSeq": too_big})),
        ("accepted", json!({"accepted": too_big, "duplicates": 0, "lastSeq": 0})),
        (
            "duplicates",
            json!({"accepted": 0, "duplicates": too_big, "lastSeq": 0}),
        ),
        (
            "lastSeq u64",
            json!({"accepted": 0, "duplicates": 0, "lastSeq": u64::MAX}),
        ),
    ] {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
        service.push(Step::status(200, body));
        assert_eq!(step(&mut sender), SendOutcome::RetryLater(5), "{name}");
        assert_eq!(sender.service_last_seq(), None, "{name}");
        assert_eq!(sender.halted(), None, "{name}");
    }
    // The largest number that is exact is an answer.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
    service.push(Step::status(
        200,
        json!({"accepted": 0, "duplicates": 0, "lastSeq": too_big - 1}),
    ));
    assert_eq!(step(&mut sender), SendOutcome::ServiceAhead(too_big - 1));
}

// ---- A refusal to a heartbeat refused nothing ----

#[test]
fn a_refusal_that_would_halt_a_batch_only_backs_off_after_a_heartbeat() {
    for (status, body) in [
        (400, json!({"error": "schema"})),
        (409, json!({"error": "schema"})),
        (409, json!({"error": "replay_conflict", "sourceSeq": 1})),
        (409, json!({"error": "seq_gap", "expectedSeq": 1})),
        (413, json!({"error": "too_large"})),
    ] {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        let mut sender = make_sender(&service, open_outbox(&tmp, "outbox.sqlite"), &clock);
        service.push(Step::status(status, body.clone()));
        assert_eq!(
            sender.heartbeat().unwrap(),
            SendOutcome::RetryLater(5),
            "{status} {body}"
        );
        assert_eq!(sender.halted(), None, "{status} {body}");
        // The next one is a heartbeat too, and the service is well again.
        clock.advance_seconds(5);
        assert_eq!(sender.heartbeat().unwrap(), SendOutcome::Sent(0), "{status} {body}");
    }
}

// ---- What kind of trouble the service is in ----

#[test]
fn the_sender_says_which_kind_of_answer_confirmed_nothing_until_one_does() {
    use spacegoat_hub::sender::ServiceTrouble;
    let cases: Vec<(Step, ServiceTrouble)> = vec![
        (
            Step::status(503, json!({"error": "unavailable"})),
            ServiceTrouble::Http(503),
        ),
        (
            Step::status_with(429, json!({"error": "rate_limited"}), &[("Retry-After", "1")]),
            ServiceTrouble::Http(429),
        ),
        (Step::status(302, json!({})), ServiceTrouble::Http(302)),
        (Step::Truncate, ServiceTrouble::Unreadable),
        (
            Step::status(200, json!({"hello": "portal"})),
            ServiceTrouble::NotConfirming,
        ),
        (Step::LoseAnswer, ServiceTrouble::NoConnection),
    ];
    for (answer, trouble) in cases {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        let mut outbox = open_outbox(&tmp, "outbox.sqlite");
        fill(&mut outbox, &clock, 1);
        let mut sender = make_sender(&service, outbox, &clock);
        assert_eq!(sender.trouble(), None, "nothing asked yet");
        service.push(answer);
        assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)), "{trouble:?}");
        assert_eq!(sender.trouble(), Some(trouble));
        clock.advance_seconds(10);
        assert!(matches!(step(&mut sender), SendOutcome::Sent(_)), "{trouble:?}");
        assert_eq!(sender.trouble(), None, "a confirming answer clears it");
    }
    // Nobody there at all: the port refuses.
    let (tmp, clock) = (TempDir::new(), TestClock::new());
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut sender = sender_with_key(
        &format!("http://127.0.0.1:{port}"),
        open_outbox(&tmp, "outbox.sqlite"),
        &clock,
        vector_key(),
    );
    assert!(matches!(sender.heartbeat().unwrap(), SendOutcome::RetryLater(_)));
    assert_eq!(sender.trouble(), Some(ServiceTrouble::Refused));
    assert_eq!(ServiceTrouble::Http(503).as_text(), "http_503");
    assert_eq!(ServiceTrouble::NoConnection.as_text(), "no_connection");
    assert_eq!(ServiceTrouble::Refused.as_text(), "refused");
    assert_eq!(ServiceTrouble::Dns.as_text(), "dns");
    assert_eq!(ServiceTrouble::Timeout.as_text(), "timeout");
    assert_eq!(ServiceTrouble::Tls.as_text(), "tls");
    assert_eq!(ServiceTrouble::Unreadable.as_text(), "unreadable");
    assert_eq!(ServiceTrouble::NotConfirming.as_text(), "not_confirming");
}

// ---- Third review round ----

/// The events each request carried, by count.
fn counts_per_request(service: &FakeService) -> Vec<usize> {
    service
        .requests()
        .into_iter()
        .map(|r| r.events.map_or(0, |events| events.len()))
        .collect()
}

#[test]
fn a_request_that_times_out_halves_the_batch_and_a_confirmed_one_lets_it_grow_again() {
    use std::time::Duration;
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 8);
    // The answer comes after the hub has given up on it (a real 200 ms against an answer 600 ms late).
    let mut sender = make_sender(&service, outbox, &clock).with_request_timeout(Duration::from_millis(200));
    for _ in 0..2 {
        service.push(Step::Delay(Duration::from_millis(600)));
        assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
        assert_eq!(sender.trouble().map(|t| t.as_text()).as_deref(), Some("timeout"));
        clock.advance_seconds(BACKOFF_MAX_SECONDS as i64);
    }
    // The service took all eight at the first request; the next answer that arrives confirms the two it carried
    // (the rest are confirmed as they are sent again, as duplicates).
    assert_eq!(step(&mut sender), SendOutcome::Sent(2));
    assert_eq!(sender.outbox().last_acked().unwrap(), 2);
    fill(sender.outbox_mut(), &clock, 30);
    drain(&mut sender);
    // Back up by a quarter (at least one) per confirmed request, never straight to the size that just failed.
    assert_eq!(counts_per_request(&service), [8, 4, 2, 3, 4, 5, 6, 7, 8, 3]);
}

#[test]
fn after_a_halving_a_batch_grows_back_by_a_quarter_up_to_500() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1_200);
    let mut sender = make_sender(&service, outbox, &clock);
    // The service takes at most 300 at a time: 500 is refused, then 250 fits.
    service.push(Step::MaxEvents(300));
    assert_eq!(step(&mut sender), SendOutcome::RetryNow);
    drain(&mut sender);
    assert_eq!(counts_per_request(&service), [500, 250, 312, 390, 248]);
    // 487 after the last of those, and a quarter more is past 500: back at the limit, and no further.
    fill(sender.outbox_mut(), &clock, 1_001);
    drain(&mut sender);
    assert_eq!(counts_per_request(&service)[5..], [500, 500, 1]);
}

#[test]
fn a_timeout_of_a_single_event_or_a_heartbeat_backs_off_and_halves_nothing() {
    use std::time::Duration;
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    let mut sender = make_sender(&service, outbox, &clock).with_request_timeout(Duration::from_millis(200));
    // A heartbeat that times out: a back-off, and the batch keeps its size.
    service.push(Step::Delay(Duration::from_millis(600)));
    assert_eq!(
        sender.heartbeat().unwrap(),
        SendOutcome::RetryLater(BACKOFF_FIRST_SECONDS)
    );
    assert_eq!(sender.trouble().map(|t| t.as_text()).as_deref(), Some("timeout"));
    clock.advance_seconds(BACKOFF_FIRST_SECONDS as i64);
    // One event that times out: a longer back-off, and still no halving.
    service.push(Step::Delay(Duration::from_millis(600)));
    assert_eq!(step(&mut sender), SendOutcome::RetryLater(2 * BACKOFF_FIRST_SECONDS));
    assert_eq!(sender.trouble().map(|t| t.as_text()).as_deref(), Some("timeout"));
    clock.advance_seconds(BACKOFF_MAX_SECONDS as i64);
    fill(sender.outbox_mut(), &clock, 3);
    drain(&mut sender);
    assert_eq!(counts_per_request(&service), [0, 1, 4]);
}

#[test]
fn a_confirmation_whose_counters_cannot_be_read_backs_off_like_one_that_cannot_be_recorded() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 2);
    let mut sender = make_sender(&service, outbox, &clock);
    // Something this code never writes, where the count of assigned numbers belongs: read only once the answer is in.
    let db = rusqlite::Connection::open(tmp.join("outbox.sqlite")).unwrap();
    db.execute("UPDATE meta SET value = 'seven' WHERE key = 'last_assigned'", [])
        .unwrap();
    assert!(sender.step().is_err());
    assert_eq!(
        step(&mut sender),
        SendOutcome::RetryLater(BACKOFF_FIRST_SECONDS),
        "not again at once"
    );
    assert_eq!(service.requests().len(), 1);
    db.execute("UPDATE meta SET value = '2' WHERE key = 'last_assigned'", [])
        .unwrap();
    clock.advance_seconds(BACKOFF_FIRST_SECONDS as i64);
    assert_eq!(step(&mut sender), SendOutcome::Sent(2));
}

#[test]
fn a_connection_refused_a_timeout_and_a_tls_failure_are_told_apart() {
    use std::time::Duration;
    // Refused: a port that was free a moment ago and has no listener now.
    let (tmp, clock) = (TempDir::new(), TestClock::new());
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut sender = sender_with_key(
        &format!("http://127.0.0.1:{port}"),
        open_outbox(&tmp, "refused.sqlite"),
        &clock,
        vector_key(),
    );
    assert!(matches!(sender.heartbeat().unwrap(), SendOutcome::RetryLater(_)));
    assert_eq!(sender.trouble().map(|t| t.as_text()).as_deref(), Some("refused"));
    // A timeout: a listener that takes the connection and never answers.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = silent.local_addr().unwrap();
    let mut sender = sender_with_key(
        &format!("http://{address}"),
        open_outbox(&tmp, "timeout.sqlite"),
        &clock,
        vector_key(),
    )
    .with_request_timeout(Duration::from_millis(200));
    assert!(matches!(sender.heartbeat().unwrap(), SendOutcome::RetryLater(_)));
    assert_eq!(sender.trouble().map(|t| t.as_text()).as_deref(), Some("timeout"));
    drop(silent);
    // TLS: an https origin on loopback whose peer answers in plain HTTP.
    let plain = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = plain.local_addr().unwrap().port();
    let peer = plain_peer(plain, 3);
    let mut sender = sender_with_key(
        &format!("https://127.0.0.1:{port}"),
        open_outbox(&tmp, "tls.sqlite"),
        &clock,
        vector_key(),
    );
    assert!(matches!(sender.heartbeat().unwrap(), SendOutcome::RetryLater(_)));
    peer.join().unwrap().unwrap();
    assert_eq!(sender.trouble().map(|t| t.as_text()).as_deref(), Some("tls"));
}

#[test]
fn plain_http_is_for_the_loopback_literals_only_not_the_name_localhost() {
    assert!(
        service_origin("http://localhost:8080").is_err(),
        "a name can be answered by the network"
    );
    assert!(service_origin("http://LOCALHOST:8080").is_err());
    assert_eq!(
        service_origin("http://127.0.0.1:8080").unwrap(),
        "http://127.0.0.1:8080"
    );
    assert_eq!(service_origin("http://[::1]:8080").unwrap(), "http://[::1]:8080");
    assert_eq!(
        service_origin("https://localhost:8443").unwrap(),
        "https://localhost:8443"
    );
}

#[test]
fn a_request_carries_events_of_one_schema_version_only() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 4);
    // As if a later build had queued the last two for another schema version.
    let db = rusqlite::Connection::open(tmp.join("outbox.sqlite")).unwrap();
    db.execute("UPDATE events SET schema_version = 2 WHERE seq > 2", [])
        .unwrap();
    drop(db);
    let mut sender = make_sender(&service, outbox, &clock);
    assert_eq!(step(&mut sender), SendOutcome::Sent(2));
    let _ = step(&mut sender);
    let requests = service.requests();
    assert_eq!(requests[0].events, Some(vec![1, 2]));
    assert_eq!(requests[1].events, Some(vec![3, 4]));
    let body = |index: usize| -> Value { serde_json::from_slice(requests[index].plain.as_ref().unwrap()).unwrap() };
    assert_eq!(
        (body(0)["schemaVersion"].clone(), body(1)["schemaVersion"].clone()),
        (json!(1), json!(2))
    );
}

// ---- What a confirming answer may mean ----

#[test]
fn a_service_that_holds_less_than_it_confirmed_halts_with_gap_also_on_a_heartbeat() {
    // Ten events delivered and confirmed; then the service holds only three. A site with nothing new to report sends
    // only heartbeats: the loss is still found, at the first answer that shows it.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 10);
    let mut sender = make_sender(&service, outbox, &clock);
    drain(&mut sender);
    assert_eq!(sender.outbox().last_acked().unwrap(), 10);
    service.set_last_seq(3);
    // The first lower answer is a suspicion: it confirms nothing and is asked again after the back-off.
    assert_eq!(
        sender.heartbeat().unwrap(),
        SendOutcome::RetryLater(BACKOFF_FIRST_SECONDS)
    );
    assert_eq!(sender.halted(), None);
    assert_eq!(sender.trouble().map(|t| t.as_text()).as_deref(), Some("not_confirming"));
    clock.advance_seconds(BACKOFF_FIRST_SECONDS as i64);
    // The next answer is lower again: the service lost events.
    assert_eq!(sender.heartbeat().unwrap(), SendOutcome::Halted(HaltReason::Gap));
    assert_eq!(sender.halted(), Some(HaltReason::Gap));
    assert_eq!(sender.outbox().last_acked().unwrap(), 10, "nothing re-declared");
    assert_eq!(sender.outbox().last_assigned().unwrap(), 10, "nothing numbered again");
}

#[test]
fn one_lower_answer_followed_by_a_good_one_halts_nothing_and_loses_nothing() {
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 10);
    let mut sender = make_sender(&service, outbox, &clock);
    drain(&mut sender);
    // Something in between answers once with a lower number (a stale replica, a proxy's cached page).
    service.push(Step::status(200, json!({"accepted": 0, "duplicates": 0, "lastSeq": 3})));
    assert_eq!(
        sender.heartbeat().unwrap(),
        SendOutcome::RetryLater(BACKOFF_FIRST_SECONDS)
    );
    clock.advance_seconds(BACKOFF_FIRST_SECONDS as i64);
    assert_eq!(
        sender.heartbeat().unwrap(),
        SendOutcome::Sent(0),
        "the service's own answer"
    );
    assert_eq!(sender.trouble(), None);
    // The suspicion is gone: one more lower answer is again only a suspicion.
    clock.advance_seconds(HEARTBEAT_SECONDS);
    service.push(Step::status(200, json!({"accepted": 0, "duplicates": 0, "lastSeq": 3})));
    assert_eq!(
        sender.heartbeat().unwrap(),
        SendOutcome::RetryLater(BACKOFF_FIRST_SECONDS)
    );
    assert_eq!(sender.halted(), None);
    assert_eq!(sender.outbox().last_acked().unwrap(), 10);
    fill(sender.outbox_mut(), &clock, 1);
    clock.advance_seconds(BACKOFF_FIRST_SECONDS as i64);
    assert_eq!(step(&mut sender), SendOutcome::Sent(1));
    assert_eq!(service.accepted_seqs(), (1..=11).collect::<Vec<u64>>());
}

#[test]
fn a_confirmation_at_or_ahead_of_the_hubs_mark_is_no_gap() {
    // An answer lost on the way back leaves the hub's mark BEHIND the service, never ahead: that is no gap.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 3);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::LoseAnswer);
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    clock.advance_seconds(BACKOFF_FIRST_SECONDS as i64);
    assert_eq!(sender.heartbeat().unwrap(), SendOutcome::Sent(0));
    assert_eq!(sender.halted(), None);
}

#[test]
fn a_200_whose_counts_do_not_account_for_the_events_sent_confirms_nothing() {
    for body in [
        json!({"accepted": 0, "duplicates": 0, "lastSeq": 2}),
        json!({"accepted": 1, "duplicates": 0, "lastSeq": 2}),
        json!({"accepted": 2, "duplicates": 1, "lastSeq": 2}),
        // The counts say both were taken, `lastSeq` says the second was not: the fields disagree, neither is trusted.
        json!({"accepted": 2, "duplicates": 0, "lastSeq": 1}),
    ] {
        let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
        let mut outbox = open_outbox(&tmp, "outbox.sqlite");
        fill(&mut outbox, &clock, 2);
        let mut sender = make_sender(&service, outbox, &clock);
        service.push(Step::status(200, body.clone()));
        assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)), "{body}");
        assert_eq!(sender.outbox().last_acked().unwrap(), 0, "{body}");
        assert_eq!(
            sender.trouble().map(|t| t.as_text()).as_deref(),
            Some("not_confirming"),
            "{body}"
        );
    }
}

#[test]
fn a_smaller_retry_answered_with_the_whole_earlier_attempt_confirms_it() {
    // Four events went and the answer was lost; the retry carries two. The service counts the two as duplicates and
    // says it holds four: `lastSeq` is cumulative, but only what a request carried is removed from the queue. The
    // other two are confirmed when they are sent.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 4);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::LoseAnswer);
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    assert_eq!(service.last_seq(), 4);
    clock.advance_seconds(BACKOFF_FIRST_SECONDS as i64);
    service.push(Step::MaxEvents(2));
    assert_eq!(step(&mut sender), SendOutcome::RetryNow, "413: the batch is halved");
    assert_eq!(step(&mut sender), SendOutcome::Sent(2));
    assert_eq!(sender.outbox().last_acked().unwrap(), 2);
    assert_eq!(
        step(&mut sender),
        SendOutcome::Sent(2),
        "the other two, counted as duplicates"
    );
    assert_eq!(sender.outbox().last_acked().unwrap(), 4);
    assert!(sender.outbox().pending(10, None).unwrap().is_empty());
}

#[test]
fn a_heartbeat_does_not_confirm_queued_events_the_service_never_compared() {
    // A queue restored from an older copy holds an event 1 the service does not have; the service holds another
    // event 1. The heartbeat's `lastSeq` says where the service stands, not that it holds THESE events: sending them
    // lets the service tell a duplicate from a conflict.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 1);
    service.set_last_seq(1);
    let mut sender = make_sender(&service, outbox, &clock);
    assert_eq!(sender.heartbeat().unwrap(), SendOutcome::Sent(0));
    assert_eq!(sender.service_last_seq(), Some(1));
    assert_eq!(sender.outbox().pending(10, None).unwrap().len(), 1, "still queued");
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::ReplayConflict));
}

#[test]
fn a_queue_whose_answer_was_lost_still_drains_after_a_restart_without_a_halt() {
    // The service holds the very events queued here (their answer was lost): after the greeting they go again, are
    // counted as duplicates byte for byte, and are confirmed.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut outbox = open_outbox(&tmp, "outbox.sqlite");
    fill(&mut outbox, &clock, 3);
    let mut sender = make_sender(&service, outbox, &clock);
    service.push(Step::LoseAnswer);
    assert!(matches!(step(&mut sender), SendOutcome::RetryLater(_)));
    let outbox = sender.into_outbox();
    let mut restarted = make_sender(&service, outbox, &clock);
    assert_eq!(restarted.heartbeat().unwrap(), SendOutcome::Sent(0));
    assert_eq!(step(&mut restarted), SendOutcome::Sent(3));
    assert_eq!(restarted.halted(), None);
    assert_eq!(restarted.outbox().last_acked().unwrap(), 3);
    assert_eq!(service.accepted_seqs(), [1, 2, 3], "each once");
    assert_eq!(events_per_request(&service).last().unwrap(), &Some(vec![1, 2, 3]));
}

#[test]
fn a_confirmation_reaching_past_the_request_removes_only_what_the_request_carried() {
    // A queue of 501 events: the first 500 are the very events the service holds, event 501 is not. The first batch
    // carries 1 to 500 and the service answers that it holds 501. Event 501 was never compared: it stays queued, and
    // when it is sent the service tells the conflict.
    let (tmp, clock, service) = (TempDir::new(), TestClock::new(), service());
    let mut ours = open_outbox(&tmp, "ours.sqlite");
    fill(&mut ours, &clock, 500);
    ours.close().unwrap();
    std::fs::copy(tmp.join("ours.sqlite"), tmp.join("theirs.sqlite")).unwrap();
    let mut theirs = open_outbox(&tmp, "theirs.sqlite");
    theirs
        .append("site.device_seen", &at(&clock, 0), &seen(), None)
        .unwrap();
    let mut other = make_sender(&service, theirs, &clock);
    drain(&mut other);
    assert_eq!(service.last_seq(), 501);
    let mut ours = open_outbox(&tmp, "ours.sqlite");
    ours.append("site.device_appeared", &at(&clock, 0), &appeared(), None)
        .unwrap();
    let mut sender = make_sender(&service, ours, &clock);
    assert_eq!(step(&mut sender), SendOutcome::Sent(500));
    assert_eq!(sender.outbox().last_acked().unwrap(), 500);
    assert_eq!(
        sender.outbox().pending(10, None).unwrap().len(),
        1,
        "event 501 still queued"
    );
    assert_eq!(step(&mut sender), SendOutcome::Halted(HaltReason::ReplayConflict));
}
