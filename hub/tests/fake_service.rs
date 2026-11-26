// SPDX-License-Identifier: AGPL-3.0-or-later
//! The test service checks what protocol §6 to §9 say an event looks like: these tests fail if it stops checking.
//!
//! Each bad event is built and signed by a real outbox (so only its form is wrong, never its signature) and sent by a
//! real sender; the service must answer `400 {"error":"schema"}`, which halts the sender with `Schema`. Each good
//! one is accepted, so a check that refused everything would fail here too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use serde_json::{Map, Value, json};
use spacegoat_hub::clock;
use spacegoat_hub::outbox::Outbox;
use spacegoat_hub::sender::{HaltReason, SendOutcome, Sender};
use support::fake_service::{FakeService, TestClock};
use support::{TempDir, vector_key};

const SOURCE: &str = "01234567-89ab-4cde-8fab-0123456789ab";
const KEY_ID: &str = "vector-key-1";
const DEVICE: &str = "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b";
const SEGMENT: &str = "0c0c0c0c-0c0c-4c0c-8c0c-0c0c0c0c0c0c";

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

fn time(clock: &TestClock, seconds_ago: i64) -> String {
    clock::observed_at_text(clock.now() - seconds_ago * 1000).unwrap()
}

struct Case {
    tmp: TempDir,
    clock: TestClock,
    service: FakeService,
    outbox: Outbox,
}

impl Case {
    fn new() -> Self {
        let tmp = TempDir::new();
        let clock = TestClock::new();
        let service = FakeService::new(SOURCE, KEY_ID, vector_key().verifying_key());
        service.set_now(clock.as_fn());
        let outbox = Outbox::open(&tmp.join("outbox.sqlite"), SOURCE, KEY_ID, vector_key()).unwrap();
        Self {
            tmp,
            clock,
            service,
            outbox,
        }
    }

    fn append(&mut self, kind: &str, attributes: Value, pii: Option<Value>) -> &mut Self {
        let at = time(&self.clock, 0);
        let pii = pii.map(object);
        self.outbox
            .append(kind, &at, &object(attributes), pii.as_ref())
            .unwrap();
        self
    }

    /// What the service makes of everything appended, in one request.
    fn send(self) -> (SendOutcome, FakeService) {
        let Self {
            tmp,
            clock,
            service,
            outbox,
        } = self;
        let mut sender = Sender::new(
            &service.base_url,
            SOURCE,
            KEY_ID,
            vector_key(),
            outbox,
            clock.as_clock(),
        )
        .unwrap();
        let outcome = sender.step().unwrap();
        drop(tmp);
        (outcome, service)
    }
}

fn verdict(kind: &str, attributes: Value, pii: Option<Value>) -> SendOutcome {
    let mut case = Case::new();
    case.append(kind, attributes, pii);
    case.send().0
}

fn refused(kind: &str, attributes: Value, pii: Option<Value>) {
    let shown = format!("{kind} {attributes} {pii:?}");
    assert_eq!(
        verdict(kind, attributes, pii),
        SendOutcome::Halted(HaltReason::Schema),
        "accepted: {shown}"
    );
}

fn accepted(kind: &str, attributes: Value, pii: Option<Value>) {
    let shown = format!("{kind} {attributes} {pii:?}");
    assert_eq!(verdict(kind, attributes, pii), SendOutcome::Sent(1), "refused: {shown}");
}

fn counts() -> Value {
    json!({"ot": 0, "printer": 1, "user_device": 2, "server": 0, "network": 0, "iot": 0, "unknown": 0})
}

#[test]
fn every_kind_in_its_protocol_form_is_accepted() {
    let pii = json!({"mac": "00005e005301", "hostname": "printer.example", "ip": "2001:db8::1"});
    let device = json!({"trustOrigin": "hub", "deviceRef": DEVICE, "segmentRef": SEGMENT});
    let mut appeared = device.clone();
    appeared["deviceClass"] = json!("printer");
    accepted("site.device_appeared", appeared.clone(), Some(pii.clone()));
    accepted("site.device_appeared", appeared.clone(), None);
    let mut changed = appeared;
    changed["changed"] = json!(["name", "address"]);
    accepted("site.device_changed", changed, Some(json!({"hostname": "p2.example"})));
    accepted("site.device_seen", device.clone(), None);
    let clock = TestClock::new();
    let mut gone = device;
    gone["lastSeenAt"] = json!(time(&clock, 89 * 86_400));
    accepted("site.device_gone", gone, None);
    accepted(
        "site.inventory_snapshot",
        json!({"trustOrigin": "hub", "segmentRef": SEGMENT, "counts": counts(), "ephemeral": 3}),
        None,
    );
    accepted(
        "site_source.input_lost",
        json!({"trustOrigin": "hub", "reason": "capture_unreadable", "toTime": time(&clock, 0)}),
        None,
    );
    accepted(
        "site_source.input_lost",
        json!({"trustOrigin": "hub", "reason": "capture_stopped", "fromTime": time(&clock, 60), "toTime": time(&clock, 0)}),
        None,
    );
    accepted(
        "site_source.event_dropped",
        json!({"trustOrigin": "hub", "reason": "operator", "originalKind": "site.device_seen"}),
        None,
    );
}

#[test]
fn an_unknown_kind_or_an_unknown_or_missing_attribute_is_refused() {
    let device = json!({"trustOrigin": "hub", "deviceRef": DEVICE, "segmentRef": SEGMENT});
    refused("site.device_exploded", device.clone(), None);
    let mut extra = device.clone();
    extra["note"] = json!("x");
    refused("site.device_seen", extra, None);
    refused("site.device_appeared", device.clone(), None); // no deviceClass
    let mut other_origin = device;
    other_origin["trustOrigin"] = json!("service");
    refused("site.device_seen", other_origin, None);
}

#[test]
fn references_must_be_uuid_version_4() {
    for (device, segment) in [
        ("0b0b0b0b-0b0b-1b0b-8b0b-0b0b0b0b0b0b", SEGMENT), // version 1
        (DEVICE, "0C0C0C0C-0C0C-4C0C-8C0C-0C0C0C0C0C0C"),  // uppercase
        ("0b0b0b0b-0b0b-4b0b-cb0b-0b0b0b0b0b0b", SEGMENT), // another variant
        ("printer", SEGMENT),
    ] {
        refused(
            "site.device_seen",
            json!({"trustOrigin": "hub", "deviceRef": device, "segmentRef": segment}),
            None,
        );
    }
    refused(
        "site.device_seen",
        json!({"trustOrigin": "hub", "deviceRef": 7, "segmentRef": SEGMENT}),
        None,
    );
}

#[test]
fn device_class_and_changed_come_from_their_lists() {
    let appeared =
        |class: Value| json!({"trustOrigin": "hub", "deviceRef": DEVICE, "segmentRef": SEGMENT, "deviceClass": class});
    refused("site.device_appeared", appeared(json!("toaster")), None);
    refused("site.device_appeared", appeared(json!(null)), None);
    for changed in [
        json!([]),
        json!(["name", "name"]),
        json!(["colour"]),
        json!("name"),
        json!([1]),
    ] {
        let mut attributes = appeared(json!("printer"));
        attributes["changed"] = changed;
        refused("site.device_changed", attributes, None);
    }
}

#[test]
fn a_snapshot_has_all_seven_counts_and_an_ephemeral_count() {
    let snapshot = |counts: Value, ephemeral: Value| json!({"trustOrigin": "hub", "segmentRef": SEGMENT, "counts": counts, "ephemeral": ephemeral});
    let mut missing = counts();
    missing.as_object_mut().unwrap().remove("iot");
    refused("site.inventory_snapshot", snapshot(missing, json!(0)), None);
    let mut extra = counts();
    extra["toaster"] = json!(1);
    refused("site.inventory_snapshot", snapshot(extra, json!(0)), None);
    let mut negative = counts();
    negative["ot"] = json!(-1);
    refused("site.inventory_snapshot", snapshot(negative, json!(0)), None);
    let mut text = counts();
    text["ot"] = json!("1");
    refused("site.inventory_snapshot", snapshot(text, json!(0)), None);
    refused("site.inventory_snapshot", snapshot(counts(), json!(-1)), None);
    refused(
        "site.inventory_snapshot",
        json!({"trustOrigin": "hub", "segmentRef": SEGMENT, "counts": counts()}),
        None,
    );
}

#[test]
fn last_seen_at_is_a_time_no_later_than_the_event_and_at_most_90_days_before() {
    let clock = TestClock::new();
    let gone =
        |last: Value| json!({"trustOrigin": "hub", "deviceRef": DEVICE, "segmentRef": SEGMENT, "lastSeenAt": last});
    refused("site.device_gone", gone(json!(time(&clock, -60))), None);
    refused("site.device_gone", gone(json!(time(&clock, 91 * 86_400))), None);
    refused("site.device_gone", gone(json!("2026-11-24T10:00:00Z")), None);
}

#[test]
fn the_sequence_kinds_carry_their_reasons_and_times() {
    let clock = TestClock::new();
    refused(
        "site_source.input_lost",
        json!({"trustOrigin": "hub", "reason": "nap", "toTime": time(&clock, 0)}),
        None,
    );
    refused(
        "site_source.input_lost",
        json!({"trustOrigin": "hub", "reason": "capture_stopped", "fromTime": time(&clock, 0), "toTime": time(&clock, 60)}),
        None,
    );
    refused(
        "site_source.input_lost",
        json!({"trustOrigin": "hub", "reason": "capture_stopped", "toTime": "yesterday"}),
        None,
    );
    refused(
        "site_source.input_lost",
        json!({"trustOrigin": "hub", "reason": "capture_stopped", "toTime": time(&clock, 0), "note": 1}),
        None,
    );
    refused(
        "site_source.event_dropped",
        json!({"trustOrigin": "hub", "reason": "expired", "originalKind": "site.device_seen"}),
        None,
    );
    refused(
        "site_source.event_dropped",
        json!({"trustOrigin": "hub", "reason": "operator", "originalKind": ""}),
        None,
    );
    refused(
        "site_source.reset",
        json!({"trustOrigin": "hub", "lastAckedSeq": 0, "reason": "oops"}),
        None,
    );
}

#[test]
fn personal_data_only_where_the_kind_allows_and_in_its_forms() {
    let device = json!({"trustOrigin": "hub", "deviceRef": DEVICE, "segmentRef": SEGMENT});
    refused("site.device_seen", device.clone(), Some(json!({"ip": "192.0.2.1"})));
    let mut appeared = device;
    appeared["deviceClass"] = json!("printer");
    for pii in [
        json!({"serial": "123"}),
        json!({"mac": "00:00:5E:00:53:01"}),
        json!({"mac": "00005E005301"}),
        json!({"hostname": ""}),
        json!({"hostname": "x".repeat(254)}),
        json!({"ip": "999.1.1.1"}),
        json!({"ip": 1}),
        json!({}),
    ] {
        refused("site.device_appeared", appeared.clone(), Some(pii));
    }
    accepted(
        "site.device_appeared",
        appeared,
        Some(json!({"hostname": "x".repeat(253)})),
    );
}

#[test]
fn a_field_beside_the_event_that_the_signature_does_not_cover_is_refused() {
    let mut case = Case::new();
    case.append(
        "site.device_seen",
        json!({"trustOrigin": "hub", "deviceRef": DEVICE, "segmentRef": SEGMENT}),
        None,
    );
    case.outbox.close().unwrap();
    let path = case.tmp.join("outbox.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    let body: String = db
        .query_row("SELECT body FROM events WHERE seq = 1", [], |row| row.get(0))
        .unwrap();
    let mut event: Value = serde_json::from_str(&body).unwrap();
    event["note"] = json!("unsigned");
    db.execute(
        "UPDATE events SET body = ?1 WHERE seq = 1",
        [spacegoat_hub::canonical::canonical_json(&event).unwrap()],
    )
    .unwrap();
    db.close().unwrap();
    case.outbox = Outbox::open(&path, SOURCE, KEY_ID, vector_key()).unwrap();
    assert_eq!(case.send().0, SendOutcome::Halted(HaltReason::Schema));
}

#[test]
fn a_reset_must_name_what_the_service_holds_wherever_it_sits_in_the_batch() {
    let seen = json!({"trustOrigin": "hub", "deviceRef": DEVICE, "segmentRef": SEGMENT});
    // Second in a batch: the service holds 1 when it reaches it.
    let mut case = Case::new();
    case.append("site.device_seen", seen.clone(), None).append(
        "site_source.reset",
        json!({"trustOrigin": "hub", "lastAckedSeq": 1, "reason": "queue_lost"}),
        None,
    );
    let (outcome, service) = case.send();
    assert_eq!(outcome, SendOutcome::Sent(2));
    assert_eq!(service.accepted_seqs(), [1, 2]);
    let mut case = Case::new();
    case.append("site.device_seen", seen, None).append(
        "site_source.reset",
        json!({"trustOrigin": "hub", "lastAckedSeq": 0, "reason": "queue_lost"}),
        None,
    );
    let (outcome, service) = case.send();
    assert_eq!(outcome, SendOutcome::Halted(HaltReason::Schema));
    assert!(service.accepted().is_empty(), "the whole batch is refused");
}

#[test]
fn a_gap_is_declared_from_the_next_number_and_carries_the_number_after_it() {
    let declared =
        |from: u64, to: u64| json!({"trustOrigin": "hub", "fromSeq": from, "toSeq": to, "reason": "operator"});
    let seen = json!({"trustOrigin": "hub", "deviceRef": DEVICE, "segmentRef": SEGMENT});
    // Numbers 1 to 3 are gone (assigned and forgotten here); the declaration is number 4.
    let at_four = |attributes: Value| {
        let mut case = Case::new();
        for _ in 0..3 {
            case.append("site.device_seen", seen.clone(), None);
        }
        // Forgotten as if confirmed; the service never saw them (it holds 0).
        case.outbox.ack(3).unwrap();
        case.append("site_source.gap_declared", attributes, None);
        case.send()
    };
    let (outcome, service) = at_four(declared(1, 3));
    assert_eq!(outcome, SendOutcome::Sent(1));
    assert_eq!(service.accepted_seqs(), [4]);
    assert_eq!(at_four(declared(1, 2)).0, SendOutcome::Halted(HaltReason::Schema));
    assert_eq!(at_four(declared(1, 4)).0, SendOutcome::Halted(HaltReason::Schema));
    assert_eq!(
        at_four(json!({"trustOrigin": "hub", "fromSeq": 1, "toSeq": 3, "reason": "lost"})).0,
        SendOutcome::Halted(HaltReason::Schema)
    );
    // Not from the next number: an ordinary gap in the sequence.
    assert_eq!(at_four(declared(2, 3)).0, SendOutcome::Halted(HaltReason::Gap));
}
