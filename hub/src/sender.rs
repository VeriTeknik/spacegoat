// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sender: delivers what the outbox holds, in order, and says honestly what happened (spec/protocol.md §10).
//!
//! One call to `step()` makes at most one request. It never sleeps and never loops: the agent's loop decides when to
//! call it again, from the outcome it returns. The clock is injected, so every decision here is testable against a
//! real service.
//!
//! What it guarantees:
//! - an event is forgotten only after the service confirmed it (`200` with `accepted`, `duplicates` and `lastSeq`,
//!   all non-negative integers); any other `200` (a proxy page, a captive portal) confirms nothing;
//! - a failed or unanswered request is sent again with the same bytes, so the service counts duplicates, never gaps.
//!   The body is the outbox's stored event texts spliced into `{"events":[...],"schemaVersion":1}`, never the events
//!   parsed and written again;
//! - a refusal no retry can fix (rejected content, a conflicting replay, a service that lost what it had confirmed)
//!   HALTS the sender. A halted sender makes no request at all: knocking for ever with the same refused batch only
//!   buries the fault. A person looks, the fault is fixed, the agent is started again and continues from there;
//! - `401` does not halt. The service gives the same answer for an unknown key and for a clock that is more than five
//!   minutes off, and a clock corrects itself: the sender says so (`problem`) and tries again, slowly;
//! - it talks to one origin only: a redirect is never followed (the signed headers and the events would go with it),
//!   no proxy is taken from the environment, and it is `https` unless the service is on this very machine;
//! - an answer that cannot be read in full, or is larger than 64 KiB, is no answer: the events are sent again.
//!
//! It also reads two things off every answer for the agent: how far the hub's clock is from the service's (`Date`),
//! and the last sequence number the service holds (`lastSeq`).

use std::fmt;
use std::io::{self, Write};
use std::net::Ipv6Addr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Map, Value};
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

use crate::clock;
use crate::outbox::{Outbox, OutboxError, StoredEvent};
use crate::signing;

pub const INGEST_PATH: &str = "/api/ops/evidence/ingest";
/// The service expects a sign of life every 300 seconds and alerts after three missed ones.
pub const HEARTBEAT_SECONDS: i64 = 240;
pub const MAX_EVENTS: usize = 500;
pub const MAX_COMPRESSED_BYTES: usize = 512 * 1024;
pub const MAX_UNCOMPRESSED_BYTES: usize = 4 * 1024 * 1024;
/// The longest `Retry-After` honoured: the hub owes a sign of life sooner than that.
pub const MAX_WAIT_SECONDS: u64 = 3600;
pub const BACKOFF_FIRST_SECONDS: u64 = 5;
pub const BACKOFF_MAX_SECONDS: u64 = 300;
/// The whole request, from resolving the name to the last byte of the answer.
pub const REQUEST_TIMEOUT_SECONDS: u64 = 30;
pub const CONNECT_TIMEOUT_SECONDS: u64 = 10;
pub const UNAUTHORIZED_RETRY_SECONDS: u64 = 300;
pub const MAX_ANSWER_BYTES: u64 = 64 * 1024;

/// The hosts plain `http` is allowed for: this very machine.
const LOCAL_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "::1"];
const MS_PER_SECOND: i64 = 1000;

/// Why the sender stopped for good (until a person starts the agent again).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltReason {
    /// `400 schema`: the service refuses the content.
    Schema,
    /// `409 replay_conflict`: another event is on record under a number this hub sent.
    ReplayConflict,
    /// `409 seq_gap`: the service lost events it had confirmed.
    Gap,
    /// One event alone is larger than a request may be.
    TooLarge,
    /// The service confirmed a number this hub never assigned: two hubs share one identity.
    Ahead,
}

impl HaltReason {
    /// The words the Python agent recorded (and its status printed).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "schema",
            Self::ReplayConflict => "replay_conflict",
            Self::Gap => "gap",
            Self::TooLarge => "too_large",
            Self::Ahead => "ahead",
        }
    }
}

impl fmt::Display for HaltReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why delivery is not working although the sender keeps trying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// `401`: an unknown key, or a clock more than five minutes off.
    Unauthorized,
}

impl Problem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one `step()` did, and so when the agent should call it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// The service confirmed a request carrying this many events (0 for a heartbeat).
    Sent(usize),
    /// Nothing to send and no heartbeat due.
    Idle,
    /// Call again at once (the batch was split).
    RetryNow,
    /// Call again in this many seconds; until then `step()` makes no request.
    RetryLater(u64),
    /// Stopped for good; `step()` makes no request any more.
    Halted(HaltReason),
    /// The service holds this sequence number and this outbox has never assigned one: the queue was lost, or this
    /// is a reinstall. The agent declares it (`Outbox::declare_reset`); nothing was confirmed.
    ServiceAhead(u64),
}

/// The service address is not an origin this hub may talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginError(&'static str);

impl fmt::Display for OriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "base_url: {}", self.0)
    }
}

impl std::error::Error for OriginError {}

/// The hub's own storage failed; the service was not the problem.
#[derive(Debug)]
pub enum SenderError {
    Outbox(OutboxError),
    Compress(io::Error),
}

impl fmt::Display for SenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Outbox(error) => error.fmt(f),
            Self::Compress(error) => write!(f, "compressing the request: {error}"),
        }
    }
}

impl std::error::Error for SenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Outbox(error) => Some(error),
            Self::Compress(error) => Some(error),
        }
    }
}

impl From<OutboxError> for SenderError {
    fn from(error: OutboxError) -> Self {
        Self::Outbox(error)
    }
}

/// An answer that was read in full.
struct Answer {
    status: u16,
    /// The body if it is a JSON object; empty otherwise.
    object: Map<String, Value>,
    retry_after: Option<String>,
}

pub struct Sender {
    url: String,
    agent: ureq::Agent,
    principal: String,
    key_id: String,
    key: SigningKey,
    outbox: Outbox,
    now: Box<dyn Fn() -> i64 + Send>,
    max_compressed: usize,
    max_uncompressed: usize,
    batch_limit: usize,
    failures: u32,
    /// No request before this moment (Unix milliseconds).
    not_before: i64,
    last_contact: Option<i64>,
    halted: Option<HaltReason>,
    last_success: Option<i64>,
    problem: Option<Problem>,
    clock_skew_ms: Option<i64>,
    service_last_seq: Option<u64>,
}

impl Sender {
    /// A sender for the service at `base_url` (an origin, see `service_origin`), delivering `outbox` as `source_id`
    /// with `key`. `now` is the clock, in Unix milliseconds.
    pub fn new(
        base_url: &str,
        source_id: &str,
        key_id: &str,
        key: SigningKey,
        outbox: Outbox,
        now: impl Fn() -> i64 + Send + 'static,
    ) -> Result<Self, OriginError> {
        let url = format!("{}{INGEST_PATH}", service_origin(base_url)?);
        let config = ureq::Agent::config_builder()
            // An answer that points elsewhere is an answer, not an instruction. With 0 the 3xx itself is returned.
            .max_redirects(0)
            // Config::default() reads HTTP(S)_PROXY and ALL_PROXY from the environment; this hub talks to one origin.
            .proxy(None)
            // 4xx and 5xx are answers the protocol defines, read like any other.
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(REQUEST_TIMEOUT_SECONDS)))
            .timeout_connect(Some(Duration::from_secs(CONNECT_TIMEOUT_SECONDS)))
            // One request every few minutes: a kept connection would only go stale and fail the next request.
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .user_agent(concat!("spacegoat-hub/", env!("CARGO_PKG_VERSION")))
            // rustls (ring) with Mozilla's roots compiled in: a device image without a CA bundle still verifies the
            // service, and nothing on the device's disk decides whom the hub trusts.
            .tls_config(
                TlsConfig::builder()
                    .provider(TlsProvider::Rustls)
                    .root_certs(RootCerts::WebPki)
                    .build(),
            )
            .build();
        Ok(Self {
            url,
            agent: ureq::Agent::new_with_config(config),
            principal: format!("source:{source_id}"),
            key_id: key_id.to_owned(),
            key,
            outbox,
            now: Box::new(now),
            max_compressed: MAX_COMPRESSED_BYTES,
            max_uncompressed: MAX_UNCOMPRESSED_BYTES,
            batch_limit: MAX_EVENTS,
            failures: 0,
            not_before: i64::MIN,
            last_contact: None,
            halted: None,
            last_success: None,
            problem: None,
            clock_skew_ms: None,
            service_last_seq: None,
        })
    }

    /// Smaller request limits than the protocol's (for tests, or a service that asks for less). Never larger: the
    /// service refuses anything over its limits.
    pub fn with_limits(mut self, max_compressed_bytes: usize, max_uncompressed_bytes: usize) -> Self {
        self.max_compressed = max_compressed_bytes.min(MAX_COMPRESSED_BYTES);
        self.max_uncompressed = max_uncompressed_bytes.min(MAX_UNCOMPRESSED_BYTES);
        self
    }

    pub fn outbox(&self) -> &Outbox {
        &self.outbox
    }

    pub fn outbox_mut(&mut self) -> &mut Outbox {
        &mut self.outbox
    }

    pub fn into_outbox(self) -> Outbox {
        self.outbox
    }

    /// Why the sender stopped, if it did.
    pub fn halted(&self) -> Option<HaltReason> {
        self.halted
    }

    /// Why delivery is not working although the sender keeps trying.
    pub fn problem(&self) -> Option<Problem> {
        self.problem
    }

    /// When the service last confirmed a request (Unix milliseconds).
    pub fn last_success(&self) -> Option<i64> {
        self.last_success
    }

    /// Hub clock minus service clock, from the last answer that carried a readable `Date`; `None` before any, and
    /// after an answer whose `Date` was missing or not an IMF-fixdate.
    pub fn clock_skew_millis(&self) -> Option<i64> {
        self.clock_skew_ms
    }

    /// The same in seconds.
    pub fn clock_skew_seconds(&self) -> Option<f64> {
        self.clock_skew_ms.map(|ms| ms as f64 / 1000.0)
    }

    /// The last sequence number the service said it holds; `None` before any confirmed answer.
    pub fn service_last_seq(&self) -> Option<u64> {
        self.service_last_seq
    }

    /// At most one request; never sleeps, never loops. An `Err` is the hub's own storage failing, never the service.
    pub fn step(&mut self) -> Result<SendOutcome, SenderError> {
        if let Some(reason) = self.halted {
            return Ok(SendOutcome::Halted(reason));
        }
        let now = (self.now)();
        if now < self.not_before {
            return Ok(SendOutcome::RetryLater(ceil_seconds(
                self.not_before.saturating_sub(now),
            )));
        }
        let events = self.outbox.pending(self.batch_limit, None)?;
        let heartbeat_due = self
            .last_contact
            .is_none_or(|at| now.saturating_sub(at) >= HEARTBEAT_SECONDS * MS_PER_SECOND);
        if events.is_empty() && !heartbeat_due {
            return Ok(SendOutcome::Idle);
        }
        let Some((body, count)) = self.fit(&events)? else {
            return Ok(self.halt(HaltReason::TooLarge));
        };
        let Some(answer) = self.post(&body, now) else {
            return Ok(self.back_off());
        };
        self.last_contact = Some(now);
        let error = answer.object.get("error").and_then(Value::as_str);
        Ok(match (answer.status, error) {
            (200, _) => self.confirmed(&answer.object, count, now)?,
            // The service expects a number this hub has already been told was confirmed, and has forgotten: the
            // service lost events. A hub cannot send what it no longer has, and it does not invent a sequence.
            (409, Some("seq_gap")) => self.halt(HaltReason::Gap),
            (401, _) => {
                self.problem = Some(Problem::Unauthorized);
                self.wait(UNAUTHORIZED_RETRY_SECONDS)
            }
            (413, _) if count <= 1 => self.halt(HaltReason::TooLarge),
            (413, _) => {
                self.batch_limit = (count / 2).max(1);
                SendOutcome::RetryNow
            }
            (429, _) => self.wait(retry_after(answer.retry_after.as_deref(), now)),
            (400 | 409, Some("schema")) => self.halt(HaltReason::Schema),
            (400 | 409, Some("replay_conflict")) => self.halt(HaltReason::ReplayConflict),
            // 5xx, a redirect, and anything this version does not know: the service's trouble, not a reason to stop.
            _ => self.back_off(),
        })
    }

    /// The compressed body of the largest prefix of `events` within both limits, and how many events it carries.
    /// `None` when even one event is not.
    fn fit(&self, events: &[StoredEvent]) -> Result<Option<(Vec<u8>, usize)>, SenderError> {
        let mut count = events.len();
        loop {
            let plain = request_body(events.get(..count).unwrap_or_default());
            // Both limits: a batch that compresses well can be small on the wire and still too large once opened.
            if plain.len() <= self.max_uncompressed {
                let body = gzip(plain.as_bytes()).map_err(SenderError::Compress)?;
                if body.len() <= self.max_compressed {
                    return Ok(Some((body, count)));
                }
            }
            if count <= 1 {
                return Ok(None);
            }
            count /= 2;
        }
    }

    /// One signed POST. `None` when there is no complete answer: the request may or may not have arrived, and
    /// sending the same bytes again is always safe.
    fn post(&mut self, body: &[u8], now: i64) -> Option<Answer> {
        let timestamp = now.div_euclid(MS_PER_SECOND).to_string();
        let message = signing::request_signing_message(&self.principal, "POST", INGEST_PATH, &timestamp, body);
        let signature = signing::sign(&self.key, &message);
        let mut response = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .header("X-VT-Principal", &self.principal)
            .header("X-VT-Key-Id", &self.key_id)
            .header("X-VT-Timestamp", &timestamp)
            .header("X-VT-Signature", &signature)
            .send(body)
            .ok()?;
        let status = response.status().as_u16();
        let single = |name: &str| {
            let mut values = response.headers().get_all(name).iter();
            match (values.next(), values.next()) {
                (Some(value), None) => value.to_str().ok().map(str::to_owned),
                _ => None,
            }
        };
        let date = single("date");
        let retry_after = single("retry-after");
        // Half an answer, or more than the cap: no answer.
        let raw = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER_BYTES)
            .read_to_vec()
            .ok()?;
        self.clock_skew_ms = date
            .as_deref()
            .and_then(clock::parse_http_date)
            .and_then(|seconds| now.checked_sub(seconds.checked_mul(MS_PER_SECOND)?));
        Some(Answer {
            status,
            object: json_object(&raw),
            retry_after,
        })
    }

    fn confirmed(&mut self, answer: &Map<String, Value>, sent: usize, now: i64) -> Result<SendOutcome, SenderError> {
        let field = |name: &str| answer.get(name).and_then(Value::as_u64);
        let (Some(_), Some(_), Some(last_seq)) = (field("accepted"), field("duplicates"), field("lastSeq")) else {
            // A 200 that is not the service's answer (a proxy, a portal page): nothing was confirmed.
            return Ok(self.back_off());
        };
        self.service_last_seq = Some(last_seq);
        self.problem = None;
        let last_assigned = self.outbox.last_assigned()?;
        if last_seq > last_assigned {
            if last_assigned == 0 {
                // This hub has no queue and the service has a history: the queue was lost, or this is a reinstall.
                // The agent declares it; nothing is confirmed here.
                return Ok(SendOutcome::ServiceAhead(last_seq));
            }
            // The service holds events this hub never assigned: two hubs share one identity. It must not go on
            // writing into that sequence.
            return Ok(self.halt(HaltReason::Ahead));
        }
        match self.outbox.ack(last_seq) {
            Ok(()) => {}
            Err(OutboxError::AckAhead) => return Ok(self.halt(HaltReason::Ahead)),
            Err(error) => return Err(error.into()),
        }
        self.failures = 0;
        self.batch_limit = self.batch_limit.saturating_mul(2).min(MAX_EVENTS);
        self.last_success = Some(now);
        Ok(SendOutcome::Sent(sent))
    }

    fn halt(&mut self, reason: HaltReason) -> SendOutcome {
        self.halted = Some(reason);
        SendOutcome::Halted(reason)
    }

    /// No request for `seconds`, counted from now (after the answer, not from when the request left).
    fn wait(&mut self, seconds: u64) -> SendOutcome {
        let ms = i64::try_from(seconds).unwrap_or(i64::MAX).saturating_mul(MS_PER_SECOND);
        self.not_before = (self.now)().saturating_add(ms);
        SendOutcome::RetryLater(seconds)
    }

    /// 5 s, doubling with each failure in a row, at most 300 s.
    fn back_off(&mut self) -> SendOutcome {
        let seconds = BACKOFF_FIRST_SECONDS
            .saturating_mul(1u64 << self.failures.min(16))
            .min(BACKOFF_MAX_SECONDS);
        self.failures = self.failures.saturating_add(1);
        self.wait(seconds)
    }
}

/// Names the service and the source, never the key.
impl fmt::Debug for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sender")
            .field("url", &self.url)
            .field("principal", &self.principal)
            .field("key_id", &self.key_id)
            .field("halted", &self.halted)
            .field("problem", &self.problem)
            .finish_non_exhaustive()
    }
}

/// `{"events":[...],"schemaVersion":1}` with the stored texts spliced in as they are. It is the canonical JSON of
/// that object (keys sorted, no whitespace) because each stored text is canonical itself: the bytes the Python agent
/// sent for the same events.
fn request_body(events: &[StoredEvent]) -> String {
    let length = events.iter().map(|event| event.json.len() + 1).sum::<usize>();
    let mut body = String::with_capacity(length + 32);
    body.push_str("{\"events\":[");
    for (index, event) in events.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str(&event.json);
    }
    body.push_str("],\"schemaVersion\":1}");
    body
}

/// gzip at the strongest level (Python's `gzip.compress` default), with no time or name in the header.
fn gzip(plain: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(plain)?;
    encoder.finish()
}

fn json_object(raw: &[u8]) -> Map<String, Value> {
    match serde_json::from_slice(raw) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

/// Whole seconds, rounded up.
fn ceil_seconds(ms: i64) -> u64 {
    u64::try_from(ms.saturating_add(MS_PER_SECOND - 1) / MS_PER_SECOND).unwrap_or(0)
}

/// `Retry-After` as seconds or as an HTTP date, between 1 s and an hour; 5 s when it is neither.
fn retry_after(value: Option<&str>, now: i64) -> u64 {
    let value = value.unwrap_or("").trim();
    let seconds: i64 = if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        // Only digits: too many of them is simply a very long time.
        value.parse().unwrap_or(i64::MAX)
    } else if let Some(at) = clock::parse_http_date(value) {
        let ms = at.saturating_mul(MS_PER_SECOND).saturating_sub(now);
        ms.saturating_add(MS_PER_SECOND - 1).div_euclid(MS_PER_SECOND)
    } else {
        return BACKOFF_FIRST_SECONDS;
    };
    let longest = i64::try_from(MAX_WAIT_SECONDS).unwrap_or(i64::MAX);
    u64::try_from(seconds.clamp(1, longest)).unwrap_or(MAX_WAIT_SECONDS)
}

/// `scheme://host[:port]` of the hub service, or the reason it is not one.
///
/// `https` only; plain `http` is for a service on this very machine (development, tests) and nothing else. No path
/// (beyond a single `/`), query, fragment or credentials: the request path is part of what is signed, and a prefix
/// check on the text would accept `http://localhost.evil.example`. The scheme and the host are compared and returned
/// in lowercase.
pub fn service_origin(base_url: &str) -> Result<String, OriginError> {
    let (scheme, rest) = base_url.split_once("://").ok_or(OriginError("not a URL"))?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err(OriginError("must be https"));
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if !tail.is_empty() && tail != "/" {
        return Err(OriginError("the service's origin only: no path, query or fragment"));
    }
    if authority.contains('@') {
        return Err(OriginError("the service's origin only: no credentials"));
    }
    let (host, port) = split_host_port(authority)?;
    let host = host.to_ascii_lowercase();
    if scheme == "http" && !LOCAL_HOSTS.contains(&host.as_str()) {
        return Err(OriginError("must be https (http only for this machine)"));
    }
    let name = if host.contains(':') { format!("[{host}]") } else { host };
    Ok(match port {
        Some(port) => format!("{scheme}://{name}:{port}"),
        None => format!("{scheme}://{name}"),
    })
}

/// The host (an IPv6 address without its brackets) and the port, if one is given.
fn split_host_port(authority: &str) -> Result<(&str, Option<u16>), OriginError> {
    let (host, port) = if let Some(inside) = authority.strip_prefix('[') {
        let (address, after) = inside.split_once(']').ok_or(OriginError("unclosed IPv6 address"))?;
        address
            .parse::<Ipv6Addr>()
            .map_err(|_| OriginError("not an IPv6 address"))?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or(OriginError("malformed port"))?),
        };
        (address, port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        let label = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'.';
        if host.is_empty() || !host.bytes().all(label) {
            return Err(OriginError("no host, or not a host name"));
        }
        (host, port)
    };
    let port = match port {
        None => None,
        Some(digits) => {
            if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(OriginError("malformed port"));
            }
            match digits.parse::<u16>() {
                Ok(port) if port > 0 => Some(port),
                _ => return Err(OriginError("malformed port")),
            }
        }
    };
    Ok((host, port))
}
