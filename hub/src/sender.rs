// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sender: delivers what the outbox holds, in order, and says honestly what happened (spec/protocol.md §10).
//!
//! One call to `step()` or `heartbeat()` makes at most one request. It never sleeps and never loops: the agent's loop
//! decides when to call it again, from the outcome it returns. The clocks are injected (`clock::Clock`), so every
//! decision here is testable against a real service. Every interval (back-off, the wait after a `401`, when a
//! heartbeat is due) is measured on the monotonic clock; the wall clock only gives the request its timestamp.
//!
//! What it guarantees:
//! - an event is forgotten only after the service confirmed it (`200` with `accepted`, `duplicates` and `lastSeq`,
//!   all integers from 0 to 2^53 - 1); any other `200` (a proxy page, a captive portal) confirms nothing. A `200` to
//!   a batch that moves the confirmed mark nowhere is a failure: it backs off rather than send the batch again at once.
//!   So is a confirmation the hub cannot record (its storage fails): it backs off, and the `Err` says why;
//! - a request that carried more than one event and timed out once its body had started to go out (or while the
//!   answer was awaited or read) halves the batch for the next attempt, as a `413` does; a timeout while resolving or
//!   connecting sent nothing, and halves nothing. A confirmed request lets the batch grow back by a quarter (at least
//!   one event), up to `MAX_EVENTS`: never straight back to the size that just failed;
//! - a failed or unanswered request is sent again with the same bytes, so the service counts duplicates, never gaps.
//!   The body is the outbox's stored event texts spliced into `{"events":[...],"schemaVersion":N}`, never the events
//!   parsed and written again, and a request carries events of one schema version only;
//! - a refusal no retry can fix (rejected content, a conflicting replay, a service that lost what it had confirmed,
//!   one event the service says is too large) to a request that carried events HALTS the sender (the same answer to
//!   a heartbeat refused nothing, and backs off). A halted sender makes no request at all: knocking for
//!   ever with the same refused batch only buries the fault. A person looks, the fault is fixed, the halt is cleared
//!   (`spacegoat-hub resume`) and the agent continues from there. A `413` halts only when it is the service's own
//!   answer (`{"error":"too_large"}`) to a request of exactly one event; to a larger batch it halves the batch, and
//!   anything else (a `413` to a heartbeat, or one from something in between) backs off;
//! - `429` waits what `Retry-After` says, at most `MAX_WAIT_SECONDS` (240), like every other wait;
//! - `401` does not halt. The service gives the same answer for an unknown key and for a clock that is more than five
//!   minutes off, and a clock corrects itself: the sender says so (`problem`) and tries again, slowly;
//! - it talks to one origin only: a redirect is never followed (the signed headers and the events would go with it),
//!   no proxy is taken from the environment, and it is `https` unless the service is on this very machine, named
//!   by a loopback literal (`127.0.0.1`, `[::1]`);
//! - an answer that cannot be read in full, or is larger than 64 KiB, is no answer: the events are sent again.
//!
//! It also reads two things off every answer for the agent: how far the hub's clock is from the service's (`Date`,
//! kept as a `ClockReading` with the hub's two clocks at that moment; an answer without a readable `Date` leaves the
//! last reading as it is), and the last sequence number the service holds (`lastSeq`).

use std::fmt;
use std::io::{self, Write};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Map, Value};
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use crate::canonical::MAX_SAFE_INTEGER;
use crate::clock::{self, Clock, ClockReading};
use crate::outbox::{Outbox, OutboxError, SCHEMA_VERSION, StoredEvent};
use crate::signing;

pub const INGEST_PATH: &str = "/api/ops/evidence/ingest";
/// The service expects a sign of life every 300 seconds and alerts after three missed ones.
pub const HEARTBEAT_SECONDS: i64 = 240;
pub const MAX_EVENTS: usize = 500;
pub const MAX_COMPRESSED_BYTES: usize = 512 * 1024;
pub const MAX_UNCOMPRESSED_BYTES: usize = 4 * 1024 * 1024;
/// The longest `Retry-After` honoured: like every other wait, no longer than the liveness interval allows (a
/// request at least every 300 seconds, protocol §11).
pub const MAX_WAIT_SECONDS: u64 = BACKOFF_MAX_SECONDS;
pub const BACKOFF_FIRST_SECONDS: u64 = 5;
/// The protocol wants a request at least every 300 seconds; a wait of 240 leaves room for the run loop's tick.
pub const BACKOFF_MAX_SECONDS: u64 = 240;
/// The whole request, from resolving the name to the last byte of the answer.
pub const REQUEST_TIMEOUT_SECONDS: u64 = 30;
pub const CONNECT_TIMEOUT_SECONDS: u64 = 10;
/// "Tries again slowly" (protocol §10), within the 300 seconds of §11.
pub const UNAUTHORIZED_RETRY_SECONDS: u64 = 240;
pub const MAX_ANSWER_BYTES: u64 = 64 * 1024;

/// The hosts plain `http` is allowed for: this very machine, by its loopback address literally. Not the name
/// `localhost`: a name is resolved, and a resolver can answer it with an address on the network.
const LOCAL_HOSTS: [&str; 2] = ["127.0.0.1", "::1"];
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
    /// A halt recorded on disk whose reason this version cannot read.
    Unknown,
}

impl HaltReason {
    /// The word `halt.json` records and the status prints.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "schema",
            Self::ReplayConflict => "replay_conflict",
            Self::Gap => "gap",
            Self::TooLarge => "too_large",
            Self::Ahead => "ahead",
            Self::Unknown => "unknown",
        }
    }

    /// The reason `as_str` wrote; `Unknown` for any other text.
    pub fn from_text(text: &str) -> Self {
        [
            Self::Schema,
            Self::ReplayConflict,
            Self::Gap,
            Self::TooLarge,
            Self::Ahead,
        ]
        .into_iter()
        .find(|reason| reason.as_str() == text)
        .unwrap_or(Self::Unknown)
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

/// Why the last request confirmed nothing (closed list; the status shows `as_text`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceTrouble {
    /// The service's name could not be resolved to an address.
    Dns,
    /// The connection was refused: nothing listens there.
    Refused,
    /// No complete answer within the request's time (`REQUEST_TIMEOUT_SECONDS`), or no connection within
    /// `CONNECT_TIMEOUT_SECONDS`.
    Timeout,
    /// The TLS handshake failed: a certificate that does not verify (or a clock it is not valid at), or a peer that
    /// does not speak TLS.
    Tls,
    /// No answer for any other reason: a connection reset or dropped, a network that is unreachable.
    NoConnection,
    /// An answer with this HTTP status that confirmed nothing.
    Http(u16),
    /// An answer that could not be read in full, or was larger than the cap.
    Unreadable,
    /// A `200` that confirmed nothing (not the service's answer, or a batch the mark did not move for).
    NotConfirming,
}

impl ServiceTrouble {
    pub fn as_text(self) -> String {
        match self {
            Self::Dns => "dns".to_owned(),
            Self::Refused => "refused".to_owned(),
            Self::Timeout => "timeout".to_owned(),
            Self::Tls => "tls".to_owned(),
            Self::NoConnection => "no_connection".to_owned(),
            Self::Http(status) => format!("http_{status}"),
            Self::Unreadable => "unreadable".to_owned(),
            Self::NotConfirming => "not_confirming".to_owned(),
        }
    }

    /// What kind of "no answer" a request error is, from its kind alone: the error's text is never looked at, and
    /// never kept (it can name the service's address).
    ///
    /// From ureq 3.5's own sources: a name that does not resolve is `HostNotFound` (the resolver below turns every
    /// resolution failure into it); a refused connect is an `Io` of kind `ConnectionRefused`; every timeout ureq
    /// enforces is `Timeout` (an `Io` of kind `TimedOut` is the socket's own); a TLS failure is `Tls`, `Rustls` or
    /// `Pem`, or an `Io` of kind `InvalidData`, which is how rustls's `complete_io` reports a handshake that failed
    /// (a certificate, an alert, a peer that answered in plain text) and which nothing else on the plain-TCP path
    /// produces.
    fn of_request_error(error: &ureq::Error) -> Self {
        match error {
            ureq::Error::HostNotFound => Self::Dns,
            ureq::Error::Timeout(_) => Self::Timeout,
            ureq::Error::Tls(_) | ureq::Error::Rustls(_) | ureq::Error::Pem(_) | ureq::Error::TlsRequired => Self::Tls,
            ureq::Error::Io(io) => match io.kind() {
                io::ErrorKind::ConnectionRefused => Self::Refused,
                io::ErrorKind::TimedOut => Self::Timeout,
                io::ErrorKind::InvalidData => Self::Tls,
                _ => Self::NoConnection,
            },
            _ => Self::NoConnection,
        }
    }
}

/// Whether a request error is a timeout at a point where the batch itself may be what took too long: once the body
/// had started to go out, or while the answer was awaited or read.
///
/// From ureq 3.5.2's `Timeout`: `Resolve` and `Connect` (a TCP connect that timed out is reported as `Connect`, also
/// when the overall limit was the one that ran out) and `SendRequest` (the request line and headers) come before the
/// body, and nothing of the batch was sent. `SendBody`, `RecvResponse` and `RecvBody` come after. `Global` and
/// `PerCall` name the overall limit, not the phase it ran out in, and an `Io` of kind `TimedOut` is a socket read or
/// write: those cannot be told apart by phase, and count as after the body started (the batch is halved). The
/// resolver below turns every resolution failure, a timeout included, into `HostNotFound`, which is no timeout.
fn timed_out_after_sending(error: &ureq::Error) -> bool {
    match error {
        ureq::Error::Timeout(ureq::Timeout::Resolve | ureq::Timeout::Connect | ureq::Timeout::SendRequest) => false,
        ureq::Error::Timeout(_) => true,
        ureq::Error::Io(io) => io.kind() == io::ErrorKind::TimedOut,
        _ => false,
    }
}

/// No complete answer: what kind of none, and whether it timed out after the body started to go out.
#[derive(Debug, Clone, Copy)]
struct NoAnswer {
    trouble: ServiceTrouble,
    after_sending: bool,
}

impl NoAnswer {
    fn of(error: &ureq::Error) -> Self {
        Self {
            trouble: ServiceTrouble::of_request_error(error),
            after_sending: timed_out_after_sending(error),
        }
    }
}

/// The batch limit after a confirmed request: a quarter more, at least one, at most `MAX_EVENTS`.
fn grown(limit: usize) -> usize {
    limit.saturating_add((limit / 4).max(1)).min(MAX_EVENTS)
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
    clock: Arc<dyn Clock>,
    max_compressed: usize,
    max_uncompressed: usize,
    batch_limit: usize,
    failures: u32,
    /// No request before this moment (monotonic milliseconds).
    not_before: i64,
    /// When the service last answered at all (monotonic milliseconds).
    last_contact: Option<i64>,
    halted: Option<HaltReason>,
    /// When the service last confirmed a request (wall milliseconds, for display).
    last_success: Option<i64>,
    problem: Option<Problem>,
    trouble: Option<ServiceTrouble>,
    reading: Option<ClockReading>,
    service_last_seq: Option<u64>,
}

impl Sender {
    /// A sender for the service at `base_url` (an origin, see `service_origin`), delivering `outbox` as `source_id`
    /// with `key`, on `clock`.
    pub fn new(
        base_url: &str,
        source_id: &str,
        key_id: &str,
        key: SigningKey,
        outbox: Outbox,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, OriginError> {
        let url = format!("{}{INGEST_PATH}", service_origin(base_url)?);
        Ok(Self {
            url,
            agent: http_agent(Duration::from_secs(REQUEST_TIMEOUT_SECONDS)),
            principal: format!("source:{source_id}"),
            key_id: key_id.to_owned(),
            key,
            outbox,
            clock,
            max_compressed: MAX_COMPRESSED_BYTES,
            max_uncompressed: MAX_UNCOMPRESSED_BYTES,
            batch_limit: MAX_EVENTS,
            failures: 0,
            not_before: i64::MIN,
            last_contact: None,
            halted: None,
            last_success: None,
            problem: None,
            trouble: None,
            reading: None,
            service_last_seq: None,
        })
    }

    /// A shorter request timeout than `REQUEST_TIMEOUT_SECONDS`, for tests that must see one expire. Production
    /// never calls it.
    #[doc(hidden)]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.agent = http_agent(timeout);
        self
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

    /// Stop for good (until a person clears it): a halt the agent decided, or one recorded before a restart. From
    /// here on no request is made.
    pub fn halt(&mut self, reason: HaltReason) -> SendOutcome {
        self.halted = Some(reason);
        SendOutcome::Halted(reason)
    }

    /// Why delivery is not working although the sender keeps trying.
    pub fn problem(&self) -> Option<Problem> {
        self.problem
    }

    /// Why the last request got no confirming answer; `None` before any request and after a confirming one.
    pub fn trouble(&self) -> Option<ServiceTrouble> {
        self.trouble
    }

    /// When the service last confirmed a request (wall clock, Unix milliseconds).
    pub fn last_success(&self) -> Option<i64> {
        self.last_success
    }

    /// The last reading of the service's clock: from the last answer that carried a readable `Date`. An answer
    /// without one (or with a `Date` that is not an IMF-fixdate) neither changes nor clears it.
    pub fn clock_reading(&self) -> Option<ClockReading> {
        self.reading
    }

    /// Hub clock minus service clock now: the last reading, corrected for any jump of the wall clock since then
    /// (`ClockReading::skew_now`). `None` before any reading.
    pub fn clock_skew_millis(&self) -> Option<i64> {
        let reading = self.reading?;
        Some(reading.skew_now(self.clock.wall_millis(), self.clock.mono_millis()))
    }

    /// The same in seconds.
    pub fn clock_skew_seconds(&self) -> Option<f64> {
        self.clock_skew_millis().map(|ms| ms as f64 / 1000.0)
    }

    /// The last sequence number the service said it holds; `None` before any confirmed answer.
    pub fn service_last_seq(&self) -> Option<u64> {
        self.service_last_seq
    }

    /// Whether a heartbeat is due: no answer yet in this run, or none for `HEARTBEAT_SECONDS` of monotonic time.
    pub fn heartbeat_due(&self) -> bool {
        let now = self.clock.mono_millis();
        self.last_contact
            .is_none_or(|at| now.saturating_sub(at) >= HEARTBEAT_SECONDS * MS_PER_SECOND)
    }

    /// At most one request: the events that wait, or a heartbeat when one is due. Never sleeps, never loops. An `Err`
    /// is the hub's own storage failing, never the service.
    pub fn step(&mut self) -> Result<SendOutcome, SenderError> {
        if let Some(waiting) = self.gate() {
            return Ok(waiting);
        }
        let events = self.batch()?;
        if events.is_empty() && !self.heartbeat_due() {
            return Ok(SendOutcome::Idle);
        }
        self.exchange(&events)
    }

    /// At most one request, and only one that carries events: never a heartbeat. For a hub that cannot say "alive,
    /// nothing to report" truthfully (its capture is failing) but still delivers what it has signed.
    pub fn step_events(&mut self) -> Result<SendOutcome, SenderError> {
        if let Some(waiting) = self.gate() {
            return Ok(waiting);
        }
        let events = self.batch()?;
        if events.is_empty() {
            return Ok(SendOutcome::Idle);
        }
        self.exchange(&events)
    }

    /// An empty request now (a heartbeat), whatever waits in the outbox: the first request of a run, which asks the
    /// service where it stands before anything is sent (protocol §11). Still none while halted or waiting out a
    /// back-off.
    pub fn heartbeat(&mut self) -> Result<SendOutcome, SenderError> {
        if let Some(waiting) = self.gate() {
            return Ok(waiting);
        }
        self.exchange(&[])
    }

    /// What waits, up to the batch limit, and only as far as it shares the first event's schema version: one request
    /// carries one `schemaVersion`.
    fn batch(&self) -> Result<Vec<StoredEvent>, SenderError> {
        let mut events = self.outbox.pending(self.batch_limit, None)?;
        if let Some(first) = events.first().map(|event| event.schema_version) {
            let same = events.iter().take_while(|event| event.schema_version == first).count();
            events.truncate(same);
        }
        Ok(events)
    }

    /// The outcome without a request: halted, or waiting until the monotonic `not_before`.
    fn gate(&self) -> Option<SendOutcome> {
        if let Some(reason) = self.halted {
            return Some(SendOutcome::Halted(reason));
        }
        let now = self.clock.mono_millis();
        (now < self.not_before).then(|| SendOutcome::RetryLater(ceil_seconds(self.not_before.saturating_sub(now))))
    }

    /// One request carrying `events` (none: a heartbeat), and what its answer means.
    fn exchange(&mut self, events: &[StoredEvent]) -> Result<SendOutcome, SenderError> {
        let Some((body, count)) = self.fit(events)? else {
            return Ok(self.halt(HaltReason::TooLarge));
        };
        let answer = match self.post(&body) {
            Ok(answer) => answer,
            Err(none) => {
                self.trouble = Some(none.trouble);
                if none.after_sending && count > 1 {
                    // A batch the service could not answer for in time may be too much for the link or for it: the
                    // next attempt carries half, as after a `413`. A confirmed request lets it grow back.
                    self.batch_limit = (count / 2).max(1);
                }
                return Ok(self.back_off());
            }
        };
        self.last_contact = Some(self.clock.mono_millis());
        if answer.status != 200 {
            // Cleared again only by a confirming answer (`confirmed`).
            self.trouble = Some(ServiceTrouble::Http(answer.status));
        }
        let error = answer.object.get("error").and_then(Value::as_str);
        let carried = count > 0;
        Ok(match (answer.status, error) {
            (200, _) => self.confirmed(&answer.object, count)?,
            // The refusals below halt only a request that carried events: to a heartbeat, nothing was refused.
            // The service expects a number this hub has already been told was confirmed, and has forgotten: the
            // service lost events. A hub cannot send what it no longer has, and it does not invent a sequence.
            (409, Some("seq_gap")) if carried => self.halt(HaltReason::Gap),
            (401, _) => {
                self.problem = Some(Problem::Unauthorized);
                self.wait(UNAUTHORIZED_RETRY_SECONDS)
            }
            // One event alone, refused by the service itself for its size: no split can help.
            (413, Some("too_large")) if count == 1 => self.halt(HaltReason::TooLarge),
            (413, _) if count > 1 => {
                self.batch_limit = (count / 2).max(1);
                SendOutcome::RetryNow
            }
            (429, _) => self.wait(retry_after(answer.retry_after.as_deref(), self.clock.wall_millis())),
            (400 | 409, Some("schema")) if carried => self.halt(HaltReason::Schema),
            (400 | 409, Some("replay_conflict")) if carried => self.halt(HaltReason::ReplayConflict),
            // 5xx, a redirect, a 413 to a heartbeat or one that is not the service's, a refusal of a heartbeat, and
            // anything this version does not know: the service's trouble (or something in between), not a reason
            // to stop.
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

    /// One signed POST, timestamped by the wall clock. An `Err` when there is no complete answer (and what kind of
    /// none): the request may or may not have arrived, and sending the same bytes again is always safe.
    fn post(&mut self, body: &[u8]) -> Result<Answer, NoAnswer> {
        let (wall, mono) = (self.clock.wall_millis(), self.clock.mono_millis());
        let timestamp = wall.div_euclid(MS_PER_SECOND).to_string();
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
            .map_err(|error| NoAnswer::of(&error))?;
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
        // Half an answer, or more than the cap: no answer. One that stopped coming in time is a timeout.
        let raw = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER_BYTES)
            .read_to_vec()
            .map_err(|error| {
                let after_sending = timed_out_after_sending(&error);
                NoAnswer {
                    trouble: if after_sending {
                        ServiceTrouble::Timeout
                    } else {
                        ServiceTrouble::Unreadable
                    },
                    after_sending,
                }
            })?;
        let skew = date
            .as_deref()
            .and_then(clock::parse_http_date)
            .and_then(|seconds| wall.checked_sub(seconds.checked_mul(MS_PER_SECOND)?));
        if let Some(skew_millis) = skew {
            // Only a readable `Date` is a reading; an answer without one keeps the last.
            self.reading = Some(ClockReading {
                skew_millis,
                wall_millis: wall,
                mono_millis: mono,
            });
        }
        Ok(Answer {
            status,
            object: json_object(&raw),
            retry_after,
        })
    }

    fn confirmed(&mut self, answer: &Map<String, Value>, sent: usize) -> Result<SendOutcome, SenderError> {
        // A count the protocol's JSON cannot carry exactly (above 2^53 - 1) is no count: the answer is malformed.
        let field = |name: &str| {
            answer
                .get(name)
                .and_then(Value::as_u64)
                .filter(|n| i64::try_from(*n).is_ok_and(|n| n <= MAX_SAFE_INTEGER))
        };
        let (Some(_), Some(_), Some(last_seq)) = (field("accepted"), field("duplicates"), field("lastSeq")) else {
            // A 200 that is not the service's answer (a proxy, a portal page): nothing was confirmed.
            self.trouble = Some(ServiceTrouble::NotConfirming);
            return Ok(self.back_off());
        };
        self.service_last_seq = Some(last_seq);
        self.problem = None;
        // The service's own answer: it is there and speaking for itself, whatever it says next.
        self.trouble = None;
        // A read that fails here is the hub's storage failing after the service answered, like an `ack` that fails:
        // a back-off, so the same batch does not meet the same disk again at once.
        let last_assigned = self.or_back_off(self.outbox.last_assigned())?;
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
        let before = self.or_back_off(self.outbox.last_acked())?;
        match self.outbox.ack(last_seq) {
            Ok(()) => {}
            Err(OutboxError::AckAhead) => return Ok(self.halt(HaltReason::Ahead)),
            Err(error) => {
                // The service confirmed, the hub could not record it (a full disk, a read-only file system, a held
                // lock): a failure like any other. Sending the same batch again at once only meets the same disk.
                self.back_off();
                return Err(error.into());
            }
        }
        let after = self.or_back_off(self.outbox.last_acked())?;
        if sent > 0 && after <= before {
            // Events went and the service confirmed none of them: whatever it is, sending the same batch again at
            // once will not change it.
            self.trouble = Some(ServiceTrouble::NotConfirming);
            return Ok(self.back_off());
        }
        self.failures = 0;
        self.batch_limit = grown(self.batch_limit);
        self.last_success = Some(self.clock.wall_millis());
        Ok(SendOutcome::Sent(sent))
    }

    /// No request for `seconds` of monotonic time, counted from now (after the answer, not from when it left).
    fn wait(&mut self, seconds: u64) -> SendOutcome {
        let ms = i64::try_from(seconds).unwrap_or(i64::MAX).saturating_mul(MS_PER_SECOND);
        self.not_before = self.clock.mono_millis().saturating_add(ms);
        SendOutcome::RetryLater(seconds)
    }

    /// `result`, after a back-off when it is a failure of the hub's own storage.
    fn or_back_off<T>(&mut self, result: Result<T, OutboxError>) -> Result<T, SenderError> {
        if result.is_err() {
            self.back_off();
        }
        result.map_err(SenderError::from)
    }

    /// The back-off after one more failure in a row (`backoff_seconds`).
    fn back_off(&mut self) -> SendOutcome {
        let seconds = backoff_seconds(self.failures);
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

/// `{"events":[...],"schemaVersion":N}` with the stored texts spliced in as they are, N the events' own schema version
/// (`SCHEMA_VERSION` for a heartbeat). It is the canonical JSON of that object (keys sorted, no whitespace) because
/// each stored text is canonical itself.
fn request_body(events: &[StoredEvent]) -> String {
    let schema_version = events.first().map_or(SCHEMA_VERSION, |event| event.schema_version);
    let length = events.iter().map(|event| event.json.len() + 1).sum::<usize>();
    let mut body = String::with_capacity(length + 32);
    body.push_str("{\"events\":[");
    for (index, event) in events.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str(&event.json);
    }
    body.push_str("],\"schemaVersion\":");
    body.push_str(&schema_version.to_string());
    body.push('}');
    body
}

/// gzip at the strongest level, with no time or name in the header.
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

/// The wait after `failures` failures in a row before this one: 5 s, doubling with each, at most
/// `BACKOFF_MAX_SECONDS`. The one rule for every back-off: the sender's, and the run loop's after a tick that failed.
pub fn backoff_seconds(failures: u32) -> u64 {
    BACKOFF_FIRST_SECONDS
        .saturating_mul(1u64 << failures.min(16))
        .min(BACKOFF_MAX_SECONDS)
}

/// Whole seconds, rounded up.
fn ceil_seconds(ms: i64) -> u64 {
    u64::try_from(ms.saturating_add(MS_PER_SECOND - 1) / MS_PER_SECOND).unwrap_or(0)
}

/// `Retry-After` as seconds or as an HTTP date, between 1 s and `MAX_WAIT_SECONDS`; 5 s when it is neither.
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
/// `https` only; plain `http` is for a service on this very machine (development, tests), named by `127.0.0.1` or
/// `[::1]`, and nothing else. No path
/// (beyond a single `/`), query, fragment or credentials: the request path is part of what is signed, and a prefix
/// check on the text would accept `http://127.0.0.1.evil.example`. The scheme and the host are compared and returned
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
        return Err(OriginError("must be https (http only for 127.0.0.1 or [::1])"));
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

/// The HTTP client: one origin, no redirects, no proxy from the environment, `timeout` for the whole request.
fn http_agent(timeout: Duration) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        // An answer that points elsewhere is an answer, not an instruction. With 0 the 3xx itself is returned.
        .max_redirects(0)
        // Config::default() reads HTTP(S)_PROXY and ALL_PROXY from the environment; this hub talks to one origin.
        .proxy(None)
        // 4xx and 5xx are answers the protocol defines, read like any other.
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
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
    ureq::Agent::with_parts(config, DefaultConnector::new(), NameResolver::default())
}

/// ureq's own resolver, with every failure to resolve said the same way (`HostNotFound`): a name that does not
/// resolve otherwise arrives as an `Io` error indistinguishable by kind from a socket's (std reports `getaddrinfo`
/// failures with an uncategorised kind). It resolves in a short-lived thread of ureq's, one per request.
#[derive(Debug, Default)]
struct NameResolver(DefaultResolver);

impl Resolver for NameResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        self.0
            .resolve(uri, config, timeout)
            .map_err(|_| ureq::Error::HostNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_timeout_once_the_body_started_to_go_out_halves_the_batch() {
        use ureq::Timeout;
        let halves = |error: ureq::Error| timed_out_after_sending(&error);
        // Nothing of the batch was sent.
        for phase in [Timeout::Resolve, Timeout::Connect, Timeout::SendRequest] {
            assert!(!halves(ureq::Error::Timeout(phase)), "{phase:?}");
        }
        // The body was going out, or the answer was awaited or read.
        for phase in [Timeout::SendBody, Timeout::RecvResponse, Timeout::RecvBody] {
            assert!(halves(ureq::Error::Timeout(phase)), "{phase:?}");
        }
        // The overall limit and a socket's own timeout do not say in which phase: as if the body had started.
        for phase in [Timeout::Global, Timeout::PerCall, Timeout::PerRead, Timeout::PerWrite] {
            assert!(halves(ureq::Error::Timeout(phase)), "{phase:?}");
        }
        assert!(halves(ureq::Error::Io(io::Error::from(io::ErrorKind::TimedOut))));
        // No timeout at all.
        assert!(!halves(ureq::Error::HostNotFound));
        assert!(!halves(ureq::Error::Io(io::Error::from(
            io::ErrorKind::ConnectionRefused
        ))));
    }

    #[test]
    fn a_batch_grows_back_by_a_quarter_and_at_least_one_up_to_the_limit() {
        assert_eq!(grown(1), 2);
        assert_eq!(grown(3), 4);
        assert_eq!(grown(250), 312);
        assert_eq!(grown(487), MAX_EVENTS);
        assert_eq!(grown(MAX_EVENTS), MAX_EVENTS);
    }
}
