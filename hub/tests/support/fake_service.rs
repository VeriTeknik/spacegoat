// SPDX-License-Identifier: AGPL-3.0-or-later
//! A hub service for tests: it checks what the real one checks (spec/protocol.md) and nothing is mocked in between.
//!
//! A real HTTP/1.1 server on a loopback socket, with its request parsing written out here (no server crate), so the
//! sender is tested against bytes on a wire. It verifies the request signature against the registered public key
//! before it looks at anything else,
//! the timestamp window, the gzip body and its limits, every event signature, the personal-data commitment and that its
//! nonce was never used by another event, the age
//! of each observation, the sequence, the reset rule and the gap rule wherever the event sits in the batch, and on a
//! replay the whole event against the one on record. Every fresh event must also have the form protocol §6 to §9
//! give its kind (`has_the_protocols_shape`): exactly its attributes and no other, each of its type and format,
//! references that are UUID version 4, enums from their lists, and personal data only in the kinds that may carry
//! it. Anything else is answered `400 {"error":"schema"}`, so a wrong field in the agent fails a test. It answers
//! with the protocol's bodies.
//!
//! A test can script the next answers to stand for a service that is down, busy, whose answer was lost on the way
//! back, or that sends no `Date`. It records every request and every event it accepted, so a test asserts on what
//! actually arrived.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Value, json};
use spacegoat_hub::canonical::canonical_json;
use spacegoat_hub::clock::{self, Clock};
use spacegoat_hub::signing::{self, EventFields};

pub const PATH: &str = "/api/ops/evidence/ingest";
const MAX_COMPRESSED: usize = 512 * 1024;
const MAX_UNCOMPRESSED: u64 = 4 * 1024 * 1024;
/// The service keeps the distance between observation and receipt in a signed 32-bit millisecond field.
const MAX_AGE_MS: i64 = (1 << 31) - 1;
const TIMESTAMP_WINDOW_SECONDS: i64 = 300;
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// A body larger than this is not even read: it is far past the compressed limit.
const MAX_READ_BODY: usize = 2 * MAX_COMPRESSED;

/// A clock in Unix milliseconds that both sides of a test can share.
pub type ServiceClock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// A wall clock (the system clock plus an offset a test moves) and a monotonic clock that moves ONLY when a test
/// moves it, shared by every clone. `advance_seconds` is time passing (both move); `step_wall_seconds` and
/// `set_offset_seconds` are the wall clock being set (only it moves); `advance_mono_seconds` is time passing for the
/// hub alone. Because the monotonic clock does not follow real time, an interval in a test is exactly what the test
/// says it is.
#[derive(Clone)]
pub struct TestClock {
    offset_ms: Arc<AtomicI64>,
    mono_ms: Arc<AtomicI64>,
}

impl Default for TestClock {
    fn default() -> Self {
        Self {
            offset_ms: Arc::new(AtomicI64::new(0)),
            // An arbitrary start: only differences mean anything.
            mono_ms: Arc::new(AtomicI64::new(1_000_000)),
        }
    }
}

impl TestClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// A clock whose wall reads `unix_millis` now (and moves on from there with real time).
    pub fn at_wall(unix_millis: i64) -> Self {
        let clock = Self::new();
        clock
            .offset_ms
            .store(unix_millis - clock::now().unwrap(), Ordering::SeqCst);
        clock
    }

    /// The wall clock.
    pub fn now(&self) -> i64 {
        clock::now().unwrap() + self.offset_ms.load(Ordering::SeqCst)
    }

    pub fn mono(&self) -> i64 {
        self.mono_ms.load(Ordering::SeqCst)
    }

    /// Time passes: both clocks move.
    pub fn advance_seconds(&self, seconds: i64) {
        self.offset_ms.fetch_add(seconds * 1000, Ordering::SeqCst);
        self.mono_ms.fetch_add(seconds * 1000, Ordering::SeqCst);
    }

    pub fn advance_millis(&self, millis: i64) {
        self.offset_ms.fetch_add(millis, Ordering::SeqCst);
        self.mono_ms.fetch_add(millis, Ordering::SeqCst);
    }

    /// The wall clock is stepped (set by a person, NTP, an RTC); the monotonic clock does not notice.
    pub fn step_wall_seconds(&self, seconds: i64) {
        self.offset_ms.fetch_add(seconds * 1000, Ordering::SeqCst);
    }

    /// The wall clock is set to the system clock plus `seconds`; the monotonic clock does not notice.
    pub fn set_offset_seconds(&self, seconds: i64) {
        self.offset_ms.store(seconds * 1000, Ordering::SeqCst);
    }

    /// Only the monotonic clock moves (for a clock that only some side reads monotonically).
    pub fn advance_mono_seconds(&self, seconds: i64) {
        self.mono_ms.fetch_add(seconds * 1000, Ordering::SeqCst);
    }

    /// The wall clock, for the service.
    pub fn as_fn(&self) -> ServiceClock {
        let clock = self.clone();
        Arc::new(move || clock.now())
    }

    /// Both clocks, for the hub.
    pub fn as_clock(&self) -> Arc<dyn Clock> {
        Arc::new(self.clone())
    }
}

impl Clock for TestClock {
    fn wall_millis(&self) -> i64 {
        self.now()
    }

    fn mono_millis(&self) -> i64 {
        self.mono()
    }
}

/// One scripted answer; each is consumed by one request.
#[derive(Debug, Clone)]
pub enum Step {
    /// Answer with this status, JSON body and extra headers, without looking at the request. A `Date` among the
    /// headers replaces the one the service would send.
    Status {
        code: u16,
        body: Value,
        headers: Vec<(String, String)>,
    },
    /// Like `Status`, but the answer carries no `Date` header at all.
    StatusWithoutDate { code: u16, body: Value },
    /// Process the request as the service would (a placeholder that lets a later step reach a later request).
    Pass,
    /// Process the batch for real, then drop the connection before answering.
    LoseAnswer,
    /// Process the batch for real, then wait this long before answering (a request still in flight, e.g. while the
    /// hub is killed, or one the hub gives up on). Later requests are served meanwhile.
    Delay(Duration),
    /// Answer 413 above this many events (for this one request).
    MaxEvents(usize),
    /// A 200 whose body stops half way (`Content-Length` promises more), then the connection closes.
    Truncate,
    /// The same for a 503.
    TruncateError,
    /// These bytes are the whole answer, then the connection closes. For answers no well-behaved server writes
    /// (not HTTP at all, a body that cannot be decoded, a page from something in between).
    Raw(Vec<u8>),
}

impl Step {
    pub fn status(code: u16, body: Value) -> Self {
        Self::Status {
            code,
            body,
            headers: Vec::new(),
        }
    }

    /// An answer with no `Date` header (a proxy, or a service that forgot it).
    pub fn without_date(code: u16, body: Value) -> Self {
        Self::StatusWithoutDate { code, body }
    }

    pub fn status_with(code: u16, body: Value, headers: &[(&str, &str)]) -> Self {
        Self::Status {
            code,
            body,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }
}

/// What one request looked like when it arrived.
#[derive(Debug, Clone)]
pub struct Record {
    pub method: String,
    pub path: String,
    /// Header names as sent; look them up with `header`.
    pub headers: Vec<(String, String)>,
    /// The body's length on the wire.
    pub bytes: usize,
    /// The sequence numbers in the batch, once the request was found authentic and its body readable.
    pub events: Option<Vec<u64>>,
    /// The body as opened (gunzipped), once the request was found authentic.
    pub plain: Option<Vec<u8>>,
}

impl Record {
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
}

struct State {
    source_id: String,
    key_id: String,
    public_key: VerifyingKey,
    last_seq: u64,
    accepted: Vec<Value>,
    /// What is on record, by sequence number: the canonical text of the event. A replay is compared with it, never
    /// taken on trust.
    stored: HashMap<u64, String>,
    /// Every personal-data nonce of an accepted event: a nonce is fresh for each event (protocol §6).
    nonces: HashSet<String>,
    requests: Vec<Record>,
    script: VecDeque<Step>,
    max_events: usize,
    now: ServiceClock,
}

pub struct FakeService {
    pub base_url: String,
    address: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeService {
    pub fn new(source_id: &str, key_id: &str, public_key: VerifyingKey) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            source_id: source_id.to_owned(),
            key_id: key_id.to_owned(),
            public_key,
            last_seq: 0,
            accepted: Vec::new(),
            stored: HashMap::new(),
            nonces: HashSet::new(),
            requests: Vec::new(),
            script: VecDeque::new(),
            max_events: 500,
            now: Arc::new(|| clock::now().unwrap()),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (state, stop) = (Arc::clone(&state), Arc::clone(&stop));
            std::thread::spawn(move || {
                for connection in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = connection {
                        serve(&state, stream);
                    }
                }
            })
        };
        Self {
            base_url: format!("http://{address}"),
            address,
            state,
            stop,
            thread: Some(thread),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// The service's clock; a test that moves the hub's clock moves this one with it.
    pub fn set_now(&self, now: ServiceClock) {
        self.state().now = now;
    }

    pub fn push(&self, step: Step) {
        self.state().script.push_back(step);
    }

    /// Forget the answers scripted and not used yet: the service is simply itself again.
    pub fn clear_script(&self) {
        self.state().script.clear();
    }

    pub fn last_seq(&self) -> u64 {
        self.state().last_seq
    }

    /// A service with a history this hub does not have (as after a lost queue).
    pub fn set_last_seq(&self, last_seq: u64) {
        self.state().last_seq = last_seq;
    }

    pub fn accepted(&self) -> Vec<Value> {
        self.state().accepted.clone()
    }

    pub fn accepted_seqs(&self) -> Vec<u64> {
        self.state()
            .accepted
            .iter()
            .map(|event| event["sourceSeq"].as_u64().unwrap())
            .collect()
    }

    pub fn requests(&self) -> Vec<Record> {
        self.state().requests.clone()
    }
}

impl Drop for FakeService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// One request read off the wire, or nothing if it was not one.
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        if buffer.len() > MAX_HEAD_BYTES {
            return None;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buffer[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let (method, path, version) = (request_line.next()?, request_line.next()?, request_line.next()?);
    if request_line.next().is_some() || version != "HTTP/1.1" {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || name.contains(|c: char| c.is_ascii_whitespace()) {
            return None;
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    // Only a body with a length: the sender never streams, and a chunked body is refused rather than parsed.
    if header(&headers, "Transfer-Encoding").is_some() {
        return None;
    }
    let lengths: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .map(|(_, v)| v.as_str())
        .collect();
    let length: usize = match lengths.as_slice() {
        [] => 0,
        [one] if !one.is_empty() && one.bytes().all(|b| b.is_ascii_digit()) => one.parse().ok()?,
        _ => return None,
    };
    if length > MAX_READ_BODY {
        return None;
    }
    let mut body = buffer[head_end + 4..].to_vec();
    if body.len() > length {
        return None;
    }
    let missing = length - body.len();
    let mut rest = vec![0u8; missing];
    stream.read_exact(&mut rest).ok()?;
    body.extend_from_slice(&rest);
    Some(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
        body,
    })
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        409 => "Conflict",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// `Tue, 24 Nov 2026 10:00:00 GMT` for a moment in Unix milliseconds.
pub fn http_date(unix_millis: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let text = clock::observed_at_text(unix_millis).unwrap();
    let weekday = WEEKDAYS[unix_millis.div_euclid(86_400_000).rem_euclid(7) as usize];
    let month: usize = text[5..7].parse().unwrap();
    format!(
        "{weekday}, {} {} {} {} GMT",
        &text[8..10],
        MONTHS[month - 1],
        &text[0..4],
        &text[11..19]
    )
}

fn write_answer(stream: &mut TcpStream, now: i64, code: u16, body: &Value, headers: &[(String, String)], date: bool) {
    let payload = serde_json::to_vec(body).unwrap();
    let mut head = format!("HTTP/1.1 {code} {}\r\n", reason(code));
    if date && header(headers, "Date").is_none() {
        head.push_str(&format!("Date: {}\r\n", http_date(now)));
    }
    head.push_str(&format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        payload.len()
    ));
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    // The client may hang up early (an answer larger than it reads); that is not the service's failure.
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&payload);
    let _ = stream.flush();
}

/// What the service does with one request: an answer, or a connection dropped without one.
enum Outcome {
    Answer(u16, Value, Vec<(String, String)>),
    AnswerWithoutDate(u16, Value),
    Drop,
    Raw(Vec<u8>),
    Late(Duration, Value),
}

fn serve(state: &Arc<Mutex<State>>, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let Some(request) = read_request(&mut stream) else {
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    };
    let (outcome, now) = {
        let mut state = state.lock().unwrap();
        let now = (state.now)();
        (handle(&mut state, &request, now), now)
    };
    match outcome {
        Outcome::Answer(code, body, headers) => write_answer(&mut stream, now, code, &body, &headers, true),
        Outcome::AnswerWithoutDate(code, body) => write_answer(&mut stream, now, code, &body, &[], false),
        Outcome::Raw(bytes) => {
            let _ = stream.write_all(&bytes);
        }
        Outcome::Late(pause, body) => {
            // Answered from a thread of its own, so the service takes the next request meanwhile (a client that gave
            // up on this answer sends again at once).
            std::thread::spawn(move || {
                std::thread::sleep(pause);
                write_answer(&mut stream, now, 200, &body, &[], true);
                let _ = stream.shutdown(Shutdown::Both);
            });
            return;
        }
        Outcome::Drop => {}
    }
    let _ = stream.shutdown(Shutdown::Both);
}

fn error(code: u16, body: Value) -> Outcome {
    Outcome::Answer(code, body, Vec::new())
}

fn schema() -> Outcome {
    error(400, json!({"error": "schema"}))
}

fn handle(state: &mut State, request: &Request, now: i64) -> Outcome {
    state.requests.push(Record {
        method: request.method.clone(),
        path: request.path.clone(),
        headers: request.headers.clone(),
        bytes: request.body.len(),
        events: None,
        plain: None,
    });
    let step = state.script.pop_front();
    match &step {
        Some(Step::TruncateError) => {
            return Outcome::Raw(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 500\r\n\r\n{\"error\": \"unav".to_vec(),
            );
        }
        Some(Step::Truncate) => {
            return Outcome::Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{\"accepted\": 1".to_vec());
        }
        Some(Step::Raw(bytes)) => return Outcome::Raw(bytes.clone()),
        Some(Step::Status { code, body, headers }) => return Outcome::Answer(*code, body.clone(), headers.clone()),
        Some(Step::StatusWithoutDate { code, body }) => return Outcome::AnswerWithoutDate(*code, body.clone()),
        _ => {}
    }
    // Whoever is not a registered hub learns nothing about what else is wrong with the request (protocol §1: the
    // service refuses every request that is not signed by a key it has on record).
    if !authentic(state, request, now) {
        return error(401, json!({"error": "unauthorized"}));
    }
    let headers = &request.headers;
    let well_formed = request.method == "POST"
        && request.path == PATH
        && header(headers, "Content-Encoding") == Some("gzip")
        && header(headers, "Origin").is_none()
        && header(headers, "Content-Type") == Some("application/json");
    if !well_formed {
        return schema();
    }
    if request.body.len() > MAX_COMPRESSED {
        return error(413, json!({"error": "too_large"}));
    }
    let plain = match gunzip(&request.body) {
        Gunzip::Plain(plain) => plain,
        Gunzip::TooLarge => return error(413, json!({"error": "too_large"})),
        Gunzip::Invalid => return schema(),
    };
    if let Some(record) = state.requests.last_mut() {
        record.plain = Some(plain.clone());
    }
    let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&plain) else {
        return schema();
    };
    let Some(Value::Array(events)) = body.get("events") else {
        return schema();
    };
    let mut seqs = Vec::with_capacity(events.len());
    for event in events {
        match event.get("sourceSeq").and_then(Value::as_u64) {
            Some(seq) if event.is_object() => seqs.push(seq),
            _ => return schema(),
        }
    }
    if let Some(record) = state.requests.last_mut() {
        record.events = Some(seqs.clone());
    }
    let limit = match step {
        Some(Step::MaxEvents(n)) => n,
        _ => state.max_events,
    };
    if events.len() > limit {
        return error(413, json!({"error": "too_large"}));
    }
    if body.get("schemaVersion") != Some(&json!(1)) {
        return schema();
    }
    let last_seq = state.last_seq;
    for (event, seq) in events.iter().zip(&seqs) {
        // A sequence number already on record must be the very event on record: the whole event, not only its
        // signature (a changed event under a reused signature is a conflict too).
        if *seq <= last_seq && state.stored.get(seq) != canonical_json(event).ok().as_ref() {
            return error(409, json!({"error": "replay_conflict", "sourceSeq": seq}));
        }
    }
    let fresh: Vec<(&Value, u64)> = events
        .iter()
        .zip(seqs.iter().copied())
        .filter(|(_, seq)| *seq > last_seq)
        .collect();
    let duplicates = events.len() - fresh.len();
    // `held` is what the service holds when it reaches each fresh event: the reset rule and the sequence are judged
    // against it, wherever in the batch the event sits.
    let mut held = last_seq;
    let mut nonces = HashSet::new();
    for (index, (event, seq)) in fresh.iter().enumerate() {
        let kind = event.get("kind").and_then(Value::as_str);
        let attributes = event.get("attributes");
        let number = |name: &str| attributes.and_then(|a| a.get(name)).and_then(Value::as_u64);
        if kind == Some("site_source.reset") && number("lastAckedSeq") != Some(held) {
            return schema();
        }
        // A gap declared from the next number on carries the number just after the gap (protocol §8).
        let declares_gap = kind == Some("site_source.gap_declared") && number("fromSeq") == Some(held + 1);
        if declares_gap {
            let to = number("toSeq");
            if to.is_none_or(|to| to < held + 1 || to.checked_add(1) != Some(*seq)) {
                return schema();
            }
        } else if *seq != held + 1 {
            return if index == 0 {
                error(409, json!({"error": "seq_gap", "expectedSeq": held + 1}))
            } else {
                schema()
            };
        }
        if !has_the_protocols_shape(event) || !event_is_valid(state, event, *seq, now) {
            return schema();
        }
        if let Some(nonce) = event.get("piiNonce").and_then(Value::as_str)
            && (state.nonces.contains(nonce) || !nonces.insert(nonce.to_owned()))
        {
            return schema();
        }
        held = *seq;
    }
    state.nonces.extend(nonces);
    for (event, seq) in &fresh {
        state.accepted.push((*event).clone());
        state.stored.insert(*seq, canonical_json(event).unwrap());
    }
    if let Some((_, seq)) = fresh.last() {
        state.last_seq = *seq;
    }
    let answer = json!({"accepted": fresh.len(), "duplicates": duplicates, "lastSeq": state.last_seq});
    match step {
        Some(Step::LoseAnswer) => Outcome::Drop,
        Some(Step::Delay(pause)) => Outcome::Late(pause, answer),
        _ => error(200, answer),
    }
}

/// The request signature, made with the registered key, over this principal, endpoint, moment and exact body.
fn authentic(state: &State, request: &Request, now: i64) -> bool {
    let headers = &request.headers;
    let principal = header(headers, "X-VT-Principal").unwrap_or("");
    let timestamp = header(headers, "X-VT-Timestamp").unwrap_or("");
    if principal != format!("source:{}", state.source_id) || header(headers, "X-VT-Key-Id") != Some(&state.key_id) {
        return false;
    }
    if timestamp.len() != 10 || !timestamp.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(seconds) = timestamp.parse::<i64>() else {
        return false;
    };
    if (now.div_euclid(1000) - seconds).abs() > TIMESTAMP_WINDOW_SECONDS {
        return false;
    }
    let message = signing::request_signing_message(principal, "POST", &request.path, timestamp, &request.body);
    verify(
        &state.public_key,
        header(headers, "X-VT-Signature").unwrap_or(""),
        &message,
    )
}

fn verify(key: &VerifyingKey, signature: &str, message: &[u8]) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

enum Gunzip {
    Plain(Vec<u8>),
    TooLarge,
    Invalid,
}

/// The body opened, never past the uncompressed limit.
fn gunzip(body: &[u8]) -> Gunzip {
    let mut plain = Vec::new();
    let decoder = flate2::read::GzDecoder::new(body);
    match decoder.take(MAX_UNCOMPRESSED + 1).read_to_end(&mut plain) {
        Ok(_) if plain.len() as u64 > MAX_UNCOMPRESSED => Gunzip::TooLarge,
        Ok(_) => Gunzip::Plain(plain),
        Err(_) => Gunzip::Invalid,
    }
}

/// One fresh event: its signature by the registered key, its time, its origin and its personal-data commitment.
fn event_is_valid(state: &State, event: &Value, seq: u64, now: i64) -> bool {
    let (Some(kind), Some(observed_at), Some(attributes), Some(signature)) = (
        event.get("kind").and_then(Value::as_str),
        event.get("observedAt").and_then(Value::as_str),
        event.get("attributes").filter(|a| a.is_object()),
        event.get("signature").and_then(Value::as_str),
    ) else {
        return false;
    };
    if attributes.get("trustOrigin").and_then(Value::as_str) != Some("hub") {
        return false;
    }
    let mut parts = signature.split(':');
    let (Some(scheme), Some(key_id), Some(signature), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if scheme != "ed25519" || key_id != state.key_id {
        return false;
    }
    let Some(observed) = clock::observed_at_millis(observed_at) else {
        return false;
    };
    if (now - observed).abs() > MAX_AGE_MS {
        return false;
    }
    // Personal data travels with its nonce and its commitment: all three or none.
    let pii = (event.get("pii"), event.get("piiNonce"), event.get("piiCommitment"));
    let commitment = match pii {
        (None, None, None) => None,
        (Some(pii), Some(Value::String(nonce)), Some(Value::String(commitment))) if pii.is_object() => {
            match signing::pii_commitment(nonce, pii) {
                Ok(computed) if computed == *commitment => Some(commitment.as_str()),
                _ => return false,
            }
        }
        _ => return false,
    };
    let Ok(message) = signing::event_signing_message(&EventFields {
        source_id: &state.source_id,
        source_seq: seq,
        kind,
        observed_at,
        attributes,
        pii_commitment: commitment,
    }) else {
        return false;
    };
    verify(&state.public_key, signature, &message)
}

/// The kinds of protocol §8 and §9 and the attributes each carries, exactly (`fromTime` of `input_lost` is optional
/// and listed apart).
const KINDS: [(&str, &[&str]); 9] = [
    (
        "site.device_appeared",
        &["trustOrigin", "deviceRef", "segmentRef", "deviceClass"],
    ),
    (
        "site.device_changed",
        &["trustOrigin", "deviceRef", "segmentRef", "deviceClass", "changed"],
    ),
    ("site.device_seen", &["trustOrigin", "deviceRef", "segmentRef"]),
    (
        "site.device_gone",
        &["trustOrigin", "deviceRef", "segmentRef", "lastSeenAt"],
    ),
    (
        "site.inventory_snapshot",
        &["trustOrigin", "segmentRef", "counts", "ephemeral"],
    ),
    (
        "site_source.gap_declared",
        &["trustOrigin", "fromSeq", "toSeq", "reason"],
    ),
    ("site_source.reset", &["trustOrigin", "lastAckedSeq", "reason"]),
    ("site_source.input_lost", &["trustOrigin", "reason", "toTime"]),
    ("site_source.event_dropped", &["trustOrigin", "reason", "originalKind"]),
];
/// The only kinds that may carry personal data, and the fields it may have (protocol §6, §9).
const PII_KINDS: [&str; 2] = ["site.device_appeared", "site.device_changed"];
const PII_FIELDS: [&str; 3] = ["mac", "hostname", "ip"];
const CLASSES: [&str; 7] = ["ot", "printer", "user_device", "server", "network", "iot", "unknown"];
const EVENT_FIELDS: [&str; 8] = [
    "sourceSeq",
    "kind",
    "observedAt",
    "attributes",
    "signature",
    "pii",
    "piiNonce",
    "piiCommitment",
];
const MAX_SAFE: u64 = (1 << 53) - 1;
const NINETY_DAYS_MS: i64 = 90 * 86_400_000;

/// A random (version 4) UUID, lowercase, with the RFC 9562 variant: the only references the service takes.
pub fn is_uuid_v4(value: &Value) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            14 => *b == b'4',
            19 => matches!(b, b'8' | b'9' | b'a' | b'b'),
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        })
}

fn is_lower_hex(value: Option<&Value>, length: usize) -> bool {
    value.and_then(Value::as_str).is_some_and(|text| {
        text.len() == length && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn safe_integer(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64).filter(|n| *n <= MAX_SAFE)
}

fn time_of(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_str).and_then(clock::observed_at_millis)
}

/// Everything protocol §6 to §9 says about an event's form, apart from its signature and its place in the sequence:
/// no unknown field at the top or in the attributes, every attribute of its kind present with its type and format,
/// enums from their lists, and personal data only where the kind allows it, in the allowed fields and forms.
pub fn has_the_protocols_shape(event: &Value) -> bool {
    let Some(fields) = event.as_object() else {
        return false;
    };
    if fields.keys().any(|key| !EVENT_FIELDS.contains(&key.as_str())) {
        return false;
    }
    if safe_integer(fields.get("sourceSeq")).is_none_or(|seq| seq == 0) {
        return false;
    }
    let (Some(kind), Some(observed_at), Some(Value::Object(attributes)), Some(Value::String(_))) = (
        fields.get("kind").and_then(Value::as_str),
        time_of(fields.get("observedAt")),
        fields.get("attributes"),
        fields.get("signature"),
    ) else {
        return false;
    };
    let Some((_, required)) = KINDS.iter().find(|(name, _)| *name == kind) else {
        return false;
    };
    let optional: &[&str] = if kind == "site_source.input_lost" {
        &["fromTime"]
    } else {
        &[]
    };
    let keys_fit = required.iter().all(|key| attributes.contains_key(*key))
        && attributes
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()));
    if !keys_fit || attributes.get("trustOrigin") != Some(&json!("hub")) {
        return false;
    }
    let get = |name: &str| attributes.get(name);
    let text = |name: &str| get(name).and_then(Value::as_str);
    let refs_ok = ["deviceRef", "segmentRef"]
        .iter()
        .filter(|name| required.contains(name))
        .all(|name| get(name).is_some_and(is_uuid_v4));
    let class_ok = !required.contains(&"deviceClass") || text("deviceClass").is_some_and(|c| CLASSES.contains(&c));
    let kind_ok = match kind {
        "site.device_changed" => match get("changed").and_then(Value::as_array) {
            Some(changed) if !changed.is_empty() => {
                let names: Vec<Option<&str>> = changed.iter().map(Value::as_str).collect();
                let distinct: std::collections::HashSet<&Option<&str>> = names.iter().collect();
                distinct.len() == names.len()
                    && names
                        .iter()
                        .all(|name| name.is_some_and(|name| ["class", "name", "address"].contains(&name)))
            }
            _ => false,
        },
        "site.device_gone" => {
            time_of(get("lastSeenAt")).is_some_and(|last| last <= observed_at && observed_at - last <= NINETY_DAYS_MS)
        }
        "site.inventory_snapshot" => {
            let counts_ok = match get("counts") {
                Some(Value::Object(counts)) => {
                    counts.len() == CLASSES.len()
                        && CLASSES.iter().all(|class| safe_integer(counts.get(*class)).is_some())
                }
                _ => false,
            };
            counts_ok && safe_integer(get("ephemeral")).is_some()
        }
        "site_source.gap_declared" => {
            let (from, to) = (safe_integer(get("fromSeq")), safe_integer(get("toSeq")));
            text("reason") == Some("operator") && from.is_some_and(|from| from >= 1 && to.is_some_and(|to| from <= to))
        }
        "site_source.reset" => {
            safe_integer(get("lastAckedSeq")).is_some()
                && text("reason").is_some_and(|reason| ["queue_lost", "reinstall"].contains(&reason))
        }
        "site_source.input_lost" => {
            let to = time_of(get("toTime"));
            let from_ok = match get("fromTime") {
                None => true,
                Some(from) => time_of(Some(from)).is_some_and(|from| to.is_some_and(|to| from <= to)),
            };
            to.is_some()
                && from_ok
                && text("reason").is_some_and(|reason| ["capture_stopped", "capture_unreadable"].contains(&reason))
        }
        "site_source.event_dropped" => {
            text("reason") == Some("operator") && text("originalKind").is_some_and(|original| !original.is_empty())
        }
        _ => true,
    };
    if !(refs_ok && class_ok && kind_ok) {
        return false;
    }
    match (fields.get("pii"), fields.get("piiNonce"), fields.get("piiCommitment")) {
        (None, None, None) => true,
        (Some(Value::Object(pii)), nonce, commitment) => {
            PII_KINDS.contains(&kind)
                && !pii.is_empty()
                && is_lower_hex(nonce, 64)
                && is_lower_hex(commitment, 64)
                && pii.iter().all(|(name, value)| match (name.as_str(), value.as_str()) {
                    ("mac", Some(mac)) => is_lower_hex(Some(value), 12) && mac.len() == 12,
                    ("hostname", Some(hostname)) => (1..=253).contains(&hostname.chars().count()),
                    ("ip", Some(ip)) => ip.parse::<std::net::IpAddr>().is_ok(),
                    _ => false,
                })
                && pii.keys().all(|name| PII_FIELDS.contains(&name.as_str()))
        }
        _ => false,
    }
}
