// SPDX-License-Identifier: AGPL-3.0-or-later
//! The agent: observe, turn what changed into events, deliver them. One `tick()` does one round of each.
//!
//! The agent holds no network logic of its own. An `Observer` says what is on the network now; the agent compares
//! that with what it last reported and writes only the difference to the outbox:
//!
//! - a device it has not announced yet: `site.device_appeared`;
//! - a device whose class, name or address differs from what it last reported: `site.device_changed`;
//! - a device that is still there and unchanged: `site.device_seen`, at most once a day;
//! - once an hour per segment: `site.inventory_snapshot`, the counts per class.
//!
//! What it guarantees:
//! - personal data (hardware address, name, IP) goes into the event's separate personal-data part and nowhere else:
//!   not into the attributes, not into `agent.json`, not into `status()`, not into an error;
//! - whatever an observer hands over is checked before it is signed: a signed event never changes, so one the service
//!   would refuse would block the whole queue behind it. A field that does not fit is left out;
//! - before it produces anything, the agent says hello (one request; empty unless events wait). The answer gives the
//!   service's clock and where the service stands in the sequence. While the hub's clock is not set, or is more than
//!   four minutes from the service's, nothing is produced: an event signed with a wrong time cannot be taken back.
//!   A hub that finds its own queue empty while the service holds a history declares it (`site_source.reset`, at the
//!   number the service gave: `queue_lost` if it remembers having been confirmed, `reinstall` if not); it never
//!   starts over as if nothing had happened;
//! - one agent runs on one state directory (a second one would hand out a second set of references and write into
//!   the same sequence): it holds an exclusive lock on `agent.lock` while it runs, and a second agent refuses to
//!   start. The kernel drops the lock when the process ends, however it ends;
//! - a halted agent makes no request and produces no event: a queue that grows while nothing can be delivered only
//!   makes the eventual backlog older than the service will accept;
//! - the clock is injected and `tick` never sleeps; `run` sleeps through an injected function.
//!
//! The rule for devices whose identity keeps changing (protocol §9, the seven days) belongs to the real observers
//! and is not in this version; the simulated network has only devices with lasting addresses.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Map, Value};

use crate::clock;
use crate::config::Config;
use crate::fsutil::{open_regular, private_file, write_atomic};
use crate::keystore::{FileKeyStore, KeyStoreError};
use crate::outbox::{Outbox, OutboxError, ResetReason};
use crate::sender::{OriginError, Problem, SendOutcome, Sender, SenderError};
use crate::state::{Confirmed, Pseudonyms, StateError};

pub const DEVICE_CLASSES: [&str; 7] = ["ot", "printer", "user_device", "server", "network", "iot", "unknown"];
pub const SEEN_EVERY_MS: i64 = 24 * 3_600 * 1_000;
pub const SNAPSHOT_EVERY_MS: i64 = 3_600 * 1_000;
/// How many requests one tick may make: enough to drain a backlog in steps, never a busy loop.
pub const SENDS_PER_TICK: usize = 8;
/// The service refuses a request whose time is more than 300 seconds off; stay well inside.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 240;
/// Seconds between ticks in `run`.
pub const TICK_SECONDS: u64 = 15;
/// How often `run` looks at the stop flag while it waits.
const STOP_POLL: Duration = Duration::from_millis(100);
/// `agent.json` is two short fields; anything larger is not one, and is not read whole.
const MAX_STATUS_FILE: u64 = 64 * 1024;

pub const KEY_FILE: &str = "hub.key";
pub const OUTBOX_FILE: &str = "outbox.sqlite";
pub const PSEUDONYMS_FILE: &str = "pseudonyms.sqlite";
pub const CONFIRMED_FILE: &str = "confirmed.json";
pub const STATUS_FILE: &str = "agent.json";
pub const LOCK_FILE: &str = "agent.lock";

/// The agent's clock, in Unix milliseconds. Shared with the sender.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// One device as an observer sees it at one moment. `identity` and `segment` are local to the hub (how it recognises
/// a device and a network) and are never reported; the service sees only their random references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    pub identity: String,
    pub segment: String,
    pub device_class: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
}

/// What is on the network right now. A real listener implements this; so does the simulation.
pub trait Observer {
    fn poll(&mut self) -> Vec<Sighting>;
}

/// Why the agent is waiting although it is not halted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitingFor {
    /// The hub's clock is not set, or is too far from the service's.
    Clock,
    /// `401`: an unknown key, or a clock more than five minutes off.
    Unauthorized,
    /// The service has not answered yet.
    Service,
}

impl WaitingFor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clock => "clock",
            Self::Unauthorized => "unauthorized",
            Self::Service => "service",
        }
    }
}

#[derive(Debug)]
pub enum AgentError {
    /// The state directory is missing, not a directory, or open to other users.
    StateDirectory(PathBuf, &'static str),
    /// Another agent holds the state directory's lock.
    AlreadyRunning(PathBuf),
    Key(KeyStoreError),
    Origin(OriginError),
    Outbox(OutboxError),
    State(StateError),
    Sender(SenderError),
    /// A file of the agent's own, by name, and what went wrong with it.
    Io(&'static str, io::Error),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateDirectory(path, why) => write!(f, "state directory {}: {why}", path.display()),
            Self::AlreadyRunning(path) => write!(f, "another agent is already running on {}", path.display()),
            Self::Key(error) => error.fmt(f),
            Self::Origin(error) => error.fmt(f),
            Self::Outbox(error) => error.fmt(f),
            Self::State(error) => error.fmt(f),
            Self::Sender(error) => error.fmt(f),
            Self::Io(what, error) => write!(f, "{what}: {error}"),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Key(error) => Some(error),
            Self::Origin(error) => Some(error),
            Self::Outbox(error) => Some(error),
            Self::State(error) => Some(error),
            Self::Sender(error) => Some(error),
            Self::Io(_, error) => Some(error),
            _ => None,
        }
    }
}

impl From<OutboxError> for AgentError {
    fn from(error: OutboxError) -> Self {
        Self::Outbox(error)
    }
}

impl From<StateError> for AgentError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<SenderError> for AgentError {
    fn from(error: SenderError) -> Self {
        Self::Sender(error)
    }
}

/// Where the hub stands: counts and state only. Nothing here names a device, an address or a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub source_id: String,
    pub key_id: String,
    pub last_assigned_seq: u64,
    pub last_acked_seq: u64,
    pub pending: u64,
    pub halted: Option<String>,
    pub waiting_for: Option<String>,
}

impl Status {
    /// The text `status` prints: the Python agent's `json.dumps(status, indent=2)`, key for key, in its order.
    pub fn to_json_text(&self) -> String {
        let text = |value: Option<&str>| match value {
            Some(value) => Value::from(value).to_string(),
            None => "null".to_owned(),
        };
        format!(
            "{{\n  \"sourceId\": {},\n  \"keyId\": {},\n  \"lastAssignedSeq\": {},\n  \"lastAckedSeq\": {},\n  \
             \"pending\": {},\n  \"halted\": {},\n  \"waitingFor\": {}\n}}",
            text(Some(&self.source_id)),
            text(Some(&self.key_id)),
            self.last_assigned_seq,
            self.last_acked_seq,
            self.pending,
            text(self.halted.as_deref()),
            text(self.waiting_for.as_deref()),
        )
    }
}

/// The status from its parts (the running agent's, or what `status` reads off the disk).
pub fn read_status(
    config: &Config,
    counters: (u64, u64),
    halted: Option<String>,
    waiting_for: Option<String>,
) -> Status {
    let (assigned, acked) = counters;
    Status {
        source_id: config.source_id.clone(),
        key_id: config.key_id.clone(),
        last_assigned_seq: assigned,
        last_acked_seq: acked,
        pending: assigned.saturating_sub(acked),
        halted,
        waiting_for,
    }
}

/// (halted, waitingFor) as the agent last saved them in `agent.json`; both `None` when there is no such file or it
/// does not hold a JSON object. A file that exists but cannot be read is an error, not "nothing to report".
pub fn read_saved_status(state_dir: &Path) -> io::Result<(Option<String>, Option<String>)> {
    let path = state_dir.join(STATUS_FILE);
    let file = match open_regular(&path, OpenOptions::new().read(true)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((None, None)),
        Err(error) => return Err(error),
    };
    let mut raw = Vec::new();
    file.take(MAX_STATUS_FILE).read_to_end(&mut raw)?;
    let Ok(Value::Object(saved)) = serde_json::from_slice::<Value>(&raw) else {
        return Ok((None, None));
    };
    let text = |name: &str| saved.get(name).and_then(Value::as_str).map(str::to_owned);
    Ok((text("halted"), text("waitingFor")))
}

pub struct Agent {
    config: Config,
    now: Clock,
    observer: Box<dyn Observer + Send>,
    sender: Sender,
    pseudonyms: Pseudonyms,
    confirmed: Confirmed,
    /// Held for the life of the agent; dropping it releases the lock.
    lock: File,
    waiting_for: Option<WaitingFor>,
    /// True once the service has answered this run: its clock and its place in the sequence are known.
    greeted: bool,
}

impl Agent {
    /// Open the agent on `config.state_dir`. Refuses a state directory others can enter, a missing or unreadable
    /// key, and a directory another agent is running on.
    pub fn open(config: &Config, observer: Box<dyn Observer + Send>, now: Clock) -> Result<Self, AgentError> {
        let state_dir = &config.state_dir;
        let found = std::fs::metadata(state_dir)
            .map_err(|_| AgentError::StateDirectory(state_dir.clone(), "missing or unreadable; run keygen first"))?;
        if !found.is_dir() {
            return Err(AgentError::StateDirectory(state_dir.clone(), "not a directory"));
        }
        if found.permissions().mode() & 0o077 != 0 {
            // Never changed here: it may not be this agent's to change.
            return Err(AgentError::StateDirectory(
                state_dir.clone(),
                "open to other users; use one only the hub's user can enter",
            ));
        }
        let key = FileKeyStore::new(state_dir.join(KEY_FILE))
            .load()
            .map_err(AgentError::Key)?;
        let lock = lock_state_dir(state_dir)?;
        let confirmed = Confirmed::new(state_dir.join(CONFIRMED_FILE));
        let outbox = Outbox::open(
            &state_dir.join(OUTBOX_FILE),
            &config.source_id,
            &config.key_id,
            key.clone(),
        )?;
        let pseudonyms = Pseudonyms::open(&state_dir.join(PSEUDONYMS_FILE))?;
        let sender_clock = Arc::clone(&now);
        let sender = Sender::new(
            &config.base_url,
            &config.source_id,
            &config.key_id,
            key,
            outbox,
            move || sender_clock(),
        )
        .map_err(AgentError::Origin)?;
        Ok(Self {
            config: config.clone(),
            now,
            observer,
            sender,
            pseudonyms,
            confirmed,
            lock,
            waiting_for: None,
            greeted: false,
        })
    }

    /// Close the databases and release the state directory.
    pub fn close(self) -> Result<(), AgentError> {
        let Self {
            sender,
            pseudonyms,
            lock,
            ..
        } = self;
        let outbox = sender.into_outbox().close();
        let pseudonyms = pseudonyms.close();
        drop(lock);
        outbox?;
        pseudonyms?;
        Ok(())
    }

    /// One round: observe, record the difference, deliver. Never sleeps. An `Err` is the hub's own storage failing.
    pub fn tick(&mut self) -> Result<(), AgentError> {
        let moment = (self.now)();
        let at = clock::observed_at_text(moment).filter(|_| clock::clock_is_set(moment));
        let Some(at) = at else {
            return self.note(Some(WaitingFor::Clock));
        };
        if self.sender.halted().is_some() {
            return self.save_status();
        }
        if !self.greeted && !self.greet()? {
            return self.save_status();
        }
        if self.clock_is_off() {
            // Keep asking (a heartbeat when one is due) so the skew is measured again; produce nothing meanwhile.
            self.note(Some(WaitingFor::Clock))?;
            self.sender.step()?;
            return self.save_status();
        }
        self.note(self.problem())?;
        let sightings = self.observer.poll();
        self.report(sightings, moment, &at)?;
        self.deliver()?;
        self.save_status()
    }

    /// Where the hub stands now: counts and state only.
    pub fn status(&self) -> Result<Status, AgentError> {
        let outbox = self.sender.outbox();
        let counters = (outbox.last_assigned()?, outbox.last_acked()?);
        Ok(read_status(
            &self.config,
            counters,
            self.sender.halted().map(|reason| reason.as_str().to_owned()),
            self.waiting_for.map(|waiting| waiting.as_str().to_owned()),
        ))
    }

    fn problem(&self) -> Option<WaitingFor> {
        self.sender.problem().map(|problem| match problem {
            Problem::Unauthorized => WaitingFor::Unauthorized,
        })
    }

    fn clock_is_off(&self) -> bool {
        let limit = MAX_CLOCK_SKEW_SECONDS.unsigned_abs() * 1_000;
        self.sender
            .clock_skew_millis()
            .is_some_and(|skew| skew.unsigned_abs() > limit)
    }

    /// The first exchange of a run. True once the agent may produce events.
    fn greet(&mut self) -> Result<bool, AgentError> {
        let outcome = self.sender.step()?;
        if self.clock_is_off() {
            self.note(Some(WaitingFor::Clock))?;
            return Ok(false);
        }
        match outcome {
            SendOutcome::ServiceAhead(held) => {
                // The queue this hub held is gone and the service has a history. Say so, at the number the service
                // holds; the service records it and a person is told.
                let reason = if self.confirmed.read().map_err(|e| AgentError::Io(CONFIRMED_FILE, e))? > 0 {
                    ResetReason::QueueLost
                } else {
                    ResetReason::Reinstall
                };
                let at = (self.now)();
                self.sender.outbox_mut().declare_reset(held, reason, at)?;
                self.pseudonyms.forget_facts()?;
                self.write_confirmed(held)?;
            }
            SendOutcome::Sent(_) => {}
            _ => {
                self.note(Some(self.problem().unwrap_or(WaitingFor::Service)))?;
                return Ok(false);
            }
        }
        self.write_confirmed(self.sender.outbox().last_acked()?)?;
        self.greeted = true;
        Ok(true)
    }

    fn deliver(&mut self) -> Result<(), AgentError> {
        for _ in 0..SENDS_PER_TICK {
            let outcome = self.sender.step()?;
            self.write_confirmed(self.sender.outbox().last_acked()?)?;
            let more = match outcome {
                SendOutcome::Sent(_) => !self.sender.outbox().pending(1, None)?.is_empty(),
                SendOutcome::RetryNow => true,
                _ => false,
            };
            if !more {
                break;
            }
        }
        Ok(())
    }

    fn write_confirmed(&self, last_acked_seq: u64) -> Result<(), AgentError> {
        self.confirmed
            .write(last_acked_seq)
            .map_err(|error| AgentError::Io(CONFIRMED_FILE, error))
    }

    fn report(&mut self, sightings: Vec<Sighting>, moment: i64, at: &str) -> Result<(), AgentError> {
        let mut seen = Vec::with_capacity(sightings.len());
        for sighting in sightings {
            seen.push(self.report_device(sighting, moment, at)?);
        }
        let segments: BTreeSet<&str> = seen.iter().map(|(segment, _)| segment.as_str()).collect();
        for segment in segments {
            let classes = seen.iter().filter(|(s, _)| s == segment).map(|(_, class)| *class);
            self.report_snapshot(segment, classes, moment, at)?;
        }
        Ok(())
    }

    /// Report one device if anything is due; returns its segment and its checked class (for the snapshot).
    fn report_device(
        &mut self,
        sighting: Sighting,
        moment: i64,
        at: &str,
    ) -> Result<(String, &'static str), AgentError> {
        let mut attributes = Map::new();
        attributes.insert("trustOrigin".into(), Value::from("hub"));
        attributes.insert(
            "deviceRef".into(),
            Value::from(self.pseudonyms.reference("device", &sighting.identity)?),
        );
        attributes.insert(
            "segmentRef".into(),
            Value::from(self.pseudonyms.reference("segment", &sighting.segment)?),
        );
        let known = self.pseudonyms.facts("device", &sighting.identity)?;
        let device_class = checked_class(&sighting.device_class);
        let mac = sighting.mac.as_deref().filter(|mac| is_mac(mac));
        let hostname = sighting.hostname.as_deref().filter(|name| is_hostname(name));
        let ip = sighting.ip.as_deref().and_then(normal_ip);
        let mut facts = Map::new();
        facts.insert("class".into(), Value::from(device_class));
        facts.insert("name".into(), hostname.map_or(Value::Null, Value::from));
        facts.insert("address".into(), ip.clone().map_or(Value::Null, Value::from));
        let mut pii = Map::new();
        let personal = [
            ("mac", mac.map(str::to_owned)),
            ("hostname", hostname.map(str::to_owned)),
            ("ip", ip),
        ];
        for (name, value) in personal {
            if let Some(value) = value {
                pii.insert(name.into(), Value::from(value));
            }
        }
        let pii = (!pii.is_empty()).then_some(&pii);
        let outbox = self.sender.outbox_mut();
        if known.is_empty() {
            attributes.insert("deviceClass".into(), Value::from(device_class));
            outbox.append("site.device_appeared", at, &attributes, pii)?;
        } else {
            let changed: Vec<Value> = ["class", "name", "address"]
                .into_iter()
                .filter(|name| known.get(*name).unwrap_or(&Value::Null) != facts.get(*name).unwrap_or(&Value::Null))
                .map(Value::from)
                .collect();
            let told_at = known.get("toldAt").and_then(Value::as_str).and_then(stored_millis);
            if !changed.is_empty() {
                attributes.insert("deviceClass".into(), Value::from(device_class));
                attributes.insert("changed".into(), Value::Array(changed));
                outbox.append("site.device_changed", at, &attributes, pii)?;
            } else if told_at.is_none_or(|told| moment.saturating_sub(told) >= SEEN_EVERY_MS) {
                outbox.append("site.device_seen", at, &attributes, None)?;
            } else {
                return Ok((sighting.segment, device_class));
            }
        }
        // After the event is durably in the outbox: what was reported is now what the hub last said.
        facts.insert("toldAt".into(), Value::from(stored_text(moment)));
        self.pseudonyms.remember("device", &sighting.identity, &facts)?;
        Ok((sighting.segment, device_class))
    }

    fn report_snapshot(
        &mut self,
        segment: &str,
        classes: impl Iterator<Item = &'static str>,
        moment: i64,
        at: &str,
    ) -> Result<(), AgentError> {
        let known = self.pseudonyms.facts("segment", segment)?;
        let last = known.get("snapshotAt").and_then(Value::as_str).and_then(stored_millis);
        if last.is_some_and(|last| moment.saturating_sub(last) < SNAPSHOT_EVERY_MS) {
            return Ok(());
        }
        let mut counts = Map::new();
        for name in DEVICE_CLASSES {
            counts.insert(name.into(), Value::from(0u64));
        }
        for class in classes {
            if let Some(Value::Number(count)) = counts.get(class) {
                let next = count.as_u64().unwrap_or(0).saturating_add(1);
                counts.insert(class.into(), Value::from(next));
            }
        }
        let mut attributes = Map::new();
        attributes.insert("trustOrigin".into(), Value::from("hub"));
        attributes.insert(
            "segmentRef".into(),
            Value::from(self.pseudonyms.reference("segment", segment)?),
        );
        attributes.insert("counts".into(), Value::Object(counts));
        attributes.insert("ephemeral".into(), Value::from(0u64));
        self.sender
            .outbox_mut()
            .append("site.inventory_snapshot", at, &attributes, None)?;
        let mut facts = Map::new();
        facts.insert("snapshotAt".into(), Value::from(stored_text(moment)));
        self.pseudonyms.remember("segment", segment, &facts)?;
        Ok(())
    }

    fn note(&mut self, waiting_for: Option<WaitingFor>) -> Result<(), AgentError> {
        if waiting_for != self.waiting_for {
            self.waiting_for = waiting_for;
            self.save_status()?;
        }
        Ok(())
    }

    /// `agent.json`: why the agent is halted or waiting, and nothing else.
    fn save_status(&self) -> Result<(), AgentError> {
        let text = |value: Option<&str>| value.map_or(Value::Null, Value::from).to_string();
        let saved = format!(
            "{{\"halted\": {}, \"waitingFor\": {}}}",
            text(self.sender.halted().map(|reason| reason.as_str())),
            text(self.waiting_for.map(WaitingFor::as_str)),
        );
        write_atomic(&self.config.state_dir.join(STATUS_FILE), saved.as_bytes())
            .map_err(|error| AgentError::Io(STATUS_FILE, error))
    }
}

/// Names the source, never the key or a device.
impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("source_id", &self.config.source_id)
            .field("waiting_for", &self.waiting_for)
            .field("greeted", &self.greeted)
            .finish_non_exhaustive()
    }
}

/// Tick every `TICK_SECONDS` until `stop` is set, then close. `sleep` is how time passes (`std::thread::sleep` in the
/// binary); the flag is looked at every 100 ms, so a stop takes effect after the tick in progress.
pub fn run(mut agent: Agent, stop: &AtomicBool, mut sleep: impl FnMut(Duration)) -> Result<(), AgentError> {
    let slices = TICK_SECONDS.saturating_mul(1_000) / u64::try_from(STOP_POLL.as_millis()).unwrap_or(100);
    let result = loop {
        if stop.load(Ordering::SeqCst) {
            break Ok(());
        }
        if let Err(error) = agent.tick() {
            break Err(error);
        }
        for _ in 0..slices {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            sleep(STOP_POLL);
        }
    };
    let closed = agent.close();
    result.and(closed)
}

/// An exclusive lock on `agent.lock` for the life of the agent (the kernel drops it when the process ends).
fn lock_state_dir(state_dir: &Path) -> Result<File, AgentError> {
    let path = state_dir.join(LOCK_FILE);
    private_file(&path).map_err(|error| AgentError::Io(LOCK_FILE, error))?;
    let file = open_regular(&path, OpenOptions::new().write(true)).map_err(|error| AgentError::Io(LOCK_FILE, error))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(AgentError::AlreadyRunning(state_dir.to_path_buf())),
        Err(TryLockError::Error(error)) => Err(AgentError::Io(LOCK_FILE, error)),
    }
}

fn checked_class(class: &str) -> &'static str {
    DEVICE_CLASSES
        .into_iter()
        .find(|known| *known == class)
        .unwrap_or("unknown")
}

/// 12 lowercase hex characters, no separators.
fn is_mac(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 1 to 253 characters of printable ASCII: a control character or a NUL in an announced name is noise, never a name.
fn is_hostname(value: &str) -> bool {
    (1..=253).contains(&value.len()) && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// An IPv4 or IPv6 address in its normal written form (IPv6 compressed and lowercase); `None` for anything else.
fn normal_ip(value: &str) -> Option<String> {
    value.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// A moment as the pseudonym store keeps it: Python's `datetime.isoformat()` of a UTC time, so a state directory
/// moves between the two implementations as it is.
fn stored_text(moment: i64) -> String {
    let text = clock::observed_at_text(moment).unwrap_or_default();
    match text.strip_suffix('Z') {
        Some(base) => format!("{base}000+00:00"),
        None => text,
    }
}

/// The moment of a stored text: `YYYY-MM-DDTHH:MM:SS`, an optional fraction of 1 to 6 digits, and `+00:00` or `Z`.
fn stored_millis(text: &str) -> Option<i64> {
    let base = text.strip_suffix("+00:00").or_else(|| text.strip_suffix('Z'))?;
    let (seconds, fraction) = match base.split_once('.') {
        Some((seconds, fraction)) => (seconds, fraction),
        None => (base, ""),
    };
    let digits = fraction.len() <= 6 && fraction.bytes().all(|b| b.is_ascii_digit());
    if !digits || (base.contains('.') && fraction.is_empty()) {
        return None;
    }
    let millis = format!("{:0<3}", fraction.get(..fraction.len().min(3)).unwrap_or_default());
    clock::observed_at_millis(&format!("{seconds}.{millis}Z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_moment_reads_back_and_python_forms_are_read() {
        let moment = 1_800_000_000_123;
        assert_eq!(stored_millis(&stored_text(moment)), Some(moment));
        let python = "2027-01-15T08:00:00.123456+00:00";
        assert_eq!(
            stored_millis(python),
            clock::observed_at_millis("2027-01-15T08:00:00.123Z")
        );
        assert_eq!(
            stored_millis("2027-01-15T08:00:00+00:00"),
            clock::observed_at_millis("2027-01-15T08:00:00.000Z")
        );
        for bad in [
            "",
            "2027-01-15T08:00:00",
            "2027-01-15T08:00:00.+00:00",
            "2027-01-15T08:00:00.1234567Z",
        ] {
            assert_eq!(stored_millis(bad), None, "{bad}");
        }
    }
}
