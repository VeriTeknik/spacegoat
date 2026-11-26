// SPDX-License-Identifier: AGPL-3.0-or-later
//! The agent: observe, turn what changed into events, deliver them. One `tick()` does one round of each.
//!
//! The agent holds no network logic of its own. An `Observer` says what is on the network now; the agent compares
//! that with what it last reported and writes only the difference to the outbox:
//!
//! - a device it has not announced yet: `site.device_appeared`;
//! - a device whose class, name or address differs from what it last reported: `site.device_changed`;
//! - a device that is still there and unchanged: `site.device_seen`, at most once a day;
//! - once an hour per segment it has ever reported, even one that is empty now: `site.inventory_snapshot`, the
//!   counts per class and the number of devices whose identity keeps changing (`ephemeral`). Such a device produces
//!   no event and gets no reference of its own (protocol §9).
//!
//! What it guarantees:
//! - personal data (hardware address, name, IP) goes into the event's separate personal-data part and nowhere else:
//!   not into the attributes, not into `agent.json`, not into `status()`, not into an error;
//! - whatever an observer hands over is checked before it is signed: a signed event never changes, so one the service
//!   would refuse would block the whole queue behind it. A field that does not fit is left out;
//! - the first request of a run is an empty heartbeat, even when events wait (protocol §11). Its answer gives the
//!   service's clock and where the service stands in the sequence;
//! - nothing is signed unless the hub's clock is trusted, and it is trusted only while there is a reading of the
//!   service's clock (a `Date` header) and the skew it implies NOW is within four minutes. The skew now is the skew
//!   at the reading plus how far the wall clock has jumped since (`clock::ClockReading`), so a wall clock stepped
//!   after the greeting stops production at once, without waiting for the next answer. While it is not trusted the
//!   agent produces nothing (`waitingFor: clock`) and keeps sending heartbeats to take a new reading;
//! - an outbox that has never assigned a number (new, lost, or set aside as damaged) starts where the service and
//!   `confirmed.json` say it must (`settle`): from 1 when neither has anything; a `site_source.reset` at the
//!   service's number (`reinstall` when this hub remembers no confirmation, `queue_lost` when it does); and a halt
//!   (`gap`) when the service holds less than it once confirmed. The hub never covers for a service that lost events;
//! - a halt is written to `halt.json` and survives a restart: a halted agent makes no request and produces no event
//!   until a person runs `spacegoat-hub resume`. A queue that grows while nothing can be delivered only makes the
//!   eventual backlog older than the service will accept;
//! - at most `MAX_PENDING_EVENTS` wait: beyond that the agent stops producing (`waitingFor: backlog`) and keeps
//!   delivering; once fewer than half wait it says what it did not capture (`site_source.input_lost`) and goes on;
//! - one agent runs on one state directory (a second one would hand out a second set of references and write into
//!   the same sequence): it holds an exclusive lock on `agent.lock` while it runs, and a second agent refuses to
//!   start. The kernel drops the lock when the process ends, however it ends;
//! - a storage file that is not a database any more (`outbox.sqlite`, `pseudonyms.sqlite`) is set aside as
//!   `<name>.damaged` and started anew, and said so; any other failure to open is an error. A failure while running
//!   is a `problem` in the status, never the end of the process (`run`);
//! - the clocks are injected (`clock::Clock`) and `tick` never sleeps; `run` sleeps through an injected function and
//!   measures every interval on the monotonic clock.
//!
//! The rule for devices whose identity keeps changing (protocol §9, the seven days) belongs to the real observers
//! and is not in this version: an observer says whether a sighting is ephemeral.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Map, Value};

use crate::clock::{self, Clock};
use crate::config::Config;
use crate::fsutil::{create_temporary, fsync_directory, open_regular, private_file, write_atomic};
use crate::keystore::{FileKeyStore, KeyStoreError};
use crate::outbox::{Outbox, OutboxError, ResetReason, database_is_damaged};
use crate::sender::{HaltReason, OriginError, Problem, SendOutcome, Sender, SenderError};
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
/// When this many events wait, the agent stops producing until fewer than half of them do.
pub const MAX_PENDING_EVENTS: usize = 20_000;
/// After a tick that failed, `run` waits this long before the next one, doubling, at most `TICK_BACKOFF_MAX_SECONDS`.
pub const TICK_BACKOFF_FIRST_SECONDS: u64 = 5;
pub const TICK_BACKOFF_MAX_SECONDS: u64 = 240;
/// How often `run` looks at the stop flag while it waits.
const STOP_POLL: Duration = Duration::from_millis(100);
/// `agent.json` and `halt.json` are a few short fields; anything larger is not one, and is not read whole.
const MAX_SMALL_FILE: u64 = 64 * 1024;

pub const KEY_FILE: &str = "hub.key";
pub const OUTBOX_FILE: &str = "outbox.sqlite";
pub const PSEUDONYMS_FILE: &str = "pseudonyms.sqlite";
pub const CONFIRMED_FILE: &str = "confirmed.json";
pub const STATUS_FILE: &str = "agent.json";
pub const HALT_FILE: &str = "halt.json";
pub const LOCK_FILE: &str = "agent.lock";
/// What a damaged database is renamed to: `<name>` followed by this.
pub const DAMAGED_SUFFIX: &str = ".damaged";

/// The prefixes of this program's temporary files in the state directory (`fsutil::create_temporary`: the prefix and
/// 32 lowercase hex characters). Only names of exactly that form are ever removed as leftovers.
const TEMPORARY_PREFIXES: [&str; 5] = [
    ".agent.json.",
    ".confirmed.json.",
    ".hub.key.",
    ".halt.json.",
    OWNER_CHECK_PREFIX,
];
/// The file `check_state_dir` creates for a moment to learn which user this process writes as.
const OWNER_CHECK_PREFIX: &str = ".owner-check.";
const TEMPORARY_RANDOM_HEX: usize = 32;

/// The agent's clocks, shared with the sender.
pub type SharedClock = Arc<dyn Clock>;

/// One device as an observer sees it at one moment. `identity` and `segment` are local to the hub (how it recognises
/// a device and a network) and are never reported; the service sees only their random references.
///
/// An `ephemeral` sighting is a device whose identity keeps changing: it is counted in its segment's snapshot and
/// nothing else is done with it (no event, no reference, nothing kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    pub identity: String,
    pub segment: String,
    pub device_class: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub ephemeral: bool,
}

/// What is on the network right now. A real listener implements this; so does the simulation.
pub trait Observer {
    fn poll(&mut self) -> Vec<Sighting>;
}

/// Why the agent is waiting although it is not halted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitingFor {
    /// The hub's clock is not set, there is no reading of the service's clock yet, or the skew is beyond four minutes.
    Clock,
    /// `401`: an unknown key, or a clock more than five minutes off.
    Unauthorized,
    /// The service has not answered yet.
    Service,
    /// `MAX_PENDING_EVENTS` wait: nothing new is produced until the queue has drained to half.
    Backlog,
}

impl WaitingFor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clock => "clock",
            Self::Unauthorized => "unauthorized",
            Self::Service => "service",
            Self::Backlog => "backlog",
        }
    }
}

#[derive(Debug)]
pub enum AgentError {
    /// The state directory is missing, not a directory, open to other users, or another user's.
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

impl AgentError {
    /// A short reason with no values in it (no path, no content): what the status shows as its `problem`.
    pub fn problem(&self) -> &'static str {
        match self {
            Self::Outbox(_) | Self::Sender(SenderError::Outbox(_)) => "outbox_failed",
            Self::Sender(SenderError::Compress(_)) => "compress_failed",
            Self::State(_) => "pseudonyms_failed",
            Self::Io(CONFIRMED_FILE, _) => "confirmed_failed",
            Self::Io(HALT_FILE, _) => "halt_file_failed",
            Self::Io(STATUS_FILE, _) => "status_file_failed",
            Self::Io(..) => "state_directory_failed",
            Self::StateDirectory(..) | Self::AlreadyRunning(_) => "state_directory_failed",
            Self::Key(_) => "key_failed",
            Self::Origin(_) => "configuration_failed",
        }
    }
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

/// A halt as `halt.json` records it: the reason (`HaltReason::as_str`) and when, if the clock could say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedHalt {
    pub reason: String,
    pub at: Option<String>,
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
    pub halted_at: Option<String>,
    pub waiting_for: Option<String>,
    pub problem: Option<String>,
    /// While halted: the command that clears the halt once the fault is fixed.
    pub resume: Option<String>,
}

impl Status {
    /// The text `status` prints: JSON, two-space indent, the keys in this order.
    pub fn to_json_text(&self) -> String {
        let text = |value: Option<&str>| match value {
            Some(value) => Value::from(value).to_string(),
            None => "null".to_owned(),
        };
        format!(
            "{{\n  \"sourceId\": {},\n  \"keyId\": {},\n  \"lastAssignedSeq\": {},\n  \"lastAckedSeq\": {},\n  \
             \"pending\": {},\n  \"halted\": {},\n  \"haltedAt\": {},\n  \"waitingFor\": {},\n  \"problem\": {},\n  \
             \"resume\": {}\n}}",
            text(Some(&self.source_id)),
            text(Some(&self.key_id)),
            self.last_assigned_seq,
            self.last_acked_seq,
            self.pending,
            text(self.halted.as_deref()),
            text(self.halted_at.as_deref()),
            text(self.waiting_for.as_deref()),
            text(self.problem.as_deref()),
            text(self.resume.as_deref()),
        )
    }
}

/// What the agent last saved in `agent.json`: why it is waiting, and its problem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavedStatus {
    pub waiting_for: Option<String>,
    pub problem: Option<String>,
}

/// The status from its parts (the running agent's, or what `status` reads off the disk). `resume_command` is how
/// the halt is cleared on this hub, shown only while it is halted.
pub fn read_status(
    config: &Config,
    counters: (u64, u64),
    halt: Option<RecordedHalt>,
    saved: SavedStatus,
    resume_command: &str,
) -> Status {
    let (assigned, acked) = counters;
    let is_halted = halt.is_some();
    let (halted, halted_at) = match halt {
        Some(halt) => (Some(halt.reason), halt.at),
        None => (None, None),
    };
    Status {
        source_id: config.source_id.clone(),
        key_id: config.key_id.clone(),
        last_assigned_seq: assigned,
        last_acked_seq: acked,
        pending: assigned.saturating_sub(acked),
        halted,
        halted_at,
        waiting_for: saved.waiting_for,
        problem: saved.problem,
        resume: is_halted.then(|| resume_command.to_owned()),
    }
}

/// A small JSON object file of the agent's own; `None` when there is no such file or it does not hold an object.
/// A file that exists but cannot be read is an error, not "nothing to report".
fn read_small_object(path: &Path) -> io::Result<Option<Map<String, Value>>> {
    let file = match open_regular(path, OpenOptions::new().read(true)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut raw = Vec::new();
    file.take(MAX_SMALL_FILE).read_to_end(&mut raw)?;
    Ok(match serde_json::from_slice::<Value>(&raw) {
        Ok(Value::Object(object)) => Some(object),
        _ => None,
    })
}

/// (waitingFor, problem) as the agent last saved them in `agent.json`.
pub fn read_saved_status(state_dir: &Path) -> io::Result<SavedStatus> {
    let Some(saved) = read_small_object(&state_dir.join(STATUS_FILE))? else {
        return Ok(SavedStatus::default());
    };
    let text = |name: &str| saved.get(name).and_then(Value::as_str).map(str::to_owned);
    Ok(SavedStatus {
        waiting_for: text("waitingFor"),
        problem: text("problem"),
    })
}

/// The halt recorded in `halt.json`, if there is one. A file that is there but unreadable as JSON is still a halt
/// (reason `unknown`): a halt is cleared by a person, never by damage.
pub fn read_halt(state_dir: &Path) -> io::Result<Option<RecordedHalt>> {
    let path = state_dir.join(HALT_FILE);
    if let Err(error) = std::fs::symlink_metadata(&path) {
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let saved = read_small_object(&path)?.unwrap_or_default();
    let reason = saved.get("reason").and_then(Value::as_str);
    Ok(Some(RecordedHalt {
        reason: HaltReason::from_text(reason.unwrap_or_default()).as_str().to_owned(),
        at: saved.get("at").and_then(Value::as_str).map(str::to_owned),
    }))
}

fn write_halt(state_dir: &Path, reason: HaltReason, wall_millis: i64) -> io::Result<()> {
    let at = clock::observed_at_text(wall_millis)
        .filter(|_| clock::clock_is_set(wall_millis))
        .map_or(Value::Null, Value::from);
    let text = format!("{{\"reason\": {}, \"at\": {}}}", Value::from(reason.as_str()), at);
    write_atomic(&state_dir.join(HALT_FILE), text.as_bytes())
}

/// `agent.json`'s text: why the agent is halted or waiting, its problem, and nothing else.
fn status_file_text(halted: Option<&str>, waiting_for: Option<&str>, problem: Option<&str>) -> String {
    let text = |value: Option<&str>| value.map_or(Value::Null, Value::from).to_string();
    format!(
        "{{\"halted\": {}, \"waitingFor\": {}, \"problem\": {}}}",
        text(halted),
        text(waiting_for),
        text(problem),
    )
}

/// Clear a recorded halt (`spacegoat-hub resume`). Refuses while an agent runs on the directory (it holds the
/// lock); returns the halt it cleared, or `None` when there was none.
pub fn resume(config: &Config, expected_owner: Option<u32>) -> Result<Option<RecordedHalt>, AgentError> {
    let state_dir = &config.state_dir;
    check_state_dir(state_dir, expected_owner)?;
    let lock = lock_state_dir(state_dir)?;
    let halt = read_halt(state_dir).map_err(|error| AgentError::Io(HALT_FILE, error))?;
    if halt.is_some() {
        std::fs::remove_file(state_dir.join(HALT_FILE)).map_err(|error| AgentError::Io(HALT_FILE, error))?;
        fsync_directory(state_dir).map_err(|error| AgentError::Io(HALT_FILE, error))?;
        // `agent.json` said halted too; say it no longer is (the rest stays until the agent next runs).
        let saved = read_saved_status(state_dir).map_err(|error| AgentError::Io(STATUS_FILE, error))?;
        let text = status_file_text(None, saved.waiting_for.as_deref(), saved.problem.as_deref());
        write_atomic(&state_dir.join(STATUS_FILE), text.as_bytes())
            .map_err(|error| AgentError::Io(STATUS_FILE, error))?;
    }
    drop(lock);
    Ok(halt)
}

/// How an agent is opened beyond its configuration. The defaults are the protocol's; tests set smaller ones.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct AgentSettings {
    /// The user the state directory must belong to. By default it is the user this process creates files as.
    pub expected_owner: Option<u32>,
    /// `MAX_PENDING_EVENTS` unless a test wants to reach it.
    pub backlog_cap: usize,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            expected_owner: None,
            backlog_cap: MAX_PENDING_EVENTS,
        }
    }
}

pub struct Agent {
    config: Config,
    clock: SharedClock,
    observer: Box<dyn Observer + Send>,
    sender: Sender,
    pseudonyms: Pseudonyms,
    confirmed: Confirmed,
    /// Held for the life of the agent; dropping it releases the lock.
    lock: File,
    waiting_for: Option<WaitingFor>,
    /// True once the service has answered this run: its place in the sequence is known.
    greeted: bool,
    /// True once an outbox that never assigned a number has been told where the sequence stands (`settle`).
    settled: bool,
    /// True while `halt.json` holds the sender's halt.
    halt_saved: bool,
    /// What went wrong in the last tick (a short reason, no values).
    problem: Option<&'static str>,
    /// A damaged store set aside when this run opened (shown while nothing else is wrong).
    replaced: Option<&'static str>,
    /// What `open` has to tell a person once (no contents): a store set aside.
    notices: Vec<String>,
    /// The text of `agent.json` as last written, so it is written only when it changes.
    last_saved: Option<String>,
    backlog_cap: u64,
    stop: Option<Arc<AtomicBool>>,
}

impl Agent {
    /// Open the agent on `config.state_dir`. Refuses a state directory others can enter or another user owns, a
    /// missing or unreadable key, and a directory another agent is running on.
    pub fn open(config: &Config, observer: Box<dyn Observer + Send>, clock: SharedClock) -> Result<Self, AgentError> {
        Self::open_with(config, observer, clock, AgentSettings::default())
    }

    #[doc(hidden)]
    pub fn open_with(
        config: &Config,
        observer: Box<dyn Observer + Send>,
        clock: SharedClock,
        settings: AgentSettings,
    ) -> Result<Self, AgentError> {
        let state_dir = &config.state_dir;
        check_state_dir(state_dir, settings.expected_owner)?;
        let key = FileKeyStore::new(state_dir.join(KEY_FILE))
            .load()
            .map_err(AgentError::Key)?;
        let lock = lock_state_dir(state_dir)?;
        // Only now: another agent could have been writing them a moment ago.
        remove_leftover_temporaries(state_dir).map_err(|error| AgentError::Io("state directory", error))?;
        let halt = read_halt(state_dir).map_err(|error| AgentError::Io(HALT_FILE, error))?;
        let mut notices = Vec::new();
        let mut replaced = None;
        let outbox_path = state_dir.join(OUTBOX_FILE);
        if set_aside_if_damaged(&outbox_path, OUTBOX_FILE)? {
            notices.push(format!(
                "{OUTBOX_FILE} was not a readable database; it was moved to {OUTBOX_FILE}{DAMAGED_SUFFIX} and a new \
                 queue was started (the service is told the queue was lost)"
            ));
            replaced = Some("outbox_replaced");
        }
        let outbox = Outbox::open(&outbox_path, &config.source_id, &config.key_id, key.clone())?;
        let pseudonyms_path = state_dir.join(PSEUDONYMS_FILE);
        if set_aside_if_damaged(&pseudonyms_path, PSEUDONYMS_FILE)? {
            notices.push(format!(
                "{PSEUDONYMS_FILE} was not a readable database; it was moved to {PSEUDONYMS_FILE}{DAMAGED_SUFFIX} and \
                 a new one was started (devices get new references)"
            ));
            replaced = replaced.or(Some("pseudonyms_replaced"));
        }
        let pseudonyms = Pseudonyms::open(&pseudonyms_path)?;
        let mut sender = Sender::new(
            &config.base_url,
            &config.source_id,
            &config.key_id,
            key,
            outbox,
            Arc::clone(&clock),
        )
        .map_err(AgentError::Origin)?;
        if let Some(halt) = &halt {
            sender.halt(HaltReason::from_text(&halt.reason));
        }
        Ok(Self {
            config: config.clone(),
            clock,
            observer,
            sender,
            pseudonyms,
            confirmed: Confirmed::new(state_dir.join(CONFIRMED_FILE)),
            lock,
            waiting_for: None,
            greeted: false,
            settled: false,
            halt_saved: halt.is_some(),
            problem: None,
            replaced,
            notices,
            last_saved: None,
            backlog_cap: u64::try_from(settings.backlog_cap.max(1)).unwrap_or(u64::MAX),
            stop: None,
        })
    }

    /// What opening found and set right, for a person to read once (it names files, never their contents).
    pub fn notices(&self) -> &[String] {
        &self.notices
    }

    /// Look at `stop` between the requests of one tick, so a stop does not wait for a whole chain of them.
    pub fn watch_stop(&mut self, stop: Arc<AtomicBool>) {
        self.stop = Some(stop);
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

    /// One round: observe, record the difference, deliver. Never sleeps. An `Err` is the hub's own storage failing;
    /// it is also recorded as the status's `problem`, and the agent can tick again.
    pub fn tick(&mut self) -> Result<(), AgentError> {
        self.problem = None;
        let result = self.round();
        if let Err(error) = &result {
            self.problem = Some(error.problem());
        }
        self.persist_halt();
        self.save_status();
        result
    }

    /// Between ticks that failed: only a heartbeat, if one is due and the sender can still work. Never fails.
    pub fn keep_alive(&mut self) {
        if self.sender.halted().is_none() && clock::clock_is_set(self.clock.wall_millis()) {
            match self.sender.heartbeat_if_due() {
                Ok(outcome) => {
                    if let Err(error) = self.after(outcome) {
                        self.problem = Some(error.problem());
                    }
                }
                Err(error) => self.problem = Some(AgentError::Sender(error).problem()),
            }
        }
        self.persist_halt();
        self.save_status();
    }

    /// Where the hub stands now: counts and state only.
    pub fn status(&self) -> Result<Status, AgentError> {
        let outbox = self.sender.outbox();
        let counters = (outbox.last_assigned()?, outbox.last_acked()?);
        let halt = self.sender.halted().map(|reason| RecordedHalt {
            reason: reason.as_str().to_owned(),
            at: None,
        });
        let saved = SavedStatus {
            waiting_for: self.waiting_for.map(|waiting| waiting.as_str().to_owned()),
            problem: self.current_problem().map(str::to_owned),
        };
        Ok(read_status(
            &self.config,
            counters,
            halt,
            saved,
            "spacegoat-hub resume --config FILE",
        ))
    }

    fn current_problem(&self) -> Option<&'static str> {
        self.problem.or(self.replaced)
    }

    fn round(&mut self) -> Result<(), AgentError> {
        if self.sender.halted().is_some() {
            self.waiting_for = None;
            return Ok(());
        }
        let wall = self.clock.wall_millis();
        let Some(at) = clock::observed_at_text(wall).filter(|_| clock::clock_is_set(wall)) else {
            // A hub that cannot tell the time asks nothing: every request would carry a timestamp that is not one.
            self.waiting_for = Some(WaitingFor::Clock);
            return Ok(());
        };
        if !self.greeted {
            // The first request of a run is a heartbeat, whatever waits (protocol §11).
            let outcome = self.sender.heartbeat()?;
            self.after(outcome)?;
            if !matches!(outcome, SendOutcome::Sent(_) | SendOutcome::ServiceAhead(_)) {
                self.waiting_for = self.reason_for_no_answer();
                return Ok(());
            }
            self.greeted = true;
        }
        if !self.clock_trusted() {
            // Produce nothing; keep the service informed and take a new reading when a heartbeat is due.
            self.waiting_for = Some(WaitingFor::Clock);
            let outcome = self.sender.heartbeat_if_due()?;
            self.after(outcome)?;
            return Ok(());
        }
        if !self.settled && !self.settle()? {
            self.waiting_for = None;
            return Ok(());
        }
        let capturing = self.capturing(wall, &at)?;
        if capturing {
            let sightings = self.observer.poll();
            self.report(sightings, wall, &at)?;
        }
        let delivered = self.deliver();
        // After delivery: what its answers said is what the status says.
        self.waiting_for = if self.sender.halted().is_some() {
            None
        } else {
            self.unauthorized().or((!capturing).then_some(WaitingFor::Backlog))
        };
        delivered
    }

    fn unauthorized(&self) -> Option<WaitingFor> {
        self.sender.problem().map(|problem| match problem {
            Problem::Unauthorized => WaitingFor::Unauthorized,
        })
    }

    /// Why the greeting got no answer, as the status says it.
    fn reason_for_no_answer(&self) -> Option<WaitingFor> {
        if self.sender.halted().is_some() {
            None
        } else if self.sender.clock_reading().is_some() && !self.clock_trusted() {
            Some(WaitingFor::Clock)
        } else {
            Some(self.unauthorized().unwrap_or(WaitingFor::Service))
        }
    }

    /// The hub's clock is trusted only while there is a reading of the service's clock and the skew it implies now
    /// is within `MAX_CLOCK_SKEW_SECONDS`.
    fn clock_trusted(&self) -> bool {
        let limit = MAX_CLOCK_SKEW_SECONDS.unsigned_abs() * 1_000;
        self.sender
            .clock_skew_millis()
            .is_some_and(|skew| skew.unsigned_abs() <= limit)
    }

    /// What every request's outcome means beyond the sender: the confirmed mark, and the service ahead of an outbox
    /// that has never assigned a number.
    fn after(&mut self, outcome: SendOutcome) -> Result<(), AgentError> {
        if let SendOutcome::ServiceAhead(_) = outcome {
            self.settled = false;
        }
        let acked = self.sender.outbox().last_acked()?;
        self.write_confirmed(acked);
        Ok(())
    }

    /// Where the sequence of an outbox that has never assigned a number starts, from `confirmed.json` (C) and the
    /// service's `lastSeq` (S). False when it halted instead.
    ///
    /// Crash safety: facts are forgotten first, the reset is declared second, the confirmed mark written last. A crash
    /// before the reset leaves an outbox that still has assigned nothing, so the next start comes back here with the
    /// same C (it has not moved) and asks S again; a crash after it leaves a queue whose first event is the reset,
    /// delivered like any other.
    fn settle(&mut self) -> Result<bool, AgentError> {
        if self.sender.outbox().last_assigned()? != 0 {
            self.settled = true;
            return Ok(true);
        }
        let Some(held) = self.sender.service_last_seq() else {
            return Ok(false);
        };
        let confirmed = self
            .confirmed
            .read()
            .map_err(|error| AgentError::Io(CONFIRMED_FILE, error))?;
        let reason = match (confirmed, held) {
            (0, 0) => None,
            (0, _) => Some(ResetReason::Reinstall),
            (confirmed, held) if held >= confirmed => Some(ResetReason::QueueLost),
            // The service holds less than it once confirmed: it lost events. The hub does not cover for that.
            _ => {
                self.sender.halt(HaltReason::Gap);
                return Ok(false);
            }
        };
        // What was reported may have sat in the lost queue: report every device again, under the same reference.
        self.pseudonyms.forget_facts()?;
        if let Some(reason) = reason {
            let at = self.clock.wall_millis();
            self.sender.outbox_mut().declare_reset(held, reason, at)?;
            self.write_confirmed(held);
        }
        self.settled = true;
        Ok(true)
    }

    /// Whether to produce this tick: not while `backlog_cap` events wait, and again once fewer than half do, after
    /// the event that says what was not captured meanwhile.
    fn capturing(&mut self, wall: i64, at: &str) -> Result<bool, AgentError> {
        let outbox = self.sender.outbox();
        let pending = outbox.last_assigned()?.saturating_sub(outbox.last_acked()?);
        match outbox.capture_stopped_at()? {
            Some(since) if pending.saturating_mul(2) < self.backlog_cap => {
                let mut attributes = Map::new();
                attributes.insert("trustOrigin".into(), Value::from("hub"));
                attributes.insert("reason".into(), Value::from("capture_stopped"));
                // Only a start that is a time and not after now (a wall clock stepped back since is possible).
                if let Some(from) = clock::observed_at_text(since).filter(|_| since <= wall) {
                    attributes.insert("fromTime".into(), Value::from(from));
                }
                attributes.insert("toTime".into(), Value::from(at));
                self.sender
                    .outbox_mut()
                    .resume_capture("site_source.input_lost", at, &attributes)?;
                Ok(true)
            }
            Some(_) => Ok(false),
            None if pending >= self.backlog_cap => {
                self.sender.outbox_mut().stop_capture(wall)?;
                Ok(false)
            }
            None => Ok(true),
        }
    }

    fn deliver(&mut self) -> Result<(), AgentError> {
        for _ in 0..SENDS_PER_TICK {
            if self.stop.as_ref().is_some_and(|stop| stop.load(Ordering::SeqCst)) {
                break;
            }
            let outcome = self.sender.step()?;
            self.after(outcome)?;
            let more = match outcome {
                SendOutcome::Sent(_) => !self.sender.outbox().pending(1, None)?.is_empty(),
                SendOutcome::RetryNow => true,
                // The service moved under an outbox that has assigned nothing: the same decision as at the greeting.
                SendOutcome::ServiceAhead(_) => self.settle()? && !self.sender.outbox().pending(1, None)?.is_empty(),
                _ => false,
            };
            if !more {
                break;
            }
        }
        Ok(())
    }

    /// Best effort: a mark that cannot be written is a problem in the status, not a reason to stop delivering. It is
    /// written again with the next answer.
    fn write_confirmed(&mut self, last_acked_seq: u64) {
        if self.confirmed.write(last_acked_seq).is_err() {
            self.problem = Some("confirmed_failed");
        }
    }

    fn report(&mut self, sightings: Vec<Sighting>, moment: i64, at: &str) -> Result<(), AgentError> {
        let mut lasting = Vec::with_capacity(sightings.len());
        let mut ephemeral: BTreeMap<String, u64> = BTreeMap::new();
        for sighting in sightings {
            if sighting.ephemeral {
                let count = ephemeral.entry(sighting.segment).or_default();
                *count = count.saturating_add(1);
            } else {
                lasting.push(self.report_device(sighting, moment, at)?);
            }
        }
        // Every segment ever reported, so that one that has emptied still says so.
        let mut segments: BTreeSet<String> = self.pseudonyms.identities("segment")?.into_iter().collect();
        segments.extend(lasting.iter().map(|(segment, _)| segment.clone()));
        segments.extend(ephemeral.keys().cloned());
        for segment in segments {
            let classes = lasting.iter().filter(|(s, _)| *s == segment).map(|(_, class)| *class);
            let changing = ephemeral.get(&segment).copied().unwrap_or(0);
            self.report_snapshot(&segment, classes, changing, moment, at)?;
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
            } else if told_at.is_none_or(|told| is_due(told, moment, SEEN_EVERY_MS)) {
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
        ephemeral: u64,
        moment: i64,
        at: &str,
    ) -> Result<(), AgentError> {
        let known = self.pseudonyms.facts("segment", segment)?;
        let last = known.get("snapshotAt").and_then(Value::as_str).and_then(stored_millis);
        if last.is_some_and(|last| !is_due(last, moment, SNAPSHOT_EVERY_MS)) {
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
        attributes.insert("ephemeral".into(), Value::from(ephemeral));
        self.sender
            .outbox_mut()
            .append("site.inventory_snapshot", at, &attributes, None)?;
        let mut facts = Map::new();
        facts.insert("snapshotAt".into(), Value::from(stored_text(moment)));
        self.pseudonyms.remember("segment", segment, &facts)?;
        Ok(())
    }

    /// Write `halt.json` once for the sender's halt. Best effort: a failure is the status's problem and is tried
    /// again at the next tick (the sender stays halted meanwhile, so nothing else happens).
    fn persist_halt(&mut self) {
        let Some(reason) = self.sender.halted() else {
            return;
        };
        if self.halt_saved {
            return;
        }
        match write_halt(&self.config.state_dir, reason, self.clock.wall_millis()) {
            Ok(()) => self.halt_saved = true,
            Err(_) => self.problem = Some("halt_file_failed"),
        }
    }

    /// `agent.json`, written only when its text changes. Best effort: a failure is the status's problem.
    fn save_status(&mut self) {
        let text = status_file_text(
            self.sender.halted().map(HaltReason::as_str),
            self.waiting_for.map(WaitingFor::as_str),
            self.current_problem(),
        );
        if self.last_saved.as_deref() == Some(text.as_str()) {
            return;
        }
        match write_atomic(&self.config.state_dir.join(STATUS_FILE), text.as_bytes()) {
            Ok(()) => self.last_saved = Some(text),
            Err(_) => self.problem = Some("status_file_failed"),
        }
    }
}

/// Names the source, never the key or a device.
impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("source_id", &self.config.source_id)
            .field("waiting_for", &self.waiting_for)
            .field("greeted", &self.greeted)
            .field("problem", &self.current_problem())
            .finish_non_exhaustive()
    }
}

/// Tick every `TICK_SECONDS` of monotonic time until `stop` is set, then close. `sleep` is how time passes
/// (`std::thread::sleep` in the binary); the flag is looked at every 100 ms and between the requests of a tick.
///
/// A tick that fails does not end the run: its problem is in the status, the next tick comes after a back-off (5 s,
/// doubling, at most `TICK_BACKOFF_MAX_SECONDS`), and meanwhile a heartbeat still goes out when one is due. Only
/// closing can fail here.
pub fn run(mut agent: Agent, stop: Arc<AtomicBool>, mut sleep: impl FnMut(Duration)) -> Result<(), AgentError> {
    agent.watch_stop(Arc::clone(&stop));
    let clock = Arc::clone(&agent.clock);
    let tick_ms = millis(TICK_SECONDS);
    let mut failures: u32 = 0;
    let mut next_tick = clock.mono_millis();
    while !stop.load(Ordering::SeqCst) {
        let now = clock.mono_millis();
        if now >= next_tick {
            match agent.tick() {
                Ok(()) => {
                    failures = 0;
                    next_tick = now.saturating_add(tick_ms);
                }
                Err(_) => {
                    let wait = TICK_BACKOFF_FIRST_SECONDS
                        .saturating_mul(1u64 << failures.min(16))
                        .min(TICK_BACKOFF_MAX_SECONDS);
                    failures = failures.saturating_add(1);
                    next_tick = now.saturating_add(millis(wait));
                }
            }
        } else {
            agent.keep_alive();
        }
        let wake = next_tick.min(clock.mono_millis().saturating_add(tick_ms));
        wait_until(clock.as_ref(), wake, &stop, &mut sleep);
    }
    agent.close()
}

fn millis(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX).saturating_mul(1_000)
}

/// Sleep in slices of at most `STOP_POLL` until the monotonic clock reaches `wake` or `stop` is set. A monotonic
/// clock that does not move while `sleep` runs (it should) still ends the wait after as many slices as it needs.
fn wait_until(clock: &dyn Clock, wake: i64, stop: &AtomicBool, sleep: &mut impl FnMut(Duration)) {
    let poll = i64::try_from(STOP_POLL.as_millis()).unwrap_or(100);
    let mut slices = wake.saturating_sub(clock.mono_millis()) / poll + 1;
    while !stop.load(Ordering::SeqCst) && slices > 0 {
        let left = wake.saturating_sub(clock.mono_millis());
        if left <= 0 {
            break;
        }
        slices -= 1;
        sleep(Duration::from_millis(u64::try_from(left.min(poll)).unwrap_or(0)));
    }
}

/// Refuse a state directory that is missing, not a directory, open to other users, or owned by another user than
/// the one this process creates files as (`expected_owner` stands for that user in tests). Never changed here: it
/// may not be this agent's to change.
pub fn check_state_dir(state_dir: &Path, expected_owner: Option<u32>) -> Result<(), AgentError> {
    let refuse = |why| AgentError::StateDirectory(state_dir.to_path_buf(), why);
    let found = std::fs::metadata(state_dir).map_err(|_| refuse("missing or unreadable; run keygen first"))?;
    if !found.is_dir() {
        return Err(refuse("not a directory"));
    }
    if found.permissions().mode() & 0o077 != 0 {
        return Err(refuse("open to other users; use one only the hub's user can enter"));
    }
    let me = match expected_owner {
        Some(uid) => uid,
        // std cannot ask for the effective uid: the owner of a file this process creates is that user.
        None => {
            let (file, path) = create_temporary(state_dir, OWNER_CHECK_PREFIX)
                .map_err(|_| refuse("belongs to another user, or this user cannot write it"))?;
            let uid = file.metadata().map(|meta| meta.uid());
            drop(file);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                // Swept by another agent's start meanwhile: gone either way.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(AgentError::Io("state directory", error)),
            }
            uid.map_err(|error| AgentError::Io("state directory", error))?
        }
    };
    if found.uid() != me {
        // Whoever owns the directory can swap what is in it.
        return Err(refuse("belongs to another user"));
    }
    Ok(())
}

/// An exclusive lock on `agent.lock` for the life of the agent (the kernel drops it when the process ends).
pub fn lock_state_dir(state_dir: &Path) -> Result<File, AgentError> {
    let path = state_dir.join(LOCK_FILE);
    private_file(&path).map_err(|error| AgentError::Io(LOCK_FILE, error))?;
    let file = open_regular(&path, OpenOptions::new().write(true)).map_err(|error| AgentError::Io(LOCK_FILE, error))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(AgentError::AlreadyRunning(state_dir.to_path_buf())),
        Err(TryLockError::Error(error)) => Err(AgentError::Io(LOCK_FILE, error)),
    }
}

/// Whether `name` is one of this program's temporary file names: a known prefix and exactly 32 lowercase hex.
fn is_our_temporary(name: &str) -> bool {
    TEMPORARY_PREFIXES.iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|rest| {
            rest.len() == TEMPORARY_RANDOM_HEX && rest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    })
}

/// Remove what a process that died mid-write left behind: files (and symbolic links: the link itself, never what it
/// points to) whose names are of this program's temporary form. A directory of such a name is left alone, as is
/// every other name. Called with the lock held, so no agent is writing them.
fn remove_leftover_temporaries(state_dir: &Path) -> io::Result<()> {
    let mut removed = false;
    for entry in std::fs::read_dir(state_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_str().is_some_and(is_our_temporary) {
            continue;
        }
        let path = entry.path();
        let kind = std::fs::symlink_metadata(&path)?.file_type();
        if kind.is_file() || kind.is_symlink() {
            match std::fs::remove_file(&path) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    if removed {
        fsync_directory(state_dir)?;
    }
    Ok(())
}

/// If the database at `path` is damaged (`outbox::database_is_damaged`), move it aside to `<path>.damaged`
/// (replacing an earlier one), with its write-ahead log beside it as `<path>.damaged-wal` and its shared-memory file
/// removed, so a new database at `path` cannot replay a log that is not its own. True when it did. A missing file
/// and anything but a regular file are left to the opener (which refuses a link). `what` names the file in an error.
fn set_aside_if_damaged(path: &Path, what: &'static str) -> Result<bool, AgentError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {}
        _ => return Ok(false),
    }
    let io_error = |error: io::Error| AgentError::Io(what, error);
    if !database_is_damaged(path).map_err(|error| io_error(io::Error::other(error)))? {
        return Ok(false);
    }
    let sidecar = |suffix: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    };
    let damaged = sidecar(DAMAGED_SUFFIX);
    std::fs::rename(path, &damaged).map_err(io_error)?;
    std::fs::set_permissions(&damaged, std::fs::Permissions::from_mode(0o600)).map_err(io_error)?;
    let ignore_missing = |result: io::Result<()>| match result {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(io_error(error)),
        _ => Ok(()),
    };
    ignore_missing(std::fs::rename(sidecar("-wal"), sidecar(".damaged-wal")))?;
    ignore_missing(std::fs::remove_file(sidecar("-shm")))?;
    let directory = path.parent().unwrap_or(Path::new("."));
    fsync_directory(directory).map_err(io_error)?;
    Ok(true)
}

/// Whether something last done at `last` is due again at `now`, `every` milliseconds later. A `last` in the future
/// (kept from a wall clock that was ahead and has since been set back) counts as due: otherwise a step back would
/// silence a device or a segment for as long as the clock had been ahead.
fn is_due(last: i64, now: i64, every: i64) -> bool {
    last > now || now.saturating_sub(last) >= every
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
