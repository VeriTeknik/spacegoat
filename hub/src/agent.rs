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
//!   not into the attributes, not into `agent.json`, not into `status()`, not into an error or a reported line;
//! - whatever an observer hands over is checked before it is signed: a signed event never changes, so one the service
//!   would refuse would block the whole queue behind it. A field that does not fit is left out;
//! - what was last reported about each device is kept in memory for the run, with the pseudonym store as its
//!   persistence: a store write that fails after the event was appended is retried, and the event is not appended
//!   again. A failure to capture or to store never keeps what is queued from being delivered;
//! - the first request of a run is an empty heartbeat, even when events wait (protocol §11). Its answer gives the
//!   service's clock and where the service stands in the sequence. The tick's clocks are read after it;
//! - nothing is signed unless the hub's clock is trusted, and it is trusted only while there is a reading of the
//!   service's clock (a `Date` header) and the skew it implies NOW is within four minutes. The skew now is the skew
//!   at the reading plus how far the wall clock has jumped since (`clock::ClockReading`), so a wall clock stepped
//!   after the greeting stops production at once. While it is not trusted the agent produces nothing (`waitingFor:
//!   clock`) and still delivers what was signed before; a clock that was trusted and is not any more takes a new
//!   reading at once (a heartbeat, or the delivery itself), heartbeats go on when due;
//! - while the last request got no confirming answer the status says so (`waitingFor: service`) and which kind of
//!   answer it was (`service`), until the next confirming one;
//! - an outbox that has never assigned a number (new, lost, or set aside as damaged) starts where the service and
//!   `confirmed.json` say it must (`settle`): from 1 when neither has anything; a `site_source.reset` at the
//!   service's number (`reinstall` when this hub remembers no confirmation, `queue_lost` when it does, or when its
//!   mark cannot be understood); and a halt (`gap`) when the service holds less than it once confirmed. The hub
//!   never covers for a service that lost events;
//! - a halt is written to `halt.json` and survives a restart: a halted agent makes no request at all, heartbeats
//!   included, and produces no event until a person runs `spacegoat-hub resume`. A queue that grows while nothing can
//!   be delivered only makes the eventual backlog older than the service will accept;
//! - at most `MAX_PENDING_EVENTS` wait: beyond that the agent stops producing (`waitingFor: backlog`) and keeps
//!   delivering, until fewer than half wait;
//! - whenever the hub could not capture for more than `STOP_DECLARED_AFTER_SECONDS` (its clock not trusted, its
//!   storage failing, halted, its backlog full), it says so once capture resumes, with one `site_source.input_lost`
//!   (`capture_stopped`, `fromTime` only when the stop began at a trusted time). The mark lives in the outbox and
//!   survives a restart; a shorter stop is not declared;
//! - while the last tick failed with a storage error, no keep-alive heartbeat goes out (it would say "alive, nothing
//!   to report", which is not true then; the service's silence alert is the signal). Events already queued are
//!   still delivered when the queue can be read;
//! - one agent runs on one state directory (a second one would hand out a second set of references and write into
//!   the same sequence): it holds an exclusive lock on `agent.lock` while it runs, and a second agent refuses to
//!   start. The kernel drops the lock when the process ends, however it ends;
//! - a storage file that is not a database any more (`outbox.sqlite`, `pseudonyms.sqlite`) is set aside as
//!   `<name>.damaged` and started anew, and said so; any other failure to open is an error. A name of the agent's
//!   own that holds a symbolic link or a directory is refused, by name, for a person to remove. A failure while
//!   running is a `problem` in the status, never the end of the process (`run`);
//! - `run` reports each change of what the status says (halted, what it waits for, its problem) as one line, never
//!   one per tick;
//! - the clocks are injected (`clock::Clock`) and `tick` never sleeps; `run` sleeps through an injected function and
//!   measures every interval on the monotonic clock.
//!
//! The rule for devices whose identity keeps changing (protocol §9, the seven days) belongs to the real observers
//! and is not in this version: an observer says whether a sighting is ephemeral.

use std::collections::{BTreeMap, BTreeSet, HashMap};
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
use crate::fsutil::{
    create_temporary, current_uid, fsync_directory, non_file_kind, open_regular, private_file, write_own_file,
};
use crate::keystore::{FileKeyStore, KeyStoreError};
use crate::outbox::{Outbox, OutboxError, ResetReason, database_is_damaged};
use crate::sender::{HaltReason, OriginError, Problem, SendOutcome, Sender, SenderError};
use crate::state::{Confirmed, Mark, Pseudonyms, StateError};

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
/// A stop in capture longer than this is declared (`site_source.input_lost`) when capture resumes.
pub const STOP_DECLARED_AFTER_SECONDS: i64 = 300;
/// How often `run` looks at the stop flag while it waits.
const STOP_POLL: Duration = Duration::from_millis(100);
/// `agent.json` and `halt.json` are a few short fields; anything larger is not one, and is not read whole.
const MAX_SMALL_FILE: u64 = 64 * 1024;

pub const KEY_FILE: &str = "hub.key";
/// The id the key was generated under, beside it (`keystore::KEY_ID_SUFFIX`).
pub const KEY_ID_FILE: &str = "hub.key.id";
pub const OUTBOX_FILE: &str = "outbox.sqlite";
pub const PSEUDONYMS_FILE: &str = "pseudonyms.sqlite";
pub const CONFIRMED_FILE: &str = "confirmed.json";
pub const STATUS_FILE: &str = "agent.json";
pub const HALT_FILE: &str = "halt.json";
pub const LOCK_FILE: &str = "agent.lock";
/// What a damaged database is renamed to: `<name>` followed by this.
pub const DAMAGED_SUFFIX: &str = ".damaged";
/// The names of the agent's own that must hold a regular file when they hold anything.
pub const OWN_FILES: [&str; 5] = [STATUS_FILE, HALT_FILE, CONFIRMED_FILE, OUTBOX_FILE, PSEUDONYMS_FILE];

/// The prefixes of this program's temporary files in the state directory (`fsutil::create_temporary`: the prefix and
/// 32 lowercase hex characters). Only names of exactly that form are ever removed as leftovers.
const TEMPORARY_PREFIXES: [&str; 6] = [
    ".agent.json.",
    ".confirmed.json.",
    ".hub.key.",
    ".hub.key.id.",
    ".halt.json.",
    WRITE_CHECK_PREFIX,
];
/// The file `check_state_dir` creates for a moment to learn whether this process can write the directory.
const WRITE_CHECK_PREFIX: &str = ".owner-check.";
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
    /// The last request got no confirming answer (the status's `service` says which kind), or none was made yet.
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

/// What a halt means, in a few words a person can act on.
pub fn halt_meaning(reason: HaltReason) -> &'static str {
    match reason {
        HaltReason::Schema => "the service refused the content of a batch",
        HaltReason::ReplayConflict => "the service holds another event under a number this hub sent",
        HaltReason::Gap => "the service holds less than this hub had confirmed",
        HaltReason::TooLarge => "one event is larger than the service accepts",
        HaltReason::Ahead => "the service confirmed numbers this hub never assigned: two hubs share one identity",
        HaltReason::Unknown => "the halt file could not be read",
    }
}

#[derive(Debug)]
pub enum AgentError {
    /// The state directory is missing, not a directory, open to other users, another user's, or not writable.
    StateDirectory(PathBuf, &'static str),
    /// Another agent holds the state directory's lock.
    AlreadyRunning(PathBuf),
    /// A name of the agent's own (`OWN_FILES`) holds something other than a regular file: the name, and what it holds.
    NotAFile(&'static str, &'static str),
    /// The configuration's key id is not the one the key was generated under.
    KeyIdMismatch {
        configured: String,
        stored: String,
    },
    /// `resume --from-service` on a halt that is not `gap` (the reason is given).
    NotAGap(String),
    /// `resume --from-service` while the outbox holds numbers the service does not have.
    QueueHoldsNumbers,
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
            Self::Io(..) | Self::NotAFile(..) | Self::NotAGap(_) | Self::QueueHoldsNumbers => "state_directory_failed",
            Self::StateDirectory(..) | Self::AlreadyRunning(_) => "state_directory_failed",
            Self::Key(_) | Self::KeyIdMismatch { .. } => "key_failed",
            Self::Origin(_) => "configuration_failed",
        }
    }

    /// Whether the error means the command could not start (the state directory, a file of its own that is not a
    /// file, the key, the lock), as opposed to having run and failed.
    pub fn is_start_refusal(&self) -> bool {
        matches!(
            self,
            Self::StateDirectory(..)
                | Self::AlreadyRunning(_)
                | Self::NotAFile(..)
                | Self::KeyIdMismatch { .. }
                | Self::Key(_)
                | Self::Origin(_)
        )
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateDirectory(path, why) => write!(f, "state directory {}: {why}", path.display()),
            Self::AlreadyRunning(path) => write!(f, "another agent is already running on {}", path.display()),
            Self::NotAFile(name, kind) => write!(
                f,
                "{name} in the state directory is {kind}, not a file the hub wrote; a person must look at it and \
                 remove it by hand"
            ),
            Self::KeyIdMismatch { configured, stored } => write!(
                f,
                "the configuration's key_id is {configured}, but the key in this state directory was generated as \
                 {stored}; use the key id the key was registered with"
            ),
            Self::NotAGap(reason) => write!(
                f,
                "--from-service is the way out of a gap halt only; this hub is halted with {reason}"
            ),
            Self::QueueHoldsNumbers => f.write_str(
                "--from-service cannot help while outbox.sqlite holds numbered events the service does not have: \
                 they cannot be numbered again. Move outbox.sqlite aside (its events will not be delivered), then \
                 run resume --from-service again",
            ),
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
    /// Why the last request got no confirming answer (`sender::ServiceTrouble::as_text`), until one does.
    pub service: Option<String>,
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
             \"pending\": {},\n  \"halted\": {},\n  \"haltedAt\": {},\n  \"waitingFor\": {},\n  \"service\": {},\n  \
             \"problem\": {},\n  \"resume\": {}\n}}",
            text(Some(&self.source_id)),
            text(Some(&self.key_id)),
            self.last_assigned_seq,
            self.last_acked_seq,
            self.pending,
            text(self.halted.as_deref()),
            text(self.halted_at.as_deref()),
            text(self.waiting_for.as_deref()),
            text(self.service.as_deref()),
            text(self.problem.as_deref()),
            text(self.resume.as_deref()),
        )
    }
}

/// What the agent last saved in `agent.json`: why it is waiting, the kind of answer the service last gave, and its
/// problem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavedStatus {
    pub waiting_for: Option<String>,
    pub service: Option<String>,
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
        service: saved.service,
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

/// (waitingFor, service, problem) as the agent last saved them in `agent.json`.
pub fn read_saved_status(state_dir: &Path) -> io::Result<SavedStatus> {
    let Some(saved) = read_small_object(&state_dir.join(STATUS_FILE))? else {
        return Ok(SavedStatus::default());
    };
    let text = |name: &str| saved.get(name).and_then(Value::as_str).map(str::to_owned);
    Ok(SavedStatus {
        waiting_for: text("waitingFor"),
        service: text("service"),
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
    write_own_file(&state_dir.join(HALT_FILE), text.as_bytes())
}

/// `agent.json`'s text: why the agent is halted or waiting, the kind of answer the service last gave, its problem,
/// and nothing else.
fn status_file_text(
    halted: Option<&str>,
    waiting_for: Option<&str>,
    service: Option<&str>,
    problem: Option<&str>,
) -> String {
    let text = |value: Option<&str>| value.map_or(Value::Null, Value::from).to_string();
    format!(
        "{{\"halted\": {}, \"waitingFor\": {}, \"service\": {}, \"problem\": {}}}",
        text(halted),
        text(waiting_for),
        text(service),
        text(problem),
    )
}

/// Refuse a name of the agent's own (`OWN_FILES`) that holds a symbolic link, a directory or anything but a regular
/// file: it is not the hub's to remove or to write through, and a person must look at it.
pub fn check_own_files(state_dir: &Path) -> Result<(), AgentError> {
    for name in OWN_FILES {
        if let Some(kind) = non_file_kind(&state_dir.join(name)).map_err(|error| AgentError::Io(name, error))? {
            return Err(AgentError::NotAFile(name, kind));
        }
    }
    Ok(())
}

/// What `resume` is asked to do beyond clearing the halt.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResumeOptions {
    /// The user the state directory must belong to (tests); by default the user this process creates files as.
    pub expected_owner: Option<u32>,
    /// Also set the confirmed mark to 0, so that the hub takes the service's number as its starting point at its
    /// next greeting: the way out of a `gap` halt, for an outbox that has never assigned a number.
    pub from_service: bool,
}

/// Clear a recorded halt (`spacegoat-hub resume`). Refuses while an agent runs on the directory (it holds the
/// lock); returns the halt it cleared, or `None` when there was none.
pub fn resume(config: &Config, expected_owner: Option<u32>) -> Result<Option<RecordedHalt>, AgentError> {
    let options = ResumeOptions {
        expected_owner,
        from_service: false,
    };
    resume_with(config, options, &|path: &Path| std::fs::remove_file(path))
}

/// `resume` with its options, and `remove` as the way `halt.json` is removed (tests make it fail).
///
/// The order: `agent.json` is rewritten first (it no longer says halted), then `halt.json` is removed. If removing
/// fails the hub is still halted (`halt.json` is what decides), and the error says so.
#[doc(hidden)]
pub fn resume_with(
    config: &Config,
    options: ResumeOptions,
    remove: &dyn Fn(&Path) -> io::Result<()>,
) -> Result<Option<RecordedHalt>, AgentError> {
    let state_dir = &config.state_dir;
    check_state_dir(state_dir, options.expected_owner, true)?;
    check_own_files(state_dir)?;
    let lock = lock_state_dir(state_dir)?;
    let Some(halt) = read_halt(state_dir).map_err(|error| AgentError::Io(HALT_FILE, error))? else {
        return Ok(None);
    };
    if options.from_service {
        if halt.reason != HaltReason::Gap.as_str() {
            return Err(AgentError::NotAGap(halt.reason));
        }
        let (assigned, _) = Outbox::read_counters(&state_dir.join(OUTBOX_FILE))?;
        if assigned != 0 {
            return Err(AgentError::QueueHoldsNumbers);
        }
        Confirmed::new(state_dir.join(CONFIRMED_FILE), &config.source_id)
            .replace(0)
            .map_err(|error| AgentError::Io(CONFIRMED_FILE, error))?;
    }
    let saved = read_saved_status(state_dir).map_err(|error| AgentError::Io(STATUS_FILE, error))?;
    let text = status_file_text(
        None,
        saved.waiting_for.as_deref(),
        saved.service.as_deref(),
        saved.problem.as_deref(),
    );
    write_own_file(&state_dir.join(STATUS_FILE), text.as_bytes())
        .map_err(|error| AgentError::Io(STATUS_FILE, error))?;
    remove(&state_dir.join(HALT_FILE)).map_err(|error| AgentError::Io(HALT_FILE, error))?;
    fsync_directory(state_dir).map_err(|error| AgentError::Io(HALT_FILE, error))?;
    drop(lock);
    Ok(Some(halt))
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

/// A stop in capture: since when on the monotonic clock (`None` when it began before this run), since when on the
/// wall clock when that was a trusted time, and whether the outbox holds its mark.
#[derive(Debug, Clone, Copy)]
struct CaptureStop {
    since_mono: Option<i64>,
    since_wall: Option<i64>,
    persisted: bool,
}

/// A reference's scope and local identity: the key of what was last reported about it.
type Subject = (String, String);

/// What `run` prints when nothing is wrong: the state a healthy run starts from, so it says nothing.
const RUNNING: &str = "running normally";

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
    /// What opening set right, shown while nothing else is wrong: a damaged store set aside, a new pseudonym store.
    replaced: Option<&'static str>,
    /// What `open` has to tell a person once (no contents): a store set aside.
    notices: Vec<String>,
    /// The text of `agent.json` as last written, so it is written only when it changes.
    last_saved: Option<String>,
    backlog_cap: u64,
    stop: Option<Arc<AtomicBool>>,
    /// What was last reported about each subject, for the run; the pseudonym store is its persistence.
    reported: HashMap<Subject, Map<String, Value>>,
    /// Subjects whose last report the store has not taken yet.
    unsaved: BTreeSet<Subject>,
    /// Whether the clock was trusted in the last tick that had a reading.
    trusted_before: bool,
    capture_stop: Option<CaptureStop>,
    /// The backlog is full, or has not drained to half since it was.
    backlog_full: bool,
    /// Whether this tick captured.
    captured: bool,
    /// Whether the last capture failed (storage).
    capture_failed: bool,
    /// Whether the last tick failed (storage): no keep-alive heartbeat then.
    tick_failed: bool,
    /// `confirmed.json` could not be understood and the outbox has never assigned a number: something was confirmed
    /// once, nobody knows how much.
    confirmed_unknown: bool,
    resume_command: String,
    /// The state `run` last reported (or the healthy one it starts from), and the line not yet taken.
    announced: String,
    announcement: Option<String>,
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
        check_state_dir(state_dir, settings.expected_owner, true)?;
        check_own_files(state_dir)?;
        let store = FileKeyStore::new(state_dir.join(KEY_FILE));
        let key = store.load().map_err(AgentError::Key)?;
        if let Some(stored) = store.read_key_id().map_err(AgentError::Key)?
            && stored != config.key_id
        {
            return Err(AgentError::KeyIdMismatch {
                configured: config.key_id.clone(),
                stored,
            });
        }
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
        let pseudonyms_set_aside = set_aside_if_damaged(&pseudonyms_path, PSEUDONYMS_FILE)?;
        if pseudonyms_set_aside {
            notices.push(format!(
                "{PSEUDONYMS_FILE} was not a readable database; it was moved to {PSEUDONYMS_FILE}{DAMAGED_SUFFIX} and \
                 a new one was started (devices get new references)"
            ));
            replaced = replaced.or(Some("pseudonyms_replaced"));
        }
        let pseudonyms = Pseudonyms::open(&pseudonyms_path)?;
        let assigned = outbox.last_assigned()?;
        let acked = outbox.last_acked()?;
        if !pseudonyms_set_aside && assigned > 0 && pseudonyms.is_empty()? {
            notices.push(format!(
                "{PSEUDONYMS_FILE} is new or empty while the queue has numbered events already: devices get new \
                 references (the service sees them as new devices)"
            ));
            replaced = replaced.or(Some("pseudonyms_new"));
        }
        let confirmed = Confirmed::new(state_dir.join(CONFIRMED_FILE), &config.source_id);
        let mut confirmed_unknown = false;
        match confirmed.read() {
            Ok(Mark::NotUnderstood) if assigned > 0 => {
                if confirmed.replace(acked).is_ok() {
                    notices.push(format!(
                        "{CONFIRMED_FILE} could not be understood; it was written again from the queue's own record \
                         of what the service confirmed"
                    ));
                } else {
                    // Written again with the next answer, whose own failure is the status's problem then.
                    notices.push(format!(
                        "{CONFIRMED_FILE} could not be understood, and could not be written again from the queue's \
                         own record yet"
                    ));
                }
            }
            Ok(Mark::NotUnderstood) => {
                confirmed_unknown = true;
                notices.push(format!(
                    "{CONFIRMED_FILE} could not be understood and the queue has never numbered an event: the hub \
                     takes the service's number as its starting point and declares a lost queue there"
                ));
            }
            Ok(Mark::Nothing | Mark::Confirmed(_)) => {}
            Err(error) => return Err(AgentError::Io(CONFIRMED_FILE, error)),
        }
        let capture_stop = outbox.capture_stop()?.map(|since_wall| CaptureStop {
            since_mono: None,
            since_wall,
            persisted: true,
        });
        let backlog_cap = u64::try_from(settings.backlog_cap.max(1)).unwrap_or(u64::MAX);
        let backlog_full = capture_stop.is_some() && assigned.saturating_sub(acked).saturating_mul(2) >= backlog_cap;
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
            confirmed,
            lock,
            waiting_for: None,
            greeted: false,
            settled: false,
            halt_saved: halt.is_some(),
            problem: None,
            replaced,
            notices,
            last_saved: None,
            backlog_cap,
            stop: None,
            reported: HashMap::new(),
            unsaved: BTreeSet::new(),
            trusted_before: false,
            capture_stop,
            backlog_full,
            captured: false,
            capture_failed: false,
            tick_failed: false,
            confirmed_unknown,
            resume_command: "spacegoat-hub resume --config FILE".to_owned(),
            announced: RUNNING.to_owned(),
            announcement: None,
        })
    }

    /// What opening found and set right, for a person to read once (it names files, never their contents).
    pub fn notices(&self) -> &[String] {
        &self.notices
    }

    /// The command that clears a halt on this hub, as the status and the reported lines name it.
    pub fn set_resume_command(&mut self, command: String) {
        self.resume_command = command;
    }

    /// Look at `stop` between the requests of one tick, so a stop does not wait for a whole chain of them.
    pub fn watch_stop(&mut self, stop: Arc<AtomicBool>) {
        self.stop = Some(stop);
    }

    /// Close the databases and release the state directory. What the store has not taken yet is tried once more.
    pub fn close(mut self) -> Result<(), AgentError> {
        let _ = self.save_unsaved();
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
        self.captured = false;
        let result = self.round();
        if let Err(error) = &result {
            self.problem = Some(error.problem());
        }
        self.tick_failed = result.is_err();
        let halted = self.sender.halted().is_some();
        if halted || !self.captured {
            // A halt and a full backlog are long by nature: their mark is kept at once.
            self.note_stopped(halted || self.backlog_full);
        }
        self.persist_halt();
        self.save_status();
        self.announce();
        result
    }

    /// Between ticks: a heartbeat if one is due and the sender can still work; after a tick that failed, only the
    /// delivery of what is queued, never a heartbeat. Never fails.
    pub fn keep_alive(&mut self) {
        if self.sender.halted().is_none() && clock::clock_is_set(self.clock.wall_millis()) {
            let outcome = if self.tick_failed {
                self.sender.step_events()
            } else {
                self.sender.heartbeat_if_due()
            };
            match outcome {
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
        self.announce();
    }

    /// The line `run` reports for the last change of state, once; `None` when nothing changed since it was taken.
    pub fn take_announcement(&mut self) -> Option<String> {
        self.announcement.take()
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
            service: self.sender.trouble().map(|trouble| trouble.as_text()),
            problem: self.current_problem().map(str::to_owned),
        };
        Ok(read_status(&self.config, counters, halt, saved, &self.resume_command))
    }

    fn current_problem(&self) -> Option<&'static str> {
        self.problem.or(self.replaced)
    }

    fn round(&mut self) -> Result<(), AgentError> {
        if self.sender.halted().is_some() {
            self.waiting_for = None;
            return Ok(());
        }
        if !clock::clock_is_set(self.clock.wall_millis()) {
            // A hub that cannot tell the time asks nothing: every request would carry a timestamp that is not one.
            self.waiting_for = Some(WaitingFor::Clock);
            return Ok(());
        }
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
        // This tick's clocks: after the greeting, which can take as long as a request does.
        let wall = self.clock.wall_millis();
        let trusted = self.clock_trusted() && clock::clock_is_set(wall);
        let jumped = self.trusted_before && !trusted;
        self.trusted_before = trusted;
        let Some(at) = clock::observed_at_text(wall).filter(|_| trusted) else {
            // Produce nothing; deliver what was signed while the clock was trusted. A clock that was trusted until
            // now takes a new reading at once: a heartbeat when nothing is queued, else the delivery itself.
            if jumped && self.sender.outbox().pending(1, None)?.is_empty() {
                let outcome = self.sender.heartbeat()?;
                self.after(outcome)?;
            }
            let delivered = self.deliver(true, false);
            self.waiting_for = self.waiting(false);
            return delivered;
        };
        if !self.settled && !self.settle()? {
            self.waiting_for = self.waiting(true);
            return Ok(());
        }
        let capture = self.capture(wall, &at);
        // A heartbeat says "alive, nothing to report": only when that is true.
        let healthy = matches!(capture, Ok(None));
        let delivered = self.deliver(healthy, true);
        self.waiting_for = self.waiting(true);
        match capture {
            Err(error) | Ok(Some(error)) => Err(error),
            Ok(None) => delivered,
        }
    }

    /// Why the agent is waiting, after this tick's requests: the clock first, then a `401`, then a service that did
    /// not confirm the last request, then a full backlog.
    fn waiting(&self, clock_trusted: bool) -> Option<WaitingFor> {
        if self.sender.halted().is_some() {
            None
        } else if !clock_trusted {
            Some(WaitingFor::Clock)
        } else if let Some(waiting) = self.unauthorized() {
            Some(waiting)
        } else if self.sender.trouble().is_some() {
            Some(WaitingFor::Service)
        } else {
            self.backlog_full.then_some(WaitingFor::Backlog)
        }
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

    /// The wall clock now, if it is a time this hub trusts.
    fn trusted_wall(&self) -> Option<i64> {
        let wall = self.clock.wall_millis();
        (clock::clock_is_set(wall) && self.clock_trusted()).then_some(wall)
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
        let confirmed = if self.confirmed_unknown {
            None
        } else {
            match self
                .confirmed
                .read()
                .map_err(|error| AgentError::Io(CONFIRMED_FILE, error))?
            {
                Mark::Nothing => Some(0),
                Mark::Confirmed(confirmed) => Some(confirmed),
                Mark::NotUnderstood => {
                    self.confirmed_unknown = true;
                    None
                }
            }
        };
        let reason = match (confirmed, held) {
            // Confirmed something once, nobody knows how much: the gap rule cannot be applied. What the service
            // holds is taken as the starting point and declared as a lost queue.
            (None, 0) => None,
            (None, _) => Some(ResetReason::QueueLost),
            (Some(0), 0) => None,
            (Some(0), _) => Some(ResetReason::Reinstall),
            (Some(confirmed), held) if held >= confirmed => Some(ResetReason::QueueLost),
            // The service holds less than it once confirmed: it lost events. The hub does not cover for that.
            (Some(_), _) => {
                self.sender.halt(HaltReason::Gap);
                return Ok(false);
            }
        };
        // What was reported may have sat in the lost queue: report every device again, under the same reference.
        self.forget_facts()?;
        if let Some(reason) = reason {
            let at = self.clock.wall_millis();
            self.sender.outbox_mut().declare_reset(held, reason, at)?;
            self.write_confirmed(held);
        }
        self.confirmed_unknown = false;
        self.settled = true;
        Ok(true)
    }

    /// One round of capture, unless the backlog is full. `Err`: capture failed (nothing, or not everything, was
    /// produced). `Ok(Some(_))`: everything due was produced, but the store did not take what was reported.
    fn capture(&mut self, wall: i64, at: &str) -> Result<Option<AgentError>, AgentError> {
        let outbox = self.sender.outbox();
        let pending = outbox.last_assigned()?.saturating_sub(outbox.last_acked()?);
        if self.backlog_full {
            self.backlog_full = pending.saturating_mul(2) >= self.backlog_cap;
        } else {
            self.backlog_full = pending >= self.backlog_cap;
        }
        if self.backlog_full {
            return Ok(None);
        }
        // The stop is declared before what is captured now, unless capture itself was what failed: then only once
        // it works again.
        if !self.capture_failed {
            self.end_stop(wall, at)?;
        }
        let sightings = self.observer.poll();
        match self.report(sightings, wall, at) {
            Err(error) => {
                self.capture_failed = true;
                Err(error)
            }
            Ok(unsaved) => {
                self.captured = true;
                if self.capture_failed {
                    self.capture_failed = false;
                    self.end_stop(wall, at)?;
                }
                Ok(unsaved)
            }
        }
    }

    /// Capture did not happen this tick: remember since when, and keep the mark in the outbox once the stop is long
    /// enough to be declared (at once when `persist_now`). Best effort: a mark that cannot be written is tried again
    /// at the next tick.
    fn note_stopped(&mut self, persist_now: bool) {
        let mono = self.clock.mono_millis();
        let stop = match self.capture_stop {
            Some(stop) => stop,
            None => {
                let stop = CaptureStop {
                    since_mono: Some(mono),
                    since_wall: self.trusted_wall(),
                    persisted: false,
                };
                self.capture_stop = Some(stop);
                stop
            }
        };
        if stop.persisted || !(persist_now || is_long(stop, mono)) {
            return;
        }
        if self.sender.outbox_mut().stop_capture(stop.since_wall).is_ok() {
            self.capture_stop = Some(CaptureStop {
                persisted: true,
                ..stop
            });
        }
    }

    /// Capture works again: a stop longer than `STOP_DECLARED_AFTER_SECONDS` (or one from an earlier run, whose
    /// length is not known here) is declared with one `site_source.input_lost`, and the mark is cleared in the same
    /// transaction; a shorter one is forgotten.
    fn end_stop(&mut self, wall: i64, at: &str) -> Result<(), AgentError> {
        let Some(stop) = self.capture_stop else {
            return Ok(());
        };
        let outbox = self.sender.outbox_mut();
        let mark = outbox.capture_stop()?;
        if !is_long(stop, self.clock.mono_millis()) {
            if mark.is_some() {
                outbox.clear_capture_stop()?;
            }
            self.capture_stop = None;
            return Ok(());
        }
        let mut attributes = Map::new();
        attributes.insert("trustOrigin".into(), Value::from("hub"));
        attributes.insert("reason".into(), Value::from("capture_stopped"));
        // Only a start that was a trusted time and is not after now (a wall clock stepped back since is possible).
        let from = mark.unwrap_or(stop.since_wall).filter(|from| *from <= wall);
        if let Some(from) = from.and_then(clock::observed_at_text) {
            attributes.insert("fromTime".into(), Value::from(from));
        }
        attributes.insert("toTime".into(), Value::from(at));
        outbox.resume_capture("site_source.input_lost", at, &attributes)?;
        self.capture_stop = None;
        Ok(())
    }

    /// Deliver what waits: up to `SENDS_PER_TICK` requests. A heartbeat goes only when `heartbeat` (the hub can say
    /// "nothing to report" truthfully); a service that moved ahead of an empty outbox is settled only when
    /// `may_produce` (settling may sign a reset).
    fn deliver(&mut self, heartbeat: bool, may_produce: bool) -> Result<(), AgentError> {
        for _ in 0..SENDS_PER_TICK {
            if self.stop.as_ref().is_some_and(|stop| stop.load(Ordering::SeqCst)) {
                break;
            }
            let outcome = if heartbeat {
                self.sender.step()?
            } else {
                self.sender.step_events()?
            };
            self.after(outcome)?;
            let more = match outcome {
                SendOutcome::Sent(_) => !self.sender.outbox().pending(1, None)?.is_empty(),
                SendOutcome::RetryNow => true,
                // The service moved under an outbox that has assigned nothing: the same decision as at the greeting.
                SendOutcome::ServiceAhead(_) => {
                    may_produce && self.settle()? && !self.sender.outbox().pending(1, None)?.is_empty()
                }
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

    /// What was last reported about a subject: from memory, or from the store the first time it is asked.
    fn facts(&mut self, scope: &str, identity: &str) -> Result<Map<String, Value>, AgentError> {
        let subject = (scope.to_owned(), identity.to_owned());
        if let Some(facts) = self.reported.get(&subject) {
            return Ok(facts.clone());
        }
        let facts = self.pseudonyms.facts(scope, identity)?;
        self.reported.insert(subject, facts.clone());
        Ok(facts)
    }

    /// Remember what was just reported: at once in memory, and in the store. A store that does not take it is
    /// returned as the error and tried again (`save_unsaved`); the report is not made again meanwhile.
    fn remember(&mut self, scope: &str, identity: &str, facts: Map<String, Value>) -> Option<AgentError> {
        let subject = (scope.to_owned(), identity.to_owned());
        let stored = self.pseudonyms.remember(scope, identity, &facts);
        self.reported.insert(subject.clone(), facts);
        match stored {
            Ok(()) => {
                self.unsaved.remove(&subject);
                None
            }
            Err(error) => {
                self.unsaved.insert(subject);
                Some(error.into())
            }
        }
    }

    /// Give the store what it did not take before. The first failure, if any.
    fn save_unsaved(&mut self) -> Option<AgentError> {
        let mut failed = None;
        let subjects: Vec<Subject> = self.unsaved.iter().cloned().collect();
        for subject in subjects {
            let Some(facts) = self.reported.get(&subject) else {
                self.unsaved.remove(&subject);
                continue;
            };
            match self.pseudonyms.remember(&subject.0, &subject.1, facts) {
                Ok(()) => {
                    self.unsaved.remove(&subject);
                }
                Err(error) => {
                    failed.get_or_insert(AgentError::from(error));
                }
            }
        }
        failed
    }

    /// Forget what was reported, in memory and in the store; keep the references.
    fn forget_facts(&mut self) -> Result<(), AgentError> {
        self.pseudonyms.forget_facts()?;
        self.reported.clear();
        self.unsaved.clear();
        Ok(())
    }

    fn report(&mut self, sightings: Vec<Sighting>, moment: i64, at: &str) -> Result<Option<AgentError>, AgentError> {
        let mut unsaved = self.save_unsaved();
        let mut lasting = Vec::with_capacity(sightings.len());
        let mut ephemeral: BTreeMap<String, u64> = BTreeMap::new();
        for sighting in sightings {
            if sighting.ephemeral {
                let count = ephemeral.entry(sighting.segment).or_default();
                *count = count.saturating_add(1);
            } else {
                let (segment, class, failed) = self.report_device(sighting, moment, at)?;
                if unsaved.is_none() {
                    unsaved = failed;
                }
                lasting.push((segment, class));
            }
        }
        // Every segment ever reported, so that one that has emptied still says so.
        let mut segments: BTreeSet<String> = self.pseudonyms.identities("segment")?.into_iter().collect();
        segments.extend(lasting.iter().map(|(segment, _)| segment.clone()));
        segments.extend(ephemeral.keys().cloned());
        for segment in segments {
            let classes = lasting.iter().filter(|(s, _)| *s == segment).map(|(_, class)| *class);
            let changing = ephemeral.get(&segment).copied().unwrap_or(0);
            let failed = self.report_snapshot(&segment, classes, changing, moment, at)?;
            if unsaved.is_none() {
                unsaved = failed;
            }
        }
        Ok(unsaved)
    }

    /// Report one device if anything is due; returns its segment, its checked class (for the snapshot), and the
    /// store's failure to take what was reported, if it failed.
    fn report_device(
        &mut self,
        sighting: Sighting,
        moment: i64,
        at: &str,
    ) -> Result<(String, &'static str, Option<AgentError>), AgentError> {
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
        let known = self.facts("device", &sighting.identity)?;
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
                return Ok((sighting.segment, device_class, None));
            }
        }
        // After the event is durably in the outbox: what was reported is now what the hub last said.
        facts.insert("toldAt".into(), Value::from(stored_text(moment)));
        let failed = self.remember("device", &sighting.identity, facts);
        Ok((sighting.segment, device_class, failed))
    }

    /// A segment's snapshot, if one is due; the store's failure to take what was reported, if it failed.
    fn report_snapshot(
        &mut self,
        segment: &str,
        classes: impl Iterator<Item = &'static str>,
        ephemeral: u64,
        moment: i64,
        at: &str,
    ) -> Result<Option<AgentError>, AgentError> {
        let known = self.facts("segment", segment)?;
        let last = known.get("snapshotAt").and_then(Value::as_str).and_then(stored_millis);
        if last.is_some_and(|last| !is_due(last, moment, SNAPSHOT_EVERY_MS)) {
            return Ok(None);
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
        Ok(self.remember("segment", segment, facts))
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
        let service = self.sender.trouble().map(|trouble| trouble.as_text());
        let text = status_file_text(
            self.sender.halted().map(HaltReason::as_str),
            self.waiting_for.map(WaitingFor::as_str),
            service.as_deref(),
            self.current_problem(),
        );
        if self.last_saved.as_deref() == Some(text.as_str()) {
            return;
        }
        match write_own_file(&self.config.state_dir.join(STATUS_FILE), text.as_bytes()) {
            Ok(()) => self.last_saved = Some(text),
            Err(_) => self.problem = Some("status_file_failed"),
        }
    }

    /// The state as one line for a person: halted (and how to resume), what it waits for, its problem. No device,
    /// name, address or file content. What `open` said in a notice (a store set aside) is not repeated here.
    fn state_line(&self) -> String {
        if let Some(reason) = self.sender.halted() {
            return format!(
                "halted: {reason} ({}); once that is dealt with: {}",
                halt_meaning(reason),
                self.resume_command
            );
        }
        let mut parts = Vec::new();
        match self.waiting_for {
            Some(WaitingFor::Service) => parts.push(match self.sender.trouble() {
                Some(trouble) => format!("waiting for the service ({})", trouble.as_text()),
                None => "waiting for the service (no answer yet)".to_owned(),
            }),
            Some(WaitingFor::Clock) => {
                parts.push("waiting for the clock (not set, or more than four minutes from the service's)".to_owned());
            }
            Some(WaitingFor::Unauthorized) => {
                parts.push("waiting: the service answers unauthorized (an unknown key, or a clock off)".to_owned());
            }
            Some(WaitingFor::Backlog) => {
                parts.push("waiting for the backlog to drain to half (capture is stopped)".to_owned());
            }
            None => {}
        }
        if let Some(problem) = self.problem {
            parts.push(format!("problem: {problem}"));
        }
        if parts.is_empty() {
            RUNNING.to_owned()
        } else {
            parts.join("; ")
        }
    }

    /// Note the state for `run` to report, if it changed.
    fn announce(&mut self) {
        let line = self.state_line();
        if line != self.announced {
            self.announcement = Some(format!("spacegoat-hub: {line}"));
            self.announced = line;
        }
    }
}

/// Whether a stop has lasted longer than `STOP_DECLARED_AFTER_SECONDS` at `mono`; one from an earlier run (its start
/// not on this run's monotonic clock) counts as long: it was kept because it was.
fn is_long(stop: CaptureStop, mono: i64) -> bool {
    stop.since_mono
        .is_none_or(|since| mono.saturating_sub(since) > STOP_DECLARED_AFTER_SECONDS * 1_000)
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

/// `run_reporting` without the reported lines.
pub fn run(agent: Agent, stop: Arc<AtomicBool>, sleep: impl FnMut(Duration)) -> Result<(), AgentError> {
    run_reporting(agent, stop, sleep, |_| {})
}

/// Tick every `TICK_SECONDS` of monotonic time until `stop` is set, then close. `sleep` is how time passes
/// (`std::thread::sleep` in the binary); the flag is looked at every 100 ms and between the requests of a tick.
/// `report` is given one line whenever what the status says changes (halted, what it waits for, its problem), never
/// one per tick.
///
/// A tick that fails does not end the run: its problem is in the status, the next tick comes after a back-off (5 s,
/// doubling, at most `TICK_BACKOFF_MAX_SECONDS`), and meanwhile what is queued is still delivered (but no heartbeat
/// goes out). Only closing can fail here.
pub fn run_reporting(
    mut agent: Agent,
    stop: Arc<AtomicBool>,
    mut sleep: impl FnMut(Duration),
    mut report: impl FnMut(&str),
) -> Result<(), AgentError> {
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
        if let Some(line) = agent.take_announcement() {
            report(&line);
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
/// the one this process creates files as (`expected_owner` stands for that user in tests); with `writable`, also one
/// this user cannot write. Never changed here: it may not be this agent's to change. Without `writable` nothing is
/// written in it (`status`).
pub fn check_state_dir(state_dir: &Path, expected_owner: Option<u32>, writable: bool) -> Result<(), AgentError> {
    let refuse = |why| AgentError::StateDirectory(state_dir.to_path_buf(), why);
    let found = match std::fs::metadata(state_dir) {
        Ok(found) => found,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(refuse("missing; run keygen first")),
        Err(_) => return Err(refuse("cannot be read")),
    };
    if !found.is_dir() {
        return Err(refuse("not a directory"));
    }
    if found.permissions().mode() & 0o077 != 0 {
        return Err(refuse("open to other users; use one only the hub's user can enter"));
    }
    let me = match expected_owner {
        Some(uid) => uid,
        None => current_uid().map_err(|error| AgentError::Io("the user this process runs as", error))?,
    };
    if found.uid() != me {
        // Whoever owns the directory can swap what is in it.
        return Err(refuse("belongs to another user"));
    }
    if writable {
        match create_temporary(state_dir, WRITE_CHECK_PREFIX) {
            Ok((file, path)) => {
                drop(file);
                match std::fs::remove_file(&path) {
                    // Swept by another agent's start meanwhile: gone either way.
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(AgentError::Io("state directory", error)),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Err(refuse("cannot be written by this user"));
            }
            Err(error) => return Err(AgentError::Io("state directory", error)),
        }
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

/// A moment as the pseudonym store keeps it: ISO 8601 with six fractional digits and the offset written as `+00:00`
/// (`2027-01-15T08:00:00.123000+00:00`). The form does not change, so a state directory written earlier still reads.
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
    fn a_stored_moment_reads_back_and_six_digit_fractions_are_read() {
        let moment = 1_800_000_000_123;
        assert_eq!(stored_millis(&stored_text(moment)), Some(moment));
        let six_digits = "2027-01-15T08:00:00.123456+00:00";
        assert_eq!(
            stored_millis(six_digits),
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
