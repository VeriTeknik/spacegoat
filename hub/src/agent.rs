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
//!   not into the attributes, not into `agent.json`, not into `status()`, not into an error, a reported line or the
//!   `Debug` form of a `Sighting`;
//! - whatever an observer hands over is checked before it is signed: a signed event never changes, so one the service
//!   would refuse would block the whole queue behind it. A field that does not fit is left out;
//! - what one round of capture produces is appended in one transaction (per `DEVICES_PER_COMMIT` devices), and what
//!   was reported is recorded in the pseudonym store in one more, after it: an event is either stored with its round or
//!   not at all, and one whose record could not be stored is not appended again (what was reported is kept in memory
//!   for the run, and the store write is retried). A failure to capture or to store never keeps what is queued from
//!   being delivered. A stored record that cannot be read counts as none: that device is announced again, and it is
//!   said once;
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
//!   service's number (`reinstall` when this hub remembers no confirmation, `queue_lost` when it does, when its mark
//!   cannot be understood, or when a person accepted the service's state with `resume --from-service`, then also
//!   when the service holds nothing); and a halt (`gap`) when the service holds less than it once confirmed. The hub
//!   never covers for a service that lost events;
//! - a halt is written to `halt.json` and survives a restart: a halted agent makes no request at all, heartbeats
//!   included, and produces no event until a person runs `spacegoat-hub resume`. A queue that grows while nothing can
//!   be delivered only makes the eventual backlog older than the service will accept;
//! - at most `MAX_PENDING_EVENTS` wait: beyond that the agent stops producing (`waitingFor: backlog`) and keeps
//!   delivering, until fewer than half wait. After a restart it is full only if that many wait;
//! - whenever the running hub could not capture for more than `STOP_DECLARED_AFTER_SECONDS` (its clock not trusted,
//!   its storage failing, halted, its backlog full), it says so once capture resumes, with one
//!   `site_source.input_lost` (`capture_stopped`, `fromTime` only when the stop began at a trusted time). The mark
//!   lives in the outbox and survives a restart; a stop that spans a restart is judged long by trusted wall time from
//!   its start (the restart's own downtime included), and a shorter stop is not declared. Time the hub was simply not
//!   running is not declared;
//! - while the last tick failed with a storage error, no keep-alive heartbeat goes out (it would say "alive, nothing
//!   to report", which is not true then; the service's silence alert is the signal). Events already queued are
//!   still delivered when the queue can be read;
//! - one agent runs on one state directory (a second one would hand out a second set of references and write into
//!   the same sequence): it holds an exclusive lock on `agent.lock` while it runs, and a second agent refuses to
//!   start. The kernel drops the lock when the process ends, however it ends;
//! - a storage file that is not a database any more (`outbox.sqlite`, `pseudonyms.sqlite`) is set aside as
//!   `<name>.damaged` and started anew, and said so; one a newer build wrote (its format version) is refused, as are
//!   `halt.json` and `confirmed.json` of a newer version; any other failure to open is an error. A name of the agent's
//!   own that holds a symbolic link or a directory is refused, by name, for a person to remove. A failure while
//!   running is a `problem` (its area) with a `cause` in the status, never the end of the process (`run`);
//! - `run` reports each change of what the status says (halted, what it waits for, its problem) as one line, never
//!   one per tick, and a state that flaps at most once per five minutes per kind of line; a halt is said at once;
//! - the clocks are injected (`clock::Clock`) and `tick` never sleeps; `run` sleeps through an injected function and
//!   measures every interval on the monotonic clock.
//!
//! The rule for devices whose identity keeps changing (protocol §9, the seven days) belongs to the real observers
//! and is not in this version: an observer says whether a sighting is ephemeral.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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

use crate::clock::{self, Clock};
use crate::config::Config;
use crate::fsutil::{fsync_directory, is_temporary_of, non_file_kind, open_regular, private_file, write_own_file};
use crate::keystore::{FileKeyStore, KeyStoreError};
use crate::outbox::{NewEvent, Outbox, OutboxError, ResetReason, database_is_damaged};
use crate::sender::{self, HaltReason, OriginError, Problem, SendOutcome, Sender, SenderError};
use crate::state::{Confirmed, Mark, Pseudonyms, StateError};
use crate::statedir::{self, Access, StateDirError};
use crate::storage::Cause;

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
/// A stop in capture longer than this is declared (`site_source.input_lost`) when capture resumes.
pub const STOP_DECLARED_AFTER_SECONDS: i64 = 300;
/// The same line kind is reported at most once in this many seconds of monotonic time (a halt: always at once).
pub const REPORT_EVERY_SECONDS: i64 = 300;
/// At most this many devices' events go into one transaction of the outbox (and one of the pseudonym store).
pub const DEVICES_PER_COMMIT: usize = 200;
/// How often `run` looks at the stop flag while it waits.
const STOP_POLL: Duration = Duration::from_millis(100);
/// `agent.json` and `halt.json` are a few short fields; anything larger is not one, and is not read whole.
const MAX_SMALL_FILE: u64 = 64 * 1024;
/// The format of `halt.json` and `agent.json` this code writes (their `version` field).
pub const SMALL_FILE_VERSION: u64 = 1;

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
/// Every name this program writes through a temporary file in the state directory (`fsutil::write_atomic`, the key's
/// installation, the state directory's probe). The one list: the temporary names are made from these
/// (`fsutil::temporary_prefix`), and only names of exactly that form are ever removed as leftovers.
pub const TEMPORARY_NAMES: [&str; 6] = [
    STATUS_FILE,
    CONFIRMED_FILE,
    HALT_FILE,
    KEY_FILE,
    KEY_ID_FILE,
    statedir::PROBE_NAME,
];

/// The agent's clocks, shared with the sender.
pub type SharedClock = Arc<dyn Clock>;

/// One device as an observer sees it at one moment. `identity` and `segment` are local to the hub (how it recognises
/// a device and a network) and are never reported; the service sees only their random references.
///
/// An `ephemeral` sighting is a device whose identity keeps changing: it is counted in its segment's snapshot and
/// nothing else is done with it (no event, no reference, nothing kept).
///
/// Its `Debug` form shows the class and whether it is ephemeral; the identity, the segment, the hardware address,
/// the name and the IP address are personal or local and are shown as `<redacted>` (or `None`).
#[derive(Clone, PartialEq, Eq)]
pub struct Sighting {
    pub identity: String,
    pub segment: String,
    pub device_class: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub ephemeral: bool,
}

impl fmt::Debug for Sighting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hidden = |value: &Option<String>| value.as_ref().map(|_| "<redacted>");
        f.debug_struct("Sighting")
            .field("identity", &"<redacted>")
            .field("segment", &"<redacted>")
            .field("device_class", &self.device_class)
            .field("mac", &hidden(&self.mac))
            .field("hostname", &hidden(&self.hostname))
            .field("ip", &hidden(&self.ip))
            .field("ephemeral", &self.ephemeral)
            .finish()
    }
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
    /// The state directory is not one the hub may keep its key and records in (`statedir::check`).
    StateDirectory(StateDirError),
    /// Another agent holds the state directory's lock.
    AlreadyRunning(PathBuf),
    /// A name of the agent's own (`OWN_FILES`) holds something other than a regular file: the name, and what it holds.
    NotAFile(&'static str, &'static str),
    /// A small file of the agent's own (`halt.json`, `confirmed.json`) was written by a newer version: its name and
    /// the version it records.
    NewerFormat(&'static str, u64),
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
    /// A database of the agent's own, by name, that could not be looked at.
    Sqlite(&'static str, rusqlite::Error),
}

impl AgentError {
    /// A short reason with no values in it (no path, no content): what the status shows as its `problem`. It names
    /// the area the failure is in: the file it happened to, or the part of the hub.
    pub fn problem(&self) -> &'static str {
        match self {
            Self::Outbox(_) | Self::Sender(SenderError::Outbox(_)) => "outbox_failed",
            Self::Sender(SenderError::Compress(_)) => "compress_failed",
            Self::State(_) => "pseudonyms_failed",
            Self::Io(name, _) | Self::NewerFormat(name, _) | Self::Sqlite(name, _) => file_area(name),
            Self::StateDirectory(_) | Self::AlreadyRunning(_) | Self::NotAFile(..) => "state_directory_failed",
            Self::NotAGap(_) | Self::QueueHoldsNumbers => "resume_refused",
            Self::Key(_) | Self::KeyIdMismatch { .. } => "key_failed",
            Self::Origin(_) => "configuration_failed",
        }
    }

    /// What kind of storage failure it is, for the errors that are one (`storage::Cause`); `None` for the others.
    pub fn cause(&self) -> Option<Cause> {
        match self {
            Self::Outbox(error) | Self::Sender(SenderError::Outbox(error)) => Some(error.cause()),
            Self::Sender(SenderError::Compress(error)) | Self::Io(_, error) => Some(Cause::of_io(error)),
            Self::State(error) => Some(error.cause()),
            Self::Sqlite(_, error) => Some(Cause::of_sqlite(error)),
            _ => None,
        }
    }

    /// Whether the error means the command could not start (the state directory, a file of its own that is not a
    /// file or a newer version's, the key, the configuration, the lock), as opposed to having run and failed.
    pub fn could_not_start(&self) -> bool {
        matches!(
            self,
            Self::StateDirectory(_)
                | Self::AlreadyRunning(_)
                | Self::NotAFile(..)
                | Self::NewerFormat(..)
                | Self::KeyIdMismatch { .. }
                | Self::Key(_)
                | Self::Origin(_)
                | Self::Outbox(OutboxError::Format(_))
                | Self::State(StateError::Format(_))
        )
    }
}

/// The status's area for a failure at a file of the agent's own.
fn file_area(name: &str) -> &'static str {
    match name {
        CONFIRMED_FILE => "confirmed_failed",
        HALT_FILE => "halt_file_failed",
        STATUS_FILE => "status_file_failed",
        OUTBOX_FILE => "outbox_failed",
        PSEUDONYMS_FILE => "pseudonyms_failed",
        _ => "state_directory_failed",
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateDirectory(error) => error.fmt(f),
            Self::AlreadyRunning(path) => write!(f, "another agent is already running on {}", path.display()),
            Self::NotAFile(name, kind) => write!(
                f,
                "{name} in the state directory is {kind}, not a file the hub wrote; a person must look at it and \
                 remove it by hand"
            ),
            Self::NewerFormat(name, version) => write!(
                f,
                "{name} was written by a newer version of spacegoat-hub (version {version}; this one writes \
                 {SMALL_FILE_VERSION}) and is not read as anything else: run that version again, or a person must \
                 look at it"
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
            Self::Sqlite(what, error) => write!(f, "{what}: {error}"),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StateDirectory(error) => Some(error),
            Self::Key(error) => Some(error),
            Self::Origin(error) => Some(error),
            Self::Outbox(error) => Some(error),
            Self::State(error) => Some(error),
            Self::Sender(error) => Some(error),
            Self::Io(_, error) => Some(error),
            Self::Sqlite(_, error) => Some(error),
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

impl From<StateDirError> for AgentError {
    fn from(error: StateDirError) -> Self {
        Self::StateDirectory(error)
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
    /// The area of the hub's own trouble (`AgentError::problem`, or what opening set right).
    pub problem: Option<String>,
    /// Its cause, when it is a storage failure (`storage::Cause::as_str`).
    pub cause: Option<String>,
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
             \"problem\": {},\n  \"cause\": {},\n  \"resume\": {}\n}}",
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
            text(self.cause.as_deref()),
            text(self.resume.as_deref()),
        )
    }
}

/// What the agent last saved in `agent.json`: why it is waiting, the kind of answer the service last gave, its
/// problem and that problem's cause.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavedStatus {
    pub waiting_for: Option<String>,
    pub service: Option<String>,
    pub problem: Option<String>,
    pub cause: Option<String>,
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
        cause: saved.cause,
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

/// (waitingFor, service, problem, cause) as the agent last saved them in `agent.json`. The file is advisory: one of
/// another version, or that cannot be understood, says nothing (and the agent writes it anew).
pub fn read_saved_status(state_dir: &Path) -> io::Result<SavedStatus> {
    let Some(saved) = read_small_object(&state_dir.join(STATUS_FILE))? else {
        return Ok(SavedStatus::default());
    };
    if saved.get("version").and_then(Value::as_u64) != Some(SMALL_FILE_VERSION) {
        return Ok(SavedStatus::default());
    }
    let text = |name: &str| saved.get(name).and_then(Value::as_str).map(str::to_owned);
    Ok(SavedStatus {
        waiting_for: text("waitingFor"),
        service: text("service"),
        problem: text("problem"),
        cause: text("cause"),
    })
}

/// The halt recorded in `halt.json`, if there is one. A file that is there but cannot be understood is still a halt
/// (reason `unknown`): a halt is cleared by a person, never by damage. One a newer version wrote is refused.
pub fn read_halt(state_dir: &Path) -> Result<Option<RecordedHalt>, AgentError> {
    let path = state_dir.join(HALT_FILE);
    if let Err(error) = std::fs::symlink_metadata(&path) {
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(AgentError::Io(HALT_FILE, error))
        };
    }
    let saved = read_small_object(&path)
        .map_err(|error| AgentError::Io(HALT_FILE, error))?
        .unwrap_or_default();
    let version = saved.get("version").and_then(Value::as_u64);
    if let Some(newer) = version.filter(|version| *version > SMALL_FILE_VERSION) {
        return Err(AgentError::NewerFormat(HALT_FILE, newer));
    }
    let understood = version == Some(SMALL_FILE_VERSION);
    let reason = saved.get("reason").and_then(Value::as_str).filter(|_| understood);
    Ok(Some(RecordedHalt {
        reason: HaltReason::from_text(reason.unwrap_or_default()).as_str().to_owned(),
        at: saved
            .get("at")
            .and_then(Value::as_str)
            .filter(|_| understood)
            .map(str::to_owned),
    }))
}

fn write_halt(state_dir: &Path, reason: HaltReason, wall_millis: i64) -> io::Result<()> {
    let at = clock::observed_at_text(wall_millis)
        .filter(|_| clock::clock_is_set(wall_millis))
        .map_or(Value::Null, Value::from);
    let text = format!(
        "{{\"version\": {SMALL_FILE_VERSION}, \"reason\": {}, \"at\": {}}}",
        Value::from(reason.as_str()),
        at
    );
    write_own_file(&state_dir.join(HALT_FILE), text.as_bytes())
}

/// `agent.json`'s text: why the agent is waiting, the kind of answer the service last gave, its problem and its
/// cause, and nothing else. The halt is not repeated here: `halt.json` is the one record of it.
fn status_file_text(saved: &SavedStatus) -> String {
    let text = |value: &Option<String>| value.as_deref().map_or(Value::Null, Value::from).to_string();
    format!(
        "{{\"version\": {SMALL_FILE_VERSION}, \"waitingFor\": {}, \"service\": {}, \"problem\": {}, \"cause\": {}}}",
        text(&saved.waiting_for),
        text(&saved.service),
        text(&saved.problem),
        text(&saved.cause),
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

/// Check the state directory as `access` needs it (`statedir::check`, the check `keygen` makes too).
pub fn check_state_dir(state_dir: &Path, access: Access, expected_owner: Option<u32>) -> Result<(), AgentError> {
    statedir::check(state_dir, access, expected_owner, &state_dir.join(KEY_FILE))?;
    Ok(())
}

/// What `resume` is asked to do beyond clearing the halt.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResumeOptions {
    /// The user the state directory must belong to (tests); by default the user this process creates files as.
    pub expected_owner: Option<u32>,
    /// Also record that the hub takes the service's state as its starting point (`Mark::AcceptService`): at its next
    /// greeting it declares a lost queue at the service's number. The way out of a `gap` halt, for an outbox that
    /// has never assigned a number.
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
/// The order: everything is checked first; `halt.json` is removed (and the directory synced); only then, with
/// `from_service`, is the confirmed mark replaced, the one step that cannot be taken back. If removing fails, the hub
/// is still halted and nothing else changed. If the mark cannot be written after the halt was cleared, the old mark
/// is still there: the hub halts again with `gap` at its next start, and `resume --from-service` can be run again.
#[doc(hidden)]
pub fn resume_with(
    config: &Config,
    options: ResumeOptions,
    remove: &dyn Fn(&Path) -> io::Result<()>,
) -> Result<Option<RecordedHalt>, AgentError> {
    let state_dir = &config.state_dir;
    check_state_dir(state_dir, Access::Write, options.expected_owner)?;
    check_own_files(state_dir)?;
    let lock = lock_state_dir(state_dir)?;
    let Some(halt) = read_halt(state_dir)? else {
        return Ok(None);
    };
    let confirmed = Confirmed::new(state_dir.join(CONFIRMED_FILE), &config.source_id);
    if options.from_service {
        if halt.reason != HaltReason::Gap.as_str() {
            return Err(AgentError::NotAGap(halt.reason));
        }
        let (assigned, _) = Outbox::read_counters(&state_dir.join(OUTBOX_FILE))?;
        if assigned != 0 {
            return Err(AgentError::QueueHoldsNumbers);
        }
        if let Mark::Newer(version) = confirmed
            .read()
            .map_err(|error| AgentError::Io(CONFIRMED_FILE, error))?
        {
            return Err(AgentError::NewerFormat(CONFIRMED_FILE, version));
        }
    }
    remove(&state_dir.join(HALT_FILE)).map_err(|error| AgentError::Io(HALT_FILE, error))?;
    fsync_directory(state_dir).map_err(|error| AgentError::Io(HALT_FILE, error))?;
    if options.from_service {
        confirmed
            .accept_service()
            .map_err(|error| AgentError::Io(CONFIRMED_FILE, error))?;
    }
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

/// What the hub's own trouble is: the area (`AgentError::problem`) and, for a storage failure, its cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OwnProblem {
    area: &'static str,
    cause: Option<Cause>,
}

impl OwnProblem {
    fn of(error: &AgentError) -> Self {
        Self {
            area: error.problem(),
            cause: error.cause(),
        }
    }
}

/// One event a round of capture is about to append, and what is recorded about its subject once it is stored.
struct Planned {
    kind: &'static str,
    attributes: Map<String, Value>,
    pii: Option<Map<String, Value>>,
    subject: Subject,
    facts: Map<String, Value>,
}

/// What `run` prints when nothing is wrong: the state a healthy run starts from, so it says nothing.
const RUNNING: &str = "running normally";
/// The kind of a halt's line: reported at once, always.
const HALTED_KIND: &str = "halted";

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
    /// What went wrong in the last tick.
    problem: Option<OwnProblem>,
    /// The confirmed mark could not be written and has not been since: its problem stays until it is.
    confirmed_behind: Option<OwnProblem>,
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
    /// Whether a stored record of facts that could not be read has been said this run.
    unreadable_said: bool,
    resume_command: String,
    /// The state `run` last reported (or the healthy one it starts from), and its kind.
    announced: String,
    announced_kind: String,
    /// When each kind of line was last reported (monotonic milliseconds).
    reported_at: HashMap<String, i64>,
    /// The lines not taken yet.
    lines: VecDeque<String>,
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
        check_state_dir(state_dir, Access::Write, settings.expected_owner)?;
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
        let halt = read_halt(state_dir)?;
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
            Ok(Mark::Newer(version)) => return Err(AgentError::NewerFormat(CONFIRMED_FILE, version)),
            // A person's decision, carried out already: the queue that numbered events began with its reset. (A
            // crash between the reset and the mark that follows it leaves this.)
            Ok(Mark::AcceptService) if assigned > 0 => {
                let _ = confirmed.replace(acked);
            }
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
            Ok(Mark::Nothing | Mark::Confirmed(_) | Mark::AcceptService) => {}
            Err(error) => return Err(AgentError::Io(CONFIRMED_FILE, error)),
        }
        let capture_stop = outbox.capture_stop()?.map(|since_wall| CaptureStop {
            since_mono: None,
            since_wall,
            persisted: true,
        });
        let backlog_cap = u64::try_from(settings.backlog_cap.max(1)).unwrap_or(u64::MAX);
        // Full only if it is: a mark and a queue above half are what a stop of another kind leaves too.
        let backlog_full = assigned.saturating_sub(acked) >= backlog_cap;
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
            confirmed_behind: None,
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
            unreadable_said: false,
            resume_command: "spacegoat-hub resume --config FILE".to_owned(),
            announced: RUNNING.to_owned(),
            announced_kind: "running".to_owned(),
            reported_at: HashMap::new(),
            lines: VecDeque::new(),
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
            self.problem = Some(OwnProblem::of(error));
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

    /// Between ticks, after a tick that failed (`run` comes here only then): the delivery of what is queued, never a
    /// heartbeat, which would say "alive, nothing to report". Never fails.
    pub fn keep_alive(&mut self) {
        if self.sender.halted().is_none() && clock::clock_is_set(self.clock.wall_millis()) {
            match self.sender.step_events() {
                Ok(outcome) => {
                    if let Err(error) = self.after(outcome) {
                        self.problem = Some(OwnProblem::of(&error));
                    }
                }
                Err(error) => self.problem = Some(OwnProblem::of(&AgentError::Sender(error))),
            }
        }
        self.persist_halt();
        self.save_status();
        self.announce();
    }

    /// The next line `run` reports (a change of state, or something said once); `None` when there is none.
    pub fn take_announcement(&mut self) -> Option<String> {
        self.lines.pop_front()
    }

    /// Where the hub stands now: counts and state only.
    pub fn status(&self) -> Result<Status, AgentError> {
        let outbox = self.sender.outbox();
        let counters = (outbox.last_assigned()?, outbox.last_acked()?);
        let halt = self.sender.halted().map(|reason| RecordedHalt {
            reason: reason.as_str().to_owned(),
            at: None,
        });
        Ok(read_status(
            &self.config,
            counters,
            halt,
            self.saved(),
            &self.resume_command,
        ))
    }

    /// The status as `agent.json` keeps it.
    fn saved(&self) -> SavedStatus {
        let problem = self.current_problem();
        SavedStatus {
            waiting_for: self.waiting_for.map(|waiting| waiting.as_str().to_owned()),
            service: self.sender.trouble().map(|trouble| trouble.as_text()),
            problem: problem.map(|problem| problem.area.to_owned()),
            cause: problem
                .and_then(|problem| problem.cause)
                .map(|cause| cause.as_str().to_owned()),
        }
    }

    /// The trouble of this tick, else a confirmed mark still not written, else what opening set right.
    fn own_problem(&self) -> Option<OwnProblem> {
        self.problem.or(self.confirmed_behind)
    }

    fn current_problem(&self) -> Option<OwnProblem> {
        self.own_problem()
            .or(self.replaced.map(|area| OwnProblem { area, cause: None }))
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
        let mark = if self.confirmed_unknown {
            Mark::NotUnderstood
        } else {
            self.confirmed
                .read()
                .map_err(|error| AgentError::Io(CONFIRMED_FILE, error))?
        };
        let reason = match (mark, held) {
            (Mark::Newer(version), _) => return Err(AgentError::NewerFormat(CONFIRMED_FILE, version)),
            // A person accepted the service's state: a lost queue at the service's number, whatever it is (a reset
            // as event 1, `lastAckedSeq` 0, when the service holds nothing).
            (Mark::AcceptService, _) => Some(ResetReason::QueueLost),
            // Confirmed something once, nobody knows how much: the gap rule cannot be applied. What the service
            // holds is taken as the starting point and declared as a lost queue.
            (Mark::NotUnderstood, 0) => None,
            (Mark::NotUnderstood, _) => Some(ResetReason::QueueLost),
            (Mark::Nothing | Mark::Confirmed(0), 0) => None,
            (Mark::Nothing | Mark::Confirmed(0), _) => Some(ResetReason::Reinstall),
            (Mark::Confirmed(confirmed), held) if held >= confirmed => Some(ResetReason::QueueLost),
            // The service holds less than it once confirmed: it lost events. The hub does not cover for that.
            (Mark::Confirmed(_), _) => {
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

    /// One round of capture, unless the backlog is full. `Err`: capture failed (nothing of this round was stored).
    /// `Ok(Some(_))`: everything due was stored, but the pseudonym store did not take what was reported.
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
        if stop.persisted || !(persist_now || self.is_long(stop)) {
            return;
        }
        if self.sender.outbox_mut().stop_capture(stop.since_wall).is_ok() {
            self.capture_stop = Some(CaptureStop {
                persisted: true,
                ..stop
            });
        }
    }

    /// Whether a stop has lasted longer than `STOP_DECLARED_AFTER_SECONDS`: on this run's monotonic clock when it
    /// began in this run; else by trusted wall time from its trusted start; a stop whose start is not known at all
    /// (it began before this run, at a time that was not trusted) counts as long: it was kept because it was.
    fn is_long(&self, stop: CaptureStop) -> bool {
        let limit = STOP_DECLARED_AFTER_SECONDS * 1_000;
        match (stop.since_mono, stop.since_wall, self.trusted_wall()) {
            (Some(since), _, _) => self.clock.mono_millis().saturating_sub(since) > limit,
            (None, Some(since), Some(now)) => now.saturating_sub(since) > limit,
            _ => true,
        }
    }

    /// Capture works again: a stop longer than `STOP_DECLARED_AFTER_SECONDS` is declared with one
    /// `site_source.input_lost`, and the mark is cleared in the same transaction; a shorter one is forgotten.
    fn end_stop(&mut self, wall: i64, at: &str) -> Result<(), AgentError> {
        let Some(stop) = self.capture_stop else {
            return Ok(());
        };
        let long = self.is_long(stop);
        let outbox = self.sender.outbox_mut();
        let mark = outbox.capture_stop()?;
        if !long {
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
    /// written again with the next answer, and the problem stays until it is.
    fn write_confirmed(&mut self, last_acked_seq: u64) {
        match self.confirmed.write(last_acked_seq) {
            Ok(()) => self.confirmed_behind = None,
            Err(error) => {
                self.confirmed_behind = Some(OwnProblem::of(&AgentError::Io(CONFIRMED_FILE, error)));
            }
        }
    }

    /// What was last reported about a subject: what this round has planned already, else from memory, else from the
    /// store the first time it is asked. A stored record that cannot be read counts as none (the subject is reported
    /// again) and is said once a run.
    fn facts(
        &mut self,
        planned: &HashMap<Subject, Map<String, Value>>,
        scope: &str,
        identity: &str,
    ) -> Result<Map<String, Value>, AgentError> {
        let subject = (scope.to_owned(), identity.to_owned());
        if let Some(facts) = planned.get(&subject).or_else(|| self.reported.get(&subject)) {
            return Ok(facts.clone());
        }
        let facts = match self.pseudonyms.facts(scope, identity) {
            Ok(facts) => facts,
            Err(StateError::Damaged(_)) => {
                if !self.unreadable_said {
                    self.unreadable_said = true;
                    self.lines.push_back(format!(
                        "spacegoat-hub: {PSEUDONYMS_FILE} holds a record of what was reported that cannot be read; \
                         that device or segment is reported again (under the same reference)"
                    ));
                }
                Map::new()
            }
            Err(error) => return Err(error.into()),
        };
        self.reported.insert(subject, facts.clone());
        Ok(facts)
    }

    /// Give the store what it did not take before, in one transaction. Its failure, if it failed.
    fn save_unsaved(&mut self) -> Option<AgentError> {
        let subjects: Vec<Subject> = self
            .unsaved
            .iter()
            .filter(|subject| self.reported.contains_key(*subject))
            .cloned()
            .collect();
        let reports: Vec<(&str, &str, &Map<String, Value>)> = subjects
            .iter()
            .filter_map(|subject| {
                self.reported
                    .get(subject)
                    .map(|facts| (subject.0.as_str(), subject.1.as_str(), facts))
            })
            .collect();
        match self.pseudonyms.remember_all(&reports) {
            Ok(()) => {
                self.unsaved.clear();
                None
            }
            Err(error) => Some(error.into()),
        }
    }

    /// Forget what was reported, in memory and in the store; keep the references.
    fn forget_facts(&mut self) -> Result<(), AgentError> {
        self.pseudonyms.forget_facts()?;
        self.reported.clear();
        self.unsaved.clear();
        Ok(())
    }

    /// Report what this round saw: the events in one outbox transaction per `DEVICES_PER_COMMIT` devices (the
    /// snapshots go with the last), and what was reported in one pseudonym-store transaction after each.
    fn report(&mut self, sightings: Vec<Sighting>, moment: i64, at: &str) -> Result<Option<AgentError>, AgentError> {
        let mut unsaved = self.save_unsaved();
        let mut lasting = Vec::with_capacity(sightings.len());
        let mut ephemeral: BTreeMap<String, u64> = BTreeMap::new();
        for sighting in sightings {
            if sighting.ephemeral {
                let count = ephemeral.entry(sighting.segment).or_default();
                *count = count.saturating_add(1);
            } else {
                lasting.push(sighting);
            }
        }
        // Every segment ever reported, so that one that has emptied still says so; and its counts per class.
        let mut segments: BTreeSet<String> = self.pseudonyms.identities("segment")?.into_iter().collect();
        segments.extend(lasting.iter().map(|sighting| sighting.segment.clone()));
        segments.extend(ephemeral.keys().cloned());
        let classes: Vec<(String, &'static str)> = lasting
            .iter()
            .map(|sighting| (sighting.segment.clone(), checked_class(&sighting.device_class)))
            .collect();
        let chunks: Vec<&[Sighting]> = if lasting.is_empty() {
            vec![&[]]
        } else {
            lasting.chunks(DEVICES_PER_COMMIT).collect()
        };
        let last = chunks.len().saturating_sub(1);
        for (index, chunk) in chunks.into_iter().enumerate() {
            let mut subjects: Vec<(&str, &str)> = Vec::new();
            for sighting in chunk {
                subjects.push(("device", &sighting.identity));
                subjects.push(("segment", &sighting.segment));
            }
            if index == last {
                subjects.extend(segments.iter().map(|segment| ("segment", segment.as_str())));
            }
            // The references first, in their own transaction: an event is never stored with a reference the store
            // could still lose.
            let refs: HashMap<(String, String), String> = subjects
                .iter()
                .map(|(scope, identity)| ((*scope).to_owned(), (*identity).to_owned()))
                .zip(self.pseudonyms.references(&subjects)?)
                .collect();
            let mut plans = Vec::new();
            let mut planned: HashMap<Subject, Map<String, Value>> = HashMap::new();
            for sighting in chunk {
                if let Some(plan) = self.plan_device(sighting, &refs, &planned, moment)? {
                    planned.insert(plan.subject.clone(), plan.facts.clone());
                    plans.push(plan);
                }
            }
            if index == last {
                for segment in &segments {
                    let counted = classes.iter().filter(|(s, _)| s == segment).map(|(_, class)| *class);
                    let changing = ephemeral.get(segment).copied().unwrap_or(0);
                    if let Some(plan) = self.plan_snapshot(segment, counted, changing, &refs, &planned, moment)? {
                        plans.push(plan);
                    }
                }
            }
            let failed = self.commit(plans, at)?;
            if unsaved.is_none() {
                unsaved = failed;
            }
        }
        Ok(unsaved)
    }

    /// Store what a round planned: the events in one transaction (all or none; `Err` when none), then what was
    /// reported, kept in memory at once and in the store in one more (its failure is returned, and retried).
    fn commit(&mut self, plans: Vec<Planned>, at: &str) -> Result<Option<AgentError>, AgentError> {
        if plans.is_empty() {
            return Ok(None);
        }
        let events: Vec<NewEvent<'_>> = plans
            .iter()
            .map(|plan| NewEvent {
                kind: plan.kind,
                observed_at: at,
                attributes: &plan.attributes,
                pii: plan.pii.as_ref(),
            })
            .collect();
        self.sender.outbox_mut().append_all(&events)?;
        // After the events are durably in the outbox: what was reported is now what the hub last said.
        for plan in &plans {
            self.reported.insert(plan.subject.clone(), plan.facts.clone());
        }
        let reports: Vec<(&str, &str, &Map<String, Value>)> = plans
            .iter()
            .map(|plan| (plan.subject.0.as_str(), plan.subject.1.as_str(), &plan.facts))
            .collect();
        match self.pseudonyms.remember_all(&reports) {
            Ok(()) => Ok(None),
            Err(error) => {
                self.unsaved.extend(plans.into_iter().map(|plan| plan.subject));
                Ok(Some(error.into()))
            }
        }
    }

    /// The event one device is due, if any.
    fn plan_device(
        &mut self,
        sighting: &Sighting,
        refs: &HashMap<(String, String), String>,
        planned: &HashMap<Subject, Map<String, Value>>,
        moment: i64,
    ) -> Result<Option<Planned>, AgentError> {
        let reference = |scope: &str, identity: &str| {
            refs.get(&(scope.to_owned(), identity.to_owned()))
                .cloned()
                .ok_or(AgentError::State(StateError::Damaged("a reference that was not made")))
        };
        let mut attributes = Map::new();
        attributes.insert("trustOrigin".into(), Value::from("hub"));
        attributes.insert(
            "deviceRef".into(),
            Value::from(reference("device", &sighting.identity)?),
        );
        attributes.insert(
            "segmentRef".into(),
            Value::from(reference("segment", &sighting.segment)?),
        );
        let known = self.facts(planned, "device", &sighting.identity)?;
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
        let pii = (!pii.is_empty()).then_some(pii);
        let (kind, pii) = if known.is_empty() {
            attributes.insert("deviceClass".into(), Value::from(device_class));
            ("site.device_appeared", pii)
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
                ("site.device_changed", pii)
            } else if told_at.is_none_or(|told| is_due(told, moment, SEEN_EVERY_MS)) {
                ("site.device_seen", None)
            } else {
                return Ok(None);
            }
        };
        facts.insert("toldAt".into(), Value::from(stored_text(moment)));
        Ok(Some(Planned {
            kind,
            attributes,
            pii,
            subject: ("device".to_owned(), sighting.identity.clone()),
            facts,
        }))
    }

    /// A segment's snapshot, if one is due.
    fn plan_snapshot(
        &mut self,
        segment: &str,
        classes: impl Iterator<Item = &'static str>,
        ephemeral: u64,
        refs: &HashMap<(String, String), String>,
        planned: &HashMap<Subject, Map<String, Value>>,
        moment: i64,
    ) -> Result<Option<Planned>, AgentError> {
        let known = self.facts(planned, "segment", segment)?;
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
        let reference = refs
            .get(&("segment".to_owned(), segment.to_owned()))
            .cloned()
            .ok_or(AgentError::State(StateError::Damaged("a reference that was not made")))?;
        let mut attributes = Map::new();
        attributes.insert("trustOrigin".into(), Value::from("hub"));
        attributes.insert("segmentRef".into(), Value::from(reference));
        attributes.insert("counts".into(), Value::Object(counts));
        attributes.insert("ephemeral".into(), Value::from(ephemeral));
        let mut facts = Map::new();
        facts.insert("snapshotAt".into(), Value::from(stored_text(moment)));
        Ok(Some(Planned {
            kind: "site.inventory_snapshot",
            attributes,
            pii: None,
            subject: ("segment".to_owned(), segment.to_owned()),
            facts,
        }))
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
            Err(error) => self.problem = Some(OwnProblem::of(&AgentError::Io(HALT_FILE, error))),
        }
    }

    /// `agent.json`, written only when its text changes. Best effort: a failure is the status's problem.
    fn save_status(&mut self) {
        let text = status_file_text(&self.saved());
        if self.last_saved.as_deref() == Some(text.as_str()) {
            return;
        }
        match write_own_file(&self.config.state_dir.join(STATUS_FILE), text.as_bytes()) {
            Ok(()) => self.last_saved = Some(text),
            Err(error) => self.problem = Some(OwnProblem::of(&AgentError::Io(STATUS_FILE, error))),
        }
    }

    /// The state as one line for a person, and the kind of line it is (what is wrong, without the details that
    /// change while it stays wrong): halted (and how to resume), what it waits for, its problem and cause. No device,
    /// name, address or file content. What `open` said in a notice (a store set aside) is not repeated here.
    fn state_line(&self) -> (String, String) {
        if let Some(reason) = self.sender.halted() {
            let line = format!(
                "halted: {reason} ({}); once that is dealt with: {}",
                halt_meaning(reason),
                self.resume_command
            );
            return (HALTED_KIND.to_owned(), line);
        }
        let mut parts = Vec::new();
        let mut kind = Vec::new();
        if let Some(waiting) = self.waiting_for {
            kind.push(waiting.as_str());
        }
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
        if let Some(problem) = self.own_problem() {
            kind.push(problem.area);
            parts.push(match problem.cause {
                Some(cause) => format!("problem: {} ({})", problem.area, cause.as_str()),
                None => format!("problem: {}", problem.area),
            });
        }
        if parts.is_empty() {
            ("running".to_owned(), RUNNING.to_owned())
        } else {
            (kind.join("+"), parts.join("; "))
        }
    }

    /// Note the state for `run` to report, if it changed: at once when it is the first line of its kind in
    /// `REPORT_EVERY_SECONDS`, or a halt; otherwise it waits, and is reported once that time is up if it still
    /// holds.
    fn announce(&mut self) {
        let (kind, line) = self.state_line();
        if line == self.announced {
            return;
        }
        let now = self.clock.mono_millis();
        let urgent = kind == HALTED_KIND || self.announced_kind == HALTED_KIND;
        let free = self
            .reported_at
            .get(&kind)
            .is_none_or(|at| now.saturating_sub(*at) >= REPORT_EVERY_SECONDS * 1_000);
        if urgent || free {
            self.lines.push_back(format!("spacegoat-hub: {line}"));
            self.reported_at.insert(kind.clone(), now);
            self.announced = line;
            self.announced_kind = kind;
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
            .field("problem", &self.current_problem().map(|problem| problem.area))
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
/// one per tick, and a line said once (an unreadable record).
///
/// A tick that fails does not end the run: its problem is in the status, the next tick comes after a back-off
/// (`sender::backoff_seconds`, the sender's own rule), and meanwhile what is queued is still delivered (`keep_alive`,
/// no heartbeat). Only closing can fail here.
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
                    next_tick = now.saturating_add(millis(sender::backoff_seconds(failures)));
                    failures = failures.saturating_add(1);
                }
            }
        } else {
            // Woken before the tick, which happens only after a failed one with a back-off longer than a tick.
            agent.keep_alive();
        }
        while let Some(line) = agent.take_announcement() {
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

/// Whether `name` is one of this program's temporary file names (`TEMPORARY_NAMES`, `fsutil::is_temporary_of`).
fn is_our_temporary(name: &str) -> bool {
    TEMPORARY_NAMES.iter().any(|own| is_temporary_of(own, name))
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
    if !database_is_damaged(path).map_err(|error| AgentError::Sqlite(what, error))? {
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
