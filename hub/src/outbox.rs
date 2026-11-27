// SPDX-License-Identifier: AGPL-3.0-or-later
//! The outbox: the hub's durable, ordered queue of signed events.
//!
//! An observation becomes an event here, in one transaction: it takes the next sequence number, its personal data
//! gets a fresh nonce and a commitment, it is signed, and the exact JSON that will be sent is stored. From then on the
//! event never changes: a delivery that fails is tried again with the same number and the same signature (the stored
//! text is returned byte for byte, never rebuilt or signed again), and the service recognises it. Nothing is signed
//! twice and no number is used twice.
//!
//! If the process dies before the transaction commits, neither the event nor its number exists. If it dies after, the
//! event is on disk and will be sent. There is no state in between.
//!
//! The file belongs to one source. It also remembers what the service last confirmed, so a hub that lost everything
//! else can still say truthfully where it stood (`declare_reset`), and that the hub has stopped capturing, and since
//! when if that is a trusted time (`stop_capture`, `append_all_ending_stop`): that mark lives and dies with the queue
//! it is about, and survives a restart.
//!
//! A file that is not a database, or fails SQLite's own `quick_check`, is recognised as such (`database_is_damaged`)
//! so the agent can set it aside and treat the queue as lost, rather than not start at all.
//!
//! The file records its format (`PRAGMA user_version`, `FORMAT_VERSION`), set when it is created: a file a newer build
//! wrote is refused rather than written into, and so is a database of no known format. Each event records the
//! protocol `schemaVersion` it was built for, so a request never mixes two (`sender`).
//!
//! Several events can be appended in one transaction (`append_all`): what one round of capture produces is stored
//! whole or not at all, with one synchronous commit instead of one per event.

use std::fmt;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde_json::{Map, Value};

use crate::canonical::canonical_json;
use crate::clock;
use crate::fsutil::private_file;
use crate::signing::{self, EventFields, SigningError};
use crate::storage::Cause;

/// How long a write waits for another connection's lock.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// The format of the files this code writes (`PRAGMA user_version`), the outbox's and the pseudonym store's.
pub const FORMAT_VERSION: i64 = 1;
/// The protocol's `schemaVersion` of the events this code builds.
pub const SCHEMA_VERSION: u64 = 1;

/// Why a queue was started again from the service's count (spec/protocol.md, `site_source.reset`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetReason {
    /// The hub still remembers having been confirmed, but its queue is gone.
    QueueLost,
    /// The hub remembers nothing.
    Reinstall,
}

impl ResetReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QueueLost => "queue_lost",
            Self::Reinstall => "reinstall",
        }
    }
}

/// An event as it was stored: its sequence number, the protocol `schemaVersion` it was built for, and the exact JSON
/// text that is sent, every time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub seq: u64,
    pub schema_version: u64,
    pub json: String,
}

/// An observation to be appended (`Outbox::append_all`).
#[derive(Debug, Clone, Copy)]
pub struct NewEvent<'a> {
    pub kind: &'a str,
    pub observed_at: &'a str,
    pub attributes: &'a Map<String, Value>,
    pub pii: Option<&'a Map<String, Value>>,
}

/// A database file whose format this code does not write: what was found, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// A newer build wrote it (`user_version` above `FORMAT_VERSION`).
    Newer { file: &'static str, found: i64 },
    /// It holds tables but records no format (`user_version` 0), or a negative one: nothing this code wrote.
    Unknown { file: &'static str },
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Newer { file, found } => write!(
                f,
                "{file} was written by a newer version of spacegoat-hub (format {found}; this one writes format \
                 {FORMAT_VERSION}) and is not written into: run that version again, or a person must look at it"
            ),
            Self::Unknown { file } => {
                write!(
                    f,
                    "{file} is a database of no format this program knows (it records none): a person must look at \
                     it. To go on without it, move it aside; "
                )?;
                if *file == "outbox.sqlite" {
                    f.write_str(
                        "the hub then starts a new queue and declares the old one lost to the service, and its events \
                         are not delivered",
                    )
                } else {
                    f.write_str("the hub then starts a new one, and devices get new references")
                }
            }
        }
    }
}

impl std::error::Error for FormatError {}

/// Why `open_durable` refused a database.
#[derive(Debug)]
pub(crate) enum DurableError {
    Sqlite(rusqlite::Error),
    /// The journal mode could not be set to WAL; the mode that stayed.
    NoWal(String),
    Format(FormatError),
}

impl From<rusqlite::Error> for DurableError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

#[derive(Debug)]
pub enum OutboxError {
    Sqlite(rusqlite::Error),
    Io(io::Error),
    /// The event cannot be signed (an `observedAt` that is not one, a float, a key id that is not one, ...).
    Signing(SigningError),
    AnotherSource,
    AckAhead,
    ResetOnNonEmpty,
    /// The file holds something this code never writes.
    Damaged(&'static str),
    /// Write-ahead logging could not be enabled; the journal mode that stayed.
    NoWal(String),
    /// A newer build wrote the file, or it is of no known format.
    Format(FormatError),
}

impl From<DurableError> for OutboxError {
    fn from(error: DurableError) -> Self {
        match error {
            DurableError::Sqlite(error) => Self::Sqlite(error),
            DurableError::NoWal(mode) => Self::NoWal(mode),
            DurableError::Format(error) => Self::Format(error),
        }
    }
}

impl OutboxError {
    /// What kind of storage failure this is (`storage::Cause`).
    pub fn cause(&self) -> Cause {
        match self {
            Self::Sqlite(error) => Cause::of_sqlite(error),
            Self::Io(error) => Cause::of_io(error),
            Self::Damaged(_) | Self::AckAhead => Cause::Damaged,
            Self::Signing(_) | Self::AnotherSource | Self::ResetOnNonEmpty | Self::NoWal(_) | Self::Format(_) => {
                Cause::Other
            }
        }
    }
}

impl fmt::Display for OutboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(f, "outbox database: {error}"),
            Self::Io(error) => write!(f, "outbox file: {error}"),
            Self::Signing(error) => write!(f, "the event cannot be signed: {error}"),
            Self::AnotherSource => f.write_str(
                "outbox.sqlite belongs to another source: the source_id in the configuration is not the one recorded \
                 in outbox.sqlite (check the configuration; a queue is never handed to another source)",
            ),
            Self::AckAhead => f.write_str("the service confirmed a sequence ahead of anything this hub assigned"),
            Self::ResetOnNonEmpty => f.write_str("a reset is declared on an empty outbox only"),
            Self::Damaged(what) => write!(f, "the outbox is damaged: {what}"),
            Self::NoWal(mode) => write!(
                f,
                "outbox.sqlite: write-ahead logging cannot be enabled (the journal mode stays {mode}); the file \
                 system may not support it, and without it a committed event is not safe from a power cut"
            ),
            Self::Format(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for OutboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Signing(error) => Some(error),
            Self::Format(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for OutboxError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<io::Error> for OutboxError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<SigningError> for OutboxError {
    fn from(error: SigningError) -> Self {
        Self::Signing(error)
    }
}

pub struct Outbox {
    db: Connection,
    source_id: String,
    key_id: String,
    key: SigningKey,
}

impl Outbox {
    pub fn open(path: &Path, source_id: &str, key_id: &str, key: SigningKey) -> Result<Self, OutboxError> {
        // Refused here rather than at the first event: an outbox that can sign nothing is not worth opening.
        if !signing::is_key_id(key_id) {
            return Err(SigningError::KeyId.into());
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
        }
        private_file(path)?;
        let db = open_durable(
            path,
            "outbox.sqlite",
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL,
             body TEXT NOT NULL);",
        )?;
        let mut outbox = Self {
            db,
            source_id: source_id.to_owned(),
            key_id: key_id.to_owned(),
            key,
        };
        let tx = outbox.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match meta(&tx, "source_id")? {
            None => {
                set_meta(&tx, "source_id", source_id)?;
                set_meta(&tx, "last_assigned", "0")?;
                set_meta(&tx, "last_acked", "0")?;
            }
            Some(owner) if owner != source_id => return Err(OutboxError::AnotherSource),
            Some(_) => {}
        }
        tx.commit()?;
        Ok(outbox)
    }

    pub fn close(self) -> Result<(), OutboxError> {
        self.db.close().map_err(|(_, error)| error.into())
    }

    /// (last assigned, last confirmed) of the outbox at `path`, read-only; (0, 0) when there is none.
    ///
    /// For `status`: it must not create the file (an empty outbox is how a lost one is recognised), take a write
    /// lock away from the running agent, or need the private key. A file that exists but cannot be read is an error,
    /// not (0, 0): a status that says "nothing assigned" about an outbox it could not read would be untrue.
    pub fn read_counters(path: &Path) -> Result<(u64, u64), OutboxError> {
        Self::read_counters_as(path, ReadMode::Live)
    }

    /// `read_counters`, opened as `mode` says.
    pub fn read_counters_as(path: &Path, mode: ReadMode) -> Result<(u64, u64), OutboxError> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let db = open_to_read(path, mode)?;
        let has_meta: bool = db.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'meta')",
            [],
            |row| row.get(0),
        )?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > FORMAT_VERSION {
            return Err(OutboxError::Format(FormatError::Newer {
                file: "outbox.sqlite",
                found: version,
            }));
        }
        if !has_meta {
            // Created (private) but never given its tables: a process that died at its very first start.
            return Ok((0, 0));
        }
        if version != FORMAT_VERSION {
            return Err(OutboxError::Format(FormatError::Unknown { file: "outbox.sqlite" }));
        }
        Ok((counter(&db, "last_assigned")?, counter(&db, "last_acked")?))
    }

    /// The `observedAt` of the oldest event not yet confirmed, if there is one.
    pub fn oldest_pending_observed_at(&self) -> Result<Option<String>, OutboxError> {
        let body: Option<String> = self
            .db
            .query_row("SELECT body FROM events ORDER BY seq LIMIT 1", [], |row| row.get(0))
            .optional()?;
        let Some(body) = body else {
            return Ok(None);
        };
        let event: Value = serde_json::from_str(&body).map_err(|_| OutboxError::Damaged("an event is not JSON"))?;
        match event.get("observedAt") {
            Some(Value::String(at)) => Ok(Some(at.clone())),
            _ => Err(OutboxError::Damaged("an event has no observedAt")),
        }
    }

    pub fn last_assigned(&self) -> Result<u64, OutboxError> {
        counter(&self.db, "last_assigned")
    }

    pub fn last_acked(&self) -> Result<u64, OutboxError> {
        counter(&self.db, "last_acked")
    }

    /// This connection's `PRAGMA synchronous` (2 = FULL); for tests and diagnostics.
    pub fn synchronous(&self) -> Result<i64, OutboxError> {
        Ok(self.db.query_row("PRAGMA synchronous", [], |row| row.get(0))?)
    }

    /// This connection's `PRAGMA secure_delete` (1 = ON); for tests and diagnostics.
    pub fn secure_delete(&self) -> Result<i64, OutboxError> {
        Ok(self.db.query_row("PRAGMA secure_delete", [], |row| row.get(0))?)
    }

    /// Give an observation its place in the sequence and its signature. Returns the sequence number.
    pub fn append(
        &mut self,
        kind: &str,
        observed_at: &str,
        attributes: &Map<String, Value>,
        pii: Option<&Map<String, Value>>,
    ) -> Result<u64, OutboxError> {
        let event = NewEvent {
            kind,
            observed_at,
            attributes,
            pii,
        };
        let numbers = self.append_all(&[event])?;
        numbers
            .last()
            .copied()
            .ok_or(OutboxError::Damaged("an append that assigned no number"))
    }

    /// Give several observations their places in the sequence, in order, in ONE transaction: all of them are stored,
    /// or none is and no number is used. Returns their sequence numbers.
    pub fn append_all(&mut self, events: &[NewEvent<'_>]) -> Result<Vec<u64>, OutboxError> {
        self.append_all_ending_stop(events, false)
    }

    /// `append_all`, and when `ends_stop`, the mark of a stop in capture (`stop_capture`) cleared in the same
    /// transaction: what says capture resumed (a `site_source.input_lost` among `events`, or the first events captured
    /// after a stop too short to declare) and the mark's removal are durable together, or neither is. `events` may
    /// then be empty.
    pub fn append_all_ending_stop(
        &mut self,
        events: &[NewEvent<'_>],
        ends_stop: bool,
    ) -> Result<Vec<u64>, OutboxError> {
        let signer = Signer {
            source_id: &self.source_id,
            key_id: &self.key_id,
            key: &self.key,
        };
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut numbers = Vec::with_capacity(events.len());
        let mut seq = counter(&tx, "last_assigned")?;
        for event in events {
            seq = seq
                .checked_add(1)
                .ok_or(OutboxError::Damaged("the sequence is exhausted"))?;
            signer.store(&tx, seq, event.kind, event.observed_at, event.attributes, event.pii)?;
            numbers.push(seq);
        }
        if ends_stop {
            tx.execute("DELETE FROM meta WHERE key = 'capture_stopped_at'", [])?;
        }
        tx.commit()?;
        Ok(numbers)
    }

    /// Start an empty outbox after a loss: the next event is `site_source.reset`, numbered right after the last
    /// sequence the SERVICE holds (the service accepts a reset only there, so the number is asked of the service,
    /// never taken from the hub's own memory). Only an outbox that has never assigned a number may do this; a hub
    /// does not rewrite a sequence it still holds. `at` (Unix milliseconds) is the event's `observedAt`.
    pub fn declare_reset(&mut self, last_acked_seq: u64, reason: ResetReason, at: i64) -> Result<u64, OutboxError> {
        let observed_at = clock::observed_at_text(at).ok_or(SigningError::ObservedAt)?;
        let signer = Signer {
            source_id: &self.source_id,
            key_id: &self.key_id,
            key: &self.key,
        };
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if counter(&tx, "last_assigned")? != 0 {
            return Err(OutboxError::ResetOnNonEmpty);
        }
        set_meta(&tx, "last_acked", &last_acked_seq.to_string())?;
        let seq = last_acked_seq.checked_add(1).ok_or(SigningError::Canonical(
            crate::canonical::CanonicalError::IntegerOutOfRange,
        ))?;
        let mut attributes = Map::new();
        attributes.insert("trustOrigin".into(), Value::from("hub"));
        attributes.insert("lastAckedSeq".into(), Value::from(last_acked_seq));
        attributes.insert("reason".into(), Value::from(reason.as_str()));
        signer.store(&tx, seq, "site_source.reset", &observed_at, &attributes, None)?;
        tx.commit()?;
        Ok(seq)
    }

    /// Whether the hub has stopped capturing (`Some`), and since when (wall clock, Unix milliseconds) when that was
    /// a trusted time; `None` while it captures. The mark is `capture_stopped_at` in `meta`: a number, or empty when
    /// the moment is not known.
    pub fn capture_stop(&self) -> Result<Option<Option<i64>>, OutboxError> {
        match meta(&self.db, "capture_stopped_at")? {
            None => Ok(None),
            Some(text) if text.is_empty() => Ok(Some(None)),
            Some(text) => text
                .parse()
                .map(|at| Some(Some(at)))
                .map_err(|_| OutboxError::Damaged("the capture mark is not a number")),
        }
    }

    /// Record that the hub stopped capturing, at `at` (wall clock, Unix milliseconds) when that is a trusted time. An
    /// earlier mark is kept: the loss began then.
    pub fn stop_capture(&mut self, at: Option<i64>) -> Result<(), OutboxError> {
        self.db.execute(
            "INSERT INTO meta (key, value) VALUES ('capture_stopped_at', ?1) ON CONFLICT (key) DO NOTHING",
            params![at.map(|at| at.to_string()).unwrap_or_default()],
        )?;
        Ok(())
    }

    /// A committed write that leaves nothing behind, of the kinds a reset makes (`declare_reset`): a counter rewritten
    /// as it is, and an event row stored and removed again. To learn whether the queue takes writes now. The row's
    /// number (0) is one no event ever has.
    pub fn probe_write(&mut self) -> Result<(), OutboxError> {
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE meta SET value = value WHERE key = 'last_acked'", [])?;
        tx.execute("INSERT INTO events (seq, schema_version, body) VALUES (0, 0, '')", [])?;
        tx.execute("DELETE FROM events WHERE seq = 0", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Undelivered events in order, exactly as they were stored: from `from_seq`, or from the first not confirmed.
    pub fn pending(&self, limit: usize, from_seq: Option<u64>) -> Result<Vec<StoredEvent>, OutboxError> {
        let start = match from_seq {
            Some(seq) => seq,
            None => self.last_acked()?.saturating_add(1),
        };
        let Ok(start) = i64::try_from(start) else {
            return Ok(Vec::new());
        };
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self
            .db
            .prepare("SELECT seq, schema_version, body FROM events WHERE seq >= ?1 ORDER BY seq LIMIT ?2")?;
        let rows = statement.query_map(params![start, limit], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (seq, schema_version, json) = row?;
            let seq = u64::try_from(seq).map_err(|_| OutboxError::Damaged("a negative sequence number"))?;
            let schema_version =
                u64::try_from(schema_version).map_err(|_| OutboxError::Damaged("a negative schema version"))?;
            events.push(StoredEvent {
                seq,
                schema_version,
                json,
            });
        }
        Ok(events)
    }

    /// The service confirmed everything up to `last_seq`. Never moves back; never past what was assigned.
    pub fn ack(&mut self, last_seq: u64) -> Result<(), OutboxError> {
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if last_seq > counter(&tx, "last_assigned")? {
            return Err(OutboxError::AckAhead);
        }
        if last_seq > counter(&tx, "last_acked")? {
            // Everything assigned fits in an i64: it was stored as one.
            let through = i64::try_from(last_seq).map_err(|_| OutboxError::Damaged("a sequence beyond i64"))?;
            tx.execute("DELETE FROM events WHERE seq <= ?1", params![through])?;
            set_meta(&tx, "last_acked", &last_seq.to_string())?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// Names the source and the key, never the key itself.
impl fmt::Debug for Outbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outbox")
            .field("source_id", &self.source_id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// What signs an event: the outbox's identity, borrowed apart from its connection.
struct Signer<'a> {
    source_id: &'a str,
    key_id: &'a str,
    key: &'a SigningKey,
}

impl Signer<'_> {
    /// Build, sign and insert event `seq`, and record it as the last assigned. Inside the caller's transaction:
    /// everything here becomes durable together at its commit, or not at all.
    fn store(
        &self,
        db: &Connection,
        seq: u64,
        kind: &str,
        observed_at: &str,
        attributes: &Map<String, Value>,
        pii: Option<&Map<String, Value>>,
    ) -> Result<(), OutboxError> {
        let attributes = Value::Object(attributes.clone());
        let mut event = Map::new();
        event.insert("sourceSeq".into(), Value::from(seq));
        event.insert("kind".into(), Value::from(kind));
        event.insert("observedAt".into(), Value::from(observed_at));
        let mut commitment = None;
        if let Some(pii) = pii {
            let pii = Value::Object(pii.clone());
            let nonce = random_nonce()?;
            let committed = signing::pii_commitment(&nonce, &pii)?;
            event.insert("pii".into(), pii);
            event.insert("piiNonce".into(), Value::from(nonce));
            event.insert("piiCommitment".into(), Value::from(committed.clone()));
            commitment = Some(committed);
        }
        let message = signing::event_signing_message(&EventFields {
            source_id: self.source_id,
            source_seq: seq,
            kind,
            observed_at,
            attributes: &attributes,
            pii_commitment: commitment.as_deref(),
        })?;
        let signature = signing::stored_signature(self.key_id, &signing::sign(self.key, &message))?;
        event.insert("attributes".into(), attributes);
        event.insert("signature".into(), Value::from(signature));
        let body = canonical_json(&Value::Object(event)).map_err(SigningError::from)?;
        let row = i64::try_from(seq).map_err(|_| OutboxError::Damaged("a sequence beyond i64"))?;
        let schema = i64::try_from(SCHEMA_VERSION).map_err(|_| OutboxError::Damaged("a schema version beyond i64"))?;
        db.execute(
            "INSERT INTO events (seq, schema_version, body) VALUES (?1, ?2, ?3)",
            params![row, schema, body],
        )?;
        set_meta(db, "last_assigned", &seq.to_string())?;
        Ok(())
    }
}

/// How a database is opened only to be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadMode {
    /// Read-only, as it stands now: what a write-ahead log beside it holds is read too. SQLite may create the log's
    /// `-wal` and `-shm` side files to do that, so the directory must be writable.
    Live,
    /// As last written to the database file itself (SQLite's `immutable`): nothing is created beside it, and what a
    /// write-ahead log still holds is not seen. For a directory this user cannot write.
    LastWritten,
}

/// Open the database at `path` only to read it (`ReadMode`).
pub(crate) fn open_to_read(path: &Path, mode: ReadMode) -> Result<Connection, rusqlite::Error> {
    let db = match mode {
        ReadMode::Live => Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?,
        ReadMode::LastWritten => Connection::open_with_flags(
            format!("{}?immutable=1", file_uri(path)),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?,
    };
    db.busy_timeout(BUSY_TIMEOUT)?;
    Ok(db)
}

/// `path` as an SQLite `file:` URI: every byte but the unreserved ones and `/` percent-encoded, so that a `?`, a `#`
/// or a `%` in a directory name stays part of the name.
fn file_uri(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(byte) {
            uri.push(char::from(*byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri
}

/// A connection in WAL mode with `synchronous=FULL` and `secure_delete=ON`, on a database of this code's format
/// (`FORMAT_VERSION`). Shared with the pseudonym store; `file` names it in an error.
///
/// - `synchronous=FULL`: a committed event survives power loss, which is the whole point of the file.
/// - `secure_delete=ON`: what is deleted (a confirmed event, forgotten facts: personal data) is overwritten, not left in
///   a free page. A copy can still sit in the write-ahead log until SQLite reuses that part of it.
/// - the format: a new database (no tables) gets `schema` and `user_version = FORMAT_VERSION` in one transaction; one
///   a newer build wrote, or one that has tables and no format, is refused.
pub(crate) fn open_durable(path: &Path, file: &'static str, schema: &str) -> Result<Connection, DurableError> {
    let mut db = Connection::open(path)?;
    // SQLite opens a file it may not write read-only and says so only at the first write: a store that cannot keep
    // what it is given is refused here, at the start.
    if db.is_readonly(rusqlite::MAIN_DB)? {
        return Err(DurableError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_READONLY),
            Some("the database file cannot be written".to_owned()),
        )));
    }
    db.busy_timeout(BUSY_TIMEOUT)?;
    let mode: String = db.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(DurableError::NoWal(mode));
    }
    db.execute_batch("PRAGMA synchronous=FULL; PRAGMA secure_delete=ON")?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let empty: bool = tx.query_row("SELECT NOT EXISTS (SELECT 1 FROM sqlite_schema)", [], |row| row.get(0))?;
    if version > FORMAT_VERSION {
        return Err(DurableError::Format(FormatError::Newer { file, found: version }));
    }
    if version != FORMAT_VERSION && !empty {
        return Err(DurableError::Format(FormatError::Unknown { file }));
    }
    tx.execute_batch(schema)?;
    if version != FORMAT_VERSION {
        tx.execute_batch(&format!("PRAGMA user_version = {FORMAT_VERSION}"))?;
    }
    tx.commit()?;
    Ok(db)
}

/// Whether the SQLite file at `path` is damaged: not a database at all, or one that fails `PRAGMA quick_check`.
/// `Ok(false)` for a sound file and for a regular file of length 0 (a database that never got its first page);
/// an `Err` for anything else that keeps it from being opened (permissions, I/O): that is not damage, and the file
/// must not be set aside for it. Shared with the pseudonym store.
pub fn database_is_damaged(path: &Path) -> Result<bool, rusqlite::Error> {
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.busy_timeout(BUSY_TIMEOUT)?;
    let checked = db.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0));
    let damaged = match checked {
        Ok(verdict) => verdict != "ok",
        Err(rusqlite::Error::SqliteFailure(error, _))
            if matches!(error.code, ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt) =>
        {
            true
        }
        Err(error) => return Err(error),
    };
    // A damaged file may not close cleanly; what matters is that this connection is gone before the file is moved.
    let _ = db.close();
    Ok(damaged)
}

fn random_nonce() -> Result<String, OutboxError> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    Ok(signing::hex(&nonce))
}

fn meta(db: &Connection, key: &str) -> Result<Option<String>, rusqlite::Error> {
    db.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |row| row.get(0))
        .optional()
}

fn set_meta(db: &Connection, key: &str, value: &str) -> Result<(), rusqlite::Error> {
    db.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// A counter kept in `meta`; absent is 0, anything but a decimal number is damage.
fn counter(db: &Connection, key: &str) -> Result<u64, OutboxError> {
    match meta(db, key)? {
        None => Ok(0),
        Some(text) => {
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(OutboxError::Damaged("a counter is not a number"));
            }
            text.parse()
                .map_err(|_| OutboxError::Damaged("a counter is out of range"))
        }
    }
}
