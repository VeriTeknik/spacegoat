// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a hub remembers beside its outbox.
//!
//! Two things, kept apart from the outbox on purpose, so that losing the queue does not lose them:
//!
//! - `Confirmed`: the last sequence number the service confirmed, and to which source. With it, a hub whose outbox is
//!   gone can still say truthfully where it stood (`site_source.reset`), instead of guessing or starting over.
//! - `Pseudonyms`: which random `deviceRef` stands for which device, and what was last reported about it. They are
//!   what lets the service see "the same device" tomorrow. They are random (UUID v4), never derived from the device,
//!   and they stay on the hub.

use std::collections::HashMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value};

use crate::fsutil::{open_regular, private_file, write_own_file};
use crate::outbox::{DurableError, FORMAT_VERSION, FormatError, ReadMode, open_durable, open_to_read};
use crate::storage::Cause;

#[derive(Debug)]
pub enum StateError {
    Sqlite(rusqlite::Error),
    Io(io::Error),
    /// The file holds something this code never writes.
    Damaged(&'static str),
    /// Write-ahead logging could not be enabled; the journal mode that stayed.
    NoWal(String),
    /// A newer build wrote the file, or it is of no known format.
    Format(FormatError),
}

impl StateError {
    /// What kind of storage failure this is (`storage::Cause`).
    pub fn cause(&self) -> Cause {
        match self {
            Self::Sqlite(error) => Cause::of_sqlite(error),
            Self::Io(error) => Cause::of_io(error),
            Self::Damaged(_) => Cause::Damaged,
            Self::NoWal(_) | Self::Format(_) => Cause::Other,
        }
    }
}

impl From<DurableError> for StateError {
    fn from(error: DurableError) -> Self {
        match error {
            DurableError::Sqlite(error) => Self::Sqlite(error),
            DurableError::NoWal(mode) => Self::NoWal(mode),
            DurableError::Format(error) => Self::Format(error),
        }
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(f, "pseudonym database: {error}"),
            Self::Io(error) => write!(f, "pseudonym file: {error}"),
            Self::Damaged(what) => write!(f, "the pseudonym store is damaged: {what}"),
            Self::NoWal(mode) => write!(
                f,
                "pseudonyms.sqlite: write-ahead logging cannot be enabled (the journal mode stays {mode}); the file \
                 system may not support it"
            ),
            Self::Format(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Format(error) => Some(error),
            Self::Damaged(_) | Self::NoWal(_) => None,
        }
    }
}

impl From<rusqlite::Error> for StateError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<io::Error> for StateError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A fresh random UUID v4 (RFC 9562), lowercase: 122 random bits, the version (4) and the variant (`10`) set.
pub fn uuid_v4() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    if let Some(version) = bytes.get_mut(6) {
        *version = (*version & 0x0f) | 0x40;
    }
    if let Some(variant) = bytes.get_mut(8) {
        *variant = (*variant & 0x3f) | 0x80;
    }
    let hex = crate::signing::hex(&bytes);
    let group = |from: usize, to: usize| hex.get(from..to).unwrap_or_default();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        group(0, 8),
        group(8, 12),
        group(12, 16),
        group(16, 20),
        group(20, 32)
    ))
}

/// `confirmed.json` holds a few short fields; anything larger is not one, and is not read whole.
const MAX_CONFIRMED_FILE: u64 = 64 * 1024;
/// The format of `confirmed.json` this code writes (its `version` field).
pub const CONFIRMED_VERSION: u64 = 1;

/// What `confirmed.json` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// There is no mark, or it was written for another source: nothing was confirmed to this one.
    Nothing,
    /// The service confirmed everything up to this number.
    Confirmed(u64),
    /// A person decided (`resume --from-service`) that the hub takes the service's state as its starting point: at the
    /// next greeting the hub declares a lost queue at the service's number, whatever that number is.
    AcceptService,
    /// The file is there but does not say anything this code writes (no source id, no version, a field that is not
    /// one). It is not 0: it says that something was confirmed once, and not how much.
    NotUnderstood,
    /// A newer build wrote it (this `version`): it is refused, never read as anything or written over.
    Newer(u64),
}

/// The last sequence number the service confirmed to one source, in a small JSON file of its own:
/// `{"version": 1, "lastAckedSeq": 41, "sourceId": "<uuid>"}`, or `{"version": 1, "acceptService": true, "sourceId":
/// "<uuid>"}` after `resume --from-service`.
#[derive(Debug)]
pub struct Confirmed {
    path: PathBuf,
    source_id: String,
}

impl Confirmed {
    pub fn new(path: impl Into<PathBuf>, source_id: &str) -> Self {
        Self {
            path: path.into(),
            source_id: source_id.to_owned(),
        }
    }

    /// The mark. A file that exists but cannot be read (permissions, a directory or a symbolic link at its name) is
    /// an error: reading "nothing" then would make the hub forget where it stood.
    pub fn read(&self) -> io::Result<Mark> {
        let file = match open_regular(&self.path, OpenOptions::new().read(true)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Mark::Nothing),
            Err(error) => return Err(error),
        };
        let mut text = Vec::new();
        file.take(MAX_CONFIRMED_FILE + 1).read_to_end(&mut text)?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONFIRMED_FILE {
            return Ok(Mark::NotUnderstood);
        }
        let Ok(Value::Object(mark)) = serde_json::from_slice::<Value>(&text) else {
            return Ok(Mark::NotUnderstood);
        };
        match mark.get("version").and_then(Value::as_u64) {
            Some(CONFIRMED_VERSION) => {}
            Some(newer) if newer > CONFIRMED_VERSION => return Ok(Mark::Newer(newer)),
            _ => return Ok(Mark::NotUnderstood),
        }
        match mark.get("sourceId") {
            Some(Value::String(source)) if *source == self.source_id => {}
            Some(Value::String(_)) => return Ok(Mark::Nothing),
            _ => return Ok(Mark::NotUnderstood),
        }
        if mark.get("acceptService") == Some(&Value::Bool(true)) {
            return Ok(Mark::AcceptService);
        }
        Ok(match mark.get("lastAckedSeq").and_then(Value::as_u64) {
            Some(number) => Mark::Confirmed(number),
            None => Mark::NotUnderstood,
        })
    }

    /// Record `last_acked_seq` if it is ahead of what is recorded; never moves back. Over a mark that is another
    /// source's, cannot be understood or accepts the service's state it is written whatever its value, except 0:
    /// that says nothing, and a person's decision stays until the service has confirmed something after it (the
    /// queue's own count replaces it at the next start, too). Over a mark a newer build wrote, never: that is an
    /// error.
    pub fn write(&self, last_acked_seq: u64) -> io::Result<()> {
        let ahead = match self.read()? {
            Mark::Confirmed(recorded) => last_acked_seq > recorded,
            Mark::Nothing | Mark::NotUnderstood | Mark::AcceptService => last_acked_seq > 0,
            Mark::Newer(_) => return Err(newer_version()),
        };
        if ahead {
            self.store_number(last_acked_seq)?;
        }
        Ok(())
    }

    /// Record `last_acked_seq` whatever is recorded (the queue's own count), except over a mark a newer build wrote:
    /// that is an error, and the file is left as it is.
    pub fn replace(&self, last_acked_seq: u64) -> io::Result<()> {
        self.refuse_newer()?;
        self.store_number(last_acked_seq)
    }

    /// Record a person's decision to take the service's state as the starting point (`Mark::AcceptService`), except
    /// over a mark a newer build wrote: that is an error, and the file is left as it is.
    pub fn accept_service(&self) -> io::Result<()> {
        self.refuse_newer()?;
        let text = format!(
            "{{\"version\": {CONFIRMED_VERSION}, \"acceptService\": true, \"sourceId\": {}}}",
            Value::from(self.source_id.as_str())
        );
        write_own_file(&self.path, text.as_bytes())
    }

    fn refuse_newer(&self) -> io::Result<()> {
        match self.read()? {
            Mark::Newer(_) => Err(newer_version()),
            _ => Ok(()),
        }
    }

    fn store_number(&self, last_acked_seq: u64) -> io::Result<()> {
        // `json.dumps` form, a space after each separator.
        let text = format!(
            "{{\"version\": {CONFIRMED_VERSION}, \"lastAckedSeq\": {last_acked_seq}, \"sourceId\": {}}}",
            Value::from(self.source_id.as_str())
        );
        write_own_file(&self.path, text.as_bytes())
    }
}

/// The error for a `confirmed.json` a newer build wrote: it is never written over.
fn newer_version() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "confirmed.json was written by a newer version",
    )
}

/// (scope, reference) -> the identity it stands for (`Pseudonyms::identities_by_reference`).
pub type ReferenceIndex = HashMap<(String, String), String>;

/// identity (how the hub recognises a device or a segment locally) -> the random reference it reports.
#[derive(Debug)]
pub struct Pseudonyms {
    db: Connection,
}

impl Pseudonyms {
    pub fn open(path: &Path) -> Result<Self, StateError> {
        private_file(path)?;
        let db = open_durable(
            path,
            "pseudonyms.sqlite",
            "CREATE TABLE IF NOT EXISTS refs (scope TEXT NOT NULL, identity TEXT NOT NULL, ref TEXT NOT NULL,
             facts TEXT NOT NULL DEFAULT '{}', PRIMARY KEY (scope, identity)) WITHOUT ROWID",
        )?;
        Ok(Self { db })
    }

    pub fn close(self) -> Result<(), StateError> {
        self.db.close().map_err(|(_, error)| error.into())
    }

    /// Whether the store at `path` is of a format `open` accepts, read only (`status`): `Format` for one a newer
    /// build wrote or one of no known format, as `open` refuses them; `Ok` when there is no store, an empty one, or
    /// one of this format. Nothing is created and nothing is written, except what `ReadMode::Live` lets SQLite create.
    pub fn check_format(path: &Path, mode: ReadMode) -> Result<(), StateError> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let db = open_to_read(path, mode)?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let empty: bool = db.query_row("SELECT NOT EXISTS (SELECT 1 FROM sqlite_schema)", [], |row| row.get(0))?;
        let file = "pseudonyms.sqlite";
        if version > FORMAT_VERSION {
            return Err(StateError::Format(FormatError::Newer { file, found: version }));
        }
        if version != FORMAT_VERSION && !empty {
            return Err(StateError::Format(FormatError::Unknown { file }));
        }
        Ok(())
    }

    /// This connection's `PRAGMA synchronous` (2 = FULL); for tests and diagnostics.
    pub fn synchronous(&self) -> Result<i64, StateError> {
        Ok(self.db.query_row("PRAGMA synchronous", [], |row| row.get(0))?)
    }

    /// This connection's `PRAGMA secure_delete` (1 = ON); for tests and diagnostics.
    pub fn secure_delete(&self) -> Result<i64, StateError> {
        Ok(self.db.query_row("PRAGMA secure_delete", [], |row| row.get(0))?)
    }

    /// The reference of `identity`, created on first use: a fresh random UUID v4, never a function of it.
    pub fn reference(&mut self, scope: &str, identity: &str) -> Result<String, StateError> {
        if let Some(found) = self.stored_reference(scope, identity)? {
            return Ok(found);
        }
        // Insert-if-absent, then read: whoever inserted first, the stored reference is the one returned.
        self.db.execute(
            "INSERT INTO refs (scope, identity, ref) VALUES (?1, ?2, ?3) ON CONFLICT (scope, identity) DO NOTHING",
            params![scope, identity, uuid_v4()?],
        )?;
        self.stored_reference(scope, identity)?
            .ok_or(StateError::Damaged("a reference vanished as it was written"))
    }

    fn stored_reference(&self, scope: &str, identity: &str) -> Result<Option<String>, StateError> {
        Ok(self
            .db
            .query_row(
                "SELECT ref FROM refs WHERE scope = ?1 AND identity = ?2",
                params![scope, identity],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Every identity in `scope` that has a reference, in a stable order (the segments a snapshot is due for,
    /// whether or not anything is on them now).
    pub fn identities(&self, scope: &str) -> Result<Vec<String>, StateError> {
        let mut statement = self
            .db
            .prepare("SELECT identity FROM refs WHERE scope = ?1 ORDER BY identity")?;
        let rows = statement.query_map(params![scope], |row| row.get::<_, String>(0))?;
        let mut found = Vec::new();
        for row in rows {
            found.push(row?);
        }
        Ok(found)
    }

    /// Every reference with what it stands for: (scope, reference) -> identity.
    ///
    /// A record whose scope, reference or identity is not text (this code never writes one: damage from outside) is
    /// passed over and counted, the second value; a failure of the database itself is an error.
    pub fn identities_by_reference(&self) -> Result<(ReferenceIndex, usize), StateError> {
        let mut statement = self.db.prepare("SELECT scope, ref, identity FROM refs")?;
        let rows = statement.query_map([], |row| {
            let text = |index: usize| -> rusqlite::Result<Option<String>> {
                Ok(match row.get_ref(index)? {
                    ValueRef::Text(bytes) => std::str::from_utf8(bytes).ok().map(str::to_owned),
                    _ => None,
                })
            };
            Ok((text(0)?, text(1)?, text(2)?))
        })?;
        let mut found = HashMap::new();
        let mut malformed = 0usize;
        for row in rows {
            match row? {
                (Some(scope), Some(reference), Some(identity)) => {
                    found.insert((scope, reference), identity);
                }
                _ => malformed = malformed.saturating_add(1),
            }
        }
        Ok((found, malformed))
    }

    /// A write that changes nothing (one record rewritten as it is), to learn whether the store takes writes now.
    pub fn probe_write(&mut self) -> Result<(), StateError> {
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE refs SET facts = facts WHERE (scope, identity) IN (SELECT scope, identity FROM refs LIMIT 1)",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Whether the store holds no reference at all (new, or emptied).
    pub fn is_empty(&self) -> Result<bool, StateError> {
        let any: bool = self
            .db
            .query_row("SELECT EXISTS (SELECT 1 FROM refs)", [], |row| row.get(0))?;
        Ok(!any)
    }

    /// What the hub last reported about `identity` (empty before its first report).
    ///
    /// A record this code never writes, in whatever way (text that is not a JSON object, text that is not UTF-8, a
    /// cell of another type), is `Damaged`: the record of that one row. A failure of the database itself (I/O, a
    /// corrupt page, a lock) stays what it is.
    pub fn facts(&self, scope: &str, identity: &str) -> Result<Map<String, Value>, StateError> {
        let cell: Option<Option<Map<String, Value>>> = self
            .db
            .query_row(
                "SELECT facts FROM refs WHERE scope = ?1 AND identity = ?2",
                params![scope, identity],
                // The cell's bytes as they are: their type and their encoding are judged here, not by a conversion
                // that would fail the whole read.
                |row| {
                    Ok(match row.get_ref(0)? {
                        ValueRef::Text(bytes) => match serde_json::from_slice(bytes) {
                            Ok(Value::Object(facts)) => Some(facts),
                            _ => None,
                        },
                        _ => None,
                    })
                },
            )
            .optional()?;
        match cell {
            None => Ok(Map::new()),
            Some(Some(facts)) => Ok(facts),
            Some(None) => Err(StateError::Damaged("stored facts are not a JSON object")),
        }
    }

    /// Forget what was reported, keep the references. After a lost queue the hub cannot know which of its reports
    /// reached the service: it reports every device again (the service takes a repeated report as an update of the
    /// same device, because the reference is the same) rather than stay silent about one that never arrived.
    pub fn forget_facts(&mut self) -> Result<(), StateError> {
        self.db.execute("UPDATE refs SET facts = '{}'", [])?;
        Ok(())
    }

    pub fn remember(&mut self, scope: &str, identity: &str, facts: &Map<String, Value>) -> Result<(), StateError> {
        self.remember_all(&[(scope, identity, facts)])
    }

    /// The references of several identities, creating those that have none, in one transaction that writes only when
    /// one is missing (a round where every device is known commits nothing).
    pub fn references(&mut self, subjects: &[(&str, &str)]) -> Result<Vec<String>, StateError> {
        let missing: Vec<&(&str, &str)> = subjects
            .iter()
            .filter(|(scope, identity)| matches!(self.stored_reference(scope, identity), Ok(None)))
            .collect();
        if !missing.is_empty() {
            let tx = self.db.transaction()?;
            for (scope, identity) in missing {
                // Insert-if-absent: whoever inserted first, the stored reference is the one returned.
                tx.execute(
                    "INSERT INTO refs (scope, identity, ref) VALUES (?1, ?2, ?3) \
                     ON CONFLICT (scope, identity) DO NOTHING",
                    params![scope, identity, uuid_v4()?],
                )?;
            }
            tx.commit()?;
        }
        subjects
            .iter()
            .map(|(scope, identity)| {
                self.stored_reference(scope, identity)?
                    .ok_or(StateError::Damaged("a reference vanished as it was written"))
            })
            .collect()
    }

    /// What was reported about several subjects, in one transaction: all of it is kept, or none.
    pub fn remember_all(&mut self, reports: &[(&str, &str, &Map<String, Value>)]) -> Result<(), StateError> {
        let tx = self.db.transaction()?;
        for (scope, identity, facts) in reports {
            tx.execute(
                "INSERT INTO refs (scope, identity, ref) VALUES (?1, ?2, ?3) ON CONFLICT (scope, identity) DO NOTHING",
                params![scope, identity, uuid_v4()?],
            )?;
            // serde_json's map is ordered by key: the stored facts are a JSON object with its keys sorted.
            let text = serde_json::to_string(facts).map_err(io::Error::other)?;
            tx.execute(
                "UPDATE refs SET facts = ?1 WHERE scope = ?2 AND identity = ?3",
                params![text, scope, identity],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}
