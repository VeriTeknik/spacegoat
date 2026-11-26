// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a hub remembers beside its outbox.
//!
//! Two things, kept apart from the outbox on purpose, so that losing the queue does not lose them:
//!
//! - `Confirmed`: the last sequence number the service confirmed, and to which source. With it, a hub whose outbox is gone can still say
//!   truthfully where it stood (`site_source.reset`), instead of guessing or starting over.
//! - `Pseudonyms`: which random `deviceRef` stands for which device, and what was last reported about it. They are
//!   what lets the service see "the same device" tomorrow. They are random (UUID v4), never derived from the device,
//!   and they stay on the hub.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value};

use crate::fsutil::{open_regular, private_file, write_own_file};
use crate::outbox::open_durable;

#[derive(Debug)]
pub enum StateError {
    Sqlite(rusqlite::Error),
    Io(io::Error),
    /// The file holds something this code never writes.
    Damaged(&'static str),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(f, "pseudonym database: {error}"),
            Self::Io(error) => write!(f, "pseudonym file: {error}"),
            Self::Damaged(what) => write!(f, "the pseudonym store is damaged: {what}"),
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Damaged(_) => None,
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

/// What `confirmed.json` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// There is no mark, or it was written for another source: nothing was confirmed to this one.
    Nothing,
    /// The service confirmed everything up to this number. A mark without a source id (the earlier form) is this
    /// source's.
    Confirmed(u64),
    /// The file is there but does not say anything this code writes. It is not 0: it says that something was
    /// confirmed once, and not how much.
    NotUnderstood,
}

/// The last sequence number the service confirmed to one source, in a small JSON file of its own:
/// `{"lastAckedSeq": 41, "sourceId": "<uuid>"}`.
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
        let Some(number) = mark.get("lastAckedSeq").and_then(Value::as_u64) else {
            return Ok(Mark::NotUnderstood);
        };
        Ok(match mark.get("sourceId") {
            None => Mark::Confirmed(number),
            Some(Value::String(source)) if *source == self.source_id => Mark::Confirmed(number),
            Some(Value::String(_)) => Mark::Nothing,
            Some(_) => Mark::NotUnderstood,
        })
    }

    /// Record `last_acked_seq` if it is ahead of what is recorded; never moves back. Over a mark that is another
    /// source's or cannot be understood it is written whatever its value (except 0, which says nothing).
    pub fn write(&self, last_acked_seq: u64) -> io::Result<()> {
        let ahead = match self.read()? {
            Mark::Confirmed(recorded) => last_acked_seq > recorded,
            Mark::Nothing | Mark::NotUnderstood => last_acked_seq > 0,
        };
        if ahead {
            self.replace(last_acked_seq)?;
        }
        Ok(())
    }

    /// Record `last_acked_seq` whatever is recorded (a person's decision, or the queue's own count).
    pub fn replace(&self, last_acked_seq: u64) -> io::Result<()> {
        // `json.dumps` form, a space after each separator.
        let text = format!(
            "{{\"lastAckedSeq\": {last_acked_seq}, \"sourceId\": {}}}",
            Value::from(self.source_id.as_str())
        );
        write_own_file(&self.path, text.as_bytes())
    }
}

/// identity (how the hub recognises a device or a segment locally) -> the random reference it reports.
#[derive(Debug)]
pub struct Pseudonyms {
    db: Connection,
}

impl Pseudonyms {
    pub fn open(path: &Path) -> Result<Self, StateError> {
        private_file(path)?;
        let db = open_durable(path)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS refs (scope TEXT NOT NULL, identity TEXT NOT NULL, ref TEXT NOT NULL,
             facts TEXT NOT NULL DEFAULT '{}', PRIMARY KEY (scope, identity)) WITHOUT ROWID",
        )?;
        Ok(Self { db })
    }

    pub fn close(self) -> Result<(), StateError> {
        self.db.close().map_err(|(_, error)| error.into())
    }

    /// This connection's `PRAGMA synchronous` (2 = FULL); for tests and diagnostics.
    pub fn synchronous(&self) -> Result<i64, StateError> {
        Ok(self.db.query_row("PRAGMA synchronous", [], |row| row.get(0))?)
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

    /// Whether the store holds no reference at all (new, or emptied).
    pub fn is_empty(&self) -> Result<bool, StateError> {
        let any: bool = self
            .db
            .query_row("SELECT EXISTS (SELECT 1 FROM refs)", [], |row| row.get(0))?;
        Ok(!any)
    }

    /// What the hub last reported about `identity` (empty before its first report).
    pub fn facts(&self, scope: &str, identity: &str) -> Result<Map<String, Value>, StateError> {
        let text: Option<String> = self
            .db
            .query_row(
                "SELECT facts FROM refs WHERE scope = ?1 AND identity = ?2",
                params![scope, identity],
                |row| row.get(0),
            )
            .optional()?;
        let Some(text) = text else {
            return Ok(Map::new());
        };
        match serde_json::from_str(&text) {
            Ok(Value::Object(facts)) => Ok(facts),
            _ => Err(StateError::Damaged("stored facts are not a JSON object")),
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
        self.reference(scope, identity)?;
        // serde_json's map is ordered by key: the stored facts are a JSON object with its keys sorted.
        let text = serde_json::to_string(facts).map_err(io::Error::other)?;
        self.db.execute(
            "UPDATE refs SET facts = ?1 WHERE scope = ?2 AND identity = ?3",
            params![text, scope, identity],
        )?;
        Ok(())
    }
}
