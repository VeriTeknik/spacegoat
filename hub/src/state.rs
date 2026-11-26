// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a hub remembers beside its outbox.
//!
//! Two things, kept apart from the outbox on purpose, so that losing the queue does not lose them:
//!
//! - `Confirmed`: the last sequence number the service confirmed. With it, a hub whose outbox is gone can still say
//!   truthfully where it stood (`site_source.reset`), instead of guessing or starting over.
//! - `Pseudonyms`: which random `deviceRef` stands for which device, and what was last reported about it. They are
//!   what lets the service see "the same device" tomorrow. They are random (UUID v4), never derived from the device,
//!   and they stay on the hub.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value};

use crate::fsutil::{private_file, write_atomic};
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

/// The last sequence number the service confirmed, in a small JSON file of its own.
#[derive(Debug)]
pub struct Confirmed {
    path: PathBuf,
}

impl Confirmed {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// 0 when nothing was ever confirmed, or when the file does not hold a non-negative integer. A file that exists
    /// but cannot be read is an error: reading 0 then would make the hub forget where it stood.
    pub fn read(&self) -> io::Result<u64> {
        let text = match std::fs::read(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error),
        };
        let value: Value = match serde_json::from_slice(&text) {
            Ok(value) => value,
            Err(_) => return Ok(0),
        };
        Ok(value.get("lastAckedSeq").and_then(Value::as_u64).unwrap_or(0))
    }

    /// Record `last_acked_seq` if it is ahead of what is recorded; never moves back.
    pub fn write(&self, last_acked_seq: u64) -> io::Result<()> {
        if last_acked_seq > self.read()? {
            // The Python agent's `json.dumps` form, space included.
            write_atomic(&self.path, format!("{{\"lastAckedSeq\": {last_acked_seq}}}").as_bytes())?;
        }
        Ok(())
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
        // serde_json's map is ordered by key: the same text Python's `json.dumps(sort_keys=True)` sorted to.
        let text = serde_json::to_string(facts).map_err(io::Error::other)?;
        self.db.execute(
            "UPDATE refs SET facts = ?1 WHERE scope = ?2 AND identity = ?3",
            params![text, scope, identity],
        )?;
        Ok(())
    }
}
