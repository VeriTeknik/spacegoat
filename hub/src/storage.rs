// SPDX-License-Identifier: AGPL-3.0-or-later
//! Why the hub's own storage failed, as one word from a closed list.
//!
//! The word comes from the error's code (SQLite's primary result code) or kind (`io::ErrorKind`), never from its text:
//! a message can name a path, and a person reading the status wants to know what to do, not what SQLite said.

use std::io;

use rusqlite::ErrorCode;

/// The cause of a storage failure. The status's `cause` and the reported line use `as_str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// The disk (or the user's quota) is full.
    DiskFull,
    /// The file or the file system cannot be written (a read-only mount, a mode that does not allow it).
    ReadOnly,
    /// The device or the operating system failed to read or write.
    Io,
    /// Another process holds the database's lock.
    Locked,
    /// The file holds something this program never writes.
    Damaged,
    /// Anything else.
    Other,
}

impl Cause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DiskFull => "disk_full",
            Self::ReadOnly => "read_only",
            Self::Io => "io",
            Self::Locked => "locked",
            Self::Damaged => "damaged",
            Self::Other => "other",
        }
    }

    /// From SQLite's primary result code; an error that did not come from SQLite itself is `Other`.
    pub fn of_sqlite(error: &rusqlite::Error) -> Self {
        let rusqlite::Error::SqliteFailure(failure, _) = error else {
            return Self::Other;
        };
        match failure.code {
            ErrorCode::DiskFull => Self::DiskFull,
            ErrorCode::ReadOnly | ErrorCode::PermissionDenied => Self::ReadOnly,
            ErrorCode::SystemIoFailure | ErrorCode::CannotOpen => Self::Io,
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => Self::Locked,
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => Self::Damaged,
            _ => Self::Other,
        }
    }

    /// From the I/O error's kind. A kind std has no name for (it says "uncategorized") is `Io`: it came from the
    /// operating system.
    pub fn of_io(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => Self::DiskFull,
            io::ErrorKind::ReadOnlyFilesystem | io::ErrorKind::PermissionDenied => Self::ReadOnly,
            io::ErrorKind::WouldBlock => Self::Locked,
            io::ErrorKind::InvalidData => Self::Damaged,
            _ => Self::Io,
        }
    }
}
