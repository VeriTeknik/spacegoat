// SPDX-License-Identifier: AGPL-3.0-or-later
//! Whether a state directory is one the hub may keep its key and its records in: the one check `keygen` and the agent
//! (`run`, `status`, `resume`) share, with one error type and one wording.
//!
//! A state directory is acceptable when it exists, is a directory, no other user can enter it (mode `0700` or
//! narrower), and it belongs to the user this process runs as. With `Access::Write` it must also be writable.
//!
//! The user this process runs as is learned from a file it creates for a moment IN the state directory (std cannot
//! ask for the effective uid): the owner of a new file is that user. Nothing outside the state directory is used, so
//! a missing or unusable temporary directory (`TMPDIR`) changes nothing. When the directory cannot be written,
//! `Access::Read` (`status`) compares the directory's owner with the owner of the key file in it instead.

use std::fmt;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::fsutil::create_temporary;

/// The name whose temporary form (`fsutil::temporary_prefix`) the probe file has.
pub const PROBE_NAME: &str = "owner-check";

/// What the caller will do in the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Write in it (`keygen`, `run`, `resume`): it must be writable.
    Write,
    /// Only read (`status`): a directory this user cannot write is accepted when its owner owns the key in it.
    Read,
}

#[derive(Debug)]
pub enum StateDirError {
    Missing(PathBuf),
    NotADirectory(PathBuf),
    OpenToOthers(PathBuf),
    OfAnotherUser(PathBuf),
    NotWritable(PathBuf),
    /// Looking at it failed for another reason.
    Io(PathBuf, io::Error),
}

impl StateDirError {
    pub fn path(&self) -> &Path {
        match self {
            Self::Missing(path)
            | Self::NotADirectory(path)
            | Self::OpenToOthers(path)
            | Self::OfAnotherUser(path)
            | Self::NotWritable(path)
            | Self::Io(path, _) => path,
        }
    }
}

impl fmt::Display for StateDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "state directory {}: ", self.path().display())?;
        match self {
            Self::Missing(_) => f.write_str("missing; run keygen first"),
            Self::NotADirectory(_) => f.write_str("not a directory"),
            Self::OpenToOthers(_) => f.write_str("open to other users; use one only the hub's user can enter"),
            Self::OfAnotherUser(_) => f.write_str("belongs to another user"),
            Self::NotWritable(_) => f.write_str("cannot be written by this user"),
            Self::Io(_, error) => write!(f, "cannot be checked: {error}"),
        }
    }
}

impl std::error::Error for StateDirError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, error) => Some(error),
            _ => None,
        }
    }
}

/// Check `directory` (see the module). `expected_owner` stands for the user this process runs as (tests); `key` is
/// the key file `Access::Read` compares with. The directory is never changed: it may not be this program's to
/// change.
pub fn check(directory: &Path, access: Access, expected_owner: Option<u32>, key: &Path) -> Result<(), StateDirError> {
    let at = || directory.to_path_buf();
    let found = match std::fs::metadata(directory) {
        Ok(found) => found,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(StateDirError::Missing(at())),
        Err(error) => return Err(StateDirError::Io(at(), error)),
    };
    if !found.is_dir() {
        return Err(StateDirError::NotADirectory(at()));
    }
    if found.permissions().mode() & 0o077 != 0 {
        return Err(StateDirError::OpenToOthers(at()));
    }
    let me = match probe_owner(directory) {
        Ok(uid) => expected_owner.unwrap_or(uid),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => match access {
            Access::Write => return Err(StateDirError::NotWritable(at())),
            Access::Read => match (expected_owner, std::fs::symlink_metadata(key)) {
                (Some(uid), _) => uid,
                (None, Ok(key)) => key.uid(),
                // Nothing to compare with, and nothing private to protect: the directory holds no key.
                (None, Err(_)) => found.uid(),
            },
        },
        Err(error) => return Err(StateDirError::Io(at(), error)),
    };
    if found.uid() != me {
        // Whoever owns the directory can swap what is in it.
        return Err(StateDirError::OfAnotherUser(at()));
    }
    Ok(())
}

/// The owner of a file created for a moment in `directory` and removed again: the user this process creates files
/// as.
fn probe_owner(directory: &Path) -> io::Result<u32> {
    let (file, path) = create_temporary(directory, &crate::fsutil::temporary_prefix(PROBE_NAME))?;
    let uid = file.metadata().map(|meta| meta.uid());
    drop(file);
    match std::fs::remove_file(&path) {
        // Swept by an agent starting meanwhile: gone either way.
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    uid
}
