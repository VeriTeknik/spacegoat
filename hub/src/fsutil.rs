// SPDX-License-Identifier: AGPL-3.0-or-later
//! The file primitives everything the hub keeps is written through.
//!
//! The state directory holds the hub's key and personal data, so every file in it is created for its owner only,
//! is never reached through a symbolic link, and is either fully written or not there at all:
//! - a temporary file has a name nobody can predict, is created exclusively (never an existing file, never through a
//!   link) with mode 0600, and is synced before it is put in place;
//! - a file is put in place by one rename (or one link), and the directory is synced afterwards, so that the new
//!   name, not only the content, survives a power cut.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::signing::hex;

/// Random bytes in a temporary file's name: 128 bits, so guessing one is not a plan.
const NAME_RANDOM_BYTES: usize = 16;

/// How many fresh names to try before giving up; a collision on 128 random bits means something else is wrong.
const NAME_ATTEMPTS: usize = 8;

/// Make a file's creation, replacement or removal in `directory` survive a power cut, not only its content.
pub fn fsync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

/// Create a new file in `directory` named `prefix` followed by random hex: exclusively (`O_CREAT | O_EXCL`, which
/// also refuses a symbolic link at that name), with mode 0600 whatever the umask allows more of.
pub fn create_temporary(directory: &Path, prefix: &str) -> io::Result<(File, PathBuf)> {
    let mut last_error = io::Error::new(io::ErrorKind::AlreadyExists, "no free temporary name");
    for _ in 0..NAME_ATTEMPTS {
        let mut random = [0u8; NAME_RANDOM_BYTES];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let path = directory.join(format!("{prefix}{}", hex(&random)));
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last_error = error,
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

/// Replace `path` so that a reader, or a power cut, sees the old content or the new, never half of one.
///
/// A symbolic link at `path` is replaced by the file; it is never written through.
pub fn write_atomic(path: &Path, content: &[u8]) -> io::Result<()> {
    let (directory, prefix) = parts(path)?;
    let (mut file, temporary) = create_temporary(directory, &prefix)?;
    let written = file
        .write_all(content)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temporary, path));
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    fsync_directory(directory)
}

/// `write_atomic` for a file of the hub's own: refused (`InvalidInput`) when its name holds anything but a regular file
/// (a symbolic link, a directory), which a person must look at, rather than replaced by the write.
pub fn write_own_file(path: &Path, content: &[u8]) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => Err(not_a_regular_file(path)),
        Ok(_) => write_atomic(path, content),
        Err(error) if error.kind() == io::ErrorKind::NotFound => write_atomic(path, content),
        Err(error) => Err(error),
    }
}

/// What a name in the state directory holds when it is not a regular file, in words: `None` for a regular file and
/// for nothing at all.
pub fn non_file_kind(path: &Path) -> io::Result<Option<&'static str>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let kind = meta.file_type();
            Ok(if kind.is_file() {
                None
            } else if kind.is_symlink() {
                Some("a symbolic link")
            } else if kind.is_dir() {
                Some("a directory")
            } else {
                Some("not a regular file")
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Create `path` for its owner only, or, if it exists, make sure it still is: the hub's state files hold personal
/// data (queued events, what was last seen of each device). A file of the hub's own that has become readable by
/// others is closed again, not trusted as it is. A symbolic link or anything but a regular file is refused.
pub fn private_file(path: &Path) -> io::Result<()> {
    match OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
        Ok(file) => {
            // The umask cannot add bits, but be exact rather than rely on that.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            drop(file);
            let (directory, _) = parts(path)?;
            fsync_directory(directory)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let file = open_regular(path, OpenOptions::new().read(true))?;
            let mode = file.metadata()?.permissions().mode() & 0o7777;
            if mode & 0o077 != 0 {
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Open `path`, which must be a regular file reached without a symbolic link at its last component.
///
/// Without `O_NOFOLLOW` (std has no portable constant for it, and `libc` is not a dependency): the name is looked at
/// without following (`lstat`), opened, and the opened file must be that same file (device and inode). A link swapped
/// in between the two steps is opened through, and then refused, before anything is read from or written to it.
pub fn open_regular(path: &Path, options: &OpenOptions) -> io::Result<File> {
    let seen = std::fs::symlink_metadata(path)?;
    if !seen.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file() || opened.dev() != seen.dev() || opened.ino() != seen.ino() {
        return Err(not_a_regular_file(path));
    }
    Ok(file)
}

fn not_a_regular_file(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} is a link or not a regular file", path.display()),
    )
}

/// The prefix of the temporary files `write_atomic` makes for a file named `name`: `.<name>.` (followed by
/// `NAME_RANDOM_BYTES` as lowercase hex). The sweeper recognises leftovers by it (`is_temporary_of`).
pub fn temporary_prefix(name: &str) -> String {
    format!(".{name}.")
}

/// Whether `candidate` is a temporary file name of `name`: its prefix and exactly the random hex, nothing else.
pub fn is_temporary_of(name: &str, candidate: &str) -> bool {
    candidate.strip_prefix(&temporary_prefix(name)).is_some_and(|rest| {
        rest.len() == NAME_RANDOM_BYTES * 2 && rest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The directory `path` is in and the prefix of its temporary files (`temporary_prefix`).
fn parts(path: &Path) -> io::Result<(&Path, String)> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "a path without a file name"))?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok((directory, temporary_prefix(&name.to_string_lossy())))
}
