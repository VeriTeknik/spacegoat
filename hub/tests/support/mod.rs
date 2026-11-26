// SPDX-License-Identifier: AGPL-3.0-or-later
//! Helpers shared by the integration tests. Each test file uses only some of them.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;

/// A private directory (0700) under the system temporary directory, with a random name, removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> Self {
        let mut random = [0u8; 12];
        getrandom::fill(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("spacegoat-hub-test-{name}"));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        // The umask may have taken bits away; set exactly 0700.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // A test may have left a directory it cannot be removed from (a mode it set on purpose); open it up first.
        fn open_up(path: &Path) {
            if let Ok(meta) = std::fs::symlink_metadata(path)
                && meta.is_dir()
            {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        open_up(&entry.path());
                    }
                }
            }
        }
        open_up(&self.path);
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The permission bits of `path` (not following a link).
pub fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// The published TEST key of the vectors: the 32 bytes 0, 1, ... 31. Never a real hub's key.
pub fn vector_key() -> SigningKey {
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = i as u8;
    }
    SigningKey::from_bytes(&seed)
}
