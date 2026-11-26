// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where the hub's private key lives.
//!
//! The key is what makes a hub that hub: whoever holds it can report as it. It is generated on the device, never
//! leaves it, and is never printed. This store keeps it in a file only its owner can read; a hardware key store (TPM)
//! is a later module behind the same two calls.
//!
//! The file is a PKCS#8 PEM (RFC 8410: an Ed25519 private key, no public key part, no encryption), the form every
//! Ed25519 tool reads. It is read strictly: exactly that structure, nothing before or after it.
//!
//! Beside it, `hub.key.id` holds the key id it was generated under (one line), so that `public-key` and `run` know it
//! without being told. A state directory made before that file existed works as before.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::fsutil::{create_temporary, fsync_directory, open_regular};

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----\n";
const PEM_END: &str = "-----END PRIVATE KEY-----\n";

/// The DER of a PKCS#8 v1 Ed25519 private key up to the 32 private bytes: SEQUENCE { INTEGER 0, SEQUENCE { OID
/// 1.3.101.112 }, OCTET STRING { OCTET STRING (32 bytes) } }.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The key file is 119 bytes; anything much longer is not one, and is not read whole.
const MAX_KEY_FILE: u64 = 4096;
/// A key id is at most 63 characters and a newline.
const MAX_KEY_ID_FILE: u64 = 256;
/// What the key id file is called, beside the key: the key's name followed by this.
pub const KEY_ID_SUFFIX: &str = ".id";

#[derive(Debug)]
pub enum KeyStoreError {
    /// There is no key file.
    NoKey(PathBuf),
    /// `create` found a key, or anything else, under the key's name.
    AlreadyExists(PathBuf),
    /// The state directory can be entered by users other than its owner.
    DirectoryOpenToOthers(PathBuf),
    /// The state directory belongs to another user.
    DirectoryOfAnotherUser(PathBuf),
    /// The state directory's name is a file, not a directory.
    NotADirectory(PathBuf),
    /// The state directory belongs to this user, who cannot write it.
    DirectoryNotWritable(PathBuf),
    /// The key id file does not hold a key id.
    NotAKeyId(PathBuf),
    /// The key file can be read or written by users other than its owner.
    Permissions(PathBuf),
    /// The key's name is a symbolic link, a directory or anything but a regular file.
    NotAFile(PathBuf),
    /// The file is not an Ed25519 key in the expected form. The reason is not given: it could quote the file.
    NotAKey(PathBuf),
    /// A file system error, with the path it happened at.
    Io(PathBuf, io::Error),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKey(path) => write!(f, "no key at {}; run `spacegoat-hub keygen` first", path.display()),
            Self::AlreadyExists(path) => write!(f, "a key already exists at {}", path.display()),
            Self::DirectoryOpenToOthers(path) => write!(
                f,
                "{} is open to other users; use one only the hub's user can enter",
                path.display()
            ),
            Self::DirectoryOfAnotherUser(path) => write!(f, "{} belongs to another user", path.display()),
            Self::NotADirectory(path) => write!(f, "{} is not a directory", path.display()),
            Self::DirectoryNotWritable(path) => write!(f, "{} cannot be written by this user", path.display()),
            Self::NotAKeyId(path) => write!(f, "{} does not hold a key id", path.display()),
            Self::Permissions(path) => write!(
                f,
                "the permissions of {} let others read the key; it must be 0600",
                path.display()
            ),
            Self::NotAFile(path) => write!(f, "{} is a link or not a regular file", path.display()),
            Self::NotAKey(path) => write!(f, "{} does not hold a readable Ed25519 key", path.display()),
            Self::Io(path, error) => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl KeyStoreError {
    /// Whether the error is about where the key lives (the state directory), rather than the key itself.
    pub fn is_directory(&self) -> bool {
        matches!(
            self,
            Self::DirectoryOpenToOthers(_)
                | Self::DirectoryOfAnotherUser(_)
                | Self::NotADirectory(_)
                | Self::DirectoryNotWritable(_)
        )
    }
}

impl std::error::Error for KeyStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct FileKeyStore {
    path: PathBuf,
    expected_owner: Option<u32>,
}

impl FileKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            expected_owner: None,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The user the state directory must belong to. By default it is the user this process creates files as (read
    /// from the temporary key file, since std cannot ask for the effective uid); tests set another to see the refusal.
    #[doc(hidden)]
    pub fn expecting_owner(mut self, uid: u32) -> Self {
        self.expected_owner = Some(uid);
        self
    }

    /// Generate a key. Never replaces one: a hub's key is its identity, and overwriting it orphans the hub.
    pub fn create(&self) -> Result<(), KeyStoreError> {
        let directory = self.directory();
        let io_at = |path: &Path| {
            let path = path.to_path_buf();
            move |error| KeyStoreError::Io(path, error)
        };
        let directory_uid = match std::fs::metadata(directory) {
            Ok(found) => {
                if !found.is_dir() {
                    return Err(KeyStoreError::NotADirectory(directory.to_path_buf()));
                }
                // Never change a directory this call did not create: it may be shared (`/tmp`, `/var/lib`).
                if found.permissions().mode() & 0o077 != 0 {
                    return Err(KeyStoreError::DirectoryOpenToOthers(directory.to_path_buf()));
                }
                found.uid()
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_private_directory(directory).map_err(io_at(directory))?;
                std::fs::metadata(directory).map_err(io_at(directory))?.uid()
            }
            Err(error) => return Err(KeyStoreError::Io(directory.to_path_buf(), error)),
        };

        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut_slice())
            .map_err(|error| KeyStoreError::Io(self.path.clone(), io::Error::other(error)))?;
        let pem = pem_of(&seed);
        drop(seed);

        // Written whole to a temporary file first, then installed under its name in one step. A hard link fails if
        // the name exists (a symbolic link there included, which is never followed), so a key is still never
        // replaced; and there is no moment at which a half-written key sits under the real name.
        let name = self.path.file_name().map(|n| n.to_string_lossy().into_owned());
        let prefix = format!(".{}.", name.unwrap_or_default());
        let (mut file, temporary) = match create_temporary(directory, &prefix) {
            Ok(created) => created,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                // Whose directory it is decides what to say: another user's, or this user's without write access.
                let me = match self.expected_owner {
                    Some(uid) => Some(uid),
                    None => crate::fsutil::current_uid().ok(),
                };
                return Err(if me.is_some_and(|me| me != directory_uid) {
                    KeyStoreError::DirectoryOfAnotherUser(directory.to_path_buf())
                } else {
                    KeyStoreError::DirectoryNotWritable(directory.to_path_buf())
                });
            }
            Err(error) => return Err(KeyStoreError::Io(directory.to_path_buf(), error)),
        };
        let installed = (|| {
            file.write_all(pem.as_bytes()).map_err(io_at(&temporary))?;
            file.sync_all().map_err(io_at(&temporary))?;
            let owner = match self.expected_owner {
                Some(uid) => uid,
                None => file.metadata().map_err(io_at(&temporary))?.uid(),
            };
            if owner != directory_uid {
                // Whoever owns the directory can swap what is in it; the key would be theirs, not this user's.
                return Err(KeyStoreError::DirectoryOfAnotherUser(directory.to_path_buf()));
            }
            match std::fs::hard_link(&temporary, &self.path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    Err(KeyStoreError::AlreadyExists(self.path.clone()))
                }
                Err(error) => Err(KeyStoreError::Io(self.path.clone(), error)),
            }
        })();
        drop(file);
        drop(pem);
        let removed = std::fs::remove_file(&temporary);
        installed?;
        removed.map_err(io_at(&temporary))?;
        // One sync makes both the new name and the removal of the temporary one durable.
        fsync_directory(directory).map_err(io_at(directory))
    }

    pub fn load(&self) -> Result<SigningKey, KeyStoreError> {
        let mut file = match open_regular(&self.path, OpenOptions::new().read(true)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(KeyStoreError::NoKey(self.path.clone()));
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                return Err(KeyStoreError::NotAFile(self.path.clone()));
            }
            Err(error) => return Err(KeyStoreError::Io(self.path.clone(), error)),
        };
        let mode = file
            .metadata()
            .map_err(|error| KeyStoreError::Io(self.path.clone(), error))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(KeyStoreError::Permissions(self.path.clone()));
        }
        // Room for the largest file read, so that reading never reallocates and leaves a copy behind.
        let mut text = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE as usize + 1));
        (&mut file)
            .take(MAX_KEY_FILE + 1)
            .read_to_end(&mut text)
            .map_err(|error| KeyStoreError::Io(self.path.clone(), error))?;
        key_of_pem(&text).ok_or_else(|| KeyStoreError::NotAKey(self.path.clone()))
    }

    /// Where the key id is recorded: beside the key, its name followed by `KEY_ID_SUFFIX`.
    pub fn key_id_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(KEY_ID_SUFFIX);
        PathBuf::from(name)
    }

    /// Record the id the key was generated under (`keygen`), privately and atomically.
    pub fn write_key_id(&self, key_id: &str) -> Result<(), KeyStoreError> {
        let path = self.key_id_path();
        crate::fsutil::write_own_file(&path, format!("{key_id}\n").as_bytes())
            .map_err(|error| KeyStoreError::Io(path, error))
    }

    /// The id the key was generated under; `None` when this state directory does not record one (it was made before
    /// the file existed).
    pub fn read_key_id(&self) -> Result<Option<String>, KeyStoreError> {
        let path = self.key_id_path();
        let file = match open_regular(&path, OpenOptions::new().read(true)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => return Err(KeyStoreError::NotAFile(path)),
            Err(error) => return Err(KeyStoreError::Io(path, error)),
        };
        let mut text = Vec::new();
        file.take(MAX_KEY_ID_FILE)
            .read_to_end(&mut text)
            .map_err(|error| KeyStoreError::Io(path.clone(), error))?;
        let id = text.strip_suffix(b"\n").unwrap_or(&text);
        match std::str::from_utf8(id) {
            Ok(id) if crate::signing::is_key_id(id) => Ok(Some(id.to_owned())),
            _ => Err(KeyStoreError::NotAKeyId(path)),
        }
    }

    fn directory(&self) -> &Path {
        match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        }
    }
}

/// Create `directory` 0700, and each missing directory above it; each one is synced into its parent, since a key in a
/// directory that a power cut removes again is a key the operator has already registered and the hub no longer has.
fn create_private_directory(directory: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = Some(directory);
    while let Some(path) = cursor {
        if path.as_os_str().is_empty() || std::fs::symlink_metadata(path).is_ok() {
            break;
        }
        missing.push(path);
        cursor = path.parent();
    }
    for path in missing.iter().rev() {
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            // Created meanwhile by someone else: it is not this call's to change, and the checks below still hold.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && *path != directory => continue,
            Err(error) => return Err(error),
        }
        if *path == directory {
            // The umask may have taken bits away from 0700; this directory is this call's, so set it exactly.
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        fsync_directory(parent)?;
    }
    Ok(())
}

fn pem_of(seed: &[u8; 32]) -> Zeroizing<String> {
    let mut der = Zeroizing::new([0u8; 48]);
    for (slot, byte) in der.iter_mut().zip(PKCS8_ED25519_PREFIX.iter().chain(seed.iter())) {
        *slot = *byte;
    }
    let mut body = Zeroizing::new(String::with_capacity(64));
    STANDARD.encode_string(der.as_slice(), &mut body);
    let mut pem = Zeroizing::new(String::with_capacity(PEM_BEGIN.len() + body.len() + 1 + PEM_END.len()));
    pem.push_str(PEM_BEGIN);
    pem.push_str(&body);
    pem.push('\n');
    pem.push_str(PEM_END);
    pem
}

fn key_of_pem(text: &[u8]) -> Option<SigningKey> {
    let body = text
        .strip_prefix(PEM_BEGIN.as_bytes())?
        .strip_suffix(PEM_END.as_bytes())?
        .strip_suffix(b"\n")?;
    let der = Zeroizing::new(STANDARD.decode(body).ok()?);
    let seed = Zeroizing::new(<[u8; 32]>::try_from(der.strip_prefix(PKCS8_ED25519_PREFIX.as_slice())?).ok()?);
    Some(SigningKey::from_bytes(&seed))
}
