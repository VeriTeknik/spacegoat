// SPDX-License-Identifier: AGPL-3.0-or-later
//! The command line: `keygen`, `public-key`, `run`, `status`, `resume`.
//!
//! Guarantees: `keygen` and `public-key` print the key id and the public key, never the private key; `status` prints
//! counts and state only, never a device, a name or an address; an error is printed as a short reason, never a file's
//! contents or key material. A usage error (an unknown command or option, a missing value) exits 2 with the usage
//! text, as the Python `argparse` did.
//!
//! `status` does not change what the hub keeps: it creates no outbox, takes no lock, does not open the key, and opens
//! the outbox read-only. Reading a database in write-ahead-log mode can make SQLite create its `-wal` and `-shm`
//! side files next to it when they are missing (it needs them to read a log a crash left behind, and an `immutable`
//! read that would avoid them would also miss what that log holds); nothing else is written.
//!
//! `run` stops on SIGTERM or SIGINT: the tick in progress is finished, the agent is closed and the exit status is 0.
//! Once the agent is open, a failure while running does not end it (`agent::run`); only failing to open exits non-zero.
//!
//! `resume` clears a recorded halt, after a person has fixed the fault: exit 0 when it cleared one, 1 (with the
//! reason) when there was none or an agent is running on the directory.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::agent::{self, Agent, AgentError, KEY_FILE, OUTBOX_FILE};
use crate::clock::SystemClock;
use crate::config::{self, Config};
use crate::keystore::{FileKeyStore, KeyStoreError};
use crate::outbox::Outbox;
use crate::signing;
use crate::simulate::SimulatedObserver;

pub const USAGE: &str = "usage: spacegoat-hub [-h] [--version] {keygen,public-key,run,status,resume} ...

commands:
  keygen --state-dir DIR --key-id ID       generate the hub's key and print its public half
  public-key --state-dir DIR --key-id ID   print the public half of the existing key again
  run --config FILE [--simulate]           observe and report until stopped
  status --config FILE                     print where the hub stands (counts only)
  resume --config FILE                     clear a halt, once its fault is fixed
";

/// Success.
pub const EXIT_OK: u8 = 0;
/// The command ran and failed (a key that exists, storage that failed).
pub const EXIT_FAILED: u8 = 1;
/// The command could not start: usage, configuration, or what the agent refuses to start with.
pub const EXIT_USAGE: u8 = 2;

const NO_OBSERVER: &str = "this version has no network observer yet; run with --simulate";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    Keygen { state_dir: PathBuf, key_id: String },
    PublicKey { state_dir: PathBuf, key_id: String },
    Run { config: PathBuf, simulate: bool },
    Status { config: PathBuf },
    Resume { config: PathBuf },
}

/// Run the command line `args` (without the program name). `run` installs the SIGTERM and SIGINT handlers.
pub fn run(args: impl IntoIterator<Item = OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    execute(args, stdout, stderr, Arc::new(AtomicBool::new(false)), true)
}

/// The same without signal handlers: `run` stops when `stop` is set (for tests, and for embedding).
pub fn run_until(
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    stop: Arc<AtomicBool>,
) -> u8 {
    execute(args, stdout, stderr, stop, false)
}

fn execute(
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    stop: Arc<AtomicBool>,
    signals: bool,
) -> u8 {
    let command = match parse(args) {
        Ok(command) => command,
        Err(reason) => {
            let _ = writeln!(stderr, "{USAGE}spacegoat-hub: error: {reason}");
            return EXIT_USAGE;
        }
    };
    match command {
        Command::Help => {
            let _ = stdout.write_all(USAGE.as_bytes());
            EXIT_OK
        }
        Command::Version => {
            let _ = writeln!(stdout, "spacegoat-hub {}", env!("CARGO_PKG_VERSION"));
            EXIT_OK
        }
        Command::Keygen { state_dir, key_id } => keygen(&state_dir, &key_id, stdout, stderr),
        Command::PublicKey { state_dir, key_id } => public_key(&state_dir, &key_id, stdout, stderr),
        Command::Run { config, simulate } => run_agent(&config, simulate, stderr, stop, signals),
        Command::Status { config } => status(&config, stdout, stderr),
        Command::Resume { config } => resume(&config, stdout, stderr),
    }
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut args = args
        .into_iter()
        .map(|arg| arg.into_string().map_err(|_| "arguments must be UTF-8 text".to_owned()))
        .collect::<Result<Vec<String>, String>>()?
        .into_iter();
    let command = match args.next() {
        None => return Err("a command is required (keygen, public-key, run, status or resume)".to_owned()),
        Some(first) => first,
    };
    // What each command takes: the option names, and whether each takes a value.
    let takes: &[(&str, bool)] = match command.as_str() {
        "-h" | "--help" => return Ok(Command::Help),
        "--version" => return Ok(Command::Version),
        "keygen" | "public-key" => &[("--state-dir", true), ("--key-id", true)],
        "run" => &[("--config", true), ("--simulate", false)],
        "status" | "resume" => &[("--config", true)],
        other if other.starts_with('-') => return Err(format!("unknown option {}", shown(other))),
        other => return Err(format!("unknown command {}", shown(other))),
    };
    let mut given: Vec<(&str, String)> = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(Command::Help);
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name.to_owned(), Some(value.to_owned())),
            _ => (arg.clone(), None),
        };
        let Some((option, needs_value)) = takes.iter().find(|(known, _)| *known == name) else {
            return Err(if name.starts_with('-') {
                format!("unknown option {}", shown(&name))
            } else {
                format!("unexpected argument {}", shown(&name))
            });
        };
        if given.iter().any(|(seen, _)| seen == option) {
            return Err(format!("{option} is given twice"));
        }
        let value = match (needs_value, inline) {
            (true, Some(value)) => value,
            (true, None) => match args.next() {
                Some(value) if !value.starts_with('-') => value,
                _ => return Err(format!("{option} needs a value")),
            },
            (false, Some(_)) => return Err(format!("{option} takes no value")),
            (false, None) => String::new(),
        };
        if *needs_value && value.is_empty() {
            return Err(format!("{option} needs a value"));
        }
        given.push((option, value));
    }
    let value = |name: &str| {
        given
            .iter()
            .find(|(seen, _)| *seen == name)
            .map(|(_, value)| value.clone())
    };
    let required = |name: &str| value(name).ok_or_else(|| format!("{name} is required"));
    Ok(match command.as_str() {
        "keygen" => Command::Keygen {
            state_dir: PathBuf::from(required("--state-dir")?),
            key_id: required("--key-id")?,
        },
        "public-key" => Command::PublicKey {
            state_dir: PathBuf::from(required("--state-dir")?),
            key_id: required("--key-id")?,
        },
        "run" => Command::Run {
            config: PathBuf::from(required("--config")?),
            simulate: value("--simulate").is_some(),
        },
        "resume" => Command::Resume {
            config: PathBuf::from(required("--config")?),
        },
        _ => Command::Status {
            config: PathBuf::from(required("--config")?),
        },
    })
}

/// An argument as an error may repeat it: plain printable text of reasonable length, or nothing.
fn shown(arg: &str) -> String {
    if arg.len() <= 64 && arg.bytes().all(|b| b.is_ascii_graphic()) {
        arg.to_owned()
    } else {
        "(not shown)".to_owned()
    }
}

fn keygen(state_dir: &Path, key_id: &str, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if !signing::is_key_id(key_id) {
        let _ = writeln!(stderr, "key id must be 3 to 63 characters of a-z, 0-9 and -");
        return EXIT_USAGE;
    }
    let store = FileKeyStore::new(state_dir.join(KEY_FILE));
    let key = match store.create().and_then(|()| store.load()) {
        Ok(key) => key,
        Err(error @ KeyStoreError::AlreadyExists(_)) => {
            // The way out that does not orphan a registered hub: the public half can always be printed again.
            let _ = writeln!(
                stderr,
                "{error}; to see its public key: spacegoat-hub public-key --state-dir {} --key-id {key_id}",
                state_dir.display()
            );
            return EXIT_FAILED;
        }
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            return EXIT_FAILED;
        }
    };
    print_public(&key, key_id, stdout);
    EXIT_OK
}

/// The public half of the key that exists, for a `keygen` whose output was lost: nothing is created or changed.
fn public_key(state_dir: &Path, key_id: &str, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if !signing::is_key_id(key_id) {
        let _ = writeln!(stderr, "key id must be 3 to 63 characters of a-z, 0-9 and -");
        return EXIT_USAGE;
    }
    match FileKeyStore::new(state_dir.join(KEY_FILE)).load() {
        Ok(key) => {
            print_public(&key, key_id, stdout);
            EXIT_OK
        }
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            EXIT_FAILED
        }
    }
}

/// The public half and the id are what a person enters at registration. The private key is never shown.
fn print_public(key: &ed25519_dalek::SigningKey, key_id: &str, stdout: &mut dyn Write) {
    let _ = writeln!(stdout, "key id:     {key_id}");
    let _ = writeln!(stdout, "public key: {}", signing::public_key_text(key));
}

fn run_agent(path: &Path, simulate: bool, stderr: &mut dyn Write, stop: Arc<AtomicBool>, signals: bool) -> u8 {
    let Some(config) = load_config(path, stderr) else {
        return EXIT_USAGE;
    };
    if !simulate {
        let _ = writeln!(stderr, "{NO_OBSERVER}");
        return EXIT_USAGE;
    }
    let agent = match Agent::open(
        &config,
        Box::new(SimulatedObserver::new()),
        Arc::new(SystemClock::new()),
    ) {
        Ok(agent) => agent,
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            return EXIT_USAGE;
        }
    };
    for notice in agent.notices() {
        let _ = writeln!(stderr, "{notice}");
    }
    if signals {
        for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
            if let Err(error) = signal_hook::flag::register(signal, Arc::clone(&stop)) {
                let _ = writeln!(stderr, "cannot handle signals: {error}");
                let _ = agent.close();
                return EXIT_FAILED;
            }
        }
    }
    match agent::run(agent, stop, std::thread::sleep) {
        Ok(()) => EXIT_OK,
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            EXIT_FAILED
        }
    }
}

fn load_config(path: &Path, stderr: &mut dyn Write) -> Option<Config> {
    match config::load(path) {
        Ok(config) => Some(config),
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            None
        }
    }
}

fn status(path: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let Some(config) = load_config(path, stderr) else {
        return EXIT_USAGE;
    };
    // Read-only: asking where the hub stands must not create a queue, take a lock from the agent or open the key.
    let state_dir = &config.state_dir;
    let saved = agent::read_saved_status(state_dir).map_err(|error| format!("{}: {error}", agent::STATUS_FILE));
    let halt = agent::read_halt(state_dir).map_err(|error| format!("{}: {error}", agent::HALT_FILE));
    let counters = Outbox::read_counters(&state_dir.join(OUTBOX_FILE)).map_err(|error| error.to_string());
    let (saved, halt, counters) = match (saved, halt, counters) {
        (Ok(saved), Ok(halt), Ok(counters)) => (saved, halt, counters),
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
            let _ = writeln!(stderr, "{error}");
            return EXIT_FAILED;
        }
    };
    let resume = format!("spacegoat-hub resume --config {}", path.display());
    let status = agent::read_status(&config, counters, halt, saved, &resume);
    let _ = writeln!(stdout, "{}", status.to_json_text());
    EXIT_OK
}

fn resume(path: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let Some(config) = load_config(path, stderr) else {
        return EXIT_USAGE;
    };
    match agent::resume(&config, None) {
        Ok(Some(halt)) => {
            let since = halt.at.map(|at| format!(" (halted at {at})")).unwrap_or_default();
            let _ = writeln!(
                stdout,
                "cleared the halt: {}{since}; the agent continues where it stood when it next runs",
                halt.reason
            );
            EXIT_OK
        }
        Ok(None) => {
            let _ = writeln!(stderr, "nothing to resume: the agent is not halted");
            EXIT_FAILED
        }
        Err(error @ AgentError::AlreadyRunning(_)) => {
            let _ = writeln!(stderr, "{error}; stop it before resuming");
            EXIT_FAILED
        }
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            EXIT_FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn options_parse_in_either_form_and_in_any_order() {
        let expected = Command::Run {
            config: PathBuf::from("/etc/hub.toml"),
            simulate: true,
        };
        assert_eq!(
            parsed(&["run", "--simulate", "--config", "/etc/hub.toml"]),
            Ok(expected)
        );
        assert_eq!(
            parsed(&["status", "--config=/etc/hub.toml"]),
            Ok(Command::Status {
                config: PathBuf::from("/etc/hub.toml")
            })
        );
    }

    #[test]
    fn what_is_not_understood_is_refused() {
        for args in [
            &[][..],
            &["frobnicate"],
            &["--frobnicate"],
            &["run"],
            &["run", "--config"],
            &["run", "--config", "--simulate"],
            &["run", "--config", ""],
            &["run", "--config", "a", "--config", "b"],
            &["run", "--config", "a", "--simulate=yes"],
            &["run", "--config", "a", "extra"],
            &["status", "--config", "a", "--simulate"],
            &["keygen", "--state-dir", "/s"],
            &["keygen", "--key-id", "k"],
            &["public-key", "--state-dir", "/s"],
            &["resume"],
            &["resume", "--config", "a", "--simulate"],
        ] {
            assert!(parsed(args).is_err(), "{args:?}");
        }
    }
}
