// SPDX-License-Identifier: AGPL-3.0-or-later
//! The command line: `keygen`, `run`, `status`.
//!
//! Guarantees: `keygen` prints the key id and the public key, never the private key; `status` prints counts and
//! state only, never a device, a name or an address, and changes nothing (it creates no outbox, takes no lock and
//! does not open the key); an error is printed as a short reason, never a file's contents or key material. A usage
//! error (an unknown command or option, a missing value) exits 2 with the usage text, as the Python `argparse` did.
//!
//! `run` stops on SIGTERM or SIGINT: the tick in progress is finished, the agent is closed and the exit status is 0.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::agent::{self, Agent, KEY_FILE, OUTBOX_FILE};
use crate::clock;
use crate::config::{self, Config};
use crate::keystore::FileKeyStore;
use crate::outbox::Outbox;
use crate::signing;
use crate::simulate::SimulatedObserver;

pub const USAGE: &str = "usage: spacegoat-hub [-h] [--version] {keygen,run,status} ...

commands:
  keygen --state-dir DIR --key-id ID   generate the hub's key and print its public half
  run --config FILE [--simulate]       observe and report until stopped
  status --config FILE                 print where the hub stands (counts only)
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
    Run { config: PathBuf, simulate: bool },
    Status { config: PathBuf },
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
        Command::Run { config, simulate } => run_agent(&config, simulate, stderr, stop, signals),
        Command::Status { config } => status(&config, stdout, stderr),
    }
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut args = args
        .into_iter()
        .map(|arg| arg.into_string().map_err(|_| "arguments must be UTF-8 text".to_owned()))
        .collect::<Result<Vec<String>, String>>()?
        .into_iter();
    let command = match args.next() {
        None => return Err("a command is required (keygen, run or status)".to_owned()),
        Some(first) => first,
    };
    // What each command takes: the option names, and whether each takes a value.
    let takes: &[(&str, bool)] = match command.as_str() {
        "-h" | "--help" => return Ok(Command::Help),
        "--version" => return Ok(Command::Version),
        "keygen" => &[("--state-dir", true), ("--key-id", true)],
        "run" => &[("--config", true), ("--simulate", false)],
        "status" => &[("--config", true)],
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
        "run" => Command::Run {
            config: PathBuf::from(required("--config")?),
            simulate: value("--simulate").is_some(),
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
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            return EXIT_FAILED;
        }
    };
    // The public half and the id are what a person enters at registration. The private key is never shown.
    let _ = writeln!(stdout, "key id:     {key_id}");
    let _ = writeln!(stdout, "public key: {}", signing::public_key_text(&key));
    EXIT_OK
}

fn run_agent(path: &Path, simulate: bool, stderr: &mut dyn Write, stop: Arc<AtomicBool>, signals: bool) -> u8 {
    let config = match config::load(path) {
        Ok(config) => config,
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            return EXIT_USAGE;
        }
    };
    if !simulate {
        let _ = writeln!(stderr, "{NO_OBSERVER}");
        return EXIT_USAGE;
    }
    let now: agent::Clock = Arc::new(|| clock::now().unwrap_or(0));
    let agent = match Agent::open(&config, Box::new(SimulatedObserver::new()), now) {
        Ok(agent) => agent,
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            return EXIT_USAGE;
        }
    };
    if signals {
        for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
            if let Err(error) = signal_hook::flag::register(signal, Arc::clone(&stop)) {
                let _ = writeln!(stderr, "cannot handle signals: {error}");
                let _ = agent.close();
                return EXIT_FAILED;
            }
        }
    }
    match agent::run(agent, &stop, std::thread::sleep) {
        Ok(()) => EXIT_OK,
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            EXIT_FAILED
        }
    }
}

fn status(path: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let config: Config = match config::load(path) {
        Ok(config) => config,
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            return EXIT_USAGE;
        }
    };
    // Read-only: asking where the hub stands must not create a queue, take a lock from the agent or open the key.
    let saved = agent::read_saved_status(&config.state_dir);
    let counters = Outbox::read_counters(&config.state_dir.join(OUTBOX_FILE));
    let ((halted, waiting_for), counters) = match (saved, counters) {
        (Ok(saved), Ok(counters)) => (saved, counters),
        (Err(error), _) => {
            let _ = writeln!(stderr, "{}: {error}", agent::STATUS_FILE);
            return EXIT_FAILED;
        }
        (_, Err(error)) => {
            let _ = writeln!(stderr, "{error}");
            return EXIT_FAILED;
        }
    };
    let status = agent::read_status(&config, counters, halted, waiting_for);
    let _ = writeln!(stdout, "{}", status.to_json_text());
    EXIT_OK
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
        ] {
            assert!(parsed(args).is_err(), "{args:?}");
        }
    }
}
