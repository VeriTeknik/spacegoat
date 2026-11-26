// SPDX-License-Identifier: AGPL-3.0-or-later
//! A hub with its own freshly generated key, registered at a fake service, with its configuration file: the fixture
//! the agent and command-line tests share (the Python tests' `hub` fixture).

use std::path::PathBuf;

use spacegoat_hub::agent::{Agent, OUTBOX_FILE};
use spacegoat_hub::config::{self, Config};
use spacegoat_hub::keystore::FileKeyStore;
use spacegoat_hub::simulate::{SimulatedObserver, devices};

use super::TempDir;
use super::fake_service::{FakeService, TestClock};

pub const SOURCE: &str = "01234567-89ab-4cde-8fab-0123456789ab";
pub const KEY_ID: &str = "hub-key-1";

pub struct Hub {
    pub service: FakeService,
    pub state: PathBuf,
    pub config_path: PathBuf,
    pub config: Config,
    /// The clock both the hub and the service read, unless a test gives the hub another.
    pub clock: TestClock,
    pub tmp: TempDir,
}

impl Hub {
    pub fn new() -> Self {
        let tmp = TempDir::new();
        let state = tmp.join("state");
        let store = FileKeyStore::new(state.join("hub.key"));
        store.create().unwrap();
        let key = store.load().unwrap();
        let service = FakeService::new(SOURCE, KEY_ID, key.verifying_key());
        let clock = TestClock::new();
        service.set_now(clock.as_fn());
        let config_path = tmp.join("hub.toml");
        std::fs::write(
            &config_path,
            format!(
                "base_url = \"{}\"\nsource_id = \"{SOURCE}\"\nkey_id = \"{KEY_ID}\"\nstate_dir = \"{}\"\n",
                service.base_url,
                state.display()
            ),
        )
        .unwrap();
        let config = config::load(&config_path).unwrap();
        Self {
            service,
            state,
            config_path,
            config,
            clock,
            tmp,
        }
    }

    /// The agent on the simulated network, on the shared clock.
    pub fn agent(&self) -> Agent {
        Agent::open(&self.config, Box::new(SimulatedObserver::new()), self.clock.as_fn()).unwrap()
    }

    /// An agent that has ticked `steps` times.
    pub fn run(&self, steps: usize) -> Agent {
        let mut agent = self.agent();
        for _ in 0..steps {
            agent.tick().unwrap();
        }
        agent
    }

    /// The outbox and its journal files are gone (a lost or wiped queue).
    pub fn lose_outbox(&self) {
        for entry in std::fs::read_dir(&self.state).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy().starts_with(OUTBOX_FILE) {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }
    }
}

/// Everything personal about the simulated devices, and the local identities the hub never reports.
pub fn personal_data() -> Vec<String> {
    let mut found = Vec::new();
    for device in devices() {
        found.push(device.identity);
        found.extend(device.mac);
        found.extend(device.hostname);
        found.extend(device.ip);
    }
    found.push("192.0.2".to_owned());
    found.push("00005e0053".to_owned());
    found
}

/// Panics, naming it, if `text` contains anything from `personal_data()`.
pub fn assert_no_personal_data(text: &str, where_: &str) {
    for item in personal_data() {
        assert!(!text.contains(&item), "{where_} contains {item:?}: {text}");
    }
}
