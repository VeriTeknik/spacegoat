// SPDX-License-Identifier: AGPL-3.0-or-later
//! A simulated network, for running the agent end to end before any real observer exists.
//!
//! Guarantee: nothing here touches a network interface, and everything it reports is reserved for documentation:
//! IPv4 192.0.2.0/24 (RFC 5737), the hardware addresses 00-00-5E-00-53-xx (RFC 7042) and names under `.example`
//! (RFC 2606). It has the shape a real observer has: each poll returns what is on the network right now.

use crate::agent::{Observer, Sighting};

/// One simulated device, as written down.
struct Device {
    identity: &'static str,
    class: &'static str,
    mac: &'static str,
    name: Option<&'static str>,
    ip: &'static str,
}

/// The one simulated segment.
const SEGMENT: &str = "sim:lan";

/// The four simulated devices, in the order they join.
const DEVICES: [Device; 4] = [
    Device {
        identity: "sim:printer",
        class: "printer",
        mac: "00005e005301",
        name: Some("printer.example"),
        ip: "192.0.2.10",
    },
    Device {
        identity: "sim:laptop",
        class: "user_device",
        mac: "00005e005302",
        name: Some("laptop.example"),
        ip: "192.0.2.21",
    },
    Device {
        identity: "sim:plc",
        class: "ot",
        mac: "00005e005303",
        name: None,
        ip: "192.0.2.50",
    },
    Device {
        identity: "sim:switch",
        class: "network",
        mac: "00005e005304",
        name: Some("switch.example"),
        ip: "192.0.2.2",
    },
];

/// Every simulated device, as the observer reports it once all have joined.
pub fn devices() -> Vec<Sighting> {
    DEVICES
        .iter()
        .map(|device| Sighting {
            identity: device.identity.to_owned(),
            segment: SEGMENT.to_owned(),
            device_class: device.class.to_owned(),
            mac: Some(device.mac.to_owned()),
            hostname: device.name.map(str::to_owned),
            ip: Some(device.ip.to_owned()),
        })
        .collect()
}

/// Devices join one per poll until all four are present; from then on they are simply still there.
#[derive(Debug, Default)]
pub struct SimulatedObserver {
    polls: usize,
}

impl SimulatedObserver {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Observer for SimulatedObserver {
    fn poll(&mut self) -> Vec<Sighting> {
        self.polls = self.polls.saturating_add(1);
        devices().into_iter().take(self.polls).collect()
    }
}
