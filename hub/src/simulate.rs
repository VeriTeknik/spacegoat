// SPDX-License-Identifier: AGPL-3.0-or-later
//! A simulated network, for running the agent end to end before any real observer exists.
//!
//! Guarantee: nothing here touches a network interface, and everything it reports is reserved for documentation:
//! IPv4 192.0.2.0/24 (RFC 5737), the hardware addresses 00-00-5E-00-53-xx (RFC 7042) and names under `.example`
//! (RFC 2606). It has the shape a real observer has: each poll returns what is on the network right now.
//!
//! Besides four devices with lasting addresses there is one whose address changes at every poll (a phone with a
//! randomised hardware address): the observer hands it over as ephemeral, so it is only ever counted.

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
            ephemeral: false,
        })
        .collect()
}

/// The device whose identity keeps changing, as it is seen at poll `poll`: a new hardware address (and so a new
/// identity) each time, still within the documentation range.
pub fn ephemeral_device(poll: usize) -> Sighting {
    let last = 0x80 + poll % 0x80;
    Sighting {
        identity: format!("sim:phone:{last:02x}"),
        segment: SEGMENT.to_owned(),
        device_class: "user_device".to_owned(),
        mac: Some(format!("00005e0053{last:02x}")),
        hostname: None,
        ip: Some(format!("192.0.2.{}", 100 + poll % 100)),
        ephemeral: true,
    }
}

/// Devices join one per poll until all four are present; from then on they are simply still there. The ephemeral
/// one is there from the first poll, under a new address each time.
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
        let mut seen: Vec<Sighting> = devices().into_iter().take(self.polls).collect();
        seen.push(ephemeral_device(self.polls));
        seen
    }
}
