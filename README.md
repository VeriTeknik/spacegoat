# SpaceGoat

Open-source on-site devices for continuous compliance.

A SpaceGoat device sits in an office or a server room, observes what a compliance programme needs to see there, signs each observation with its own key and sends it to a hub service that records it as evidence.
The principle is simple: you cannot fix what you cannot see.

> **Status: early development.**
> Nothing here is ready for production use.
> This repository holds the protocol, its test vectors, and a first hub agent (`hub/`).
> The agent signs, queues and delivers events, but it observes a simulated network only: it has no real network observer and no display yet, and it has not run on a real board or against a real hub service.

## Why open source

A device that observes a network has to be trusted by the people on that network.
The device software is published so that anyone can read what it collects, what it sends and what it never touches.

## What a device does and does not do

- It connects outbound only. It accepts no inbound connection and takes no commands from the network it sits on.
- It signs every request with a per-device Ed25519 key.
- It listens first. The first hub release sends no port scans; industrial equipment can fail under a scan.
- Detection only: no deauthentication, containment or jamming; no password cracking; no capture of traffic content from neighbouring networks.
- A device that cannot reach its hub service says so: its status shows that it is waiting for the service and what kind of answer it got, and the agent says it once on its error output. It never shows a stale "all clear".

## Repository layout

| Path | What it is | Licence |
|---|---|---|
| `hub/` | The Linux hub agent, in Rust: signs, queues and delivers observations to the hub service. Today it observes a simulated network only; listening on a real network, classifying devices and driving a display are not written yet | AGPL-3.0 |
| `hub/profiles/` | The planned shape of a per-hardware profile (interface, display, key store, radios); nothing reads profiles yet | AGPL-3.0 |
| `core/` | Portable C core for microcontroller devices (signing, encoding). Not started | AGPL-3.0 |
| `boards/` | Thin per-board layers for microcontroller devices (display, input, sound). Not started | AGPL-3.0 |
| `spec/` | The wire contract and shared test vectors, so that other hardware can implement it without copying this code | Apache-2.0 |
| `docs/` | Design notes | AGPL-3.0 |

### Supporting different devices

Hardware differences are to live in a **profile**, not in the agent.
A profile will declare the capabilities of one device: its network interface, whether it has a display and which kind, where the device key is stored, and which radios are present.
The agent will load only the modules a profile declares, so adding a device will mean adding a profile and, if needed, one driver module.
Nothing reads profiles yet.
See [`hub/profiles/README.md`](hub/profiles/README.md).

## Licence

The device software is licensed under the GNU Affero General Public License v3.0 (see [`LICENSE`](LICENSE)).
The contents of `spec/` are licensed under the Apache License 2.0 (see [`spec/LICENSE`](spec/LICENSE)).

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).

SpaceGoat is developed by [VeriTeknik](https://veriteknik.com).
