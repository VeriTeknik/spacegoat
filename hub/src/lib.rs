// SPDX-License-Identifier: AGPL-3.0-or-later
//! The SpaceGoat hub agent.
//!
//! The protocol it speaks is in `spec/protocol.md`; the behaviour it must have is in `hub/README.md`.

pub mod agent;
pub mod canonical;
pub mod cli;
pub mod clock;
pub mod config;
pub mod fsutil;
pub mod keystore;
pub mod outbox;
pub mod sender;
pub mod signing;
pub mod simulate;
pub mod state;
