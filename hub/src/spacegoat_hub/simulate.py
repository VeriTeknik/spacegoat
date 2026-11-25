# SPDX-License-Identifier: AGPL-3.0-or-later
"""A simulated network, for running the agent end to end before any real observer exists.

It is the same shape a real observer has: each poll returns what is on the network right now. Nothing here touches
a network interface. Every address is from a documentation range: IPv4 192.0.2.0/24, and the hardware addresses
00-00-5E-00-53-xx that RFC 7042 sets aside for documentation; the names are under `.example`.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Sighting:
    """One device as an observer sees it at one moment. `identity` is local to the hub and is never reported."""

    identity: str
    segment: str
    device_class: str
    mac: str | None = None
    hostname: str | None = None
    ip: str | None = None


_DEVICES = (
    Sighting("sim:printer", "sim:lan", "printer", "00005e005301", "printer.example", "192.0.2.10"),
    Sighting("sim:laptop", "sim:lan", "user_device", "00005e005302", "laptop.example", "192.0.2.21"),
    Sighting("sim:plc", "sim:lan", "ot", "00005e005303", None, "192.0.2.50"),
    Sighting("sim:switch", "sim:lan", "network", "00005e005304", "switch.example", "192.0.2.2"),
)


class SimulatedObserver:
    """Devices join one per poll until all four are present; from then on they are simply still there."""

    def __init__(self) -> None:
        self._polls = 0

    def poll(self) -> list[Sighting]:
        self._polls += 1
        return list(_DEVICES[: self._polls])
