# SPDX-License-Identifier: AGPL-3.0-or-later
"""A simulated network, for running the agent end to end before any real observer exists.

It is the same shape a real observer has: each poll returns what is on the network right now. Nothing here touches
a network interface. The addresses are documentation ranges and the hardware addresses are locally administered
examples; the names are under `.example`.
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
    Sighting("sim:printer", "sim:lan", "printer", "0200005e1001", "printer.example", "192.0.2.10"),
    Sighting("sim:laptop", "sim:lan", "user_device", "0200005e1002", "laptop.example", "192.0.2.21"),
    Sighting("sim:plc", "sim:lan", "ot", "0200005e1003", None, "192.0.2.50"),
    Sighting("sim:switch", "sim:lan", "network", "0200005e1004", "switch.example", "192.0.2.2"),
)


class SimulatedObserver:
    """Devices join one per poll until all four are present; from then on they are simply still there."""

    def __init__(self) -> None:
        self._polls = 0

    def poll(self) -> list[Sighting]:
        self._polls += 1
        return list(_DEVICES[: self._polls])
