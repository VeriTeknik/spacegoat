# SPDX-License-Identifier: AGPL-3.0-or-later
"""The agent: observe, turn what changed into events, deliver them. One `tick()` does one round of each.

The agent holds no network logic of its own. An observer says what is on the network now; the agent compares that
with what it last reported and writes only the difference to the outbox:

- a device it has not announced yet: `site.device_appeared`;
- a device whose class, name or address differs from what it last reported: `site.device_changed`;
- a device that is still there and unchanged: `site.device_seen`, at most once a day;
- once an hour: `site.inventory_snapshot`, the counts per class.

Personal data (hardware address, name, IP) goes into the event's separate personal-data part and nowhere else: not
into the attributes, not into a log line, not into `status()`.
"""
from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import clock
from .keystore import FileKeyStore
from .outbox import Outbox
from .sender import Sender
from .signing import KEY_ID
from .simulate import Sighting, SimulatedObserver
from .state import Confirmed, Pseudonyms, write_atomic

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
DEVICE_CLASSES = ("ot", "printer", "user_device", "server", "network", "iot", "unknown")
SEEN_EVERY = timedelta(days=1)
SNAPSHOT_EVERY = timedelta(hours=1)
# How many requests one tick may make: enough to drain a backlog in steps, never a busy loop.
SENDS_PER_TICK = 8
CONFIG_KEYS = {"base_url", "source_id", "key_id", "state_dir"}


@dataclass(frozen=True)
class Config:
    base_url: str
    source_id: str
    key_id: str
    state_dir: Path


def load_config(path: Path | str) -> Config:
    """Read the hub's configuration; anything it cannot run with is refused here, by name, before anything starts."""
    raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    unknown = set(raw) - CONFIG_KEYS
    if unknown:
        raise ValueError(f"unknown configuration key: {sorted(unknown)[0]}")
    for key in sorted(CONFIG_KEYS):
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise ValueError(f"configuration key {key} is missing")
    if not raw["base_url"].startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise ValueError("base_url must be https")
    if not UUID.fullmatch(raw["source_id"]):
        raise ValueError("source_id must be the UUID the service assigned at registration")
    if not KEY_ID.fullmatch(raw["key_id"]):
        raise ValueError("key_id must be 3 to 63 characters of a-z, 0-9 and -")
    state_dir = Path(raw["state_dir"])
    if not state_dir.is_absolute():
        raise ValueError("state_dir must be an absolute path")
    return Config(raw["base_url"], raw["source_id"], raw["key_id"], state_dir)


class Agent:
    def __init__(self, config: Config, *, simulate: bool = False, now: Callable[[], datetime] = clock.now) -> None:
        if not simulate:
            raise ValueError("this version has no network observer yet; run with --simulate")
        self._config = config
        self._now = now
        self._observer = SimulatedObserver()
        key = FileKeyStore(config.state_dir / "hub.key").load()
        self._confirmed = Confirmed(config.state_dir / "confirmed.json")
        outbox_path = config.state_dir / "outbox.sqlite"
        lost = not outbox_path.exists() and self._confirmed.read() > 0
        self._outbox = Outbox(outbox_path, source_id=config.source_id, key_id=config.key_id, private_key=key)
        if lost:
            # The service confirmed events and the queue that held what came after is gone. Say so, with the last
            # confirmed number; the service records it and a person is told. Never start over as if nothing happened.
            self._outbox.declare_reset(last_acked_seq=self._confirmed.read(), reason="queue_lost")
        self._pseudonyms = Pseudonyms(config.state_dir / "pseudonyms.sqlite")
        self._sender = Sender(
            base_url=config.base_url, source_id=config.source_id, key_id=config.key_id, private_key=key,
            outbox=self._outbox, now=lambda: self._now().timestamp(),
        )
        self._waiting_for: str | None = None

    def close(self) -> None:
        self._outbox.close()
        self._pseudonyms.close()

    def tick(self) -> None:
        moment = self._now()
        if not clock.clock_is_set(moment):
            self._note("clock")
            return
        self._note(None)
        self._report(self._observer.poll(), moment)
        for _ in range(SENDS_PER_TICK):
            outcome = self._sender.step()
            self._confirmed.write(self._outbox.last_acked())
            if outcome.kind not in ("sent", "retry_now") or (outcome.kind == "sent" and not self._outbox.pending(1)):
                break
        self._save_status()

    def _report(self, sightings: list[Sighting], moment: datetime) -> None:
        at = clock.observed_at_text(moment)
        for sighting in sightings:
            self._report_device(sighting, moment, at)
        for segment in sorted({sighting.segment for sighting in sightings}):
            self._report_snapshot(segment, [s for s in sightings if s.segment == segment], moment, at)

    def _report_device(self, sighting: Sighting, moment: datetime, at: str) -> None:
        refs = {
            "trustOrigin": "hub",
            "deviceRef": self._pseudonyms.ref("device", sighting.identity),
            "segmentRef": self._pseudonyms.ref("segment", sighting.segment),
        }
        known = self._pseudonyms.facts("device", sighting.identity)
        facts = {"class": sighting.device_class, "name": sighting.hostname, "address": sighting.ip}
        personal = (("mac", sighting.mac), ("hostname", sighting.hostname), ("ip", sighting.ip))
        pii = {key: value for key, value in personal if value is not None}
        if not known:
            self._outbox.append("site.device_appeared", at, {**refs, "deviceClass": sighting.device_class}, pii or None)
        else:
            changed = [name for name in ("class", "name", "address") if known.get(name) != facts[name]]
            last_told = datetime.fromisoformat(known["toldAt"])
            if changed:
                attributes = {**refs, "deviceClass": sighting.device_class, "changed": changed}
                self._outbox.append("site.device_changed", at, attributes, pii or None)
            elif moment - last_told >= SEEN_EVERY:
                self._outbox.append("site.device_seen", at, refs)
            else:
                return
        # After the event is durably in the outbox: what was reported is now what the hub last said.
        self._pseudonyms.remember("device", sighting.identity, {**facts, "toldAt": moment.isoformat()})

    def _report_snapshot(self, segment: str, sightings: list[Sighting], moment: datetime, at: str) -> None:
        known = self._pseudonyms.facts("segment", segment)
        if known and moment - datetime.fromisoformat(known["snapshotAt"]) < SNAPSHOT_EVERY:
            return
        counts = {name: sum(1 for sighting in sightings if sighting.device_class == name) for name in DEVICE_CLASSES}
        attributes = {
            "trustOrigin": "hub",
            "segmentRef": self._pseudonyms.ref("segment", segment),
            "counts": counts,
            "ephemeral": 0,
        }
        self._outbox.append("site.inventory_snapshot", at, attributes)
        self._pseudonyms.remember("segment", segment, {"snapshotAt": moment.isoformat()})

    def _note(self, waiting_for: str | None) -> None:
        if waiting_for != self._waiting_for:
            self._waiting_for = waiting_for
            self._save_status()

    def _save_status(self) -> None:
        saved = {"halted": self._sender.halted, "waitingFor": self._waiting_for}
        write_atomic(self._config.state_dir / "agent.json", json.dumps(saved))

    def status(self) -> dict[str, Any]:
        return read_status(self._config, self._outbox, halted=self._sender.halted, waiting_for=self._waiting_for)


def read_status(config: Config, outbox: Outbox, *, halted: str | None, waiting_for: str | None) -> dict[str, Any]:
    """Counts and state only: nothing here names a device, an address or a name."""
    assigned, acked = outbox.last_assigned(), outbox.last_acked()
    return {
        "sourceId": config.source_id,
        "keyId": config.key_id,
        "lastAssignedSeq": assigned,
        "lastAckedSeq": acked,
        "pending": assigned - acked,
        "halted": halted,
        "waitingFor": waiting_for,
    }
