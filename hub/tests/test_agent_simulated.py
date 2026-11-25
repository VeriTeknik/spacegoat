# SPDX-License-Identifier: AGPL-3.0-or-later
"""The whole agent with simulated observations: keygen, run, an interruption, a lost outbox, the clock gate."""
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from spacegoat_hub.agent import Agent, load_config
from spacegoat_hub.cli import main
from spacegoat_hub.keystore import FileKeyStore

from .fake_service import FakeService

SOURCE = "01234567-89ab-4cde-8fab-0123456789ab"


@pytest.fixture
def hub(tmp_path):
    """A hub with its own freshly generated key, registered at a fake service, and its config file."""
    state = tmp_path / "state"
    assert main(["keygen", "--state-dir", str(state), "--key-id", "hub-key-1"]) == 0
    key = FileKeyStore(state / "hub.key").load()
    service = FakeService(source_id=SOURCE, key_id="hub-key-1", public_key=key.public_key())
    config = tmp_path / "hub.toml"
    config.write_text(
        f'base_url = "{service.base_url}"\nsource_id = "{SOURCE}"\nkey_id = "hub-key-1"\nstate_dir = "{state}"\n',
        encoding="utf-8",
    )
    yield {"service": service, "config": config, "state": state}
    service.close()


def run_simulated(config: Path, steps: int) -> Agent:
    agent = Agent(load_config(config), simulate=True)
    for _ in range(steps):
        agent.tick()
    return agent


def test_keygen_prints_the_public_key_and_never_the_private_one(tmp_path, capsys):
    state = tmp_path / "state"
    assert main(["keygen", "--state-dir", str(state), "--key-id", "hub-key-1"]) == 0
    out = capsys.readouterr().out
    public = next(line.split()[-1] for line in out.splitlines() if "ed25519:" in line)
    Ed25519PublicKey.from_public_bytes(__import__("base64").urlsafe_b64decode(public.split(":")[1] + "="))
    assert "hub-key-1" in out
    assert "PRIVATE" not in out and (state / "hub.key").read_text() not in out
    # A second keygen refuses: it would orphan a registered hub.
    assert main(["keygen", "--state-dir", str(state), "--key-id", "hub-key-1"]) == 1
    assert "already exists" in capsys.readouterr().err


def test_keygen_refuses_a_malformed_key_id(tmp_path, capsys):
    assert main(["keygen", "--state-dir", str(tmp_path / "s"), "--key-id", "Bad Key"]) == 2
    assert not (tmp_path / "s" / "hub.key").exists()


def test_simulated_run_reports_devices_in_order_and_the_service_accepts_each_once(hub):
    # Six hours pass between rounds: a device that is still there is reported as seen once a day, not every round.
    start = datetime.now(UTC)
    rounds = {"n": 0}

    def moment() -> datetime:
        return start + timedelta(hours=6 * rounds["n"])

    hub["service"].now = lambda: moment().timestamp()
    agent = Agent(load_config(hub["config"]), simulate=True, now=moment)
    for _ in range(12):
        agent.tick()
        rounds["n"] += 1
    seen = [e for e in hub["service"].accepted if e["kind"] == "site.device_seen"]
    per_device = {ref: sum(1 for e in seen if e["attributes"]["deviceRef"] == ref)
                  for ref in {e["attributes"]["deviceRef"] for e in seen}}
    assert per_device and max(per_device.values()) <= 3      # twelve rounds are three days
    snapshots = [e for e in hub["service"].accepted if e["kind"] == "site.inventory_snapshot"]
    assert sum(snapshots[-1]["attributes"]["counts"].values()) == 4
    accepted = hub["service"].accepted
    assert [event["sourceSeq"] for event in accepted] == list(range(1, len(accepted) + 1))
    kinds = {event["kind"] for event in accepted}
    assert {"site.device_appeared", "site.device_seen", "site.inventory_snapshot"} <= kinds
    assert all(event["attributes"]["trustOrigin"] == "hub" for event in accepted)
    appeared = next(event for event in accepted if event["kind"] == "site.device_appeared")
    assert set(appeared["pii"]) <= {"mac", "hostname", "ip"} and not set(appeared["pii"]) & set(appeared["attributes"])
    assert agent.status()["lastAckedSeq"] == len(accepted)


def test_stopping_mid_run_and_starting_again_loses_and_repeats_nothing(hub):
    hub["service"].script.append(("lose_answer",))
    first = run_simulated(hub["config"], steps=3)
    before = first.status()["lastAssignedSeq"]
    first.close()                                   # the process ends with events still unconfirmed
    second = run_simulated(hub["config"], steps=40)
    accepted = hub["service"].accepted
    assert [event["sourceSeq"] for event in accepted] == list(range(1, len(accepted) + 1))
    assert second.status()["lastAssignedSeq"] > before
    assert second.status()["lastAckedSeq"] == second.status()["lastAssignedSeq"]
    # The same simulated devices are the same pseudonyms after the restart.
    refs = {e["attributes"]["deviceRef"] for e in accepted if e["kind"] == "site.device_appeared"}
    assert len(refs) == len([e for e in accepted if e["kind"] == "site.device_appeared"])


def test_a_lost_outbox_is_declared_never_papered_over(hub):
    first = run_simulated(hub["config"], steps=8)
    confirmed = first.status()["lastAckedSeq"]
    first.close()
    for leftover in hub["state"].glob("outbox.sqlite*"):
        leftover.unlink()
    second = run_simulated(hub["config"], steps=8)
    accepted = hub["service"].accepted
    reset = next(event for event in accepted if event["kind"] == "site_source.reset")
    assert reset["sourceSeq"] == confirmed + 1
    assert reset["attributes"] == {"trustOrigin": "hub", "lastAckedSeq": confirmed, "reason": "queue_lost"}
    assert [event["sourceSeq"] for event in accepted] == list(range(1, len(accepted) + 1))
    assert second.status()["halted"] is None


def test_a_hub_with_no_record_of_ever_being_confirmed_starts_at_one(hub):
    agent = run_simulated(hub["config"], steps=4)
    assert hub["service"].accepted[0]["sourceSeq"] == 1
    assert all(event["kind"] != "site_source.reset" for event in hub["service"].accepted)
    agent.close()


def test_nothing_is_produced_while_the_clock_is_not_set(hub):
    agent = Agent(load_config(hub["config"]), simulate=True, now=lambda: datetime(2020, 1, 1, tzinfo=UTC))
    for _ in range(5):
        agent.tick()
    assert agent.status()["lastAssignedSeq"] == 0 and hub["service"].requests == []
    assert agent.status()["waitingFor"] == "clock"


def test_status_prints_counts_and_no_device(hub, capsys):
    run_simulated(hub["config"], steps=6).close()
    assert main(["status", "--config", str(hub["config"])]) == 0
    out = capsys.readouterr().out
    status = json.loads(out)
    assert set(status) == {"sourceId", "keyId", "lastAssignedSeq", "lastAckedSeq", "pending", "halted", "waitingFor"}
    assert "printer" not in out and "192.0.2" not in out and "0200" not in out


def test_a_halted_agent_says_why_and_stays_halted_across_ticks(hub):
    hub["service"].script.append(("status", 401, {"error": "unauthorized"}))
    agent = run_simulated(hub["config"], steps=6)
    assert agent.status()["halted"] == "unauthorized"
    assert len(hub["service"].requests) == 1


def test_config_refuses_what_it_cannot_run_with(tmp_path):
    bad = tmp_path / "hub.toml"
    good = {
        "base_url": "https://hub.example",
        "source_id": SOURCE,
        "key_id": "hub-key-1",
        "state_dir": "/var/lib/spacegoat",
    }
    bad.write_text("".join(f'{key} = "{value}"\n' for key, value in good.items()), encoding="utf-8")
    assert load_config(bad).state_dir == Path("/var/lib/spacegoat")
    cases = [
        {**good, "base_url": "http://hub.example"}, {**good, "source_id": "nope"}, {**good, "key_id": "K"},
        {**good, "state_dir": "relative"}, {**good, "extra": "1"}, {k: v for k, v in good.items() if k != "key_id"},
    ]
    for case in cases:
        text = "".join(f'{key} = "{value}"\n' for key, value in case.items())
        bad.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError):
            load_config(bad)


def test_the_installed_command_runs(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    done = subprocess.run([sys.executable, "-m", "spacegoat_hub", "--version"], capture_output=True, text=True, env=env)
    assert done.returncode == 0 and done.stdout.strip().startswith("spacegoat-hub ")
