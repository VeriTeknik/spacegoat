# SPDX-License-Identifier: AGPL-3.0-or-later
"""The command line: `keygen`, `run`, `status`."""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

from . import __version__
from .agent import Agent, load_config, read_status
from .keystore import FileKeyStore, KeyStoreError
from .outbox import Outbox
from .signing import KEY_ID, public_key_text

TICK_SECONDS = 15


def _keygen(args: argparse.Namespace) -> int:
    if not KEY_ID.fullmatch(args.key_id):
        print("key id must be 3 to 63 characters of a-z, 0-9 and -", file=sys.stderr)
        return 2
    store = FileKeyStore(Path(args.state_dir) / "hub.key")
    try:
        store.create()
    except KeyStoreError as error:
        print(str(error), file=sys.stderr)
        return 1
    # The public half and the id are what a person enters at registration. The private key is never shown.
    print(f"key id:     {args.key_id}")
    print(f"public key: {public_key_text(store.load())}")
    return 0


def _run(args: argparse.Namespace) -> int:
    try:
        agent = Agent(load_config(args.config), simulate=args.simulate)
    except (ValueError, KeyStoreError) as error:
        print(str(error), file=sys.stderr)
        return 2
    stopping = False

    def stop(*_signal: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        agent.tick()
        for _ in range(TICK_SECONDS * 10):
            if stopping:
                break
            time.sleep(0.1)
    agent.close()
    return 0


def _status(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
        key = FileKeyStore(config.state_dir / "hub.key").load()
    except (ValueError, KeyStoreError) as error:
        print(str(error), file=sys.stderr)
        return 2
    try:
        saved = json.loads((config.state_dir / "agent.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        saved = {}
    outbox_path = config.state_dir / "outbox.sqlite"
    outbox = Outbox(outbox_path, source_id=config.source_id, key_id=config.key_id, private_key=key)
    status = read_status(config, outbox, halted=saved.get("halted"), waiting_for=saved.get("waitingFor"))
    outbox.close()
    print(json.dumps(status, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="spacegoat-hub", description="SpaceGoat hub agent")
    parser.add_argument("--version", action="version", version=f"spacegoat-hub {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="generate the hub's key and print its public half")
    keygen.add_argument("--state-dir", required=True)
    keygen.add_argument("--key-id", required=True)
    keygen.set_defaults(handler=_keygen)

    run = commands.add_parser("run", help="observe and report until stopped")
    run.add_argument("--config", required=True)
    run.add_argument("--simulate", action="store_true", help="report a simulated network instead of a real one")
    run.set_defaults(handler=_run)

    status = commands.add_parser("status", help="print where the hub stands (counts only)")
    status.add_argument("--config", required=True)
    status.set_defaults(handler=_status)

    args = parser.parse_args(argv)
    return args.handler(args)
