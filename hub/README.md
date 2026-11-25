# Hub agent

The Linux hub agent.
It observes the local network, keeps what it sees as signed events in an ordered local queue, and sends them to the hub service.
Licence: AGPL-3.0-or-later.

The protocol it speaks is in [`../spec/protocol.md`](../spec/protocol.md); the agent is tested against the vectors in [`../spec/vectors`](../spec/vectors).

## State of this version (0.1)

| Part | State |
|---|---|
| Key, signing, canonical JSON | Done; checked against the published vectors |
| Durable ordered queue | Done |
| Delivery, retry, halting on refusals | Done; tested against a service that verifies signatures and sequence |
| Simulated network (`--simulate`) | Done |
| Real network observers (ARP, DHCP, mDNS, ...) | Not yet |
| Display, hardware profiles, service unit | Not yet |

This version cannot observe a real network: `run` refuses to start without `--simulate`.

## Try it

Requires Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).

```bash
cd hub
uv sync
uv run pytest
```

### 1. Generate the hub's key

```bash
uv run spacegoat-hub keygen --state-dir /var/lib/spacegoat --key-id hub-key-1
```

It prints the key id and the public key.
The private key stays in `/var/lib/spacegoat/hub.key`, readable by its owner only, and is never printed.
`keygen` refuses to replace an existing key: the key is the hub's identity.

### 2. Register the hub

A person registers the hub in the hub service's panel, with the key id and the public key from step 1.
The service answers with the hub's **source id**.
Registration is a deliberate, recorded act by a person; the agent cannot register itself.

### 3. Configure

```toml
# /etc/spacegoat/hub.toml
base_url  = "https://<the hub service>"
source_id = "<the source id from registration>"
key_id    = "hub-key-1"
state_dir = "/var/lib/spacegoat"
```

Unknown keys are refused. `base_url` must be `https`.

### 4. Run

```bash
uv run spacegoat-hub run --config /etc/spacegoat/hub.toml --simulate
uv run spacegoat-hub status --config /etc/spacegoat/hub.toml
```

`status` prints counts and state only: the last sequence number assigned and confirmed, how many events wait, and why the agent stopped if it did.
It never prints a device, a name or an address.

## What the agent keeps on disk

All under `state_dir`, readable by its owner only:

| File | What |
|---|---|
| `hub.key` | The private key |
| `outbox.sqlite` | Signed events not yet confirmed by the service |
| `confirmed.json` | The last sequence number the service confirmed |
| `pseudonyms.sqlite` | Which random reference stands for which device, and what was last reported about it |
| `agent.json` | Why the agent is waiting or halted |

`pseudonyms.sqlite` holds what the hub last saw of each device, including its name and addresses.
It is personal data: keep the state directory private, and take it with you if you move the hub to new hardware (the service then keeps recognising the same devices).

## How it behaves when things go wrong

- **No answer, or the service is down:** the same events are sent again later, with the same signatures. The service counts repeats; nothing is lost and nothing is recorded twice.
- **Power cut:** an event is either fully in the queue or not there at all. The sequence continues without a gap.
- **The queue is lost but `confirmed.json` is not:** the agent starts a new queue with a `site_source.reset` event that says where it stood. It never starts over silently.
- **Everything is lost (a reinstall):** the service refuses the new sequence and the agent halts with `gap`. Declaring a reinstall is a deliberate step that this version does not automate.
- **The service refuses a batch for good** (rejected content, unknown key, conflicting replay): the agent **halts** and makes no further request. Sending a refused batch for ever only buries the fault. `status` says why; after the fault is fixed, start the agent again and it continues from where it stood.
- **The clock is not set:** nothing is produced. An event signed with a wrong time cannot be taken back.

## Layout

| Module | What it is |
|---|---|
| `canonical.py` | Canonical JSON |
| `signing.py` | What is signed and how |
| `keystore.py` | The private key on disk |
| `outbox.py` | The durable, ordered queue of signed events |
| `sender.py` | Delivery: one request per step, an honest outcome |
| `state.py` | The confirmed mark and the pseudonyms |
| `agent.py` | Observe, report what changed, deliver |
| `simulate.py` | A simulated network |
| `cli.py` | `keygen`, `run`, `status` |

Hardware differences are declared in [`profiles/`](profiles/README.md); nothing reads them yet.
