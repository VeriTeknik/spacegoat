# Hub agent

The Linux hub agent.
It observes the local network, keeps what it sees as signed events in an ordered local queue, and sends them to the hub service.
Licence: AGPL-3.0-or-later.

The protocol it speaks is in [`../spec/protocol.md`](../spec/protocol.md); an implementation is checked against the vectors in [`../spec/vectors`](../spec/vectors).

## State of this version (0.1)

The agent is written in Rust: one static binary, no async runtime, no `unsafe`.

| Part | State |
|---|---|
| Key, signing, canonical JSON | Done; checked byte for byte against the published vectors |
| Durable ordered queue | Done |
| Delivery, retry, halting on refusals | Done; tested against a service that verifies signatures and sequence |
| Simulated network (`--simulate`) | Done |
| Real network observers (ARP, DHCP, mDNS, ...) | Not yet |
| Display, hardware profiles, service unit, release binaries | Not yet |

This version cannot observe a real network: `run` refuses to start without `--simulate`.
It has been run on Linux (aarch64, musl) and macOS in tests only; it has not run on a real board or against a real hub service.

Measured on `aarch64-unknown-linux-musl`, release build: a 2.9 MB static binary; 2.7 MB of resident memory and one thread while waiting for a service it cannot reach.
Memory while delivering over TLS has not been measured yet.

## Build and try

Requires the Rust toolchain named in [`rust-toolchain.toml`](rust-toolchain.toml) (rustup installs it on first use) and a C compiler (SQLite and the TLS library's primitives are compiled in).

```bash
cd hub
cargo test
cargo build --release
```

```bash
# 1. The hub's key. Prints the key id and the public key; never the private key.
spacegoat-hub keygen --state-dir /var/lib/spacegoat --key-id hub-key-1

# 2. A person registers the hub in the hub service's panel and receives its source id.

# 3. /etc/spacegoat/hub.toml
#    base_url  = "https://<the hub service>"
#    source_id = "<the source id from registration>"
#    key_id    = "hub-key-1"
#    state_dir = "/var/lib/spacegoat"

# 4. Run, and look.
spacegoat-hub run --config /etc/spacegoat/hub.toml --simulate
spacegoat-hub status --config /etc/spacegoat/hub.toml

# The output of step 1 was lost? Print the public half again (never the private key).
spacegoat-hub public-key --state-dir /var/lib/spacegoat --key-id hub-key-1

# After a halt, once its fault is fixed (see below):
spacegoat-hub resume --config /etc/spacegoat/hub.toml
```

`SIGTERM` and `SIGINT` finish the current step and exit with 0.
`run` exits non-zero only when it cannot start (configuration, state directory, key, storage that cannot be opened); once running, a failure is shown in the status and the agent keeps going.
Run the service unit with core dumps disabled (`LimitCORE=0` under systemd): a core dump of the process would hold its private key.

The rest of this page is the behaviour the agent has, written apart from the code so that it can be reviewed by itself.

## Identity and registration

- The hub has one Ed25519 key. Generating it prints the key id and the public key; the private key is readable by its owner only and is never printed.
- Generating a key never replaces an existing one: the key is the hub's identity. If the printed public key was lost, `public-key` prints it again from the key on disk; there is no need to delete the identity and register anew.
- A person registers the hub in the hub service's panel with the key id and the public key, and receives the hub's source id. Registration is a deliberate, recorded act by a person; the agent cannot register itself.

## Configuration

The agent is given the service's origin, its source id, its key id and a private state directory.
Unknown settings are refused.
The service address is an origin only: `https`, a host and optionally a port; no path, query or credentials.

## What the agent keeps

All in its state directory, readable by its owner only:

- the private key;
- signed events not yet confirmed by the service;
- the last sequence number the service confirmed;
- which random reference stands for which device, and what was last reported about it;
- why the agent is waiting, and its current problem (`agent.json`, rewritten only when that changes);
- why and since when it is halted (`halt.json`), until a person clears it.

The agent refuses a state directory that other users can enter or that belongs to another user, and never changes the permissions of one that already exists.
When it starts it removes temporary files a process that died mid-write left behind: only files (or symbolic links, which are removed and never followed) whose names have the exact form of its own temporary files; any other name, and a directory, is left alone.

The record of what was last reported about each device includes its name and addresses.
It is personal data: keep the state directory private, and take it along when the hub moves to new hardware (the service then keeps recognising the same devices).

A status command prints counts and state only: the last sequence number assigned and confirmed, how many events wait, why the agent stopped and since when (with the `resume` command that clears it), what it is waiting for, and its current problem.
It never prints a device, a name or an address.
It changes nothing the hub keeps; reading the queue may make SQLite create the queue's `-wal` and `-shm` side files when they are missing.

## Time

The hub reads two clocks.
The wall clock says what time it is; it is used only to name a time: when something was observed, the timestamp of a request, and the times it keeps across a restart.
Every interval within a run (back-off, the wait after `unauthorized`, when a heartbeat is due, the pause between rounds) is measured on the monotonic clock, which a wall clock that is set, stepped back or jumps ahead does not move.

The hub trusts its wall clock only while it has a reading of the service's clock (the `Date` of an answer) and the difference that reading implies now is within four minutes.
"Now" includes any jump of the wall clock since the reading: a clock stepped an hour ahead after the reading stops the hub producing at once, without waiting for the next answer, and a clock that was wrong and has since been corrected is trusted again at once.
An answer without a readable `Date` neither gives a reading nor takes one away.
While the clock is not trusted, the hub produces nothing, shows `waitingFor: clock`, and sends a heartbeat whenever one is due to take a new reading.
A time kept from an earlier run that lies in the future (the clock was ahead then) counts as due, so a clock that is set back does not silence a device.

## How it behaves when things go wrong

- **An event gets its sequence number and its signature once**, in one durable step, before anything is sent.
- **The first request of every run is an empty heartbeat**, even when events wait. Its answer gives the service's clock and where the service stands in the sequence; events follow in the next request.
- **No answer, or the service is down:** the same events are sent again later, with the same signatures. The service counts repeats; nothing is lost and nothing is recorded twice. Waits double from 5 seconds up to 240, so the service still hears from the hub at least every 300 seconds.
- **A `200` that confirms nothing** (a batch went and the confirmed mark did not move, or the counts are not integers the protocol's JSON can carry) is treated like no answer: the hub waits before it tries again.
- **Power cut:** an event is either fully in the queue or not there at all. The sequence continues without a gap.
- **The queue is new, lost or damaged:** before it produces anything, the hub compares what the service holds with what it remembers having been confirmed. Neither holds anything: it starts at 1. The service holds a history and the hub remembers nothing: a `site_source.reset` (`reinstall`) at the service's number. The hub remembers a confirmation and the service holds at least that much: a `site_source.reset` (`queue_lost`) at the service's number. The service holds less than the hub remembers being confirmed: the hub **halts** (`gap`); the service lost events, and the hub does not cover for it. Whenever it starts a new queue it reports every device again, under the same reference, since the reports in the lost queue may never have arrived. The service records a reset and a person is told. It never starts over silently.
- **A storage file is damaged:** a queue or pseudonym file that is not a database any more is moved aside (`outbox.sqlite.damaged`, `pseudonyms.sqlite.damaged`, replacing an earlier one) and started anew; the hub says so once on its error output and in its status. A new queue then goes through the rule above. A new pseudonym store means devices get new references: the service sees them as new devices. Any other failure to open a file (permissions, I/O) stops the hub from starting.
- **A storage error while running:** the round is shown as a `problem` in the status, the next round comes after a back-off (5 seconds, doubling, at most 240), and heartbeats go on meanwhile. Failing to write `agent.json` or the confirmed mark is a problem in the status, not a reason to stop delivering.
- **Too much waits:** when 20 000 events wait, the hub stops producing (`waitingFor: backlog`) and keeps delivering. When fewer than half of them wait, it sends one `site_source.input_lost` (`capture_stopped`, from when it stopped to now) and produces again.
- **The service refuses a batch for good** (rejected content, a conflicting replay, a service that lost events, one event the service says is too large): the agent **halts**. It makes no further request and produces no further events, also after a restart: the halt is kept in the state directory. Sending a refused batch for ever only buries the fault. The status says why and since when, and names the command that clears it. After the fault is fixed, a person runs `spacegoat-hub resume --config FILE` (it refuses while the agent runs) and starts the agent, which continues from where it stood.
- **Too large:** a batch of several events that the service finds too large is halved, whatever the answer's body. One event is "too large for good" only when the service itself says so (`{"error":"too_large"}`); a `413` to a heartbeat, or one that is not the service's answer, is a reason to wait, not to halt.
- **`unauthorized`:** not final. The service gives that answer for an unknown key and for a clock more than five minutes off, and a clock corrects itself. The agent shows it in its status and tries again every 240 seconds.
- **A redirect, or an answer that is not the service's:** never followed, never taken as a confirmation.
- **Half an answer:** an answer that cannot be read in full is no answer; the events are sent again.

### Known limits

- The service refuses an event older than about 24.8 days. A hub that could not deliver for longer than that halts when it reconnects, and cannot get past it by itself (see "Known gap in version 1" in the protocol).
- `site.device_gone` is not sent by this version, and the seven-day rule for devices whose identity keeps changing (protocol §9) is not in it: an observer says whether a device is ephemeral, and the simulated one does.
- References of devices that are long gone are not pruned yet: what was last reported about them, personal data included, stays in the state directory.
- A device whose address flaps is reported at every change; there is no debouncing yet.
- A hub clock that is wrong by more than the validity of the service's certificate fails the TLS handshake before any clock reading can be taken; it shows as waiting for the service.
- The root certificates are compiled in (Mozilla's list, `webpki-roots`); they change only with a new binary.

## Layout

| Module | What it is |
|---|---|
| `canonical.rs` | Canonical JSON |
| `signing.rs` | What is signed and how |
| `keystore.rs` | The private key on disk |
| `outbox.rs` | The durable, ordered queue of signed events |
| `sender.rs` | Delivery: one request per step, an honest outcome |
| `state.rs` | The confirmed mark and the pseudonyms |
| `agent.rs` | Observe, report what changed, deliver |
| `simulate.rs` | A simulated network |
| `config.rs`, `cli.rs` | Configuration; `keygen`, `public-key`, `run`, `status`, `resume` |
| `clock.rs`, `fsutil.rs` | The wall and monotonic clocks, protocol time; private, atomic files |
| `tests/support/fake_service.rs` | A test service that verifies what the protocol says the real one does |

Hardware differences are declared in [`profiles/`](profiles/README.md); nothing reads them yet.
