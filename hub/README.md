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

Measured on `aarch64-unknown-linux-musl`, release build: a 3.0 MB static binary (2,969,688 bytes).
Resident memory was 2.7 MB, with one thread, while waiting for a service it could not reach; that was measured before the last two rounds of fixes and has not been measured again.
Memory while delivering over TLS has not been measured yet.

## Build and try

Requires the Rust toolchain named in [`rust-toolchain.toml`](rust-toolchain.toml) (rustup installs it on first use) and a C compiler (SQLite and the TLS library's primitives are compiled in).

```bash
cd hub
cargo test
cargo build --release
```

```bash
# 1. The hub's key. Prints the key id and the public key; never the private key. The state directory must not
#    exist yet (keygen creates it, 0700) or must already be private to this user (0700); keygen never changes the
#    permissions of a directory it did not create.
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

# The output of step 1 was lost? Print the public half again (never the private key). The key id is read from
# the state directory; --key-id is needed only for a state directory an earlier build made.
spacegoat-hub public-key --state-dir /var/lib/spacegoat

# After a halt, once its fault is dealt with (see "Halts" below):
spacegoat-hub resume --config /etc/spacegoat/hub.toml
```

Exit codes, the same in every command:

| Code | Meaning |
|---|---|
| 0 | Success. For `run`: it was stopped by `SIGTERM` or `SIGINT`, after finishing the current step. |
| 1 | The command ran and failed: a runtime error, nothing to resume, a halt that was not cleared, a key that already exists. |
| 2 | It could not start: usage, configuration, the state directory or a file of the hub's own in it, the key, another agent holding the state directory's lock. |

Once `run` is running, a failure does not end it: it is shown in the status, said once on its error output, and the agent keeps going.
Run the service unit with core dumps disabled (`LimitCORE=0` under systemd): a core dump of the process would hold its private key.

The rest of this page is the behaviour the agent has, written apart from the code so that it can be reviewed by itself.

## Identity and registration

- The hub has one Ed25519 key. Generating it prints the key id and the public key; the private key is readable by its owner only and is never printed.
- Generating a key never replaces an existing one: the key is the hub's identity. If the printed public key was lost, `public-key` prints it again from the key on disk; there is no need to delete the identity and register anew.
- The key id is kept beside the key (`hub.key.id`). `public-key` prints it without being told, and refuses a `--key-id` that differs; `run` refuses a configuration whose `key_id` is not that id, naming both. A state directory made before this file existed works as before (then `public-key` needs `--key-id`).
- A person registers the hub in the hub service's panel with the key id and the public key, and receives the hub's source id. Registration is a deliberate, recorded act by a person; the agent cannot register itself.

## Configuration

The agent is given the service's origin, its source id, its key id and a private state directory.
Unknown settings are refused.
The service address is an origin only: `https` (plain `http` only for a service on this very machine: `127.0.0.1`, `localhost`, `::1`), a host and optionally a port; no path, query or credentials.

## What the agent keeps

All in its state directory, readable by its owner only:

- the private key;
- signed events not yet confirmed by the service;
- the last sequence number the service confirmed, and to which source (`confirmed.json`; a mark of another source counts as none, and one in the earlier form without a source is this source's);
- which random reference stands for which device, and what was last reported about it;
- why the agent is waiting, and its current problem (`agent.json`, rewritten only when that changes);
- why and since when it is halted (`halt.json`), until a person clears it.

The agent refuses a state directory that is missing, is not a directory, that other users can enter, that belongs to another user, or that this user cannot write, and says which; it never changes the permissions of one that already exists.
A name of its own (`agent.json`, `halt.json`, `confirmed.json`, `outbox.sqlite`, `pseudonyms.sqlite`) that holds a symbolic link or a directory is refused by every command that meets it, by name: a person must look at it and remove it by hand.
When it starts it removes temporary files a process that died mid-write left behind: only files (or symbolic links, which are removed and never followed) whose names have the exact form of its own temporary files; any other name, and a directory, is left alone.

The record of what was last reported about each device includes its name and addresses.
It is personal data: keep the state directory private, and take it along when the hub moves to new hardware (the service then keeps recognising the same devices).

`status` prints counts and state only, as JSON, these fields in this order:

| Field | What it says |
|---|---|
| `sourceId`, `keyId` | The source and key id from the configuration |
| `lastAssignedSeq` | The last sequence number given to an event |
| `lastAckedSeq` | The last sequence number the service confirmed |
| `pending` | How many events wait to be confirmed |
| `halted` | Why the agent halted (see "Halts"), or `null` |
| `haltedAt` | When it halted, if the clock could say |
| `waitingFor` | `clock`, `unauthorized`, `service` or `backlog`, or `null` |
| `service` | Why the last request got no confirming answer: `no_connection`, `http_<status>` (the number only), `unreadable` (an answer that could not be read in full), `not_confirming` (a `200` that confirmed nothing); `null` after a confirming one |
| `problem` | The hub's own trouble (a short reason, e.g. `pseudonyms_failed`, `outbox_replaced`, `pseudonyms_new`), or `null` |
| `resume` | While halted: the command that clears it, with the configuration's absolute path |

It never prints a device, a name or an address.
It refuses what `run` refuses about the state directory (exit 2) rather than print a status of nothing; a directory that is fine but has never run gives a status of zeros.
It changes nothing the hub keeps and writes nothing in the state directory (to learn which user it runs as it makes a temporary file in the system's temporary directory for a moment); reading the queue may make SQLite create the queue's `-wal` and `-shm` side files when they are missing.

## Time

The hub reads two clocks.
The wall clock says what time it is; it is used only to name a time: when something was observed, the timestamp of a request, and the times it keeps across a restart.
Every interval within a run (back-off, the wait after `unauthorized`, when a heartbeat is due, the pause between rounds) is measured on the monotonic clock, which a wall clock that is set, stepped back or jumps ahead does not move.

The hub trusts its wall clock only while it has a reading of the service's clock (the `Date` of an answer) and the difference that reading implies now is within four minutes.
"Now" includes any jump of the wall clock since the reading: a clock stepped an hour ahead after the reading stops the hub producing at once, without waiting for the next answer, and a clock that was wrong and has since been corrected is trusted again at once.
An answer without a readable `Date` neither gives a reading nor takes one away.
While the clock is not trusted, the hub produces nothing and shows `waitingFor: clock`; it still delivers what it signed before, and sends a heartbeat whenever one is due to take a new reading.
A clock that was trusted and stops being so (a jump) takes a new reading at once: a heartbeat, or the delivery itself, unless the hub is waiting out a back-off.
The tick reads its clocks after the first request of the run has been answered, not before.
A time kept from an earlier run that lies in the future (the clock was ahead then) counts as due, so a clock that is set back does not silence a device.

## How it behaves when things go wrong

- **An event gets its sequence number and its signature once**, in one durable step, before anything is sent.
- **The first request of every run is an empty heartbeat**, even when events wait. Its answer gives the service's clock and where the service stands in the sequence; events follow in the next request.
- **No answer, or the service is down:** the same events are sent again later, with the same signatures. The service counts repeats; nothing is lost and nothing is recorded twice. Waits double from 5 seconds up to 240, so a hub that is running, not halted and not failing to capture is heard from at least every 300 seconds. The status says `waitingFor: service` and which kind of answer it got (`service`), until a confirming one.
- **A `200` that confirms nothing** (a batch went and the confirmed mark did not move, or the counts are not integers the protocol's JSON can carry) is treated like no answer: the hub waits before it tries again.
- **`rate_limited` (`429`):** it waits what `Retry-After` says, but never longer than 240 seconds, like every other wait.
- **Power cut:** an event is either fully in the queue or not there at all. The sequence continues without a gap.
- **The queue is new, lost or damaged:** before it produces anything, the hub compares what the service holds with what it remembers having been confirmed. Neither holds anything: it starts at 1. The service holds a history and the hub remembers nothing: a `site_source.reset` (`reinstall`) at the service's number. The hub remembers a confirmation and the service holds at least that much: a `site_source.reset` (`queue_lost`) at the service's number. The service holds less than the hub remembers being confirmed: the hub **halts** (`gap`); the service lost events, and the hub does not cover for it. Whenever it starts a new queue it reports every device again, under the same reference, since the reports in the lost queue may never have arrived. The service records a reset and a person is told. It never starts over silently.
- **`confirmed.json` cannot be understood:** that is not "nothing was confirmed". Beside a queue that has numbered events, the mark is written again from the queue's own count and the hub says so. Beside a queue that never numbered one, the hub knows it was confirmed something but not how much: it does not apply the gap rule, takes the service's number as its starting point (a `site_source.reset`, `queue_lost`, when the service holds any; 1 when it holds none) and says so.
- **A storage file is damaged:** a queue or pseudonym file that is not a database any more is moved aside (`outbox.sqlite.damaged`, `pseudonyms.sqlite.damaged`, replacing an earlier one) and started anew; the hub says so once on its error output and in its status. A new queue then goes through the rule above. A new pseudonym store means devices get new references: the service sees them as new devices. A pseudonym store that is new or empty beside a queue that has numbered events is said the same way (`pseudonyms_new`). Any other failure to open a file (permissions, a read-only file, I/O, a database another process holds locked) stops the hub from starting, and the file is left where it is: a sound file is never set aside.
- **A storage error while running:** the round is shown as a `problem` in the status and said once on the error output, and the next round comes after a back-off (5 seconds, doubling, at most 240). What is already queued is still delivered. No heartbeat goes out meanwhile: a heartbeat says "alive, nothing to report", which a hub that cannot capture cannot say, so the service's silence alert is the signal. What was last reported about each device is kept in memory for the run: a store that fails to take it does not make the hub report the device again, and the write is retried. Failing to write `agent.json` or the confirmed mark is a problem in the status, not a reason to stop delivering.
- **Too much waits:** when 20 000 events wait, the hub stops producing (`waitingFor: backlog` while the service confirms; `service` while it does not) and keeps delivering, until fewer than half of them wait.
- **Capture stopped for a while:** whenever the hub could not capture for more than 300 seconds (its clock not trusted, its storage failing, halted, its backlog full), it sends one `site_source.input_lost` (`capture_stopped`, until now, and from when it stopped if that was a trusted time) once capture resumes, also after a restart. A shorter stop is not declared.
- **The service refuses a batch for good** (rejected content, a conflicting replay, a service that lost events, one event the service says is too large): the agent **halts**. The same answer to an empty heartbeat refused nothing, and is only a reason to back off. A halted agent makes no further request at all, heartbeats included, and produces no further events, also after a restart: the halt is kept in the state directory. The service cannot tell it from a dead hub; its silence alert is the signal. Sending a refused batch for ever only buries the fault. The status says why and since when, and names the command that clears it; `run` says it once on its error output. See "Halts" below.
- **Too large:** a batch of several events that the service finds too large is halved, whatever the answer's body. One event is "too large for good" only when the service itself says so (`{"error":"too_large"}`); a `413` to a heartbeat, or one that is not the service's answer, is a reason to wait, not to halt.
- **`unauthorized`:** not final. The service gives that answer for an unknown key and for a clock more than five minutes off, and a clock corrects itself. The agent shows it in its status and tries again every 240 seconds.
- **A redirect, or an answer that is not the service's:** never followed, never taken as a confirmation.
- **Half an answer:** an answer that cannot be read in full is no answer; the events are sent again.

### Halts

`spacegoat-hub resume --config FILE` clears a halt (it refuses while the agent runs), and says what clearing it means for its reason.
It first rewrites `agent.json`, then removes `halt.json`; if removing fails the hub is still halted and `resume` exits 1.
After it, the agent continues from where it stood when it next runs.

| Reason | What happened | What a person does before resuming |
|---|---|---|
| `schema` | The service refused the content of a batch. | Find out from the service what it refused, and have it put right (on the service, or with a newer agent). The same batch is sent again: if nothing changed, the hub halts again. An event older than about 24.8 days can never be accepted (see "Known limits"). |
| `replay_conflict` | The service holds another event under a number this hub sent. | Check that no other hub uses this identity, and that the state directory was not restored from an older copy. |
| `too_large` | One event alone is larger than the service accepts. | Check the service's limits and the agent version; unless the service now accepts it, the hub halts again. |
| `ahead` | The service confirmed numbers this hub never assigned: two hubs share one identity. | Resuming does not fix it. Retire one of the two hubs and register it anew (a new key, a new source id). |
| `gap` | The service holds less than this hub had confirmed: it lost events. | The service's operator investigates first; resuming alone halts again unless the service was put right. If the loss is accepted: `resume --config FILE --from-service`, which also sets the confirmed mark to 0, so the hub takes the service's number as its starting point at its next greeting (a `site_source.reset` there, when the service holds any). That works only while the queue holds no numbered events: a gap met during delivery leaves events the service does not have, which cannot be numbered again, and `--from-service` then refuses until `outbox.sqlite` is moved aside (its events are then not delivered). |
| `unknown` | `halt.json` could not be read, or another version wrote a reason this one does not know. | Look at the service's record of this hub before running the agent again. |

### Known limits

- The service refuses an event older than about 24.8 days. A hub that could not deliver for longer than that halts when it reconnects, and cannot get past it by itself (see "Known gap in version 1" in the protocol).
- `site.device_gone` is not sent by this version, and the seven-day rule for devices whose identity keeps changing (protocol §9) is not in it: an observer says whether a device is ephemeral, and the simulated one does.
- References of devices that are long gone are not pruned yet: what was last reported about them, personal data included, stays in the state directory.
- A device whose address flaps is reported at every change; there is no debouncing yet.
- A hub clock that is wrong by more than the validity of the service's certificate fails the TLS handshake before any clock reading can be taken; it shows as waiting for the service (`no_connection`).
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

Hardware differences will be declared in [`profiles/`](profiles/README.md); nothing reads them yet.
