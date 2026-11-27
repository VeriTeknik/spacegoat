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

Measured on `aarch64-unknown-linux-musl`, release build, at the last review pass (memory at the round before it): a 3.0 MB static binary (3,035,224 bytes), 2.9 MB resident (3.2 MB peak) and one thread while waiting for a service it could not reach; memory while delivering over TLS has not been measured.
The HTTP client resolves the service's name in a short-lived thread of its own for each request.

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
# the state directory; --key-id is needed only if keygen stopped between writing the key and writing its id.
spacegoat-hub public-key --state-dir /var/lib/spacegoat

# After a halt, once its fault is dealt with (see "Halts" below):
spacegoat-hub resume --config /etc/spacegoat/hub.toml
```

Exit codes, the same in every command:

| Code | Meaning |
|---|---|
| 0 | Success. For `run`: it was stopped by `SIGTERM` or `SIGINT`, after finishing the current step. |
| 1 | The command ran and failed: a runtime error, nothing to resume, a halt that was not cleared, a key that already exists, a queue `status` cannot read, output the system refused to take (a write error, a pipe whose reader went away; the error output then says what the command did all the same: a key it created, a halt it cleared, a decision it recorded). A standard output that was closed before the command started (`>&-`) cannot be detected and gives 0. |
| 2 | It could not start: usage, configuration, the state directory or a file of the hub's own in it (one a newer version wrote included), the key, another agent holding the state directory's lock. For `run`, anything that keeps the agent from opening. |

Once `run` is running, a failure does not end it: it is shown in the status, said once on its error output, and the agent keeps going.
Run the service unit with core dumps disabled (`LimitCORE=0` under systemd): a core dump of the process would hold its private key.

The rest of this page is the behaviour the agent has, written apart from the code so that it can be reviewed by itself.

## Identity and registration

- The hub has one Ed25519 key. Generating it prints the key id and the public key; the private key is readable by its owner only and is never printed.
- Generating a key never replaces an existing one: the key is the hub's identity. If the printed public key was lost, `public-key` prints it again from the key on disk; there is no need to delete the identity and register anew.
- The key id is kept beside the key (`hub.key.id`). `public-key` prints it without being told, and refuses a `--key-id` that differs; `run` refuses a configuration whose `key_id` is not that id, naming both. If `keygen` stopped after writing the key and before writing its id, the key still works: `run` then cannot check the id, and `public-key` needs `--key-id`.
- A person registers the hub in the hub service's panel with the key id and the public key, and receives the hub's source id. Registration is a deliberate, recorded act by a person; the agent cannot register itself.

## Configuration

The agent is given the service's origin, its source id, its key id and a private state directory, all four as text and all required.
Unknown settings are refused, and so is a value that breaks these rules:

- `source_id` is the UUID the service assigned at registration, in its lowercase 8-4-4-4-12 form;
- `key_id` is 3 to 63 characters of `a`-`z`, `0`-`9` and `-`, starting with a letter or a digit (the same rule `keygen` applies);
- `state_dir` is an absolute path.

The service address is an origin only: `https`, a host and optionally a port; no path, query or credentials.
Plain `http` is accepted only for a service on this very machine named by a loopback address literally, `http://127.0.0.1:<port>` or `http://[::1]:<port>`; not `localhost`, because a name is resolved and a resolver can answer it with an address on the network.

## What the agent keeps

All in its state directory, readable by its owner only:

- the private key;
- signed events not yet confirmed by the service, each with the protocol `schemaVersion` it was built for (`outbox.sqlite`);
- the last sequence number the service confirmed, and to which source (`confirmed.json`; a mark of another source counts as none, and one without a source id or a version cannot be understood), or, after `resume --from-service`, the decision to take the service's state as the starting point;
- which random reference stands for which device, and what was last reported about it (`pseudonyms.sqlite`);
- why the agent is waiting, and its current problem and its cause (`agent.json`, rewritten only when that changes; advisory, it holds no copy of the halt);
- why and since when it is halted (`halt.json`), until a person clears it.

Every file records its format: `PRAGMA user_version = 1` in both databases (set when the file is created), `"version": 1` in `confirmed.json`, `halt.json` and `agent.json`.
A database or a `confirmed.json` or `halt.json` that a newer version wrote is refused (exit 2) by `run` and by `status` alike, never written into or read as something else; so is a database that has tables but records no format ("of no format this program knows").
Such a database is not this program's to repair: a person looks at it, and to go on without it moves it aside.
The hub then starts that file anew: a new queue is declared lost to the service (a `site_source.reset`, under the rule in "How it behaves when things go wrong"), and its events are not delivered; a new pseudonym store gives devices new references.
`agent.json` of another version is simply written anew.

Both databases delete with `secure_delete` on: a confirmed event, or a record of facts that was forgotten, is overwritten in the database file, not left in a free page.
The queue's write-ahead log (`outbox.sqlite-wal`) may still hold a copy of what was deleted until SQLite reuses that part of it.

The agent refuses a state directory that is missing, is not a directory, that other users can enter, that belongs to another user, or that this user cannot write, and says which, in the same words in every command (`keygen` and `public-key` included; `public-key` and `status` only read, and accept a directory this user cannot write); it never changes the permissions of one that already exists.
It learns which user it runs as from a file it creates in the state directory for a moment and removes again; nothing outside the state directory is used, so a missing or unusable temporary directory (`TMPDIR`) does not matter.
`status` and `public-key` on a state directory they cannot write (its permissions, or a file system mounted read-only) compare the directory's owner with the owner of the key file in it instead.
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
| `service` | Why the last request got no confirming answer, or `null` after a confirming one (see below) |
| `problem` | The area of the hub's own trouble, or `null`: `outbox_failed`, `pseudonyms_failed`, `confirmed_failed`, `halt_file_failed`, `status_file_failed`, `compress_failed`, `state_directory_failed`; or what opening set right: `outbox_replaced`, `pseudonyms_replaced`, `pseudonyms_new` |
| `cause` | For a storage failure, its cause (see below); otherwise `null` |
| `resume` | While halted: the command that clears it, with the configuration's absolute path |
| `readOnly` | `true` when `status` could not write in the state directory, so the figures are those last written to the database files themselves (see below); otherwise `false` |

`service` is one of a closed list, taken from the kind of failure, never from an error's text:

| Word | Meaning |
|---|---|
| `dns` | The service's name could not be resolved |
| `refused` | The connection was refused: nothing listens there |
| `timeout` | No complete answer within 30 seconds (or no connection within 10) |
| `tls` | The TLS handshake failed: a certificate that does not verify, a clock it is not valid at, a peer that does not speak TLS |
| `no_connection` | No answer for any other reason (a connection reset or dropped, a network that is unreachable) |
| `http_<status>` | An answer with this status that confirmed nothing (the number only) |
| `unreadable` | An answer that could not be read in full |
| `not_confirming` | A `200` that confirmed nothing |

`cause` is one of `disk_full`, `read_only`, `io`, `locked`, `damaged`, `other`, taken from SQLite's result code or the operating system's error kind, never from an error's text.
The line `run` prints for a problem names the same two words: `problem: outbox_failed (disk_full)`.

It never prints a device, a name or an address.
It refuses what `run` refuses about the state directory (exit 2) rather than print a status of nothing; a directory that is fine but has never run gives a status of zeros.
It changes nothing the hub keeps: the only file it writes in the state directory is the moment's file that tells it which user it runs as, removed at once; reading the queue and the pseudonym store (for their counts and their format) may make SQLite create their `-wal` and `-shm` side files when they are missing.
On a state directory it cannot write it creates nothing: it reads the databases as they were last written to their own files (SQLite's `immutable` mode), which needs no side file, and says so with `"readOnly": true`.
What a write-ahead log beside them still holds (one an agent that was killed left behind) is then not counted; an agent that stopped normally has written everything into the files themselves.

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
- **The first request of every run is an empty heartbeat**, even when events wait. Its answer gives the service's clock and where the service stands in the sequence; events follow in the next request. It confirms nothing queued: an event leaves the queue only after an answer to a request that carried it, and only up to that request's last event, whatever `lastSeq` says beyond it (events above it are confirmed when they are sent, so the service compares each). After a restart that lost an answer, the queued events go again and the service counts them as duplicates; a different event under one of those numbers (a state directory restored from an older copy, or a second hub with this identity) is a `replay_conflict`, not something forgotten unseen.
- **No answer, or the service is down:** the same events are sent again later, with the same signatures. The service counts repeats; nothing is lost and nothing is recorded twice. Waits double from 5 seconds up to 240, so a hub that is running, not halted and not failing to capture is heard from at least every 300 seconds. The status says `waitingFor: service` and which kind of answer it got (`service`), until a confirming one.
- **A `200` that confirms nothing** (a batch went and the confirmed mark did not move, the counts are not integers the protocol's JSON can carry, `accepted` and `duplicates` do not add up to the events sent, or they say every event was taken while `lastSeq` is below the last one sent: the two fields disagree and neither is trusted) is treated like no answer: the hub waits before it tries again.
- **An answer that says the service holds less than it once confirmed** (its `lastSeq` below the hub's confirmed mark, to a heartbeat as much as to a batch): it confirms nothing and is asked again after the back-off (`service: not_confirming`), since something in between may have answered for the service. If the next such answer is lower again, with none at or above the mark between, the service lost events and the hub **halts** (`gap`), as after `seq_gap`. A site with nothing new to report sends only heartbeats, and this is how it finds the loss. An answer lost on the way back leaves the hub's mark behind the service, never ahead, so it is never taken for a loss. The hub does not re-number or re-declare what it holds.
- **A confirmation the hub cannot record** (its disk is full, its file system read-only, the queue locked): a failure like any other. The same batch goes again at the back-off's pace, not at every round, and the status shows `problem: outbox_failed` with its cause.
- **A request that times out:** when it carried more than one event and timed out once its body had started to go out, or while the answer was awaited or read, the next attempt carries half as many, as after a `413`. A timeout while resolving the name or connecting sent nothing of the batch, and halves nothing. When the client cannot say in which phase the time ran out (the overall 30-second limit, a socket's own timeout), the batch is halved. Each confirmed request lets the batch grow back by a quarter (at least one event) up to 500, so it does not jump straight back to the size that just failed.
- **`rate_limited` (`429`):** it waits what `Retry-After` says, but never longer than 240 seconds, like every other wait.
- **Power cut:** an event is either fully in the queue or not there at all. The sequence continues without a gap.
- **The queue is new, lost or damaged:** before it produces anything, the hub compares what the service holds with what it remembers having been confirmed. Neither holds anything: it starts at 1. The service holds a history and the hub remembers nothing: a `site_source.reset` (`reinstall`) at the service's number. The hub remembers a confirmation and the service holds at least that much: a `site_source.reset` (`queue_lost`) at the service's number. The service holds less than the hub remembers being confirmed: once is a suspicion (nothing is settled or produced, `service: not_confirming`, and a fresh greeting follows the back-off); if the next answer is lower again, with none at or above the mark between, the hub **halts** (`gap`): the service lost events, and the hub does not cover for it. Whenever it starts a new queue it reports every device again, under the same reference, since the reports in the lost queue may never have arrived. "At the service's number" means: the reset's `lastAckedSeq` is the `lastSeq` the service reported, and its own `sourceSeq` is the next number. The service records a reset and a person is told. It never starts over silently. A reset is signed only while the clock is trusted at that very moment (it may have jumped during the request whose answer called for the reset); otherwise nothing is written, the answer is dropped, and once the clock is trusted again the hub asks the service again before it declares anything. Meanwhile it keeps the cadence of an untrusted clock: a reading at once after a jump, then a heartbeat whenever one is due, not one per round. If its own storage fails before the reset is declared, what the service said is dropped and no request goes out until the stores settlement writes take a write again; then the next attempt first asks the service again with a heartbeat, since the service's number may have moved meanwhile.
- **`confirmed.json` cannot be understood:** that is not "nothing was confirmed". Beside a queue that has numbered events, the mark is written again from the queue's own count and the hub says so. Beside a queue that never numbered one, the hub knows it was confirmed something but not how much: it does not apply the gap rule, takes the service's number as its starting point (a `site_source.reset`, `queue_lost`, when the service holds any; 1 when it holds none) and says so.
- **A storage file is damaged:** a queue or pseudonym file that is not a database any more is moved aside (`outbox.sqlite.damaged`, `pseudonyms.sqlite.damaged`, replacing an earlier one) and started anew; the hub says so once on its error output and in its status. A new queue then goes through the rule above. A new pseudonym store means devices get new references: the service sees them as new devices. A pseudonym store that is new or empty beside a queue that has numbered events is said the same way (`pseudonyms_new`). A database that is missing while its write-ahead log or shared-memory file is still there (it was moved away without them, or setting a damaged one aside stopped half way) is treated the same way before a new one is made: the log is kept as `outbox.sqlite.damaged-wal` (or `pseudonyms.sqlite.damaged-wal`), never read into the new file nor deleted, and the hub says so. Any other failure to open a file (permissions, a read-only file, I/O, a database another process holds locked) stops the hub from starting, and the file is left where it is: a sound file is never set aside. A reference record in the pseudonym store whose value is not text (damage from outside this program) is passed over when the queue is read at the start, counted and said once; it does not stop the start.
- **A storage error while running:** the round is shown as a `problem` with its `cause` in the status and said on the error output, and the next round comes after a back-off (5 seconds, doubling, at most 240; the same rule as the sender's). What is already queued is still delivered. No heartbeat goes out meanwhile: a heartbeat says "alive, nothing to report", which a hub that cannot capture cannot say, so the service's silence alert is the signal. What one round captures is stored in one transaction per 200 devices (the snapshots go with the last 200): each such part all or nothing. When a later part fails, the earlier parts stay stored and are delivered once, and the failed part is captured at the next round; nothing is reported twice. What was last reported about each device is kept in memory for the run: a store that fails to take it does not make the hub report the device again, and the write is retried, every round (also while capture is stopped by a full backlog or an untrusted clock). An event whose report the store has not taken stays in the queue even after the service confirms it, so a restart in between can still learn what was reported; it is not sent again in this run, delivery of the events behind it goes on, and it leaves the queue as soon as the store has taken its report (after a restart it is sent once more and counted as a duplicate). Such events count toward the backlog's 20 000; the status shows `problem: pseudonyms_failed` with its cause meanwhile. At the start, what the events still queued reported counts as what was last reported (and is written to the store with the next round): the store takes it only after the event is queued, in another file, and a process that ended in between must not leave it behind. Failing to write `agent.json` or the confirmed mark is a problem in the status, not a reason to stop delivering; the confirmed mark's problem stays until the mark is written.
- **One record of what was reported cannot be read**, in whatever way (text that is not a JSON object, text that is not UTF-8, a value that is not text): that device (or segment) counts as never reported: it is announced again (a segment gets its snapshot), under the same reference, and the hub says so once a run on its error output. Capture goes on. A failure of the database itself is a storage error, as above.
- **A state that flaps** (a service that fails and confirms in turn): each kind of line is said at most once in five minutes, and the state that holds at the end of that time is said then. A halt is always said at once.
- **Too much waits:** when 20 000 events wait, the hub stops producing (`waitingFor: backlog` while the service confirms; `service` while it does not) and keeps delivering, until fewer than half of them wait. After a restart it is full only if 20 000 still wait.
- **Capture stopped for a while:** whenever the hub could not capture for more than 300 seconds while it was running (its clock not trusted, its storage failing, halted, its backlog full), it sends one `site_source.input_lost` (`capture_stopped`, until now, and from when it stopped if that was a trusted time) once capture resumes, also after a restart. "Resumes" means the first events captured afterwards are stored: the declaration goes into that same transaction, ahead of them, so a capture that fails first leaves the stop running and one interruption is declared once. A stop that spans a restart is measured by trusted wall time from its start, so a short one is still not declared; time the hub was simply not running is not declared.
- **The service refuses a batch for good** (rejected content, a conflicting replay, a service that lost events, one event the service says is too large): the agent **halts**. The same answer to an empty heartbeat refused nothing, and is only a reason to back off. A halted agent makes no further request at all, heartbeats included, and produces no further events, also after a restart: the halt is kept in the state directory. The service cannot tell it from a dead hub; its silence alert is the signal. Sending a refused batch for ever only buries the fault. The status says why and since when, and names the command that clears it; `run` says it once on its error output. See "Halts" below.
- **Too large:** a batch of several events that the service finds too large is halved, whatever the answer's body. One event is "too large for good" only when the service itself says so (`{"error":"too_large"}`); a `413` to a heartbeat, or one that is not the service's answer, is a reason to wait, not to halt.
- **`unauthorized`:** not final. The service gives that answer for an unknown key and for a clock more than five minutes off, and a clock corrects itself. The agent shows it in its status and tries again every 240 seconds.
- **A redirect, or an answer that is not the service's:** never followed, never taken as a confirmation.
- **Half an answer:** an answer that cannot be read in full is no answer; the events are sent again.

### Halts

`spacegoat-hub resume --config FILE` clears a halt (it refuses while the agent runs), and says what clearing it means for its reason.
It removes `halt.json`; if removing fails the hub is still halted, nothing else changed, and `resume` exits 1.
After it, the agent continues from where it stood when it next runs.

| Reason | What happened | What a person does before resuming |
|---|---|---|
| `schema` | The service refused the content of a batch. | Find out from the service what it refused, and have it put right (on the service, or with a newer agent). The same batch is sent again: if nothing changed, the hub halts again. An event older than about 24.8 days can never be accepted (see "Known limits"). |
| `replay_conflict` | The service holds another event under a number this hub sent. | Check that no other hub uses this identity, and that the state directory was not restored from an older copy. |
| `too_large` | One event alone is larger than the service accepts. | Check the service's limits and the agent version; unless the service now accepts it, the hub halts again. |
| `ahead` | The service confirmed numbers this hub never assigned: two hubs share one identity. | Resuming does not fix it. Retire one of the two hubs and register it anew (a new key, a new source id). |
| `gap` | The service holds less than this hub had confirmed: it lost events. | The service's operator investigates first; resuming alone halts again unless the service was put right. If the loss is accepted: `resume --config FILE --from-service`, which also records in `confirmed.json` that the hub takes the service's state as its starting point: at its next greeting it declares a `site_source.reset` (`queue_lost`) at the service's number, also when the service holds nothing (the reset is then event 1, `lastAckedSeq` 0). It removes the halt first and records the decision last: if the halt cannot be removed, the mark is unchanged; if the decision cannot be recorded, the hub halts again with `gap` at its next start and `--from-service` can be run again. That works only while the queue holds no numbered events: a gap met once the queue numbered events (during delivery, or in a heartbeat's answer) leaves events the service may not have, which cannot be numbered again, and `--from-service` then refuses until `outbox.sqlite`, `outbox.sqlite-wal` and `outbox.sqlite-shm` are moved aside together (their events are then not delivered; a log left behind would be set aside at the next start anyway). |
| `unknown` | `halt.json` could not be read, or another version wrote a reason this one does not know. | Look at the service's record of this hub before running the agent again. |

### Known limits

- The service refuses an event older than about 24.8 days. A hub that could not deliver for longer than that halts when it reconnects, and cannot get past it by itself (see "Known gap in version 1" in the protocol).
- `site.device_gone` is not sent by this version, and the seven-day rule for devices whose identity keeps changing (protocol §9) is not in it: an observer says whether a device is ephemeral, and the simulated one does.
- References of devices that are long gone are not pruned yet: what was last reported about them, personal data included, stays in the state directory.
- A device whose address flaps is reported at every change; there is no debouncing yet.
- A hub clock that is wrong by more than the validity of the service's certificate fails the TLS handshake before any clock reading can be taken; it shows as waiting for the service (`tls`).
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
| `statedir.rs`, `storage.rs` | Whether a state directory is acceptable; the cause of a storage failure |
| `tests/support/fake_service.rs` | A test service that verifies what the protocol says the real one does |

Hardware differences will be declared in [`profiles/`](profiles/README.md); nothing reads them yet.
