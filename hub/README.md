# Hub agent

The Linux hub agent.
It observes the local network, keeps what it sees as signed events in an ordered local queue, and sends them to the hub service.
Licence: AGPL-3.0-or-later.

The protocol it speaks is in [`../spec/protocol.md`](../spec/protocol.md); an implementation is checked against the vectors in [`../spec/vectors`](../spec/vectors).

## State

**There is no agent code in this repository yet.**
The agent is being written in Rust: one small static binary, few dependencies, and a memory-safe parser for the untrusted packets it will read, so that it also runs well on small boards.
It arrives in its own pull request.

What follows is the behaviour that agent must have.
It is written down here, apart from any code, so that it can be reviewed first.

## Identity and registration

- The hub has one Ed25519 key. Generating it prints the key id and the public key; the private key is readable by its owner only and is never printed.
- Generating a key never replaces an existing one: the key is the hub's identity.
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
- why the agent is waiting or halted.

The agent refuses a state directory that other users can enter, and never changes the permissions of one that already exists.

The record of what was last reported about each device includes its name and addresses.
It is personal data: keep the state directory private, and take it along when the hub moves to new hardware (the service then keeps recognising the same devices).

A status command prints counts and state only: the last sequence number assigned and confirmed, how many events wait, and why the agent stopped if it did.
It never prints a device, a name or an address.

## How it behaves when things go wrong

- **An event gets its sequence number and its signature once**, in one durable step, before anything is sent.
- **No answer, or the service is down:** the same events are sent again later, with the same signatures. The service counts repeats; nothing is lost and nothing is recorded twice.
- **Power cut:** an event is either fully in the queue or not there at all. The sequence continues without a gap.
- **The queue is lost:** the agent asks the service where it stands and starts a new queue with a `site_source.reset` event: its `lastAckedSeq` is the `lastSeq` the service reported and its own `sourceSeq` is the next number (`queue_lost` if it still remembers having been confirmed, `reinstall` if it remembers nothing). The service records it and a person is told. It never starts over silently.
- **The service refuses a batch for good** (rejected content, a conflicting replay, a service that lost events): the agent **halts**. It makes no further request and produces no further events. Sending a refused batch for ever only buries the fault. The status says why; after the fault is fixed, the agent is started again and continues from where it stood.
- **`unauthorized`:** not final. The service gives that answer for an unknown key and for a clock more than five minutes off, and a clock corrects itself. The agent shows it in its status and tries again every five minutes.
- **The clock is wrong:** the agent's first request is an empty one; from the answer it learns the service's time. While its own clock is more than four minutes off (or not set at all), it produces nothing. An event signed with a wrong time cannot be taken back.
- **A redirect, or an answer that is not the service's:** never followed, never taken as a confirmation.
- **Half an answer:** an answer that cannot be read in full is no answer; the events are sent again.

### Known limit

The service refuses an event older than about 24.8 days. A hub that could not deliver for longer than that halts when it reconnects, and cannot get past it by itself (see "Known gap in version 1" in the protocol).

Hardware differences are declared in [`profiles/`](profiles/README.md).
