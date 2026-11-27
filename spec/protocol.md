# SpaceGoat hub protocol

Version 1. Licence: Apache-2.0 (see [`LICENSE`](LICENSE)).

This document says what a hub sends to the hub service, how it signs it, and what the service answers.
It is written so that a second implementation can be built from it and checked against the vectors in [`vectors/signing.json`](vectors/signing.json).
The reference implementation is the agent in [`../hub`](../hub).

Nothing here is secret.
The service refuses every request that is not signed by a key it has on record for that hub; knowing the format gives no access.

## 1. Roles

- A **hub** is a device on a local network. It observes that network and reports what it sees.
- The **hub service** receives the reports and appends them to an append-only record of the organisation that owns the hub.
- A hub only ever makes outbound HTTPS requests. The service never connects to a hub.

A hub is known to the service as a **source**: a UUID the service assigned when a person registered the hub together with its public key.
Registration is done by a person in the service's panel, not by the hub; this document does not cover it.

## 2. Canonical JSON

Everything that is signed is signed over canonical JSON:

- object keys sorted by code point, at every level;
- no whitespace: separators are `,` and `:`;
- text is UTF-8 and is not escaped to ASCII (`"ş"` stays `"ş"`); `"` and `\` are escaped, `/` is not;
- the control characters U+0000 to U+001F are escaped, the short way where JSON has one (`\b`, `\t`, `\n`, `\f`, `\r`) and otherwise as `\u00xx` with lowercase hex (`\u001f`); nothing else is escaped (DEL, U+2028 and U+2029 stay as they are);
- the only values are strings, integers, booleans, `null`, objects and arrays;
- integers stay within ±(2^53 - 1);
- object keys are non-empty printable ASCII;
- text is valid Unicode (a lone surrogate has no UTF-8 form and is refused).

A floating-point number has more than one spelling, so it is not allowed anywhere in a signed payload.
An implementation refuses such a value; it does not round it.

In Python this is `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` after checking the value.

## 3. Keys and signatures

- Algorithm: Ed25519.
- Public key text: `ed25519:` followed by the 32 raw public key bytes in base64url without padding.
- Signature text: the 64 signature bytes in base64url without padding.
- Key id: chosen at registration, `^[a-z0-9][a-z0-9-]{2,62}$`.
- A signature that travels with an event names its key: `ed25519:<keyId>:<signature>`.

The private key never leaves the hub.

## 4. Event signature

Each event is signed over:

```
"vt-evidence-event/v1\n" + canonicalJson({
  "sourceId": <the hub's source UUID>,
  "sourceSeq": <integer>,
  "kind": <string>,
  "observedAt": <string>,
  "attributes": <object>,
  "piiCommitment": <64 hex characters, or null>
})
```

- `observedAt` is UTC with millisecond precision and a literal `Z`: `2026-11-24T10:00:00.123Z`. No offset form is accepted.
- `observedAt` must be within 2^31 - 1 milliseconds (about 24.8 days) of the moment the service receives the event, in either direction. An event outside that window is refused with `schema` (section 10).
- `attributes` carries no personal data (section 6).
- `piiCommitment` is `null` when the event has no personal data. That `null` is part of the signed message only: on the wire (section 7) and in an export, an event without personal data omits `piiCommitment`.

The service stores the signature with the event and can verify it again at any later time from the stored fields.

## 5. Request signature

Every request carries four headers:

```
X-VT-Principal: source:<source UUID>
X-VT-Key-Id:    <keyId>
X-VT-Timestamp: <unix seconds>
X-VT-Signature: base64url(Ed25519(
  "vt-machine/v1\n" + principal + "\n" + METHOD + " " + path + "\n" + timestamp + "\n" + sha256hex(bodyBytes)))
```

- `path` is the request path including any query string.
- `bodyBytes` are the exact bytes sent, that is, the compressed bytes when the body is compressed.
- The timestamp is exactly ten digits and must be within 300 seconds of the service's clock.
- Every answer carries a `Date` header; a hub compares it with its own clock (section 11).
- A hub talks to one origin and never follows a redirect: the signed headers and the events would go with it.
- No `Origin` header is sent.

The signature binds the request to one hub, one endpoint, one moment and one body; it cannot be moved to another.

## 6. Personal data

A device's hardware address, announced name and IP address are personal data.
They never appear in `attributes`.
An event that has them carries three extra fields, all three or none:

| Field | Content |
|---|---|
| `pii` | an object with the personal fields the event kind allows |
| `piiNonce` | 64 lowercase hex characters, fresh random for each event |
| `piiCommitment` | `sha256hex(piiNonce + "\|" + canonicalJson(pii))`, where the separator is one vertical bar character |

Only the commitment is signed.
The service keeps the personal data apart from the event and deletes it after its retention period; the event and its signature stay verifiable.

Fields a hub may send as personal data:

| Field | Form |
|---|---|
| `mac` | 12 lowercase hex characters, no separators |
| `hostname` | 1 to 253 characters |
| `ip` | an IPv4 or IPv6 address |

## 7. The ingest request

```
POST <base-url>/api/ops/evidence/ingest
Content-Type: application/json
Content-Encoding: gzip
```

```json
{
  "schemaVersion": 1,
  "events": [
    {
      "sourceSeq": 7,
      "kind": "site.device_appeared",
      "observedAt": "2026-11-24T10:00:00.123Z",
      "attributes": { "trustOrigin": "hub", "deviceRef": "<uuid v4>", "segmentRef": "<uuid v4>", "deviceClass": "printer" },
      "pii": { "mac": "00005e005301", "hostname": "printer.example", "ip": "192.0.2.10" },
      "piiNonce": "<64 hex>",
      "piiCommitment": "<64 hex>",
      "signature": "ed25519:<keyId>:<base64url>"
    }
  ]
}
```

Limits: at most 500 events, 512 KiB compressed, 4 MiB uncompressed.
A request with an empty `events` array is a **heartbeat**: it says the hub is alive and has nothing to report.

## 8. Sequence

`sourceSeq` starts at 1 and increases by exactly one with every event the hub produces, for the life of the source.
The service accepts a batch only when its first event is the next one it expects.
A sequence number is assigned once: an event that was not delivered is sent again with the same number and the same signature.

Four event kinds let a hub say what happened to its own sequence instead of hiding it:

| Kind | When | Attributes |
|---|---|---|
| `site_source.gap_declared` | Events `fromSeq`..`toSeq` will never arrive | `fromSeq`, `toSeq`, `reason`: `operator` |
| `site_source.reset` | The hub lost its queue or was reinstalled | `lastAckedSeq`, `reason`: `queue_lost` or `reinstall` |
| `site_source.input_lost` | The hub could not observe for a time | `reason`: `capture_stopped` or `capture_unreadable`, `toTime`, optional `fromTime` |
| `site_source.event_dropped` | One event was refused for good and is replaced | `reason`: `operator`, `originalKind` |

A `gap_declared` event carries the sequence number just after the gap.

A `reset` event does not restart the sequence.
Its `lastAckedSeq` must equal the last sequence number the **service** holds, and its own sequence number is that plus one; anything else is refused.
The service recognises a repeated event first (section 10): a reset or a gap declaration it has already recorded is counted in `duplicates` when it is sent again, and these rules are applied only to events it has not recorded yet.
A hub therefore asks before it declares: an empty request (section 7) is answered with `lastSeq`, and the hub uses that number, not its own memory of what was confirmed (the two differ whenever an answer was lost on the way back).
Each of them is recorded and raises an alert for a person to look at. A hub never invents a sequence.

All of them carry `trustOrigin: "hub"`.

## 9. What a hub reports

Every event carries `attributes.trustOrigin = "hub"`.

| Kind | When | Attributes | Personal data |
|---|---|---|---|
| `site.device_appeared` | A device with a lasting identity is seen for the first time | `deviceRef`, `segmentRef`, `deviceClass` | `mac`, `hostname`, `ip` |
| `site.device_changed` | Its class, name or address changed | `deviceRef`, `segmentRef`, `deviceClass`, `changed` | `mac`, `hostname`, `ip` |
| `site.device_seen` | It is still there and unchanged; at most once a day per device | `deviceRef`, `segmentRef` | none |
| `site.device_gone` | It has not been seen for the hub's configured time | `deviceRef`, `segmentRef`, `lastSeenAt` | none |
| `site.inventory_snapshot` | Once an hour | `segmentRef`, `counts`, `ephemeral` | none |

- `deviceClass` is one of `ot`, `printer`, `user_device`, `server`, `network`, `iot`, `unknown`.
- `changed` is a non-empty list without repeats drawn from `class`, `name`, `address`.
- `counts` has an integer for each of the seven classes; `ephemeral` is the number of devices whose identity keeps changing.
- `lastSeenAt` has the form of `observedAt`. The service bounds it to the event's own time: it cannot be later, and it counts for at most 90 days before it.

### Pseudonyms

`deviceRef` and `segmentRef` are random version 4 UUIDs the hub generates and remembers.
They are never derived from a hardware address, a subnet or any other property of the device or the network.
The service refuses any other UUID version.

A hub keeps the mapping from a device to its `deviceRef` across restarts and, where it can, across a reinstall.
A hub that loses the mapping starts new pseudonyms; the old devices then simply stop being seen.

### Devices whose identity keeps changing

A device that changes its hardware address is not reported one event at a time: it would write a new permanent record for every address.
Such devices are counted in `ephemeral` only.

A locally administered hardware address alone does not mean the identity is changing.
A device with such an address starts as ephemeral; when the same address is seen on the same segment for 7 days it is treated as lasting and `site.device_appeared` is sent.

## 10. Answers

| Status | Body | What the hub does |
|---|---|---|
| 200 | `{ "accepted": n, "duplicates": m, "lastSeq": k }` | Removes from its queue the events this request carried, up to `k` |
| 400 | `{ "error": "schema" }` | Stops sending and shows the fault locally; the answer never says which field |
| 401 | `{ "error": "unauthorized" }` | Shows the fault locally and tries again slowly (every five minutes) |
| 409 | `{ "error": "seq_gap", "expectedSeq": k }` | Stops sending: the service lost events it had confirmed |
| 409 | `{ "error": "replay_conflict", "sourceSeq": s }` | Stops sending and shows the fault locally |
| 413 | `{ "error": "too_large" }` | Splits the batch |
| 429 | `{ "error": "rate_limited" }` with `Retry-After` | Waits what `Retry-After` says, but never longer than its liveness interval (section 11) allows |
| 503 | `{ "error": "unavailable" }` | Backs off and tries again |

A hub removes from its queue only events the answered request carried, up to `lastSeq`: an answer to an empty request confirms no queued event, and an event above the request's last one is confirmed only by an answer to a request that carries it.
An event the service has already accepted is counted in `duplicates` and changes nothing, so sending a batch again after a lost answer is always safe.
The service compares a repeated event with the one it has on record; a different event under a number already used is a `replay_conflict`.

`401` is the answer both for a key the service does not know and for a timestamp more than 300 seconds off.
A clock corrects itself, so a hub does not treat `401` as final.

A `200` confirms events only when it carries all three of `accepted`, `duplicates` and `lastSeq` as integers.
Any other `200` (a proxy page, a captive portal) confirms nothing.

`seq_gap` cannot ask for anything a hub still has: a hub forgets an event only after the service confirmed it, so the service can only be asking for events it lost.

A hub that stops does not retry by itself: sending the same refused batch for ever only buries the fault.
A person looks, and the hub continues from where it stood.
A stopped hub also stops producing events: a queue that grows behind a fault only gets older.

### Known gap in version 1

An event is signed once and never changes, and the service refuses one older than about 24.8 days.
A hub that could not deliver for longer than that therefore holds events the service will never take, and version 1 gives it no way to say so: the sequence kinds of section 8 carry only the reason `operator`.
Until the protocol gains a reason for expired events, such a hub stops with `schema` and needs a person.

## 11. Liveness

A hub sends at least one request every 300 seconds: a batch when it has events, a heartbeat otherwise.
A hub that stays silent for three times that long raises an alert at the service.
A stopped hub (section 10) sends nothing, heartbeats included, so the service cannot tell it from a dead one: the silence alert is the signal.
A hub that could not capture for a while declares it with `site_source.input_lost` when it resumes.

The first request of a run is a heartbeat.
Its answer tells the hub two things it must not guess: the service's clock (`Date`) and where the service stands in the hub's sequence (`lastSeq`).
A hub whose clock is more than a few minutes from the service's produces no events until it is right: an event signed with a wrong time cannot be taken back.

## 12. What a hub must not do

These are not protocol rules; they are the rules of the project, and a conforming hub follows them:

- no deauthentication, containment or jamming of any network;
- from networks it is not part of, metadata only;
- no password cracking;
- only a fixed list of local commands, never one supplied from outside;
- outbound connections only;
- no active scanning of ports in the first release: it listens, and it may send low-rate ARP requests on its own subnet.
