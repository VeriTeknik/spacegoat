# SpaceGoat evidence export

Version 1. Licence: Apache-2.0 (see [`LICENSE`](LICENSE)).

This document says what an evidence export contains and what a verifier checks in it.
An export is a file an auditor can check without SpaceGoat's software: everything needed is in the file, in [`protocol.md`](protocol.md) and in this document.
It is written so that a verifier can be built from these two documents alone and checked against the vectors in [`vectors/export/`](vectors/export/).

An export changes nothing in protocol version 1.
Its events are the events a hub signed, unchanged.

## 1. Encoding

- The file is UTF-8 without a byte order mark.
- It is a sequence of lines, each ended by one LF (`0x0A`); a missing LF after the last line is accepted.
- Each line is one JSON object; there are no empty lines and no comments.
- The first line is the header (section 2); every further line is one event (section 3).

Lines end with LF only.
A line starts with the `{` of its object and ends with its `}`: a CR, or any other whitespace before or after the object, breaks the line (it fails `form`, and for the first line the header is unreadable).
Whitespace between the tokens inside the object is JSON's and is accepted.

An empty line is a line.
As the first line it is an unreadable header; as any later line, including an empty line after the LF that ends the last event, it is an event line that fails `form` (section 5).
The LF that ends the last line is not followed by a line: a file that ends with exactly one LF has no empty line.

A producer writes each line as compact JSON with object keys sorted by code point, as the vectors do.
A verifier does not require that form: the signature covers the canonical form of protocol section 2, which it rebuilds itself.

## 2. Header

```json
{"format":"spacegoat-export/v1","sourceId":"<uuid>","fromSeq":1,"toSeq":7,"keys":[{"keyId":"<keyId>","publicKey":"ed25519:<base64url>"}]}
```

| Field | Rule |
|---|---|
| `format` | exactly `spacegoat-export/v1` |
| `sourceId` | the source UUID of protocol section 1, as 36 lowercase characters `8-4-4-4-12` |
| `fromSeq` | integer, 1 to 2^53 - 1; the sequence number of the first event in the file |
| `toSeq` | integer, `fromSeq` to 2^53 - 1; the sequence number of the last event in the file |
| `keys` | a non-empty array of key objects |

Each key object has exactly two fields:

| Field | Rule |
|---|---|
| `keyId` | a key id of protocol section 3, matched in full (nothing before or after the pattern, not even a line feed); no two key objects share one |
| `publicKey` | public key text of protocol section 3: `ed25519:` and 43 base64url characters, without padding, that decode to 32 bytes, in the canonical spelling (section 4) |

`keys` lists the keys the source has on record.
Which key was valid at which moment is not part of version 1 (section 7).

The header has no other fields.
A header that breaks any rule here, or any value rule of section 4, is **unreadable**: the verifier checks nothing else and exits with status 2.
An empty file, a file that starts with a byte order mark and a first line that is not UTF-8 or not a JSON object are unreadable headers too.

## 3. Event lines

Each event line is one event in the wire form of protocol section 7, as the hub sent it.

| Field | Rule |
|---|---|
| `sourceSeq` | integer, 1 to 2^53 - 1 |
| `kind` | a non-empty string |
| `observedAt` | the form of protocol section 4: `YYYY-MM-DDTHH:MM:SS.mmmZ`, a moment that exists in the proleptic Gregorian calendar, hours 00 to 23, minutes and seconds 00 to 59; the form is checked, not whether the time is plausible, so the year `0000` is accepted |
| `attributes` | an object |
| `signature` | `ed25519:<keyId>:<signature>`: a key id of protocol section 3, matched in full, and 86 base64url characters, without padding, that decode to 64 bytes, in the canonical spelling (section 4) |
| `pii` | an object |
| `piiNonce` | 64 lowercase hex characters |
| `piiCommitment` | 64 lowercase hex characters |

The first five fields are required.
The personal-data fields come in exactly one of three shapes:

| Shape | Fields present | Meaning |
|---|---|---|
| full | `pii`, `piiNonce` and `piiCommitment` | the event has personal data and it is still held |
| redacted | `piiCommitment` only | the event had personal data and it was deleted after its retention period |
| none | none of the three | the event has no personal data |

Any other combination, and any other field, breaks the line.
An event without personal data omits `piiCommitment` (protocol section 4): an explicit `"piiCommitment": null` is present, so it is none of the three shapes and the line fails `form`.

A redacted event is not a fault.
Only the commitment is signed (protocol section 6), so its signature stays verifiable after the personal data is gone.

A verifier does not judge an event's attributes against its kind (protocol section 9), with one exception: the attributes of the two sequence kinds that the `sequence` check reads (section 5).

## 4. Value rules

These apply to every value on every line, the header included, at every depth:

- the value rules of protocol section 2: strings, integers, booleans, `null`, objects and arrays only;
- an integer is a JSON number written as an optional `-` and digits, with no fraction and no exponent, within ±(2^53 - 1); any other number (`1.5`, `1.0`, `1e3`) is a floating-point number and is refused; `-0` is a second spelling of `0` and is refused;
- object keys are non-empty printable ASCII (`0x20` to `0x7E`);
- text is valid Unicode: a lone surrogate, written as a `\u` escape, is refused;
- no object has the same key twice; keys are compared after their escapes are decoded, so `"a"` and `"a"` are the same key and an object holding both breaks the rule;
- nothing is nested deeper than 64 levels: the line's object is level 1, and each object or array inside it adds one level, so a line may hold objects and arrays nested 63 deep below its own object; a deeper line breaks the rule however deep the verifier's parser could read it;
- base64url text (public keys and signatures) is accepted only in its canonical spelling: no padding, and the unused low bits of the last character are zero, so that every key and signature has exactly one spelling.

A floating-point number is valid JSON, but it has more than one spelling and so has no place in a signed payload.
A verifier refuses it and does not round it.

## 5. Checks

A verifier runs five checks.
Each event line is judged by each check that can be evaluated for it, as follows.

### `form`

The line is valid UTF-8, one JSON object, and keeps the rules of sections 1, 3 and 4.

A line that fails `form` is evaluated by no other check except `sequence`, and there only as follows.
It takes the next expected number (previous + 1, or `fromSeq` for the first line), whatever `sourceSeq` it may contain, and nothing more: it justifies no jump, and its kind and attributes are not read.
It passes `sequence` unless that number is greater than `toSeq`, in which case it fails `sequence` too.
This keeps the result independent of how far a verifier could read a broken line.
An empty line after the last event (section 1) is such a line: it fails `form`, and also `sequence` when its number runs past `toSeq`.

### `key`

The key id named in `signature` is, in full, the `keyId` of a key object in the header.

An event that fails `key` is not evaluated by `signature`.

### `signature`

The signature verifies, under the public key the header gives for that key id, over the message of protocol section 4.
The message is built from the header's `sourceId` and the event's `sourceSeq`, `kind`, `observedAt`, `attributes` and `piiCommitment` (`null` when the event has none).
RFC 8032 section 5.1.7 allows two group equations that disagree on some crafted signatures; this check uses the cofactorless one, as the service and the common libraries do:

1. Decode the 32 public key bytes `A` as in RFC 8032 section 5.1.3: a `y` that is not below p, or a `y` for which no point exists, fails the check.
2. Read `S` from the last 32 signature bytes as a little-endian integer; an `S` that is not below the group order L fails the check.
3. Compute `k` = SHA-512(`R` || `A` || message) mod L, where `R` is the first 32 signature bytes and `A` the public key bytes as given.
4. Compute R' = [S]B - [k]A.
5. The check passes only when the encoding of R' (RFC 8032 section 5.1.2) is byte for byte equal to `R`. `R` is never decoded, so a non-canonical or non-decodable `R` fails.

A public key of small order is not refused.
Such a key lets anyone produce signatures that pass; the defence is the comparison of each key's fingerprint with the registration record (section 7).

### `sequence`

The events are walked in file order.
`previous` starts at `fromSeq` - 1; after each event it becomes that event's number (the number it occupies, for a line that failed `form`).
"The first event" is the first line after the header, whether or not that line passed `form`: when the first line is broken, the line after it is never the first event, even if it is a gap declaration.
An event with number `s` passes when one of these holds:

- it is the first event, `s` equals `fromSeq`, and it is not a `site_source.gap_declared` or `site_source.reset` whose own rule below fails;
- `s` equals `previous` + 1, and it is not a `site_source.gap_declared` or `site_source.reset` whose own rule below fails;
- it is a `site_source.gap_declared`, it is not the first event, `s` is greater than `previous` + 1, and its own rule holds.

The rules of the two sequence kinds of protocol section 8:

- `site_source.gap_declared`: `attributes.fromSeq` and `attributes.toSeq` are integers, `toSeq` equals `s` - 1, `fromSeq` is at least 1 and at most `toSeq`, and, unless it is the first event, `fromSeq` equals `previous` + 1.
- `site_source.reset`: `attributes.lastAckedSeq` is an integer equal to `s` - 1.

An attribute these rules read that is missing or is not an integer makes the rule fail, so the event fails `sequence`; it does not fail `form`, which judges no attribute against its kind (section 3).

An event whose number is greater than `toSeq` fails.
After the last line, `previous` must equal `toSeq`; otherwise the check fails at the number `previous` + 1 (at `fromSeq` when there is no event line).

### `commitment`

Evaluated only for an event of the full shape.
`sha256hex(piiNonce + "|" + canonicalJson(pii))` (protocol section 6) equals `piiCommitment`.
A `pii` value that has no canonical form has already failed `form`.

## 6. Result

| Item | Content |
|---|---|
| each check | `ok` when it passed for every event line it was evaluated for, `failed` otherwise |
| `redacted` | the number of event lines that pass `form` and have the redacted shape |
| `firstFailedSeq` | the number of the first event line, in file order, on which any check failed, or `null` when none failed; for a line that failed `form` it is the number that line occupies (section 5), and for a failure after the last line it is the number given there |
| last sequence number | `toSeq`, stated as the end of what the export can show (section 7) |
| keys | each header key with its id and the SHA-256 fingerprint of its 32 raw public key bytes, in lowercase hex |
| exit status | `0` when every check is `ok`; `1` when at least one is `failed`; `2` for an unreadable header or wrong usage |

A redacted event alone never makes a check fail.

The exit status is always `0`, `1` or `2`.
A verifier that cannot write or flush its report (a closed or missing standard output, a broken pipe, any write error) never exits `0`, because nobody saw the result: it exits `1` when a check failed and `2` otherwise, says so on standard error when standard error can be written, and does not end in an uncaught error.
A verifier states the result together with its limit: a file that passes is consistent with the keys named in it, and those keys are not verified by the file (section 7).

[`vectors/export/expected.json`](vectors/export/expected.json) gives, for each vector file, the exit status, the state of each check, `redacted` and `firstFailedSeq`.

## 7. What an export does not prove

- **Events after `toSeq`.**
  An export says nothing about events after its last one.
  Events removed from the end of a file, together with a lowered `toSeq`, cannot be seen.
  A verifier states the last sequence number so that a reader can compare it with what the service reports for the source.
- **Events before `fromSeq`.**
  An export says nothing about events before its first one.
  Events removed from the start of a file, together with a raised `fromSeq`, cannot be seen: such a file passes every check.
  When `fromSeq` is above 1, a verifier says plainly that the file starts at that number and not at 1.
- **That the keys are the registered keys.**
  The header names keys; whoever wrote the file chose them.
  That a key is the one a person registered for the hub must be checked against the registration record.
  A verifier prints each key's SHA-256 fingerprint for that comparison.
- **The clock.**
  `observedAt` is the hub's clock, signed.
  A signature proves that the hub said the time, not that the time was right.
- **The observation.**
  A signature proves that the hub with that key reported an event, not that what it reported was true of the network.
- **Key revocation.**
  Version 1 has no record of when a key stopped being valid.
  An event signed by a listed key is accepted whatever its time.
