# Reference verifier

`spacegoat_verify.py` checks a SpaceGoat evidence export ([`../export.md`](../export.md)) without any SpaceGoat software.
It is one file of plain Python 3.9 or later, standard library only, so an auditor can read all of it before running it.
Licence: Apache-2.0, like the rest of `spec/`.

It is a second, independent implementation.
It was written from [`../protocol.md`](../protocol.md), [`../export.md`](../export.md), the vectors in [`../vectors/`](../vectors/) and RFC 8032 alone.
It shares no code with the hub agent in `hub/`, and its author did not read that code.
Ed25519 verification is implemented inside the file from RFC 8032 section 5.1; there is no signing code and no private key anywhere in this directory.

## Running it

```sh
python3 spacegoat_verify.py EXPORT.jsonl           # human-readable report
python3 spacegoat_verify.py EXPORT.jsonl --json    # one JSON object with the same facts
python3 spacegoat_verify.py --self-test ../vectors/export
python3 -m unittest spec/verify/test_verify.py     # from the repository root
```

The verifier only reads its input.
It writes no file, opens no network connection and never executes anything it reads.

## Exit status

| Status | Meaning |
|---|---|
| `0` | Every check passed (`form`, `key`, `signature`, `sequence`, `commitment`). |
| `1` | At least one check failed. |
| `2` | The header is unreadable (export.md section 2), the file cannot be read, or the command line is wrong. |

With `--self-test`, `0` means every file named in `expected.json` gave the expected exit status, check states, `redacted` count and `firstFailedSeq`; `1` means at least one disagreed; `2` means the directory or `expected.json` could not be read.

## What the report states

- the source id, the range `fromSeq..toSeq`, the number of event lines read and the number of redacted events;
- the state of each of the five checks and the first failed sequence number;
- the SHA-256 fingerprint of every public key in the header, with the reminder that it must be compared with the registration record;
- the last sequence number, with the reminder that events after it cannot be known from the file;
- each failure with its line, sequence number, check and reason.

Text taken from the file is never printed, except the source id and key ids, which the header rules restrict to a safe alphabet.

## What it proves

When every check passes:

- every line is well formed and keeps the value rules (no floating-point numbers, no duplicate keys, valid Unicode);
- every event is signed by one of the keys listed in the header, over exactly the fields in the file;
- the sequence numbers run from `fromSeq` to `toSeq` without a hole, except where the hub itself declared a gap or a reset in a signed event;
- every personal-data object still present matches the commitment the hub signed.

## What it does not prove

This list is export.md section 7.

- **Events after `toSeq`.**
  An export says nothing about events after its last one.
  Events removed from the end of a file, together with a lowered `toSeq`, cannot be seen.
  The verifier states the last sequence number so that a reader can compare it with what the service reports for the source.
- **That the keys are the registered keys.**
  The header names keys; whoever wrote the file chose them.
  That a key is the one a person registered for the hub must be checked against the registration record.
  The verifier prints each key's SHA-256 fingerprint for that comparison.
- **The clock.**
  `observedAt` is the hub's clock, signed.
  A signature proves that the hub said the time, not that the time was right.
- **The observation.**
  A signature proves that the hub with that key reported an event, not that what it reported was true of the network.
- **Key revocation.**
  Version 1 has no record of when a key stopped being valid.
  An event signed by a listed key is accepted whatever its time.

## Rules where two verifiers could easily differ

export.md states each of these; they are listed here because a verifier built in a hurry would get them wrong.

- The signature check is the cofactorless rule of export.md section 5: the encoding of R' = [S]B - [k]A must equal the R bytes, `S` must be below L, and a public key that does not decode is refused.
  A public key of small order is not refused, and anyone can make signatures that pass under it: compare the fingerprints.
- Base64url keys and signatures are accepted only in their canonical spelling (no padding, unused low bits zero).
- A line starts with `{` and ends with `}`: a CR before the LF, or any whitespace around the object, fails `form`.
- Nothing may be nested deeper than 64 levels; the verifier counts the depth itself before parsing, so the result does not depend on the Python version.
- A broken line takes the next expected number, passes `sequence` unless that number is above `toSeq`, and is evaluated by no other check; an empty line after the last LF is such a line.
- An attribute of a sequence kind that is missing or not an integer fails `sequence`, not `form`; a declared gap starts at 1 or later.
- An explicit `"piiCommitment": null` fails `form`: an event without personal data omits the field.
- Key ids are matched in full, and the year `0000` is accepted in `observedAt`: the form is checked, not the plausibility of the time.

## Speed

Measured on an Apple M4 Max with Python 3.15 and Python 3.9: about 2 ms per event, that is **about 20 seconds per 10 000 events**.
Almost all of it is the two scalar multiplications of each Ed25519 verification in plain Python.
The whole `valid.jsonl` vector (7 events) runs in about 0.05 seconds, interpreter start included.
