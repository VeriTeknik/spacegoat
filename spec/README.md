# Specification

The protocol a SpaceGoat hub speaks, and the vectors an implementation is checked against.
Licence: Apache-2.0 ([`LICENSE`](LICENSE)), so that anyone may build a compatible device or service.

| File | What it is |
|---|---|
| [`protocol.md`](protocol.md) | What a hub sends, how it signs it, what the service answers |
| [`vectors/signing.json`](vectors/signing.json) | Canonical JSON cases, signed events, a signed request and a personal-data commitment |

## The vectors

`signing.json` is produced with a **published test key** (private bytes `0x00` to `0x1f`).
Never register that key anywhere real.

- `canonical`: a value and the exact text it canonicalises to.
- `events`: the input of an event signature, the bytes that are signed (`messageHex`) and the signature.
- `request`: the parts of a request signature, the bytes that are signed and the signature.
- `pii`: a nonce, a personal-data object and its commitment.

The first four `events` entries are also pinned, with the same signatures, in the test suite of the hub service.
An implementation that reproduces every `messageHex` and every `signature` agrees with the service byte for byte.

The addresses in the vectors are documentation ranges (`192.0.2.0/24`) and a locally administered example address; the names are under `.example`.
