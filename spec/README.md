# Specification

The protocol a SpaceGoat hub speaks, and the vectors an implementation is checked against.
Licence: Apache-2.0 ([`LICENSE`](LICENSE)), so that anyone may build a compatible device or service.

| File | What it is |
|---|---|
| [`protocol.md`](protocol.md) | What a hub sends, how it signs it, what the service answers |
| [`vectors/signing.json`](vectors/signing.json) | Canonical JSON cases, signed events, a signed request and a personal-data commitment |

## The vectors

`signing.json` is produced with a **published test key**: its 32 private bytes are 0, 1, 2, ... 31.
Never register that key anywhere real.
The bytes are stated here rather than in the file so that secret scanners do not mistake them for a leaked key.

- `canonical`: a value and the exact text it canonicalises to.
- `events`: the input of an event signature, the bytes that are signed (`messageHex`) and the signature.
- `request`: the parts of a request signature, the bytes that are signed and the signature.
- `pii`: a nonce, a personal-data object and its commitment.

The first four `events` entries are also pinned, with the same signatures, in the test suite of the hub service.
An implementation that reproduces every `messageHex` and every `signature` agrees with the service byte for byte.

The addresses in the vectors are documentation ranges (`192.0.2.0/24`, and hardware addresses `00-00-5E-00-53-xx`, RFC 7042); the names are under `.example`.
