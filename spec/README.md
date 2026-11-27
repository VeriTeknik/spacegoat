# Specification

The protocol a SpaceGoat hub speaks, and the vectors an implementation is checked against.
Licence: Apache-2.0 ([`LICENSE`](LICENSE)), so that anyone may build a compatible device or service.

| File | What it is |
|---|---|
| [`protocol.md`](protocol.md) | What a hub sends, how it signs it, what the service answers |
| [`vectors/signing.json`](vectors/signing.json) | Canonical JSON cases, signed events, a signed request and a personal-data commitment |
| [`export.md`](export.md) | The evidence export: a file an auditor can check without SpaceGoat's software, and the checks a verifier runs |
| [`vectors/export/`](vectors/export/) | Ten export files, one valid and the others each broken in one way, and the expected result for each in `expected.json` |

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

The export vectors in `vectors/export/` use the same key, listed in each header as `vector-key-1`.
`unknown-key.jsonl` has one event signed by a **second published test key**, named `vector-key-2`, whose 32 private bytes are 32, 33, 34, ... 63.
That key is deliberately absent from the header; never register it anywhere real either.
The files are built by `hub/tests/export_vectors.rs` from fixed values only (times, nonces, UUIDs), so the suite rebuilds every file and compares it byte for byte with the one here.

The addresses in the vectors are documentation ranges (`192.0.2.0/24`, and hardware addresses `00-00-5E-00-53-xx`, RFC 7042); the names are under `.example`.
