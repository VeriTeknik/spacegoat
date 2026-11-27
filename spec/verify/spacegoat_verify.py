#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reference verifier for a SpaceGoat evidence export (spec/export.md, version 1).

Built from spec/protocol.md, spec/export.md and RFC 8032 alone; it shares no code with the hub agent.
Python 3.9 or later, standard library only.

    python3 spacegoat_verify.py EXPORT.jsonl [--json]
    python3 spacegoat_verify.py --self-test VECTORS_DIR

Exit status (export.md section 6): 0 every check passed, 1 at least one check failed, 2 unreadable header or wrong
usage. With --self-test: 0 every vector agrees with expected.json, 1 at least one disagrees, 2 the directory or
expected.json cannot be read.

The verifier only reads. It writes no file, opens no network connection and never executes anything from its input.
There is no signing code and no private key handling here: Ed25519 below is verification only.

Section references: "P" is spec/protocol.md, "E" is spec/export.md, "RFC" is RFC 8032.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys

MAX_INT = 2**53 - 1  # P2, E4: integers stay within +-(2^53 - 1)
CHECKS = ("form", "key", "signature", "sequence", "commitment")  # E5
EXPORT_FORMAT = "spacegoat-export/v1"  # E2
EVENT_DOMAIN = b"vt-evidence-event/v1\n"  # P4
BOM = b"\xef\xbb\xbf"

# =====================================================================================================================
# Ed25519 verification, RFC 8032 section 5.1 (verification only)
# =====================================================================================================================

_P = 2**255 - 19  # RFC 5.1: the field prime
_L = 2**252 + 27742317777372353535851937790883648493  # RFC 5.1: the group order
_D = (-121665 * pow(121666, _P - 2, _P)) % _P  # RFC 5.1: the curve constant d
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)  # RFC 5.1.3: a square root of -1
_IDENTITY = (0, 1, 1, 0)  # extended coordinates (X, Y, Z, T), RFC 5.1.4


def _point_add(a, b):
    """Point addition in extended coordinates, RFC 5.1.4. The formula also doubles (a == b)."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    p_a = (y1 - x1) * (y2 - x2) % _P
    p_b = (y1 + x1) * (y2 + x2) % _P
    p_c = 2 * t1 * t2 * _D % _P
    p_d = 2 * z1 * z2 % _P
    e, f, g, h = p_b - p_a, p_d - p_c, p_d + p_c, p_b + p_a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(k, point):
    """[k]point by double and add."""
    result = _IDENTITY
    while k:
        if k & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        k >>= 1
    return result


def _recover_x(y, sign):
    """RFC 5.1.3 steps 2 to 4: the x for y with the given low bit, or None when there is none."""
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    vx2 = v * x * x % _P
    if vx2 == u:
        pass
    elif vx2 == (-u) % _P:
        x = x * _SQRT_M1 % _P
    else:
        return None  # x^2 has no square root: not a point
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


def _decode_point(encoded):
    """RFC 5.1.3: 32 bytes to a point, or None when the bytes are not a valid encoding."""
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None  # RFC 5.1.3 step 1: a non-canonical y is refused
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _base_point():
    y = 4 * pow(5, _P - 2, _P) % _P  # RFC 5.1: B has y = 4/5 and a positive (even) x
    x = _recover_x(y, 0)
    return (x, y, 1, x * y % _P)


_BASE_DOUBLINGS = []  # [2^i]B for i = 0..252, filled on first use


def _base_mult(k):
    """[k]B for 0 <= k < 2^253, from a table of doublings of B."""
    if not _BASE_DOUBLINGS:
        point = _base_point()
        for _ in range(253):
            _BASE_DOUBLINGS.append(point)
            point = _point_add(point, point)
    result = _IDENTITY
    i = 0
    while k:
        if k & 1:
            result = _point_add(result, _BASE_DOUBLINGS[i])
        k >>= 1
        i += 1
    return result


def _encode_point(point):
    """RFC 5.1.2: y in little-endian with the low bit of x in the top bit. Always the canonical encoding."""
    x, y, z, _ = point
    z_inv = pow(z, _P - 2, _P)
    x, y = x * z_inv % _P, y * z_inv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_verify(public, message, signature):
    """Ed25519 verification by the rule of E5 `signature`. Returns True or False; never raises on malformed input.

    E5 picks the cofactorless rule: decode A (a y not below p or a y with no point is refused), refuse S not below L,
    k = SHA-512(R || A || M) mod L, R' = [S]B - [k]A, and accept only when the encoding of R' equals the R bytes.
    R is never decoded: the encoding of R' is canonical, so a non-canonical or non-decodable R cannot match.
    Small-order public keys are not refused.
    """
    if not all(isinstance(v, (bytes, bytearray)) for v in (public, message, signature)):
        return False
    public, message, signature = bytes(public), bytes(message), bytes(signature)
    if len(public) != 32 or len(signature) != 64:
        return False
    point_a = _decode_point(public)
    if point_a is None:
        return False
    r_bytes = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public + message).digest(), "little") % _L
    x, y, z, t = point_a
    minus_a = ((-x) % _P, y, z, (-t) % _P)  # -A: negate x (RFC 5.1.4 extended coordinates)
    r_prime = _point_add(_base_mult(s), _scalar_mult(k, minus_a))
    return _encode_point(r_prime) == r_bytes


# =====================================================================================================================
# Values and canonical JSON, protocol.md section 2 and export.md section 4
# =====================================================================================================================


def _key_ok(key):
    """P2, E4: object keys are non-empty printable ASCII, 0x20 to 0x7E."""
    return isinstance(key, str) and key != "" and all(0x20 <= ord(c) <= 0x7E for c in key)


def _text_ok(text):
    """P2, E4: text is valid Unicode; a lone surrogate has no UTF-8 form."""
    try:
        text.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def is_integer(value):
    """P2, E4: an integer within +-(2^53 - 1). A boolean is not an integer."""
    return type(value) is int and -MAX_INT <= value <= MAX_INT


def check_value(value):
    """Raise ValueError unless every value, at every depth, keeps the value rules of P2 and E4.

    Iterative, so a deeply nested value is judged instead of exhausting the stack.
    """
    stack = [value]
    while stack:
        item = stack.pop()
        if item is None or isinstance(item, bool):
            continue
        if type(item) is int:
            if not is_integer(item):
                raise ValueError("integer outside +-(2^53 - 1)")
        elif isinstance(item, str):
            if not _text_ok(item):
                raise ValueError("text that is not valid Unicode")
        elif isinstance(item, dict):
            for key, child in item.items():
                if not _key_ok(key):
                    raise ValueError("object key that is not non-empty printable ASCII")
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, float):
            raise ValueError("floating-point number")
        else:
            raise ValueError("value of a type JSON does not have")


def canonical_json(value):
    """P2: keys sorted by code point, no whitespace, UTF-8 text not escaped to ASCII; raises ValueError otherwise."""
    check_value(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except RecursionError:
        raise ValueError("value nested too deeply to write") from None


def event_message(source_id, event):
    """P4: the bytes an event signature covers. `piiCommitment` is null when the event has none (E5)."""
    signed = {
        "sourceId": source_id,
        "sourceSeq": event["sourceSeq"],
        "kind": event["kind"],
        "observedAt": event["observedAt"],
        "attributes": event["attributes"],
        "piiCommitment": event.get("piiCommitment"),
    }
    return EVENT_DOMAIN + canonical_json(signed).encode("utf-8")


def pii_commitment(nonce_hex, pii):
    """P6: sha256hex(piiNonce + "|" + canonicalJson(pii)); the nonce is used as its hex text."""
    return hashlib.sha256((nonce_hex + "|" + canonical_json(pii)).encode("utf-8")).hexdigest()


# =====================================================================================================================
# Strict reading of one line, export.md sections 1 and 4
# =====================================================================================================================

_INT_TEXT = re.compile(r"-?(?:0|[1-9][0-9]*)")


def _no_duplicate_keys(pairs):
    """E4: no object has the same key twice."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("an object has the same key twice")
        result[key] = value
    return result


def _refuse_float(_text):
    raise ValueError("floating-point number")  # E4: 1.5, 1.0 and 1e3 are refused, not rounded


def _refuse_constant(_text):
    raise ValueError("NaN or Infinity is not JSON")


def _parse_int(text):
    """E4: an optional '-' and digits, within +-(2^53 - 1). Judged on the text before any conversion."""
    if not _INT_TEXT.fullmatch(text) or len(text.lstrip("-")) > 16:
        raise ValueError("integer outside +-(2^53 - 1)")
    value = int(text)
    if not is_integer(value):
        raise ValueError("integer outside +-(2^53 - 1)")
    return value


MAX_DEPTH = 64  # E4: the line's object is level 1; each object or array inside it adds one


def _check_depth(text):
    """E4: refuse nesting deeper than MAX_DEPTH, counted on the text before parsing.

    Brackets inside strings do not count. Counting first means the result never depends on how deep the
    interpreter's own parser can go; text that is not JSON is refused by the parser afterwards.
    """
    depth, in_string, escaped = 0, False, False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("nested deeper than %d levels" % MAX_DEPTH)
        elif char in "]}":
            depth -= 1


def read_json_object(raw):
    """One line (bytes, without its LF) to a dict, or ValueError with the reason (E1, E4)."""
    if b"\n" in raw:
        raise ValueError("a line contains a line feed")
    try:
        text = raw.decode("utf-8")  # strict: invalid UTF-8 and encoded surrogates are refused
    except UnicodeDecodeError:
        raise ValueError("not valid UTF-8") from None
    if not (text.startswith("{") and text.endswith("}")):
        # E1: the line is the object, from its '{' to its '}': a CR or any whitespace around it breaks the line.
        raise ValueError("not a JSON object from the first to the last character of the line")
    _check_depth(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_float=_refuse_float,
            parse_int=_parse_int,
            parse_constant=_refuse_constant,
        )
    except RecursionError:
        # Not reachable after _check_depth; if it were, a line too deep for the parser is the same E4 failure.
        raise ValueError("nested deeper than %d levels" % MAX_DEPTH) from None
    except ValueError as error:
        reason = str(error)
        if not reason.startswith(("floating", "integer", "an object", "NaN")):
            reason = "not JSON"
        raise ValueError(reason) from None
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    check_value(value)
    return value


# =====================================================================================================================
# Field forms, protocol.md sections 3 and 4, export.md sections 2 and 3
# =====================================================================================================================

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")  # E2 sourceId
_KEY_ID = r"[a-z0-9][a-z0-9-]{2,62}"  # P3
_KEY_ID_RE = re.compile(_KEY_ID)
_PUBLIC_KEY = re.compile(r"ed25519:([A-Za-z0-9_-]{43})")  # P3, E2
_SIGNATURE = re.compile(r"ed25519:(" + _KEY_ID + r"):([A-Za-z0-9_-]{86})")  # P3, E3
_HEX64 = re.compile(r"[0-9a-f]{64}")  # E3 piiNonce, piiCommitment
_OBSERVED_AT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}Z")  # P4, E3


def _decode_base64url(text, length):
    """P3: base64url without padding, decoding to exactly `length` bytes, in its one canonical spelling.

    E2, E3: only the canonical spelling is accepted. A spelling whose unused low bits are not zero decodes to the
    same bytes as the canonical one; it is refused so that a signature or key text has a single spelling.
    """
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if len(raw) != length or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != text:
        return None
    return raw


def _is_leap(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)  # proleptic Gregorian


def observed_at_ok(text):
    """E3: YYYY-MM-DDTHH:MM:SS.mmmZ, a day that exists in the proleptic Gregorian calendar, 00-23, 00-59, 00-59."""
    match = _OBSERVED_AT.fullmatch(text) if isinstance(text, str) else None
    if not match:
        return False
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    days = [31, 29 if _is_leap(year) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return 1 <= month <= 12 and 1 <= day <= days[month - 1] and hour <= 23 and minute <= 59 and second <= 59


def _seq_ok(value):
    """E2, E3: an integer from 1 to 2^53 - 1."""
    return is_integer(value) and value >= 1


class Unreadable(Exception):
    """E2: an unreadable header; nothing else is checked and the exit status is 2."""


def read_header(raw):
    """E2: the header line to (sourceId, fromSeq, toSeq, [(keyId, public key bytes)]), or Unreadable."""
    if raw.startswith(BOM):
        raise Unreadable("the file starts with a byte order mark")
    try:
        header = read_json_object(raw)
    except ValueError as error:
        raise Unreadable("the header line: " + str(error)) from None
    fields = ("format", "sourceId", "fromSeq", "toSeq", "keys")
    if set(header) != set(fields):
        raise Unreadable("the header must have exactly the fields " + ", ".join(fields))
    if header["format"] != EXPORT_FORMAT:
        raise Unreadable("format is not " + EXPORT_FORMAT)
    if not isinstance(header["sourceId"], str) or not _UUID.fullmatch(header["sourceId"]):
        raise Unreadable("sourceId is not a lowercase 8-4-4-4-12 UUID")
    from_seq, to_seq = header["fromSeq"], header["toSeq"]
    if not _seq_ok(from_seq):
        raise Unreadable("fromSeq is not an integer from 1 to 2^53 - 1")
    if not _seq_ok(to_seq) or to_seq < from_seq:
        raise Unreadable("toSeq is not an integer from fromSeq to 2^53 - 1")
    keys = header["keys"]
    if not isinstance(keys, list) or not keys:
        raise Unreadable("keys is not a non-empty array")
    result = []
    for entry in keys:
        if not isinstance(entry, dict) or set(entry) != {"keyId", "publicKey"}:
            raise Unreadable("a key object must have exactly keyId and publicKey")
        key_id, text = entry["keyId"], entry["publicKey"]
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            raise Unreadable("a keyId does not have the form of protocol section 3")
        if any(key_id == known for known, _ in result):
            raise Unreadable("two key objects share a keyId")
        match = _PUBLIC_KEY.fullmatch(text) if isinstance(text, str) else None
        public = _decode_base64url(match.group(1), 32) if match else None
        if public is None:
            raise Unreadable("a publicKey is not ed25519: and 43 base64url characters for 32 bytes")
        result.append((key_id, public))
    return header["sourceId"], from_seq, to_seq, result


_REQUIRED = ("sourceSeq", "kind", "observedAt", "attributes", "signature")  # E3
_PII_FIELDS = ("pii", "piiNonce", "piiCommitment")  # E3
_SHAPES = {(True, True, True): "full", (False, False, True): "redacted", (False, False, False): "none"}  # E3


class Event:
    """An event line that passed `form`."""

    def __init__(self, fields, shape, key_id, signature):
        self.fields = fields
        self.shape = shape
        self.key_id = key_id
        self.signature = signature
        self.seq = fields["sourceSeq"]
        self.kind = fields["kind"]


def read_event(raw):
    """E3, E4: an event line to an Event, or ValueError with the reason (the line fails `form`)."""
    event = read_json_object(raw)
    unknown = set(event) - set(_REQUIRED) - set(_PII_FIELDS)
    if unknown:
        raise ValueError("a field export.md section 3 does not list")
    if any(name not in event for name in _REQUIRED):
        raise ValueError("a required field is missing")
    if not _seq_ok(event["sourceSeq"]):
        raise ValueError("sourceSeq is not an integer from 1 to 2^53 - 1")
    if not isinstance(event["kind"], str) or event["kind"] == "":
        raise ValueError("kind is not a non-empty string")
    if not observed_at_ok(event["observedAt"]):
        raise ValueError("observedAt is not YYYY-MM-DDTHH:MM:SS.mmmZ at a moment that exists")
    if not isinstance(event["attributes"], dict):
        raise ValueError("attributes is not an object")
    match = _SIGNATURE.fullmatch(event["signature"]) if isinstance(event["signature"], str) else None
    signature = _decode_base64url(match.group(2), 64) if match else None
    if signature is None:
        raise ValueError("signature is not ed25519:<keyId>:<86 base64url characters for 64 bytes>")
    shape = _SHAPES.get(tuple(name in event for name in _PII_FIELDS))
    if shape is None:
        raise ValueError("the personal-data fields are not one of the shapes full, redacted or none")
    if shape == "full":
        if not isinstance(event["pii"], dict):
            raise ValueError("pii is not an object")
        if not isinstance(event["piiNonce"], str) or not _HEX64.fullmatch(event["piiNonce"]):
            raise ValueError("piiNonce is not 64 lowercase hex characters")
    if shape != "none":
        if not isinstance(event["piiCommitment"], str) or not _HEX64.fullmatch(event["piiCommitment"]):
            raise ValueError("piiCommitment is not 64 lowercase hex characters")
    return Event(event, shape, match.group(1), signature)


# =====================================================================================================================
# The sequence rules, export.md section 5 `sequence`
# =====================================================================================================================

GAP_DECLARED = "site_source.gap_declared"
RESET = "site_source.reset"


def _own_rule_holds(event, previous, first):
    """E5: the rule of a sequence kind (P8). True for any other kind.

    A missing or non-integer attribute makes the rule fail, so the event fails `sequence`, not `form` (E5).
    """
    attributes, s = event.fields["attributes"], event.seq
    if event.kind == GAP_DECLARED:
        start, end = attributes.get("fromSeq"), attributes.get("toSeq")
        if not (is_integer(start) and is_integer(end)):
            return False
        if end != s - 1 or start < 1 or start > end:
            return False
        return first or start == previous + 1
    if event.kind == RESET:
        last = attributes.get("lastAckedSeq")
        return is_integer(last) and last == s - 1
    return True


def sequence_passes(event, previous, first, from_seq, to_seq):
    """E5: whether an event that passed `form` passes `sequence`."""
    s = event.seq
    if s > to_seq:
        return False  # E5: an event whose number is greater than toSeq fails
    own = _own_rule_holds(event, previous, first)
    if first:
        return s == from_seq and own
    if s == previous + 1:
        return own
    return event.kind == GAP_DECLARED and s > previous + 1 and own


# =====================================================================================================================
# The export, export.md sections 5 and 6
# =====================================================================================================================


class Report:
    """The result of export.md section 6, and the facts the report states."""

    def __init__(self):
        self.unreadable = None  # the reason, when the header is unreadable (exit 2)
        self.checks = {name: "ok" for name in CHECKS}
        self.redacted = 0
        self.first_failed_seq = None
        self.source_id = None
        self.from_seq = None
        self.to_seq = None
        self.events_read = 0
        self.keys = []  # [(keyId, SHA-256 fingerprint hex)]
        self.failures = []  # [(file line number or None, sequence number, check, reason)]

    @property
    def exit_status(self):
        if self.unreadable is not None:
            return 2
        return 1 if any(state == "failed" for state in self.checks.values()) else 0

    def fail(self, line_number, seq, check, reason):
        self.checks[check] = "failed"
        self.failures.append((line_number, seq, check, reason))
        if self.first_failed_seq is None:
            self.first_failed_seq = seq  # E6: the first event line, in file order, on which any check failed


def split_lines(data):
    """E1: lines ended by one LF; a missing LF after the last line is accepted."""
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()  # the LF that ends the last line, not an empty line
    return lines


def _as_lines(lines):
    if isinstance(lines, (bytes, bytearray)):
        return split_lines(bytes(lines))
    # A list such as file.readlines() gives: each element ends with the LF that ended it, except perhaps the last.
    return [bytes(line[:-1]) if line.endswith(b"\n") else bytes(line) for line in lines]


def verify_export(lines):
    """Verify an export, given as the file's bytes or as a list of its lines (bytes). Returns a Report."""
    report = Report()
    lines = _as_lines(lines)
    if not lines:
        report.unreadable = "the file is empty"
        report.checks = {name: None for name in CHECKS}
        return report
    try:
        source_id, from_seq, to_seq, keys = read_header(lines[0])
    except Unreadable as error:
        report.unreadable = str(error)
        report.checks = {name: None for name in CHECKS}
        return report
    report.source_id, report.from_seq, report.to_seq = source_id, from_seq, to_seq
    report.keys = [(key_id, hashlib.sha256(public).hexdigest()) for key_id, public in keys]  # E6
    public_keys = dict(keys)

    previous = from_seq - 1  # E5 `sequence`
    for index, raw in enumerate(lines[1:]):
        line_number = index + 2
        first = index == 0
        report.events_read += 1
        try:
            event = read_event(raw)
        except ValueError as error:
            # E5 `form`: not evaluated by key, signature or commitment; for sequence it occupies previous + 1.
            seq = previous + 1
            report.fail(line_number, seq, "form", str(error))
            if seq > to_seq:
                report.fail(line_number, seq, "sequence", "number greater than toSeq")
            previous = seq
            continue

        seq = event.seq
        if event.shape == "redacted":
            report.redacted += 1  # E6

        if event.key_id not in public_keys:
            report.fail(line_number, seq, "key", "the key id is not in the header")  # E5 `key`
        else:
            message = event_message(source_id, event.fields)
            if not ed25519_verify(public_keys[event.key_id], message, event.signature):
                report.fail(line_number, seq, "signature", "the signature does not verify")  # E5 `signature`

        if not sequence_passes(event, previous, first, from_seq, to_seq):
            report.fail(line_number, seq, "sequence", "expected %d after %d" % (previous + 1, previous))
        previous = seq

        if event.shape == "full":  # E5 `commitment`
            if pii_commitment(event.fields["piiNonce"], event.fields["pii"]) != event.fields["piiCommitment"]:
                report.fail(line_number, seq, "commitment", "the personal data does not match its commitment")

    if previous != to_seq:  # E5: after the last line, previous must equal toSeq
        report.fail(None, previous + 1, "sequence", "the file ends before toSeq %d" % to_seq)
    return report


# =====================================================================================================================
# Output
# =====================================================================================================================

KEYS_SENTENCE = (
    "Each fingerprint must be compared with the registration record of the hub: "
    "whoever wrote this file chose the keys in its header."
)
END_SENTENCE = "Events after the last sequence number cannot be known from this file."
NOT_PROVEN = (
    "A signature proves that the holder of the key reported the event; "
    "it does not prove that the stated time was right, that the observation was true, or that the key was "
    "still valid then (version 1 has no key revocation)."
)
MAX_LISTED = 50


def report_to_json(report):
    if report.unreadable is not None:
        return {"exit": 2, "unreadable": report.unreadable}
    return {
        "exit": report.exit_status,
        "checks": dict(report.checks),
        "redacted": report.redacted,
        "firstFailedSeq": report.first_failed_seq,
        "sourceId": report.source_id,
        "fromSeq": report.from_seq,
        "toSeq": report.to_seq,
        "lastSequenceNumber": report.to_seq,
        "eventsRead": report.events_read,
        "keys": [{"keyId": key_id, "fingerprint": fp} for key_id, fp in report.keys],
        "failures": [
            {"line": line, "sourceSeq": seq, "check": check, "reason": reason}
            for line, seq, check, reason in report.failures
        ],
        "notes": [KEYS_SENTENCE, END_SENTENCE, NOT_PROVEN],
    }


def report_to_text(report, path):
    """The human-readable report. Only validated values from the file are printed (no free text from the input)."""
    out = ["SpaceGoat evidence export verifier (export.md version 1)", "File:            %s" % path]
    if report.unreadable is not None:
        out += ["Unreadable header: %s." % report.unreadable, "Nothing else was checked.", "Exit status: 2"]
        return "\n".join(out) + "\n"
    out += [
        "Source:          %s" % report.source_id,
        "Range:           %d..%d" % (report.from_seq, report.to_seq),
        "Events read:     %d" % report.events_read,
        "Redacted events: %d" % report.redacted,
        "",
        "Checks:",
    ]
    out += ["  %-11s %s" % (name, report.checks[name]) for name in CHECKS]
    first = "none" if report.first_failed_seq is None else str(report.first_failed_seq)
    out += ["First failed sequence number: %s" % first, ""]
    out.append("Keys in the header (SHA-256 fingerprint of the 32 raw public key bytes):")
    out += ["  %s  %s" % (key_id, fp) for key_id, fp in report.keys]
    out += [KEYS_SENTENCE, ""]
    out.append("Last sequence number: %d." % report.to_seq)
    out.append("%s Compare %d with what the service reports for this source." % (END_SENTENCE, report.to_seq))
    out += ["", NOT_PROVEN]
    if report.failures:
        listed = min(len(report.failures), MAX_LISTED)
        out += ["", "Failures: %d (%d listed):" % (len(report.failures), listed)]
        for line, seq, check, reason in report.failures[:MAX_LISTED]:
            where = "after the last line" if line is None else "line %d" % line
            out.append("  %s, sequence number %d: %s: %s" % (where, seq, check, reason))
    out += ["", "Result: %s (exit status %d)" % ("PASSED" if report.exit_status == 0 else "FAILED", report.exit_status)]
    return "\n".join(out) + "\n"


# =====================================================================================================================
# Self-test against vectors/export/expected.json (export.md section 6)
# =====================================================================================================================


def self_test(directory):
    try:
        with open(os.path.join(directory, "expected.json"), "rb") as f:
            expected = read_json_object(f.read().replace(b"\n", b" ").rstrip())
    except (OSError, ValueError) as error:
        print("cannot read expected.json in %s: %s" % (directory, error), file=sys.stderr)
        return 2
    disagreements = 0
    for name in sorted(expected):
        want = expected[name]
        try:
            with open(os.path.join(directory, name + ".jsonl"), "rb") as f:
                report = verify_export(f.read())
        except OSError as error:
            print("DIFFERS %s: cannot read the file (%s)" % (name, error))
            disagreements += 1
            continue
        got = {
            "exit": report.exit_status,
            "checks": report.checks,
            "redacted": report.redacted,
            "firstFailedSeq": report.first_failed_seq,
        }
        wrong = [field for field in got if not isinstance(want, dict) or want.get(field) != got[field]]
        if wrong:
            disagreements += 1
            for field in wrong:
                want_value = want.get(field) if isinstance(want, dict) else None
                print("DIFFERS %s: %s expected %s, got %s" % (name, field, json.dumps(want_value), json.dumps(got[field])))
        else:
            print("ok      %s" % name)
    print("%d vectors, %d disagree" % (len(expected), disagreements))
    return 1 if disagreements else 0


# =====================================================================================================================
# Command line
# =====================================================================================================================


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="spacegoat_verify.py",
        description="Verify a SpaceGoat evidence export (spec/export.md, version 1).",
    )
    parser.add_argument("export", nargs="?", help="the export file (.jsonl)")
    parser.add_argument("--json", action="store_true", help="print one JSON object instead of the text report")
    parser.add_argument("--self-test", metavar="VECTORS_DIR", help="check every file named in VECTORS_DIR/expected.json")
    args = parser.parse_args(argv)  # wrong usage: argparse exits with status 2
    if (args.self_test is None) == (args.export is None):
        parser.error("give either an export file or --self-test VECTORS_DIR")
    if args.self_test is not None:
        return self_test(args.self_test)
    try:
        with open(args.export, "rb") as f:
            data = f.read()
    except OSError as error:
        print("cannot read %s: %s" % (args.export, error.strerror or error), file=sys.stderr)
        return 2
    report = verify_export(data)
    if args.json:
        print(json.dumps(report_to_json(report), sort_keys=True))
    else:
        sys.stdout.write(report_to_text(report, args.export))
    return report.exit_status


if __name__ == "__main__":
    sys.exit(main())
