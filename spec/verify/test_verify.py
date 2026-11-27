# SPDX-License-Identifier: Apache-2.0
"""Tests for spacegoat_verify.py.

Run from the repository root:  python3 -m unittest spec/verify/test_verify.py

Every expectation here comes from spec/protocol.md, spec/export.md, the published vectors in spec/vectors/
or RFC 8032. Nothing here signs anything: there is no private key in this file.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import spacegoat_verify as sv  # noqa: E402

VECTORS = os.path.join(HERE, "..", "vectors")
EXPORT_DIR = os.path.join(VECTORS, "export")
SCRIPT = os.path.join(HERE, "spacegoat_verify.py")

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def load_signing():
    with open(os.path.join(VECTORS, "signing.json"), encoding="utf-8") as f:
        return json.load(f)


def read_vector(name):
    with open(os.path.join(EXPORT_DIR, name + ".jsonl"), "rb") as f:
        return f.read()


def b64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def flip(data, bit):
    out = bytearray(data)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


def replace_line(data, index, new_line):
    lines = data.split(b"\n")
    lines[index] = new_line
    return b"\n".join(lines)


def edit_event(data, index, edit):
    """Parse event line `index`, apply `edit` to the dict, write it back compactly."""
    lines = data.split(b"\n")
    obj = json.loads(lines[index].decode("utf-8"))
    edit(obj)
    lines[index] = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b"\n".join(lines)


def states(report):
    return {name: report.checks[name] for name in ("form", "key", "signature", "sequence", "commitment")}


def all_ok_but(**failed):
    result = {name: "ok" for name in ("form", "key", "signature", "sequence", "commitment")}
    for name, value in failed.items():
        result[name] = value
    return result


# ---------------------------------------------------------------------------------------------------------------------
# protocol.md section 2: canonical JSON


class CanonicalJson(unittest.TestCase):
    def test_every_canonical_vector(self):
        for case in load_signing()["canonical"]:
            with self.subTest(case["name"]):
                self.assertEqual(sv.canonical_json(case["value"]), case["text"])

    def test_forbidden_values_raise_value_error(self):
        forbidden = [
            1.5,
            1.0,
            {"a": 1.0},
            [float("nan")],
            float("inf"),
            2**53,
            -(2**53),
            {"a": [2**60]},
            "\ud800",
            {"k": "a\udc00b"},
            {"": 1},
            {"é": 1},
            {"a\x7f": 1},
            {"a\x1f": 1},
            {1: 2},
            b"bytes",
            (1, 2),
            {1, 2},
            object(),
        ]
        for value in forbidden:
            with self.subTest(repr(value)):
                with self.assertRaises(ValueError):
                    sv.canonical_json(value)

    def test_limits_and_booleans(self):
        self.assertEqual(sv.canonical_json(2**53 - 1), "9007199254740991")
        self.assertEqual(sv.canonical_json(-(2**53 - 1)), "-9007199254740991")
        self.assertEqual(sv.canonical_json([True, False, None]), "[true,false,null]")
        self.assertEqual(sv.canonical_json({" ~": 1}), '{" ~":1}')

    def test_control_characters_are_escaped(self):
        # protocol.md section 2: U+0000..U+001F escaped, the short way where JSON has one, else \u00xx lowercase.
        self.assertEqual(sv.canonical_json("\b\t\n\f\r"), '"\\b\\t\\n\\f\\r"')
        self.assertEqual(sv.canonical_json("\x00\x1f\x0b"), '"\\u0000\\u001f\\u000b"')
        # Nothing else is escaped: DEL, U+2028, U+2029, '/', non-ASCII.
        self.assertEqual(sv.canonical_json("\x7f  /ç"), '"\x7f  /ç"')

    @staticmethod
    def nested_lists(levels):
        value = []
        for _ in range(levels - 1):
            value = [value]
        return value

    def test_deep_nesting_exact_outcome(self):
        # The verifier only canonicalises values that passed export.md section 4, so canonical_json applies the same
        # 64-level limit, counted without recursion: the outcome never depends on the interpreter.
        self.assertEqual(sv.canonical_json(self.nested_lists(64)), "[" * 64 + "]" * 64)
        with self.assertRaises(ValueError):
            sv.canonical_json(self.nested_lists(65))
        with self.assertRaises(ValueError):
            sv.canonical_json(self.nested_lists(100001))
        with self.assertRaises(ValueError):
            sv.canonical_json({"a": self.nested_lists(64)})


# ---------------------------------------------------------------------------------------------------------------------
# protocol.md sections 3, 4, 5 and 6 with the signing vectors


class SigningVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vec = load_signing()
        assert cls.vec["publicKey"].startswith("ed25519:")
        cls.public = b64url(cls.vec["publicKey"][len("ed25519:"):])

    def test_event_messages_and_signatures(self):
        for case in self.vec["events"]:
            with self.subTest(case["name"]):
                inp = case["input"]
                message = sv.event_message(inp["sourceId"], inp)
                self.assertEqual(message.hex(), case["messageHex"])
                signature = b64url(case["signature"])
                self.assertEqual(len(signature), 64)
                self.assertTrue(sv.ed25519_verify(self.public, message, signature))
                for bit in (0, 255, 256, 511):
                    self.assertFalse(sv.ed25519_verify(self.public, message, flip(signature, bit)), "sig bit %d" % bit)
                for bit in (0, len(message) * 8 - 1):
                    self.assertFalse(sv.ed25519_verify(self.public, flip(message, bit), signature), "msg bit %d" % bit)
                for bit in (0, 254):
                    self.assertFalse(sv.ed25519_verify(flip(self.public, bit), message, signature), "key bit %d" % bit)

    def test_event_message_without_commitment_field_is_null(self):
        inp = dict(self.vec["events"][2]["input"])
        del inp["piiCommitment"]
        self.assertEqual(sv.event_message(inp["sourceId"], inp).hex(), self.vec["events"][2]["messageHex"])

    def test_pii_commitment(self):
        case = self.vec["pii"]
        self.assertEqual(sv.pii_commitment(case["nonceHex"], case["payload"]), case["commitment"])

    def test_request_signature(self):
        # protocol.md section 5. Not used by the export verifier; checked here because it is trivial.
        req = self.vec["request"]
        body = bytes.fromhex(req["bodyHex"])
        message = (
            "vt-machine/v1\n" + req["principal"] + "\n" + req["method"] + " " + req["path"] + "\n"
            + req["timestamp"] + "\n" + hashlib.sha256(body).hexdigest()
        ).encode("utf-8")
        self.assertEqual(message.hex(), req["messageHex"])
        self.assertTrue(sv.ed25519_verify(self.public, message, b64url(req["signature"])))


# ---------------------------------------------------------------------------------------------------------------------
# RFC 8032 section 7.1, tests 1 to 3. The bytes are written from memory of the RFC; a single wrong byte in a public
# key, message or signature would make verification fail, so a pass is itself evidence that they were remembered right.

RFC8032 = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


def legendre_is_square(a):
    a %= P
    return a == 0 or pow(a, (P - 1) // 2, P) == 1


class Ed25519(unittest.TestCase):
    def test_rfc8032_vectors_1_to_3(self):
        for i, (pk, msg, sig) in enumerate(RFC8032, start=1):
            with self.subTest(test=i):
                public, message, signature = bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)
                self.assertTrue(sv.ed25519_verify(public, message, signature))
                self.assertFalse(sv.ed25519_verify(public, message + b"x", signature))
                self.assertFalse(sv.ed25519_verify(public, message, flip(signature, 300)))

    def test_wrong_lengths_return_false(self):
        pk, msg, sig = (bytes.fromhex(x) for x in RFC8032[0])
        for public, signature in ((pk[:31], sig), (pk + b"\0", sig), (pk, sig[:63]), (pk, sig + b"\0"), (b"", b"")):
            self.assertFalse(sv.ed25519_verify(public, msg, signature))

    def test_wrong_types_return_false(self):
        pk, msg, sig = (bytes.fromhex(x) for x in RFC8032[0])
        for args in ((None, msg, sig), (pk, None, sig), (pk, msg, None), (pk.hex(), msg, sig), (pk, "text", sig), (1, 2, 3)):
            self.assertFalse(sv.ed25519_verify(*args))

    def test_non_canonical_s_is_refused(self):
        # S + L is the same scalar modulo L, so the group equation still holds: only the S < L rule refuses it.
        pk, msg, sig = (bytes.fromhex(x) for x in RFC8032[0])
        s = int.from_bytes(sig[32:], "little")
        self.assertLess(s + L, 2**256)
        bad = sig[:32] + (s + L).to_bytes(32, "little")
        self.assertFalse(sv.ed25519_verify(pk, msg, bad))
        self.assertFalse(sv.ed25519_verify(pk, msg, sig[:32] + L.to_bytes(32, "little")))
        self.assertFalse(sv.ed25519_verify(pk, msg, sig[:32] + b"\xff" * 32))

    def test_public_key_that_is_not_a_point(self):
        # Find y < p for which (y^2 - 1) / (d y^2 + 1) is not a square: no x exists (RFC 8032 section 5.1.3).
        d = (-121665 * pow(121666, P - 2, P)) % P
        y = 2
        while legendre_is_square((y * y - 1) * pow(d * y * y + 1, P - 2, P)):
            y += 1
        not_a_point = y.to_bytes(32, "little")
        _, msg, sig = (bytes.fromhex(x) for x in RFC8032[0])
        self.assertFalse(sv.ed25519_verify(not_a_point, msg, sig))
        # The same encoding as R is refused too.
        pk = bytes.fromhex(RFC8032[0][0])
        self.assertFalse(sv.ed25519_verify(pk, msg, not_a_point + sig[32:]))

    def test_non_canonical_y_is_refused(self):
        # y >= p has no valid encoding (RFC 8032 section 5.1.3, step 1).
        _, msg, sig = (bytes.fromhex(x) for x in RFC8032[0])
        for y in (P, P + 1, 2**255 - 1):
            self.assertFalse(sv.ed25519_verify(y.to_bytes(32, "little"), msg, sig))

    def test_r_bytes_altered(self):
        # export.md section 5: R' = [S]B - [k]A must encode to exactly the R bytes of the signature.
        pk, msg, sig = (bytes.fromhex(x) for x in RFC8032[0])
        for bit in (0, 7, 128, 254, 255):
            self.assertFalse(sv.ed25519_verify(pk, msg, flip(sig, bit)), "R bit %d" % bit)

    # Points known without any arithmetic: the identity (x 0, y 1) and the point of order two (x 0, y -1).
    IDENTITY = (1).to_bytes(32, "little")
    ORDER_TWO = (P - 1).to_bytes(32, "little")

    def test_small_order_public_key_is_not_refused(self):
        # With A the identity and S = 0, R' is the identity whatever k is: the signature (identity, 0) verifies for
        # every message. export.md section 5 does not refuse such a key; the fingerprint check is the defence.
        for msg in (b"", b"any message"):
            self.assertTrue(sv.ed25519_verify(self.IDENTITY, msg, self.IDENTITY + bytes(32)))

    def test_non_canonical_r_encoding_is_refused(self):
        # y = p + 1 is another spelling of y = 1 (the identity); the encoding of R' is canonical, so it cannot match.
        non_canonical = (P + 1).to_bytes(32, "little")
        self.assertFalse(sv.ed25519_verify(self.IDENTITY, b"", non_canonical + bytes(32)))

    def test_rule_is_cofactorless(self):
        # A and R the point T of order two, S = 0: R' = -[k]T, which is T when k is odd and the identity when k is
        # even. The cofactored equation would accept both; the cofactorless rule accepts only odd k.
        seen = set()
        for i in range(64):
            msg = b"m%d" % i
            k = int.from_bytes(hashlib.sha512(self.ORDER_TWO + self.ORDER_TWO + msg).digest(), "little") % L
            expected = k % 2 == 1
            self.assertEqual(sv.ed25519_verify(self.ORDER_TWO, msg, self.ORDER_TWO + bytes(32)), expected, msg)
            seen.add(expected)
        self.assertEqual(seen, {True, False})

    def test_x_zero_with_sign_bit_is_refused(self):
        # y = 1 decodes to x = 0; with the sign bit set the encoding is invalid (RFC 8032 section 5.1.3, step 4).
        _, msg, sig = (bytes.fromhex(x) for x in RFC8032[0])
        encoding = bytearray((1).to_bytes(32, "little"))
        encoding[31] |= 0x80
        self.assertFalse(sv.ed25519_verify(bytes(encoding), msg, sig))


# ---------------------------------------------------------------------------------------------------------------------
# export.md: the published export vectors


class ExportVectors(unittest.TestCase):
    def test_every_vector_in_expected_json(self):
        with open(os.path.join(EXPORT_DIR, "expected.json"), encoding="utf-8") as f:
            expected = json.load(f)
        self.assertEqual(len(expected), 10)
        for name, want in sorted(expected.items()):
            with self.subTest(name):
                report = sv.verify_export(read_vector(name))
                self.assertEqual(report.exit_status, want["exit"])
                self.assertEqual(states(report), want["checks"])
                self.assertEqual(report.redacted, want["redacted"])
                self.assertEqual(report.first_failed_seq, want["firstFailedSeq"])

    def test_every_vector_file_is_named_in_expected_json(self):
        with open(os.path.join(EXPORT_DIR, "expected.json"), encoding="utf-8") as f:
            expected = json.load(f)
        files = sorted(n[: -len(".jsonl")] for n in os.listdir(EXPORT_DIR) if n.endswith(".jsonl"))
        self.assertEqual(files, sorted(expected))

    def test_list_of_lines_is_accepted(self):
        lines = read_vector("valid").split(b"\n")[:-1]
        self.assertEqual(sv.verify_export(lines).exit_status, 0)

    def test_valid_report_facts(self):
        report = sv.verify_export(read_vector("valid"))
        self.assertEqual(report.source_id, "01234567-89ab-4cde-8fab-0123456789ab")
        self.assertEqual((report.from_seq, report.to_seq), (1, 7))
        self.assertEqual((report.event_lines_read, report.events_well_formed), (7, 7))
        public = b64url("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg")
        self.assertEqual(report.keys, [("vector-key-1", hashlib.sha256(public).hexdigest())])


# ---------------------------------------------------------------------------------------------------------------------
# export.md sections 1 to 5: malformed input, built by editing the valid vector


class MalformedInput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.valid = read_vector("valid")

    def assert_unreadable(self, data):
        report = sv.verify_export(data)
        self.assertEqual(report.exit_status, 2)
        self.assertIsNotNone(report.unreadable)
        return report

    def assert_result(self, data, first_failed, **failed):
        report = sv.verify_export(data)
        self.assertEqual(states(report), all_ok_but(**failed))
        self.assertEqual(report.first_failed_seq, first_failed)
        self.assertEqual(report.exit_status, 1 if failed else 0)
        return report

    # Header (section 2)

    def test_empty_file(self):
        self.assert_unreadable(b"")

    def test_byte_order_mark(self):
        self.assert_unreadable(b"\xef\xbb\xbf" + self.valid)

    def test_header_not_json(self):
        self.assert_unreadable(replace_line(self.valid, 0, b"not json"))

    def test_header_empty_line(self):
        self.assert_unreadable(b"\n" + self.valid)

    def test_header_is_an_array(self):
        self.assert_unreadable(replace_line(self.valid, 0, b"[1,2]"))

    def test_header_invalid_utf8(self):
        header = self.valid.split(b"\n")[0].replace(b"spacegoat-export/v1", b"spacegoat-export/v1\xff")
        self.assert_unreadable(replace_line(self.valid, 0, header))

    def test_header_duplicate_key(self):
        header = self.valid.split(b"\n")[0]
        self.assert_unreadable(replace_line(self.valid, 0, header[:-1] + b',"toSeq":7}'))

    def header_with(self, **changes):
        header = json.loads(self.valid.split(b"\n")[0].decode("utf-8"))
        for key, value in changes.items():
            if value is KeyError:
                del header[key]
            else:
                header[key] = value
        line = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return replace_line(self.valid, 0, line)

    def test_header_field_rules(self):
        key = {"keyId": "vector-key-1", "publicKey": "ed25519:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}
        bad = [
            {"format": "spacegoat-export/v2"},
            {"format": KeyError},
            {"sourceId": "01234567-89AB-4cde-8fab-0123456789ab"},
            {"sourceId": "0123456789ab4cde8fab0123456789ab"},
            {"fromSeq": 0},
            {"fromSeq": True},
            {"fromSeq": "1"},
            {"toSeq": 2**53},
            {"fromSeq": 8},
            {"keys": []},
            {"keys": [key, key]},
            {"keys": [dict(key, extra=1)]},
            {"keys": [{"keyId": "vector-key-1"}]},
            {"keys": [dict(key, keyId="Vector-key-1")]},
            {"keys": [dict(key, keyId="ab")]},
            {"keys": [dict(key, publicKey="ed25519:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=")]},
            {"keys": [dict(key, publicKey="ed25519:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMb")]},
            {"keys": [dict(key, publicKey="ed25519:A6EHv+POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg")]},
            {"keys": [dict(key, publicKey="A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg")]},
            {"extra": 1},
        ]
        for change in bad:
            with self.subTest(change):
                self.assert_unreadable(self.header_with(**change))

    def test_header_float_is_unreadable(self):
        header = self.valid.split(b"\n")[0].replace(b'"toSeq":7', b'"toSeq":7.0')
        self.assert_unreadable(replace_line(self.valid, 0, header))

    def test_header_lone_surrogate_is_unreadable(self):
        header = self.valid.split(b"\n")[0].replace(b'"toSeq":7', b'"toSeq":7,"x\\ud800":1')
        self.assert_unreadable(replace_line(self.valid, 0, header))

    def test_header_only_fails_sequence_at_from_seq(self):
        header = self.valid.split(b"\n")[0] + b"\n"
        report = self.assert_result(header, 1, sequence="failed")
        self.assertEqual((report.event_lines_read, report.events_well_formed), (0, 0))

    # Line structure (section 1)

    def test_missing_final_newline_is_accepted(self):
        self.assertTrue(self.valid.endswith(b"\n"))
        self.assert_result(self.valid[:-1], None)

    def test_trailing_blank_line_is_a_broken_event_line(self):
        # "there are no empty lines": the blank line is an event line that fails form; it occupies number 8, which
        # is greater than toSeq, so sequence fails too.
        report = self.assert_result(self.valid + b"\n", 8, form="failed", sequence="failed")
        self.assertEqual((report.event_lines_read, report.events_well_formed), (8, 7))

    def test_blank_line_in_the_middle(self):
        lines = self.valid.split(b"\n")
        data = b"\n".join(lines[:3] + [b""] + lines[3:])
        self.assert_result(data, 3, form="failed", sequence="failed")

    # Event lines (sections 3 and 4)

    def test_event_line_invalid_utf8(self):
        line = self.valid.split(b"\n")[2].replace(b"site.device_seen", b"site.device_seen\xc3")
        self.assert_result(replace_line(self.valid, 2, line), 2, form="failed")

    def test_event_line_is_an_array(self):
        self.assert_result(replace_line(self.valid, 3, b"[1,2,3]"), 3, form="failed")

    def test_event_line_not_json(self):
        self.assert_result(replace_line(self.valid, 3, b"{"), 3, form="failed")

    def test_event_line_duplicate_key(self):
        line = self.valid.split(b"\n")[2]
        self.assert_result(replace_line(self.valid, 2, line[:-1] + b',"sourceSeq":2}'), 2, form="failed")

    def test_event_line_duplicate_key_nested(self):
        line = self.valid.split(b"\n")[2].replace(b'"trustOrigin":"hub"', b'"trustOrigin":"hub","trustOrigin":"hub"')
        self.assert_result(replace_line(self.valid, 2, line), 2, form="failed")

    def test_event_numbers_that_are_not_integers(self):
        for spelling in (b"1.5", b"1.0", b"1e3", b"1E3", b"-0.0", b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(spelling):
                line = self.valid.split(b"\n")[4].replace(b'"ephemeral":2', b'"ephemeral":' + spelling)
                self.assert_result(replace_line(self.valid, 4, line), 4, form="failed")

    def test_integer_out_of_range_and_huge(self):
        for spelling in (b"9007199254740992", b"-9007199254740992", b"1" * 5000):
            with self.subTest(len(spelling)):
                line = self.valid.split(b"\n")[4].replace(b'"ephemeral":2', b'"ephemeral":' + spelling)
                self.assert_result(replace_line(self.valid, 4, line), 4, form="failed")

    def test_integer_at_limit_is_form_ok(self):
        # The event no longer matches its signature, but form accepts the value.
        line = self.valid.split(b"\n")[4].replace(b'"ephemeral":2', b'"ephemeral":-9007199254740991')
        self.assert_result(replace_line(self.valid, 4, line), 4, signature="failed")

    def test_lone_surrogate_in_event(self):
        line = self.valid.split(b"\n")[2].replace(b'"trustOrigin":"hub"', b'"trustOrigin":"hub\\udc00"')
        self.assert_result(replace_line(self.valid, 2, line), 2, form="failed")

    def test_escaped_surrogate_pair_is_fine(self):
        # A valid pair is valid Unicode: form passes, the changed value breaks the signature only.
        line = self.valid.split(b"\n")[2].replace(b'"trustOrigin":"hub"', b'"trustOrigin":"\\ud83d\\udc10"')
        self.assert_result(replace_line(self.valid, 2, line), 2, signature="failed")

    def test_key_rules_in_event(self):
        for key in (b"", b"\\u00e9", b"\\u007f", b"\\u0001"):
            with self.subTest(key):
                line = self.valid.split(b"\n")[2].replace(b'"trustOrigin":"hub"', b'"trustOrigin":"hub","' + key + b'":1')
                self.assert_result(replace_line(self.valid, 2, line), 2, form="failed")

    def nested(self, levels, opener=b"[", closer=b"]"):
        # The line's object is level 1 and attributes level 2, so `levels` - 2 more brackets reach `levels`.
        extra = levels - 2
        line = self.valid.split(b"\n")[2].replace(
            b'"trustOrigin":"hub"', b'"trustOrigin":"hub","deep":' + opener * extra + closer * extra
        )
        return replace_line(self.valid, 2, line)

    def test_nesting_limit_is_64_levels(self):
        # export.md section 4: 64 levels pass form (the changed attributes then fail the signature), 65 fail form,
        # whatever the interpreter.
        self.assert_result(self.nested(64), 2, signature="failed")
        self.assert_result(self.nested(65), 2, form="failed")
        self.assert_result(self.nested(65, b'{"a":', b"}"), 2, form="failed")
        self.assert_result(self.nested(100000), 2, form="failed")

    def test_brackets_inside_text_do_not_count(self):
        line = self.valid.split(b"\n")[2].replace(b'"trustOrigin":"hub"', b'"trustOrigin":"hub","t":"' + b"[{" * 100 + b'\\""')
        self.assert_result(replace_line(self.valid, 2, line), 2, signature="failed")

    def test_header_nesting_limit(self):
        header = self.valid.split(b"\n")[0].replace(b'"toSeq":7', b'"toSeq":7,"x":' + b"[" * 64 + b"]" * 64)
        report = self.assert_unreadable(replace_line(self.valid, 0, header))
        self.assertIn("64 levels", report.unreadable)  # refused for its depth, before the extra field is seen

    def test_whitespace_around_the_object_fails_form(self):
        line = self.valid.split(b"\n")[2]
        for changed in (line + b"\r", line + b" ", b" " + line, b"\t" + line, line + b"\t"):
            with self.subTest(repr(changed[:1] + changed[-1:])):
                self.assert_result(replace_line(self.valid, 2, changed), 2, form="failed")

    def test_crlf_file(self):
        self.assert_unreadable(self.valid.replace(b"\n", b"\r\n"))
        lines = self.valid.split(b"\n")
        report = sv.verify_export(lines[0] + b"\n" + b"\r\n".join(lines[1:]))
        self.assertEqual(report.checks["form"], "failed")

    def test_header_whitespace_is_unreadable(self):
        header = self.valid.split(b"\n")[0]
        self.assert_unreadable(replace_line(self.valid, 0, header + b"\r"))
        self.assert_unreadable(replace_line(self.valid, 0, b" " + header))

    def test_whitespace_inside_the_object_is_accepted(self):
        # The verifier does not require compact form (export.md section 1): JSON whitespace between tokens is fine.
        line = self.valid.split(b"\n")[2].replace(b'":', b'" : ').replace(b",", b", ")
        self.assert_result(replace_line(self.valid, 2, line), None)

    def test_explicit_null_commitment_fails_form(self):
        # export.md section 3: an event without personal data omits piiCommitment; a null there fails form.
        self.assert_result(edit_event(self.valid, 2, lambda e: e.update(piiCommitment=None)), 2, form="failed")

    def test_event_field_rules(self):
        cases = [
            ("unknown field", lambda e: e.update(extra=1)),
            ("missing kind", lambda e: e.pop("kind")),
            ("missing attributes", lambda e: e.pop("attributes")),
            ("empty kind", lambda e: e.update(kind="")),
            ("kind not text", lambda e: e.update(kind=1)),
            ("seq zero", lambda e: e.update(sourceSeq=0)),
            ("seq true", lambda e: e.update(sourceSeq=True)),
            ("seq text", lambda e: e.update(sourceSeq="2")),
            ("attributes array", lambda e: e.update(attributes=[])),
            ("observedAt offset", lambda e: e.update(observedAt="2026-11-24T10:05:00.000+00:00")),
            ("observedAt no millis", lambda e: e.update(observedAt="2026-11-24T10:05:00Z")),
            ("observedAt lowercase z", lambda e: e.update(observedAt="2026-11-24T10:05:00.000z")),
            ("observedAt 30 February", lambda e: e.update(observedAt="2026-02-30T10:05:00.000Z")),
            ("observedAt 29 February 2026", lambda e: e.update(observedAt="2026-02-29T10:05:00.000Z")),
            ("observedAt 29 February 1900", lambda e: e.update(observedAt="1900-02-29T10:05:00.000Z")),
            ("observedAt hour 24", lambda e: e.update(observedAt="2026-11-24T24:00:00.000Z")),
            ("observedAt second 60", lambda e: e.update(observedAt="2026-12-31T23:59:60.000Z")),
            ("observedAt month 13", lambda e: e.update(observedAt="2026-13-01T10:05:00.000Z")),
            ("observedAt Arabic-Indic digit", lambda e: e.update(observedAt="2026-11-2٤T10:05:00.000Z")),
            ("signature without prefix", lambda e: e.update(signature=e["signature"][len("ed25519:"):])),
            ("signature bad key id", lambda e: e.update(signature=e["signature"].replace("vector-key-1", "Vector-key-1"))),
            ("signature too short", lambda e: e.update(signature=e["signature"][:-1])),
            ("signature padded", lambda e: e.update(signature=e["signature"] + "==")),
            ("signature trailing newline", lambda e: e.update(signature=e["signature"] + "\n")),
            ("pii without nonce", lambda e: e.update(pii={"ip": "192.0.2.1"}, piiCommitment="0" * 64)),
            ("nonce only", lambda e: e.update(piiNonce="0" * 64)),
            ("pii only", lambda e: e.update(pii={})),
        ]
        for name, edit in cases:
            with self.subTest(name):
                self.assert_result(edit_event(self.valid, 2, edit), 2, form="failed")

    def test_full_shape_field_rules(self):
        cases = [
            ("nonce uppercase", lambda e: e.update(piiNonce=e["piiNonce"].upper())),
            ("nonce short", lambda e: e.update(piiNonce=e["piiNonce"][:-1])),
            ("commitment uppercase", lambda e: e.update(piiCommitment=e["piiCommitment"].upper())),
            ("commitment null", lambda e: e.update(piiCommitment=None)),
            ("pii array", lambda e: e.update(pii=[])),
        ]
        for name, edit in cases:
            with self.subTest(name):
                self.assert_result(edit_event(self.valid, 1, edit), 1, form="failed")

    def test_non_canonical_base64_signature_is_refused(self):
        # 86 characters carry 516 bits for 64 bytes; the last 4 bits must be zero so the text has one spelling.
        def edit(e):
            text = e["signature"]
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            last = alphabet.index(text[-1])
            self.assertEqual(last & 0x0F, 0)
            e["signature"] = text[:-1] + alphabet[last | 1]
        self.assert_result(edit_event(self.valid, 2, edit), 2, form="failed")

    def test_redacted_shape_counts(self):
        def redact(e):
            del e["pii"]
            del e["piiNonce"]
        report = self.assert_result(edit_event(self.valid, 1, redact), None)
        self.assertEqual(report.redacted, 1)

    def test_form_failed_line_justifies_no_jump(self):
        # Line 4 (seq 4) breaks form; it occupies number 4; line 5 (seq 5) then follows on.
        self.assert_result(replace_line(self.valid, 4, b"{}"), 4, form="failed")
        # A broken line whose sourceSeq says 6 still occupies 4: line 5 (seq 5) follows on, line 6 (seq 6) too.
        self.assert_result(edit_event(self.valid, 4, lambda e: e.update(extra=True, sourceSeq=6)), 4, form="failed")

    def test_key_failure_skips_signature(self):
        self.assert_result(
            edit_event(self.valid, 2, lambda e: e.update(signature=e["signature"].replace("vector-key-1", "vector-key-9"))),
            2,
            key="failed",
        )

    def test_gap_declared_rules(self):
        gap = read_vector("declared-gap")
        bad = [
            ("toSeq not s-1", lambda e: e["attributes"].update(toSeq=4)),
            ("fromSeq not previous+1", lambda e: e["attributes"].update(fromSeq=5)),
            ("fromSeq missing", lambda e: e["attributes"].pop("fromSeq")),
            ("toSeq text", lambda e: e["attributes"].update(toSeq="5")),
        ]
        for name, edit in bad:
            with self.subTest(name):
                self.assert_result(edit_event(gap, 4, edit), 6, sequence="failed", signature="failed")

    def test_gap_declared_as_first_event_needs_from_seq_at_least_1(self):
        # export.md section 5: attributes.fromSeq is at least 1, also for a gap declared as the first event.
        gap = read_vector("declared-gap").split(b"\n")
        header = gap[0].replace(b'"fromSeq":1', b'"fromSeq":6')
        self.assert_result(b"\n".join([header, gap[4]]) + b"\n", None)
        for start in (0, -3):
            with self.subTest(start=start):
                line = json.loads(gap[4].decode("utf-8"))
                line["attributes"]["fromSeq"] = start
                body = json.dumps(line, sort_keys=True, separators=(",", ":")).encode("utf-8")
                self.assert_result(b"\n".join([header, body]) + b"\n", 6, sequence="failed", signature="failed")

    def test_reset_rule(self):
        reset = read_vector("reset")
        self.assert_result(
            edit_event(reset, 4, lambda e: e["attributes"].update(lastAckedSeq=2)), 4, sequence="failed", signature="failed"
        )

    def test_event_after_to_seq_fails_sequence(self):
        header = self.valid.split(b"\n")[0].replace(b'"toSeq":7', b'"toSeq":6')
        self.assert_result(replace_line(self.valid, 0, header), 7, sequence="failed")

    def test_short_file_fails_after_last_line(self):
        lines = self.valid.split(b"\n")
        self.assert_result(b"\n".join(lines[:6]) + b"\n", 6, sequence="failed")

    def test_gap_on_the_line_after_a_broken_first_line_is_not_first(self):
        # export.md section 5: "the first event" is the first line after the header, broken or not. The broken
        # first line occupies 1, so the gap on line 2 is not first and its fromSeq must be previous + 1 = 2.
        gap = read_vector("declared-gap").split(b"\n")
        line = json.loads(gap[4].decode("utf-8"))
        # fromSeq 4 is the signed original, so only its sequence fails; fromSeq 2 keeps the sequence but not the signature.
        for start, failed in ((2, {"signature": "failed"}), (4, {"sequence": "failed"})):
            with self.subTest(start=start):
                line["attributes"]["fromSeq"] = start
                body = json.dumps(line, sort_keys=True, separators=(",", ":")).encode("utf-8")
                data = b"\n".join([gap[0], b"{}", body]) + b"\n"
                self.assert_result(data, 1, form="failed", **failed)

    def test_reset_on_the_line_after_a_broken_first_line(self):
        reset = read_vector("reset").split(b"\n")
        header = reset[0].replace(b'"toSeq":4', b'"toSeq":2')
        line = json.loads(reset[4].decode("utf-8"))
        line["sourceSeq"] = 2
        line["attributes"]["lastAckedSeq"] = 1
        body = json.dumps(line, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assert_result(b"\n".join([header, b"{}", body]) + b"\n", 1, form="failed", signature="failed")

    def test_minus_zero_fails_form(self):
        # export.md section 4: -0 is refused.
        line = self.valid.split(b"\n")[4].replace(b'"ephemeral":2', b'"ephemeral":-0')
        self.assert_result(replace_line(self.valid, 4, line), 4, form="failed")
        header = self.valid.split(b"\n")[0].replace(b'"fromSeq":1', b'"fromSeq":-0')
        self.assert_unreadable(replace_line(self.valid, 0, header))

    def test_escaped_key_spelling_is_the_same_key(self):
        # export.md section 4: keys are compared after decoding their escapes.
        line = self.valid.split(b"\n")[2].replace(b'"trustOrigin":"hub"', b'"trustOrigin":"hub","\\u0074rustOrigin":"hub"')
        self.assert_result(replace_line(self.valid, 2, line), 2, form="failed")
        header = self.valid.split(b"\n")[0].replace(b'"toSeq":7', b'"toSeq":7,"to\\u0053eq":7')
        self.assert_unreadable(replace_line(self.valid, 0, header))

    def test_swapped_source_id_fails_every_signature(self):
        header = self.valid.split(b"\n")[0].replace(b"01234567-89ab-4cde-8fab-0123456789ab", b"01234567-89ab-4cde-8fab-0123456789ac")
        report = self.assert_result(replace_line(self.valid, 0, header), 1, signature="failed")
        self.assertEqual(sum(1 for f in report.failures if f[2] == "signature"), 7)

    def test_other_public_key_under_the_same_key_id_fails_every_signature(self):
        other = base64.urlsafe_b64encode(bytes.fromhex(RFC8032[0][0])).decode("ascii").rstrip("=")
        header = self.valid.split(b"\n")[0].replace(b"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg", other.encode("ascii"))
        report = self.assert_result(replace_line(self.valid, 0, header), 1, signature="failed")
        self.assertEqual(sum(1 for f in report.failures if f[2] == "signature"), 7)

    def test_file_starting_after_one_says_so(self):
        # export.md section 7: events before fromSeq cannot be known; events 1..4 removed and fromSeq 5 still pass.
        lines = self.valid.split(b"\n")
        header = lines[0].replace(b'"fromSeq":1', b'"fromSeq":5')
        report = self.assert_result(b"\n".join([header] + lines[5:]), None)
        text = sv.report_to_text(report, "x.jsonl")
        self.assertIn("This file starts at sequence number 5, not at 1.", text)
        self.assertIn("Events before sequence number 5 cannot be known from this file.", text)
        self.assertEqual(sv.report_to_json(report)["startsAtOne"], False)
        valid = sv.verify_export(self.valid)
        self.assertNotIn("starts at sequence number", sv.report_to_text(valid, "x.jsonl"))
        self.assertEqual(sv.report_to_json(valid)["startsAtOne"], True)


# ---------------------------------------------------------------------------------------------------------------------
# The command line and the report (export.md section 6)


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT] + list(args), capture_output=True, text=True, timeout=300)

    def test_valid_text_report(self):
        result = self.run_cli(os.path.join(EXPORT_DIR, "valid.jsonl"))
        self.assertEqual(result.returncode, 0, result.stderr)
        public = b64url("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg")
        out = result.stdout
        self.assertIn(hashlib.sha256(public).hexdigest(), out)
        self.assertIn("must be compared with the registration record", out)
        self.assertIn("Events after the last sequence number cannot be known from this file", out)
        self.assertIn("01234567-89ab-4cde-8fab-0123456789ab", out)
        self.assertIn("1..7", out)

    def test_json_report(self):
        result = self.run_cli(os.path.join(EXPORT_DIR, "deleted-event.jsonl"), "--json")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["checks"]["sequence"], "failed")
        self.assertEqual(report["firstFailedSeq"], 5)
        self.assertEqual(report["exit"], 1)
        self.assertEqual(report["sourceId"], "01234567-89ab-4cde-8fab-0123456789ab")
        self.assertEqual((report["eventLinesRead"], report["eventsWellFormed"]), (6, 6))
        self.assertEqual(len(report["keys"][0]["fingerprint"]), 64)
        self.assertIn("lastSequenceNumber", report)

    def test_self_test(self):
        result = self.run_cli("--self-test", EXPORT_DIR)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_usage_errors_exit_2_without_traceback(self):
        for args in ((), ("a", "b"), (os.path.join(HERE, "does-not-exist.jsonl"),), ("--self-test", HERE + "/nowhere")):
            with self.subTest(args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("Traceback", result.stderr)

    # -- export.md section 6: the exit status is always 0, 1 or 2, also when the report cannot be written

    def run_with_closed_pipe(self, *args):
        proc = subprocess.Popen([sys.executable, SCRIPT] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.stdout.close()  # the reader goes away before the verifier writes, like `| head -0`
        stderr = proc.stderr.read().decode("utf-8", "replace")
        proc.stderr.close()
        return proc.wait(timeout=300), stderr

    def test_broken_pipe(self):
        for name, status in (("deleted-event", 1), ("valid", 2)):
            for extra in ((), ("--json",)):
                with self.subTest(name=name, extra=extra):
                    code, stderr = self.run_with_closed_pipe(os.path.join(EXPORT_DIR, name + ".jsonl"), *extra)
                    self.assertEqual(code, status, stderr)
                    self.assertNotIn("Traceback", stderr)
                    self.assertNotIn("Exception ignored", stderr)
                    self.assertIn("report could not be written", stderr)
        code, stderr = self.run_with_closed_pipe("--self-test", EXPORT_DIR)
        self.assertEqual(code, 2, stderr)
        self.assertNotIn("Traceback", stderr)

    def test_closed_stdout(self):
        for name, status in (("deleted-event", 1), ("valid", 2)):
            with self.subTest(name=name):
                result = subprocess.run(
                    ["/bin/sh", "-c", '"$0" "$1" "$2" >&-', sys.executable, SCRIPT, os.path.join(EXPORT_DIR, name + ".jsonl")],
                    capture_output=True, text=True, timeout=300,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn("report could not be written", result.stderr)

    # -- the file name cannot forge the report

    def test_path_is_printed_escaped(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x\x1b[2J\nResult: PASSED (exit status 0)\n.jsonl")
            with open(path, "wb") as f:
                f.write(read_vector("deleted-event"))
            result = self.run_cli(path)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("\x1b", result.stdout)
            self.assertFalse(any(line.startswith("Result: PASSED") for line in result.stdout.splitlines()))
            self.assertEqual(sum(line.startswith("Result: ") for line in result.stdout.splitlines()), 1)

    def test_path_that_is_not_utf8(self):
        result = subprocess.run([os.fsencode(sys.executable), os.fsencode(SCRIPT), b"/nowhere/bad\xff\x1b.jsonl"],
                                capture_output=True, timeout=300)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertNotIn(b"\x1b", result.stderr)
        report = sv.verify_export(read_vector("valid"))
        text = sv.report_to_text(report, "bad\udcff\x1b\u2028.jsonl")  # what Python makes of a non-UTF-8 argument
        text.encode("ascii")
        self.assertIn("bad\\udcff\\x1b\\u2028.jsonl", text)

    # -- export.md section 6: the result line and the two forms of the report

    def test_result_line_states_the_limit(self):
        ok = sv.report_to_text(sv.verify_export(read_vector("valid")), "v.jsonl").splitlines()
        result = [line for line in ok if line.startswith("Result: ")]
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].startswith("Result: PASSED (exit status 0)"))
        self.assertIn("keys named in this file", result[0])
        self.assertIn("NOT verified", result[0])
        bad = sv.report_to_text(sv.verify_export(read_vector("reordered")), "r.jsonl").splitlines()
        self.assertTrue([line for line in bad if line.startswith("Result: ")][0].startswith("Result: FAILED (exit status 1)"))

    def test_json_and_text_agree_on_every_fact(self):
        import re

        lines = read_vector("valid").split(b"\n")
        variants = {name: read_vector(name) for name in ("valid", "deleted-event", "redacted-pii", "float-attribute")}
        variants["starts-at-5"] = b"\n".join([lines[0].replace(b'"fromSeq":1', b'"fromSeq":5')] + lines[5:])
        variants["trailing-blank"] = read_vector("valid") + b"\n"
        for name, data in variants.items():
            with self.subTest(name):
                report = sv.verify_export(data)
                facts = sv.report_to_json(report)
                text = sv.report_to_text(report, "f.jsonl")

                def field(label):
                    match = re.search(r"^%s:\s+(.*)$" % re.escape(label), text, re.M)
                    self.assertIsNotNone(match, label)
                    return match.group(1)

                self.assertEqual(field("Source"), facts["sourceId"])
                self.assertEqual(field("Range"), "%d..%d" % (facts["fromSeq"], facts["toSeq"]))
                self.assertEqual(int(field("Event lines read")), facts["eventLinesRead"])
                self.assertEqual(int(field("Well-formed events")), facts["eventsWellFormed"])
                self.assertEqual(int(field("Redacted events")), facts["redacted"])
                first = field("First failed sequence number")
                self.assertEqual(None if first == "none" else int(first), facts["firstFailedSeq"])
                for check, state in facts["checks"].items():
                    self.assertRegex(text, r"(?m)^  %s\s+%s$" % (check, state))
                for key in facts["keys"]:
                    self.assertRegex(text, r"(?m)^  %s  %s$" % (re.escape(key["keyId"]), key["fingerprint"]))
                self.assertIn("Last sequence number: %d." % facts["lastSequenceNumber"], text)
                self.assertEqual("starts at sequence number" not in text, facts["startsAtOne"])
                self.assertIn("Result: %s (exit status %d)" % ("PASSED" if facts["exit"] == 0 else "FAILED", facts["exit"]), text)
                self.assertEqual(len(re.findall(r"(?m)^  (line \d+|after the last line), ", text)), len(facts["failures"]))
                for note in facts["notes"]:
                    self.assertIn(note, text)

    # -- --self-test

    def self_test_dir(self, expected, files):
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(os.path.join(tmp.name, "expected.json"), "w", encoding="utf-8") as f:
            json.dump(expected, f)
        for name in files:
            with open(os.path.join(tmp.name, name + ".jsonl"), "wb") as f:
                f.write(read_vector(name))
        return self.run_cli("--self-test", tmp.name)

    def test_self_test_rules(self):
        with open(os.path.join(EXPORT_DIR, "expected.json"), encoding="utf-8") as f:
            valid = json.load(f)["valid"]
        result = self.self_test_dir({"valid": valid}, ["valid"])
        self.assertEqual(result.returncode, 0, result.stdout)
        result = self.self_test_dir({}, [])
        self.assertEqual(result.returncode, 1)
        self.assertIn("no vectors", result.stdout)
        result = self.self_test_dir({"valid": dict(valid, redacted=False)}, ["valid"])  # False must not equal 0
        self.assertEqual(result.returncode, 1, result.stdout)
        result = self.self_test_dir({"valid": dict(valid, exit=False)}, ["valid"])
        self.assertEqual(result.returncode, 1, result.stdout)
        result = self.self_test_dir({"valid": valid, "reset": valid}, ["valid"])  # reset.jsonl missing
        self.assertEqual(result.returncode, 1, result.stdout)
        result = self.self_test_dir({"valid": valid}, ["valid", "reset"])  # reset.jsonl not named
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("reset", result.stdout)

    def test_unreadable_header_exits_2(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bom.jsonl")
            with open(path, "wb") as f:
                f.write(b"\xef\xbb\xbf" + read_vector("valid"))
            result = self.run_cli(path)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("Traceback", result.stderr)
            result = self.run_cli(path, "--json")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["exit"], 2)


if __name__ == "__main__":
    unittest.main()
