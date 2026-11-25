# SPDX-License-Identifier: AGPL-3.0-or-later
"""Canonical JSON: the one byte form a signed payload has (spec/protocol.md, "Canonical JSON").

Two implementations in two languages sign and verify the same bytes, so the form admits nothing either of them
could write differently: object keys sorted, no whitespace, text as UTF-8 (never escaped to ASCII), and only strings,
safe integers, booleans, null, objects and arrays. A float has more than one spelling; it is refused, not rounded.
"""
from __future__ import annotations

import json
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1


def _check(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("integer outside the safe range")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii() or not key.isprintable():
                raise ValueError("object key must be printable ASCII text")
            _check(item)
        return
    raise ValueError(f"value of type {type(value).__name__} cannot be signed")


def canonical_json(value: Any) -> str:
    """The canonical text of `value`; raises ValueError for anything that has no single spelling."""
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
