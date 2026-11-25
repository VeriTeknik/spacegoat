# SPDX-License-Identifier: AGPL-3.0-or-later
import math

import pytest

from spacegoat_hub.canonical import MAX_SAFE_INTEGER, canonical_json


def test_every_canonical_vector(vectors):
    for case in vectors["canonical"]:
        assert canonical_json(case["value"]) == case["text"], case["name"]


@pytest.mark.parametrize("value", [1.5, 1.0, math.nan, math.inf, {"a": 0.1}, [1, 2.0]])
def test_a_float_has_no_single_spelling_and_is_refused(value):
    with pytest.raises(ValueError):
        canonical_json(value)


def test_integers_stay_in_the_range_both_languages_agree_on():
    assert canonical_json(MAX_SAFE_INTEGER) == str(MAX_SAFE_INTEGER)
    assert canonical_json(-MAX_SAFE_INTEGER) == str(-MAX_SAFE_INTEGER)
    with pytest.raises(ValueError):
        canonical_json(MAX_SAFE_INTEGER + 1)


@pytest.mark.parametrize("key", ["", "ş", "a\nb", "tab\t", 1, None])
def test_object_keys_are_printable_ascii_text(key):
    with pytest.raises(ValueError):
        canonical_json({key: 1})


@pytest.mark.parametrize("value", [b"bytes", {1, 2}, object()])
def test_other_types_are_refused(value):
    with pytest.raises(ValueError):
        canonical_json(value)


def test_text_that_is_not_unicode_is_refused_not_crashed_on():
    with pytest.raises(ValueError):
        canonical_json({"name": "caf\udce9"})


def test_booleans_are_not_integers():
    assert canonical_json([True, False, 1, 0]) == "[true,false,1,0]"
