# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import UTC, datetime, timedelta, timezone

from spacegoat_hub import clock
from spacegoat_hub.signing import OBSERVED_AT


def test_observed_at_is_utc_milliseconds_whatever_zone_the_moment_came_in():
    istanbul = timezone(timedelta(hours=3))
    moment = datetime(2026, 11, 24, 13, 0, 0, 123_999, tzinfo=istanbul)
    assert clock.observed_at_text(moment) == "2026-11-24T10:00:00.123Z"
    assert OBSERVED_AT.fullmatch(clock.observed_at_text(clock.now()))


def test_a_clock_before_the_protocol_existed_is_not_set():
    assert not clock.clock_is_set(datetime(1970, 1, 1, tzinfo=UTC))
    assert not clock.clock_is_set(datetime(2025, 12, 31, 23, 59, tzinfo=UTC))
    assert clock.clock_is_set(datetime(2026, 1, 1, tzinfo=UTC))
