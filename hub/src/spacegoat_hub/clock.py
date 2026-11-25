# SPDX-License-Identifier: AGPL-3.0-or-later
"""Time as the protocol writes it, and the one check a hub makes before it trusts its own clock."""
from __future__ import annotations

from datetime import UTC, datetime

# A hub that boots without a battery-backed clock starts in the past. An event signed with that time cannot be taken
# back, so nothing is produced until the clock has been set (spec/protocol.md was published in this year).
EARLIEST_PLAUSIBLE_YEAR = 2026


def observed_at_text(moment: datetime) -> str:
    """UTC, millisecond precision, a literal Z: the only form `observedAt` has."""
    utc = moment.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def now() -> datetime:
    return datetime.now(UTC)


def clock_is_set(moment: datetime) -> bool:
    return moment.astimezone(UTC).year >= EARLIEST_PLAUSIBLE_YEAR
