// SPDX-License-Identifier: AGPL-3.0-or-later
//! Time as the protocol writes it, the one check a hub makes before it trusts its own clock, and the reading of the
//! service's `Date` header.
//!
//! A moment is a count of milliseconds since 1970-01-01T00:00:00Z (Unix time, no leap seconds), so it has no zone to
//! get wrong. The calendar arithmetic is done here by hand (proleptic Gregorian, days counted from 1970-03-01 in
//! 400-year eras) rather than taken from a date library: it is small, and every text it produces is one that
//! `signing::is_observed_at` accepts and that reads back to the same moment.

use std::time::{SystemTime, UNIX_EPOCH};

/// A hub that boots without a battery-backed clock starts in the past. An event signed with that time cannot be taken
/// back, so nothing is produced until the clock has been set (spec/protocol.md was published in this year).
pub const EARLIEST_PLAUSIBLE_YEAR: i64 = 2026;

const MS_PER_SECOND: i64 = 1_000;
const SECONDS_PER_DAY: i64 = 86_400;
const MS_PER_DAY: i64 = SECONDS_PER_DAY * MS_PER_SECOND;

/// The years a four-digit text can hold.
const FIRST_YEAR: i64 = 0;
const LAST_YEAR: i64 = 9_999;

const WEEKDAYS: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Milliseconds since the Unix epoch, floored (a moment 1 µs before the epoch is -1, not 0); `None` only outside
/// the ±292 million years an `i64` of milliseconds holds.
pub fn unix_millis(moment: SystemTime) -> Option<i64> {
    match moment.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).ok(),
        Err(before) => {
            let before = before.duration();
            let whole = i64::try_from(before.as_millis()).ok()?;
            let partial = before.subsec_nanos() % 1_000_000 != 0;
            whole.checked_neg()?.checked_sub(i64::from(partial))
        }
    }
}

/// The system clock now, in milliseconds since the Unix epoch.
pub fn now() -> Option<i64> {
    unix_millis(SystemTime::now())
}

/// UTC, millisecond precision, a literal Z: the only form `observedAt` has. `None` for a moment outside the years
/// 0000 to 9999, which that form cannot write.
pub fn observed_at_text(unix_millis: i64) -> Option<String> {
    let days = unix_millis.div_euclid(MS_PER_DAY);
    let of_day = unix_millis.rem_euclid(MS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    if !(FIRST_YEAR..=LAST_YEAR).contains(&year) {
        return None;
    }
    let (hour, minute) = (of_day / 3_600_000, of_day / 60_000 % 60);
    let (second, milli) = (of_day / MS_PER_SECOND % 60, of_day % MS_PER_SECOND);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milli:03}Z"
    ))
}

/// The moment an `observedAt` text names; `None` for any text `signing::is_observed_at` refuses.
pub fn observed_at_millis(text: &str) -> Option<i64> {
    if !crate::signing::is_observed_at(text) {
        return None;
    }
    let bytes = text.as_bytes();
    let field = |from: usize, to: usize| digits(bytes.get(from..to)?);
    let days = days_from_civil(field(0, 4)?, field(5, 7)?, field(8, 10)?);
    let seconds = field(11, 13)? * 3_600 + field(14, 16)? * 60 + field(17, 19)?;
    Some(days * MS_PER_DAY + seconds * MS_PER_SECOND + field(20, 23)?)
}

/// Whether the clock shows a time a hub could actually be running at: not before the protocol existed.
pub fn clock_is_set(unix_millis: i64) -> bool {
    unix_millis >= days_from_civil(EARLIEST_PLAUSIBLE_YEAR, 1, 1) * MS_PER_DAY
}

/// The moment an HTTP `Date` header names, in seconds since the Unix epoch.
///
/// Only the IMF-fixdate form a sender must use (RFC 9110, 5.6.7), exactly: `Tue, 24 Nov 2026 10:00:00 GMT`. The
/// weekday must be that date's; the obsolete RFC 850 and asctime forms, other zones, other capitalisation, extra or
/// missing spaces, a leap second and a date that does not exist are all refused. A clock check built on a header
/// that was read leniently would trust what it should not.
pub fn parse_http_date(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let shape = b"www, dd mmm dddd dd:dd:dd GMT";
    if bytes.len() != shape.len() {
        return None;
    }
    let shaped = bytes.iter().zip(shape).all(|(b, s)| match s {
        b'd' => b.is_ascii_digit(),
        b'w' | b'm' => b.is_ascii_alphabetic(),
        _ => b == s,
    });
    if !shaped {
        return None;
    }
    let month_name = bytes.get(8..11)?;
    let month = MONTHS.iter().position(|name| name.as_slice() == month_name)?;
    let month = i64::try_from(month).ok()? + 1;
    let field = |from: usize, to: usize| digits(bytes.get(from..to)?);
    let (year, day) = (field(12, 16)?, field(5, 7)?);
    let (hour, minute, second) = (field(17, 19)?, field(20, 22)?, field(23, 25)?);
    if day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let weekday = WEEKDAYS.get(usize::try_from(days.rem_euclid(7)).ok()?)?;
    if bytes.get(0..3)? != weekday.as_slice() {
        return None;
    }
    Some(days * SECONDS_PER_DAY + hour * 3_600 + minute * 60 + second)
}

/// The value of a run of ASCII digits (the caller has checked they are digits).
fn digits(bytes: &[u8]) -> Option<i64> {
    bytes
        .iter()
        .try_fold(0i64, |n, b| b.is_ascii_digit().then(|| n * 10 + i64::from(b - b'0')))
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
///
/// The year is counted from March, so the leap day is the last day of its year; a 400-year era has exactly
/// 146097 days, which makes the rest plain arithmetic.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400; // [0, 399]
    let month_from_march = (month + 9) % 12; // March = 0 ... February = 11
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1; // [0, 365]
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year; // [0, 146096]
    era * 146_097 + day_of_era - 719_468 // 719468: days from 0000-03-01 to 1970-01-01
}

/// The proleptic Gregorian date of a count of days since 1970-01-01 (the inverse of `days_from_civil`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097; // [0, 146096]
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // [0, 399]
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100); // [0, 365]
    let month_from_march = (5 * day_of_year + 2) / 153; // [0, 11]
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1; // [1, 31]
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}
