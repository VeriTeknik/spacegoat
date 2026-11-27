// SPDX-License-Identifier: AGPL-3.0-or-later
//! Time as the protocol writes it: every text the clock produces is one `signing::is_observed_at` accepts, and the
//! `Date` header of an answer is read strictly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use spacegoat_hub::clock;
use spacegoat_hub::signing::is_observed_at;

const DAY_MS: i64 = 86_400_000;
/// 0000-01-01T00:00:00.000Z and 9999-12-31T23:59:59.999Z: the first and last moment the four-digit form can write.
const FIRST_MS: i64 = -62_167_219_200_000;
const LAST_MS: i64 = 253_402_300_799_999;

/// Known moments, computed independently of this implementation.
const KNOWN: [(i64, &str); 7] = [
    (0, "1970-01-01T00:00:00.000Z"),
    (-1, "1969-12-31T23:59:59.999Z"),
    (1_795_514_400_123, "2026-11-24T10:00:00.123Z"),
    (951_868_799_999, "2000-02-29T23:59:59.999Z"),
    (-2_203_891_200_000, "1900-03-01T00:00:00.000Z"),
    (-62_135_596_800_000, "0001-01-01T00:00:00.000Z"),
    (1_767_225_600_000, "2026-01-01T00:00:00.000Z"),
];

#[test]
fn observed_at_is_utc_milliseconds_with_the_sub_millisecond_part_dropped() {
    // A `SystemTime` has no zone: it is UTC by definition.
    let moment = UNIX_EPOCH + Duration::new(1_795_514_400, 123_999_999);
    let millis = clock::unix_millis(moment).unwrap();
    assert_eq!(clock::observed_at_text(millis).unwrap(), "2026-11-24T10:00:00.123Z");
    assert!(is_observed_at(&clock::observed_at_text(clock::now().unwrap()).unwrap()));
}

#[test]
fn a_moment_before_1970_is_floored_not_rounded_toward_zero() {
    let moment = UNIX_EPOCH - Duration::from_micros(1);
    assert_eq!(clock::unix_millis(moment), Some(-1));
    assert_eq!(clock::observed_at_text(-1).unwrap(), "1969-12-31T23:59:59.999Z");
    let moment = UNIX_EPOCH - Duration::from_millis(1);
    assert_eq!(clock::unix_millis(moment), Some(-1));
    let moment = UNIX_EPOCH - Duration::from_nanos(1_000_001);
    assert_eq!(clock::unix_millis(moment), Some(-2));
}

#[test]
fn known_moments_have_their_known_text() {
    for (millis, text) in KNOWN {
        assert_eq!(clock::observed_at_text(millis).as_deref(), Some(text), "{millis}");
        assert_eq!(clock::observed_at_millis(text), Some(millis), "{text}");
    }
}

#[test]
fn a_clock_before_the_protocol_existed_is_not_set() {
    let at = |text: &str| clock::observed_at_millis(text).unwrap();
    assert!(!clock::clock_is_set(at("1970-01-01T00:00:00.000Z")));
    assert!(!clock::clock_is_set(at("2025-12-31T23:59:00.000Z")));
    assert!(!clock::clock_is_set(at("2025-12-31T23:59:59.999Z")));
    assert!(clock::clock_is_set(at("2026-01-01T00:00:00.000Z")));
    assert!(!clock::clock_is_set(i64::MIN));
    assert!(clock::clock_is_set(i64::MAX));
}

#[test]
fn every_text_the_clock_writes_is_an_observed_at_and_reads_back_to_its_moment() {
    // Every day of the whole range at a time of day that moves through the day, so every month and leap rule shows.
    let mut millis = FIRST_MS;
    let mut count = 0u64;
    while millis <= LAST_MS {
        let text = clock::observed_at_text(millis).unwrap();
        assert!(is_observed_at(&text), "{millis} -> {text}");
        assert_eq!(clock::observed_at_millis(&text), Some(millis), "{text}");
        count += 1;
        millis += DAY_MS + 3_600_000 + 61_001;
    }
    assert!(count > 3_000_000);
}

#[test]
fn consecutive_days_are_consecutive_dates() {
    // The text of each midnight is one day after the last: no day is skipped or repeated, Feb 29 only in leap years.
    let mut previous = clock::observed_at_text(FIRST_MS).unwrap();
    let mut millis = FIRST_MS + DAY_MS;
    let mut leap_days = 0;
    while millis <= LAST_MS {
        let text = clock::observed_at_text(millis).unwrap();
        let (y, m, d) = (&text[0..4], &text[5..7], &text[8..10]);
        let (py, pm, pd) = (&previous[0..4], &previous[5..7], &previous[8..10]);
        if y == py && m == pm {
            assert_eq!(
                d.parse::<u32>().unwrap(),
                pd.parse::<u32>().unwrap() + 1,
                "{previous} -> {text}"
            );
        } else {
            assert_eq!(d, "01", "{previous} -> {text}");
            assert!(is_observed_at(&previous));
            // The previous day was the last of its month: one more day is not a date.
            let next = format!(
                "{}{:02}{}",
                &previous[..8],
                pd.parse::<u32>().unwrap() + 1,
                &previous[10..]
            );
            assert!(!is_observed_at(&next), "{next}");
        }
        if &text[5..10] == "02-29" {
            leap_days += 1;
        }
        previous = text;
        millis += DAY_MS;
    }
    // 10000 years of the Gregorian calendar have 2425 leap days.
    assert_eq!(leap_days, 2425);
}

#[test]
fn a_moment_the_form_cannot_write_gives_no_text() {
    assert_eq!(
        clock::observed_at_text(FIRST_MS).as_deref(),
        Some("0000-01-01T00:00:00.000Z")
    );
    assert_eq!(
        clock::observed_at_text(LAST_MS).as_deref(),
        Some("9999-12-31T23:59:59.999Z")
    );
    assert_eq!(clock::observed_at_text(FIRST_MS - 1), None);
    assert_eq!(clock::observed_at_text(LAST_MS + 1), None);
    assert_eq!(clock::observed_at_text(i64::MIN), None);
    assert_eq!(clock::observed_at_text(i64::MAX), None);
}

#[test]
fn observed_at_millis_reads_only_what_is_observed_at() {
    for bad in [
        "2026-11-24T10:00:00.123+00:00",
        "2026-11-24T10:00:00Z",
        "2026-13-01T00:00:00.000Z",
        "2026-02-29T00:00:00.000Z",
        "2026-11-24t10:00:00.123Z",
        "",
    ] {
        assert_eq!(clock::observed_at_millis(bad), None, "{bad}");
    }
}

#[test]
fn now_moves_with_the_system_clock() {
    let before = clock::unix_millis(SystemTime::now()).unwrap();
    let now = clock::now().unwrap();
    let after = clock::unix_millis(SystemTime::now()).unwrap();
    assert!(before <= now && now <= after);
}

#[test]
fn a_date_header_is_read_as_unix_seconds() {
    assert_eq!(
        clock::parse_http_date("Tue, 24 Nov 2026 10:00:00 GMT"),
        Some(1_795_514_400)
    );
    assert_eq!(clock::parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
    assert_eq!(clock::parse_http_date("Wed, 31 Dec 1969 23:59:59 GMT"), Some(-1));
    assert_eq!(
        clock::parse_http_date("Tue, 29 Feb 2000 23:59:59 GMT"),
        Some(951_868_799)
    );
    assert_eq!(
        clock::parse_http_date("Thu, 01 Mar 1900 00:00:00 GMT"),
        Some(-2_203_891_200)
    );
    assert_eq!(
        clock::parse_http_date("Fri, 31 Dec 9999 23:59:59 GMT"),
        Some(253_402_300_799)
    );
    // RFC 9110's own example.
    assert_eq!(
        clock::parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
        Some(784_111_777)
    );
}

#[test]
fn a_date_header_agrees_with_the_clock_for_every_day() {
    let days = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut seconds = FIRST_MS / 1000;
    while seconds <= LAST_MS / 1000 {
        let text = clock::observed_at_text(seconds * 1000).unwrap();
        let day_index = (seconds.div_euclid(86_400)).rem_euclid(7) as usize;
        let month: usize = text[5..7].parse().unwrap();
        let header = format!(
            "{}, {} {} {} {} GMT",
            days[day_index],
            &text[8..10],
            months[month - 1],
            &text[0..4],
            &text[11..19]
        );
        assert_eq!(clock::parse_http_date(&header), Some(seconds), "{header}");
        seconds += 86_400 * 3 + 3_599;
    }
}

#[test]
fn a_date_header_in_any_other_form_is_refused() {
    for bad in [
        // The weekday does not match the date.
        "Mon, 24 Nov 2026 10:00:00 GMT",
        // Not GMT, or not spelled as IMF-fixdate spells it.
        "Tue, 24 Nov 2026 10:00:00 UTC",
        "Tue, 24 Nov 2026 10:00:00 gmt",
        "Tue, 24 Nov 2026 10:00:00 +0000",
        "tue, 24 Nov 2026 10:00:00 GMT",
        "Tue, 24 nov 2026 10:00:00 GMT",
        "Tue, 24 NOV 2026 10:00:00 GMT",
        // The obsolete forms (RFC 850 and asctime), which a sender must not use.
        "Tuesday, 24-Nov-26 10:00:00 GMT",
        "Tue Nov 24 10:00:00 2026",
        // Wrong widths and spacing.
        "Tue, 4 Nov 2026 10:00:00 GMT",
        "Tue,  24 Nov 2026 10:00:00 GMT",
        "Tue, 24 Nov 2026 10:00:00 GMT ",
        " Tue, 24 Nov 2026 10:00:00 GMT",
        "Tue, 24 Nov 2026 10:00:00 GMT\r\n",
        "Tue 24 Nov 2026 10:00:00 GMT",
        "Tue, 24 Nov 26 10:00:00 GMT",
        "Tue, 24 Nov 2026 10:00 GMT",
        // Dates and times that do not exist.
        "Thu, 29 Feb 2026 10:00:00 GMT",
        "Sun, 31 Nov 2026 10:00:00 GMT",
        "Tue, 00 Nov 2026 10:00:00 GMT",
        "Tue, 24 Nov 2026 24:00:00 GMT",
        "Tue, 24 Nov 2026 10:60:00 GMT",
        "Tue, 24 Nov 2026 10:00:60 GMT",
        // Signs and digits of other scripts are not digits.
        "Tue, 24 Nov 2026 10:00:+0 GMT",
        "Tue, 24 Nov 2026 10:00:0\u{0661} GMT",
        "",
    ] {
        assert_eq!(clock::parse_http_date(bad), None, "{bad:?}");
    }
}
