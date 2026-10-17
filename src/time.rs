//! Calendar arithmetic for the three date shapes S3 speaks: `x-amz-date`
//! (`20130524T000000Z`), RFC 3339 in listings (`2009-10-12T17:50:30.000Z`) and HTTP dates in
//! headers (`Wed, 12 Oct 2009 17:50:30 GMT`). Proleptic Gregorian, UTC only.

use std::time::{SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date (year, month, day) of a day count since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn split(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time.
pub fn amz_date(secs: i64) -> String {
    let (y, m, d, hh, mm, ss) = split(secs);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `Wed, 12 Oct 2009 17:50:30 GMT` for a Unix time.
pub fn http_date(secs: i64) -> String {
    let (y, m, d, hh, mm, ss) = split(secs);
    let weekday = (secs.div_euclid(86_400) + 3).rem_euclid(7) as usize; // 1970-01-01 was a Thursday
    format!(
        "{}, {d:02} {} {y:04} {hh:02}:{mm:02}:{ss:02} GMT",
        DAYS[weekday],
        MONTHS[m as usize - 1]
    )
}

/// `2009-10-12T17:50:30.000Z` for a nanosecond Unix time (listings carry milliseconds; the
/// stand-in server writes what it has).
pub fn rfc3339(ns: i128) -> String {
    let secs = ns.div_euclid(1_000_000_000) as i64;
    let frac = ns.rem_euclid(1_000_000_000) as u32 / 1_000_000;
    let (y, m, d, hh, mm, ss) = split(secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{frac:03}Z")
}

/// Nanoseconds since the epoch from RFC 3339 with a `Z` zone and any fraction length.
fn month_len(y: i64, m: u32) -> Option<u32> {
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    Some(match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    })
}

pub fn parse_rfc3339(s: &str) -> Option<i128> {
    let s = s.trim();
    let (date, time) = s.split_once('T')?;
    let mut dp = date.split('-');
    let (y, m, d): (i64, u32, u32) = (
        dp.next()?.parse().ok()?,
        dp.next()?.parse().ok()?,
        dp.next()?.parse().ok()?,
    );
    if dp.next().is_some() || !(1..=12).contains(&m) || d == 0 || d > month_len(y, m)? {
        return None;
    }
    let time = time
        .strip_suffix('Z')
        .or_else(|| time.strip_suffix("+00:00"))?;
    let (hms, frac, had_dot) = match time.split_once('.') {
        Some((a, b)) => (a, b, true),
        None => (time, "", false),
    };
    if had_dot && (frac.is_empty() || !frac.bytes().all(|c| c.is_ascii_digit())) {
        return None;
    }
    let mut tp = hms.split(':');
    let (hh, mm, ss): (i64, i64, i64) = (
        tp.next()?.parse().ok()?,
        tp.next()?.parse().ok()?,
        tp.next()?.parse().ok()?,
    );
    if tp.next().is_some()
        || !(0..=23).contains(&hh)
        || !(0..=59).contains(&mm)
        || !(0..=60).contains(&ss)
    {
        return None;
    }
    let days = days_from_civil(y, m, d);
    let secs = days
        .checked_mul(86_400)?
        .checked_add(hh.checked_mul(3600)?)?
        .checked_add(mm.checked_mul(60)?)?
        .checked_add(ss)?;
    let mut nanos: i128 = 0;
    let mut scale: i128 = 100_000_000;
    for c in frac.chars().take(9) {
        nanos += (c.to_digit(10)? as i128) * scale;
        scale /= 10;
    }
    Some(secs as i128 * 1_000_000_000 + nanos)
}

/// Seconds since the epoch from an HTTP date (`Wed, 12 Oct 2009 17:50:30 GMT`), read as
/// exactly as [`parse_http_date_ns`] reads it.
pub fn parse_http_date(s: &str) -> Option<i64> {
    parse_http_date_ns(s).map(|ns| (ns / 1_000_000_000) as i64)
}

/// An RFC 1123 `getlastmodified` (`Tue, 15 Nov 1994 12:45:26 GMT`) as nanoseconds since the
/// epoch. Returns `None` for a form it does not recognize rather than guessing: a wrong
/// mtime makes `sync` copy or skip the wrong files, which is worse than no mtime at all.
///
/// "Exactly" means the IMF-fixdate shape of RFC 7231 and nothing looser: a day name, a
/// two-digit day, a month, a FOUR-digit year, `HH:MM:SS`, and the literal `GMT`. A looser
/// reader takes `94` as a year and ignores the zone token, so `+0200` and `PST` read as
/// GMT and an RFC 850 date reads as year 94. Each of those is a wrong instant handed to
/// the planner with full confidence, which is the one thing this
/// function exists not to do.
pub fn parse_http_date_ns(s: &str) -> Option<i128> {
    let s = s.trim();
    let (_, rest) = s.split_once(", ")?;
    let mut it = rest.split(' ');
    let digits = |t: &str, n: usize| -> Option<i64> {
        (t.len() == n && t.bytes().all(|b| b.is_ascii_digit()))
            .then(|| t.parse().ok())
            .flatten()
    };
    let day = digits(it.next()?, 2)?;
    let month_name = it.next()?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == month_name)? as i64
        + 1;
    let year = digits(it.next()?, 4)?;
    let mut hms = it.next()?.split(':');
    let (h, mi, sec) = (
        digits(hms.next()?, 2)?,
        digits(hms.next()?, 2)?,
        digits(hms.next()?, 2)?,
    );
    if hms.next().is_some() || it.next()? != "GMT" || it.next().is_some() {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ][month as usize - 1];
    // 60 is a leap second and RFC 7231 allows it; a second past that is not a time
    if day < 1 || day > days_in_month || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, month as u32, day as u32);
    // The day name is part of the shape and it was ignored: `Notaday, 15 Nov 1994 ...` and
    // a `Tue` on a Wednesday both read as dates. 1970-01-01 was a Thursday, so the name
    // the date implies is a lookup on days-since-epoch, and it has to match.
    let day_name = s.split(", ").next()?;
    let implied = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    if day_name != implied {
        return None;
    }
    Some((days * 86_400 + h * 3600 + mi * 60 + sec) as i128 * 1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trips_across_leap_years_and_the_epoch() {
        for days in [-719_468, -1, 0, 1, 59, 60, 365, 10_957, 19_000, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y}-{m}-{d}");
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
    }

    #[test]
    fn the_three_formats_agree() {
        let secs = 1_255_369_830; // 2009-10-12T17:50:30Z
        assert_eq!(http_date(secs), "Mon, 12 Oct 2009 17:50:30 GMT");
        assert_eq!(
            rfc3339(secs as i128 * 1_000_000_000 + 7_000_000),
            "2009-10-12T17:50:30.007Z"
        );
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
        assert_eq!(parse_http_date("Mon, 12 Oct 2009 17:50:30 GMT"), Some(secs));
        assert_eq!(
            parse_rfc3339("2009-10-12T17:50:30.000Z"),
            Some(secs as i128 * 1_000_000_000)
        );
        assert_eq!(
            parse_rfc3339("2009-10-12T17:50:30.123456789Z"),
            Some(secs as i128 * 1_000_000_000 + 123_456_789)
        );
        assert_eq!(
            parse_rfc3339("2009-10-12T17:50:30Z"),
            Some(secs as i128 * 1_000_000_000)
        );
        assert_eq!(parse_rfc3339("garbage"), None);
    }

    #[test]
    fn an_http_date_is_read_exactly_or_not_at_all() {
        assert_eq!(parse_http_date_ns("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date_ns("Tue, 15 Nov 1994 12:45:26 GMT"),
            Some(784_903_526_000_000_000)
        );
        // a leap day and a century non-leap year, which is where a naive /4 goes wrong
        assert_eq!(
            parse_http_date_ns("Mon, 29 Feb 2016 00:00:00 GMT"),
            Some(1_456_704_000_000_000_000)
        );
        // `Wed` stood here until the day name was checked: 1900-03-01 was a Thursday, and
        // the old reader accepted the wrong name without a word
        assert_eq!(
            parse_http_date_ns("Thu, 01 Mar 1900 00:00:00 GMT"),
            Some(-2_203_891_200_000_000_000)
        );
        assert_eq!(
            parse_http_date_ns("Sat, 01 Jan 2028 00:00:00 GMT"),
            Some(1_830_297_600_000_000_000)
        );
        // the asctime and unrecognized forms answer None rather than a wrong instant: a
        // wrong mtime makes `sync` copy or skip the wrong files
        assert_eq!(parse_http_date_ns("Tue Nov 15 12:45:26 1994"), None);
        assert_eq!(parse_http_date_ns(""), None);
        assert_eq!(parse_http_date_ns("Tue, 15 Foo 1994 12:45:26 GMT"), None);
        assert_eq!(parse_http_date_ns("Tue, 15 Nov 1994 25:45:26 GMT"), None);
        // The shape is exact: a two-digit year is RFC 850 and reads as year 94, a zone
        // other than GMT is an offset this does not apply, a signed field is not a field,
        // and the 31st of a month with 30 days is not a day. Each answered `Some` before.
        for loose in [
            "Tue, 15 Nov 94 12:45:26 GMT",
            "Tue, 15 Nov 1994 12:45:26 +0200",
            "Tue, 15 Nov 1994 12:45:26 PST",
            "Tue, 15 Nov 1994 12:45:26",
            "Tue, 15 Nov 1994 12:45:26 GMT extra",
            "Tue, -5 Nov 1994 12:45:26 GMT",
            "Tue, 5 Nov 1994 12:45:26 GMT",
            "Tue, 31 Nov 1994 12:45:26 GMT",
            "Wed, 29 Feb 1900 00:00:00 GMT",
            "Tue, 15 Nov 1994 12:45 GMT",
            "15 Nov 1994 12:45:26 GMT",
        ] {
            assert_eq!(
                parse_http_date_ns(loose),
                None,
                "{loose:?} was read as a date"
            );
        }
        // the control for the leap rule: 2000 is a leap year and 1900 is not
        assert!(parse_http_date_ns("Tue, 29 Feb 2000 00:00:00 GMT").is_some());
        // the day name is checked against the date: 15 Nov 1994 was a Tuesday
        for wrong in [
            "Wed, 15 Nov 1994 12:45:26 GMT",
            "Notaday, 15 Nov 1994 12:45:26 GMT",
            "Tuesday, 15 Nov 1994 12:45:26 GMT",
        ] {
            assert_eq!(
                parse_http_date_ns(wrong),
                None,
                "{wrong:?} was read as a date"
            );
        }
        // and a leap second is a time (RFC 7231 allows it), which is the control for the
        // `sec > 60` line being about 61 and not about 60
        assert!(parse_http_date_ns("Sat, 30 Jun 2012 23:59:60 GMT").is_some());
    }
}
