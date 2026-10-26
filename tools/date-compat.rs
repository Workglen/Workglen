// SPDX-License-Identifier: Apache-2.0
// Development-only oracle against the former pinned Chrono rlib.
extern crate old_chrono as chrono;
#[allow(dead_code)]
#[path = "../src/datetime.rs"]
mod native;
fn main() {
    let mut counts = [0usize; 4];
    for year in -800..=2400 {
        for month in 0..=13 {
            for day in [0, 1, 28, 29, 30, 31, 32] {
                let a = native::NaiveDate::from_ymd_opt(year, month, day);
                let b = chrono::NaiveDate::from_ymd_opt(year, month, day);
                assert_eq!(
                    a.map(|x| x.to_string()),
                    b.map(|x| x.to_string()),
                    "date {year} {month} {day}"
                );
                if let (Some(a), Some(b)) = (a, b) {
                    assert_eq!(
                        a.and_hms_opt(0, 0, 0).unwrap().timestamp(),
                        b.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp()
                    );
                }
                counts[0] += 1;
            }
        }
    }
    let low = chrono::NaiveDate::MIN
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc()
        .timestamp();
    let high = chrono::NaiveDate::MAX
        .and_hms_opt(23, 59, 59)
        .unwrap()
        .and_utc()
        .timestamp();
    let mut times = vec![
        i64::MIN,
        low - 1,
        low,
        low + 1,
        -62167219200,
        -1,
        0,
        1,
        59,
        60,
        86399,
        high - 1,
        high,
        high + 1,
        i64::MAX,
    ];
    let mut seed = 0x1234_5678_9abc_def1u64;
    for _ in 0..10000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        times.push(low + (seed % ((high - low + 1) as u64)) as i64);
    }
    for sec in times {
        for nano in [
            0, 1, 1000, 1000000, 123456789, 999999999, 1000000000, 1999999999, 2000000000,
        ] {
            let a = native::DateTime::from_timestamp(sec, nano);
            let b = chrono::DateTime::from_timestamp(sec, nano);
            assert_eq!(a.is_some(), b.is_some(), "timestamp range {sec} {nano}");
            if let (Some(a), Some(b)) = (a, b) {
                assert_eq!(a.to_rfc3339(), b.to_rfc3339(), "RFC3339 {sec} {nano}");
                for f in ["%Y-%m-%d", "%Y%m%d%H%M%SZ", "%d-%b-%Y %H:%M:%S +0000"] {
                    assert_eq!(
                        a.format(f).to_string(),
                        b.format(f).to_string(),
                        "format {sec} {nano} {f}"
                    );
                }
                if (0..253402300800).contains(&sec) {
                    assert_eq!(a.to_rfc2822(), b.to_rfc2822());
                }
            }
            counts[1] += 1;
        }
    }
    let dates = [
        "2024-02-29",
        "2023-02-29",
        "1900-02-29",
        "2000-02-29",
        "0000-01-01",
        "-0001-12-31",
        "+10000-01-01",
        "-262143-01-01",
        "+262142-12-31",
        "2024-1-1",
        " 2024- 1-1",
        "2024-01-01 ",
        "2024-00-32",
        "02/29/2024",
        "1/1/2024",
        "20240229",
        "2024111",
        "01-Jan-2024",
        "1-jan-2024",
        "1-January-2024",
        "",
        "日本語",
        "2024-１２-01",
    ];
    for f in ["%Y-%m-%d", "%m/%d/%Y", "%Y%m%d", "%d-%b-%Y"] {
        for text in dates {
            let a = native::NaiveDate::parse_from_str(text, f);
            let b = chrono::NaiveDate::parse_from_str(text, f);
            assert_eq!(
                a.map(|x| x.to_string()).ok(),
                b.map(|x| x.to_string()).ok(),
                "date parse {text:?} {f}"
            );
            counts[2] += 1;
        }
    }
    let rfc = [
        "Mon, 1 Jan 2024 00:00:00 GMT",
        "Wed, 1 Jan 2024 00:00:00 GMT",
        "Mon, 1 Jan 2024 00:00 GMT",
        "1 Jan 2024 00:00:00 GMT",
        "Mon, 1 Jan 24 00:00:00 UT",
        "Mon, 1 Jan 2024 00:00:00 UTC",
        "Mon, 1 Jan 2024 00:00:00 Z",
        "Mon, 1 Jan 2024 00:00:00 J",
        "Mon, 1 Jan 2024 00:00:00 +00:00",
        "(hi) Mon, 1 Jan 2024 00:00:00 +0000 (test)",
        "Mon, 1 Jan 2024 00:00:60 +0000",
        "1 Jan 049 00:00:00 GMT",
        "1 Jan 0049 00:00:00 GMT",
        "Mon, 1 Jan 2024 00:00:00 GMT (a(b\\)c))",
        "Mon, 1 Jan 2024 00 : 00 :00 GMT",
        "Mon, 1 Jan 2024 00:00: 00 GMT",
    ];
    for s in rfc {
        for suffix in ["", " ", "\r\n", "(comment)", " (a(b)c) ", "(", " x"] {
            let text = format!("{s}{suffix}");
            let a = native::DateTime::parse_from_rfc2822(&text)
                .ok()
                .map(|x| (x.timestamp(), x.to_rfc3339()));
            let b = chrono::DateTime::parse_from_rfc2822(&text)
                .ok()
                .map(|x| (x.timestamp(), x.to_rfc3339()));
            assert_eq!(a, b, "rfc parse {text:?}");
            counts[3] += 1;
        }
    }
    for day in ["1", "01", " 1", "32"] {
        for month in ["Jan", "JAN", "January", "é"] {
            for year in ["2024", "0000", "-0001", "+10000", "20245"] {
                for clock in ["00:00:00", "0:0:0", "23:59:60", "24:00:00", "00 :00:00"] {
                    for zone in [
                        "+0000", "-0500", "+01:30", "+01::30", "+01 30", "−0100", "+2400", "+0060",
                        "Z", "GMT",
                    ] {
                        let s = format!("{day}-{month}-{year} {clock} {zone}");
                        let a = native::DateTime::parse_from_str(&s, "%d-%b-%Y %H:%M:%S %z")
                            .ok()
                            .map(|x| (x.timestamp(), x.to_rfc3339()));
                        let b = chrono::DateTime::parse_from_str(&s, "%d-%b-%Y %H:%M:%S %z")
                            .ok()
                            .map(|x| (x.timestamp(), x.to_rfc3339()));
                        assert_eq!(a, b, "IMAP parse {s:?}");
                        counts[2] += 1;
                    }
                }
            }
        }
    }

    for year in [-262143, -1, 0, 1, 9999, 10000, 262142] {
        for date in [format!("01-Jan-{year:+05}"), format!("31-Dec-{year:+05}")] {
            for zone in ["+2359", "+0000", "-2359"] {
                let text = format!("{date} 23:59:59 {zone}");
                let a = native::DateTime::parse_from_str(&text, "%d-%b-%Y %H:%M:%S %z")
                    .ok()
                    .map(|x| x.timestamp());
                let b = chrono::DateTime::parse_from_str(&text, "%d-%b-%Y %H:%M:%S %z")
                    .ok()
                    .map(|x| x.timestamp());
                assert_eq!(a, b, "boundary offset {text}");
                counts[2] += 1;
            }
        }
    }
    for millis in [
        i64::MIN,
        low * 1000 - 1,
        low * 1000,
        -1001,
        -1000,
        -1,
        0,
        1,
        999,
        1000,
        high * 1000 + 999,
        high * 1000 + 1000,
        i64::MAX,
    ] {
        assert_eq!(
            native::DateTime::from_timestamp_millis(millis).map(|d| d.to_rfc3339()),
            chrono::DateTime::from_timestamp_millis(millis).map(|d| d.to_rfc3339())
        );
        counts[1] += 1;
    }
    let zones = [
        "UT", "GMT", "EST", "EDT", "CST", "CDT", "MST", "MDT", "PST", "PDT", "A", "I", "J", "K",
        "Y", "Z", "UTC", "+0000", "-2359", "+2400", "-0060",
    ];
    for year in [0, 49, 50, 99, 999, 1000, 1900, 2000, 2024, 9999] {
        for month in 1..=12 {
            for day in [1, 15, 28] {
                let old = chrono::NaiveDate::from_ymd_opt(year, month, day)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    .and_utc();
                let raw = old.to_rfc2822();
                for zone in zones {
                    let text = raw.replace("+0000", zone);
                    let a = native::DateTime::parse_from_rfc2822(&text)
                        .ok()
                        .map(|d| (d.timestamp(), d.to_rfc3339()));
                    let b = chrono::DateTime::parse_from_rfc2822(&text)
                        .ok()
                        .map(|d| (d.timestamp(), d.to_rfc3339()));
                    assert_eq!(a, b, "named/numeric zone {text}");
                    counts[3] += 1;
                }
            }
        }
    }
    // Deterministic single-edit mutations probe acceptance without executing input.
    for (base, format) in [
        ("2024-02-29", "%Y-%m-%d"),
        ("02/29/2024", "%m/%d/%Y"),
        ("20240229", "%Y%m%d"),
        ("29-Feb-2024", "%d-%b-%Y"),
        ("29-Feb-2024 23:59:60 +0530", "IMAP"),
        ("Thu, 29 Feb 2024 23:59:60 +0000 (note)", "RFC"),
    ] {
        for _ in 0..3000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mut text = base.to_string();
            let at = (seed as usize) % (text.len() + 1);
            let value = [
                "0", "9", " ", "\t", "\r\n", "−", "é", "+", ":", "/", "-", "(", ")", "x", "",
            ][((seed >> 16) as usize) % 15];
            if seed & 1 == 0 && at < text.len() {
                text.remove(at);
            }
            text.insert_str(at.min(text.len()), value);
            if format == "RFC" {
                let a = native::DateTime::parse_from_rfc2822(&text)
                    .ok()
                    .map(|d| (d.timestamp(), d.to_rfc3339()));
                let b = chrono::DateTime::parse_from_rfc2822(&text)
                    .ok()
                    .map(|d| (d.timestamp(), d.to_rfc3339()));
                assert_eq!(a, b, "mutated RFC {text:?}");
                counts[3] += 1;
            } else if format == "IMAP" {
                let f = "%d-%b-%Y %H:%M:%S %z";
                let a = native::DateTime::parse_from_str(&text, f)
                    .ok()
                    .map(|d| (d.timestamp(), d.to_rfc3339()));
                let b = chrono::DateTime::parse_from_str(&text, f)
                    .ok()
                    .map(|d| (d.timestamp(), d.to_rfc3339()));
                assert_eq!(a, b, "mutated IMAP {text:?}");
                counts[2] += 1;
            } else {
                let a = native::NaiveDate::parse_from_str(&text, format)
                    .ok()
                    .map(|d| d.to_string());
                let b = chrono::NaiveDate::parse_from_str(&text, format)
                    .ok()
                    .map(|d| d.to_string());
                assert_eq!(a, b, "mutated date {text:?} {format}");
                counts[2] += 1;
            }
        }
    }
    println!(
        "Chrono/native comparisons passed: {} Gregorian validity/day conversions, {} timestamps/formats, {} date/IMAP parser cases, {} RFC2822 cases",
        counts[0], counts[1], counts[2], counts[3]
    );
}
