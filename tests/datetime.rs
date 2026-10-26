//! Fixed known answers and application boundaries for the native date utility.
use std::time::{Duration, UNIX_EPOCH};
use workglen_mail::{
    accounting::model,
    datetime::{DateTime, NaiveDate},
};

#[test]
fn gregorian_leaps_and_supported_bounds() {
    for (year, leap) in [
        (-400, true),
        (-100, false),
        (0, true),
        (1600, true),
        (1900, false),
        (2000, true),
        (2024, true),
        (2100, false),
    ] {
        assert_eq!(NaiveDate::from_ymd_opt(year, 2, 29).is_some(), leap);
    }
    assert!(NaiveDate::from_ymd_opt(-262144, 1, 1).is_none());
    assert_eq!(
        NaiveDate::from_ymd_opt(-262143, 1, 1).unwrap().to_string(),
        "-262143-01-01"
    );
    assert_eq!(
        NaiveDate::from_ymd_opt(262142, 12, 31).unwrap().to_string(),
        "+262142-12-31"
    );
    assert!(NaiveDate::from_ymd_opt(262143, 1, 1).is_none());
    for (m, d) in [(0, 1), (13, 1), (1, 0), (1, 32), (4, 31)] {
        assert!(NaiveDate::from_ymd_opt(2024, m, d).is_none());
    }
    assert!(DateTime::from_timestamp(i64::MIN, 0).is_none());
    assert!(DateTime::from_timestamp(i64::MAX, 0).is_none());
}
#[test]
fn before_epoch_and_millisecond_timestamps_keep_fraction_and_day() {
    for (millis, expected) in [
        (-1001, "1969-12-31T23:59:58.999+00:00"),
        (-1, "1969-12-31T23:59:59.999+00:00"),
        (0, "1970-01-01T00:00:00+00:00"),
        (1, "1970-01-01T00:00:00.001+00:00"),
        (1000, "1970-01-01T00:00:01+00:00"),
    ] {
        assert_eq!(
            DateTime::from_timestamp_millis(millis)
                .unwrap()
                .to_rfc3339(),
            expected
        );
    }
    let before = DateTime::from_system_time(UNIX_EPOCH - Duration::from_nanos(1)).unwrap();
    assert_eq!(before.timestamp(), -1);
    assert_eq!(before.to_rfc3339(), "1969-12-31T23:59:59.999999999+00:00");
    let after = DateTime::from_system_time(UNIX_EPOCH + Duration::from_micros(123456)).unwrap();
    assert_eq!(after.to_rfc3339(), "1970-01-01T00:00:00.123456+00:00");
}
#[test]
fn mail_imap_rfc3339_and_certificate_format_known_answers() {
    let d = DateTime::from_timestamp(784111777, 0).unwrap();
    assert_eq!(d.to_rfc2822(), "Sun, 6 Nov 1994 08:49:37 +0000");
    assert_eq!(d.to_rfc3339(), "1994-11-06T08:49:37+00:00");
    assert_eq!(
        d.format("%d-%b-%Y %H:%M:%S +0000").to_string(),
        "06-Nov-1994 08:49:37 +0000"
    );
    assert_eq!(d.format("%Y%m%d%H%M%SZ").to_string(), "19941106084937Z");
    assert_eq!(
        DateTime::default().to_rfc3339(),
        "1970-01-01T00:00:00+00:00"
    );
}
#[test]
fn accounting_dates_stay_canonical_and_remediation_uses_calendar_days() {
    assert!(model::date("2024-02-29").is_ok());
    for bad in [
        "2023-02-29",
        "2024-2-29",
        "2024-02-29 ",
        " 2024-02-29",
        "2024-13-01",
    ] {
        assert!(model::date(bad).is_err(), "{bad}");
    }
    assert_eq!(
        (model::date("2024-03-01").unwrap() - model::date("2024-02-28").unwrap()).num_days(),
        2
    );
    assert_eq!(
        (model::date("2025-01-01").unwrap() - model::date("2024-12-31").unwrap()).num_days(),
        1
    );
    assert_eq!(
        model::date("2024-01-01")
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp(),
        1704067200
    );
    assert_eq!(
        NaiveDate::parse_from_str("2/29/2024", "%m/%d/%Y")
            .unwrap()
            .to_string(),
        "2024-02-29"
    );
    assert_eq!(
        NaiveDate::parse_from_str("20240229", "%Y%m%d")
            .unwrap()
            .to_string(),
        "2024-02-29"
    );
}
#[test]
fn imap_offsets_and_legacy_leap_seconds_keep_existing_epoch_semantics() {
    let fmt = "%d-%b-%Y %H:%M:%S %z";
    let d = DateTime::parse_from_str("01-Jan-2024 00:00:00 +0530", fmt).unwrap();
    assert_eq!(d.timestamp(), 1704047400);
    assert_eq!(
        DateTime::from_timestamp(d.timestamp(), 0)
            .unwrap()
            .to_rfc3339(),
        "2023-12-31T18:30:00+00:00"
    );
    let leap = DateTime::parse_from_str("31-Dec-2016 23:59:60 +0000", fmt).unwrap();
    assert_eq!(leap.timestamp(), 1483228799);
    assert_eq!(leap.to_rfc3339(), "2016-12-31T23:59:60+00:00");
    assert!(DateTime::from_timestamp(60, 1_000_000_000).is_none());
    assert!(DateTime::from_timestamp(59, 2_000_000_000).is_none());
    for text in [
        "01-Jan-2024 00:00:00 +2400",
        "01-Jan-2024 24:00:00 +0000",
        "01-Jan-2024 00:00:61 +0000",
        "01-Jan-2024 00:00:00 +0060",
    ] {
        assert!(DateTime::parse_from_str(text, fmt).is_err());
    }
}
#[test]
fn retry_after_dates_require_valid_weekday_zone_and_complete_input() {
    let valid = "Mon, 1 Jan 2024 00:00:00 GMT";
    assert_eq!(
        DateTime::parse_from_rfc2822(valid).unwrap().timestamp(),
        1704067200
    );
    assert_eq!(
        DateTime::parse_from_rfc2822("1 Jan 24 00:00 EST")
            .unwrap()
            .timestamp(),
        1704085200
    );
    for invalid in [
        "Tue, 1 Jan 2024 00:00:00 GMT",
        "Mon, 1 Jan 2024 00:00:00 UTC",
        "Mon, 1 Jan 2024 00:00:00 GMT ",
        "Mon, 1 Jan 2024 00:00:00 GMT (unfinished",
    ] {
        assert!(DateTime::parse_from_rfc2822(invalid).is_err());
    }
    let deep = format!("{valid} {}x{}", "(".repeat(20000), ")".repeat(20000));
    assert_eq!(
        DateTime::parse_from_rfc2822(&deep).unwrap().timestamp(),
        1704067200
    );
    let huge = format!("1 Jan {} 00:00 GMT", "9".repeat(100000));
    assert!(DateTime::parse_from_rfc2822(&huge).is_err());
}
