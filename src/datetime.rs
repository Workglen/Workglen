//! Workglen's fixed-format Gregorian dates and UTC/fixed-offset timestamps.
//! No local timezone database, locale, third-party parser or runtime service.
// SPDX-License-Identifier: Apache-2.0
use std::{
    fmt,
    ops::Sub,
    time::{SystemTime, UNIX_EPOCH},
};
const MIN_YEAR: i32 = -262_143;
const MAX_YEAR: i32 = 262_142;
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Problem {
    Invalid,
    Range,
    Short,
    Long,
    Impossible,
    Format,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError(Problem);
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Problem::Invalid => "input contains invalid characters",
            Problem::Range => "input is out of range",
            Problem::Short => "premature end of input",
            Problem::Long => "trailing input",
            Problem::Impossible => "no possible date and time matching input",
            Problem::Format => "bad or unsupported format string",
        })
    }
}
impl std::error::Error for ParseError {}
type Parsed<T> = Result<T, ParseError>;
fn problem(p: Problem) -> ParseError {
    ParseError(p)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NaiveDate {
    days: i64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DateTime {
    seconds: i64,
    nanos: u32,
    offset: i32,
}
pub struct Utc;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Days(i64);
impl Days {
    pub fn num_days(self) -> i64 {
        self.0
    }
}
impl Sub for NaiveDate {
    type Output = Days;
    fn sub(self, rhs: Self) -> Days {
        Days(self.days - rhs.days)
    }
}

// Reuse the Gregorian arithmetic already used by first-party Pratique's
// ASN.1 and PKI code (Howard Hinnant civil/day conversion). Euclidean division
// keeps the same calendar rules before year zero and before the Unix epoch.
fn day_number(year: i32, month: u32, day: u32) -> i64 {
    let adjusted = i64::from(year) - i64::from(month <= 2);
    let era = adjusted.div_euclid(400);
    let y = adjusted.rem_euclid(400);
    let m = if month > 2 { month - 3 } else { month + 9 };
    era * 146_097 + y * 365 + y / 4 - y / 100 + (153 * i64::from(m) + 2) / 5 + i64::from(day)
        - 1
        - 719_468
}
fn civil(days: i64) -> (i32, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let within = shifted.rem_euclid(146_097);
    let y = (within - within / 1460 + within / 36_524 - within / 146_096) / 365;
    let doy = within - (365 * y + y / 4 - y / 100);
    let m = (5 * doy + 2) / 153;
    let day = doy - (153 * m + 2) / 5 + 1;
    let month = if m < 10 { m + 3 } else { m - 9 };
    (
        (era * 400 + y + i64::from(month <= 2)) as i32,
        month as u32,
        day as u32,
    )
}
fn year_text(year: i32) -> String {
    if year < 0 {
        format!("-{:04}", -year)
    } else if year > 9999 {
        format!("+{year}")
    } else {
        format!("{year:04}")
    }
}
impl NaiveDate {
    pub fn from_ymd_opt(year: i32, month: u32, day: u32) -> Option<Self> {
        if !(MIN_YEAR..=MAX_YEAR).contains(&year) || !(1..=12).contains(&month) {
            return None;
        }
        let leap =
            year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
        let max = match month {
            2 => {
                if leap {
                    29
                } else {
                    28
                }
            }
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        (day >= 1 && day <= max).then(|| Self {
            days: day_number(year, month, day),
        })
    }
    fn from_days(days: i64) -> Option<Self> {
        (day_number(MIN_YEAR, 1, 1)..=day_number(MAX_YEAR, 12, 31))
            .contains(&days)
            .then_some(Self { days })
    }
    pub fn parse_from_str(input: &str, format: &str) -> Parsed<Self> {
        let mut c = Cursor(input);
        let date = c.date(format)?;
        c.finish()?;
        Ok(date)
    }
    pub fn format(&self, format: &str) -> Formatted {
        Formatted {
            date: *self,
            clock: None,
            offset: 0,
            format: format.into(),
        }
    }
    pub fn and_hms_opt(self, hour: u32, minute: u32, second: u32) -> Option<DateTime> {
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        Some(DateTime {
            seconds: self.days * 86_400 + i64::from(hour * 3600 + minute * 60 + second),
            nanos: 0,
            offset: 0,
        })
    }
    fn weekday(self) -> usize {
        (self.days + 3).rem_euclid(7) as usize
    }
}
impl fmt::Display for NaiveDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, m, d) = civil(self.days);
        write!(f, "{}-{m:02}-{d:02}", year_text(y))
    }
}
impl Utc {
    pub fn now() -> crate::error::Result<DateTime> {
        utc_from_system_time(SystemTime::now())
    }
}
fn utc_from_system_time(time: SystemTime) -> crate::error::Result<DateTime> {
    use crate::error::Context;
    DateTime::from_system_time(time).context("System clock outside supported Gregorian range")
}
impl DateTime {
    pub fn from_timestamp(seconds: i64, nanos: u32) -> Option<Self> {
        NaiveDate::from_days(seconds.div_euclid(86_400))?;
        if nanos >= 2_000_000_000 || (nanos >= 1_000_000_000 && seconds.rem_euclid(60) != 59) {
            return None;
        }
        Some(Self {
            seconds,
            nanos,
            offset: 0,
        })
    }
    pub fn from_timestamp_millis(millis: i64) -> Option<Self> {
        Self::from_timestamp(
            millis.div_euclid(1000),
            (millis.rem_euclid(1000) * 1_000_000) as u32,
        )
    }
    pub fn from_system_time(time: SystemTime) -> Option<Self> {
        let (seconds, nanos) = match time.duration_since(UNIX_EPOCH) {
            Ok(d) => (i64::try_from(d.as_secs()).ok()?, d.subsec_nanos()),
            Err(e) => {
                let d = e.duration();
                let s = i64::try_from(d.as_secs()).ok()?;
                if d.subsec_nanos() == 0 {
                    (-s, 0)
                } else {
                    (
                        s.checked_neg()?.checked_sub(1)?,
                        1_000_000_000 - d.subsec_nanos(),
                    )
                }
            }
        };
        Self::from_timestamp(seconds, nanos)
    }
    pub fn timestamp(self) -> i64 {
        self.seconds
    }
    pub fn and_utc(self) -> Self {
        self
    }
    pub fn date_naive(self) -> NaiveDate {
        NaiveDate {
            days: (self.seconds + i64::from(self.offset)).div_euclid(86_400),
        }
    }
    fn clock(self) -> (u32, u32, u32) {
        let seconds = (self.seconds + i64::from(self.offset)).rem_euclid(86_400) as u32;
        (
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60 + self.nanos / 1_000_000_000,
        )
    }
    pub fn format(&self, format: &str) -> Formatted {
        Formatted {
            date: self.date_naive(),
            clock: Some(self.clock()),
            offset: self.offset,
            format: format.into(),
        }
    }
    pub fn to_rfc2822(self) -> String {
        let date = self.date_naive();
        let (year, month, day) = civil(date.days);
        let (h, m, s) = self.clock();
        assert!(
            (0..=9999).contains(&year),
            "RFC 2822 year outside 0000..9999"
        );
        format!(
            "{}, {day} {} {year:04} {h:02}:{m:02}:{s:02} {}",
            WEEKDAYS[date.weekday()],
            MONTHS[(month - 1) as usize],
            zone(self.offset, false)
        )
    }
    pub fn to_rfc3339(self) -> String {
        let (h, m, s) = self.clock();
        let fraction = self.nanos % 1_000_000_000;
        let sub = if fraction == 0 {
            String::new()
        } else if fraction.is_multiple_of(1_000_000) {
            format!(".{:03}", fraction / 1_000_000)
        } else if fraction.is_multiple_of(1000) {
            format!(".{:06}", fraction / 1000)
        } else {
            format!(".{fraction:09}")
        };
        format!(
            "{}T{h:02}:{m:02}:{s:02}{sub}{}",
            self.date_naive(),
            zone(self.offset, true)
        )
    }
    fn local(date: NaiveDate, h: i64, m: i64, s: i64, offset: i32) -> Parsed<Self> {
        if !(0..24).contains(&h)
            || !(0..60).contains(&m)
            || !(0..=60).contains(&s)
            || offset.abs() >= 86_400
        {
            return Err(problem(Problem::Range));
        }
        let seconds = date.days * 86_400 + h * 3600 + m * 60 + s.min(59) - i64::from(offset);
        let mut result = Self::from_timestamp(seconds, if s == 60 { 1_000_000_000 } else { 0 })
            .ok_or(problem(Problem::Range))?;
        result.offset = offset;
        Ok(result)
    }
    pub fn parse_from_str(input: &str, format: &str) -> Parsed<Self> {
        if format != "%d-%b-%Y %H:%M:%S %z" {
            return Err(problem(Problem::Format));
        }
        let mut c = Cursor(input);
        let date = c.date("%d-%b-%Y")?;
        c.space(false)?;
        let h = c.number(1, 2, true)?.0;
        c.literal(":")?;
        let m = c.number(1, 2, true)?.0;
        c.literal(":")?;
        let s = c.number(1, 2, true)?.0;
        c.space(false)?;
        let offset = c.offset(true)?;
        c.finish()?;
        Self::local(date, h, m, s, offset)
    }
    pub fn parse_from_rfc2822(input: &str) -> Parsed<Self> {
        let mut c = Cursor(input);
        c.space(false)?;
        let weekday = c.named(&WEEKDAYS).ok();
        if weekday.is_some() {
            c.literal(",")?;
        }
        let day = c.number(1, 2, true)?.0;
        c.space(true)?;
        let month = c.named(&MONTHS)? + 1;
        c.space(true)?;
        let (mut year, width) = c.number(2, usize::MAX, false)?;
        year += match (width, year) {
            (2, 0..=49) => 2000,
            (2, _) | (3, _) => 1900,
            _ => 0,
        };
        let year = i32::try_from(year).map_err(|_| problem(Problem::Range))?;
        let date = NaiveDate::from_ymd_opt(year, month as u32, day as u32)
            .ok_or(problem(Problem::Range))?;
        if weekday.is_some_and(|w| w != date.weekday()) {
            return Err(problem(Problem::Impossible));
        }
        c.space(true)?;
        let h = c.number(2, 2, false)?.0;
        c.space(false)?;
        c.literal(":")?;
        c.space(false)?;
        let m = c.number(2, 2, false)?.0;
        let before = c.0;
        c.space(false)?;
        let s = if c.0.starts_with(':') {
            c.literal(":")?;
            c.number(2, 2, false)?.0
        } else {
            c.0 = before;
            0
        };
        c.space(true)?;
        let length = c.0.bytes().take_while(u8::is_ascii_alphabetic).count();
        let offset = if length == 0 {
            c.offset(false)?
        } else {
            if length > 3 {
                return Err(problem(Problem::Invalid));
            }
            let name = c.0[..length].to_ascii_uppercase();
            c.0 = &c.0[length..];
            match name.as_str() {
                "UT" | "GMT" | "Z" => 0,
                "EDT" => -14400,
                "EST" | "CDT" => -18000,
                "CST" | "MDT" => -21600,
                "MST" | "PDT" => -25200,
                "PST" => -28800,
                _ if length == 1 && matches!(name.as_bytes()[0],b'A'..=b'I'|b'K'..=b'Y') => 0,
                _ => return Err(problem(Problem::Invalid)),
            }
        };
        // Nested comments are scanned iteratively, without recursion or allocation.
        loop {
            let before = c.0;
            c.space(false)?;
            if !c.0.starts_with('(') {
                c.0 = before;
                break;
            }
            let mut depth = 0usize;
            let mut escaped = false;
            let mut end = None;
            for (i, b) in c.0.bytes().enumerate() {
                if escaped {
                    escaped = false;
                    continue;
                }
                match b {
                    b'\\' => escaped = true,
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            c.0 = &c.0[end.ok_or(problem(Problem::Short))?..];
        }
        c.finish()?;
        Self::local(date, h, m, s, offset)
    }
}
fn zone(offset: i32, colon: bool) -> String {
    let sign = if offset < 0 { '-' } else { '+' };
    let n = offset.unsigned_abs();
    format!(
        "{sign}{:02}{}{:02}",
        n / 3600,
        if colon { ":" } else { "" },
        n / 60 % 60
    )
}
pub struct Formatted {
    date: NaiveDate,
    clock: Option<(u32, u32, u32)>,
    offset: i32,
    format: String,
}
impl fmt::Display for Formatted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, m, d) = civil(self.date.days);
        let mut chars = self.format.chars();
        while let Some(ch) = chars.next() {
            if ch != '%' {
                write!(f, "{ch}")?;
                continue;
            }
            match chars.next().ok_or(fmt::Error)? {
                '%' => f.write_str("%")?,
                'Y' => f.write_str(&year_text(y))?,
                'm' => write!(f, "{m:02}")?,
                'd' => write!(f, "{d:02}")?,
                'b' => f.write_str(MONTHS[(m - 1) as usize])?,
                'H' => write!(f, "{:02}", self.clock.ok_or(fmt::Error)?.0)?,
                'M' => write!(f, "{:02}", self.clock.ok_or(fmt::Error)?.1)?,
                'S' => write!(f, "{:02}", self.clock.ok_or(fmt::Error)?.2)?,
                'z' => f.write_str(&zone(self.offset, false))?,
                _ => return Err(fmt::Error),
            }
        }
        Ok(())
    }
}
struct Cursor<'a>(&'a str);
impl Cursor<'_> {
    fn finish(&self) -> Parsed<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(problem(Problem::Long))
        }
    }
    fn space(&mut self, required: bool) -> Parsed<()> {
        let tail = self.0.trim_start();
        if required && tail.len() == self.0.len() {
            return Err(problem(Problem::Invalid));
        }
        self.0 = tail;
        Ok(())
    }
    fn literal(&mut self, expected: &str) -> Parsed<()> {
        self.0 = self
            .0
            .strip_prefix(expected)
            .ok_or(problem(if self.0.is_empty() {
                Problem::Short
            } else {
                Problem::Invalid
            }))?;
        Ok(())
    }
    fn number(&mut self, min: usize, max: usize, trim: bool) -> Parsed<(i64, usize)> {
        if trim {
            self.space(false)?;
        }
        let n = self
            .0
            .bytes()
            .take(max)
            .take_while(u8::is_ascii_digit)
            .count();
        if n < min {
            return Err(problem(if self.0.len() < min {
                Problem::Short
            } else {
                Problem::Invalid
            }));
        }
        let value = self.0[..n].parse().map_err(|_| problem(Problem::Range))?;
        self.0 = &self.0[n..];
        Ok((value, n))
    }
    fn year(&mut self) -> Parsed<i32> {
        self.space(false)?;
        let signed = self.0.starts_with(['+', '-']);
        let negative = self.0.starts_with('-');
        if signed {
            self.0 = &self.0[1..];
        }
        let value = self
            .number(1, if signed { usize::MAX } else { 4 }, false)?
            .0;
        i32::try_from(if negative { -value } else { value }).map_err(|_| problem(Problem::Range))
    }
    fn named(&mut self, names: &[&str]) -> Parsed<usize> {
        let prefix = self.0.get(..3).ok_or(problem(Problem::Short))?;
        let index = names
            .iter()
            .position(|name| name.eq_ignore_ascii_case(prefix))
            .ok_or(problem(Problem::Invalid))?;
        self.0 = &self.0[3..];
        Ok(index)
    }
    fn date(&mut self, format: &str) -> Parsed<NaiveDate> {
        let (y, m, d) = match format {
            "%Y-%m-%d" | "%Y%m%d" => {
                let y = self.year()?;
                if format.contains('-') {
                    self.literal("-")?;
                }
                let m = self.number(1, 2, true)?.0;
                if format.contains('-') {
                    self.literal("-")?;
                }
                let d = self.number(1, 2, true)?.0;
                (y, m, d)
            }
            "%m/%d/%Y" => {
                let m = self.number(1, 2, true)?.0;
                self.literal("/")?;
                let d = self.number(1, 2, true)?.0;
                self.literal("/")?;
                (self.year()?, m, d)
            }
            "%d-%b-%Y" => {
                let d = self.number(1, 2, true)?.0;
                self.literal("-")?;
                let m = self.named(&MONTHS)? as i64 + 1;
                self.literal("-")?;
                (self.year()?, m, d)
            }
            _ => return Err(problem(Problem::Format)),
        };
        NaiveDate::from_ymd_opt(y, m as u32, d as u32).ok_or(problem(Problem::Range))
    }
    fn offset(&mut self, imap: bool) -> Parsed<i32> {
        let negative = if self.0.starts_with('-') {
            self.0 = &self.0[1..];
            true
        } else if imap && self.0.starts_with('−') {
            self.0 = &self.0['−'.len_utf8()..];
            true
        } else {
            self.literal("+")?;
            false
        };
        let h = self.number(2, 2, false)?.0;
        if imap {
            while self.0.starts_with(':') || self.0.chars().next().is_some_and(char::is_whitespace)
            {
                if self.0.starts_with(':') {
                    self.0 = &self.0[1..];
                } else {
                    self.space(false)?;
                }
            }
        }
        let m = self.number(2, 2, false)?.0;
        if h > 23 || m > 59 {
            return Err(problem(Problem::Range));
        }
        Ok(((h * 3600 + m * 60) * if negative { -1 } else { 1 }) as i32)
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;

    #[test]
    fn utc_conversion_rejects_out_of_range_clocks_without_fallback() {
        let epoch = utc_from_system_time(UNIX_EPOCH).unwrap();
        assert_eq!(epoch.timestamp(), 0);

        let out_of_range = UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(i64::MAX as u64))
            .expect("test platform must represent the synthetic clock");
        let error = utc_from_system_time(out_of_range).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("System clock outside supported Gregorian range")
        );
    }
}
