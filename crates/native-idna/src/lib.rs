//! First-party UTS #46 processing, using Unicode 18.0.0 mapping/property data.
//! The application uses nontransitional processing with bidi and ContextJ checks.
//! DNS label/length and URL forbidden-character policies remain with callers.
//! Unicode data is attributed separately; see LICENSE-UNICODE and data/SHA256.json.
use std::fmt;
mod tables;
pub const UNICODE_VERSION: &str = "18.0.0";
const MAX_INPUT: usize = 64 * 1024;
const MAX_NORMALIZED: usize = 4 * MAX_INPUT;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn require(ok: bool, message: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(Error(message)) }
}
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub use_std3_ascii_rules: bool,
    pub check_hyphens: bool,
    pub verify_dns_length: bool,
    pub check_bidi: bool,
    pub check_joiners: bool,
    pub transitional: bool,
    pub allow_trailing_dot: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            use_std3_ascii_rules: false,
            check_hyphens: false,
            verify_dns_length: false,
            check_bidi: true,
            check_joiners: true,
            transitional: false,
            allow_trailing_dot: true,
        }
    }
}
fn property(c: char, table: &[(u32, u32, u8)]) -> u8 {
    let cp = c as u32;
    let n = table.partition_point(|r| r.0 <= cp);
    if n > 0 && cp <= table[n - 1].1 {
        table[n - 1].2
    } else {
        0
    }
}
fn ccc(c: char) -> u8 {
    property(c, tables::CCC)
}
fn mapping(c: char) -> (u8, &'static str) {
    let i = tables::MAPPING.partition_point(|r| r.0 <= c as u32) - 1;
    let r = tables::MAPPING[i];
    (r.2, r.3)
}
fn compose(a: char, b: char) -> Option<char> {
    let (a, b) = (a as u32, b as u32);
    let cp = if (0x1100..0x1113).contains(&a) && (0x1161..0x1176).contains(&b) {
        0xac00 + ((a - 0x1100) * 21 + b - 0x1161) * 28
    } else if (0xac00..0xd7a4).contains(&a)
        && (a - 0xac00).is_multiple_of(28)
        && (0x11a8..0x11c3).contains(&b)
    {
        a + b - 0x11a7
    } else {
        let key = ((a as u64) << 21) | b as u64;
        tables::COMPOSITION
            .binary_search_by_key(&key, |r| r.0)
            .ok()
            .map(|i| tables::COMPOSITION[i].1)?
    };
    char::from_u32(cp)
}
/// NFC only. Stable canonical ordering avoids quadratic insertion on long runs.
/// Hangul decomposition/composition is algorithmic; all other mappings are data.
pub fn normalize_nfc(input: &str) -> Result<String> {
    require(input.len() <= MAX_NORMALIZED, "normalization input limit")?;
    let mut decomposed = Vec::new();
    for c in input.chars() {
        let cp = c as u32;
        if (0xac00..0xd7a4).contains(&cp) {
            let s = cp - 0xac00;
            decomposed.push((char::from_u32(0x1100 + s / 588).unwrap(), 0));
            decomposed.push((char::from_u32(0x1161 + (s % 588) / 28).unwrap(), 0));
            if !s.is_multiple_of(28) {
                decomposed.push((char::from_u32(0x11a7 + s % 28).unwrap(), 0));
            }
        } else if let Ok(i) = tables::DECOMPOSITION.binary_search_by_key(&cp, |r| r.0) {
            decomposed.extend(tables::DECOMPOSITION[i].1.chars().map(|c| (c, ccc(c))));
        } else {
            decomposed.push((c, ccc(c)));
        }
        require(
            decomposed.len() <= MAX_NORMALIZED,
            "normalization expansion limit",
        )?;
    }
    let mut start = 0;
    for i in 0..=decomposed.len() {
        if i == decomposed.len() || decomposed[i].1 == 0 {
            decomposed[start..i].sort_by_key(|v| v.1);
            start = i + 1;
        }
    }
    let mut out: Vec<char> = Vec::with_capacity(decomposed.len());
    let mut starter: Option<usize> = None;
    let mut previous = 0;
    for (c, class) in decomposed {
        if let Some(s) = starter
            && (previous == 0 || previous < class)
            && let Some(composed) = compose(out[s], c)
        {
            out[s] = composed;
            continue;
        }
        if class == 0 {
            starter = Some(out.len());
        }
        out.push(c);
        previous = class;
    }
    Ok(out.into_iter().collect())
}
fn joiners(label: &[char]) -> bool {
    for (i, &c) in label.iter().enumerate() {
        if !matches!(c, '\u{200c}' | '\u{200d}') {
            continue;
        }
        if i > 0 && ccc(label[i - 1]) == 9 {
            continue;
        }
        if c == '\u{200d}' {
            return false;
        }
        let before = label[..i]
            .iter()
            .rev()
            .map(|c| property(*c, tables::JOINING))
            .find(|v| *v != 4);
        let after = label[i + 1..]
            .iter()
            .map(|c| property(*c, tables::JOINING))
            .find(|v| *v != 4);
        if !matches!(before, Some(1 | 3)) || !matches!(after, Some(2 | 3)) {
            return false;
        }
    }
    true
}
fn bidi(label: &[char]) -> bool {
    if label.is_empty() {
        return true;
    }
    let classes: Vec<_> = label.iter().map(|c| property(*c, tables::BIDI)).collect();
    let rtl = matches!(classes[0], 1 | 2);
    if !rtl && classes[0] != 0 {
        return false;
    }
    if classes.iter().any(|v| {
        if rtl {
            !matches!(v, 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 13)
        } else {
            !matches!(v, 0 | 3 | 4 | 5 | 7 | 8 | 9 | 13)
        }
    }) {
        return false;
    }
    let last = classes.iter().rev().find(|c| **c != 8);
    if !last.is_some_and(|v| {
        if rtl {
            matches!(v, 1 | 2 | 3 | 6)
        } else {
            matches!(v, 0 | 3)
        }
    }) {
        return false;
    }
    !rtl || !(classes.contains(&3) && classes.contains(&6))
}
fn labels(input: &str, options: Options) -> Result<Vec<Vec<char>>> {
    require(input.len() <= MAX_INPUT, "domain input limit")?;
    let mut mapped = String::new();
    for c in input.chars() {
        let (status, value) = mapping(c);
        match status {
            2 => {}
            1 | 4 if status == 1 || options.transitional => {
                if options.transitional && c == '\u{1e9e}' {
                    mapped.push_str("ss");
                } else {
                    mapped.push_str(value);
                }
            }
            _ => mapped.push(c),
        }
        require(mapped.len() <= MAX_NORMALIZED, "domain mapping limit")?;
    }
    let normalized = normalize_nfc(&mapped)?;
    let mut out = Vec::new();
    for text in normalized.split('.') {
        let label: Vec<char> = if let Some(encoded) = text.strip_prefix("xn--") {
            require(encoded.len() <= 2000, "Punycode input limit")?;
            let decoded =
                pratique::idna::punycode_decode(encoded).ok_or(Error("invalid Punycode"))?;
            require(decoded.iter().any(|c| !c.is_ascii()), "ASCII-only A-label")?;
            let decoded_text: String = decoded.iter().collect();
            require(
                normalize_nfc(&decoded_text)? == decoded_text,
                "A-label is not NFC",
            )?;
            decoded
        } else {
            text.chars().collect()
        };
        if !label.is_empty() {
            require(
                !label.starts_with(&['x', 'n', '-', '-']),
                "reserved label prefix",
            )?;
            if options.check_hyphens {
                require(
                    label.first() != Some(&'-')
                        && label.last() != Some(&'-')
                        && !(label.get(2) == Some(&'-') && label.get(3) == Some(&'-')),
                    "label hyphen rule",
                )?;
            }
            require(
                property(label[0], tables::MARK) == 0,
                "leading combining mark",
            )?;
            for &c in &label {
                require(
                    c != '.' && matches!(mapping(c).0, 0 | 4),
                    "disallowed label code point",
                )?;
                if options.use_std3_ascii_rules && c.is_ascii() {
                    require(
                        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-',
                        "STD3 ASCII rule",
                    )?;
                }
            }
            if options.check_joiners {
                require(joiners(&label), "ContextJ rule")?;
            }
        }
        out.push(label);
    }
    if options.check_bidi
        && out
            .iter()
            .flatten()
            .any(|c| matches!(property(*c, tables::BIDI), 1 | 2 | 6))
    {
        require(
            out.iter().all(|label| bidi(label)),
            "bidirectional label rule",
        )?;
    }
    Ok(out)
}
pub fn to_ascii(input: &str, options: Options) -> Result<String> {
    let mut output = String::new();
    for (i, label) in labels(input, options)?.iter().enumerate() {
        if i > 0 {
            output.push('.');
        }
        if label.iter().all(char::is_ascii) {
            output.extend(label.iter());
        } else {
            require(label.len() <= 1000, "Punycode output limit")?;
            output.push_str("xn--");
            output.push_str(
                &pratique::idna::punycode_encode(label).ok_or(Error("Punycode overflow"))?,
            );
        }
    }
    if options.verify_dns_length {
        let trimmed = if options.allow_trailing_dot {
            output.strip_suffix('.').unwrap_or(&output)
        } else {
            &output
        };
        require(
            !trimmed.is_empty()
                && trimmed.len() <= 253
                && trimmed.split('.').all(|s| !s.is_empty() && s.len() <= 63),
            "DNS length rule",
        )?;
    }
    Ok(output)
}
pub fn domain_to_ascii(input: &str) -> Result<String> {
    to_ascii(input, Options::default())
}
/// UTS #46 with STD3, hyphen and DNS-length checks. This is not the full
/// IDNA2008 PVALID/ContextO profile and does not detect impersonation.
pub fn domain_to_ascii_strict(input: &str) -> Result<String> {
    to_ascii(
        input,
        Options {
            use_std3_ascii_rules: true,
            check_hyphens: true,
            verify_dns_length: true,
            ..Options::default()
        },
    )
}
/// Validated Unicode form. Invalid input returns an error, never a display name.
pub fn to_unicode(input: &str, options: Options) -> Result<String> {
    Ok(labels(input, options)?
        .iter()
        .map(|s| s.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("."))
}
