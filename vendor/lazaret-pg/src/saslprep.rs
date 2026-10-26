//! RFC 4013 with PostgreSQL's raw-password fallback, ported from Lazaret.
#[rustfmt::skip]
#[path = "unicode_data.rs"]
mod data;

fn flags(c: u32) -> u8 {
    let i = data::PROPERTIES.partition_point(|(_, end, _)| *end < c);
    data::PROPERTIES
        .get(i)
        .filter(|(start, _, _)| *start <= c)
        .map_or(0, |x| x.2)
}
fn cc(c: u32) -> u8 {
    data::COMBINING
        .binary_search_by_key(&c, |p| p.0)
        .ok()
        .map_or(0, |i| data::COMBINING[i].1)
}
fn combine(a: u32, b: u32) -> Option<u32> {
    if (0x1100..0x1113).contains(&a) && (0x1161..0x1176).contains(&b) {
        return Some(0xac00 + (a - 0x1100) * 588 + (b - 0x1161) * 28);
    }
    if (0xac00..0xd7a4).contains(&a)
        && (a - 0xac00).is_multiple_of(28)
        && (0x11a8..0x11c3).contains(&b)
    {
        return Some(a + b - 0x11a7);
    }
    let key = (u64::from(a) << 32) | u64::from(b);
    data::COMPOSITIONS
        .binary_search_by_key(&key, |p| p.0)
        .ok()
        .map(|i| data::COMPOSITIONS[i].1)
}
fn normalize(input: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    for &c in input {
        if (0xac00..0xd7a4).contains(&c) {
            let n = c - 0xac00;
            out.push(0x1100 + n / 588);
            out.push(0x1161 + (n % 588) / 28);
            if n % 28 != 0 {
                out.push(0x11a7 + n % 28);
            }
        } else if let Ok(i) = data::DECOMPOSITIONS.binary_search_by_key(&c, |p| p.0) {
            out.extend_from_slice(data::DECOMPOSITIONS[i].1);
        } else {
            out.push(c);
        }
    }
    let mut start = 0;
    for i in 0..=out.len() {
        if i == out.len() || cc(out[i]) == 0 {
            out[start..i].sort_by_key(|c| cc(*c));
            start = i + 1;
        }
    }
    let mut result = Vec::new();
    let mut starter = None;
    let mut previous = 0;
    for c in out {
        let class = cc(c);
        if let Some(at) = starter
            && (previous == 0 || previous < class)
            && let Some(joined) = combine(result[at], c)
        {
            result[at] = joined;
            continue;
        }
        if class == 0 {
            starter = Some(result.len());
        }
        result.push(c);
        previous = class;
    }
    result
}
pub(crate) fn prepare(value: &str) -> Option<String> {
    if value.is_ascii() && value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Some(value.into());
    }
    let mapped: Vec<u32> = value
        .chars()
        .filter_map(|c| {
            let f = flags(c as u32);
            if f & 2 != 0 {
                Some(32)
            } else if f & 1 != 0 {
                None
            } else {
                Some(c as u32)
            }
        })
        .collect();
    if mapped.is_empty() || mapped.iter().any(|c| flags(*c) & 4 != 0) {
        return None;
    }
    let normal = normalize(&mapped);
    if normal.is_empty() || normal.iter().any(|c| flags(*c) & 4 != 0) {
        return None;
    }
    if normal.iter().any(|c| flags(*c) & 8 != 0)
        && (normal.iter().any(|c| flags(*c) & 16 != 0)
            || flags(normal[0]) & 8 == 0
            || flags(*normal.last()?) & 8 == 0)
    {
        return None;
    }
    normal.into_iter().map(char::from_u32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_unicode_scalar_matches_lazaret_python() {
        use pratique::crypto::sha2::{Hash, Sha256};
        let mut hash = Sha256::new();
        for i in 0u32..0x110000 {
            if let Some(c) = char::from_u32(i) {
                hash.update(&i.to_be_bytes());
                match prepare(&c.to_string()) {
                    None => hash.update(&[0]),
                    Some(s) => {
                        hash.update(&[1]);
                        hash.update(s.as_bytes());
                        hash.update(&[0]);
                    }
                }
            }
        }
        assert_eq!(
            pratique::util::hex(&hash.finalize()),
            "a9cec22deeffa4fb8a7b226c0481442467aa5d4c1733653637ee578da8cabc99"
        );
    }
    #[test]
    fn lazaret_postgres_normalization_cases() {
        for (s, want) in [
            ("I\u{ad}X", "IX"),
            ("user\u{a0}name", "user name"),
            ("\u{2168}", "IX"),
            ("\u{210c}", "H"),
            ("\u{2f874}x", "\u{5f53}x"),
            ("\u{fb01}x", "fix"),
            ("a\u{ad}bé", "abé"),
            ("e\u{301}", "é"),
            ("\u{1100}\u{1161}", "가"),
        ] {
            assert_eq!(prepare(s).as_deref(), Some(want));
        }
        for s in [
            "a\x07",
            "\u{627}1",
            "\u{ad}\u{ad}",
            "\u{1f100}x",
            "\u{fa70}x",
            "\u{2150}x",
            "\u{1f130}bc",
            "e\u{341}x",
        ] {
            assert!(prepare(s).is_none(), "{s:?}");
        }
    }
}
