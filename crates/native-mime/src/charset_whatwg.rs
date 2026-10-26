//! First-party whole-buffer decoders implementing WHATWG Encoding algorithms.
//! Scalar indexes/labels are generated from official, attributed WHATWG data.
//! Invalid sequences report failure and preserve ASCII delimiters as specified.
#[path = "charset_whatwg_tables.rs"]
mod tables;

pub(super) fn for_label(label: &str) -> Option<&'static str> {
    let label = label
        .trim_matches(|c: char| matches!(c, '\t' | '\n' | '\u{c}' | '\r' | ' '))
        .to_ascii_lowercase();
    tables::LABELS
        .binary_search_by_key(&label.as_str(), |(name, _)| *name)
        .ok()
        .map(|i| tables::LABELS[i].1)
}

#[derive(Default)]
struct Output {
    text: String,
    bad: bool,
}
impl Output {
    fn scalar(&mut self, value: Option<u32>) {
        if let Some(c) = value.and_then(char::from_u32) {
            self.text.push(c);
        } else {
            self.error();
        }
    }
    fn error(&mut self) {
        self.bad = true;
        self.text.push(char::REPLACEMENT_CHARACTER);
    }
    fn finish(self) -> (String, bool) {
        (self.text, self.bad)
    }
}
fn lookup(table: &[u32], index: usize) -> Option<u32> {
    table.get(index).copied().filter(|v| *v != u32::MAX)
}
fn utf8(bytes: &[u8]) -> (String, bool) {
    let value = String::from_utf8_lossy(bytes);
    let bad = matches!(value, std::borrow::Cow::Owned(_));
    (value.into_owned(), bad)
}

fn utf16_standard(bytes: &[u8], big: bool) -> (String, bool) {
    let mut out = Output::default();
    let mut i = 0;
    let unit = |pair: &[u8]| {
        if big {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        }
    };
    while i < bytes.len() {
        if bytes.len() - i < 2 {
            out.error();
            break;
        }
        let first = unit(&bytes[i..]);
        i += 2;
        if (0xd800..=0xdbff).contains(&first) {
            if bytes.len() - i < 2 {
                out.error();
                break;
            }
            let second = unit(&bytes[i..]);
            if (0xdc00..=0xdfff).contains(&second) {
                i += 2;
                out.scalar(Some(
                    0x10000 + (u32::from(first) - 0xd800) * 1024 + u32::from(second) - 0xdc00,
                ));
            } else {
                out.error();
            }
        } else {
            out.scalar(Some(u32::from(first)));
        }
    }
    out.finish()
}

pub(super) fn decode(name: &str, bytes: &[u8]) -> (String, bool) {
    // Preserve the previous charset API's BOM override, including legacy labels.
    if let Some(bytes) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return utf8(bytes);
    }
    if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe]) {
        return utf16_standard(bytes, false);
    }
    if let Some(bytes) = bytes.strip_prefix(&[0xfe, 0xff]) {
        return utf16_standard(bytes, true);
    }
    if let Some(table) = tables::single_byte(name) {
        let mut out = Output::default();
        for &b in bytes {
            out.scalar(if b < 128 {
                Some(u32::from(b))
            } else {
                lookup(table, usize::from(b) - 128)
            });
        }
        return out.finish();
    }
    match name {
        "UTF-8" => utf8(bytes),
        "UTF-16LE" => utf16_standard(bytes, false),
        "UTF-16BE" => utf16_standard(bytes, true),
        "GBK" | "gb18030" => gb18030(bytes),
        "Big5" | "Shift_JIS" | "EUC-KR" => two_byte(name, bytes),
        "EUC-JP" => euc_jp(bytes),
        "ISO-2022-JP" => iso2022_jp(bytes),
        "replacement" => {
            if bytes.is_empty() {
                (String::new(), false)
            } else {
                ("\u{fffd}".into(), true)
            }
        }
        "x-user-defined" => (
            bytes
                .iter()
                .map(|b| {
                    char::from_u32(if *b < 128 {
                        u32::from(*b)
                    } else {
                        0xf780 + u32::from(*b) - 128
                    })
                    .unwrap()
                })
                .collect(),
            false,
        ),
        _ => unreachable!("canonical label missing a first-party decoder"),
    }
}

fn gb_range(pointer: u32) -> Option<u32> {
    if (39420..189000).contains(&pointer) || pointer > 1237575 {
        return None;
    }
    if pointer == 7457 {
        return Some(0xe7c7);
    }
    let i = tables::GB18030_RANGES.partition_point(|(start, _)| *start <= pointer) - 1;
    let (start, scalar) = tables::GB18030_RANGES[i];
    Some(scalar + pointer - start)
}

fn gb18030(bytes: &[u8]) -> (String, bool) {
    let mut out = Output::default();
    let mut i = 0;
    while i < bytes.len() {
        let lead = bytes[i];
        i += 1;
        if lead < 128 {
            out.scalar(Some(u32::from(lead)));
            continue;
        }
        if lead == 0x80 {
            out.scalar(Some(0x20ac));
            continue;
        }
        if !(0x81..=0xfe).contains(&lead) {
            out.error();
            continue;
        }
        let Some(&second) = bytes.get(i) else {
            out.error();
            break;
        };
        if second.is_ascii_digit() {
            let Some(&third) = bytes.get(i + 1) else {
                out.error();
                break;
            };
            if !(0x81..=0xfe).contains(&third) {
                out.error();
                continue;
            }
            let Some(&fourth) = bytes.get(i + 2) else {
                out.error();
                break;
            };
            if !fourth.is_ascii_digit() {
                out.error();
                continue;
            }
            let pointer = u32::from(lead - 0x81) * 12600
                + u32::from(second - 0x30) * 1260
                + u32::from(third - 0x81) * 10
                + u32::from(fourth - 0x30);
            i += 3;
            out.scalar(gb_range(pointer));
        } else {
            let scalar = if (0x40..=0x7e).contains(&second) || (0x80..=0xfe).contains(&second) {
                lookup(
                    tables::GB18030,
                    usize::from(lead - 0x81) * 190
                        + usize::from(second - if second < 0x7f { 0x40 } else { 0x41 }),
                )
            } else {
                None
            };
            if scalar.is_some() || second >= 128 {
                i += 1;
            }
            out.scalar(scalar);
        }
    }
    out.finish()
}

fn two_byte(name: &str, bytes: &[u8]) -> (String, bool) {
    let mut out = Output::default();
    let mut i = 0;
    while i < bytes.len() {
        let lead = bytes[i];
        i += 1;
        if lead < 128 || (name == "Shift_JIS" && lead == 0x80) {
            out.scalar(Some(u32::from(lead)));
            continue;
        }
        if name == "Shift_JIS" && (0xa1..=0xdf).contains(&lead) {
            out.scalar(Some(0xff61 + u32::from(lead - 0xa1)));
            continue;
        }
        let valid_lead = if name == "Shift_JIS" {
            (0x81..=0x9f).contains(&lead) || (0xe0..=0xfc).contains(&lead)
        } else {
            (0x81..=0xfe).contains(&lead)
        };
        if !valid_lead {
            out.error();
            continue;
        }
        let Some(&trail) = bytes.get(i) else {
            out.error();
            break;
        };
        let scalar = match name {
            "Big5" if (0x40..=0x7e).contains(&trail) || (0xa1..=0xfe).contains(&trail) => {
                let index = usize::from(lead - 0x81) * 157
                    + usize::from(trail - if trail < 0x7f { 0x40 } else { 0x62 });
                let pair = match index {
                    1133 => Some((0xca, 0x304)),
                    1135 => Some((0xca, 0x30c)),
                    1164 => Some((0xea, 0x304)),
                    1166 => Some((0xea, 0x30c)),
                    _ => None,
                };
                if let Some((a, b)) = pair {
                    out.scalar(Some(a));
                    out.scalar(Some(b));
                    i += 1;
                    continue;
                }
                lookup(tables::BIG5, index)
            }
            "Shift_JIS" if (0x40..=0x7e).contains(&trail) || (0x80..=0xfc).contains(&trail) => {
                let index = usize::from(lead - if lead < 0xa0 { 0x81 } else { 0xc1 }) * 188
                    + usize::from(trail - if trail < 0x7f { 0x40 } else { 0x41 });
                if (8836..=10715).contains(&index) {
                    Some(0xe000 + index as u32 - 8836)
                } else {
                    lookup(tables::JIS0208, index)
                }
            }
            "EUC-KR" if (0x41..=0xfe).contains(&trail) => lookup(
                tables::EUC_KR,
                usize::from(lead - 0x81) * 190 + usize::from(trail - 0x41),
            ),
            _ => None,
        };
        if scalar.is_some() || trail >= 128 {
            i += 1;
        }
        out.scalar(scalar);
    }
    out.finish()
}

fn euc_jp(bytes: &[u8]) -> (String, bool) {
    let mut out = Output::default();
    let mut i = 0;
    while i < bytes.len() {
        let mut lead = bytes[i];
        i += 1;
        if lead < 128 {
            out.scalar(Some(u32::from(lead)));
            continue;
        }
        if !matches!(lead, 0x8e | 0x8f | 0xa1..=0xfe) {
            out.error();
            continue;
        }
        let Some(&second) = bytes.get(i) else {
            out.error();
            break;
        };
        if lead == 0x8e && (0xa1..=0xdf).contains(&second) {
            i += 1;
            out.scalar(Some(0xff61 + u32::from(second - 0xa1)));
            continue;
        }
        let jis0212 = lead == 0x8f && (0xa1..=0xfe).contains(&second);
        if jis0212 {
            lead = second;
            i += 1;
        }
        let Some(&trail) = bytes.get(i) else {
            out.error();
            break;
        };
        let scalar = if (0xa1..=0xfe).contains(&lead) && (0xa1..=0xfe).contains(&trail) {
            lookup(
                if jis0212 {
                    tables::JIS0212
                } else {
                    tables::JIS0208
                },
                usize::from(lead - 0xa1) * 94 + usize::from(trail - 0xa1),
            )
        } else {
            None
        };
        if scalar.is_some() || trail >= 128 {
            i += 1;
        }
        out.scalar(scalar);
    }
    out.finish()
}

#[derive(Clone, Copy)]
enum IsoState {
    Ascii,
    Roman,
    Katakana,
    Lead,
    Trail,
    EscapeStart,
    Escape,
}

fn iso2022_jp(bytes: &[u8]) -> (String, bool) {
    use IsoState::*;
    let mut out = Output::default();
    let mut i = 0;
    let mut state = Ascii;
    let mut output_state = Ascii;
    let mut lead = 0;
    let mut last_was_escape = false;
    loop {
        let byte = bytes.get(i).copied();
        if byte.is_some() {
            i += 1;
        }
        match state {
            Ascii | Roman | Katakana | Lead => {
                let Some(byte) = byte else {
                    break;
                };
                if byte == 0x1b {
                    state = EscapeStart;
                    continue;
                }
                last_was_escape = false;
                match state {
                    Ascii | Roman if byte < 128 && byte != 0x0e && byte != 0x0f => {
                        out.scalar(Some(if matches!(state, Roman) && byte == 0x5c {
                            0xa5
                        } else if matches!(state, Roman) && byte == 0x7e {
                            0x203e
                        } else {
                            u32::from(byte)
                        }))
                    }
                    Katakana if (0x21..=0x5f).contains(&byte) => {
                        out.scalar(Some(0xff61 + u32::from(byte - 0x21)))
                    }
                    Lead if (0x21..=0x7e).contains(&byte) => {
                        lead = byte;
                        state = Trail;
                    }
                    _ => out.error(),
                }
            }
            Trail => {
                state = Lead;
                match byte {
                    Some(0x1b) => {
                        state = EscapeStart;
                        out.error();
                    }
                    Some(byte @ 0x21..=0x7e) => out.scalar(lookup(
                        tables::JIS0208,
                        usize::from(lead - 0x21) * 94 + usize::from(byte - 0x21),
                    )),
                    _ => out.error(),
                }
            }
            EscapeStart => {
                if let Some(byte @ (0x24 | 0x28)) = byte {
                    lead = byte;
                    state = Escape;
                } else {
                    if byte.is_some() {
                        i -= 1;
                    }
                    state = output_state;
                    last_was_escape = false;
                    out.error();
                }
            }
            Escape => {
                let next = match (lead, byte) {
                    (0x28, Some(0x42)) => Some(Ascii),
                    (0x28, Some(0x4a)) => Some(Roman),
                    (0x28, Some(0x49)) => Some(Katakana),
                    (0x24, Some(0x40 | 0x42)) => Some(Lead),
                    _ => None,
                };
                if let Some(next) = next {
                    state = next;
                    output_state = next;
                    if last_was_escape {
                        out.error();
                    }
                    last_was_escape = true;
                } else {
                    i -= if byte.is_some() { 2 } else { 1 };
                    state = output_state;
                    last_was_escape = false;
                    out.error();
                }
            }
        }
    }
    out.finish()
}
