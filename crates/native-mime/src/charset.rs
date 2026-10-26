//! MIME charset selection with first-party codecs and attributed standard mapping data.
#[path = "charset_tables.rs"]
mod tables;
#[path = "charset_whatwg.rs"]
mod whatwg;
fn utf16(bytes: &[u8], big: bool) -> (String, bool) {
    let mut bad = !bytes.len().is_multiple_of(2);
    let text = char::decode_utf16(bytes.as_chunks::<2>().0.iter().map(|b| {
        if big {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        }
    }))
    .map(|v| {
        v.unwrap_or_else(|_| {
            bad = true;
            char::REPLACEMENT_CHARACTER
        })
    })
    .collect();
    (text, bad)
}
fn utf7(bytes: &[u8]) -> (String, bool) {
    let mut out = String::new();
    let mut bad = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'+' {
            if bytes[i].is_ascii() {
                out.push(bytes[i] as char);
            } else {
                out.push(char::REPLACEMENT_CHARACTER);
                bad = true;
            }
            i += 1;
            continue;
        }
        i += 1;
        if bytes.get(i) == Some(&b'-') {
            out.push('+');
            i += 1;
            continue;
        }
        let start = i;
        while bytes
            .get(i)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
        {
            i += 1;
        }
        let (decoded, problem) = crate::transfer::base64(&bytes[start..i]);
        let (text, invalid) = utf16(&decoded, true);
        out.push_str(&text);
        bad |= problem || invalid || i == start;
        if bytes.get(i) == Some(&b'-') {
            i += 1;
        }
    }
    (out, bad)
}
pub(crate) fn decode(bytes: &[u8], label: Option<&str>) -> (String, bool) {
    let label = label
        .unwrap_or("utf-8")
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-");
    let compact = label.replace('-', "");
    let compact = compact.split(':').next().unwrap_or(&compact).to_owned();
    if matches!(
        compact.as_str(),
        "utf8" | "unicode11utf8" | "unicode20utf8" | "xunicode20utf8"
    ) {
        let v = String::from_utf8_lossy(bytes);
        let bad = matches!(v, std::borrow::Cow::Owned(_));
        return (v.into_owned(), bad);
    }
    if matches!(compact.as_str(), "utf7" | "csutf7" | "unicode11utf7") {
        return utf7(bytes);
    }
    if matches!(
        compact.as_str(),
        "utf16" | "csutf16" | "csunicode" | "unicode" | "ucs2" | "iso10646ucs2"
    ) {
        return if bytes.starts_with(&[0xff, 0xfe]) {
            utf16(&bytes[2..], false)
        } else if bytes.starts_with(&[0xfe, 0xff]) {
            utf16(&bytes[2..], true)
        } else {
            utf16(bytes, false)
        };
    }
    if matches!(compact.as_str(), "utf16be" | "csutf16be" | "unicodefffe") {
        return utf16(bytes, true);
    }
    if matches!(compact.as_str(), "utf16le" | "csutf16le" | "unicodefeff") {
        return utf16(bytes, false);
    }
    if matches!(
        compact.as_str(),
        "ibm850" | "cp850" | "850" | "cspc850multilingual"
    ) {
        return (
            bytes
                .iter()
                .map(|b| char::from_u32(tables::CP850[*b as usize]).unwrap())
                .collect(),
            false,
        );
    }
    let iso = compact
        .strip_prefix("iso8859")
        .and_then(|n| n.parse::<u8>().ok())
        .or(match compact.as_str() {
            "isoir101" | "latin2" | "l2" | "csisolatin2" => Some(2),
            "isoir109" | "latin3" | "l3" | "csisolatin3" => Some(3),
            "isoir110" | "latin4" | "l4" | "csisolatin4" => Some(4),
            "isoir144" | "cyrillic" | "csisolatincyrillic" => Some(5),
            "isoir127" | "ecma114" | "arabic" | "asmo708" | "csisolatinarabic" | "csiso88596e"
            | "csiso88596i" | "iso88596e" | "iso88596i" => Some(6),
            "isoir126" | "ecma118" | "elot928" | "greek" | "greek8" | "csisolatingreek"
            | "suneugreek" => Some(7),
            "isoir138" | "hebrew" | "csisolatinhebrew" | "csiso88598e" | "csiso88598i"
            | "iso88598e" | "iso88598i" | "visual" | "logical" => Some(8),
            "isoir148" | "latin5" | "l5" | "csisolatin5" => Some(9),
            "isoir157" | "latin6" | "l6" | "csisolatin6" => Some(10),
            "tis620" | "cstis620" => Some(11),
            "latin7" | "l7" | "csiso885913" => Some(13),
            "isoir199" | "isoceltic" | "latin8" | "l8" | "csiso885914" => Some(14),
            "latin9" | "l9" | "csisolatin9" | "csiso885915" => Some(15),
            "isoir226" | "latin10" | "l10" | "csiso885916" => Some(16),
            _ => None,
        });
    if iso == Some(16) {
        return (
            bytes
                .iter()
                .map(|b| char::from_u32(tables::ISO8859_16[*b as usize]).unwrap())
                .collect(),
            false,
        );
    }
    let normalized = if let Some(n) = iso {
        format!("iso-8859-{n}")
    } else if let Some(n) = compact
        .strip_prefix("cp")
        .or_else(|| compact.strip_prefix("xcp"))
        .or_else(|| compact.strip_prefix("cswindows"))
    {
        format!("windows-{n}")
    } else {
        label.clone()
    };
    let alias = match normalized.as_str() {
        "850" => "ibm850",
        "ansi-x3.4-1968" => "windows-1252",
        "extended-unix-code-packed-format-for-japanese" => "euc-jp",
        "ks-c-5601-1987" | "ks-c-5601-1989" | "ksc-5601" => "euc-kr",
        "ms-kanji" => "shift_jis",
        "csgb18030" | "gb2312" => "gb18030",
        "cp819" | "windows-819" => "windows-1252",
        "cswindows874" => "windows-874",
        "iso-ir-149" => "euc-kr",
        "iso-ir-58" => "gbk",
        "866" | "windows-866" => "ibm866",
        "ms936" | "csgbk" | "windows-936" | "x-gbk" | "chinese" | "gb-2312" | "gb-2312-80"
        | "csiso58gb231280" => "gbk",
        "windows-949" | "korean" | "csksc56011987" => "euc-kr",
        "windows-932" | "windows-31j" | "ms932" => "shift_jis",
        "csbig5" | "cn-big5" | "x-x-big5" => "big5",
        "x-mac-roman" => "macintosh",
        "cskoi8u" | "koi8-ru" => "koi8-u",
        "koi" | "koi8" => "koi8-r",
        "replacement" => "iso-2022-kr",
        s => s,
    };
    let Some(encoding) = whatwg::for_label(alias) else {
        let v = String::from_utf8_lossy(bytes);
        return (v.into_owned(), true);
    };
    // ISO 8859-9 and TIS-620 historically preserve C1 controls, while WHATWG aliases
    // select Windows extensions. Decode each byte for these specific legacy labels.
    if matches!(iso, Some(9 | 11)) {
        let mut text = String::new();
        let mut bad = false;
        for &b in bytes {
            if (0x80..=0x9f).contains(&b) {
                text.push(b as char);
            } else {
                let data = [b];
                let (v, e) = whatwg::decode(encoding, &data);
                text.push_str(&v);
                bad |= e;
            }
        }
        return (text, bad);
    }
    let (text, mut bad) = whatwg::decode(encoding, bytes);
    if encoding.starts_with("windows-") {
        let text = text
            .chars()
            .map(|c| {
                if ('\u{80}'..='\u{9f}').contains(&c) {
                    bad = true;
                    char::REPLACEMENT_CHARACTER
                } else {
                    c
                }
            })
            .collect();
        return (text, bad);
    }
    (text, bad)
}
