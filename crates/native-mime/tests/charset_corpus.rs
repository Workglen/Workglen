//! Deterministic decoder corpus: no random system state or external runtime.
pub const CANONICAL: &[&str] = &[
    "UTF-8",
    "IBM866",
    "ISO-8859-2",
    "ISO-8859-3",
    "ISO-8859-4",
    "ISO-8859-5",
    "ISO-8859-6",
    "ISO-8859-7",
    "ISO-8859-8",
    "ISO-8859-8-I",
    "ISO-8859-10",
    "ISO-8859-13",
    "ISO-8859-14",
    "ISO-8859-15",
    "ISO-8859-16",
    "KOI8-R",
    "KOI8-U",
    "macintosh",
    "windows-874",
    "windows-1250",
    "windows-1251",
    "windows-1252",
    "windows-1253",
    "windows-1254",
    "windows-1255",
    "windows-1256",
    "windows-1257",
    "windows-1258",
    "x-mac-cyrillic",
    "GBK",
    "gb18030",
    "Big5",
    "EUC-JP",
    "ISO-2022-JP",
    "Shift_JIS",
    "EUC-KR",
    "replacement",
    "UTF-16BE",
    "UTF-16LE",
    "x-user-defined",
];
pub const LABELS: &[&str] = &[
    "866",
    "ansi_x3.4-1968",
    "arabic",
    "ascii",
    "asmo-708",
    "big5",
    "big5-hkscs",
    "chinese",
    "cn-big5",
    "cp1250",
    "cp1251",
    "cp1252",
    "cp1253",
    "cp1254",
    "cp1255",
    "cp1256",
    "cp1257",
    "cp1258",
    "cp819",
    "cp850",
    "cp866",
    "csbig5",
    "cseuckr",
    "cseucpkdfmtjapanese",
    "csgb2312",
    "csibm866",
    "csiso2022jp",
    "csiso2022kr",
    "csiso58gb231280",
    "csiso88596e",
    "csiso88596i",
    "csiso88598e",
    "csiso88598i",
    "csisolatin1",
    "csisolatin2",
    "csisolatin3",
    "csisolatin4",
    "csisolatin5",
    "csisolatin6",
    "csisolatin9",
    "csisolatinarabic",
    "csisolatincyrillic",
    "csisolatingreek",
    "csisolatinhebrew",
    "cskoi8r",
    "csksc56011987",
    "csmacintosh",
    "csshiftjis",
    "csunicode",
    "cyrillic",
    "dos-874",
    "ecma-114",
    "ecma-118",
    "elot_928",
    "euc-jp",
    "euc-kr",
    "gb18030",
    "gb2312",
    "gb_2312",
    "gb_2312-80",
    "gbk",
    "greek",
    "greek8",
    "hebrew",
    "hz-gb-2312",
    "ibm819",
    "ibm866",
    "iso-10646-ucs-2",
    "iso-2022-cn",
    "iso-2022-cn-ext",
    "iso-2022-jp",
    "iso-2022-kr",
    "iso-8859-1",
    "iso-8859-10",
    "iso-8859-11",
    "iso-8859-13",
    "iso-8859-14",
    "iso-8859-15",
    "iso-8859-16",
    "iso-8859-2",
    "iso-8859-3",
    "iso-8859-4",
    "iso-8859-5",
    "iso-8859-6",
    "iso-8859-6-e",
    "iso-8859-6-i",
    "iso-8859-7",
    "iso-8859-8",
    "iso-8859-8-e",
    "iso-8859-8-i",
    "iso-8859-9",
    "iso-ir-100",
    "iso-ir-101",
    "iso-ir-109",
    "iso-ir-110",
    "iso-ir-126",
    "iso-ir-127",
    "iso-ir-138",
    "iso-ir-144",
    "iso-ir-148",
    "iso-ir-149",
    "iso-ir-157",
    "iso-ir-58",
    "iso8859-1",
    "iso8859-10",
    "iso8859-11",
    "iso8859-13",
    "iso8859-14",
    "iso8859-15",
    "iso8859-2",
    "iso8859-3",
    "iso8859-4",
    "iso8859-5",
    "iso8859-6",
    "iso8859-7",
    "iso8859-8",
    "iso8859-9",
    "iso88591",
    "iso885910",
    "iso885911",
    "iso885913",
    "iso885914",
    "iso885915",
    "iso88592",
    "iso88593",
    "iso88594",
    "iso88595",
    "iso88596",
    "iso88597",
    "iso88598",
    "iso88599",
    "iso_8859-1",
    "iso_8859-15",
    "iso_8859-1:1987",
    "iso_8859-2",
    "iso_8859-2:1987",
    "iso_8859-3",
    "iso_8859-3:1988",
    "iso_8859-4",
    "iso_8859-4:1988",
    "iso_8859-5",
    "iso_8859-5:1988",
    "iso_8859-6",
    "iso_8859-6:1987",
    "iso_8859-7",
    "iso_8859-7:1987",
    "iso_8859-8",
    "iso_8859-8:1988",
    "iso_8859-9",
    "iso_8859-9:1989",
    "koi",
    "koi8",
    "koi8-r",
    "koi8-ru",
    "koi8-u",
    "koi8_r",
    "korean",
    "ks_c_5601-1987",
    "ks_c_5601-1989",
    "ksc5601",
    "ksc_5601",
    "l1",
    "l2",
    "l3",
    "l4",
    "l5",
    "l6",
    "l9",
    "latin1",
    "latin10",
    "latin2",
    "latin3",
    "latin4",
    "latin5",
    "latin6",
    "logical",
    "mac",
    "macintosh",
    "ms932",
    "ms_kanji",
    "replacement",
    "shift-jis",
    "shift_jis",
    "sjis",
    "sun_eu_greek",
    "tis-620",
    "tis620",
    "ucs-2",
    "unicode",
    "unicode-1-1-utf-8",
    "unicode11utf8",
    "unicode20utf8",
    "unicodefeff",
    "unicodefffe",
    "us-ascii",
    "utf-16",
    "utf-16be",
    "utf-16le",
    "utf-8",
    "utf7",
    "utf8",
    "visual",
    "windows-1250",
    "windows-1251",
    "windows-1252",
    "windows-1253",
    "windows-1254",
    "windows-1255",
    "windows-1256",
    "windows-1257",
    "windows-1258",
    "windows-31j",
    "windows-874",
    "windows-936",
    "windows-949",
    "x-cp1250",
    "x-cp1251",
    "x-cp1252",
    "x-cp1253",
    "x-cp1254",
    "x-cp1255",
    "x-cp1256",
    "x-cp1257",
    "x-cp1258",
    "x-euc-jp",
    "x-gbk",
    "x-mac-cyrillic",
    "x-mac-roman",
    "x-mac-ukrainian",
    "x-sjis",
    "x-unicode20utf8",
    "x-unknown",
    "x-user-defined",
    "x-x-big5",
];
pub fn cases(mut emit: impl FnMut(&str, &[u8])) {
    for label in LABELS {
        emit(label, b"");
        for byte in 0..=255 {
            emit(label, &[byte]);
        }
    }
    for label in [
        "gbk",
        "gb18030",
        "big5",
        "shift_jis",
        "euc-jp",
        "euc-kr",
        "iso-2022-jp",
        "utf-8",
    ] {
        for x in 0..=u16::MAX {
            emit(label, &x.to_be_bytes());
        }
    }
    for a in 0x81..=0xfe {
        for b in b'0'..=b'9' {
            for c in 0x81..=0xfe {
                for d in b'0'..=b'9' {
                    emit("gb18030", &[a, b, c, d]);
                }
            }
        }
    }
    for x in 0..=u16::MAX {
        let [a, b] = x.to_be_bytes();
        emit("euc-jp", &[0x8f, a, b]);
    }
    for esc in [b"\x1b(B", b"\x1b(J", b"\x1b(I", b"\x1b$B", b"\x1b$@"] {
        for x in 0..=u16::MAX {
            let mut bytes = esc.to_vec();
            bytes.extend_from_slice(&x.to_be_bytes());
            emit("iso-2022-jp", &bytes);
        }
    }
    for label in CANONICAL {
        for bom in [b"\xef\xbb\xbf".as_slice(), b"\xff\xfe", b"\xfe\xff"] {
            if *label == "windows-1252" {
                for x in 0..=u16::MAX {
                    let mut bytes = bom.to_vec();
                    bytes.extend_from_slice(&x.to_be_bytes());
                    emit(label, &bytes);
                }
            }
            for suffix in [
                b"".as_slice(),
                b"a",
                b"\x00\xd8a",
                b"\xd8\x00a",
                b"\x00\xdc\x00",
                b"\x00\xd8\x00\xd8a",
            ] {
                let mut bytes = bom.to_vec();
                bytes.extend_from_slice(suffix);
                emit(label, &bytes);
            }
        }
    }
    let mut seed = 0x12ab34cd56ef78u64;
    for label in CANONICAL {
        for _ in 0..3000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (seed % 32) as usize;
            let mut bytes = Vec::new();
            for _ in 0..len {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                bytes.push((seed >> 32) as u8);
            }
            emit(label, &bytes);
        }
    }
    // State transitions, consecutive designations, interrupted/truncated sequences.
    let escapes = [
        b"\x1b(B".as_slice(),
        b"\x1b(J",
        b"\x1b(I",
        b"\x1b$B",
        b"\x1b$@",
        b"\x1b",
        b"\x1b(",
        b"\x1b$",
        b"\x1b(X",
    ];
    for a in escapes {
        for b in escapes {
            for tail in [
                b"".as_slice(),
                b"A",
                b"\x21\x21",
                b"\x5c\x7e",
                b"\x0e\xff",
                b"\x1b\x28\x42",
            ] {
                let mut bytes = a.to_vec();
                bytes.extend_from_slice(b);
                bytes.extend_from_slice(tail);
                emit("iso-2022-jp", &bytes);
            }
        }
    }
}
