//! Unicode's official conformance inputs, pinned verbatim with their license.
use workglen_idna::{Options, normalize_nfc, to_ascii, to_unicode};
fn unescape(input: &str) -> Option<String> {
    if input == "\"\"" {
        return Some(String::new());
    }
    let mut out = String::new();
    let mut c = input.chars();
    while let Some(ch) = c.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let kind = c.next()?;
        let hex = match kind {
            'u' => c.by_ref().take(4).collect::<String>(),
            'x' => {
                if c.next()? != '{' {
                    return None;
                }
                let mut s = String::new();
                loop {
                    let h = c.next()?;
                    if h == '}' {
                        break;
                    }
                    s.push(h);
                }
                s
            }
            _ => return None,
        };
        out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
    }
    Some(out)
}
fn bad(status: &str, unicode: bool) -> bool {
    status
        .trim_matches(['[', ']'])
        .split(',')
        .map(str::trim)
        .any(|s| !s.is_empty() && s != "X4_2" && !(unicode && matches!(s, "A4_1" | "A4_2")))
}
#[test]
fn unicode_18_idna_conformance() {
    let mut total = 0;
    let mut skipped = 0;
    let mut failures = Vec::new();
    for (line_number, line) in include_str!("../data/IdnaTestV2.txt").lines().enumerate() {
        let raw = line.split('#').next().unwrap().trim();
        if raw.is_empty() {
            continue;
        }
        let f: Vec<_> = raw.split(';').map(str::trim).collect();
        assert!(f.len() >= 7);
        let Some(source) = unescape(f[0]) else {
            skipped += 1;
            continue;
        };
        let unicode = if f[1].is_empty() {
            Some(source.clone())
        } else {
            unescape(f[1])
        };
        let ascii = if f[3].is_empty() {
            unicode.clone()
        } else {
            unescape(f[3])
        };
        let transitional = if f[5].is_empty() {
            ascii.clone()
        } else {
            unescape(f[5])
        };
        let ast = if f[4].is_empty() { f[2] } else { f[4] };
        let tst = if f[6].is_empty() { ast } else { f[6] };
        for (kind, expected, status) in
            [(0, unicode, f[2]), (1, ascii, ast), (2, transitional, tst)]
        {
            let options = Options {
                use_std3_ascii_rules: true,
                check_hyphens: true,
                verify_dns_length: true,
                allow_trailing_dot: false,
                transitional: kind == 2,
                ..Options::default()
            };
            let result = if kind == 0 {
                to_unicode(&source, options)
            } else {
                to_ascii(&source, options)
            };
            total += 1;
            if result.is_err() != bad(status, kind == 0)
                || result.as_ref().is_ok_and(|s| Some(s) != expected.as_ref())
            {
                failures.push(format!(
                    "line {} kind {kind}: {:?}; want {:?}, status {status}; got {result:?}",
                    line_number + 1,
                    source,
                    expected
                ));
            }
        }
    }
    println!(
        "{total} official IDNA checks; {skipped} ill-formed UTF-16 source rows cannot be represented by Rust str"
    );
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.into_iter().take(20).collect::<Vec<_>>().join("\n")
    );
}
fn codepoints(s: &str) -> String {
    s.split_whitespace()
        .map(|v| char::from_u32(u32::from_str_radix(v, 16).unwrap()).unwrap())
        .collect()
}
#[test]
fn unicode_18_nfc_conformance() {
    let mut count = 0;
    for line in include_str!("../data/NormalizationTest.txt").lines() {
        let raw = line.split('#').next().unwrap().trim();
        if raw.is_empty() || raw.starts_with('@') {
            continue;
        }
        let f: Vec<_> = raw.split(';').take(5).map(codepoints).collect();
        assert_eq!(f.len(), 5);
        for i in 0..5 {
            let expected = if i < 3 { &f[1] } else { &f[3] };
            assert_eq!(
                &normalize_nfc(&f[i]).unwrap(),
                expected,
                "row {count}, column {i}"
            );
        }
        count += 1;
    }
    println!("{count} normalization rows, {} NFC assertions", count * 5);
}
#[test]
fn policies_context_and_limits() {
    assert_eq!(
        workglen_idna::domain_to_ascii("BÜCHER。Example").unwrap(),
        "xn--bcher-kva.example"
    );
    assert_eq!(
        workglen_idna::domain_to_ascii("faß.de").unwrap(),
        "xn--fa-hia.de"
    );
    assert!(workglen_idna::domain_to_ascii("x\u{200d}.test").is_err());
    assert!(workglen_idna::domain_to_ascii("0.א").is_err());
    assert!(workglen_idna::domain_to_ascii("_smtp.-x").is_ok());
    assert!(workglen_idna::domain_to_ascii_strict("_smtp.-x").is_err());
    assert!(workglen_idna::domain_to_ascii("xn--abc-").is_err());
    assert!(workglen_idna::domain_to_ascii(&"ü".repeat(1001)).is_err());
    assert!(workglen_idna::domain_to_ascii(&"a".repeat(65537)).is_err());
    let long = format!("a{}", "\u{0315}\u{0300}".repeat(20000));
    assert_eq!(normalize_nfc(&long).unwrap().chars().count(), 40000);
}
