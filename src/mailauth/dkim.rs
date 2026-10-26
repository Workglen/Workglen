//! RFC 6376 canonicalization, signing and verification, with RFC 8463 Ed25519.
use crate::{
    encoding::STANDARD,
    error::{Result, ensure},
};
use pratique::crypto::sha2::{Hash, Sha256};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Canonicalization {
    Simple,
    Relaxed,
}
#[derive(Clone, Debug)]
pub struct Header<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
    pub raw: &'a [u8],
}
pub fn headers(raw: &[u8]) -> Result<(Vec<Header<'_>>, &[u8])> {
    let end = raw
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or_else(|| crate::error!("missing header separator"))?;
    ensure!(end <= 65536, "header budget exceeded");
    let mut headers = Vec::new();
    let mut start = 0;
    let mut cursor = 0;
    while cursor < end + 2 {
        let next = raw[cursor..end + 2]
            .windows(2)
            .position(|b| b == b"\r\n")
            .map(|n| cursor + n + 2)
            .ok_or_else(|| crate::error!("invalid header line"))?;
        if next < end + 2 && matches!(raw[next], b' ' | b'\t') {
            cursor = next;
            continue;
        }
        let field = &raw[start..next];
        let colon = field
            .iter()
            .position(|b| *b == b':')
            .ok_or_else(|| crate::error!("invalid header"))?;
        ensure!(
            colon > 0
                && field[..colon]
                    .iter()
                    .all(|b| (33..=126).contains(b) && *b != b':'),
            "invalid header name"
        );
        headers.push(Header {
            name: &field[..colon],
            value: &field[colon + 1..],
            raw: field,
        });
        ensure!(headers.len() <= 256, "too many headers");
        start = next;
        cursor = next;
    }
    Ok((headers, &raw[end + 4..]))
}
pub fn canonical_header(header: &Header<'_>, kind: Canonicalization) -> Vec<u8> {
    if kind == Canonicalization::Simple {
        return header.raw.to_vec();
    }
    let mut out = header.name.to_ascii_lowercase();
    out.push(b':');
    let mut whitespace = false;
    let mut begun = false;
    for &b in header.value {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            whitespace = begun;
            continue;
        }
        if whitespace {
            out.push(b' ');
        }
        out.push(b);
        begun = true;
        whitespace = false;
    }
    out.extend_from_slice(b"\r\n");
    out
}
/// Stream the canonical form, holding only a count of pending empty lines.
pub fn write_canonical_body(body: &[u8], kind: Canonicalization, mut write: impl FnMut(&[u8])) {
    let mut rest = body;
    let mut empty = 0usize;
    let mut nonempty = false;
    while !rest.is_empty() {
        let (line, tail) = rest
            .windows(2)
            .position(|b| b == b"\r\n")
            .map_or((rest, &[][..]), |i| (&rest[..i], &rest[i + 2..]));
        let line = if kind == Canonicalization::Relaxed {
            &line[..line
                .iter()
                .rposition(|b| !matches!(b, b' ' | b'\t'))
                .map_or(0, |i| i + 1)]
        } else {
            line
        };
        if line.is_empty() {
            empty += 1;
        } else {
            for _ in 0..empty {
                write(b"\r\n");
            }
            empty = 0;
            nonempty = true;
            if kind == Canonicalization::Simple {
                write(line);
            } else {
                let mut at = 0;
                while at < line.len() {
                    if matches!(line[at], b' ' | b'\t') {
                        while at < line.len() && matches!(line[at], b' ' | b'\t') {
                            at += 1;
                        }
                        write(b" ");
                    } else {
                        let start = at;
                        while at < line.len() && !matches!(line[at], b' ' | b'\t') {
                            at += 1;
                        }
                        write(&line[start..at]);
                    }
                }
            }
            write(b"\r\n");
        }
        rest = tail;
    }
    if !nonempty && kind == Canonicalization::Simple {
        write(b"\r\n");
    }
}
pub fn canonical_body(body: &[u8], kind: Canonicalization) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical_body(body, kind, |bytes| out.extend_from_slice(bytes));
    out
}
pub(super) fn signed_headers(
    headers: &[Header<'_>],
    names: &[&str],
    kind: Canonicalization,
) -> Vec<u8> {
    let mut used = HashSet::new();
    let mut out = Vec::new();
    for name in names {
        if let Some((i, h)) = headers
            .iter()
            .enumerate()
            .rev()
            .find(|(i, h)| !used.contains(i) && h.name.eq_ignore_ascii_case(name.as_bytes()))
        {
            used.insert(i);
            out.extend(canonical_header(h, kind));
        }
    }
    out
}
/// Sign every occurrence of the selected headers and one extra absent occurrence.
pub fn sign(
    raw: &[u8],
    domain: &str,
    selector: &str,
    key: &pratique::sign::SigningKey,
) -> Result<Vec<u8>> {
    let domain = workglen_dns::Name::parse(domain)?
        .as_str()
        .trim_end_matches('.')
        .to_owned();
    let selector = workglen_dns::Name::parse(selector)?
        .as_str()
        .trim_end_matches('.')
        .to_owned();
    let pratique::x509::PublicKey::Rsa(rsa) = pratique::x509::parse_spki(&key.public_key_spki())?
    else {
        crate::bail!("DKIM signing requires RSA");
    };
    ensure!(
        (2048..=4096).contains(&rsa.bits()),
        "DKIM signing requires RSA 2048..4096 bits"
    );
    let (all, body) = headers(raw)?;
    let canon = Canonicalization::Relaxed;
    let protected = [
        "From",
        "To",
        "Cc",
        "Subject",
        "Date",
        "Message-ID",
        "Reply-To",
        "Sender",
        "MIME-Version",
        "Content-Type",
        "Content-Transfer-Encoding",
        "Content-Disposition",
        "In-Reply-To",
        "References",
    ];
    let mut names = Vec::new();
    for name in protected {
        let count = all
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name.as_bytes()))
            .count();
        names.extend(std::iter::repeat_n(name, count + 1));
    }
    let mut hasher = Sha256::new();
    write_canonical_body(body, canon, |bytes| hasher.update(bytes));
    let hash = STANDARD.encode(hasher.finalize());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut hnames = String::new();
    let mut column = 3;
    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            hnames.push(':');
            column += 1;
        }
        if column + name.len() > 72 {
            hnames.push_str("\r\n\t");
            column = 1;
        }
        hnames.push_str(name);
        column += name.len();
    }
    let field = format!(
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n\td={domain}; s={selector}; t={now};\r\n\th={};\r\n\tbh={hash}; b=",
        hnames
    );
    let mut input = signed_headers(&all, &names, canon);
    let colon = field.find(':').unwrap();
    let mut canonical = canonical_header(
        &Header {
            name: &field.as_bytes()[..colon],
            value: &field.as_bytes()[colon + 1..],
            raw: field.as_bytes(),
        },
        canon,
    );
    canonical.truncate(canonical.len() - 2);
    input.extend(canonical);
    let encoded = STANDARD.encode(key.sign_x509(&input)?);
    let mut out = field.into_bytes();
    for (i, chunk) in encoded.as_bytes().chunks(64).enumerate() {
        if i > 0 {
            out.extend_from_slice(b"\r\n\t");
        }
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(raw);
    Ok(out)
}

pub use super::verify_dkim::{Algorithm, Outcome, Status, verify, verify_bytes};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6376_body_vectors_and_empty_line_rules() {
        // RFC 6376 sections 3.4.3-3.4.5: explicit independent expected bytes.
        for (body, simple, relaxed) in [
            ("", "\r\n", ""),
            ("\r\n\r\n", "\r\n", ""),
            (" \t\r\n\r\n", " \t\r\n", ""),
            (
                " C \r\nD \t E\r\n\r\n\r\n",
                " C \r\nD \t E\r\n",
                " C\r\nD E\r\n",
            ),
            ("Message\r\n \t\r\n", "Message\r\n \t\r\n", "Message\r\n"),
            (
                "\r\n \t\r\nMessage",
                "\r\n \t\r\nMessage\r\n",
                "\r\n\r\nMessage\r\n",
            ),
        ] {
            assert_eq!(
                canonical_body(body.as_bytes(), Canonicalization::Simple),
                simple.as_bytes()
            );
            assert_eq!(
                canonical_body(body.as_bytes(), Canonicalization::Relaxed),
                relaxed.as_bytes()
            );
        }
        for (kind, expected) in [
            (
                Canonicalization::Simple,
                "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=",
            ),
            (
                Canonicalization::Relaxed,
                "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            ),
        ] {
            let mut hash = Sha256::new();
            write_canonical_body(b"", kind, |b| hash.update(b));
            assert_eq!(STANDARD.encode(hash.finalize()), expected);
        }
    }

    #[test]
    fn rfc6376_header_folding_and_case() {
        let raw = b"SUBJect: \tHello\r\n\t world \t\r\n\r\n";
        let (parsed, _) = headers(raw).unwrap();
        assert_eq!(
            canonical_header(&parsed[0], Canonicalization::Relaxed),
            b"subject:Hello world\r\n"
        );
        assert_eq!(
            canonical_header(&parsed[0], Canonicalization::Simple),
            &raw[..raw.len() - 2]
        );
    }
}
