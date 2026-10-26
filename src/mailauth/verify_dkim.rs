//! Bounded RFC 6376 / RFC 8463 verification using Pratique cryptography.
use super::dkim::{
    Canonicalization, Header, canonical_header, headers, signed_headers, write_canonical_body,
};
use crate::{
    encoding::STANDARD,
    error::{Result, bail, ensure},
};
use pratique::crypto::{
    ed25519, legacy,
    rsa::RsaPublicKey,
    sha2::{Hash, HashAlg, Sha256},
};
use std::collections::HashMap;
pub(crate) fn tags(bytes: &[u8]) -> Result<HashMap<String, String>> {
    let text = std::str::from_utf8(bytes)?;
    let mut out = HashMap::new();
    for part in text.split(';') {
        let part = part.trim_matches([' ', '\t', '\r', '\n']);
        if part.is_empty() {
            continue;
        }
        let (name, value) = part
            .split_once('=')
            .ok_or_else(|| crate::error!("invalid DKIM tag"))?;
        let name = name.trim_end_matches([' ', '\t']);
        ensure!(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid DKIM tag name"
        );
        let value = value
            .chars()
            .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
            .collect();
        ensure!(
            out.insert(name.to_owned(), value).is_none(),
            "duplicate DKIM tag"
        );
    }
    Ok(out)
}
pub(crate) fn required<'a>(tags: &'a HashMap<String, String>, name: &str) -> Result<&'a str> {
    tags.get(name)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| crate::error!("missing DKIM {name}"))
}
pub(crate) fn base64(value: &str) -> Result<Vec<u8>> {
    let mut s = value.to_owned();
    if !s.contains('=') {
        while !s.len().is_multiple_of(4) {
            s.push('=');
        }
    }
    STANDARD.decode(s).map_err(Into::into)
}
#[cfg(test)]
mod decoder_differential_tests {
    use super::*;
    #[test]
    fn dkim_and_mime_decode_identical_bytes_for_their_shared_language() {
        for len in 0..=256 {
            let bytes: Vec<_> = (0..len).map(|i| i as u8).collect();
            let encoded = STANDARD.encode(&bytes);
            for text in [encoded.as_str(), encoded.trim_end_matches('=')] {
                let raw = format!("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n{text}\r\n");
                let message = workglen_mime::MessageParser::default().parse(raw.as_bytes()).unwrap();
                assert_eq!(message.parts[0].contents(), base64(text).unwrap());
                assert!(!message.parts[0].is_encoding_problem);
            }
        }
        for text in ["YR==", "YWJj$", "Y=WJj", "YWJj====", "Y"] {
            assert!(base64(text).is_err());
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha256,
    RsaSha1,
    Ed25519Sha256,
}
impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::RsaSha1 => "rsa-sha1",
            Self::Ed25519Sha256 => "ed25519-sha256",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "rsa-sha256" => Ok(Self::RsaSha256),
            "rsa-sha1" => Ok(Self::RsaSha1),
            "ed25519-sha256" => Ok(Self::Ed25519Sha256),
            _ => bail!("unsupported DKIM algorithm"),
        }
    }
}
pub fn verify_bytes(
    record: &str,
    algorithm: Algorithm,
    input: &[u8],
    signature: &[u8],
) -> Result<()> {
    let key = tags(record.as_bytes())?;
    ensure!(
        key.get("v").is_none_or(|v| v == "DKIM1"),
        "invalid DKIM key version"
    );
    let public = base64(required(&key, "p")?)?;
    ensure!(!public.is_empty(), "revoked DKIM key");
    if let Some(h) = key.get("h") {
        let hash = if algorithm == Algorithm::RsaSha1 {
            "sha1"
        } else {
            "sha256"
        };
        ensure!(h.split(':').any(|h| h == hash), "key hash restriction");
    }
    if let Some(s) = key.get("s") {
        ensure!(
            s.split(':').any(|s| matches!(s, "*" | "email")),
            "key service restriction"
        );
    }
    let valid = match (key.get("k").map(String::as_str).unwrap_or("rsa"), algorithm) {
        ("rsa", Algorithm::RsaSha256 | Algorithm::RsaSha1) => {
            ensure!(public.len() <= 2048, "oversized RSA key");
            let rsa = match pratique::x509::parse_spki(&public) {
                Ok(pratique::x509::PublicKey::Rsa(k)) => k,
                Ok(_) => bail!("wrong DKIM key type"),
                Err(_) => RsaPublicKey::from_pkcs1_der(&public)?,
            };
            ensure!(
                (1024..=8192).contains(&rsa.bits()),
                "RSA public key must be 1024..8192 bits"
            );
            ensure!(rsa.exponent() < 1u64 << 33, "oversized RSA exponent");
            if algorithm == Algorithm::RsaSha1 {
                legacy::verify_rsa_sha1(&rsa, input, signature)
            } else {
                rsa.verify_pkcs1(HashAlg::Sha256, input, signature)
            }
        }
        ("ed25519", Algorithm::Ed25519Sha256) => {
            ensure!(
                public.len() == 32 && ed25519::public_key_is_valid(&public),
                "invalid Ed25519 key"
            );
            ed25519::verify_strict(&public, &Sha256::digest(input), signature)
        }
        _ => bail!("DKIM key and algorithm mismatch"),
    };
    ensure!(valid, "DKIM signature mismatch");
    Ok(())
}
pub(crate) fn empty_signature(field: &[u8]) -> Result<Vec<u8>> {
    let colon = field
        .iter()
        .position(|b| *b == b':')
        .ok_or_else(|| crate::error!("invalid signature field"))?;
    let mut out = field[..colon + 1].to_vec();
    let mut found = false;
    for (i, part) in field[colon + 1..].split(|b| *b == b';').enumerate() {
        if i > 0 {
            out.push(b';');
        }
        let equal = part.iter().position(|b| *b == b'=');
        if let Some(equal) = equal
            && part[..equal].trim_ascii() == b"b"
        {
            ensure!(!found, "duplicate signature value");
            found = true;
            out.extend_from_slice(&part[..equal + 1]);
            // RFC 6376 removes the b= value and its surrounding folding space.
        } else {
            out.extend_from_slice(part);
        }
    }
    ensure!(found, "missing signature value");
    Ok(out)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Temporary,
}
#[derive(Clone, Debug)]
pub struct Outcome {
    pub domain: String,
    pub status: Status,
    pub detail: String,
}
struct Signature {
    domain: String,
    selector: String,
    algorithm: Algorithm,
    header: Canonicalization,
    body: Canonicalization,
    names: Vec<String>,
    hash: Vec<u8>,
    signature: Vec<u8>,
    length: Option<usize>,
    identity: String,
    strict_identity: bool,
    atps: Option<(String, String)>,
}
fn signature(field: &Header<'_>, now: u64, arc: bool) -> Result<Signature> {
    let t = tags(field.value)?;
    if !arc {
        ensure!(required(&t, "v")? == "1", "invalid signature version");
    }
    let algorithm = Algorithm::parse(required(&t, "a")?)?;
    let domain = workglen_dns::Name::parse(required(&t, "d")?)?
        .as_str()
        .trim_end_matches('.')
        .to_owned();
    let selector = workglen_dns::Name::parse(required(&t, "s")?)?
        .as_str()
        .trim_end_matches('.')
        .to_owned();
    let (hc, bc) = t
        .get("c")
        .map(String::as_str)
        .unwrap_or(if arc {
            "relaxed/relaxed"
        } else {
            "simple/simple"
        })
        .split_once('/')
        .unwrap_or((t.get("c").map(String::as_str).unwrap_or("simple"), "simple"));
    let canon = |s| match s {
        "simple" => Ok(Canonicalization::Simple),
        "relaxed" => Ok(Canonicalization::Relaxed),
        _ => Err(crate::error!("unknown canonicalization")),
    };
    let names: Vec<_> = required(&t, "h")?.split(':').map(str::to_owned).collect();
    ensure!(
        names.len() <= 512 && names.iter().any(|n| n.eq_ignore_ascii_case("from")),
        "DKIM must sign From"
    );
    if let Some(q) = t.get("q") {
        ensure!(
            q.split(':').any(|q| q == "dns/txt"),
            "unsupported query method"
        );
    }
    let timestamp = t
        .get("t")
        .map(|s| s.parse::<u64>())
        .transpose()?
        .unwrap_or(0);
    if let Some(x) = t.get("x") {
        let x = x.parse::<u64>()?;
        ensure!(x > now && x > timestamp, "expired signature");
    }
    let decoded_identity = if !arc {
        t.get("i").map(|s| decode_identity(s)).transpose()?
    } else {
        None
    };
    let identity = if let Some(value) = &decoded_identity {
        value
            .rsplit_once('@')
            .map(|(_, d)| d.to_ascii_lowercase())
            .ok_or_else(|| crate::error!("invalid DKIM identity"))?
    } else {
        domain.clone()
    };
    ensure!(
        identity == domain || identity.ends_with(&format!(".{domain}")),
        "DKIM identity outside signing domain"
    );
    Ok(Signature {
        domain,
        selector,
        algorithm,
        header: canon(hc)?,
        body: canon(bc)?,
        names,
        hash: base64(required(&t, "bh")?)?,
        signature: base64(required(&t, "b")?)?,
        length: t.get("l").map(|s| s.parse()).transpose()?,
        identity,
        strict_identity: false,
        atps: t.get("atps").map(|d| {
            (
                d.to_ascii_lowercase(),
                t.get("atpsh").cloned().unwrap_or_else(|| "none".into()),
            )
        }),
    })
}
// RFC 6376 i= uses dkim-quoted-printable, not MIME encoded words.
fn decode_identity(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            ensure!(i + 2 < bytes.len(), "truncated DKIM identity escape");
            let a = (bytes[i + 1] as char)
                .to_digit(16)
                .ok_or_else(|| crate::error!("invalid DKIM identity escape"))?;
            let b = (bytes[i + 2] as char)
                .to_digit(16)
                .ok_or_else(|| crate::error!("invalid DKIM identity escape"))?;
            out.push((a * 16 + b) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}
pub async fn verify(raw: &[u8], resolver: &impl super::Dns, now: u64) -> Result<Vec<Outcome>> {
    verify_named(raw, resolver, now, b"dkim-signature", None).await
}
pub(crate) async fn verify_named(
    raw: &[u8],
    resolver: &impl super::Dns,
    now: u64,
    name: &[u8],
    instance: Option<u32>,
) -> Result<Vec<Outcome>> {
    let (all, body) = headers(raw)?;
    let mut results = Vec::new();
    let fields: Vec<_> = all
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .collect();
    ensure!(
        fields.len() <= if instance.is_some() { 50 } else { 8 },
        "too many signatures"
    );
    for field in fields {
        if let Some(i) = instance
            && tags(field.value)
                .ok()
                .and_then(|t| t.get("i").and_then(|v| v.parse::<u32>().ok()))
                != Some(i)
        {
            continue;
        }
        let parsed = signature(field, now, instance.is_some());
        let mut domain = String::new();
        let mut temporary = false;
        let result = async {
            let mut sig = parsed?;
            domain = sig.domain.clone();
            let mut sha1 = legacy::Sha1::new();
            let mut sha256 = Sha256::new();
            let mut length = 0usize;
            write_canonical_body(body, sig.body, |bytes| {
                let take = sig
                    .length
                    .unwrap_or(usize::MAX)
                    .saturating_sub(length)
                    .min(bytes.len());
                sha1.update(&bytes[..take]);
                sha256.update(&bytes[..take]);
                length = length.saturating_add(bytes.len());
            });
            ensure!(
                sig.length.is_none_or(|n| n <= length),
                "body shorter than signed length"
            );
            let hash = if sig.algorithm == Algorithm::RsaSha1 {
                sha1.finalize().to_vec()
            } else {
                sha256.finalize().to_vec()
            };
            ensure!(hash == sig.hash, "DKIM body hash mismatch");
            let lookup = match resolver
                .lookup(
                    &format!("{}._domainkey.{}", sig.selector, sig.domain),
                    workglen_dns::RecordType::TXT,
                )
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    temporary = !e.is_no_records_found();
                    return Err(e.into());
                }
            };
            let records: Vec<_> = lookup
                .iter()
                .filter_map(|r| {
                    if let workglen_dns::RData::TXT(t) = r {
                        String::from_utf8(t.txt_data.concat()).ok()
                    } else {
                        None
                    }
                })
                .collect();
            ensure!(records.len() == 1, "ambiguous DKIM key records");
            let key = tags(records[0].as_bytes())?;
            sig.strict_identity = key.get("t").is_some_and(|s| s.split(':').any(|v| v == "s"));
            ensure!(
                !sig.strict_identity || sig.identity == sig.domain,
                "DKIM strict identity mismatch"
            );
            let names: Vec<_> = sig.names.iter().map(String::as_str).collect();
            let other: Vec<_> = all
                .iter()
                .filter(|h| !std::ptr::eq(*h, field))
                .cloned()
                .collect();
            let mut input = signed_headers(&other, &names, sig.header);
            let empty = empty_signature(field.raw)?;
            let colon = empty.iter().position(|b| *b == b':').unwrap();
            let empty_field = Header {
                name: &empty[..colon],
                value: &empty[colon + 1..],
                raw: &empty,
            };
            let mut canonical = canonical_header(&empty_field, sig.header);
            if canonical.ends_with(b"\r\n") {
                canonical.truncate(canonical.len() - 2);
            }
            input.extend(canonical);
            verify_bytes(&records[0], sig.algorithm, &input, &sig.signature)?;
            if let Some((author, algorithm)) = &sig.atps {
                let matched = super::from_addresses(raw)?.iter().any(|a| {
                    a.rsplit_once('@')
                        .is_some_and(|(_, d)| d.eq_ignore_ascii_case(author))
                });
                if matched {
                    let label = match algorithm.as_str() {
                        "none" => sig.domain.clone(),
                        "sha256" => base32(&Sha256::digest(sig.domain.as_bytes())),
                        "sha1" => {
                            let mut h = legacy::Sha1::new();
                            h.update(sig.domain.as_bytes());
                            base32(&h.finalize())
                        }
                        _ => return Ok(()), // Unknown experimental ATPS algorithm leaves DKIM intact.
                    };
                    let answers = match resolver
                        .lookup(
                            &format!("{label}._atps.{author}"),
                            workglen_dns::RecordType::TXT,
                        )
                        .await
                    {
                        Ok(a) => a,
                        Err(e) => {
                            temporary = !e.is_no_records_found();
                            return Err(e.into());
                        }
                    };
                    let authorized = answers
                        .iter()
                        .filter_map(|r| {
                            if let workglen_dns::RData::TXT(t) = r {
                                Some(t.txt_data.concat())
                            } else {
                                None
                            }
                        })
                        .filter(|v| tags(v).is_ok_and(|t| t.get("v").is_some_and(|v| v == "ATPS1")))
                        .count();
                    ensure!(authorized == 1, "ATPS authorization missing or ambiguous");
                }
            }
            Ok(())
        }
        .await;
        results.push(Outcome {
            domain,
            status: if result.is_ok() {
                Status::Pass
            } else if temporary {
                Status::Temporary
            } else {
                Status::Fail
            },
            detail: result.err().map(|e| e.to_string()).unwrap_or_default(),
        });
    }
    Ok(results)
}

fn base32(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut bits = 0u32;
    let mut count = 0;
    for &b in bytes {
        bits = (bits << 8) | u32::from(b);
        count += 8;
        while count >= 5 {
            count -= 5;
            out.push(CHARS[((bits >> count) & 31) as usize] as char);
        }
    }
    if count > 0 {
        out.push(CHARS[((bits << (5 - count)) & 31) as usize] as char);
    }
    out
}

pub fn public_key_bits(record: &str) -> Result<usize> {
    let t = tags(record.as_bytes())?;
    let p = base64(required(&t, "p")?)?;
    ensure!(
        t.get("v").is_none_or(|v| v == "DKIM1"),
        "invalid key version"
    );
    match t.get("k").map(String::as_str).unwrap_or("rsa") {
        "rsa" => {
            ensure!(p.len() <= 2048, "oversized key");
            let k = match pratique::x509::parse_spki(&p) {
                Ok(pratique::x509::PublicKey::Rsa(k)) => k,
                Ok(_) => bail!("wrong key type"),
                Err(_) => RsaPublicKey::from_pkcs1_der(&p)?,
            };
            ensure!(
                (1024..=8192).contains(&k.bits()) && k.exponent() < 1u64 << 33,
                "invalid RSA key size or exponent"
            );
            Ok(k.bits())
        }
        "ed25519" => {
            ensure!(
                p.len() == 32 && ed25519::public_key_is_valid(&p),
                "invalid Ed25519 key"
            );
            Ok(256)
        }
        _ => bail!("unsupported key type"),
    }
}
