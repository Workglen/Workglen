//! RFC 8617 ARC sets. Verifies the newest message signature and every seal;
//! old message signatures are bound by seals, since forwarding may change content.
use super::{
    Dns,
    crypto::SigningKey,
    dkim::{self, Canonicalization, Header},
    verify_dkim::{self, Algorithm, base64, empty_signature, required, tags},
};
use crate::{
    encoding::STANDARD,
    error::{Result, ensure},
};
use pratique::crypto::sha2::{Hash, Sha256};
use std::collections::BTreeMap;
use workglen_dns::{RData, RecordType};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    None,
    Pass,
    Fail,
    Temporary,
}
#[derive(Clone, Debug)]
pub struct Outcome {
    pub status: Status,
    pub instances: u32,
    pub detail: String,
}
struct Set<'a> {
    aar: Header<'a>,
    ams: Header<'a>,
    seal: Header<'a>,
}
fn instance(h: &Header<'_>) -> Result<u32> {
    let first = if h.name.eq_ignore_ascii_case(b"arc-authentication-results") {
        h.value.split(|b| *b == b';').next().unwrap_or_default()
    } else {
        h.value
    };
    let t = tags(first)?;
    let i = required(&t, "i")?.parse()?;
    ensure!((1..=50).contains(&i), "ARC instance limit");
    Ok(i)
}
fn sets(raw: &[u8]) -> Result<BTreeMap<u32, Set<'_>>> {
    let (h, _) = dkim::headers(raw)?;
    let mut groups: BTreeMap<u32, [Option<Header<'_>>; 3]> = BTreeMap::new();
    for field in h {
        let slot = if field
            .name
            .eq_ignore_ascii_case(b"arc-authentication-results")
        {
            0
        } else if field.name.eq_ignore_ascii_case(b"arc-message-signature") {
            1
        } else if field.name.eq_ignore_ascii_case(b"arc-seal") {
            2
        } else {
            continue;
        };
        let i = instance(&field)?;
        ensure!(
            groups.entry(i).or_insert([None, None, None])[slot]
                .replace(field)
                .is_none(),
            "duplicate ARC header"
        );
    }
    let mut out = BTreeMap::new();
    for (n, (i, fields)) in groups.into_iter().enumerate() {
        ensure!(i == n as u32 + 1, "ARC sequence gap");
        let [aar, ams, seal] = fields;
        fn required(v: Option<Header<'_>>) -> Result<Header<'_>> {
            v.ok_or_else(|| crate::error!("incomplete ARC set"))
        }
        out.insert(
            i,
            Set {
                aar: required(aar)?,
                ams: required(ams)?,
                seal: required(seal)?,
            },
        );
    }
    Ok(out)
}
fn canonical(h: &Header<'_>, empty: bool) -> Result<Vec<u8>> {
    if !empty {
        return Ok(dkim::canonical_header(h, Canonicalization::Relaxed));
    }
    let raw = empty_signature(h.raw)?;
    let colon = raw.iter().position(|b| *b == b':').unwrap();
    let mut v = dkim::canonical_header(
        &Header {
            name: &raw[..colon],
            value: &raw[colon + 1..],
            raw: &raw,
        },
        Canonicalization::Relaxed,
    );
    v.truncate(v.len() - 2);
    Ok(v)
}
pub async fn verify(raw: &[u8], dns: &impl Dns, now: u64) -> Outcome {
    let mut temporary = false;
    let mut instances = 0;
    let result = async {
        let sets = sets(raw)?;
        instances = sets.len() as u32;
        if sets.is_empty() {
            return Ok(Status::None);
        }
        for (&i, set) in &sets {
            let t = tags(set.seal.value)?;
            ensure!(
                required(&t, "cv")? == if i == 1 { "none" } else { "pass" },
                "ARC validation state is not passing"
            );
            ensure!(!t.contains_key("h"), "ARC seals cannot select headers");
        }
        let ams =
            verify_dkim::verify_named(raw, dns, now, b"arc-message-signature", Some(instances))
                .await?;
        ensure!(ams.len() == 1, "missing newest ARC message signature");
        if ams[0].status == dkim::Status::Temporary {
            temporary = true;
        }
        ensure!(
            ams[0].status == dkim::Status::Pass,
            "ARC message signature: {}",
            ams[0].detail
        );
        for (&i, set) in &sets {
            let t = tags(set.seal.value)?;
            let alg = Algorithm::parse(required(&t, "a")?)?;
            let d = workglen_dns::Name::parse(required(&t, "d")?)?;
            let s = workglen_dns::Name::parse(required(&t, "s")?)?;
            let mut input = Vec::new();
            for (&j, item) in sets.range(..=i) {
                input.extend(canonical(&item.aar, false)?);
                input.extend(canonical(&item.ams, false)?);
                input.extend(canonical(&item.seal, j == i)?);
            }
            let records = match dns
                .lookup(
                    &format!(
                        "{}._domainkey.{}",
                        s.as_str().trim_end_matches('.'),
                        d.as_str()
                    ),
                    RecordType::TXT,
                )
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    temporary = !e.is_no_records_found();
                    return Err(e.into());
                }
            };
            let records: Vec<_> = records
                .into_iter()
                .filter_map(|r| {
                    if let RData::TXT(t) = r {
                        String::from_utf8(t.txt_data.concat()).ok()
                    } else {
                        None
                    }
                })
                .collect();
            ensure!(records.len() == 1, "missing or ambiguous ARC key");
            verify_dkim::verify_bytes(&records[0], alg, &input, &base64(required(&t, "b")?)?)?;
        }
        Ok::<_, crate::error::Error>(Status::Pass)
    }
    .await;
    match result {
        Ok(status) => Outcome {
            status,
            instances,
            detail: String::new(),
        },
        Err(e) => Outcome {
            status: if temporary {
                Status::Temporary
            } else {
                Status::Fail
            },
            instances,
            detail: e.to_string(),
        },
    }
}
/// Returns the three new ARC header fields, to be prepended to the message.
/// `auth_results` is the locally computed Authentication-Results value.
pub async fn seal(
    raw: &[u8],
    dns: &impl Dns,
    domain: &str,
    selector: &str,
    key: &SigningKey,
    auth_results: &str,
    now: u64,
) -> Result<String> {
    let domain = workglen_dns::Name::parse(domain)?
        .as_str()
        .trim_end_matches('.')
        .to_owned();
    let selector = workglen_dns::Name::parse(selector)?
        .as_str()
        .trim_end_matches('.')
        .to_owned();
    ensure!(
        !auth_results.is_empty()
            && auth_results.is_ascii()
            && !auth_results.bytes().any(|b| b.is_ascii_control()),
        "invalid local Authentication-Results"
    );
    let prior = sets(raw)?;
    let result = verify(raw, dns, now).await;
    ensure!(
        result.status != Status::Temporary,
        "ARC DNS temporarily unavailable"
    );
    ensure!(prior.len() < 50, "ARC chain limit");
    if let Some((_, s)) = prior.last_key_value() {
        ensure!(
            required(&tags(s.seal.value)?, "cv")? != "fail",
            "cannot extend failed ARC chain"
        );
    }
    let i = prior.len() as u32 + 1;
    let cv = if i == 1 {
        "none"
    } else if result.status == Status::Pass {
        "pass"
    } else {
        "fail"
    };
    let aar = format!("ARC-Authentication-Results: i={i}; {auth_results}\r\n");
    let (h, body) = dkim::headers(raw)?;
    let mut names = Vec::new();
    for name in [
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
    ] {
        let count = h
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name.as_bytes()))
            .count();
        names.extend(std::iter::repeat_n(name, count + 1));
    }
    let mut hash = Sha256::new();
    dkim::write_canonical_body(body, Canonicalization::Relaxed, |b| hash.update(b));
    let value = format!(
        "i={i}; a={}; c=relaxed/relaxed; d={domain}; s={selector}; t={now}; h={}; bh={}; b=",
        key.algorithm().name(),
        names.join(":"),
        STANDARD.encode(hash.finalize())
    );
    let field = format!("ARC-Message-Signature: {value}");
    let colon = field.find(':').unwrap();
    let last = Header {
        name: &field.as_bytes()[..colon],
        value: &field.as_bytes()[colon + 1..],
        raw: field.as_bytes(),
    };
    let mut input = dkim::signed_headers(&h, &names, Canonicalization::Relaxed);
    input.extend(canonical(&last, true)?);
    let ams = fold_words(
        "ARC-Message-Signature",
        &format!("{value}{}", STANDARD.encode(key.sign(&input)?)),
    );
    let value = format!(
        "i={i}; a={}; d={domain}; s={selector}; t={now}; cv={cv}; b=",
        key.algorithm().name()
    );
    let field = format!("ARC-Seal: {value}");
    let colon = field.find(':').unwrap();
    let current = Header {
        name: &field.as_bytes()[..colon],
        value: &field.as_bytes()[colon + 1..],
        raw: field.as_bytes(),
    };
    let mut input = Vec::new();
    if cv != "fail" {
        for set in prior.values() {
            input.extend(canonical(&set.aar, false)?);
            input.extend(canonical(&set.ams, false)?);
            input.extend(canonical(&set.seal, false)?);
        }
    }
    for field in [&aar, &ams] {
        let colon = field.find(':').unwrap();
        input.extend(canonical(
            &Header {
                name: &field.as_bytes()[..colon],
                value: &field.as_bytes()[colon + 1..],
                raw: field.as_bytes(),
            },
            false,
        )?);
    }
    input.extend(canonical(&current, true)?);
    let seal = fold_words(
        "ARC-Seal",
        &format!("{value}{}", STANDARD.encode(key.sign(&input)?)),
    );
    Ok(format!("{seal}{ams}{aar}"))
}
// Folds only at whitespace or within b=, where folding whitespace is removed
// before hashing. Never inserts new whitespace into an h= field-name token.
fn fold_words(name: &str, value: &str) -> String {
    let mut out = format!("{name}:");
    let mut column = name.len() + 1;
    for word in value.split(' ') {
        if column + 1 + word.len() > 76 {
            out.push_str("\r\n\t");
            column = 1;
        } else {
            out.push(' ');
            column += 1;
        }
        if let Some(encoded) = word.strip_prefix("b=") {
            out.push_str("b=");
            column += 2;
            for chunk in encoded.as_bytes().chunks(64) {
                if column + chunk.len() > 76 {
                    out.push_str("\r\n\t");
                    column = 1;
                }
                out.push_str(std::str::from_utf8(chunk).unwrap());
                column += chunk.len();
            }
        } else {
            out.push_str(word);
            column += word.len();
        }
    }
    out.push_str("\r\n");
    out
}
