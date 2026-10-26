//! RFC 9989 DNS-tree-walk policy discovery and identifier alignment.
use super::{Dns, dkim, spf};
use std::collections::HashMap;
use workglen_dns::{Error, RData, RecordType, ResponseCode};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    None,
    Pass,
    Fail,
    Temporary,
    Permanent,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    pub policy: Policy,
}
#[derive(Clone)]
struct Record {
    policy: Option<Policy>,
    sub: Policy,
    nonexistent: Policy,
    strict_dkim: bool,
    strict_spf: bool,
    psd: Option<bool>,
    testing: bool,
    report: bool,
}
fn policy(s: &str) -> Option<Policy> {
    match s {
        "none" => Some(Policy::None),
        "quarantine" => Some(Policy::Quarantine),
        "reject" => Some(Policy::Reject),
        _ => None,
    }
}
fn record(text: &str) -> Result<Option<Record>, Status> {
    let mut tags = HashMap::new();
    let mut parts = text.split(';');
    if !parts
        .next()
        .and_then(|s| s.split_once('='))
        .is_some_and(|(k, v)| k.trim() == "v" && v.trim() == "DMARC1")
    {
        return Ok(None);
    }
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').ok_or(Status::Permanent)?;
        let k = k.trim();
        if tags.insert(k, v.trim()).is_some() {
            return Err(Status::Permanent);
        }
    }
    let mut p = tags.get("p").and_then(|v| policy(v));
    if ["sp", "np"]
        .iter()
        .any(|k| tags.get(k).is_some_and(|v| policy(v).is_none()))
    {
        p = None;
    }
    let sp = tags
        .get("sp")
        .and_then(|v| policy(v))
        .or(p)
        .unwrap_or(Policy::None);
    let np = tags.get("np").and_then(|v| policy(v)).unwrap_or(sp);
    let strict = |k| match tags.get(k) {
        None | Some(&"r") => Ok(false),
        Some(&"s") => Ok(true),
        _ => Err(Status::Permanent),
    };
    let report = tags.get("rua").is_some_and(|s| {
        s.split(',').any(|s| {
            s.trim().strip_prefix("mailto:").is_some_and(|s| {
                let s = s.split('!').next().unwrap_or("");
                s.rsplit_once('@')
                    .is_some_and(|(l, d)| !l.is_empty() && workglen_dns::Name::parse(d).is_ok())
            })
        })
    });
    Ok(Some(Record {
        policy: p,
        sub: sp,
        nonexistent: np,
        strict_dkim: strict("adkim")?,
        strict_spf: strict("aspf")?,
        psd: match tags.get("psd") {
            Some(&"y") => Some(true),
            Some(&"n") => Some(false),
            _ => None,
        },
        testing: tags.get("t") == Some(&"y"),
        report,
    }))
}
fn domain(s: &str) -> Result<String, Status> {
    workglen_dns::Name::parse(s)
        .map(|n| n.as_str().trim_end_matches('.').to_owned())
        .map_err(|_| Status::Permanent)
}
async fn walk(dns: &impl Dns, domain: &str) -> Result<Vec<(String, Record)>, Status> {
    let labels: Vec<_> = domain.split('.').collect();
    if labels.len() < 2 {
        return Ok(Vec::new());
    }
    let mut depth = labels.len();
    let mut found = Vec::new();
    loop {
        let name = labels[labels.len() - depth..].join(".");
        let records = match dns.lookup(&format!("_dmarc.{name}"), RecordType::TXT).await {
            Ok(v) => v,
            Err(Error::NoRecords(_)) => Vec::new(),
            Err(_) => return Err(Status::Temporary),
        };
        let mut selected = None;
        let mut count = 0;
        for r in records {
            if let RData::TXT(t) = r {
                let bytes = t.txt_data.concat();
                let Ok(text) = std::str::from_utf8(&bytes) else {
                    continue;
                };
                if let Ok(Some(record)) = record(text) {
                    count += 1;
                    selected = Some(record);
                }
            }
        }
        if count == 1
            && let Some(record) = selected
        {
            let stop = record.psd.is_some();
            found.push((name, record));
            if stop {
                break;
            }
        }
        if depth == 1 {
            break;
        }
        depth = if depth >= 8 { 7 } else { depth - 1 };
    }
    Ok(found)
}
fn organizational(walk: &[(String, Record)], start: &str) -> String {
    for (name, record) in walk {
        match record.psd {
            Some(false) => return name.clone(),
            Some(true) if name != start => {
                let labels: Vec<_> = start.split('.').collect();
                let count = name.split('.').count() + 1;
                return labels[labels.len().saturating_sub(count)..].join(".");
            }
            _ => {}
        }
    }
    walk.last()
        .map(|(n, _)| n.as_str())
        .unwrap_or(start)
        .to_owned()
}
async fn aligned(
    dns: &impl Dns,
    candidate: &str,
    author: &str,
    org: &str,
    strict: bool,
    memo: &mut HashMap<String, String>,
) -> Result<bool, Status> {
    let candidate = domain(candidate)?;
    if candidate == author {
        return Ok(true);
    }
    if strict
        || !(candidate == org
            || candidate
                .strip_suffix(org)
                .is_some_and(|s| s.ends_with('.')))
    {
        return Ok(false);
    }
    let candidate_org = if let Some(org) = memo.get(&candidate) {
        org.clone()
    } else {
        let value = organizational(&walk(dns, &candidate).await?, &candidate);
        memo.insert(candidate, value.clone());
        value
    };
    Ok(candidate_org == org)
}
pub async fn verify(
    dns: &impl Dns,
    author: &str,
    sender_domain: &str,
    spf: spf::Status,
    dkim: &[dkim::Outcome],
) -> Outcome {
    let mut policy = Policy::None;
    let result = async {
        let author = domain(author)?;
        let records = walk(dns, &author).await?;
        if records.is_empty() {
            return Ok(Status::None);
        }
        let org = organizational(&records, &author);
        let chosen = records
            .iter()
            .find(|(n, _)| n == &author)
            .or_else(|| records.iter().find(|(n, _)| n == &org))
            .or_else(|| records.last())
            .unwrap();
        let record = &chosen.1;
        policy = if let Some(p) = record.policy {
            if chosen.0 == author {
                p
            } else if record.nonexistent != record.sub
                && matches!(
                    dns.lookup(&author, RecordType::A).await,
                    Err(Error::NoRecords(ResponseCode::NXDomain))
                )
            {
                record.nonexistent
            } else {
                record.sub
            }
        } else if record.report {
            Policy::None
        } else {
            return Ok(Status::None);
        };
        if record.testing {
            policy = match policy {
                Policy::Reject => Policy::Quarantine,
                Policy::Quarantine | Policy::None => Policy::None,
            };
        }
        let mut memo = HashMap::from([(author.clone(), org.clone())]);
        let mut temporary = false;
        if matches!(spf, spf::Status::Pass | spf::Status::Temporary) {
            match aligned(
                dns,
                sender_domain,
                &author,
                &org,
                record.strict_spf,
                &mut memo,
            )
            .await
            {
                Ok(true) if spf == spf::Status::Pass => return Ok(Status::Pass),
                Ok(true) | Err(Status::Temporary) => temporary = true,
                Err(_) => return Err(Status::Permanent),
                _ => {}
            }
        }
        for signature in dkim {
            if matches!(
                signature.status,
                dkim::Status::Pass | dkim::Status::Temporary
            ) {
                match aligned(
                    dns,
                    &signature.domain,
                    &author,
                    &org,
                    record.strict_dkim,
                    &mut memo,
                )
                .await
                {
                    Ok(true) if signature.status == dkim::Status::Pass => return Ok(Status::Pass),
                    Ok(true) | Err(Status::Temporary) => temporary = true,
                    Err(_) => return Err(Status::Permanent),
                    _ => {}
                }
            }
        }
        Ok(if temporary {
            Status::Temporary
        } else {
            Status::Fail
        })
    }
    .await;
    Outcome {
        status: result.unwrap_or_else(|s| s),
        policy,
    }
}
