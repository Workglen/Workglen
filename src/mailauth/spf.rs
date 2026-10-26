//! RFC 7208 SPF evaluation with shared recursive-query and void-lookup budgets.
use super::Dns;
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
};
use workglen_dns::{Error, RData, RecordType};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    Temporary,
    Permanent,
}
#[derive(Clone, Copy)]
pub struct Parameters<'a> {
    pub ip: IpAddr,
    pub helo: &'a str,
    pub sender: &'a str,
}
struct State<'a, D> {
    dns: &'a D,
    ip: IpAddr,
    helo: String,
    sender: String,
    lookups: u8,
    voids: u8,
    ptr: Option<Vec<String>>,
    receiver: String,
    explanation: Option<(String, String)>,
}
#[derive(Debug)]
struct Term {
    qualifier: Status,
    kind: String,
    arg: String,
    v4: u8,
    v6: u8,
}
fn suffix(name: &str, base: &str) -> bool {
    name == base || name.strip_suffix(base).is_some_and(|p| p.ends_with('.'))
}
fn normalize(s: &str) -> Result<String, Status> {
    workglen_dns::Name::parse(s)
        .map(|n| n.as_str().trim_end_matches('.').to_owned())
        .map_err(|_| Status::Permanent)
}
fn limit(state: &mut u8, max: u8) -> Result<(), Status> {
    *state += 1;
    if *state > max {
        Err(Status::Permanent)
    } else {
        Ok(())
    }
}
type ParsedTerms = (Vec<Term>, Option<String>, Option<String>);
fn parse_terms(record: &str) -> Result<ParsedTerms, Status> {
    let mut words = record.split(' ').filter(|s| !s.is_empty());
    if !words
        .next()
        .is_some_and(|s| s.eq_ignore_ascii_case("v=spf1"))
    {
        return Err(Status::Permanent);
    }
    let mut terms = Vec::new();
    let mut redirect = None;
    let mut explanation = None;
    for word in words {
        if !word.is_ascii() || word.bytes().any(|b| b <= 32 || b >= 127) {
            return Err(Status::Permanent);
        }
        let has_qualifier = matches!(word.as_bytes().first(), Some(b'+' | b'-' | b'~' | b'?'));
        let (qualifier, word) = match word.as_bytes().first() {
            Some(b'+') => (Status::Pass, &word[1..]),
            Some(b'-') => (Status::Fail, &word[1..]),
            Some(b'~') => (Status::SoftFail, &word[1..]),
            Some(b'?') => (Status::Neutral, &word[1..]),
            _ => (Status::Pass, word),
        };
        let head_end = word.find([':', '/', '=']).unwrap_or(word.len());
        let kind = word[..head_end].to_ascii_lowercase();
        let tail = &word[head_end..];
        if let Some(value) = tail.strip_prefix('=') {
            if has_qualifier
                || value.is_empty()
                || kind.is_empty()
                || !kind.as_bytes()[0].is_ascii_alphabetic()
                || !kind
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            {
                return Err(Status::Permanent);
            }
            macro_syntax(value, false)?;
            if kind == "redirect" {
                if redirect.replace(value.to_owned()).is_some() {
                    return Err(Status::Permanent);
                }
            } else if kind == "exp" && explanation.replace(value.to_owned()).is_some() {
                return Err(Status::Permanent);
            }
            continue;
        }
        if !matches!(
            kind.as_str(),
            "all" | "include" | "a" | "mx" | "ptr" | "ip4" | "ip6" | "exists"
        ) {
            return Err(Status::Permanent);
        }
        let arg = tail.strip_prefix(':').unwrap_or(tail);
        let mut nesting = 0;
        let mut slash = None;
        for (i, b) in arg.bytes().enumerate() {
            match b {
                b'{' => nesting += 1,
                b'}' => nesting -= 1,
                b'/' if nesting == 0 => {
                    slash = Some(i);
                    break;
                }
                _ => {}
            }
            if nesting < 0 {
                return Err(Status::Permanent);
            }
        }
        let (arg, cidr) = slash.map_or((arg, ""), |i| (&arg[..i], &arg[i..]));
        let (mut v4, mut v6) = (32, 128);
        if !cidr.is_empty() {
            if !matches!(kind.as_str(), "a" | "mx" | "ip4" | "ip6") {
                return Err(Status::Permanent);
            }
            if kind == "ip6" {
                v6 = cidr
                    .strip_prefix('/')
                    .unwrap()
                    .parse()
                    .map_err(|_| Status::Permanent)?;
            } else {
                let (a, b) = cidr
                    .split_once("//")
                    .map_or((cidr, None), |(a, b)| (a, Some(b)));
                if !a.is_empty() {
                    v4 = a
                        .strip_prefix('/')
                        .ok_or(Status::Permanent)?
                        .parse()
                        .map_err(|_| Status::Permanent)?;
                }
                if let Some(b) = b {
                    if kind == "ip4" {
                        return Err(Status::Permanent);
                    }
                    v6 = b.parse().map_err(|_| Status::Permanent)?;
                }
            }
        }
        if v4 > 32 || v6 > 128 {
            return Err(Status::Permanent);
        }
        if kind == "all" && !tail.is_empty() {
            return Err(Status::Permanent);
        }
        if matches!(kind.as_str(), "include" | "exists" | "ip4" | "ip6")
            && (!tail.starts_with(':') || arg.is_empty())
        {
            return Err(Status::Permanent);
        }
        if !arg.is_empty() && !tail.starts_with(':') {
            return Err(Status::Permanent);
        }
        if tail.starts_with(':') && arg.is_empty() {
            return Err(Status::Permanent);
        }
        if kind == "ip4" {
            arg.parse::<Ipv4Addr>().map_err(|_| Status::Permanent)?;
        }
        if kind == "ip6" {
            arg.parse::<Ipv6Addr>().map_err(|_| Status::Permanent)?;
        }
        if !matches!(kind.as_str(), "ip4" | "ip6") {
            macro_syntax(arg, false)?;
        }
        terms.push(Term {
            qualifier,
            kind,
            arg: arg.into(),
            v4,
            v6,
        });
    }
    Ok((terms, redirect, explanation))
}
fn prefix(ip: IpAddr, other: IpAddr, v4: u8, v6: u8) -> bool {
    match other {
        IpAddr::V4(b) => {
            let a = match ip {
                IpAddr::V4(a) => a,
                IpAddr::V6(a) => match a.to_ipv4_mapped() {
                    Some(a) => a,
                    None => return false,
                },
            };
            v4 == 0 || u32::from(a) >> (32 - v4) == u32::from(b) >> (32 - v4)
        }
        IpAddr::V6(b) => {
            let a = match ip {
                IpAddr::V6(a) => a,
                IpAddr::V4(a) => a.to_ipv6_mapped(),
            };
            v6 == 0 || u128::from(a) >> (128 - v6) == u128::from(b) >> (128 - v6)
        }
    }
}
impl<D: Dns> State<'_, D> {
    async fn query(&mut self, name: &str, kind: RecordType) -> Result<Vec<RData>, Status> {
        match self.dns.lookup(name, kind).await {
            Ok(v) => {
                if v.is_empty() {
                    limit(&mut self.voids, 2)?;
                }
                Ok(v)
            }
            Err(Error::NoRecords(_)) => {
                limit(&mut self.voids, 2)?;
                Ok(Vec::new())
            }
            Err(Error::InvalidName) => Err(Status::Permanent),
            Err(_) => Err(Status::Temporary),
        }
    }
    async fn validated_ptr(&mut self) -> Vec<String> {
        if let Some(v) = &self.ptr {
            return v.clone();
        }
        let reverse = match self.ip {
            IpAddr::V4(ip) => {
                let o = ip.octets();
                format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
            }
            IpAddr::V6(ip) => {
                let mut s = String::new();
                for b in ip.octets().iter().rev() {
                    s.push_str(&format!("{:x}.{:x}.", b & 15, b >> 4));
                }
                s.push_str("ip6.arpa");
                s
            }
        };
        let kind = if self.ip.is_ipv4() {
            RecordType::A
        } else {
            RecordType::AAAA
        };
        let mut valid = Vec::new();
        // RFC 7208: PTR DNS errors are treated as a non-match, not TempError.
        let records = self
            .query(&reverse, RecordType::PTR)
            .await
            .unwrap_or_default();
        for record in records.into_iter().take(10) {
            if let RData::PTR(name) = record {
                let host = name.as_str().trim_end_matches('.');
                if let Ok(addresses) = self.query(host, kind).await
                    && addresses.into_iter().take(10).any(|r| match r {
                        RData::A(a) => IpAddr::V4(a.0) == self.ip,
                        RData::AAAA(a) => IpAddr::V6(a.0) == self.ip,
                        _ => false,
                    })
                {
                    valid.push(host.to_owned());
                }
            }
        }
        self.ptr = Some(valid.clone());
        valid
    }
    async fn expand_value(
        &mut self,
        input: &str,
        domain: &str,
        explanation: bool,
    ) -> Result<String, Status> {
        if input.len() > 4096 {
            return Err(Status::Permanent);
        }
        macro_syntax(input, explanation)?;
        let mut out = String::new();
        let b = input.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'%' {
                out.push(b[i] as char);
                i += 1;
                continue;
            }
            i += 1;
            match b.get(i) {
                Some(b'%') => {
                    out.push('%');
                    i += 1;
                }
                Some(b'_') => {
                    out.push(' ');
                    i += 1;
                }
                Some(b'-') => {
                    out.push_str("%20");
                    i += 1;
                }
                Some(b'{') => {
                    let end = b[i + 1..]
                        .iter()
                        .position(|b| *b == b'}')
                        .map(|n| i + 1 + n)
                        .ok_or(Status::Permanent)?;
                    let content = &input[i + 1..end];
                    let c = content.bytes().next().ok_or(Status::Permanent)?;
                    let lower = c.to_ascii_lowercase();
                    let (sender_local, sender_domain) =
                        self.sender.rsplit_once('@').ok_or(Status::Permanent)?;
                    let value = match lower {
                        b's' => self.sender.clone(),
                        b'l' => if sender_local.is_empty() {
                            "postmaster"
                        } else {
                            sender_local
                        }
                        .into(),
                        b'o' => sender_domain.into(),
                        b'd' => domain.into(),
                        b'h' => self.helo.clone(),
                        b'c' if explanation => self.ip.to_string(),
                        b'r' if explanation => self.receiver.clone(),
                        b't' if explanation => super::now().to_string(),
                        b'v' => if self.ip.is_ipv4() { "in-addr" } else { "ip6" }.into(),
                        b'i' => match self.ip {
                            IpAddr::V4(ip) => ip.to_string(),
                            IpAddr::V6(ip) => ip
                                .octets()
                                .iter()
                                .flat_map(|b| [format!("{:x}", b >> 4), format!("{:x}", b & 15)])
                                .collect::<Vec<_>>()
                                .join("."),
                        },
                        b'p' => {
                            let names = self.validated_ptr().await;
                            names
                                .iter()
                                .find(|n| *n == domain)
                                .or_else(|| names.iter().find(|n| suffix(n, domain)))
                                .or_else(|| names.first())
                                .cloned()
                                .unwrap_or("unknown".into())
                        }
                        _ => return Err(Status::Permanent),
                    };
                    let rest = &content[1..];
                    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
                    let count = if digits == 0 {
                        None
                    } else {
                        let n = rest[..digits]
                            .parse::<usize>()
                            .map_err(|_| Status::Permanent)?;
                        if n == 0 {
                            return Err(Status::Permanent);
                        }
                        Some(n)
                    };
                    let rest = &rest[digits..];
                    let (reverse, delimiters) =
                        rest.strip_prefix('r').map_or((false, rest), |s| (true, s));
                    if !delimiters
                        .bytes()
                        .all(|b| matches!(b, b'.' | b'-' | b'+' | b',' | b'/' | b'_' | b'='))
                    {
                        return Err(Status::Permanent);
                    }
                    let delimiters = if delimiters.is_empty() {
                        "."
                    } else {
                        delimiters
                    };
                    let mut parts: Vec<_> = value.split(|c| delimiters.contains(c)).collect();
                    if reverse {
                        parts.reverse();
                    }
                    if let Some(n) = count
                        && parts.len() > n
                    {
                        parts = parts[parts.len() - n..].to_vec();
                    }
                    let value = parts.join(".");
                    if c.is_ascii_uppercase() {
                        for b in value.bytes() {
                            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                                out.push(b as char);
                            } else {
                                out.push_str(&format!("%{b:02X}"));
                            }
                        }
                    } else {
                        out.push_str(&value);
                    }
                    i = end + 1;
                }
                _ => return Err(Status::Permanent),
            }
            if out.len() > 4096 {
                return Err(Status::Permanent);
            }
        }
        if self.voids > 2 {
            return Err(Status::Permanent);
        }
        if explanation {
            return Ok(out);
        }
        // RFC 7208 truncation removes leftmost labels, never partial labels.
        while out.len() > 253 {
            let Some((_, tail)) = out.split_once('.') else {
                return Err(Status::Permanent);
            };
            out = tail.to_owned();
        }
        normalize(&out)
    }
    async fn expand(&mut self, input: &str, domain: &str) -> Result<String, Status> {
        self.expand_value(input, domain, false).await
    }
    fn evaluate<'a>(
        &'a mut self,
        domain: String,
        depth: u8,
    ) -> Pin<Box<dyn Future<Output = Status> + 'a>> {
        Box::pin(async move {
            if depth > 10 {
                return Status::Permanent;
            }
            let records = match self.query(&domain, RecordType::TXT).await {
                Ok(v) => v,
                Err(e) => return e,
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
                .filter(|s| {
                    s.split(' ')
                        .next()
                        .is_some_and(|s| s.eq_ignore_ascii_case("v=spf1"))
                })
                .collect();
            if records.is_empty() {
                return Status::None;
            }
            if records.len() != 1 {
                return Status::Permanent;
            }
            let (terms, redirect, explanation) = match parse_terms(&records[0]) {
                Ok(v) => v,
                Err(e) => return e,
            };
            for term in terms {
                if matches!(
                    term.kind.as_str(),
                    "include" | "a" | "mx" | "ptr" | "exists"
                ) && limit(&mut self.lookups, 10).is_err()
                {
                    return Status::Permanent;
                }
                let matched = match term.kind.as_str() {
                    "all" => true,
                    "ip4" => prefix(self.ip, IpAddr::V4(term.arg.parse().unwrap()), term.v4, 128),
                    "ip6" => prefix(self.ip, IpAddr::V6(term.arg.parse().unwrap()), 32, term.v6),
                    kind => {
                        let target = if term.arg.is_empty() {
                            domain.clone()
                        } else {
                            match self.expand(&term.arg, &domain).await {
                                Ok(v) => v,
                                Err(e) => return e,
                            }
                        };
                        match kind {
                            "include" => match self.evaluate(target, depth + 1).await {
                                Status::Pass => true,
                                Status::Temporary => return Status::Temporary,
                                Status::Permanent | Status::None => return Status::Permanent,
                                _ => false,
                            },
                            "a" | "exists" => {
                                let rt = if kind == "exists" || self.ip.is_ipv4() {
                                    RecordType::A
                                } else {
                                    RecordType::AAAA
                                };
                                let records = match self.query(&target, rt).await {
                                    Ok(v) => v,
                                    Err(e) => return e,
                                };
                                records.iter().any(|r| match r {
                                    RData::A(a) => {
                                        kind == "exists"
                                            || prefix(self.ip, IpAddr::V4(a.0), term.v4, term.v6)
                                    }
                                    RData::AAAA(a) => {
                                        prefix(self.ip, IpAddr::V6(a.0), term.v4, term.v6)
                                    }
                                    _ => false,
                                })
                            }
                            "mx" => {
                                let records = match self.query(&target, RecordType::MX).await {
                                    Ok(v) => v,
                                    Err(e) => return e,
                                };
                                let hosts: Vec<_> = records
                                    .iter()
                                    .filter_map(|r| {
                                        if let RData::MX(m) = r {
                                            Some(&m.exchange)
                                        } else {
                                            None
                                        }
                                    })
                                    .collect();
                                if hosts.len() > 10 {
                                    return Status::Permanent;
                                }
                                let mut matched = false;
                                for host in hosts {
                                    if host.as_str() == "." {
                                        continue;
                                    }
                                    let rt = if self.ip.is_ipv4() {
                                        RecordType::A
                                    } else {
                                        RecordType::AAAA
                                    };
                                    let addresses = match self.query(host.as_str(), rt).await {
                                        Ok(v) => v,
                                        Err(e) => return e,
                                    };
                                    if addresses.len() > 10 {
                                        return Status::Permanent;
                                    }
                                    if addresses.iter().any(|r| match r {
                                        RData::A(a) => {
                                            prefix(self.ip, IpAddr::V4(a.0), term.v4, term.v6)
                                        }
                                        RData::AAAA(a) => {
                                            prefix(self.ip, IpAddr::V6(a.0), term.v4, term.v6)
                                        }
                                        _ => false,
                                    }) {
                                        matched = true;
                                        break;
                                    }
                                }
                                matched
                            }
                            "ptr" => {
                                let v = self.validated_ptr().await;
                                if self.voids > 2 {
                                    return Status::Permanent;
                                }
                                v.iter().any(|n| suffix(n, &target))
                            }
                            _ => return Status::Permanent,
                        }
                    }
                };
                if matched {
                    if term.qualifier == Status::Fail {
                        self.explanation = explanation.map(|e| (e, domain.clone()));
                    }
                    return term.qualifier;
                }
            }
            if let Some(target) = redirect {
                if limit(&mut self.lookups, 10).is_err() {
                    return Status::Permanent;
                }
                let target = match self.expand(&target, &domain).await {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let result = self.evaluate(target, depth + 1).await;
                if result == Status::None {
                    Status::Permanent
                } else {
                    result
                }
            } else {
                Status::Neutral
            }
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    pub explanation: Option<String>,
}
pub async fn verify(dns: &impl Dns, params: Parameters<'_>) -> Status {
    evaluate(dns, params, "unknown", false).await.status
}
pub async fn verify_detailed(dns: &impl Dns, params: Parameters<'_>, receiver: &str) -> Outcome {
    evaluate(dns, params, receiver, true).await
}
async fn evaluate(
    dns: &impl Dns,
    params: Parameters<'_>,
    receiver: &str,
    want_explanation: bool,
) -> Outcome {
    let ip = params.ip;
    let sender = if params.sender.is_empty() {
        format!("postmaster@{}", params.helo)
    } else {
        params.sender.to_owned()
    };
    let domain = match sender.rsplit_once('@').map(|(_, d)| normalize(d)) {
        Some(Ok(v)) => v,
        _ => {
            return Outcome {
                status: Status::None,
                explanation: None,
            };
        }
    };
    let mut state = State {
        dns,
        ip,
        helo: params.helo.into(),
        sender,
        lookups: 0,
        voids: 0,
        ptr: None,
        receiver: receiver.into(),
        explanation: None,
    };
    let status = state.evaluate(domain, 0).await;
    let mut explanation = None;
    if status == Status::Fail
        && want_explanation
        && let Some((spec, domain)) = state.explanation.take()
    {
        // Explanation failures do not change the already computed SPF result.
        if let Ok(name) = state.expand(&spec, &domain).await
            && let Ok(records) = dns.lookup(&name, RecordType::TXT).await
        {
            let texts: Vec<_> = records
                .into_iter()
                .filter_map(|r| {
                    if let RData::TXT(t) = r {
                        String::from_utf8(t.txt_data.concat()).ok()
                    } else {
                        None
                    }
                })
                .collect();
            if texts.len() == 1 {
                explanation = state.expand_value(&texts[0], &domain, true).await.ok();
            }
        }
    }
    Outcome {
        status,
        explanation,
    }
}

fn macro_syntax(input: &str, explanation: bool) -> Result<(), Status> {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            if !bytes[i].is_ascii() || (!explanation && !(33..=126).contains(&bytes[i])) {
                return Err(Status::Permanent);
            }
            i += 1;
            continue;
        }
        i += 1;
        match bytes.get(i) {
            Some(b'%' | b'_' | b'-') => i += 1,
            Some(b'{') => {
                i += 1;
                let c = bytes.get(i).ok_or(Status::Permanent)?.to_ascii_lowercase();
                if !b"slodipvh".contains(&c) && !(explanation && b"crt".contains(&c)) {
                    return Err(Status::Permanent);
                }
                i += 1;
                let start = i;
                while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
                if i > start && input[start..i].parse::<usize>().ok().is_none_or(|n| n == 0) {
                    return Err(Status::Permanent);
                }
                if bytes.get(i) == Some(&b'r') {
                    i += 1;
                }
                while bytes.get(i).is_some_and(|c| b".-+,/_=".contains(c)) {
                    i += 1;
                }
                if bytes.get(i) != Some(&b'}') {
                    return Err(Status::Permanent);
                }
                i += 1;
            }
            _ => return Err(Status::Permanent),
        }
    }
    Ok(())
}
