//! Native DKIM2 chain signatures and reconstruction. Preserves the deployed
//! draft wire format; cryptography and bounded sequence diff stay in Pratique/Workglen.
use super::{
    Dns,
    crypto::SigningKey,
    dkim::{self, Canonicalization},
    verify_dkim::{Algorithm, base64, required, tags},
};
use crate::{
    encoding::STANDARD,
    error::{Result, ensure},
};
use pratique::crypto::sha2::{Hash, Sha256};
use std::collections::{BTreeMap, HashSet};
use workglen_dns::{RData, RecordType};
pub mod native_diff;
pub mod recipe;
pub use recipe::{BodyRecipe, HeaderRecipe, Recipe, Step};
pub struct Message<'a> {
    pub headers: Vec<(&'a [u8], &'a [u8])>,
    pub raw_message: &'a [u8],
    body: &'a [u8],
}
impl<'a> Message<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        let (h, body) = dkim::headers(raw)?;
        Ok(Self {
            headers: h.into_iter().map(|h| (h.name, h.value)).collect(),
            raw_message: raw,
            body,
        })
    }
    pub fn raw_body(&self) -> &'a [u8] {
        self.body
    }
}
pub fn excluded(name: &[u8]) -> bool {
    name.starts_with(b"X-")
        || name.starts_with(b"x-")
        || [
            "received",
            "return-path",
            "delivered-to",
            "authentication-results",
            "dkim-signature",
            "message-instance",
            "dkim2-signature",
            "arc-authentication-results",
            "arc-message-signature",
            "arc-seal",
        ]
        .iter()
        .any(|s| name.eq_ignore_ascii_case(s.as_bytes()))
}
pub fn hashes(message: &Message<'_>) -> (Vec<u8>, Vec<u8>) {
    let mut fields: Vec<_> = message
        .headers
        .iter()
        .rev()
        .filter(|(n, _)| !excluded(n))
        .collect();
    fields.sort_by_key(|(n, _)| n.to_ascii_lowercase());
    let mut h = Sha256::new();
    for &&(name, value) in &fields {
        h.update(&dkim::canonical_header(
            &dkim::Header {
                name,
                value,
                raw: &[],
            },
            Canonicalization::Relaxed,
        ));
    }
    let mut b = Sha256::new();
    dkim::write_canonical_body(message.body, Canonicalization::Simple, |v| b.update(v));
    (h.finalize().to_vec(), b.finalize().to_vec())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
}
impl Envelope {
    pub fn new(from: impl AsRef<str>, to: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            mail_from: path(from.as_ref()),
            rcpt_to: to.into_iter().map(|s| path(s.as_ref())).collect(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hop {
    Real(Envelope),
    NextDomain(String),
}
impl Hop {
    pub fn real(from: impl AsRef<str>, to: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self::Real(Envelope::new(from, to))
    }
    pub fn imaginary(domain: impl Into<String>) -> Self {
        Self::NextDomain(domain.into())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureValue {
    pub selector: String,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub i: u32,
    pub m: u32,
    pub t: u64,
    pub domain: String,
    pub signatures: Vec<SignatureValue>,
    pub hop: Hop,
    pub flags: Vec<String>,
    pub nonce: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageInstance {
    pub m: u32,
    pub header_hash: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub recipe: Option<Recipe>,
}
#[derive(Clone, Debug)]
pub struct Signed {
    pub signature: Signature,
    pub message_instance: Option<MessageInstance>,
}
impl Signed {
    pub fn to_header(&self) -> String {
        let mut s = fold("DKIM2-Signature", &self.signature.value(false));
        if let Some(mi) = &self.message_instance {
            s.push_str(&fold("Message-Instance", &mi.value()));
        }
        s
    }
}
pub struct Signer {
    pub domain: String,
    pub keys: Vec<(String, SigningKey)>,
    pub flags: Vec<String>,
    pub nonce: Option<String>,
}
impl Signer {
    pub fn new(domain: impl Into<String>, selector: impl Into<String>, key: SigningKey) -> Self {
        Self {
            domain: domain.into(),
            keys: vec![(selector.into(), key)],
            flags: Vec::new(),
            nonce: None,
        }
    }
    pub fn sign(&self, raw: &[u8], hop: Hop) -> Result<Signed> {
        self.sign_at(raw, None, hop, super::now())
    }
    pub fn sign_revised(&self, original: &[u8], modified: &[u8], hop: Hop) -> Result<Signed> {
        self.sign_at(modified, Some(original), hop, super::now())
    }
    pub fn sign_at(
        &self,
        raw: &[u8],
        original: Option<&[u8]>,
        hop: Hop,
        now: u64,
    ) -> Result<Signed> {
        ensure!(raw.len() <= 64 * 1024 * 1024, "DKIM2 message limit");
        let msg = Message::parse(raw)?;
        let mut chain = Chain::parse(&msg)?;
        ensure!(chain.signatures.len() < 50, "DKIM2 chain limit");
        let (hh, bh) = hashes(&msg);
        let previous = chain.instances.last_key_value();
        let changed = previous.is_none_or(|(_, (_, m))| m.header_hash != hh || m.body_hash != bh);
        let mi = if changed {
            let recipe = if let Some(original) = original {
                Some(Recipe::diff(&Message::parse(original)?, &msg))
            } else if previous.is_some() {
                Some(Recipe {
                    headers: Vec::new(),
                    body: BodyRecipe::Unreconstructable,
                })
            } else {
                None
            };
            Some(MessageInstance {
                m: previous.map_or(1, |(m, _)| m + 1),
                header_hash: hh,
                body_hash: bh,
                recipe,
            })
        } else {
            None
        };
        let domain = normalize(&self.domain)?;
        ensure!(
            !self.keys.is_empty() && self.keys.len() <= 16,
            "DKIM2 signing key count"
        );
        validate_hop(&hop)?;
        ensure!(self.flags.iter().all(|v|!v.is_empty()&&v.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'-')),"invalid DKIM2 flags");
        ensure!(
            self.nonce.as_ref().is_none_or(|n| !n.is_empty()
                && n.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"+/=_-".contains(&c))),
            "invalid nonce"
        );
        let mut sig = Signature {
            i: chain.signatures.len() as u32 + 1,
            m: mi
                .as_ref()
                .map(|m| m.m)
                .or_else(|| previous.map(|(m, _)| *m))
                .unwrap(),
            t: now,
            domain,
            signatures: Vec::new(),
            hop,
            flags: self.flags.clone(),
            nonce: self.nonce.clone(),
        };
        for (selector, key) in &self.keys {
            sig.signatures.push(SignatureValue {
                selector: normalize(selector)?,
                algorithm: key.algorithm(),
                signature: Vec::new(),
            });
        }
        if let Some(mi) = &mi {
            chain.instances.insert(mi.m, (mi.value(), mi.clone()));
        }
        let input = chain.input(&sig, &sig.value(true))?;
        for (v, (_, key)) in sig.signatures.iter_mut().zip(&self.keys) {
            v.signature = key.sign(&input)?;
        }
        let signed = Signed {
            signature: sig,
            message_instance: mi,
        };
        let header_bytes = msg
            .headers
            .iter()
            .map(|(n, v)| n.len() + v.len() + 1)
            .sum::<usize>();
        ensure!(
            signed.to_header().len() + header_bytes <= 64 * 1024,
            "DKIM2 header limit"
        );
        Ok(signed)
    }
}
fn normalize(s: &str) -> Result<String> {
    Ok(workglen_dns::Name::parse(s)?
        .as_str()
        .trim_end_matches('.')
        .into())
}
fn path(s: &str) -> String {
    if s.starts_with('<') && s.ends_with('>') {
        s.into()
    } else {
        format!("<{s}>")
    }
}
fn address(s: &str) -> Result<(&str, &str)> {
    ensure!(
        s.starts_with('<') && s.ends_with('>') && !s.bytes().any(|c| c.is_ascii_control()),
        "invalid envelope path"
    );
    let s = &s[1..s.len() - 1];
    if s.is_empty() {
        return Ok(("", ""));
    }
    s.rsplit_once('@')
        .filter(|(l, d)| !l.is_empty() && !d.is_empty())
        .ok_or_else(|| crate::error!("invalid envelope mailbox"))
}
fn same_address(a: &str, b: &str) -> bool {
    match (address(a), address(b)) {
        (Ok((al, ad)), Ok((bl, bd))) => al == bl && ad.eq_ignore_ascii_case(bd),
        _ => false,
    }
}
fn within(child: &str, parent: &str) -> bool {
    child.eq_ignore_ascii_case(parent)
        || child
            .to_ascii_lowercase()
            .strip_suffix(&parent.to_ascii_lowercase())
            .is_some_and(|s| s.ends_with('.'))
}
fn validate_hop(hop: &Hop) -> Result<()> {
    match hop {
        Hop::NextDomain(d) => {
            normalize(d)?;
        }
        Hop::Real(e) => {
            address(&e.mail_from)?;
            ensure!(
                !e.rcpt_to.is_empty() && e.rcpt_to.len() <= 1000,
                "recipient count"
            );
            for a in &e.rcpt_to {
                let (_, d) = address(a)?;
                ensure!(!d.is_empty(), "empty recipient");
            }
        }
    }
    Ok(())
}
impl Signature {
    fn value(&self, empty: bool) -> String {
        let mut s = format!(
            "i={}; m={}; t={}; d={}; ",
            self.i, self.m, self.t, self.domain
        );
        match &self.hop {
            Hop::Real(e) => s.push_str(&format!(
                "mf={}; rt={}",
                STANDARD.encode(e.mail_from.as_bytes()),
                e.rcpt_to
                    .iter()
                    .map(|v| STANDARD.encode(v.as_bytes()))
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            Hop::NextDomain(d) => s.push_str(&format!("nd={d}")),
        };
        s.push_str("; s=");
        s.push_str(
            &self
                .signatures
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}:{}",
                        k.selector,
                        k.algorithm.name(),
                        if empty {
                            String::new()
                        } else {
                            STANDARD.encode(&k.signature)
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join(","),
        );
        s.push(';');
        if let Some(n) = &self.nonce {
            s.push_str(&format!(" n={n};"));
        }
        if !self.flags.is_empty() {
            s.push_str(&format!(" f={};", self.flags.join(",")));
        }
        s
    }
    fn parse(value: &[u8]) -> Result<Self> {
        let t = tags(value)?;
        let i = required(&t, "i")?.parse()?;
        let m = required(&t, "m")?.parse()?;
        let time = required(&t, "t")?.parse()?;
        let hop = if let Some(d) = t.get("nd") {
            ensure!(
                !t.contains_key("mf") && !t.contains_key("rt"),
                "ambiguous custody binding"
            );
            Hop::NextDomain(normalize(d)?)
        } else {
            Hop::Real(Envelope {
                mail_from: String::from_utf8(base64(required(&t, "mf")?)?)?,
                rcpt_to: required(&t, "rt")?
                    .split(',')
                    .map(|s| Ok(String::from_utf8(base64(s)?)?))
                    .collect::<Result<_>>()?,
            })
        };
        validate_hop(&hop)?;
        let mut signatures = Vec::new();
        for item in required(&t, "s")?.split(',') {
            let mut p = item.splitn(3, ':');
            let selector = normalize(p.next().unwrap())?;
            let a = p.next().ok_or_else(|| crate::error!("missing algorithm"))?;
            let b = p.next().ok_or_else(|| crate::error!("missing signature"))?;
            if let Ok(algorithm) = Algorithm::parse(a) {
                signatures.push(SignatureValue {
                    selector,
                    algorithm,
                    signature: base64(b)?,
                });
            }
        }
        ensure!(
            !signatures.is_empty() && signatures.len() <= 16,
            "no supported DKIM2 signature or excessive keys"
        );
        Ok(Self {
            i,
            m,
            t: time,
            domain: normalize(required(&t, "d")?)?,
            signatures,
            hop,
            flags: t
                .get("f")
                .map(|s| s.split(',').map(str::to_owned).collect())
                .unwrap_or_default(),
            nonce: t.get("n").cloned(),
        })
    }
}
impl MessageInstance {
    fn value(&self) -> String {
        let mut s = format!(
            "m={}; h=sha256:{}:{}",
            self.m,
            STANDARD.encode(&self.header_hash),
            STANDARD.encode(&self.body_hash)
        );
        if let Some(recipe) = &self.recipe {
            let mut json = Vec::new();
            recipe.to_json(&mut json).expect("Vec JSON serialization");
            s.push_str(&format!("; r={}", STANDARD.encode(json)));
        }
        s.push(';');
        s
    }
    fn parse(v: &[u8]) -> Result<Self> {
        let t = tags(v)?;
        let mut hashes = None;
        for hash in required(&t, "h")?.split(',') {
            let p: Vec<_> = hash.split(':').collect();
            ensure!(p.len() == 3, "invalid instance hash");
            if p[0] == "sha256" {
                ensure!(hashes.is_none(), "duplicate sha256 hash");
                let h = base64(p[1])?;
                let b = base64(p[2])?;
                ensure!(h.len() == 32 && b.len() == 32, "invalid hash length");
                hashes = Some((h, b));
            }
        }
        let (header_hash, body_hash) =
            hashes.ok_or_else(|| crate::error!("no supported instance hash"))?;
        Ok(Self {
            m: required(&t, "m")?.parse()?,
            header_hash,
            body_hash,
            recipe: t
                .get("r")
                .map(|v| Recipe::from_json(&base64(v)?))
                .transpose()?,
        })
    }
}
fn compact(name: &str, value: &str) -> Vec<u8> {
    let mut out = name.to_ascii_lowercase().into_bytes();
    out.push(b':');
    out.extend(value.bytes().filter(|b| !b.is_ascii_whitespace()));
    out.extend(b"\r\n");
    out
}
fn blank(value: &str) -> Result<String> {
    let mut out = String::new();
    for (i, part) in value.split(';').enumerate() {
        if i > 0 {
            out.push(';');
        }
        if let Some((k, v)) = part.split_once('=')
            && k.trim() == "s"
        {
            out.push_str(k);
            out.push('=');
            for (j, sig) in v.split(',').enumerate() {
                if j > 0 {
                    out.push(',');
                }
                let (p, _) = sig
                    .rsplit_once(':')
                    .ok_or_else(|| crate::error!("invalid signature tuple"))?;
                out.push_str(p);
                out.push(':');
            }
        } else {
            out.push_str(part);
        }
    }
    Ok(out)
}
pub(crate) fn fold(name: &str, value: &str) -> String {
    let line = format!("{name}: {value}");
    let mut out = String::new();
    for (i, chunk) in line.as_bytes().chunks(76).enumerate() {
        if i > 0 {
            out.push_str("\r\n\t");
        }
        out.push_str(std::str::from_utf8(chunk).expect("ASCII protocol field"));
    }
    out.push_str("\r\n");
    out
}
struct Chain {
    signatures: BTreeMap<u32, (String, Signature)>,
    instances: BTreeMap<u32, (String, MessageInstance)>,
}
impl Chain {
    fn parse(msg: &Message<'_>) -> Result<Self> {
        let mut out = Self {
            signatures: BTreeMap::new(),
            instances: BTreeMap::new(),
        };
        for &(name, value) in &msg.headers {
            if name.eq_ignore_ascii_case(b"dkim2-signature") {
                let sig = Signature::parse(value)?;
                ensure!(
                    out.signatures
                        .insert(sig.i, (std::str::from_utf8(value)?.into(), sig))
                        .is_none(),
                    "duplicate signature instance"
                );
            } else if name.eq_ignore_ascii_case(b"message-instance") {
                let mi = MessageInstance::parse(value)?;
                ensure!(
                    out.instances
                        .insert(mi.m, (std::str::from_utf8(value)?.into(), mi))
                        .is_none(),
                    "duplicate message instance"
                );
            }
        }
        ensure!(
            out.signatures.len() <= 50 && out.instances.len() <= 50,
            "DKIM2 chain limit"
        );
        let mut previous = 0;
        let mut referenced = HashSet::new();
        for (n, (&i, (_, s))) in out.signatures.iter().enumerate() {
            ensure!(
                i == n as u32 + 1 && s.m > 0 && s.m >= previous && s.m <= previous + 1,
                "signature sequence gap"
            );
            previous = s.m;
            referenced.insert(s.m);
        }
        for (n, &m) in out.instances.keys().enumerate() {
            ensure!(
                m == n as u32 + 1 && referenced.contains(&m),
                "unsigned or missing message instance"
            );
        }
        ensure!(
            out.signatures.is_empty() && out.instances.is_empty()
                || out
                    .instances
                    .last_key_value()
                    .is_some_and(|(m, _)| *m == previous),
            "missing or excessive message instance"
        );
        Ok(out)
    }
    fn input(&self, sig: &Signature, value: &str) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for (_, (v, _)) in self.instances.range(..=sig.m) {
            out.extend(compact("message-instance", v));
        }
        for (_, (v, _)) in self.signatures.range(..sig.i) {
            out.extend(compact("dkim2-signature", v));
        }
        out.extend(compact("dkim2-signature", &blank(value)?));
        Ok(out)
    }
}
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
    pub chain: Vec<Signature>,
    pub detail: String,
}
impl Outcome {
    pub fn feedback_domains(&self) -> Vec<&str> {
        self.chain
            .iter()
            .filter(|s| s.flags.iter().any(|f| f == "feedback"))
            .map(|s| s.domain.as_str())
            .collect()
    }
    pub fn feedback_relay(&self) -> Option<&str> {
        self.chain
            .iter()
            .rev()
            .find(|s| s.flags.iter().any(|f| f == "feedhere"))
            .map(|s| s.domain.as_str())
    }
    pub fn return_path(&self) -> Option<&str> {
        match &self.chain.last()?.hop {
            Hop::Real(e) if e.mail_from != "<>" => Some(&e.mail_from),
            _ => None,
        }
    }
}
pub async fn verify(raw: &[u8], dns: &impl Dns, envelope: &Envelope, now: u64) -> Outcome {
    verify_inner(raw, dns, envelope, now, true).await
}
async fn verify_inner(
    raw: &[u8],
    dns: &impl Dns,
    envelope: &Envelope,
    now: u64,
    body_present: bool,
) -> Outcome {
    let mut temporary = false;
    let mut signatures = Vec::new();
    let result = async {
        ensure!(raw.len() <= 64 * 1024 * 1024, "DKIM2 message limit");
        let msg = Message::parse(raw)?;
        let chain = Chain::parse(&msg)?;
        if chain.signatures.is_empty() {
            return Ok(Status::None);
        }
        let top = &chain.signatures.last_key_value().unwrap().1.1;
        let Hop::Real(binding) = &top.hop else {
            crate::bail!("last hop must bind envelope")
        };
        ensure!(
            same_address(&binding.mail_from, &envelope.mail_from)
                && envelope
                    .rcpt_to
                    .iter()
                    .all(|r| binding.rcpt_to.iter().any(|b| same_address(b, r))),
            "envelope mismatch"
        );
        if binding.mail_from != "<>" {
            ensure!(
                within(address(&binding.mail_from)?.1, &top.domain),
                "sender domain mismatch"
            );
        }
        let mut previous: Option<&Signature> = None;
        for (v, sig) in chain.signatures.values() {
            ensure!(
                now.saturating_sub(sig.t) <= 14 * 86400,
                "DKIM2 signature expired"
            );
            if let Some(p) = previous {
                match &p.hop {
                    Hop::NextDomain(d) => {
                        ensure!(d.eq_ignore_ascii_case(&sig.domain), "next domain mismatch")
                    }
                    Hop::Real(e) => {
                        let domain = match &sig.hop {
                            Hop::Real(e) => address(&e.mail_from)?.1,
                            Hop::NextDomain(_) => &sig.domain,
                        };
                        ensure!(
                            e.rcpt_to
                                .iter()
                                .any(|r| address(r).is_ok_and(|(_, d)| within(domain, d))),
                            "custody break"
                        );
                    }
                }
            }
            let input = chain.input(sig, v)?;
            for key in &sig.signatures {
                let records = match dns
                    .lookup(
                        &format!("{}._domainkey.{}", key.selector, sig.domain),
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
                let txt: Vec<_> = records
                    .into_iter()
                    .filter_map(|r| {
                        if let RData::TXT(t) = r {
                            String::from_utf8(t.txt_data.concat()).ok()
                        } else {
                            None
                        }
                    })
                    .collect();
                ensure!(txt.len() == 1, "missing or ambiguous DKIM2 key");
                super::verify_dkim::verify_bytes(&txt[0], key.algorithm, &input, &key.signature)?;
            }
            previous = Some(sig);
            signatures.push(sig.clone());
        }
        let mut reconstructed = raw.to_vec();
        let mut work = 0usize;
        for (_, mi) in chain.instances.values().rev() {
            work = work.saturating_add(reconstructed.len());
            ensure!(work <= 256 * 1024 * 1024, "DKIM2 reconstruction budget");
            let current = Message::parse(&reconstructed)?;
            let (h, b) = hashes(&current);
            ensure!(h == mi.header_hash, "DKIM2 header hash mismatch");
            if !body_present {
                break;
            }
            ensure!(b == mi.body_hash, "DKIM2 body hash mismatch");
            if mi.m > 1
                && let Some(recipe) = &mi.recipe
            {
                reconstructed = recipe.apply(&current.headers, current.raw_body())?;
            }
        }
        for sig in &signatures {
            if sig.flags.iter().any(|s| s == "donotmodify") {
                let reference = &chain.instances[&sig.m].1;
                ensure!(
                    chain
                        .instances
                        .range(sig.m..)
                        .all(|(_, (_, m))| m.header_hash == reference.header_hash
                            && m.body_hash == reference.body_hash),
                    "modification forbidden"
                );
            }
            if sig.flags.iter().any(|s| s == "donotexplode") {
                ensure!(
                    !signatures
                        .iter()
                        .any(|s| s.i > sig.i && s.flags.iter().any(|f| f == "exploded")),
                    "list expansion forbidden"
                );
            }
        }
        Ok::<_, crate::error::Error>(Status::Pass)
    }
    .await;
    match result {
        Ok(status) => Outcome {
            status,
            chain: signatures,
            detail: String::new(),
        },
        Err(e) => Outcome {
            status: if temporary {
                Status::Temporary
            } else {
                Status::Fail
            },
            chain: signatures,
            detail: e.to_string(),
        },
    }
}

/// Authenticates both the DSN and its returned message, with custody alignment.
/// Header-only returns authenticate the recorded header hash and chain; a body
/// hash is checked only when the DSN actually includes the original body.
pub async fn verify_dsn(
    raw: &[u8],
    dns: &impl Dns,
    envelope: &Envelope,
    now: u64,
) -> Result<(Outcome, Outcome)> {
    use workglen_mime::{MessageParser, MimeHeaders, PartType};
    ensure!(raw.len() <= 64 * 1024 * 1024, "DSN input limit");
    let mime = MessageParser::default()
        .parse(raw)
        .ok_or_else(|| crate::error!("invalid DSN MIME"))?;
    ensure!(mime.parts.len() <= 1024, "DSN MIME limit");
    let PartType::Multipart(children) = &mime.root_part().body else {
        crate::bail!("multipart DSN required")
    };
    let mut returned = None;
    for id in children {
        let part = &mime.parts[*id as usize];
        let full = part.is_content_type("message", "rfc822");
        if full || part.is_content_type("text", "rfc822-headers") {
            ensure!(returned.is_none(), "ambiguous returned message");
            returned = Some((
                raw.get(part.offset_body as usize..part.offset_end as usize)
                    .ok_or_else(|| crate::error!("invalid MIME range"))?,
                full,
            ));
        }
    }
    let (returned, full) = returned.ok_or_else(|| crate::error!("returned message missing"))?;
    let mut bytes = returned.to_vec();
    if !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
        if !bytes.ends_with(b"\r\n") {
            bytes.extend(b"\r\n");
        }
        bytes.extend(b"\r\n");
    }
    let msg = Message::parse(&bytes)?;
    let chain = Chain::parse(&msg)?;
    let top = &chain
        .signatures
        .last_key_value()
        .ok_or_else(|| crate::error!("unsigned returned message"))?
        .1
        .1;
    let Hop::Real(binding) = &top.hop else {
        crate::bail!("returned message lacks envelope")
    };
    let outer = verify(raw, dns, envelope, now).await;
    ensure!(
        outer.status == Status::Pass,
        "DSN verification: {}",
        outer.detail
    );
    let inner = verify_inner(&bytes, dns, binding, now, full).await;
    ensure!(
        inner.status == Status::Pass,
        "returned-message verification: {}",
        inner.detail
    );
    let signer = &outer.chain.last().unwrap().domain;
    ensure!(
        binding
            .rcpt_to
            .iter()
            .any(|r| address(r).is_ok_and(|(_, d)| within(d, signer)))
            && envelope
                .rcpt_to
                .iter()
                .any(|r| address(r).is_ok_and(|(_, d)| within(d, &top.domain))),
        "DSN custody alignment failed"
    );
    Ok((outer, inner))
}
