use crate::config;
use crate::error::{Result, ensure};
use crate::mailauth::{self, dkim, dmarc, spf};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use dmarc::Policy;
use std::{net::IpAddr, time::Duration};

pub fn hash(password: &str) -> Result<String> {
    ensure!(
        password.len() >= 12 && password.len() <= 1024,
        "password must be 12..1024 bytes"
    );
    let mut salt = [0; 16];
    pratique::crypto::rand::fill(&mut salt).map_err(|e| crate::error!("{e}"))?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| crate::error!("{e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| crate::error!("{e}"))?
        .to_string())
}
pub fn verify(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded).ok().is_some_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}
pub struct AuthContext<'a> {
    pub ip: IpAddr,
    pub helo: &'a str,
    pub from: &'a str,
    pub hostname: &'a str,
    pub policy: &'a config::Policy,
    pub seconds: u64,
}
pub struct Checker {
    resolver: workglen_dns::Resolver,
}
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Accept,
    Quarantine,
    Reject(&'static str),
    Temporary,
}
impl Checker {
    pub(crate) fn lookup(
        &self,
        name: &str,
        kind: workglen_dns::RecordType,
    ) -> Result<workglen_dns::Lookup> {
        // Fully qualified queries never leak into a system DNS search suffix.
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        pratique::asyncio::block_on(async {
            Ok(pratique::asyncio::timeout(
                Duration::from_secs(10),
                self.resolver.lookup(fqdn, kind),
            )
            .await??)
        })
    }
    pub fn new(dns: Option<std::net::SocketAddr>) -> Result<Self> {
        let cfg = if let Some(addr) = dns {
            workglen_dns::Config::new(vec![addr])
        } else {
            workglen_dns::Config::system()?
        };
        let resolver = workglen_dns::Resolver::new(cfg)?;
        Ok(Self { resolver })
    }
    pub fn check(
        &self,
        raw: &[u8],
        ip: IpAddr,
        helo: &str,
        from: &str,
        c: &config::Config,
    ) -> Result<Verdict> {
        self.check_context(
            raw,
            AuthContext {
                ip,
                helo,
                from,
                hostname: &c.hostname,
                policy: &c.policy,
                seconds: c.limits.auth_seconds,
            },
        )
    }
    pub fn check_context(&self, raw: &[u8], context: AuthContext<'_>) -> Result<Verdict> {
        let AuthContext {
            ip,
            helo,
            from,
            hostname: _,
            policy,
            seconds,
        } = context;
        validate(raw)?;
        let from_addresses = mailauth::from_addresses(raw)?;
        ensure!(
            from_addresses.len() == 1,
            "exactly one From address required"
        );
        let author = config::address(&from_addresses[0])?;
        if blocked(&author, policy) || blocked(from, policy) {
            return Ok(Verdict::Reject("sender blocked"));
        }
        let domain = from.rsplit_once('@').map(|(_, d)| d).unwrap_or(helo);
        Ok(pratique::asyncio::block_on(async {
            pratique::asyncio::timeout(Duration::from_secs(seconds), async {
                let spf = spf::verify(
                    &self.resolver,
                    spf::Parameters {
                        ip,
                        helo,
                        sender: from,
                    },
                )
                .await;
                let dkim = match dkim::verify(raw, &self.resolver, mailauth::now()).await {
                    Ok(v) => v,
                    Err(_) => return Verdict::Reject("invalid DKIM headers"),
                };
                let author_domain = author.rsplit_once('@').map(|(_, d)| d).unwrap();
                let dmarc = dmarc::verify(&self.resolver, author_domain, domain, spf, &dkim).await;
                let dkim_pass = dkim.iter().any(|d| d.status == dkim::Status::Pass);
                if dmarc.status == dmarc::Status::Temporary
                    || spf == spf::Status::Temporary
                    || (!dkim_pass && dkim.iter().any(|d| d.status == dkim::Status::Temporary))
                {
                    return Verdict::Temporary;
                }
                if policy.reject_spf_fail && spf == spf::Status::Fail {
                    return Verdict::Reject("SPF failure");
                }
                if policy.require_dkim && !dkim_pass {
                    return Verdict::Reject("passing DKIM signature required");
                }
                if policy.reject_dkim_fail && !dkim_pass && !dkim.is_empty() {
                    return Verdict::Reject("DKIM failure");
                }
                if dmarc.status == dmarc::Status::Fail {
                    match dmarc.policy {
                        Policy::Reject => return Verdict::Reject("DMARC reject policy"),
                        Policy::Quarantine => {
                            return if policy.quarantine_dmarc {
                                Verdict::Quarantine
                            } else {
                                Verdict::Reject("DMARC quarantine policy")
                            };
                        }
                        _ => {}
                    }
                }
                Verdict::Accept
            })
            .await
            .unwrap_or(Verdict::Temporary)
        }))
    }
}
pub fn blocked(address: &str, p: &config::Policy) -> bool {
    p.blocked_senders
        .iter()
        .any(|s| s.eq_ignore_ascii_case(address))
        || address
            .rsplit_once('@')
            .is_some_and(|(_, d)| p.blocked_domains.iter().any(|b| b.eq_ignore_ascii_case(d)))
}
pub const MAX_MIME_DEPTH: usize = 32;

pub fn mime_budget(raw: &[u8]) -> Result<()> {
    ensure!(
        raw.windows(4)
            .filter(|w| *w == b"\r\n--")
            .take(1025)
            .count()
            <= 1024,
        "too many MIME boundaries"
    );
    Ok(())
}
/// Validate the shape before it enters a mailbox. The same nesting ceiling is
/// used by IMAP BODYSTRUCTURE; a sender cannot store a message that exceeds it.
fn mime_shape(raw: &[u8]) -> Result<()> {
    let parsed = workglen_mime::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| crate::error!("cannot parse MIME message"))?;
    let mut pending = vec![(&parsed, 0usize, 0usize)];
    let mut visited = 0usize;
    while let Some((message, id, depth)) = pending.pop() {
        ensure!(depth < MAX_MIME_DEPTH, "MIME nesting too deep");
        visited += 1;
        ensure!(visited <= 1024, "too many MIME parts");
        let part = message
            .parts
            .get(id)
            .ok_or_else(|| crate::error!("missing MIME part"))?;
        match &part.body {
            workglen_mime::PartType::Multipart(children) => {
                ensure!(
                    pending.len() + children.len() <= 1024,
                    "too many MIME parts"
                );
                pending.extend(children.iter().map(|id| (message, *id as usize, depth + 1)));
            }
            workglen_mime::PartType::Message(nested) => pending.push((nested, 0, depth + 1)),
            _ => {}
        }
    }
    Ok(())
}

pub fn validate(raw: &[u8]) -> Result<()> {
    mime_budget(raw)?;
    let end = raw
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or_else(|| crate::error!("missing header separator"))?;
    ensure!(end <= 65536, "headers exceed 64 KiB");
    let mut from = 0;
    let mut fields = 0;
    let mut signatures = 0;
    let mut previous = false;
    for line in raw[..end].split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        ensure!(!line.contains(&0), "NUL header");
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            ensure!(previous, "orphan folded header");
            continue;
        }
        let i = line
            .iter()
            .position(|b| *b == b':')
            .ok_or_else(|| crate::error!("invalid header"))?;
        ensure!(
            i > 0
                && line[..i]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-'),
            "invalid field name"
        );
        previous = true;
        fields += 1;
        let name = String::from_utf8_lossy(&line[..i]);
        if name.eq_ignore_ascii_case("from") {
            from += 1;
        }
        if name.eq_ignore_ascii_case("dkim-signature")
            || name.eq_ignore_ascii_case("dkim2-signature")
        {
            signatures += 1;
        }
    }
    ensure!(
        from == 1 && fields <= 256 && signatures <= 8,
        "invalid or excessive headers"
    );
    mime_shape(raw)
}
