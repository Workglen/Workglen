//! Bounded SMTP routing through the configured recursive DNS resolver.
use crate::error::{Context, Result, bail, ensure};
use crate::{app::App, config, relay::Permanent};
use std::net::{IpAddr, SocketAddr};
use workglen_dns::{Error as NetError, RData, RecordType};

#[derive(Debug)]
pub struct Target {
    pub host: String,
    pub address: SocketAddr,
    preference: u16,
}

fn absent(e: &crate::error::Error) -> bool {
    e.downcast_ref::<NetError>()
        .is_some_and(NetError::is_no_records_found)
}
fn nxdomain(e: &crate::error::Error) -> bool {
    e.downcast_ref::<NetError>()
        .is_some_and(NetError::is_nx_domain)
}
fn normalized(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
pub fn public_address(ip: IpAddr) -> bool {
    match normalized(ip) {
        IpAddr::V4(v) => {
            let n = u32::from(v);
            ![
                (0, 8),
                (0x0a000000, 8),
                (0x64400000, 10),
                (0x7f000000, 8),
                (0xa9fe0000, 16),
                (0xac100000, 12),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc0586300, 24),
                (0xc0a80000, 16),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 3),
            ]
            .iter()
            .any(|(network, bits)| n >> (32 - bits) == network >> (32 - bits))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

/// A and AAAA are queried independently, so one family's failure doesn't hide
/// valid addresses in the other. DNS search suffixes and /etc/hosts are not used.
fn addresses(app: &App, host: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![normalized(ip)]);
    }
    let mut ips = Vec::new();
    let mut temporary = None;
    for kind in [RecordType::A, RecordType::AAAA] {
        match app.checker.lookup(host, kind) {
            Ok(result) => {
                for record in result.answers() {
                    let ip = match &record.data {
                        RData::A(a) => IpAddr::V4(a.0),
                        RData::AAAA(a) => IpAddr::V6(a.0),
                        _ => continue,
                    };
                    let ip = normalized(ip);
                    if !ips.contains(&ip) {
                        ensure!(ips.len() < 32, "host exceeds 32-address routing limit");
                        ips.push(ip);
                    }
                }
            }
            Err(e) if absent(&e) => {}
            Err(e) => temporary = Some(e),
        }
    }
    if ips.is_empty()
        && let Some(e) = temporary
    {
        return Err(e).context("address lookup temporarily failed");
    }
    Ok(ips)
}

pub fn relay_targets(app: &App, value: &str) -> Result<Vec<SocketAddr>> {
    let (host, port) = config::endpoint(value)?;
    let ips = addresses(app, &host)?;
    ensure!(!ips.is_empty(), "configured relay has no A/AAAA addresses");
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

pub fn direct_targets(app: &App, domain: &str) -> Result<Vec<Target>> {
    let cfg = app.config.direct.as_ref().unwrap();
    let lookup = app.checker.lookup(domain, RecordType::MX);
    let mut mx = Vec::new();
    match lookup {
        Ok(result) => {
            for record in result.answers() {
                if let RData::MX(value) = &record.data {
                    let host = value.exchange.to_ascii().to_ascii_lowercase();
                    mx.push((value.preference, host.trim_end_matches('.').to_string()));
                }
            }
        }
        Err(e) if nxdomain(&e) => {
            return Err(
                Permanent("5.1.2 recipient domain does not exist (NXDOMAIN)".into()).into(),
            );
        }
        Err(e) if absent(&e) => {}
        Err(e) => return Err(e).context("MX lookup temporarily failed"),
    }
    if mx.len() == 1 && mx[0] == (0, String::new()) {
        return Err(Permanent(
            "5.1.10 recipient domain publishes Null MX (accepts no mail)".into(),
        )
        .into());
    }
    ensure!(
        !mx.iter().any(|(_, h)| h.is_empty()),
        "invalid mixed or nonzero Null MX; retry after DNS repair"
    );
    ensure!(mx.len() <= 32, "MX response exceeds 32-host routing limit");
    let implicit = mx.is_empty();
    if implicit {
        mx.push((0, domain.to_string()));
    }
    let mut randomized = Vec::new();
    for (preference, host) in mx {
        ensure!(config::domain(&host), "invalid MX hostname");
        let mut random = [0u8; 8];
        pratique::crypto::rand::fill(&mut random)
            .map_err(|e| crate::error!("MX ordering entropy: {e}"))?;
        randomized.push((preference, u64::from_le_bytes(random), host));
    }
    randomized.sort();
    let own = cfg
        .own_addresses
        .iter()
        .copied()
        .map(normalized)
        .collect::<Vec<_>>();
    let listener = app.config.smtp_listen.parse::<SocketAddr>()?;
    // Discard our MX and every equally/worse-preferred MX, per RFC 5321 5.1.
    let mut cutoff = randomized
        .iter()
        .filter(|(_, _, h)| h.eq_ignore_ascii_case(&app.config.hostname))
        .map(|(p, _, _)| *p)
        .min();
    let mut targets = Vec::new();
    let mut temporary = None;
    let mut blocked = false;
    let dns_until = std::time::Instant::now() + std::time::Duration::from_secs(60);
    for (preference, _, host) in randomized {
        if cutoff.is_some_and(|p| preference >= p) {
            continue;
        }
        app.require_mail()?;
        if std::time::Instant::now() >= dns_until {
            temporary = Some(crate::error!("MX resolution time budget exhausted"));
            break;
        }
        match addresses(app, &host) {
            Ok(ips) => {
                // A test/development custom SMTP port can share an IP with the
                // local listener. Only an exact listener endpoint is self there.
                let is_self = ips.iter().any(|ip| {
                    own.contains(ip)
                        || !listener.ip().is_unspecified()
                            && normalized(listener.ip()) == *ip
                            && listener.port() == cfg.port
                });
                if is_self {
                    cutoff = Some(cutoff.map_or(preference, |p| p.min(preference)));
                    continue;
                }
                for ip in ips {
                    if !cfg.allow_private_addresses && !public_address(ip) {
                        blocked = true;
                        continue;
                    }
                    let address = SocketAddr::new(ip, cfg.port);
                    if !targets
                        .iter()
                        .any(|t: &Target| t.address == address && t.host == host)
                    {
                        ensure!(
                            targets.len() < 128,
                            "MX response exceeds 128-address routing limit"
                        );
                        targets.push(Target {
                            host: host.clone(),
                            address,
                            preference,
                        });
                    }
                }
            }
            Err(e) => temporary = Some(e),
        }
    }
    targets.retain(|t| cutoff.is_none_or(|p| t.preference < p));
    if !targets.is_empty() {
        return Ok(targets);
    }
    if let Some(e) = temporary {
        return Err(e).context("MX address lookup temporarily failed");
    }
    if cutoff.is_some() {
        return Err(
            Permanent("5.4.6 mail routing loop: no MX preferred over this server".into()).into(),
        );
    }
    if blocked {
        return Err(Permanent(
            "5.7.1 all MX destinations are non-public addresses; refused".into(),
        )
        .into());
    }
    if implicit {
        return Err(
            Permanent("5.1.2 domain has neither MX nor A/AAAA mail destination".into()).into(),
        );
    }
    bail!(Permanent(
        "5.4.4 advertised MX hosts have no usable A/AAAA addresses".into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_internal_and_special_destinations() {
        for ip in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.31.1.2",
            "192.168.1.2",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.4",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "3fff::1",
        ] {
            assert!(!public_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2606:4700:4700::1111"] {
            assert!(public_address(ip.parse().unwrap()), "{ip}");
        }
        assert_eq!(
            normalized("::ffff:8.8.8.8".parse().unwrap()),
            IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))
        );
    }
}
