use crate::error::{Result, bail, ensure};
use std::{fs, path::Path};

#[cfg(test)]
#[path = "config_toml_tests.rs"]
mod toml_tests;

#[derive(Debug, Clone)]
pub struct Config {
    /// Local administration and optional Accounting, without mail listeners.
    pub admin_only: bool,
    /// Owner-only key for the dedicated encrypted local Admin store.
    pub admin_storage_key_file: Option<String>,
    pub mode: Mode,
    pub node_id: String,
    pub security_remotes: Vec<crate::security_remote::Remote>,
    pub web: Option<Web>,
    pub webmail: Option<Webmail>,
    pub accounting: Option<crate::accounting::Config>,
    pub hostname: String,
    pub dns_server: Option<std::net::SocketAddr>,
    pub domain: String,
    pub data_dir: String,
    pub admin_listen: std::net::SocketAddr,
    pub admin_token_file: String,
    pub role: Role,
    pub tls_cert: String,
    pub tls_key: String,
    pub acme: Option<crate::certificates::AcmeSettings>,
    pub smtp_listen: String,
    pub submission_listen: String,
    pub imap_listen: String,
    pub limits: Limits,
    pub policy: Policy,
    pub replication: Replication,
    pub witness: Option<Witness>,
    pub relay: Option<Relay>,
    pub direct: Option<Direct>,
    pub dkim: Option<Dkim>,
}
// Keep new optional fields at the end so legacy positional fixtures remain decodable.
pratique::data_decode!(Config, deny_unknown=true, { admin_only = Default::default(), mode = Default::default(), node_id = default_node_id(), security_remotes = Default::default(), web, webmail, accounting, hostname, dns_server, domain, data_dir, admin_listen, admin_token_file, role, tls_cert = Default::default(), tls_key = Default::default(), acme, smtp_listen, submission_listen, imap_listen, limits = Default::default(), policy = Default::default(), replication, witness, relay, direct, dkim, admin_storage_key_file = Default::default() });

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    Single,
    #[default]
    Dual,
}
impl pratique::data::Encode for Mode {
    fn encode(&self) -> Result<pratique::data::Node, pratique::data::Error> {
        pratique::data::Encode::encode(match self {
            Self::Single => "single",
            Self::Dual => "dual",
        })
    }
}
impl pratique::data::Decode for Mode {
    fn decode(n: pratique::data::Node) -> Result<Self, pratique::data::Error> {
        let at = n.offset;
        match pratique::data::unit_variant(n)?.as_str() {
            "single" => Ok(Self::Single),
            "dual" => Ok(Self::Dual),
            _ => Err(pratique::data::Error::new("unknown Mode variant").at(at)),
        }
    }
}

fn default_node_id() -> String {
    "node-a".into()
}
#[derive(Debug, Clone)]
pub struct Web {
    pub listen: std::net::SocketAddr,
    pub origin: String,
    pub username: String,
    pub password_hash_file: String,
    pub session_minutes: u64,
}
pratique::data_decode!(Web, deny_unknown=true, { listen, origin, username, password_hash_file, session_minutes = default_session_minutes() });

#[derive(Debug, Clone)]
pub struct Webmail {
    pub listen: std::net::SocketAddr,
    pub origin: String,
    pub session_minutes: u64,
}
pratique::data_decode!(Webmail, deny_unknown=true, { listen, origin, session_minutes = default_session_minutes() });

impl Webmail {
    pub fn validate(&self) -> Result<()> {
        Web {
            listen: self.listen,
            origin: self.origin.clone(),
            username: "validation".into(),
            password_hash_file: "/unused".into(),
            session_minutes: self.session_minutes,
        }
        .validate()
    }
}
fn default_session_minutes() -> u64 {
    30
}
impl Web {
    pub fn validate(&self) -> Result<()> {
        let u = crate::url::Url::parse(&self.origin)?;
        ensure!(
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
                && u.path() == "/"
                && u.origin().ascii_serialization() == self.origin,
            "web.origin must be a canonical HTTPS origin without a trailing slash"
        );
        ensure!(
            (1..=60).contains(&self.session_minutes),
            "web session_minutes must be 1..60"
        );
        ensure!(
            !self.username.is_empty()
                && self.username.len() <= 64
                && self
                    .username
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_@.".contains(&b)),
            "invalid web username"
        );
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Primary,
    Standby,
}
impl pratique::data::Decode for Role {
    fn decode(n: pratique::data::Node) -> Result<Self, pratique::data::Error> {
        let at = n.offset;
        match pratique::data::unit_variant(n)?.as_str() {
            "primary" => Ok(Self::Primary),
            "standby" => Ok(Self::Standby),
            _ => Err(pratique::data::Error::new("unknown Role variant").at(at)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub connections: usize,
    pub data_transfers: usize,
    pub message_bytes: usize,
    pub recipients: usize,
    pub session_seconds: u64,
    pub io_seconds: u64,
    pub auth_seconds: u64,
    pub commands: usize,
    pub mailbox_messages: usize,
    pub quota_bytes: u64,
    pub queue_messages: usize,
}
pratique::data_encode!(Limits {
    connections,
    data_transfers,
    message_bytes,
    recipients,
    session_seconds,
    io_seconds,
    auth_seconds,
    commands,
    mailbox_messages,
    quota_bytes,
    queue_messages
});
pratique::data_decode!(Limits, deny_unknown=true, { connections = Self::default().connections, data_transfers = Self::default().data_transfers, message_bytes = Self::default().message_bytes, recipients = Self::default().recipients, session_seconds = Self::default().session_seconds, io_seconds = Self::default().io_seconds, auth_seconds = Self::default().auth_seconds, commands = Self::default().commands, mailbox_messages = Self::default().mailbox_messages, quota_bytes = Self::default().quota_bytes, queue_messages = Self::default().queue_messages });

impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: 16,
            data_transfers: 2,
            message_bytes: 10 * 1024 * 1024,
            recipients: 25,
            session_seconds: 1800,
            io_seconds: 60,
            auth_seconds: 20,
            commands: 10000,
            mailbox_messages: 10000,
            quota_bytes: 1024 * 1024 * 1024,
            queue_messages: 1000,
        }
    }
}
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub reject_spf_fail: bool,
    pub reject_dkim_fail: bool,
    pub require_dkim: bool,
    pub blocked_senders: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub blocked_ips: Vec<String>,
    pub quarantine_dmarc: bool,
}
pratique::data_encode!(Policy {
    reject_spf_fail,
    reject_dkim_fail,
    require_dkim,
    blocked_senders,
    blocked_domains,
    blocked_ips,
    quarantine_dmarc
});
pratique::data_decode!(Policy, deny_unknown=true, { reject_spf_fail = Self::default().reject_spf_fail, reject_dkim_fail = Self::default().reject_dkim_fail, require_dkim = Self::default().require_dkim, blocked_senders = Self::default().blocked_senders, blocked_domains = Self::default().blocked_domains, blocked_ips = Self::default().blocked_ips, quarantine_dmarc = Self::default().quarantine_dmarc });

#[derive(Debug, Clone)]
pub struct Replication {
    pub cluster_id: String,
    pub listen: String,
    pub peer_address: String,
    pub peer_name: String,
    pub ca_file: String,
    pub token_file: String,
}
pratique::data_decode!(Replication, deny_unknown=true, { cluster_id, listen = Default::default(), peer_address = Default::default(), peer_name = Default::default(), ca_file = Default::default(), token_file = Default::default() });

#[derive(Debug, Clone)]
pub struct Relay {
    pub address: String,
    pub server_name: String,
    pub ca_file: String,
    pub username: String,
    pub password_file: String,
}
pratique::data_decode!(Relay, deny_unknown=true, { address, server_name, ca_file, username, password_file });

#[derive(Debug, Clone)]
pub struct Dkim {
    pub selector: String,
    pub key_file: String,
}
pratique::data_decode!(Dkim, deny_unknown=true, { selector, key_file });

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DeliveryTls {
    #[default]
    Required,
    Opportunistic,
}
impl pratique::data::Encode for DeliveryTls {
    fn encode(&self) -> Result<pratique::data::Node, pratique::data::Error> {
        pratique::data::Encode::encode(match self {
            Self::Required => "required",
            Self::Opportunistic => "opportunistic",
        })
    }
}
impl pratique::data::Decode for DeliveryTls {
    fn decode(n: pratique::data::Node) -> Result<Self, pratique::data::Error> {
        let at = n.offset;
        match pratique::data::unit_variant(n)?.as_str() {
            "required" => Ok(Self::Required),
            "opportunistic" => Ok(Self::Opportunistic),
            _ => Err(pratique::data::Error::new("unknown DeliveryTls variant").at(at)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Direct {
    pub tls: DeliveryTls,
    pub ca_file: Option<String>,
    pub port: u16,
    pub allow_private_addresses: bool,
    pub own_addresses: Vec<std::net::IpAddr>,
    pub retry_seconds: u64,
}
pratique::data_decode!(Direct, deny_unknown=true, { tls = Self::default().tls, ca_file = Self::default().ca_file, port = Self::default().port, allow_private_addresses = Self::default().allow_private_addresses, own_addresses = Self::default().own_addresses, retry_seconds = Self::default().retry_seconds });

impl Default for Direct {
    fn default() -> Self {
        Self {
            tls: DeliveryTls::Required,
            ca_file: None,
            port: 25,
            allow_private_addresses: false,
            own_addresses: Vec::new(),
            retry_seconds: 1800,
        }
    }
}
impl Config {
    pub fn outbound_enabled(&self) -> bool {
        self.direct.is_some() || self.relay.is_some()
    }
    pub fn witness(&self) -> Result<&Witness> {
        self.witness
            .as_ref()
            .ok_or_else(|| crate::error!("dual mode requires [witness]"))
    }
    pub fn node_id(&self) -> &str {
        self.witness
            .as_ref()
            .map(|w| w.node_id.as_str())
            .unwrap_or(&self.node_id)
    }

    pub fn load(path: &str) -> Result<Self> {
        let c: Self = workglen_toml::from_str(&fs::read_to_string(path)?)?;
        if c.admin_only {
            ensure!(c.mode == Mode::Single, "admin_only requires single mode");
            ensure!(
                c.admin_storage_key_file
                    .as_deref()
                    .is_some_and(|path| Path::new(path).is_absolute()),
                "admin_only requires an absolute admin_storage_key_file"
            );
            ensure!(
                c.web.as_ref().is_some_and(|w| w.listen.ip().is_loopback()),
                "admin_only requires a loopback HTTPS administration listener"
            );
            ensure!(
                c.webmail.is_none() && c.direct.is_none() && c.relay.is_none() && c.dkim.is_none(),
                "admin_only does not run Mail, Webmail or outbound delivery"
            );
            ensure!(
                c.acme.is_none(),
                "Use a local certificate for the loopback Admin console"
            );
        } else {
            ensure!(
                c.admin_storage_key_file.is_none(),
                "admin_storage_key_file is only valid with admin_only=true"
            );
        }
        let mut names = vec![c.hostname.clone()];
        for origin in [
            c.web.as_ref().map(|w| &w.origin),
            c.webmail.as_ref().map(|w| &w.origin),
        ]
        .into_iter()
        .flatten()
        {
            names.push(
                crate::url::Url::parse(origin)?
                    .host_str()
                    .ok_or_else(|| crate::error!("HTTPS origin needs a hostname"))?
                    .to_owned(),
            );
        }
        crate::certificates::validate(
            &c.tls_cert,
            &c.tls_key,
            c.acme.as_ref(),
            &names.iter().map(String::as_str).collect::<Vec<_>>(),
        )?;
        let mut ids = std::collections::HashSet::new();
        for remote in &c.security_remotes {
            remote.validate()?;
            ensure!(ids.insert(&remote.id), "Duplicate security instance ID");
        }
        if let Some(a) = &c.accounting {
            a.validate()?;
        }
        ensure!(
            domain(&c.hostname) && domain(&c.domain),
            "invalid hostname/domain"
        );
        ensure!(
            (1..=32).contains(&c.limits.connections),
            "connections must be 1..32"
        );
        ensure!(
            (1..=2).contains(&c.limits.data_transfers),
            "data_transfers must be 1..2"
        );
        ensure!(
            (1024..=10 * 1024 * 1024).contains(&c.limits.message_bytes),
            "message_bytes must be 1 KiB..10 MiB"
        );
        ensure!(
            (1..=100).contains(&c.limits.recipients),
            "recipients must be 1..100"
        );
        ensure!(
            c.limits.mailbox_messages <= 10000 && c.limits.mailbox_messages > 0,
            "mailbox_messages must be 1..10000"
        );
        ensure!(
            !c.node_id().is_empty()
                && c.node_id().len() <= 32
                && c.node_id()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid node id"
        );
        match c.mode {
            Mode::Single => {
                ensure!(
                    c.role == Role::Primary,
                    "single mode must have role=primary"
                );
                ensure!(
                    c.witness.is_none(),
                    "remove witness configuration in single mode"
                );
            }
            Mode::Dual => {
                let w = c.witness()?;
                w.address.parse::<std::net::SocketAddr>()?;
                ensure!(domain(&w.server_name), "invalid witness name");
                c.replication.listen.parse::<std::net::SocketAddr>()?;
                c.replication.peer_address.parse::<std::net::SocketAddr>()?;
                ensure!(domain(&c.replication.peer_name), "invalid peer name");
            }
        }
        if let Some(w) = &c.web {
            w.validate()?;
        }
        if let Some(w) = &c.webmail {
            w.validate()?;
            if let Some(admin) = &c.web {
                ensure!(
                    w.listen != admin.listen && w.origin != admin.origin,
                    "Webmail requires its own HTTPS listener and origin"
                );
            }
        }
        ensure!(
            c.replication.cluster_id.len() >= 16
                && c.replication.cluster_id.len() <= 64
                && c.replication
                    .cluster_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "cluster_id must be 16..64 safe characters"
        );
        ensure!(
            c.limits.io_seconds > 0
                && c.limits.session_seconds >= c.limits.io_seconds
                && c.limits.auth_seconds > 0,
            "invalid timeouts"
        );
        ensure!(
            Path::new(&c.data_dir).is_absolute(),
            "data_dir must be absolute"
        );
        for s in [&c.smtp_listen, &c.submission_listen, &c.imap_listen] {
            s.parse::<std::net::SocketAddr>()?;
        }
        ensure!(
            c.admin_listen.ip().is_loopback(),
            "admin_listen must be loopback"
        );
        if let Some(r) = &c.relay {
            endpoint(&r.address)?;
            ensure!(domain(&r.server_name), "invalid relay name");
        }
        ensure!(
            c.relay.is_none() || c.direct.is_none(),
            "choose [direct] or [relay], not both"
        );
        if let Some(d) = &c.direct {
            ensure!(c.dkim.is_some(), "direct delivery requires [dkim]");
            ensure!(
                d.port > 0 && (1..=3600).contains(&d.retry_seconds),
                "invalid direct port or retry_seconds"
            );
            ensure!(d.own_addresses.len() <= 32, "too many own_addresses");
        }
        if let Some(d) = &c.dkim {
            ensure!(
                domain(&d.selector) && d.selector.len() <= 63,
                "invalid DKIM selector"
            );
            ensure!(
                format!("{}._domainkey.{}", d.selector, c.domain).len() <= 253,
                "DKIM DNS name too long"
            );
            ensure!(
                Path::new(&d.key_file).is_absolute(),
                "DKIM key_file must be absolute"
            );
        }
        Ok(c)
    }
}
pub fn endpoint(value: &str) -> Result<(String, u16)> {
    if let Ok(addr) = value.parse::<std::net::SocketAddr>() {
        ensure!(addr.port() > 0, "endpoint port must be nonzero");
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| crate::error!("endpoint requires host:port"))?;
    let port: u16 = port.parse()?;
    ensure!(domain(host) && port > 0, "invalid endpoint host or port");
    Ok((host.to_ascii_lowercase(), port))
}
pub fn domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
pub fn address(s: &str) -> Result<String> {
    let (local, host) = s
        .rsplit_once('@')
        .ok_or_else(|| crate::error!("address requires domain"))?;
    ensure!(
        !local.is_empty() && local.len() <= 64 && s.len() <= 254 && domain(host),
        "invalid address"
    );
    // Deliberately support ASCII dot-atom mailboxes only; never advertise SMTPUTF8.
    ensure!(
        !local.starts_with('.')
            && !local.ends_with('.')
            && !local.contains("..")
            && local
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b)),
        "unsupported local part"
    );
    Ok(s.to_ascii_lowercase())
}
pub fn folder(s: &str) -> Result<String> {
    if s.eq_ignore_ascii_case("inbox") {
        return Ok("INBOX".into());
    }
    if s.is_empty()
        || s.len() > 128
        || !s
            .bytes()
            .all(|b| (32..127).contains(&b) && !b"\\\"/".contains(&b))
    {
        bail!("folder must be a flat ASCII or modified UTF-7 name (max 128 bytes)");
    }
    Ok(s.into())
}
pub fn secret(path: &str) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let m = fs::metadata(path)?;
    ensure!(
        m.permissions().mode() & 0o077 == 0,
        "secret {path} must have mode 0600 or stricter"
    );
    let s = fs::read_to_string(path)?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    ensure!(
        !s.is_empty() && s.len() <= 1024 && !s.contains(['\r', '\n', '\0']),
        "invalid secret"
    );
    Ok(s)
}
#[derive(Clone, Debug)]
pub struct User {
    pub password_hash: String,
    pub quota: u64,
}
pratique::data_encode!(User {
    password_hash,
    quota
});
pratique::data_decode!(User, deny_unknown=false, { password_hash, quota });

#[derive(Clone, Debug)]
pub struct Folder {
    pub validity: u32,
    pub next_uid: u32,
    pub subscribed: bool,
}
pratique::data_encode!(Folder {
    validity,
    next_uid,
    subscribed
});
pratique::data_decode!(Folder, deny_unknown=false, { validity, next_uid, subscribed });

#[derive(Clone, Debug)]
pub struct Message {
    pub blob: String,
    pub uid: u32,
    pub flags: Vec<String>,
    pub size: usize,
    pub date: i64,
}
pratique::data_encode!(Message {
    blob,
    uid,
    flags,
    size,
    date
});
pratique::data_decode!(Message, deny_unknown=false, { blob, uid, flags, size, date });

#[derive(Clone, Debug)]
pub struct QueueItem {
    pub blob: String,
    pub sender: String,
    pub recipient: String,
    pub attempts: u32,
    pub next_try: i64,
    pub created: i64,
    pub status: String,
    pub last_error: String,
    pub dkim_signed: bool,
}
pratique::data_encode!(QueueItem {
    blob,
    sender,
    recipient,
    attempts,
    next_try,
    created,
    status,
    last_error,
    dkim_signed
});
pratique::data_decode!(QueueItem, deny_unknown=false, { blob, sender, recipient, attempts, next_try, created, status, last_error, dkim_signed });

#[derive(Debug, Clone)]
pub struct Witness {
    pub address: String,
    pub server_name: String,
    pub ca_file: String,
    pub token_file: String,
    pub node_id: String,
}
pratique::data_decode!(Witness, deny_unknown=true, { address, server_name, ca_file, token_file, node_id });

/// RFC 5321 EHLO accepts a domain or an IPv4/IPv6 address literal.
pub fn greeting(s: &str) -> bool {
    domain(s)
        || s.strip_prefix('[')
            .and_then(|v| v.strip_suffix(']'))
            .is_some_and(|v| {
                if let Some(ip) = v
                    .get(..5)
                    .filter(|p| p.eq_ignore_ascii_case("IPv6:"))
                    .map(|_| &v[5..])
                {
                    ip.parse::<std::net::Ipv6Addr>().is_ok()
                } else {
                    v.parse::<std::net::Ipv4Addr>().is_ok()
                }
            })
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    pratique::data_encode!(Config {
        admin_only,
        // Test-only legacy encoder: decoding the optional key field is covered
        // separately and existing serialized Config fixtures stay stable.
        admin_storage_key_file => |_| true,
        mode,
        node_id,
        security_remotes,
        web,
        webmail,
        accounting,
        hostname,
        dns_server,
        domain,
        data_dir,
        admin_listen,
        admin_token_file,
        role,
        tls_cert,
        tls_key,
        acme,
        smtp_listen,
        submission_listen,
        imap_listen,
        limits,
        policy,
        replication,
        witness,
        relay,
        direct,
        dkim
    });
    #[test]
    fn record_contract_config() {
        crate::data_contracts::check::<Config>(
            "src_config_Config",
            &[
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{}"###,
                r###"[true,"single","sample-\u00e9\ud83d\ude00",[],null,null,null,"sample-\u00e9\ud83d\ude00",null,"sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","127.0.0.1:12345","sample-\u00e9\ud83d\ude00","primary","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",null,"sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},null,null,null,null]"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"unexpected_field":1}"###,
                r###"{"hostname":"sample-\u00e9\ud83d\ude00","domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}}"###,
                r###"{"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":"wrong","mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"admin_only":true}"###,
                r###"{"admin_only":true,"node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"wrong","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"mode":"single"}"###,
                r###"{"admin_only":true,"mode":"single","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":false,"security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"node_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":"wrong","web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"security_remotes":[]}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":"wrong","webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"web":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615},"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":"wrong","accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"webmail":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615},"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":"wrong","hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"accounting":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"verified-tls"},"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":false,"dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"hostname":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":"wrong","domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"dns_server":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":"127.0.0.1:12345","domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":false,"data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"domain":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":false,"admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"data_dir":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"wrong","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"admin_listen":"127.0.0.1:12345"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":false,"role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"admin_token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"wrong","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"role":"primary"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":false,"tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"tls_cert":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":false,"acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"tls_key":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":"wrong","smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"acme":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true},"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":false,"submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"smtp_listen":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":false,"imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"submission_listen":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":false,"limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"imap_listen":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":"wrong","policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":"wrong","replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":"wrong","witness":null,"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":"wrong","relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"witness":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00"},"relay":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":"wrong","direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"relay":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00"},"direct":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":"wrong","dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"direct":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615},"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":"wrong"}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":null,"dkim":null}"###,
                r###"{"admin_only":true,"mode":"single","node_id":"sample-\u00e9\ud83d\ude00","security_remotes":[],"web":null,"webmail":null,"accounting":null,"hostname":"sample-\u00e9\ud83d\ude00","dns_server":null,"domain":"sample-\u00e9\ud83d\ude00","data_dir":"sample-\u00e9\ud83d\ude00","admin_listen":"127.0.0.1:12345","admin_token_file":"sample-\u00e9\ud83d\ude00","role":"primary","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":"sample-\u00e9\ud83d\ude00","submission_listen":"sample-\u00e9\ud83d\ude00","imap_listen":"sample-\u00e9\ud83d\ude00","limits":{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535},"policy":{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true},"replication":{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"},"witness":null,"relay":null,"direct":null,"dkim":{"selector":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00"}}"###,
            ],
        );
    }
    #[test]
    fn record_contract_mode() {
        crate::data_contracts::check::<Mode>(
            "src_config_Mode",
            &[
                r###""single""###,
                r###""invalid""###,
                r###"null"###,
                r###"{"single":null}"###,
                r###"{"single":{}}"###,
            ],
        );
    }
    pratique::data_encode!(Web {
        listen,
        origin,
        username,
        password_hash_file,
        session_minutes
    });
    #[test]
    fn record_contract_web() {
        crate::data_contracts::check::<Web>(
            "src_config_Web",
            &[
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{}"###,
                r###"["127.0.0.1:12345","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",18446744073709551615]"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615,"unexpected_field":1}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{"listen":"wrong","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615,"listen":"127.0.0.1:12345"}"###,
                r###"{"listen":"127.0.0.1:12345","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{"listen":"127.0.0.1:12345","origin":false,"username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615,"origin":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":false,"password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615,"username":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":false,"session_minutes":18446744073709551615}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615,"password_hash_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":"wrong"}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_hash_file":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615,"session_minutes":18446744073709551615}"###,
            ],
        );
    }
    pratique::data_encode!(Webmail {
        listen,
        origin,
        session_minutes
    });
    #[test]
    fn record_contract_webmail() {
        crate::data_contracts::check::<Webmail>(
            "src_config_Webmail",
            &[
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{}"###,
                r###"["127.0.0.1:12345","sample-\u00e9\ud83d\ude00",18446744073709551615]"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615,"unexpected_field":1}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"origin":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{"listen":"wrong","origin":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615,"listen":"127.0.0.1:12345"}"###,
                r###"{"listen":"127.0.0.1:12345","session_minutes":18446744073709551615}"###,
                r###"{"listen":"127.0.0.1:12345","origin":false,"session_minutes":18446744073709551615}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615,"origin":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","session_minutes":"wrong"}"###,
                r###"{"listen":"127.0.0.1:12345","origin":"sample-\u00e9\ud83d\ude00","session_minutes":18446744073709551615,"session_minutes":18446744073709551615}"###,
            ],
        );
    }
    impl pratique::data::Encode for Role {
        fn encode(&self) -> Result<pratique::data::Node, pratique::data::Error> {
            pratique::data::Encode::encode(match self {
                Self::Primary => "primary",
                Self::Standby => "standby",
            })
        }
    }
    #[test]
    fn record_contract_role() {
        crate::data_contracts::check::<Role>(
            "src_config_Role",
            &[
                r###""primary""###,
                r###""invalid""###,
                r###"null"###,
                r###"{"primary":null}"###,
                r###"{"primary":{}}"###,
            ],
        );
    }
    #[test]
    fn record_contract_limits() {
        crate::data_contracts::check::<Limits>(
            "src_config_Limits",
            &[
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{}"###,
                r###"[65535,65535,65535,65535,18446744073709551615,18446744073709551615,18446744073709551615,65535,65535,18446744073709551615,65535]"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"unexpected_field":1}"###,
                r###"{"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":"wrong","data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"connections":65535}"###,
                r###"{"connections":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":"wrong","message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"data_transfers":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":"wrong","recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"message_bytes":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":"wrong","session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"recipients":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":"wrong","io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"session_seconds":18446744073709551615}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":"wrong","auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"io_seconds":18446744073709551615}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":"wrong","commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"auth_seconds":18446744073709551615}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":"wrong","mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"commands":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":"wrong","quota_bytes":18446744073709551615,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"mailbox_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":"wrong","queue_messages":65535}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"quota_bytes":18446744073709551615}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":"wrong"}"###,
                r###"{"connections":65535,"data_transfers":65535,"message_bytes":65535,"recipients":65535,"session_seconds":18446744073709551615,"io_seconds":18446744073709551615,"auth_seconds":18446744073709551615,"commands":65535,"mailbox_messages":65535,"quota_bytes":18446744073709551615,"queue_messages":65535,"queue_messages":65535}"###,
            ],
        );
    }
    #[test]
    fn record_contract_policy() {
        crate::data_contracts::check::<Policy>(
            "src_config_Policy",
            &[
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{}"###,
                r###"[true,true,true,["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],true]"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true,"unexpected_field":1}"###,
                r###"{"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":"wrong","reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true,"reject_spf_fail":true}"###,
                r###"{"reject_spf_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":"wrong","require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true,"reject_dkim_fail":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":"wrong","blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true,"require_dkim":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":"wrong","blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":"wrong","blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true,"blocked_domains":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":"wrong","quarantine_dmarc":true}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true,"blocked_ips":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":"wrong"}"###,
                r###"{"reject_spf_fail":true,"reject_dkim_fail":true,"require_dkim":true,"blocked_senders":["sample-\u00e9\ud83d\ude00"],"blocked_domains":["sample-\u00e9\ud83d\ude00"],"blocked_ips":["sample-\u00e9\ud83d\ude00"],"quarantine_dmarc":true,"quarantine_dmarc":true}"###,
            ],
        );
    }
    pratique::data_encode!(Replication {
        cluster_id,
        listen,
        peer_address,
        peer_name,
        ca_file,
        token_file
    });
    #[test]
    fn record_contract_replication() {
        crate::data_contracts::check::<Replication>(
            "src_config_Replication",
            &[
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00"]"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","unexpected_field":1}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":false,"listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":false,"peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":false,"peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":false,"ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":false,"token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":false}"###,
                r###"{"cluster_id":"sample-\u00e9\ud83d\ude00","listen":"sample-\u00e9\ud83d\ude00","peer_address":"sample-\u00e9\ud83d\ude00","peer_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    pratique::data_encode!(Relay {
        address,
        server_name,
        ca_file,
        username,
        password_file
    });
    #[test]
    fn record_contract_relay() {
        crate::data_contracts::check::<Relay>(
            "src_config_Relay",
            &[
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00"]"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00","unexpected_field":1}"###,
                r###"{"server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":false,"server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00","address":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":false,"ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":false,"username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":false,"password_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":false}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","username":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00","password_file":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    pratique::data_encode!(Dkim { selector, key_file });
    #[test]
    fn record_contract_dkim() {
        crate::data_contracts::check::<Dkim>(
            "src_config_Dkim",
            &[
                r###"{"selector":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00"]"###,
                r###"{"selector":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","unexpected_field":1}"###,
                r###"{"key_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"selector":false,"key_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"selector":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","selector":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"selector":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"selector":"sample-\u00e9\ud83d\ude00","key_file":false}"###,
                r###"{"selector":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    #[test]
    fn record_contract_deliverytls() {
        crate::data_contracts::check::<DeliveryTls>(
            "src_config_DeliveryTls",
            &[
                r###""required""###,
                r###""invalid""###,
                r###"null"###,
                r###"{"required":null}"###,
                r###"{"required":{}}"###,
            ],
        );
    }
    pratique::data_encode!(Direct {
        tls,
        ca_file,
        port,
        allow_private_addresses,
        own_addresses,
        retry_seconds
    });
    #[test]
    fn record_contract_direct() {
        crate::data_contracts::check::<Direct>(
            "src_config_Direct",
            &[
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615}"###,
                r###"{}"###,
                r###"["required",null,65535,true,["127.0.0.1"],18446744073709551615]"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615,"unexpected_field":1}"###,
                r###"{"ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615}"###,
                r###"{"tls":"wrong","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615,"tls":"required"}"###,
                r###"{"tls":"required","port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615}"###,
                r###"{"tls":"required","ca_file":"wrong","port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615,"ca_file":null}"###,
                r###"{"tls":"required","ca_file":"sample-\u00e9\ud83d\ude00","port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615}"###,
                r###"{"tls":"required","ca_file":null,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615}"###,
                r###"{"tls":"required","ca_file":null,"port":"wrong","allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615,"port":65535}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":"wrong","own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615,"allow_private_addresses":true}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"retry_seconds":18446744073709551615}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":"wrong","retry_seconds":18446744073709551615}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615,"own_addresses":["127.0.0.1"]}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"]}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":"wrong"}"###,
                r###"{"tls":"required","ca_file":null,"port":65535,"allow_private_addresses":true,"own_addresses":["127.0.0.1"],"retry_seconds":18446744073709551615,"retry_seconds":18446744073709551615}"###,
            ],
        );
    }
    #[test]
    fn record_contract_user() {
        crate::data_contracts::check::<User>(
            "src_config_User",
            &[
                r###"{"password_hash":"sample-\u00e9\ud83d\ude00","quota":18446744073709551615}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",18446744073709551615]"###,
                r###"{"password_hash":"sample-\u00e9\ud83d\ude00","quota":18446744073709551615,"unexpected_field":1}"###,
                r###"{"quota":18446744073709551615}"###,
                r###"{"password_hash":false,"quota":18446744073709551615}"###,
                r###"{"password_hash":"sample-\u00e9\ud83d\ude00","quota":18446744073709551615,"password_hash":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"password_hash":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"password_hash":"sample-\u00e9\ud83d\ude00","quota":"wrong"}"###,
                r###"{"password_hash":"sample-\u00e9\ud83d\ude00","quota":18446744073709551615,"quota":18446744073709551615}"###,
            ],
        );
    }
    #[test]
    fn record_contract_folder() {
        crate::data_contracts::check::<Folder>(
            "src_config_Folder",
            &[
                r###"{"validity":4294967295,"next_uid":4294967295,"subscribed":true}"###,
                r###"{}"###,
                r###"[4294967295,4294967295,true]"###,
                r###"{"validity":4294967295,"next_uid":4294967295,"subscribed":true,"unexpected_field":1}"###,
                r###"{"next_uid":4294967295,"subscribed":true}"###,
                r###"{"validity":"wrong","next_uid":4294967295,"subscribed":true}"###,
                r###"{"validity":4294967295,"next_uid":4294967295,"subscribed":true,"validity":4294967295}"###,
                r###"{"validity":4294967295,"subscribed":true}"###,
                r###"{"validity":4294967295,"next_uid":"wrong","subscribed":true}"###,
                r###"{"validity":4294967295,"next_uid":4294967295,"subscribed":true,"next_uid":4294967295}"###,
                r###"{"validity":4294967295,"next_uid":4294967295}"###,
                r###"{"validity":4294967295,"next_uid":4294967295,"subscribed":"wrong"}"###,
                r###"{"validity":4294967295,"next_uid":4294967295,"subscribed":true,"subscribed":true}"###,
            ],
        );
    }
    #[test]
    fn record_contract_message() {
        crate::data_contracts::check::<Message>(
            "src_config_Message",
            &[
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",4294967295,["sample-\u00e9\ud83d\ude00"],65535,-9223372036854775808]"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808,"unexpected_field":1}"###,
                r###"{"uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808}"###,
                r###"{"blob":false,"uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808,"blob":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":"wrong","flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808,"uid":4294967295}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"size":65535,"date":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":"wrong","size":65535,"date":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808,"flags":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"date":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":"wrong","date":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808,"size":65535}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":"wrong"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","uid":4294967295,"flags":["sample-\u00e9\ud83d\ude00"],"size":65535,"date":-9223372036854775808,"date":-9223372036854775808}"###,
            ],
        );
    }
    #[test]
    fn record_contract_queueitem() {
        crate::data_contracts::check::<QueueItem>(
            "src_config_QueueItem",
            &[
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",4294967295,-9223372036854775808,-9223372036854775808,"sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",true]"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true,"unexpected_field":1}"###,
                r###"{"sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":false,"sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true,"blob":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":false,"recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true,"sender":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":false,"attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true,"recipient":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":"wrong","next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true,"attempts":4294967295}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":"wrong","created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true,"next_try":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":"wrong","status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true,"created":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":false,"last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true,"status":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":false,"dkim_signed":true}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true,"last_error":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":"wrong"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","sender":"sample-\u00e9\ud83d\ude00","recipient":"sample-\u00e9\ud83d\ude00","attempts":4294967295,"next_try":-9223372036854775808,"created":-9223372036854775808,"status":"sample-\u00e9\ud83d\ude00","last_error":"sample-\u00e9\ud83d\ude00","dkim_signed":true,"dkim_signed":true}"###,
            ],
        );
    }
    pratique::data_encode!(Witness {
        address,
        server_name,
        ca_file,
        token_file,
        node_id
    });
    #[test]
    fn record_contract_witness() {
        crate::data_contracts::check::<Witness>(
            "src_config_Witness",
            &[
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00"]"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00","unexpected_field":1}"###,
                r###"{"server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":false,"server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00","address":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":false,"ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":false,"token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":false,"node_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":false}"###,
                r###"{"address":"sample-\u00e9\ud83d\ude00","server_name":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00","node_id":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
}
