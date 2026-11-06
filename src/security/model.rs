use crate::error::{Result, ensure};
use pratique::json_value::{Value, json};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::Path,
};
pub const MAX_MESSAGE: usize = 10 * 1024 * 1024;
pub const MAX_BODY: usize = 22 * 1024 * 1024;
pub const PERMISSIONS: &[&str] = &[
    "read",
    "rules.write",
    "rules.test",
    "rules.activate",
    "content",
    "release",
    "discard",
    "remediation.preview",
    "remediation.execute",
    "configure",
    "retention",
    "jobs",
    "audit",
    "learn",
    "cluster.operate",
    "cluster.takeover",
];
pub fn now() -> crate::error::Result<i64> {
    Ok(crate::datetime::Utc::now()?.timestamp())
}
pub fn id() -> String {
    crate::store::random_id()
}
pub fn hash(b: &[u8]) -> String {
    use pratique::crypto::sha2::{Hash, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}
pub fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .ok_or_else(|| crate::error!("Missing text field: {k}"))
}
pub fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .ok_or_else(|| crate::error!("Missing integer: {k}"))
}
pub fn arr<'a>(v: &'a Value, k: &str) -> Result<&'a Vec<Value>> {
    v[k].as_array()
        .ok_or_else(|| crate::error!("Missing list: {k}"))
}
pub fn key(v: &str) -> Result<()> {
    ensure!(
        !v.is_empty()
            && v.len() <= 128
            && v.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.@".contains(&c)),
        "Invalid identifier"
    );
    Ok(())
}
pub fn address(v: &str) -> Result<String> {
    crate::config::address(v)
}
#[derive(Clone, Debug)]
pub struct Route {
    pub host: String,
    pub port: u16,
    pub implicit_tls: bool,
    pub public_only: bool,
    pub ca_file: Option<String>,
    pub username: Option<String>,
    pub password_file: Option<String>,
}
pratique::data_encode!(Route { host, port, implicit_tls, public_only => std::ops::Not::not, ca_file, username, password_file });
pratique::data_decode!(Route, deny_unknown=true, { host, port, implicit_tls = Default::default(), public_only = Default::default(), ca_file, username, password_file });

#[derive(Clone, Debug)]
pub struct Connector {
    pub r#type: String,
    pub mailboxes: Vec<String>,
    pub allow_hard_delete: bool,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub ca_file: Option<String>,
    pub password_files: BTreeMap<String, String>,
    pub tenant: Option<String>,
    pub client_id: Option<String>,
    pub secret_file: Option<String>,
    pub token_file: Option<String>,
    pub endpoint: Option<String>,
    pub username: Option<String>,
    pub password_file: Option<String>,
}
pratique::data_encode!(Connector {
    r#type,
    mailboxes,
    allow_hard_delete,
    host,
    port,
    ca_file,
    password_files,
    tenant,
    client_id,
    secret_file,
    token_file,
    endpoint,
    username,
    password_file
});
pratique::data_decode!(Connector, deny_unknown=true, { r#type, mailboxes, allow_hard_delete = Default::default(), host, port, ca_file, password_files = Default::default(), tenant, client_id, secret_file, token_file, endpoint, username, password_file });

#[derive(Clone, Debug)]
pub struct ReplicationPeer {
    pub node_id: String,
    pub origin: String,
    pub ca_file: Option<String>,
    pub key_file: String,
}
pratique::data_encode!(ReplicationPeer {
    node_id,
    origin,
    ca_file,
    key_file
});
pratique::data_decode!(ReplicationPeer, deny_unknown=true, { node_id, origin, ca_file, key_file });

#[derive(Clone, Debug)]
pub struct ReplicationConfig {
    pub peers: Vec<ReplicationPeer>,
    pub durable_copies: u8,
    pub acknowledgement_timeout_seconds: u64,
    pub degraded_acceptance: bool,
    pub max_degraded_operations: u64,
    pub max_degraded_bytes: u64,
}
pratique::data_encode!(ReplicationConfig {
    peers,
    durable_copies,
    acknowledgement_timeout_seconds,
    degraded_acceptance,
    max_degraded_operations,
    max_degraded_bytes
});
pratique::data_decode!(ReplicationConfig, deny_unknown=true, {
    peers,
    durable_copies,
    acknowledgement_timeout_seconds = default_replication_timeout(),
    degraded_acceptance = Default::default(),
    max_degraded_operations = Default::default(),
    max_degraded_bytes = Default::default()
});

fn default_replication_timeout() -> u64 {
    10
}

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: String,
    pub storage_key_file: String,
    pub workspace: String,
    pub instance: String,
    pub origin: String,
    pub hostname: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub acme: Option<crate::certificates::AcmeSettings>,
    pub control_key_file: String,
    pub smtp_listen: (IpAddr, u16),
    pub https_listen: (IpAddr, u16),
    pub require_inbound_tls: bool,
    pub routes: BTreeMap<String, Route>,
    pub connectors: BTreeMap<String, Connector>,
    pub recipient_directory: Option<super::directory::Microsoft365>,
    pub admin_origin: Option<String>,
    pub dns_server: Option<SocketAddr>,
    pub trusted_admin: Option<Actor>,
    pub replication: Option<ReplicationConfig>,
}
pratique::data_decode!(Config, deny_unknown=true, { data_dir, storage_key_file, workspace, instance, origin, hostname, tls_cert = Default::default(), tls_key = Default::default(), acme, control_key_file, smtp_listen, https_listen, require_inbound_tls = Default::default(), routes = Default::default(), connectors = Default::default(), recipient_directory, admin_origin, dns_server, trusted_admin, replication });

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let c: Self = pratique::json_value::from_slice(&std::fs::read(path)?)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        if let Some(directory) = &self.recipient_directory {
            directory.validate()?;
        }
        if let Some(origin) = &self.admin_origin {
            super::directory::admin_origin(origin)?;
        }
        for path in [&self.data_dir, &self.storage_key_file] {
            ensure!(
                Path::new(path).is_absolute()
                    && !Path::new(path)
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir)),
                "Use absolute storage paths without parent traversal"
            );
        }
        ensure!(
            !Path::new(&self.storage_key_file).starts_with(&self.data_dir),
            "Keep the storage key outside the data directory"
        );
        key(&self.workspace)?;
        key(&self.instance)?;
        ensure!(crate::config::domain(&self.hostname), "Invalid hostname");
        let u = crate::url::Url::parse(&self.origin)?;
        crate::certificates::validate(
            &self.tls_cert,
            &self.tls_key,
            self.acme.as_ref(),
            &[&self.hostname, u.host_str().unwrap_or("")],
        )?;
        ensure!(
            u.scheme() == "https"
                && u.origin().ascii_serialization() == self.origin
                && u.path() == "/"
                && u.query().is_none()
                && u.fragment().is_none()
                && u.username().is_empty()
                && u.password().is_none(),
            "Use a canonical HTTPS origin"
        );
        ensure!(
            self.smtp_listen != self.https_listen
                && self.smtp_listen.1 > 0
                && self.https_listen.1 > 0,
            "Distinct nonzero listeners required"
        );
        ensure!(
            crate::config::secret(&self.control_key_file)?.len() >= 32,
            "Management key needs at least 32 characters"
        );
        for (name, r) in &self.routes {
            key(name)?;
            ensure!(
                r.port > 0 && !r.host.is_empty() && !r.host.chars().any(char::is_control),
                "Invalid route"
            );
            ensure!(
                r.password_file.is_some() == r.username.is_some(),
                "SMTP username and password file must be paired"
            );
        }
        for (name, c) in &self.connectors {
            key(name)?;
            ensure!(
                ["graph", "ews", "workglen"].contains(&c.r#type.as_str())
                    && !c.mailboxes.is_empty(),
                "Invalid connector"
            );
            for a in &c.mailboxes {
                address(a)?;
            }
        }
        if let Some(replication) = &self.replication {
            ensure!(
                !replication.peers.is_empty() && replication.peers.len() <= 15,
                "Configure 1–15 replication peers"
            );
            ensure!(
                (2..=replication.peers.len() + 1)
                    .contains(&usize::from(replication.durable_copies)),
                "Durable copies must include the local node and at least one peer"
            );
            ensure!(
                (1..=30).contains(&replication.acknowledgement_timeout_seconds),
                "Replication acknowledgement timeout must be 1–30 seconds"
            );
            ensure!(
                !replication.degraded_acceptance
                    || (replication.max_degraded_operations > 0
                        && replication.max_degraded_bytes > 0),
                "Degraded acceptance requires explicit operation and byte limits"
            );
            ensure!(
                replication.degraded_acceptance
                    || (replication.max_degraded_operations == 0
                        && replication.max_degraded_bytes == 0),
                "Degraded limits require degraded acceptance"
            );
            let mut nodes = std::collections::BTreeSet::new();
            let mut origins = std::collections::BTreeSet::new();
            for peer in &replication.peers {
                key(&peer.node_id)?;
                ensure!(
                    peer.node_id != self.instance,
                    "Replication peer cannot be this node"
                );
                ensure!(
                    nodes.insert(&peer.node_id),
                    "Duplicate replication peer node"
                );
                let origin = crate::url::Url::parse(&peer.origin)?;
                ensure!(
                    origin.scheme() == "https"
                        && origin.origin().ascii_serialization() == peer.origin
                        && origin.path() == "/"
                        && origin.query().is_none()
                        && origin.fragment().is_none()
                        && origin.username().is_empty()
                        && origin.password().is_none(),
                    "Use a canonical HTTPS replication peer origin"
                );
                ensure!(
                    peer.origin != self.origin,
                    "Replication peer cannot use this node origin"
                );
                ensure!(
                    origins.insert(&peer.origin),
                    "Duplicate replication peer origin"
                );
                ensure!(
                    crate::config::secret(&peer.key_file)?.len() >= 32,
                    "Replication peer key needs at least 32 characters"
                );
            }
        }
        Ok(())
    }
    pub fn db_path(&self) -> std::path::PathBuf {
        Path::new(&self.data_dir).join("security.redb")
    }
}
#[derive(Clone, Debug)]
pub struct Actor {
    pub id: String,
    pub permissions: Vec<String>,
    pub domains: Vec<String>,
    pub mailboxes: Vec<String>,
    pub mailbox: Option<String>,
    pub revision: u64,
}
pratique::data_encode!(Actor {
    id,
    permissions,
    domains,
    mailboxes,
    mailbox,
    revision
});
pratique::data_decode!(Actor, deny_unknown=false, { id = Default::default(), permissions = Default::default(), domains = Default::default(), mailboxes = Default::default(), mailbox, revision = Default::default() });

impl Actor {
    pub fn owner(name: &str) -> Self {
        Self {
            id: name.into(),
            permissions: PERMISSIONS.iter().map(|s| s.to_string()).collect(),
            domains: vec!["*".into()],
            mailboxes: vec!["*".into()],
            mailbox: None,
            revision: 0,
        }
    }
    pub fn require(&self, p: &str, recipient: Option<&str>) -> Result<()> {
        if let Some(m) = &self.mailbox {
            ensure!(
                matches!(p, "read" | "content" | "release" | "discard") && recipient == Some(m),
                "Mailbox access denied"
            );
            return Ok(());
        }
        ensure!(
            self.permissions.iter().any(|x| x == p),
            "Permission denied: {p}"
        );
        if let Some(r) = recipient {
            let d = r.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
            ensure!(
                self.domains.iter().any(|x| x == "*" || x == d)
                    && self.mailboxes.iter().any(|x| x == "*" || x == r),
                "Mailbox scope denied"
            );
        }
        Ok(())
    }
    /// Whether every authority represented by `other` is already inside this
    /// actor's effective permission and mailbox/domain grant.
    pub fn covers(&self, other: &Actor) -> bool {
        let scope_covers = |ours: &[String], theirs: &[String]| {
            ours.iter().any(|scope| scope == "*")
                || (!theirs.iter().any(|scope| scope == "*")
                    && theirs.iter().all(|scope| ours.contains(scope)))
        };
        match (&self.mailbox, &other.mailbox) {
            (Some(ours), Some(theirs)) => ours == theirs,
            (Some(_), None) => false,
            (None, Some(mailbox)) => {
                let domain = mailbox
                    .rsplit_once('@')
                    .map(|(_, domain)| domain)
                    .unwrap_or("");
                ["read", "content", "release", "discard"]
                    .iter()
                    .all(|permission| self.permissions.iter().any(|ours| ours == permission))
                    && (self.domains.iter().any(|scope| scope == "*")
                        || self.domains.iter().any(|scope| scope == domain))
                    && (self.mailboxes.iter().any(|scope| scope == "*")
                        || self.mailboxes.iter().any(|scope| scope == mailbox))
            }
            (None, None) => {
                other
                    .permissions
                    .iter()
                    .all(|permission| self.permissions.contains(permission))
                    && scope_covers(&self.domains, &other.domains)
                    && scope_covers(&self.mailboxes, &other.mailboxes)
            }
        }
    }
    pub fn visible(&self, r: &str) -> bool {
        self.require("read", Some(r)).is_ok()
    }
    pub fn global(&self, settings: &Value) -> Result<()> {
        ensure!(
            self.mailbox.is_none()
                && self.mailboxes.iter().any(|x| x == "*")
                && (self.domains.iter().any(|x| x == "*")
                    || arr(settings, "domains")?
                        .iter()
                        .all(|d| self.domains.iter().any(|x| Some(x.as_str()) == d.as_str()))),
            "All configured mailbox scopes are required"
        );
        Ok(())
    }
}
#[derive(Clone)]
pub struct Command {
    pub action: String,
    pub data: Value,
    pub request_id: String,
}
pratique::data_encode!(Command {
    action,
    data,
    request_id
});
pratique::data_decode!(Command, deny_unknown=true, { action, data = Default::default(), request_id });

pub fn settings() -> Value {
    json!({"enabled":false,"domains":[],"routes":{},"mailboxes":{},"protected_people":[],"protected_domains":[],"mixed_script_check":false,"connectors":{},"retention_days":30,"digest_hours":24,"digest_sender":"","max_messages":10000,"max_bytes":1073741824u64,"max_jobs":20000,"min_free_bytes":268435456u64,"scan_input_bytes":10485760,"scan_decoded_bytes":33554432,"scan_parts":200,"scan_concurrency":2,"delivery_concurrency":4,"revision":0,"retrospective_default":false})
}
pub fn rules() -> Value {
    json!([
     {"id":"spam","type":"spam","threshold":6,"action":"quarantine","enabled":true},
     {"id":"links","type":"bad_url","values":[],"action":"quarantine","enabled":true},
     {"id":"sender","type":"sender","values":[],"action":"quarantine","enabled":true},
     {"id":"impersonation","type":"impersonation","threshold":3,"action":"quarantine","enabled":true},
     {"id":"ai-instructions","type":"ai_instructions","threshold":3,"action":"quarantine","enabled":true}
    ])
}
pub fn permission(action: &str) -> Option<&'static str> {
    if matches!(action, "learn" | "learning-reset") {
        return Some("learn");
    }
    if action == "learning" {
        return Some("read");
    }
    crate::security_remote::permission(action).and_then(|x| x.strip_prefix("security."))
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    #[test]
    fn record_contract_route() {
        crate::data_contracts::check::<Route>(
            "src_security_model_Route",
            &[
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",65535,true,true,null,null,null]"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null,"unexpected_field":1}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535}"###,
                r###"{"port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null}"###,
                r###"{"host":false,"port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null,"host":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":"wrong","implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null,"port":65535}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"public_only":true,"ca_file":null,"username":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":"wrong","public_only":true,"ca_file":null,"username":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null,"implicit_tls":true}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"ca_file":null,"username":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":"wrong","ca_file":null,"username":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null,"public_only":true}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"username":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":"wrong","username":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null,"ca_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":"sample-\u00e9\ud83d\ude00","username":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":"wrong","password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null,"username":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":"sample-\u00e9\ud83d\ude00","password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":"wrong"}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":null,"password_file":null}"###,
                r###"{"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"public_only":true,"ca_file":null,"username":null,"password_file":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    #[test]
    fn record_contract_connector() {
        crate::data_contracts::check::<Connector>(
            "src_security_model_Connector",
            &[
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",["sample-\u00e9\ud83d\ude00"],true,null,null,null,{},null,null,null,null,null,null,null]"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"unexpected_field":1}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":false,"mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"type":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":"wrong","allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"mailboxes":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":"wrong","host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"allow_hard_delete":true}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":"wrong","port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"host":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":"sample-\u00e9\ud83d\ude00","port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":"wrong","ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"port":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":65535,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":"wrong","password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"ca_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":"sample-\u00e9\ud83d\ude00","password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":"wrong","tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"password_files":{}}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":"wrong","client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"tenant":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":"sample-\u00e9\ud83d\ude00","client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":"wrong","secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"client_id":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":"sample-\u00e9\ud83d\ude00","secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":"wrong","token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"secret_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":"sample-\u00e9\ud83d\ude00","token_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":"wrong","endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"token_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":"sample-\u00e9\ud83d\ude00","endpoint":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":"wrong","username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"endpoint":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":"sample-\u00e9\ud83d\ude00","username":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":"wrong","password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"username":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":"sample-\u00e9\ud83d\ude00","password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":"wrong"}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":null,"password_file":null}"###,
                r###"{"type":"sample-\u00e9\ud83d\ude00","mailboxes":["sample-\u00e9\ud83d\ude00"],"allow_hard_delete":true,"host":null,"port":null,"ca_file":null,"password_files":{},"tenant":null,"client_id":null,"secret_file":null,"token_file":null,"endpoint":null,"username":null,"password_file":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    pratique::data_encode!(Config {
        data_dir,
        storage_key_file,
        workspace,
        instance,
        origin,
        hostname,
        tls_cert,
        tls_key,
        acme,
        control_key_file,
        smtp_listen,
        https_listen,
        require_inbound_tls,
        routes,
        connectors,
        recipient_directory,
        admin_origin,
        dns_server,
        trusted_admin,
        replication => Option::is_none
    });
    #[test]
    fn record_contract_config() {
        crate::data_contracts::check::<Config>(
            "src_security_model_Config",
            &[
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",null,"sample-\u00e9\ud83d\ude00",["127.0.0.1",12345],["127.0.0.1",12345],true,{},{},null,null,null,null,null]"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"unexpected_field":1}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345]}"###,
                r###"{"storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":false,"storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"data_dir":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":false,"workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"storage_key_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":false,"instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"workspace":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":false,"origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"instance":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":false,"hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"origin":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":false,"tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"hostname":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":false,"tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"tls_cert":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":false,"acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"tls_key":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":"wrong","control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"acme":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true},"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":false,"smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"control_key_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":"wrong","https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"smtp_listen":["127.0.0.1",12345]}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":"wrong","require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"https_listen":["127.0.0.1",12345]}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":"wrong","routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"require_inbound_tls":true}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":"wrong","connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"routes":{}}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":"wrong","recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"connectors":{}}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":"wrong","admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"recipient_directory":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":{"tenant":"sample-\u00e9\ud83d\ude00","client_id":"sample-\u00e9\ud83d\ude00","secret_file":"sample-\u00e9\ud83d\ude00"},"admin_origin":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":"wrong","dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"admin_origin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":"sample-\u00e9\ud83d\ude00","dns_server":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":"wrong","trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"dns_server":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":"127.0.0.1:12345","trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":"wrong"}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":null,"trusted_admin":null}"###,
                r###"{"data_dir":"sample-\u00e9\ud83d\ude00","storage_key_file":"sample-\u00e9\ud83d\ude00","workspace":"sample-\u00e9\ud83d\ude00","instance":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","hostname":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"control_key_file":"sample-\u00e9\ud83d\ude00","smtp_listen":["127.0.0.1",12345],"https_listen":["127.0.0.1",12345],"require_inbound_tls":true,"routes":{},"connectors":{},"recipient_directory":null,"admin_origin":null,"dns_server":null,"trusted_admin":{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615}}"###,
            ],
        );
    }
    #[test]
    fn record_contract_actor() {
        crate::data_contracts::check::<Actor>(
            "src_security_model_Actor",
            &[
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],null,18446744073709551615]"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615,"unexpected_field":1}"###,
                r###"{"permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615}"###,
                r###"{"id":false,"permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615,"id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":"wrong","domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615,"permissions":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":"wrong","mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615,"domains":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":"wrong","mailbox":null,"revision":18446744073709551615}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615,"mailboxes":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"revision":18446744073709551615}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":"wrong","revision":18446744073709551615}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615,"mailbox":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":"sample-\u00e9\ud83d\ude00","revision":18446744073709551615}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":"wrong"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","permissions":["sample-\u00e9\ud83d\ude00"],"domains":["sample-\u00e9\ud83d\ude00"],"mailboxes":["sample-\u00e9\ud83d\ude00"],"mailbox":null,"revision":18446744073709551615,"revision":18446744073709551615}"###,
            ],
        );
    }
    #[test]
    fn record_contract_command() {
        crate::data_contracts::check::<Command>(
            "src_security_model_Command",
            &[
                r###"{"action":"sample-\u00e9\ud83d\ude00","data":{"z":[1,true,null],"a":"sample"},"request_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",{"z":[1,true,null],"a":"sample"},"sample-\u00e9\ud83d\ude00"]"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","data":{"z":[1,true,null],"a":"sample"},"request_id":"sample-\u00e9\ud83d\ude00","unexpected_field":1}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","request_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"data":{"z":[1,true,null],"a":"sample"},"request_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"action":false,"data":{"z":[1,true,null],"a":"sample"},"request_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","data":{"z":[1,true,null],"a":"sample"},"request_id":"sample-\u00e9\ud83d\ude00","action":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","data":"wrong","request_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","data":{"z":[1,true,null],"a":"sample"},"request_id":"sample-\u00e9\ud83d\ude00","data":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","data":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","data":{"z":[1,true,null],"a":"sample"},"request_id":false}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","data":{"z":[1,true,null],"a":"sample"},"request_id":"sample-\u00e9\ud83d\ude00","request_id":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
}
