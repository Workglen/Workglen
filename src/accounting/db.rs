use crate::error::{Result, ensure};
use crate::net::{Gate, Permit};
use lazaret_pg::{
    Client,
    config::{Host, SslMode, TargetSessionAttrs},
};
use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Debug, Clone)]
pub struct Config {
    pub dsn_file: String,
    pub ca_file: Option<String>,
    pub feed_key_file: Option<String>,
    pub pool_size: usize,
    pub transport: Transport,
}
pratique::data_decode!(Config, deny_unknown=true, { dsn_file, ca_file, feed_key_file, pool_size = pool_default(), transport = Default::default() });

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Transport {
    #[default]
    VerifiedTls,
    /// Explicitly local: literal loopback TCP or an absolute Unix socket path.
    Local,
}
impl pratique::data::Decode for Transport {
    fn decode(n: pratique::data::Node) -> Result<Self, pratique::data::Error> {
        let at = n.offset;
        match pratique::data::unit_variant(n)?.as_str() {
            "verified-tls" => Ok(Self::VerifiedTls),
            "local" => Ok(Self::Local),
            _ => Err(pratique::data::Error::new("unknown Transport variant").at(at)),
        }
    }
}

/// Parse and constrain transport without connecting or including secrets in errors.
pub fn connection_config(config: &Config) -> Result<lazaret_pg::Config> {
    let secret = crate::config::secret(&config.dsn_file)?;
    parse_connection(&secret, config.transport)
}
fn parse_connection(secret: &str, transport: Transport) -> Result<lazaret_pg::Config> {
    let mut cfg: lazaret_pg::Config = secret
        .parse()
        .map_err(|_| crate::error!("Invalid PostgreSQL connection file"))?;
    ensure!(
        cfg.get_hosts().len() == 1 && cfg.get_hostaddrs().is_empty(),
        "Use exactly one PostgreSQL host without a hostaddr override"
    );
    ensure!(
        cfg.get_dbname().is_some() && cfg.get_user().is_some(),
        "PostgreSQL database and user are required"
    );
    match transport {
        Transport::VerifiedTls => ensure!(
            matches!(cfg.get_hosts()[0], Host::Tcp(_)),
            "Verified TLS requires a TCP endpoint"
        ),
        Transport::Local => match &cfg.get_hosts()[0] {
            Host::Tcp(host) => ensure!(
                host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback()),
                "Local PostgreSQL TCP requires literal 127.0.0.1 or ::1; remote addresses and DNS names are refused"
            ),
            Host::Unix(path) => ensure!(
                path.is_absolute()
                    && !path
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir)),
                "Local PostgreSQL socket path must be absolute without parent traversal"
            ),
        },
    }
    cfg.ssl_mode(if transport == Transport::Local { SslMode::Disable } else { SslMode::Require })
        .target_session_attrs(TargetSessionAttrs::ReadWrite).connect_timeout(Duration::from_secs(5))
        .operation_timeout(Duration::from_secs(15))
        .application_name("workglen-accounting")
        .options("-c statement_timeout=15000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=20000 -c synchronous_commit=on -c search_path=pg_catalog");
    cfg.validate()?;
    Ok(cfg)
}
fn pool_default() -> usize {
    2
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.transport != Transport::Local || self.ca_file.is_none(),
            "Local PostgreSQL uses host-local transport, not a CA file; select verified-tls to use TLS"
        );
        ensure!(
            (1..=8).contains(&self.pool_size),
            "accounting pool_size must be 1..8"
        );
        ensure!(
            std::path::Path::new(&self.dsn_file).is_absolute(),
            "accounting dsn_file must be absolute"
        );
        if let Some(k) = &self.feed_key_file {
            ensure!(
                std::path::Path::new(k).is_absolute(),
                "feed_key_file must be absolute"
            );
        }
        Ok(())
    }
}
pub struct Db {
    pub(super) config: Config,
    idle: Mutex<Vec<Client>>,
    gate: Arc<Gate>,
    pub workspace: String,
}
pub struct Connection<'a> {
    db: &'a Db,
    client: Option<Client>,
    _permit: Permit,
}
impl Deref for Connection<'_> {
    type Target = Client;
    fn deref(&self) -> &Client {
        self.client.as_ref().unwrap()
    }
}
impl DerefMut for Connection<'_> {
    fn deref_mut(&mut self) -> &mut Client {
        self.client.as_mut().unwrap()
    }
}
impl Drop for Connection<'_> {
    fn drop(&mut self) {
        if let Some(c) = self
            .client
            .take()
            .filter(|c| !std::thread::panicking() && !c.is_closed())
        {
            crate::resilience::reset_lock(&self.db.idle).push(c);
        }
    }
}
impl Db {
    pub fn new(config: Config, workspace: String) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            gate: Gate::new(config.pool_size),
            config,
            idle: Mutex::new(Vec::new()),
            workspace,
        })
    }
    pub fn connect(&self) -> Result<Connection<'_>> {
        // Brief, bounded contention is normal when the status panel and a write
        // arrive together. Never create extra connections or an unbounded queue.
        let until = std::time::Instant::now() + Duration::from_millis(500);
        let permit = loop {
            if let Some(p) = self.gate.enter() {
                break p;
            }
            ensure!(
                std::time::Instant::now() < until,
                "Accounting is busy. Retry shortly."
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        if let Some(c) = crate::resilience::reset_lock(&self.idle)
            .pop()
            .filter(|c| !c.is_closed())
        {
            return Ok(Connection {
                db: self,
                client: Some(c),
                _permit: permit,
            });
        }
        let mut cfg = connection_config(&self.config)?;
        if self.config.transport == Transport::Local {
            let c = cfg.connect().map_err(|_| crate::error!("Cannot connect to local PostgreSQL. Check local endpoint, database, role and authentication."))?;
            return Ok(Connection {
                db: self,
                client: Some(c),
                _permit: permit,
            });
        }
        if let Some(ca) = &self.config.ca_file {
            cfg.ca_file(ca);
        }
        let c=cfg.connect().map_err(|_|crate::error!("Cannot connect to PostgreSQL with verified TLS. Check endpoint, credentials, CA and network access."))?;
        Ok(Connection {
            db: self,
            client: Some(c),
            _permit: permit,
        })
    }
    pub fn initialize(&self) -> Result<String> {
        let mut c = self.connect()?;
        let mut tx = c.transaction()?;
        tx.batch_execute("SELECT pg_advisory_xact_lock(17981243)")?;
        let existing: Option<String> = tx
            .query_one(
                "SELECT to_regclass('workglen_accounting.installation')::text",
                &[],
            )?
            .get(0);
        if existing.is_none() {
            tx.batch_execute(include_str!("../../schema/accounting.sql"))?;
            let id = crate::store::random_id();
            tx.execute("INSERT INTO workglen_accounting.installation(singleton,version,workspace_id,database_id) VALUES(true,2,$1,$2)",&[&self.workspace,&id])?;
        }
        let row=tx.query_one("SELECT workspace_id,database_id,version FROM workglen_accounting.installation WHERE singleton",&[])?;
        ensure!(
            row.get::<_, String>(0) == self.workspace && row.get::<_, i32>(2) == 2,
            "Accounting database belongs to a different workspace or schema version"
        );
        let id: String = row.get(1);
        tx.commit()?;
        Ok(id)
    }
    pub fn status(&self) -> Result<pratique::json_value::Value> {
        let mut c = self.connect()?;
        let r=c.query_one("SELECT workspace_id,database_id,enabled,revision,version FROM workglen_accounting.installation WHERE singleton",&[])
            .map_err(|_|crate::error!("Accounting schema unavailable. Run accounting-init with the schema owner."))?;
        ensure!(
            r.get::<_, String>(0) == self.workspace && r.get::<_, i32>(4) == 2,
            "Accounting database workspace or schema mismatch"
        );
        Ok(
            pratique::json_value::json!({"configured":true,"ready":true,"database_id":r.get::<_,String>(1),"enabled":r.get::<_,bool>(2),"revision":r.get::<_,i64>(3),"backend":"PostgreSQL","pool_size":self.config.pool_size}),
        )
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    #[test]
    fn local_transport_never_falls_back_to_a_remote_endpoint() {
        for host in ["127.0.0.1", "::1", "/tmp"] {
            assert!(
                parse_connection(
                    &format!("host={host} user=workglen dbname=workglen"),
                    Transport::Local
                )
                .is_ok()
            );
        }
        for host in [
            "localhost",
            "db.example.com",
            "192.0.2.1",
            "127.0.0.1,192.0.2.1",
            "/tmp/../tmp",
        ] {
            assert!(
                parse_connection(
                    &format!("host={host} user=workglen dbname=workglen"),
                    Transport::Local
                )
                .is_err()
            );
        }
        assert!(
            parse_connection(
                "host=127.0.0.1 hostaddr=192.0.2.1 user=x dbname=x",
                Transport::Local
            )
            .is_err()
        );
        assert!(parse_connection("user=x dbname=x", Transport::Local).is_err());
    }
    #[test]
    fn verified_tls_remains_the_default_and_overrides_dsn_downgrades() {
        let cfg = parse_connection(
            "host=db.example.com user=x dbname=x sslmode=disable",
            Transport::VerifiedTls,
        )
        .unwrap();
        assert_eq!(cfg.get_ssl_mode(), SslMode::Require);
        assert!(parse_connection("host=/tmp user=x dbname=x", Transport::VerifiedTls).is_err());
        assert_eq!(Transport::default(), Transport::VerifiedTls);
    }
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    pratique::data_encode!(Config {
        dsn_file,
        ca_file,
        feed_key_file,
        pool_size,
        transport
    });
    #[test]
    fn record_contract_config() {
        crate::data_contracts::check::<Config>(
            "src_accounting_db_Config",
            &[
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"verified-tls"}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",null,null,65535,"verified-tls"]"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"verified-tls","unexpected_field":1}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"verified-tls"}"###,
                r###"{"dsn_file":false,"ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"verified-tls"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"verified-tls","dsn_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","feed_key_file":null,"pool_size":65535,"transport":"verified-tls"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":"wrong","feed_key_file":null,"pool_size":65535,"transport":"verified-tls"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"verified-tls","ca_file":null}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00","feed_key_file":null,"pool_size":65535,"transport":"verified-tls"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"pool_size":65535,"transport":"verified-tls"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":"wrong","pool_size":65535,"transport":"verified-tls"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"verified-tls","feed_key_file":null}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":"sample-\u00e9\ud83d\ude00","pool_size":65535,"transport":"verified-tls"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"transport":"verified-tls"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":"wrong","transport":"verified-tls"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"verified-tls","pool_size":65535}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":65535}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"wrong"}"###,
                r###"{"dsn_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"feed_key_file":null,"pool_size":65535,"transport":"verified-tls","transport":"verified-tls"}"###,
            ],
        );
    }
    impl pratique::data::Encode for Transport {
        fn encode(&self) -> Result<pratique::data::Node, pratique::data::Error> {
            pratique::data::Encode::encode(match self {
                Self::VerifiedTls => "verified-tls",
                Self::Local => "local",
            })
        }
    }
    #[test]
    fn record_contract_transport() {
        crate::data_contracts::check::<Transport>(
            "src_accounting_db_Transport",
            &[
                r###""verified-tls""###,
                r###""invalid""###,
                r###"null"###,
                r###"{"verified-tls":null}"###,
                r###"{"verified-tls":{}}"###,
            ],
        );
    }
}
