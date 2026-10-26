use crate::error::{Result, ensure};
use crate::{
    auth,
    config::{Config, Mode, User},
    net::Gate,
    store::{Op, Store},
};
use std::{
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
pub struct Lease {
    pub term: u64,
    pub until: Instant,
}
#[derive(Default)]
pub struct ReplicationStatus {
    pub last_contact: Option<i64>,
    pub peer_sequence: Option<u64>,
    pub term: Option<u64>,
    pub last_error: Option<String>,
    pub direction: Option<String>,
}
pratique::data_encode!(ReplicationStatus {
    last_contact,
    peer_sequence,
    term,
    last_error,
    direction
});

pub struct App {
    pub config: Config,
    pub accounting: Option<crate::accounting::Db>,
    pub store: RwLock<Store>,
    pub lease: Mutex<Lease>,
    pub writes: Mutex<()>,
    pub authorization: RwLock<()>,
    pub connections: Arc<Gate>,
    pub data: Arc<Gate>,
    pub passwords: Mutex<()>,
    pub checker: auth::Checker,
    pub signer: Option<crate::dkim::Signer>,
    pub outbound_tls: Option<pratique::tls::ClientConfig>,
    pub tls: Arc<pratique::tls::server::ServerConfig>,
    pub certificates: crate::certificates::ManagedTls,
    pub changes: AtomicU64,
    pub dummy_hash: String,
    pub replication_status: Mutex<ReplicationStatus>,
    pub backups: Mutex<()>,
    pub relay_activity: Mutex<()>,
}
impl App {
    pub fn new(config: Config, store: Store) -> Result<Arc<Self>> {
        if config.admin_only {
            let modules = crate::modules::state(&store)?;
            ensure!(
                !modules.mail_enabled && !modules.webmail_enabled,
                "Initialize a fresh local Admin store before admin-serve; do not reuse an enabled Mail store"
            );
        }
        let checker = auth::Checker::new(config.dns_server)?;
        let certificates = crate::certificates::ManagedTls::start(
            &config.tls_cert,
            &config.tls_key,
            config.acme.as_ref(),
            |_| {},
        )?;
        let tls = certificates.tls.clone();
        store.enter_mode(config.mode)?;
        if config.mode == Mode::Single && store.meta("term")? == 0 {
            store.begin_term(1)?;
        }
        Ok(Arc::new(Self {
            signer: config
                .dkim
                .as_ref()
                .map(|d| crate::dkim::Signer::load(d, &config.domain))
                .transpose()?,
            outbound_tls: crate::relay::tls_config(&config)?,
            accounting: config
                .accounting
                .clone()
                .map(|c| crate::accounting::Db::new(c, config.replication.cluster_id.clone()))
                .transpose()?,
            replication_status: Mutex::new(ReplicationStatus::default()),
            backups: Mutex::new(()),
            relay_activity: Mutex::new(()),
            connections: Gate::new(config.limits.connections),
            data: Gate::new(config.limits.data_transfers),
            passwords: Mutex::new(()),
            config,
            store: RwLock::new(store),
            lease: Mutex::new(Lease {
                term: 0,
                until: Instant::now(),
            }),
            writes: Mutex::new(()),
            authorization: RwLock::new(()),
            checker,
            tls,
            certificates,
            changes: AtomicU64::new(0),
            dummy_hash: auth::hash("no-account-exists-random-dummy")?,
        }))
    }
    pub fn read_store(&self) -> Result<std::sync::RwLockReadGuard<'_, Store>> {
        self.store.read().map_err(|_| {
            crate::error!("Store replacement was interrupted; node fenced pending recovery")
        })
    }
    pub fn write_store(&self) -> Result<std::sync::RwLockWriteGuard<'_, Store>> {
        self.store.write().map_err(|_| {
            crate::error!("Store replacement was interrupted; node fenced pending recovery")
        })
    }
    pub fn current_lease(&self) -> std::sync::MutexGuard<'_, Lease> {
        match self.lease.lock() {
            Ok(guard) => guard,
            Err(error) => {
                let mut guard = error.into_inner();
                *guard = Lease {
                    term: 0,
                    until: Instant::now(),
                };
                self.lease.clear_poison();
                guard
            }
        }
    }
    pub fn primary(&self) -> bool {
        !self.store.is_poisoned()
            && (self.config.mode == Mode::Single
                || self.current_lease().until > Instant::now() + Duration::from_millis(500))
    }
    pub fn require_primary(&self) -> Result<()> {
        ensure!(
            self.primary(),
            "not current primary; reconnect to active node"
        );
        Ok(())
    }
    pub fn commit<R>(
        &self,
        f: impl FnOnce(&redb::Table<&str, &[u8]>) -> Result<(Vec<Op>, R)>,
    ) -> Result<R> {
        let _lock = self.writes.lock().unwrap_or_else(|e| e.into_inner());
        self.require_primary()?;
        let (seq, r) = self.read_store()?.write(f)?;
        if self.config.mode == Mode::Single && seq > 128 {
            self.read_store()?.prune(seq - 128)?;
        }
        self.changes.fetch_add(1, Ordering::SeqCst);
        self.require_primary()?;
        Ok(r)
    }
    pub fn mail_enabled(&self) -> bool {
        if self.config.admin_only {
            return false;
        }
        self.read_store()
            .and_then(|s| crate::modules::state(&s))
            .map(|s| s.mail_enabled)
            .unwrap_or(false)
    }
    pub fn require_mail(&self) -> Result<()> {
        ensure!(
            !self.config.admin_only,
            "Mail is unavailable in the local Admin profile"
        );
        self.require_primary()?;
        ensure!(
            self.mail_enabled(),
            "Mail is disabled. Enable it in Modules or with the CLI."
        );
        Ok(())
    }
    pub fn mail_commit<R>(
        &self,
        f: impl FnOnce(&redb::Table<&str, &[u8]>) -> Result<(Vec<Op>, R)>,
    ) -> Result<R> {
        self.commit(|t| {
            let state: crate::modules::State =
                crate::store::json(t, crate::modules::STATE_KEY)?.unwrap_or_default();
            ensure!(state.mail_enabled, "Mail is disabled");
            f(t)
        })
    }
    pub fn login(&self, user: &str, password: &str) -> Result<bool> {
        self.require_mail()?;
        let _password_guard = self.passwords.lock().unwrap_or_else(|e| e.into_inner());
        if password.len() > 1024 {
            return Ok(false);
        }
        let user = crate::config::address(user).unwrap_or_default();
        let account = self.read_store()?.get::<User>(&format!("user/{user}"))?;
        let hash = account
            .as_ref()
            .map(|u| u.password_hash.as_str())
            .unwrap_or(&self.dummy_hash);
        let good = auth::verify(password, hash);
        Ok(account.is_some() && good)
    }
}
