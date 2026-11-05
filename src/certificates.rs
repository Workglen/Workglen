//! Shared native certificate lifecycle for every TLS listener in a service.
use crate::error::{Result, ensure};
use pratique::http::server::{
    AcmeHttp01, HttpConfig, Limits, Reloader, Request, Response, Server, ServerBuilder,
    acme::{self, Acme, AcmeConfig},
};
use pratique::json_value::{Value, json};
use pratique::tls::{certs::CertStore, server::ServerConfig};
use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path},
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct AcmeSettings {
    pub domains: Vec<String>,
    pub email: String,
    pub state_dir: String,
    pub http_listen: SocketAddr,
    pub staging: bool,
    pub agree_to_terms: bool,
}
pratique::data_decode!(AcmeSettings, deny_unknown=true, { domains, email, state_dir, http_listen = challenge_address(), staging = Default::default(), agree_to_terms = Default::default() });

fn challenge_address() -> SocketAddr {
    "0.0.0.0:80".parse().unwrap()
}

/// Configuration checks are offline: no account, key, listener or CA request.
pub fn validate(
    cert: &str,
    key: &str,
    acme: Option<&AcmeSettings>,
    required_names: &[&str],
) -> Result<()> {
    let Some(a) = acme else {
        ensure!(
            !cert.is_empty() && !key.is_empty(),
            "Supply tls_cert and tls_key, or configure acme"
        );
        return Ok(());
    };
    ensure!(
        cert.is_empty() && key.is_empty(),
        "Choose acme or manual tls_cert/tls_key, not both"
    );
    ensure!(
        a.agree_to_terms,
        "Review Let's Encrypt subscriber terms, then set acme.agree_to_terms=true"
    );
    ensure!(
        (1..=20).contains(&a.domains.len()),
        "acme.domains must contain 1..20 DNS names"
    );
    let mut names = std::collections::BTreeSet::new();
    for name in &a.domains {
        ensure!(
            crate::config::domain(name)
                && name.contains('.')
                && !name.ends_with('.')
                && name == &name.to_ascii_lowercase()
                && name.parse::<std::net::IpAddr>().is_err()
                && names.insert(name.as_str()),
            "ACME needs unique lowercase DNS hostnames; wildcards and IP addresses are not supported"
        );
    }
    for name in required_names {
        ensure!(
            names.contains(name),
            "acme.domains must include service hostname {name}"
        );
    }
    ensure!(
        crate::config::address(&a.email).is_ok() && a.email.len() <= 254,
        "acme.email must be a contact email address"
    );
    ensure!(
        a.http_listen.port() != 0,
        "acme.http_listen requires a nonzero port; public HTTP-01 traffic must reach port 80"
    );
    let path = Path::new(&a.state_dir);
    ensure!(
        path.is_absolute()
            && path.parent().is_some()
            && !path.components().any(|p| matches!(p, Component::ParentDir)),
        "acme.state_dir must be an absolute dedicated directory without parent traversal"
    );
    Ok(())
}

#[derive(Default)]
struct Events {
    last: Option<&'static str>,
    at: Option<i64>,
    error: Option<&'static str>,
}

pub struct ManagedTls {
    pub tls: Arc<ServerConfig>,
    mode: &'static str,
    staging: bool,
    events: Arc<Mutex<Events>>,
    // Drop the worker before the challenge listener and state lock.
    _renewal: Option<Reloader>,
    _challenge: Option<Server>,
    _lock: Option<fs::File>,
}

impl Drop for ManagedTls {
    fn drop(&mut self) {
        // Pratique's Server needs explicit shutdown; dropping its handle alone
        // does not close the listeners. Retain HTTP-01 until the worker stops.
        drop(self._renewal.take());
        if let Some(server) = self._challenge.take() {
            server.shutdown(Duration::from_secs(1));
        }
    }
}

fn private_state(path: &Path) -> Result<fs::File> {
    // Never follow provisioned symlinks into another state/key tree.
    for ancestor in path.ancestors() {
        if let Ok(m) = fs::symlink_metadata(ancestor) {
            ensure!(
                m.is_dir() && !m.file_type().is_symlink(),
                "ACME state path must contain only real directories"
            );
        }
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    fn check(path: &Path) -> Result<()> {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            !m.file_type().is_symlink(),
            "ACME state cannot contain symbolic links"
        );
        if m.is_dir() {
            ensure!(
                m.permissions().mode() & 0o077 == 0,
                "ACME state directories must be owner-only (0700)"
            );
            for entry in fs::read_dir(path)? {
                check(&entry?.path())?;
            }
        } else {
            ensure!(
                m.is_file() && m.nlink() == 1,
                "ACME state must contain only regular, unlinked files"
            );
            if path.extension().is_some_and(|e| e == "key")
                || path
                    .file_name()
                    .is_some_and(|n| n == "key.pem" || n == "manager.lock")
            {
                ensure!(
                    m.permissions().mode() & 0o077 == 0,
                    "ACME private keys and locks must be owner-only (0600)"
                );
            }
        }
        Ok(())
    }
    check(path)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(crate::net::OPEN_NOFOLLOW)
        .open(path.join("manager.lock"))?;
    lock.try_lock()
        .map_err(|_| crate::error!("ACME state directory is already in use"))?;
    Ok(lock)
}

impl ManagedTls {
    pub fn start(
        cert: &str,
        key: &str,
        settings: Option<&AcmeSettings>,
        report: impl Fn(&str) + Send + 'static,
    ) -> Result<Self> {
        validate(cert, key, settings, &[])?;
        let Some(settings) = settings else {
            return Ok(Self {
                tls: crate::net::server_config(cert, key)?,
                mode: "manual",
                staging: false,
                events: Arc::default(),
                _renewal: None,
                _challenge: None,
                _lock: None,
            });
        };
        let directory = if settings.staging {
            acme::LETS_ENCRYPT_STAGING
        } else {
            acme::LETS_ENCRYPT
        };
        let client = pratique::http::Client::new()?.timeout(Duration::from_secs(30));
        let config = AcmeConfig::new(directory, &settings.state_dir)
            .contact(&format!("mailto:{}", settings.email))
            .agree_to_terms()
            .client(client);
        Self::start_acme(settings, config, report)
    }

    fn start_acme(
        settings: &AcmeSettings,
        config: AcmeConfig,
        report: impl Fn(&str) + Send + 'static,
    ) -> Result<Self> {
        let lock = private_state(Path::new(&settings.state_dir))?;
        let challenges = AcmeHttp01::new();
        let acme = Acme::new(config.http01(&challenges))?;
        let challenge = ServerBuilder::new(challenges.wrap(|_: Request| Response::new(404)))
            .plain(&settings.http_listen.to_string())
            .http_config(HttpConfig {
                max_request_line: 2048,
                max_header_bytes: 8192,
                max_headers: 24,
                max_body: Some(0),
                max_requests_per_connection: 8,
                server_header: None,
                ..Default::default()
            })
            .limits(Limits {
                max_connections: 32,
                max_connections_per_ip: 8,
                head_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(5),
                write_timeout: Duration::from_secs(5),
                ..Default::default()
            })
            .start()?;
        let tls = Arc::new(ServerConfig::with_certificates(CertStore::new()).with_alpn(&[]));
        let store = tls.store.as_ref().unwrap().clone();
        // Make a saved certificate available before any TLS listeners start.
        let names: Vec<_> = settings.domains.iter().map(String::as_str).collect();
        if let Some(cert) = acme.load(&names) {
            store.replace(vec![cert]);
        }
        let events = Arc::new(Mutex::new(Events::default()));
        let status = events.clone();
        let renewal = acme::manage(
            acme,
            vec![settings.domains.clone()],
            store,
            move |message| {
                // Publish bounded event types, never filesystem paths or CA-supplied text to APIs/audit.
                let kind = if message.contains("trying again at") {
                    "issuance-or-renewal-failed"
                } else if message.starts_with("renewal information for") {
                    "renewal-information-unavailable"
                } else if message.contains("has expired") {
                    "certificate-expired"
                } else if message.contains("loaded from") {
                    "certificate-loaded"
                } else if message.contains("valid until") {
                    "certificate-issued-or-renewed"
                } else {
                    "renewal-scheduled"
                };
                {
                    let mut e = status.lock().unwrap_or_else(|e| e.into_inner());
                    e.last = Some(kind);
                    let clock_failed = match crate::datetime::Utc::now() {
                        Ok(now) => {
                            e.at = Some(now.timestamp());
                            false
                        }
                        Err(error) => {
                            e.at = None;
                            e.error = Some("clock-unavailable");
                            eprintln!("TLS certificate event timestamp unavailable: {error}");
                            true
                        }
                    };
                    if matches!(
                        kind,
                        "issuance-or-renewal-failed"
                            | "renewal-information-unavailable"
                            | "certificate-expired"
                    ) {
                        e.error = Some(kind);
                    } else if kind == "certificate-issued-or-renewed" && !clock_failed {
                        e.error = None;
                    }
                }
                eprintln!(
                    "TLS ACME: {}",
                    message
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(1024)
                        .collect::<String>()
                );
                report(kind);
            },
        );
        Ok(Self {
            tls,
            mode: "letsencrypt",
            staging: settings.staging,
            events,
            _renewal: Some(renewal),
            _challenge: Some(challenge),
            _lock: Some(lock),
        })
    }

    pub fn status(&self) -> Result<Value> {
        let certs = self.tls.store.as_ref().unwrap().certificates();
        let now = crate::datetime::Utc::now()?.timestamp();
        let expires = certs.iter().map(|c| c.not_after()).min();
        let e = self.events.lock().unwrap_or_else(|e| e.into_inner());
        Ok(
            json!({"mode":self.mode,"staging":self.staging,"automatic_renewal":self.mode=="letsencrypt",
            "ready":expires.is_some_and(|t| t>now),"expires_at":expires,
            "expiring_soon":expires.is_some_and(|t| t-now<=7*86400),
            "domains":certs.iter().flat_map(|c| c.dns_names()).collect::<Vec<_>>(),
            "renewal_strategy":if self.mode=="letsencrypt" { "CA renewal window (ARI), with certificate-lifetime fallback" } else { "manual" },
            "last_event":e.last,"last_event_at":e.at,"last_error":e.error}),
        )
    }
}

#[cfg(test)]
mod tests;
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    pratique::data_encode!(AcmeSettings {
        domains,
        email,
        state_dir,
        http_listen,
        staging,
        agree_to_terms
    });
    #[test]
    fn record_contract_acmesettings() {
        crate::data_contracts::check::<AcmeSettings>(
            "src_certificates_AcmeSettings",
            &[
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true}"###,
                r###"{}"###,
                r###"[["sample-\u00e9\ud83d\ude00"],"sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","127.0.0.1:12345",true,true]"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true,"unexpected_field":1}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true}"###,
                r###"{"domains":"wrong","email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true,"domains":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":false,"state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true,"email":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":false,"http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true,"state_dir":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","staging":true,"agree_to_terms":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"wrong","staging":true,"agree_to_terms":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true,"http_listen":"127.0.0.1:12345"}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","agree_to_terms":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":"wrong","agree_to_terms":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true,"staging":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":"wrong"}"###,
                r###"{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true,"agree_to_terms":true}"###,
            ],
        );
    }
}
