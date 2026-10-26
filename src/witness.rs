use crate::error::{Result, ensure};
use crate::{
    app::App,
    config::{Config, secret},
    net::{Gate, Wire},
};
use std::{
    fs,
    io::Write,
    net::TcpListener,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
pub struct WitnessConfig {
    pub listen: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub acme: Option<crate::certificates::AcmeSettings>,
    pub token_file: String,
    pub state_file: String,
    pub cluster_id: String,
    pub lease_seconds: u64,
}
pratique::data_decode!(WitnessConfig, deny_unknown=true, { listen, tls_cert = Default::default(), tls_key = Default::default(), acme, token_file, state_file, cluster_id, lease_seconds });

#[derive(Clone)]
pub struct State {
    pub holder: String,
    pub term: u64,
    pub until: Instant,
    pub startup_until: Instant,
}
impl State {
    pub fn acquire(&mut self, node: &str, ready: bool, now: Instant, ttl: Duration) -> Option<u64> {
        if now < self.startup_until || !ready {
            return None;
        }
        if self.holder == node && now < self.until {
            self.until = now + ttl;
            return Some(self.term);
        }
        if now >= self.until {
            self.term += 1;
            self.holder = node.into();
            self.until = now + ttl;
            return Some(self.term);
        }
        None
    }
}
pub fn same(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
fn durable_term(path: &str, term: u64) -> Result<()> {
    let temp = format!("{path}.tmp");
    {
        let mut f = fs::File::create(&temp)?;
        writeln!(f, "{term}")?;
        f.sync_all()?;
    }
    fs::rename(temp, path)?;
    if let Some(p) = std::path::Path::new(path).parent() {
        fs::File::open(p)?.sync_all()?;
    }
    Ok(())
}
// A panic could occur after persisting a new term but before publishing it in
// memory or after sending a grant. Reload the durable fence and wait out every
// possible prior grant; never simply resume the partially updated authority.
fn lock_state<'a>(
    state: &'a Mutex<State>,
    c: &WitnessConfig,
) -> Result<std::sync::MutexGuard<'a, State>> {
    match state.lock() {
        Ok(guard) => Ok(guard),
        Err(error) => {
            let mut guard = error.into_inner();
            let durable: u64 = fs::read_to_string(&c.state_file)?.trim().parse()?;
            let now = Instant::now();
            *guard = State {
                holder: String::new(),
                term: durable.max(guard.term),
                until: now,
                startup_until: now + Duration::from_secs(c.lease_seconds + 2),
            };
            state.clear_poison();
            Ok(guard)
        }
    }
}

#[cfg(test)]
mod panic_tests {
    use super::*;
    #[test]
    fn interrupted_grant_waits_for_prior_lease_and_reloads_durable_term() {
        let dir = crate::test_support::tempdir().unwrap();
        let file = dir.path().join("term");
        std::fs::write(&file, "42\n").unwrap();
        let c = WitnessConfig {
            listen: String::new(),
            tls_cert: String::new(),
            tls_key: String::new(),
            acme: None,
            token_file: String::new(),
            state_file: file.to_string_lossy().into(),
            cluster_id: "test".into(),
            lease_seconds: 10,
        };
        let now = Instant::now();
        let state = Mutex::new(State {
            holder: "old".into(),
            term: 41,
            until: now + Duration::from_secs(10),
            startup_until: now,
        });
        let _: Result<()> = crate::resilience::boundary("grant fault", || {
            let _guard = state.lock().unwrap();
            panic!("durable term written, reply outcome unknown");
        });
        let mut recovered = lock_state(&state, &c).unwrap();
        assert_eq!(recovered.term, 42);
        assert!(recovered.holder.is_empty());
        assert!(
            recovered
                .acquire("new", true, now, Duration::from_secs(10))
                .is_none()
        );
        let after = recovered.startup_until + Duration::from_secs(1);
        assert_eq!(
            recovered.acquire("new", true, after, Duration::from_secs(10)),
            Some(43)
        );
    }
    #[test]
    fn invalid_durable_fence_never_recovers_authority() {
        let now = Instant::now();
        let state = Mutex::new(State {
            holder: "old".into(),
            term: 2,
            until: now,
            startup_until: now,
        });
        let _: Result<()> = crate::resilience::boundary("grant fault", || {
            let _guard = state.lock().unwrap();
            panic!("fault");
        });
        let c = WitnessConfig {
            listen: String::new(),
            tls_cert: String::new(),
            tls_key: String::new(),
            acme: None,
            token_file: String::new(),
            state_file: "/no-such-synthetic-witness-state".into(),
            cluster_id: "test".into(),
            lease_seconds: 10,
        };
        assert!(lock_state(&state, &c).is_err());
        assert!(state.is_poisoned());
    }
}
pub fn serve(path: &str) -> Result<()> {
    let c: WitnessConfig = workglen_toml::from_str(&fs::read_to_string(path)?)?;
    ensure!(
        (10..=60).contains(&c.lease_seconds),
        "lease must be 10..60 seconds"
    );
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(format!("{}.lock", c.state_file))?;
    lock.try_lock()?;
    let term = match fs::read_to_string(&c.state_file) {
        Ok(s) => s.trim().parse()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e.into()),
    };
    let state = Arc::new(Mutex::new(State {
        holder: String::new(),
        term,
        until: Instant::now(),
        startup_until: Instant::now() + Duration::from_secs(c.lease_seconds + 2),
    }));
    let certificates =
        crate::certificates::ManagedTls::start(&c.tls_cert, &c.tls_key, c.acme.as_ref(), |_| {})?;
    let tls = certificates.tls.clone();
    let token = Arc::new(secret(&c.token_file)?);
    ensure!(token.len() >= 32, "witness token must be >=32 characters");
    let listener = TcpListener::bind(&c.listen)?;
    let gate = Gate::new(8);
    let c = Arc::new(c);
    for tcp in listener.incoming() {
        let tcp = tcp?;
        let Some(permit) = gate.enter() else {
            continue;
        };
        let (c, tls, token, state) = (c.clone(), tls.clone(), token.clone(), state.clone());
        std::thread::spawn(move || {
            let _p = permit;
            let result = crate::resilience::boundary("witness operation", || -> Result<()> {
                let mut w = Wire::accept(tcp, &tls)?;
                w.deadline.set(Duration::from_secs(3));
                let line = w.text(2048)?;
                let p: Vec<_> = line.split_whitespace().collect();
                ensure!(
                    p.len() >= 3 && same(p[1], &token) && p[2] == c.cluster_id,
                    "unauthorized witness request"
                );
                let mut s = lock_state(&state, &c)?;
                let now = Instant::now();
                if p[0] == "STATUS" {
                    if now < s.until {
                        w.send(&format!("HOLDER {} {}\r\n", s.holder, s.term))?;
                    } else {
                        w.send("NONE\r\n")?;
                    }
                    return Ok(());
                }
                ensure!(
                    p.len() == 5 && p[0] == "LEASE" && p[3].len() <= 32,
                    "invalid lease request"
                );
                let old = s.term;
                let mut candidate = s.clone();
                if let Some(term) =
                    candidate.acquire(p[3], p[4] == "1", now, Duration::from_secs(c.lease_seconds))
                {
                    if term != old {
                        durable_term(&c.state_file, term)?;
                    }
                    *s = candidate;
                    w.send(&format!("GRANT {term} {}\r\n", c.lease_seconds))?;
                } else {
                    w.send("WAIT\r\n")?;
                }
                Ok(())
            });
            if let Err(e) = result {
                eprintln!("witness: {e}");
            }
        });
    }
    Ok(())
}
fn request(c: &Config, line: &str) -> Result<String> {
    let wc = c.witness()?;
    let mut w = Wire::connect(wc.address.parse()?, &wc.server_name, &wc.ca_file)?;
    w.deadline.set(Duration::from_secs(3));
    w.send(line)?;
    w.text(256)
}
pub fn holder(c: &Config) -> Result<Option<(String, u64)>> {
    let r = request(
        c,
        &format!(
            "STATUS {} {}\r\n",
            secret(&c.witness()?.token_file)?,
            c.replication.cluster_id
        ),
    )?;
    let p: Vec<_> = r.split_whitespace().collect();
    if p.len() == 3 && p[0] == "HOLDER" {
        Ok(Some((p[1].into(), p[2].parse()?)))
    } else {
        Ok(None)
    }
}
pub fn renew_loop(app: Arc<App>) {
    loop {
        let start = Instant::now();
        let result = crate::resilience::boundary("witness operation", || -> Result<()> {
            let ready = app.read_store()?.meta("ready")? == 1;
            let r = request(
                &app.config,
                &format!(
                    "LEASE {} {} {} {}\r\n",
                    secret(&app.config.witness()?.token_file)?,
                    app.config.replication.cluster_id,
                    app.config.node_id(),
                    if ready { 1 } else { 0 }
                ),
            )?;
            let p: Vec<_> = r.split_whitespace().collect();
            if p.len() == 3 && p[0] == "GRANT" {
                let term = p[1].parse()?;
                let ttl: u64 = p[2].parse()?;
                // Deadline is measured from request START, subtracting a safety margin. Network delay cannot extend a lease.
                let until = start + Duration::from_secs(ttl.saturating_sub(3));
                ensure!(until > Instant::now(), "lease response arrived too late");
                let _write = app.writes.lock().unwrap_or_else(|e| e.into_inner());
                let store = app.read_store()?;
                if store.meta("term")? != term {
                    store.begin_term(term)?;
                    eprintln!("became primary: term={term}");
                }
                ensure!(
                    until > Instant::now(),
                    "lease expired while waiting for storage"
                );
                *app.current_lease() = crate::app::Lease { term, until };
            } else {
                app.current_lease().until = Instant::now();
            }
            Ok(())
        });
        if let Err(e) = result {
            eprintln!("lease renewal: {e}");
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    pratique::data_encode!(WitnessConfig {
        listen,
        tls_cert,
        tls_key,
        acme,
        token_file,
        state_file,
        cluster_id,
        lease_seconds
    });
    #[test]
    fn record_contract_witnessconfig() {
        crate::data_contracts::check::<WitnessConfig>(
            "src_witness_WitnessConfig",
            &[
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",null,"sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",18446744073709551615]"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615,"unexpected_field":1}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":false,"tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615,"listen":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":false,"tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615,"tls_cert":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":false,"acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615,"tls_key":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":"wrong","token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615,"acme":null}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":{"domains":["sample-\u00e9\ud83d\ude00"],"email":"sample-\u00e9\ud83d\ude00","state_dir":"sample-\u00e9\ud83d\ude00","http_listen":"127.0.0.1:12345","staging":true,"agree_to_terms":true},"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":false,"state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615,"token_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":false,"cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615,"state_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":false,"lease_seconds":18446744073709551615}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615,"cluster_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":"wrong"}"###,
                r###"{"listen":"sample-\u00e9\ud83d\ude00","tls_cert":"sample-\u00e9\ud83d\ude00","tls_key":"sample-\u00e9\ud83d\ude00","acme":null,"token_file":"sample-\u00e9\ud83d\ude00","state_file":"sample-\u00e9\ud83d\ude00","cluster_id":"sample-\u00e9\ud83d\ude00","lease_seconds":18446744073709551615,"lease_seconds":18446744073709551615}"###,
            ],
        );
    }
}
