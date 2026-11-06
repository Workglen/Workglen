use super::{db::*, model::*, service::Service};

use crate::net::Wire;

use crate::error::{Result, bail, ensure};

use crate::encoding::STANDARD;

use pratique::json_value::{Value, json};

use std::{
    net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
    },
    time::{Duration, Instant},
};

const ACCEPTANCE_BATCH_MAX: usize = 16;
const ACCEPTANCE_BATCH_WAIT: Duration = Duration::from_micros(500);

struct AcceptanceRequest {
    raw: Vec<u8>,
    sender: String,
    recipients: Vec<String>,
    ip: IpAddr,
    helo: String,
    settings: Value,
    response: SyncSender<Result<Vec<String>>>,
}

#[derive(Default)]
struct AcceptanceStats {
    commits: AtomicU64,
    messages: AtomicU64,
    max_batch: AtomicUsize,
}

pub(super) struct AcceptanceBatcher {
    sender: Option<SyncSender<AcceptanceRequest>>,
    stats: Arc<AcceptanceStats>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl AcceptanceBatcher {
    pub(super) fn new(db: Arc<Db>) -> Result<Self> {
        let (sender, receiver) = sync_channel(32);
        let stats = Arc::new(AcceptanceStats::default());
        let worker_stats = stats.clone();
        let worker = std::thread::Builder::new()
            .name("security-acceptance".into())
            .spawn(move || acceptance_loop(&db, &receiver, &worker_stats))?;
        Ok(Self {
            sender: Some(sender),
            stats,
            worker: Some(worker),
        })
    }

    fn accept(
        &self,
        raw: Vec<u8>,
        sender: String,
        recipients: Vec<String>,
        ip: IpAddr,
        helo: String,
        settings: Value,
    ) -> Result<Vec<String>> {
        let (response, result) = sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| crate::error!("Acceptance writer unavailable"))?
            .send(AcceptanceRequest {
                raw,
                sender,
                recipients,
                ip,
                helo,
                settings,
                response,
            })
            .map_err(|_| crate::error!("Acceptance writer unavailable"))?;
        result
            .recv()
            .map_err(|_| crate::error!("Acceptance writer stopped"))?
    }

    pub(super) fn status(&self) -> Value {
        let commits = self.stats.commits.load(Ordering::Relaxed);
        let messages = self.stats.messages.load(Ordering::Relaxed);
        json!({
            "durable_commits":commits,
            "messages":messages,
            "max_batch":self.stats.max_batch.load(Ordering::Relaxed),
            "messages_per_commit":if commits == 0 { 0.0 } else { messages as f64 / commits as f64 }
        })
    }
}

impl Drop for AcceptanceBatcher {
    fn drop(&mut self) {
        // Disconnect first so a writer blocked in recv can exit, then wait until
        // its database handle is gone before Service::open can reacquire the
        // exclusive encrypted-store lock during an immediate restart.
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn acceptance_loop(db: &Db, receiver: &Receiver<AcceptanceRequest>, stats: &AcceptanceStats) {
    while let Ok(first) = receiver.recv() {
        let mut requests = vec![first];
        let deadline = Instant::now() + ACCEPTANCE_BATCH_WAIT;
        while requests.len() < ACCEPTANCE_BATCH_MAX {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match receiver.recv_timeout(remaining) {
                Ok(request) => requests.push(request),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        let results = db.write(|t| accept_batch(t, &requests));
        match results {
            Ok(results) => {
                let accepted = results.iter().filter(|result| result.is_ok()).count();
                if accepted > 0 {
                    stats.commits.fetch_add(1, Ordering::Relaxed);
                    stats.messages.fetch_add(accepted as u64, Ordering::Relaxed);
                    stats.max_batch.fetch_max(accepted, Ordering::Relaxed);
                }
                for (request, result) in requests.into_iter().zip(results) {
                    let _ = request
                        .response
                        .send(result.map_err(crate::error::Error::msg));
                }
            }
            Err(error) => {
                let error = error.to_string();
                for request in requests {
                    let _ = request.response.send(Err(crate::error!("{error}")));
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct Uncertain;

impl std::fmt::Display for Uncertain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Remote acknowledgment uncertain; review before retry")
    }
}

impl std::error::Error for Uncertain {}

#[derive(Debug)]
pub struct RetryAfter(pub i64);

impl std::fmt::Display for RetryAfter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Provider requested a delayed retry")
    }
}

impl std::error::Error for RetryAfter {}

pub fn tls(ca: Option<&str>) -> Result<pratique::tls::ClientConfig> {
    let mut c = if let Some(path) = ca {
        pratique::tls::ClientConfig::new(pratique::sys::trust_store_from_pem_file(path)?)
    } else {
        pratique::tls::ClientConfig::with_system_roots()?
    };

    c.alpn_protocols.clear();

    Ok(c)
}

pub fn connect(host: &str, port: u16, ca: Option<&str>, implicit: bool) -> Result<Wire> {
    connect_scoped(host, port, ca, implicit, false)
}

/// Browser-created destinations must stay public at every connection, including
/// later retries. Connect to the checked address, while retaining the DNS TLS name.
pub(super) fn public_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2))))
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return public_destination(IpAddr::V4(v4));
            }
            let s = v.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && s[0] != 0x3fff
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
        }
    }
}

fn connect_scoped(
    host: &str,
    port: u16,
    ca: Option<&str>,
    implicit: bool,
    public_only: bool,
) -> Result<Wire> {
    let mut w = None;
    let addresses: Vec<_> = (host, port).to_socket_addrs()?.take(8).collect();
    ensure!(
        !addresses.is_empty(),
        "Delivery hostname has no usable addresses"
    );
    ensure!(
        !public_only || addresses.iter().all(|a| public_destination(a.ip())),
        "This destination resolves to a private or reserved address; use an installation-provisioned route for private networks"
    );
    for addr in addresses {
        if let Ok(tcp) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            w = Some(Wire::plain(tcp)?);

            break;
        }
    }

    let mut w = w.ok_or_else(|| crate::error!("Cannot connect to provisioned endpoint"))?;

    w.deadline.set(Duration::from_secs(30));

    if implicit {
        w.starttls_client(host, &tls(ca)?)?;
    }

    Ok(w)
}

fn response(w: &mut Wire, code: u16) -> Result<String> {
    let mut lines = String::new();

    for _ in 0..100 {
        let l = w.text(4096)?;

        ensure!(
            l.is_ascii() && l.len() >= 4 && l[..3].parse::<u16>()? == code,
            "Unexpected SMTP response"
        );

        lines.push_str(&l);

        lines.push('\n');

        if l.as_bytes()[3] == b' ' {
            return Ok(lines);
        }

        ensure!(l.as_bytes()[3] == b'-', "Invalid SMTP continuation");
    }

    bail!("Too many SMTP response lines")
}

fn smtp(c: &Route) -> Result<Wire> {
    let mut w = connect_scoped(
        &c.host,
        c.port,
        c.ca_file.as_deref(),
        c.implicit_tls,
        c.public_only,
    )?;

    let greeting = response(&mut w, 220)?;

    ensure!(
        !greeting.contains("Workglen Security"),
        "Routing loop to security gateway"
    );

    w.send("EHLO workglen-security\r\n")?;

    let capabilities = response(&mut w, 250)?;

    if !w.secure {
        ensure!(
            capabilities
                .lines()
                .any(|s| s[4..].eq_ignore_ascii_case("STARTTLS")),
            "Next hop requires STARTTLS"
        );

        w.send("STARTTLS\r\n")?;

        response(&mut w, 220)?;

        w.starttls_client(&c.host, &tls(c.ca_file.as_deref())?)?;

        w.send("EHLO workglen-security\r\n")?;

        response(&mut w, 250)?;
    }

    if let (Some(user), Some(file)) = (&c.username, &c.password_file) {
        ensure!(!user.contains(['\0', '\r', '\n']), "Invalid SMTP username");

        let password = crate::config::secret(file)?;

        ensure!(!password.contains('\0'), "Invalid SMTP credential");

        w.send(&format!(
            "AUTH PLAIN {}\r\n",
            STANDARD.encode(format!("\0{user}\0{password}"))
        ))?;

        response(&mut w, 235)?;
    }

    Ok(w)
}

pub fn probe(c: &Route) -> Result<()> {
    let mut w = smtp(c)?;

    w.send("NOOP\r\n")?;

    response(&mut w, 250)?;

    let _ = w.send("QUIT\r\n");

    Ok(())
}

pub fn valid_lines(raw: &[u8]) -> bool {
    raw.iter().enumerate().all(|(i, b)| {
        (*b != b'\n' || i > 0 && raw[i - 1] == b'\r')
            && (*b != b'\r' || raw.get(i + 1) == Some(&b'\n'))
    })
}

pub fn send(c: &Route, sender: &str, recipient: &str, raw: &[u8]) -> Result<()> {
    if !sender.is_empty() {
        address(sender)?;
    }

    address(recipient)?;

    ensure!(valid_lines(raw), "Ambiguous SMTP line endings");

    let mut w = smtp(c)?;

    w.send(&format!("MAIL FROM:<{sender}>\r\n"))?;

    response(&mut w, 250)?;

    w.send(&format!("RCPT TO:<{recipient}>\r\n"))?;

    response(&mut w, 250)?;

    w.send("DATA\r\n")?;

    response(&mut w, 354)?;

    let mut body = Vec::with_capacity(raw.len() + 1024);

    let mut start = true;

    for b in raw {
        if start && *b == b'.' {
            body.push(b'.');
        }

        body.push(*b);

        start = *b == b'\n';
    }

    if !body.ends_with(b"\r\n") {
        body.extend_from_slice(b"\r\n");
    }

    body.extend_from_slice(b".\r\n");

    w.bytes(&body).map_err(|_| Uncertain)?;

    let first = w.text(4096).map_err(|_| Uncertain)?;

    ensure!(
        first.starts_with("250 "),
        "Next hop did not acknowledge accepted content"
    );

    let _ = w.send("QUIT\r\n");

    Ok(())
}

/// Add our trusted SMTP hop to the outgoing copy, never to the preserved blob.
/// Source metadata comes from the socket at acceptance, not message headers or
/// the untrusted EHLO value. Retries and releases reproduce the same trace.
pub(super) fn delivery_copy(raw: &[u8], message: &Value, hostname: &str) -> Result<Vec<u8>> {
    let Some(source) = message["engines"].get("source_ip") else {
        // Mailbox remediation has no observed SMTP peer. Do not invent one.
        return Ok(raw.to_vec());
    };
    let ip: IpAddr = source
        .as_str()
        .ok_or_else(|| crate::error!("Invalid stored SMTP peer"))?
        .parse()?;
    let peer = match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => ip.to_string(),
            None => format!("IPv6:{ip}"),
        },
    };
    let id = s(message, "id")?;
    ensure!(
        crate::config::domain(hostname)
            && (1..=64).contains(&id.len())
            && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "Invalid stored SMTP trace identity"
    );
    let arrived = message["arrived"]
        .as_i64()
        .filter(|t| (0..=253402300799).contains(t))
        .ok_or_else(|| crate::error!("Invalid stored SMTP arrival time"))?;
    let date = crate::datetime::DateTime::from_timestamp(arrived, 0)
        .ok_or_else(|| crate::error!("Invalid stored SMTP arrival time"))?
        .to_rfc2822();
    let mut copy = format!(
        "Received: from [{peer}]\r\n\tby {hostname} (Workglen) with ESMTP id {id};\r\n\t{date}\r\n"
    )
    .into_bytes();
    copy.extend_from_slice(raw);
    Ok(copy)
}

fn accept_batch(
    t: &mut Table,
    requests: &[AcceptanceRequest],
) -> Result<Vec<std::result::Result<Vec<String>, String>>> {
    let mut results = Vec::with_capacity(requests.len());
    for request in requests {
        let preflight = (|| -> Result<Value> {
            ensure!(
                super::cluster::acceptance_eligible(t)?,
                "Cluster node is drained or resynchronizing"
            );
            ensure!(
                must(t, "settings")?["revision"] == request.settings["revision"],
                "Configuration changed; retry"
            );
            let active = super::service::active(t)?;
            super::service::capacity_check(
                t,
                &request.settings,
                request.raw.len(),
                request.recipients.len(),
                request.recipients.len(),
            )?;
            Ok(active)
        })();
        let active = match preflight {
            Ok(active) => active,
            Err(error) => {
                results.push(Err(error.to_string()));
                continue;
            }
        };
        results.push(Ok(commit_acceptance(t, request, &active)?));
    }
    Ok(results)
}

fn commit_acceptance(
    t: &mut Table,
    request: &AcceptanceRequest,
    active: &Value,
) -> Result<Vec<String>> {
    let content_hash = blob(t, &request.raw)?;
    let ingress_id = id();
    let arrived = now()?;
    let shadow_version = get(t, "shadow")?
        .and_then(|version| version.as_u64())
        .filter(|version| *version != active["id"].as_u64().unwrap_or(0))
        .map_or(Value::Null, |version| json!(version));
    let mut routes = json!({});
    for recipient in &request.recipients {
        let domain = recipient.rsplit('@').next().unwrap_or("");
        routes[recipient] = request.settings["routes"][domain].clone();
    }
    let replication_enabled = super::cluster::enabled(t)?;
    let mut record = json!({
        "id":ingress_id,
        "state":if replication_enabled { "awaiting-replication" } else { "queued" },
        "due":arrived,
        "attempts":0,
        "lease_token":null,
        "lease_until":0,
        "cancel_requested":false,
        "error":"",
        "hash":content_hash,
        "envelope_from":request.sender,
        "recipients":request.recipients,
        "source_ip":request.ip.to_string(),
        "helo":request.helo,
        "arrived":arrived,
        "expires":arrived+n(&request.settings,"retention_days")? as i64*86400,
        "routes":routes,
        "settings_revision":request.settings["revision"],
        "analysis_settings":super::scan_worker::analysis_settings(&request.settings)?,
        "scan_lane":super::scan_worker::scheduling_lane(&request.raw),
        "rule_version":active["id"],
        "shadow_version":shadow_version,
        "api_version":super::scan::ANALYSIS_API_VERSION,
        "profile_version":super::scan::ANALYSIS_PROFILE_VERSION,
        "coverage_version":super::scan::COVERAGE_VERSION
        ,"replication_degraded":false
        ,"replication_ready_at":if replication_enabled { Value::Null } else { json!(arrived) }
    });
    let ownership = super::cluster::new_ingress_metadata(t)?;
    for field in [
        "origin_node",
        "origin_sequence",
        "delivery_partition",
        "delivery_owner",
        "delivery_term",
        "scan_owner",
        "scan_generation",
    ] {
        record[field] = ownership[field].clone();
    }
    put(t, &format!("ingress/{ingress_id}"), &record)?;
    super::cluster::record_acceptance(t, &record)?;
    for recipient in &request.recipients {
        audit(
            t,
            "smtp",
            "accepted-pending-scan",
            recipient,
            json!({
                "ingress":ingress_id,
                "hash":content_hash,
                "state":"pending-scan",
                "version":active["id"],
                "api_version":super::scan::ANALYSIS_API_VERSION,
                "profile_version":super::scan::ANALYSIS_PROFILE_VERSION,
                "coverage_version":super::scan::COVERAGE_VERSION
            }),
        )?;
    }
    Ok(vec![ingress_id])
}

impl Service {
    pub fn accept(
        &self,
        raw: &[u8],
        sender: &str,
        recipients: &[String],
        ip: IpAddr,
        helo: &str,
    ) -> Result<Vec<String>> {
        ensure!(
            valid_lines(raw) && raw.len() <= MAX_MESSAGE,
            "Invalid SMTP content"
        );

        let settings = self.settings()?;

        ensure!(settings["enabled"] == true, "Gateway paused");
        super::filesystem::admit(
            std::path::Path::new(&self.config.data_dir),
            raw.len(),
            n(&settings, "min_free_bytes")?,
        )?;
        ensure!(
            raw.len() <= super::scan::scan_limits(&settings)?.input_bytes,
            "Message exceeds configured scanner input budget"
        );

        ensure!(
            (1..=25).contains(&recipients.len())
                && recipients.iter().all(|r| settings["mailboxes"]
                    .get(r)
                    .is_some_and(|p| p["enabled"] != false)),
            "Recipient rejected"
        );

        let recipients: Vec<String> = recipients
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let ids = self.acceptance.accept(
            raw.to_vec(),
            sender.to_string(),
            recipients,
            ip,
            helo.to_string(),
            settings,
        )?;
        if self.config.replication.is_some() {
            let result = super::cluster_transport::wait_for_acceptance(self, &ids);
            match result {
                Ok(degraded) => self
                    .db
                    .write(|t| super::cluster::complete_acceptance(t, &ids, degraded))?,
                Err(error) => {
                    let reason = error.to_string();
                    self.db
                        .write(|t| super::cluster::defer_acceptance(t, &ids, &reason))?;
                    return Err(error);
                }
            }
        }
        Ok(ids)
    }
}

pub fn start(service: Arc<Service>) -> Result<std::thread::JoinHandle<()>> {
    let listener = TcpListener::bind(service.config.smtp_listen)?;

    let tls = service.tls()?;

    let gate = crate::net::Gate::new(16);

    Ok(std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { continue };

            let Some(permit) = gate.enter() else { continue };

            let s = service.clone();

            let tls = tls.clone();

            std::thread::spawn(move || {
                let _ = crate::resilience::boundary("security SMTP session", move || {
                    let _permit = permit;
                    handle(&s, tcp, &tls)
                });
            });
        }
    }))
}

fn envelope<'a>(arg: &'a str, prefix: &str) -> Result<(&'a str, &'a str)> {
    let (p, rest) = arg
        .split_once(':')
        .ok_or_else(|| crate::error!("Invalid envelope"))?;

    ensure!(p.eq_ignore_ascii_case(prefix), "Invalid envelope");

    let rest = rest
        .trim_start()
        .strip_prefix('<')
        .ok_or_else(|| crate::error!("Invalid envelope"))?;

    let (a, tail) = rest
        .split_once('>')
        .ok_or_else(|| crate::error!("Invalid envelope"))?;

    Ok((a, tail))
}

fn handle(
    svc: &Service,
    tcp: TcpStream,
    tls: &Arc<pratique::tls::server::ServerConfig>,
) -> Result<()> {
    let ip = tcp.peer_addr()?.ip();

    let mut w = Wire::plain(tcp)?;

    w.send(&format!(
        "220 {} Workglen Security\r\n",
        svc.config.hostname
    ))?;

    let start = Instant::now();

    let mut helo = String::new();

    let mut sender = None;

    let mut recipients = Vec::new();

    for _ in 0..500 {
        ensure!(
            start.elapsed() < Duration::from_secs(300),
            "SMTP connection deadline"
        );

        w.deadline.set(
            Duration::from_secs(30).min(Duration::from_secs(300).saturating_sub(start.elapsed())),
        );

        let line = w.text(8192)?;

        ensure!(line.is_ascii(), "ASCII commands required");

        let (cmd, arg) = line.split_once(' ').unwrap_or((&line, ""));

        match cmd.to_ascii_uppercase().as_str() {
            "EHLO" | "HELO" => {
                ensure!(
                    !arg.is_empty() && arg.len() <= 255 && !arg.chars().any(char::is_control),
                    "Invalid greeting"
                );

                helo = arg.into();

                sender = None;

                recipients.clear();

                let message_limit = super::scan::scan_limits(&svc.settings()?)?.input_bytes;
                w.send(&format!(
                    "250-{}\r\n250-SIZE {message_limit}\r\n{}250 8BITMIME\r\n",
                    svc.config.hostname,
                    if w.secure { "" } else { "250-STARTTLS\r\n" }
                ))?;
            }

            "QUIT" => {
                w.send("221 Bye\r\n")?;

                return Ok(());
            }

            "NOOP" => w.send("250 OK\r\n")?,
            "RSET" => {
                sender = None;

                recipients.clear();

                w.send("250 Reset\r\n")?;
            }

            "STARTTLS" if !w.secure && !helo.is_empty() => {
                w.send("220 Start TLS\r\n")?;

                w.starttls(tls)?;

                helo.clear();

                sender = None;

                recipients.clear();
            }

            _ if helo.is_empty() => w.send("503 EHLO first\r\n")?,
            _ if svc.config.require_inbound_tls && !w.secure => {
                w.send("530 STARTTLS required\r\n")?
            }

            "MAIL" => {
                sender = None;

                recipients.clear();

                let message_limit = super::scan::scan_limits(&svc.settings()?)?.input_bytes;
                let parsed = (|| -> Result<String> {
                    let (a, tail) = envelope(arg, "FROM")?;

                    for option in tail.split_whitespace() {
                        let u = option.to_ascii_uppercase();

                        if let Some(size) = u.strip_prefix("SIZE=") {
                            ensure!(size.parse::<usize>()? <= message_limit, "Message too large");
                        } else {
                            ensure!(u == "BODY=8BITMIME", "Unsupported MAIL parameter");
                        }
                    }

                    Ok(if a.is_empty() {
                        String::new()
                    } else {
                        address(a)?
                    })
                })();

                if let Ok(a) = parsed {
                    sender = Some(a);

                    w.send("250 Sender accepted\r\n")?;
                } else {
                    w.send("501 Invalid sender or parameters\r\n")?;
                }
            }

            "RCPT" if sender.is_some() => {
                let parsed = (|| -> Result<String> {
                    let (a, tail) = envelope(arg, "TO")?;

                    ensure!(tail.is_empty(), "Unsupported recipient parameter");

                    let r = address(a)?;

                    let v = svc.settings()?;

                    ensure!(
                        v["enabled"] == true
                            && recipients.len() < 25
                            && v["mailboxes"]
                                .get(&r)
                                .is_some_and(|v| v["enabled"] != false),
                        "Recipient unavailable"
                    );

                    Ok(r)
                })();

                if let Ok(r) = parsed {
                    recipients.push(r);

                    w.send("250 Recipient accepted\r\n")?;
                } else {
                    w.send("550 Recipient unavailable\r\n")?;
                }
            }

            "DATA" if sender.is_some() && !recipients.is_empty() && arg.is_empty() => {
                let message_limit = super::scan::scan_limits(&svc.settings()?)?.input_bytes;
                w.send("354 End with dot\r\n")?;

                let mut raw = Vec::new();

                let mut over = false;

                loop {
                    let line = w.line(65538)?;

                    ensure!(start.elapsed() < Duration::from_secs(300), "SMTP deadline");

                    if line == b".\r\n" {
                        break;
                    }

                    let line = if line.starts_with(b"..") {
                        &line[1..]
                    } else {
                        &line[..]
                    };

                    if raw.len() + line.len() > message_limit {
                        over = true;
                    }

                    if !over {
                        raw.extend_from_slice(line);
                    }
                }

                if over {
                    w.send("552 Message too large\r\n")?;
                } else {
                    let result =
                        svc.accept(&raw, sender.as_deref().unwrap(), &recipients, ip, &helo);

                    svc.record_smtp_result(result.is_ok());
                    if result.is_err() {
                        super::exit_if_storage_failed(svc);
                    }

                    w.send(if result.is_ok() {
                        "250 Stored securely\r\n"
                    } else {
                        "451 Processing unavailable; retry later\r\n"
                    })?;
                }

                sender = None;

                recipients.clear();
            }

            _ => w.send("503 Invalid command or sequence\r\n")?,
        }
    }

    Ok(())
}
