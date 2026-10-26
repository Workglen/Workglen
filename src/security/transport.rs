use super::{db::*, model::*, service::Service};

use crate::net::Wire;

use crate::error::{Result, bail, ensure};

use crate::encoding::STANDARD;

use pratique::json_value::{Value, json};

use std::{
    net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant},
};

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

        ensure!(
            (1..=25).contains(&recipients.len())
                && recipients.iter().all(|r| settings["mailboxes"]
                    .get(r)
                    .is_some_and(|p| p["enabled"] != false)),
            "Recipient rejected"
        );

        let policy = crate::config::Policy {
            quarantine_dmarc: true,
            ..Default::default()
        };

        let auth = self.checker.check_context(
            raw,
            crate::auth::AuthContext {
                ip,
                helo,
                from: sender,
                hostname: &self.config.hostname,
                policy: &policy,
                seconds: 20,
            },
        )?;

        ensure!(
            auth != crate::auth::Verdict::Temporary,
            "Temporary authentication lookup failure"
        );

        let evidence = json!({
        "authentication_action":if matches!(auth,crate::auth::Verdict::Quarantine|crate::auth::Verdict::Reject(_)){
        "quarantine"}
        else{
        "pass-policy"}
        ,"source_ip":ip.to_string(),"helo":helo,"engine":super::scan::ENGINE}
        );

        self.db.write(|t|{
ensure!(must(t,"settings")?["revision"]==settings["revision"],"Configuration changed; retry");
let v=super::service::active(t)?;
let verdict=self.evaluate(t,raw,&v["rules"],&settings,&evidence)?;
self.capacity(t,&settings,raw.len(),recipients.len(),recipients.len())?;
let hash=blob(t,raw)?;
let shadow=get(t,"shadow")?.map(|id|must(t,&format!("rule/{id}"))).transpose()?;
let mut ids=Vec::new();
let mut seen=std::collections::BTreeSet::new();
for recipient in recipients{
if !seen.insert(recipient){
continue}
let id=id();
let mut m=json!({
"id":id,"recipient":recipient,"arrived":now(),"state":if verdict["action"]=="quarantine"{
"quarantined"}
else{
"queued"}
,"revision":1,"hash":hash,"envelope_from":sender,"subject":verdict["subject"],"sender":verdict["sender"],"releasable":verdict["releasable"],"verdict":verdict,"engines":evidence,"rule_version":v["id"],"expires":now()+n(&settings,"retention_days")? as i64*86400,"hold":false,"route":settings["routes"][recipient.rsplit('@').next().unwrap_or("")]}
);
if let Some(shadow)=&shadow&& shadow["id"]!=v["id"]{
m["shadow"]=json!({
"version":shadow["id"],"verdict":self.evaluate(t,raw,&shadow["rules"],&settings,&evidence)?}
);
}
save_message(t,&m)?;
if m["state"]=="queued"{
job(t,"delivery",json!({
"recipient":recipient,"message":id}
),&format!("delivery-{id}"))?;
}
audit(t,"smtp","accepted",recipient,json!({
"id":id,"hash":hash,"state":m["state"],"version":v["id"],"engine":super::scan::ENGINE}
))?;
ids.push(id);
}
Ok(ids)}
)
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

                w.send(&format!(
                    "250-{}\r\n250-SIZE {MAX_MESSAGE}\r\n{}250 8BITMIME\r\n",
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

                let parsed = (|| -> Result<String> {
                    let (a, tail) = envelope(arg, "FROM")?;

                    for option in tail.split_whitespace() {
                        let u = option.to_ascii_uppercase();

                        if let Some(size) = u.strip_prefix("SIZE=") {
                            ensure!(size.parse::<usize>()? <= MAX_MESSAGE, "Message too large");
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

                    if raw.len() + line.len() > MAX_MESSAGE {
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
