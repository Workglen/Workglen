//! Direct MX delivery and optional authenticated relay, sharing one durable queue.
use crate::encoding::STANDARD;
use crate::error::{Context, Result, bail, ensure};
use crate::{
    app::App,
    config::{Config, DeliveryTls, QueueItem, secret},
    net::Wire,
    store::{self, Op},
};
use pratique::{tls::ClientConfig, x509::TrustStore};
use std::{
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(crate) struct Permanent(pub String);
impl std::fmt::Display for Permanent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Permanent {}
#[derive(Debug)]
struct UncertainDelivery;
impl std::fmt::Display for UncertainDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "4.4.2 connection lost after DATA terminator; acceptance unknown, queued for retry",
        )
    }
}
impl std::error::Error for UncertainDelivery {}

pub fn status(app: &App) -> pratique::json_value::Value {
    pratique::json_value::json!({
        "mode": if app.config.direct.is_some() { "direct" } else if app.config.relay.is_some() { "relay" } else { "disabled" },
        "tls": app.config.direct.as_ref().map(|d| d.tls),
        "dkim_selector": app.config.dkim.as_ref().map(|d| d.selector.as_str()),
        "dkim_domain": app.config.dkim.as_ref().map(|_| app.config.domain.as_str()),
    })
}

pub fn tls_config(config: &Config) -> Result<Option<ClientConfig>> {
    if !config.outbound_enabled() {
        return Ok(None);
    }
    let ca = config
        .relay
        .as_ref()
        .map(|r| r.ca_file.as_str())
        .or_else(|| config.direct.as_ref().and_then(|d| d.ca_file.as_deref()));
    let mut client = if let Some(ca) = ca {
        let mut roots = TrustStore::empty();
        ensure!(
            roots.add_pem(&std::fs::read_to_string(ca)?) > 0,
            "no outbound CA certificates"
        );
        ClientConfig::new(roots)
    } else {
        ClientConfig::with_system_roots()?
    };
    client.alpn_protocols.clear();
    Ok(Some(client))
}
#[derive(Debug)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}
fn response(w: &mut Wire) -> Result<Reply> {
    let mut code = None;
    let mut lines = Vec::new();
    for _ in 0..50 {
        let line = w.text(1024)?;
        let bytes = line.as_bytes();
        ensure!(
            bytes.len() >= 3 && bytes[..3].iter().all(u8::is_ascii_digit),
            "malformed SMTP reply"
        );
        ensure!(
            !bytes.iter().any(|b| b.is_ascii_control() && *b != b'\t'),
            "control character in SMTP reply"
        );
        let n: u16 = line[..3].parse()?;
        ensure!(
            (200..600).contains(&n) && code.is_none_or(|c| c == n),
            "inconsistent SMTP reply code"
        );
        code = Some(n);
        let separator = bytes.get(3).copied().unwrap_or(b' ');
        ensure!(
            separator == b' ' || separator == b'-',
            "invalid SMTP reply separator"
        );
        lines.push(line.get(4..).unwrap_or("").to_string());
        if separator == b' ' {
            return Ok(Reply { code: n, lines });
        }
    }
    bail!("too many SMTP reply lines")
}
fn expect(reply: Reply, accepted: &[u16], stage: &str, permanent: bool) -> Result<Reply> {
    if accepted.contains(&reply.code) {
        return Ok(reply);
    }
    let reason = format!("SMTP {} at {stage}", reply.code);
    if permanent && reply.code >= 500 {
        return Err(Permanent(reason).into());
    }
    bail!("{reason}")
}
fn arm(w: &Wire, until: Instant, seconds: u64) -> Result<()> {
    let left = until.saturating_duration_since(Instant::now());
    ensure!(!left.is_zero(), "delivery attempt time budget exhausted");
    w.deadline.set(left.min(Duration::from_secs(seconds)));
    Ok(())
}
fn command(
    w: &mut Wire,
    until: Instant,
    text: &str,
    accepted: &[u16],
    stage: &str,
    permanent: bool,
) -> Result<Reply> {
    arm(w, until, 300)?;
    w.send(text)?;
    expect(response(w)?, accepted, stage, permanent)
}
#[derive(Default)]
struct Capabilities {
    starttls: bool,
    eight_bit: bool,
    size: Option<usize>,
    auth_plain: bool,
}
fn capabilities(reply: &Reply) -> Result<Capabilities> {
    let mut c = Capabilities::default();
    for line in reply.lines.iter().skip(1) {
        let mut words = line.split_ascii_whitespace();
        match words.next().unwrap_or("").to_ascii_uppercase().as_str() {
            "STARTTLS" => c.starttls = true,
            "8BITMIME" => c.eight_bit = true,
            "SIZE" => {
                if let Some(value) = words.next() {
                    let size: usize = value.parse().context("invalid EHLO SIZE")?;
                    if size > 0 {
                        c.size = Some(c.size.map_or(size, |n| n.min(size)));
                    }
                }
            }
            "AUTH" => c.auth_plain = words.any(|m| m.eq_ignore_ascii_case("PLAIN")),
            _ => {}
        }
    }
    Ok(c)
}
fn greeting(w: &mut Wire, app: &App, until: Instant, relay: bool) -> Result<Capabilities> {
    arm(w, until, 300)?;
    w.send(&format!("EHLO {}\r\n", app.config.hostname))?;
    let reply = response(w)?;
    if !relay && [500, 502, 504].contains(&reply.code) {
        command(
            w,
            until,
            &format!("HELO {}\r\n", app.config.hostname),
            &[250],
            "HELO",
            false,
        )?;
        return Ok(Capabilities::default());
    }
    capabilities(&expect(reply, &[250], "EHLO", false)?)
}
/// No SMTPUTF8 or on-the-fly MIME conversion: signed octets must be preserved.
pub(crate) fn message_features(body: &[u8]) -> Result<bool> {
    let head = body
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| crate::error!("message has no header separator"))?;
    ensure!(
        body[..head].is_ascii(),
        "SMTPUTF8 headers are unsupported; use MIME encoded words"
    );
    ensure!(body.ends_with(b"\r\n"), "message must end with CRLF");
    for (i, b) in body.iter().enumerate() {
        ensure!(
            *b != 0
                && (*b != b'\r' || body.get(i + 1) == Some(&b'\n'))
                && (*b != b'\n' || i > 0 && body[i - 1] == b'\r'),
            "invalid message line ending or NUL"
        );
    }
    ensure!(
        body.split_inclusive(|b| *b == b'\n')
            .all(|l| l.len() <= 1000),
        "message line exceeds SMTP limit"
    );
    Ok(!body[head + 4..].is_ascii())
}
fn session(
    app: &App,
    item: &QueueItem,
    body: &[u8],
    eight_bit: bool,
    addr: SocketAddr,
    host: &str,
    until: Instant,
) -> Result<()> {
    app.require_mail()?;
    let relay = app.config.relay.as_ref();
    let remaining = until.saturating_duration_since(Instant::now());
    ensure!(
        !remaining.is_zero(),
        "delivery attempt time budget exhausted"
    );
    let tcp = TcpStream::connect_timeout(&addr, remaining.min(Duration::from_secs(10)))?;
    let mut w = Wire::plain(tcp)?;
    if relay.is_some() {
        arm(&w, until, 20)?;
        w.starttls_client(host, app.outbound_tls.as_ref().unwrap())?;
    }
    arm(&w, until, 300)?;
    expect(response(&mut w)?, &[220], "greeting", false)?;
    let mut caps = greeting(&mut w, app, until, relay.is_some())?;
    if relay.is_none() {
        if caps.starttls {
            command(&mut w, until, "STARTTLS\r\n", &[220], "STARTTLS", false)?;
            arm(&w, until, 20)?;
            w.starttls_client(host, app.outbound_tls.as_ref().unwrap())?;
            // RFC 3207: discard all capabilities learned before TLS.
            caps = greeting(&mut w, app, until, false)?;
        } else {
            ensure!(
                app.config.direct.as_ref().unwrap().tls == DeliveryTls::Opportunistic,
                "4.7.5 destination offers no STARTTLS; TLS is required"
            );
        }
    }
    if let Some(relay) = relay {
        ensure!(
            caps.auth_plain,
            "configured relay does not advertise AUTH PLAIN"
        );
        let password = secret(&relay.password_file)?;
        let credentials = STANDARD.encode(format!("\0{}\0{}", relay.username, password));
        // Authentication failures are configuration errors, not recipient bounces.
        command(
            &mut w,
            until,
            &format!("AUTH PLAIN {credentials}\r\n"),
            &[235],
            "AUTH",
            false,
        )?;
    }
    if caps.size.is_some_and(|max| body.len() > max) {
        return Err(Permanent("5.3.4 signed message exceeds destination SIZE limit".into()).into());
    }
    ensure!(
        !eight_bit || caps.eight_bit,
        "4.6.3 destination lacks 8BITMIME; refusing to alter signed message"
    );
    app.require_mail()?;
    let mut envelope = format!("MAIL FROM:<{}>", item.sender);
    if caps.size.is_some() {
        envelope.push_str(&format!(" SIZE={}", body.len()));
    }
    if eight_bit {
        envelope.push_str(" BODY=8BITMIME");
    }
    envelope.push_str("\r\n");
    command(&mut w, until, &envelope, &[250], "MAIL FROM", true)?;
    command(
        &mut w,
        until,
        &format!("RCPT TO:<{}>\r\n", item.recipient),
        &[250, 251],
        "RCPT TO",
        true,
    )?;
    command(&mut w, until, "DATA\r\n", &[354], "DATA", true)?;
    arm(&w, until, 180)?;
    for line in body.split_inclusive(|b| *b == b'\n') {
        app.require_mail()?;
        if line.starts_with(b".") {
            w.bytes(b".")?;
        }
        w.bytes(line)?;
    }
    app.require_mail()?;
    // Once the terminator may have reached the peer, never try another MX in
    // this attempt without an explicit SMTP reply. A lost 250 is ambiguous.
    arm(&w, until, 600)?;
    w.send(".\r\n")
        .map_err(|_| crate::error::Error::from(UncertainDelivery))?;
    let reply = response(&mut w).map_err(|_| crate::error::Error::from(UncertainDelivery))?;
    expect(reply, &[250], "end of DATA", true)?;
    // Delivery is committed remotely. A QUIT/connection-close error is irrelevant.
    w.deadline.set(Duration::from_secs(2));
    let _ = w.send("QUIT\r\n");
    Ok(())
}
fn send(app: &App, item: &QueueItem) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(1200);
    let body = app.read_store()?.blob(&item.blob)?;
    let eight_bit = message_features(&body)
        .map_err(|e| crate::error::Error::from(Permanent(format!("5.6.0 {e}"))))?;
    let targets = if let Some(relay) = &app.config.relay {
        crate::routing::relay_targets(app, &relay.address)?
            .into_iter()
            .map(|a| (relay.server_name.clone(), a))
            .collect::<Vec<_>>()
    } else {
        ensure!(
            item.dkim_signed,
            "direct delivery refuses an unsigned queue item"
        );
        let domain = item
            .recipient
            .rsplit_once('@')
            .ok_or_else(|| crate::error!("invalid queued recipient"))?
            .1;
        crate::routing::direct_targets(app, domain)?
            .into_iter()
            .map(|t| (t.host, t.address))
            .collect()
    };
    let mut last = None;
    for (host, address) in targets {
        app.require_mail()?;
        match session(app, item, &body, eight_bit, address, &host, until) {
            Ok(()) => return Ok(()),
            Err(e) if e.is::<Permanent>() || e.is::<UncertainDelivery>() => return Err(e),
            Err(e) => last = Some(e.context(format!("destination {host}"))),
        }
        if Instant::now() >= until {
            break;
        }
    }
    Err(last.unwrap_or_else(|| crate::error!("no delivery destination")))
}
fn finish(app: &App, key: &str, item: &QueueItem, result: Result<()>) -> Result<()> {
    let now = crate::datetime::Utc::now()?.timestamp();
    match result {
        Ok(()) => app.commit(|t| {
            let mut ops = vec![Op::del(key.into())];
            ops.extend(store::gc_ops(t, &[key.into()])?);
            Ok((ops, ()))
        }),
        Err(e) => {
            let mut item = item.clone();
            item.attempts = item.attempts.saturating_add(1);
            item.last_error = format!("{e:#}")
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .take(256)
                .collect();
            let failed = e.downcast_ref::<Permanent>().is_some()
                || now.saturating_sub(item.created) > 5 * 86400;
            item.status = if e.is::<crate::resilience::IsolatedPanic>() {
                "uncertain"
            } else if failed {
                "failed"
            } else {
                "pending"
            }
            .into();
            let base = app
                .config
                .direct
                .as_ref()
                .map_or(60, |d| d.retry_seconds as i64);
            item.next_try = now
                + (base.saturating_mul(1i64 << item.attempts.saturating_sub(1).min(12)))
                    .min(6 * 3600);
            eprintln!("queue {}: {} ({})", key, item.status, item.last_error);
            app.commit(|t|{let mut ops=vec![Op::json(key.into(),&item)?];
            if failed{let id=store::random_id();let body=format!("From: Mail Delivery System <postmaster@{}>\r\nTo: {}\r\nDate: {}\r\nMessage-ID: <{}@{}>\r\nSubject: Mail delivery failed\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour message to {} could not be delivered.\r\nReason: {}\r\nQueue reference: {}\r\nThe original remains available to the administrator in the failed queue.\r\n",app.config.domain,item.sender,crate::datetime::Utc::now()?.to_rfc2822(),id,app.config.hostname,item.recipient,item.last_error,key).into_bytes();
                if let Ok((more,_,_))=store::append_ops(t,&item.sender,"INBOX",&id,body.len(),vec![],now,&app.config.limits){ops.extend(more);ops.push(Op{key:format!("blob/{id}"),value:Some(body)});}else{eprintln!("delivery failure notice could not be stored; inspect failed queue");}}
            Ok((ops,()))
        })
        }
    }
}
pub fn run(app: Arc<App>) {
    loop {
        let _ = crate::resilience::boundary("relay worker", || {
            if app.primary() && app.mail_enabled() && app.config.outbound_enabled() {
                let queue = app.read_store().and_then(|s| s.list::<QueueItem>("queue/"));
                if let Ok(queue) = queue {
                    for (key, _) in queue {
                        if !app.primary() || !app.mail_enabled() {
                            break;
                        }
                        let item = app.read_store().and_then(|s| s.get::<QueueItem>(&key));
                        let Ok(Some(item)) = item else { continue };
                        if item.status != "pending"
                            || item.next_try > crate::datetime::Utc::now()?.timestamp()
                        {
                            continue;
                        }
                        let Some(_permit) = app.data.enter() else {
                            break;
                        };
                        let _delivery =
                            app.relay_activity.lock().unwrap_or_else(|e| e.into_inner());
                        if !app.primary() || !app.mail_enabled() {
                            break;
                        }
                        let result = if crate::datetime::Utc::now()?
                            .timestamp()
                            .saturating_sub(item.created)
                            >= 5 * 86400
                        {
                            Err(crate::error::Error::from(Permanent(
                                "5.4.7 delivery queue lifetime expired".into(),
                            )))
                        } else {
                            // Persist the ambiguous phase before contacting the
                            // peer. A panic during send or result persistence
                            // must not make the next loop silently redeliver.
                            let mut sending = item.clone();
                            sending.status = "sending".into();
                            app.commit(|t| {
                                let current: QueueItem = store::json(t, &key)?
                                    .ok_or_else(|| crate::error!("Queue item disappeared"))?;
                                ensure!(current.status == "pending", "Queue item changed");
                                Ok((vec![Op::json(key.clone(), &sending)?], ()))
                            })?;
                            crate::resilience::boundary("SMTP delivery", || send(&app, &item))
                        };
                        if let Err(e) = finish(&app, &key, &item, result) {
                            eprintln!("queue state update failed: {e}");
                        }
                    }
                }
            }
            Ok(())
        });
        std::thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn reply(bytes: &[u8]) -> Result<Reply> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let bytes = bytes.to_vec();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let _ = socket.write_all(&bytes);
        });
        let mut wire = Wire::plain(TcpStream::connect(address)?)?;
        let result = response(&mut wire);
        peer.join().unwrap();
        result
    }
    #[test]
    fn smtp_replies_are_framed_and_bounded() {
        assert_eq!(reply(b"220\r\n").unwrap().code, 220);
        assert_eq!(
            reply(b"250-fixture\r\n250 SIZE 1000\r\n")
                .unwrap()
                .lines
                .len(),
            2
        );
        for invalid in [
            &b"250-fixture\r\n550 changed code\r\n"[..],
            b"250bad separator\r\n",
            b"250 control\x00\r\n",
            b"250 bare LF\n",
        ] {
            assert!(reply(invalid).is_err());
        }
        assert!(reply(&b"250-more\r\n".repeat(51)).is_err());
    }
    #[test]
    fn signed_message_transfer_never_rewrites_octets() {
        assert!(!message_features(b"From: a@example.test\r\n\r\nASCII\r\n").unwrap());
        assert!(message_features("From: a@example.test\r\n\r\ncafé\r\n".as_bytes()).unwrap());
        for invalid in [
            &b"From: a@example.test\r\n\r\nbare\rCR\r\n"[..],
            b"From: a@example.test\r\n\r\nNUL\0\r\n",
            b"From: a@example.test\r\n\r\nno final CRLF",
        ] {
            assert!(message_features(invalid).is_err());
        }
    }
}
