use crate::encoding::STANDARD;
use crate::error::{Result, ensure};
use crate::{
    app::App,
    auth::{self, Verdict},
    config::{self, QueueItem, User},
    net::Wire,
    store::{self, Op},
};
use std::{
    net::{IpAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
fn path<'a>(s: &'a str, prefix: &str) -> Result<(String, &'a str)> {
    ensure!(
        s.len() >= prefix.len()
            && s.get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix)),
        "bad envelope command"
    );
    let s = s[prefix.len()..].trim_start();
    ensure!(s.starts_with('<'), "expected angle path");
    let end = s.find('>').ok_or_else(|| crate::error!("missing >"))?;
    let value = &s[1..end];
    Ok((
        if value.is_empty() {
            String::new()
        } else {
            config::address(value)?
        },
        s[end + 1..].trim(),
    ))
}
pub fn serve(tcp: TcpStream, app: Arc<App>, submission: bool) -> Result<()> {
    let ip = tcp.peer_addr()?.ip();
    let mut w = if submission {
        Wire::accept(tcp, &app.tls)?
    } else {
        Wire::plain(tcp)?
    };
    w.deadline
        .set(Duration::from_secs(app.config.limits.io_seconds));
    if !app.primary() || !app.mail_enabled() {
        w.send("421 4.3.2 Mail unavailable on this node; retry later\r\n")?;
        return Ok(());
    }
    if app
        .config
        .policy
        .blocked_ips
        .iter()
        .any(|s| s.parse::<IpAddr>().ok() == Some(ip))
    {
        w.send("554 5.7.1 Connection blocked\r\n")?;
        return Ok(());
    }
    w.send(&format!(
        "220 {} ESMTP Workglen Mail\r\n",
        app.config.hostname
    ))?;
    let start = Instant::now();
    let mut helo = String::new();
    let mut sender = None;
    let mut recipients: Vec<String> = Vec::new();
    let mut user: Option<String> = None;
    let mut auth_failures = 0;
    for _ in 0..app.config.limits.commands {
        if start.elapsed().as_secs() > app.config.limits.session_seconds
            || (!app.primary() || !app.mail_enabled())
        {
            w.send("421 4.3.2 Session ended\r\n")?;
            break;
        }
        w.deadline
            .set(Duration::from_secs(app.config.limits.io_seconds));
        let line = match w.text(512) {
            Ok(line) => line,
            Err(e) if e.is::<crate::net::LineTooLong>() => {
                // Do not drain an attacker-controlled unlimited line or process
                // its suffix as another command. Reply once, then close.
                let _ = w.send("500 5.5.2 Command line too long\r\n");
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        app.require_mail()?;
        let (verb, arg) = line.split_once(' ').unwrap_or((&line, ""));
        match verb.to_ascii_uppercase().as_str() {
            "EHLO" | "HELO" => {
                if !config::greeting(arg) {
                    w.send("501 5.5.2 Invalid greeting\r\n")?;
                    continue;
                }
                helo = arg.to_ascii_lowercase();
                sender = None;
                recipients.clear();
                if verb.eq_ignore_ascii_case("HELO") {
                    w.send(&format!("250 {}\r\n", app.config.hostname))?;
                } else {
                    w.send(&format!(
                        "250-{}\r\n250-SIZE {}\r\n250-8BITMIME\r\n",
                        app.config.hostname, app.config.limits.message_bytes
                    ))?;
                    if !w.secure {
                        w.send("250-STARTTLS\r\n")?;
                    }
                    if submission && w.secure {
                        w.send("250-AUTH PLAIN LOGIN\r\n")?;
                    }
                    w.send("250 HELP\r\n")?;
                }
            }
            "STARTTLS"
                if !submission
                    && !w.secure
                    && !helo.is_empty()
                    && sender.is_none()
                    && arg.is_empty() =>
            {
                w.send("220 2.0.0 Begin TLS\r\n")?;
                w.starttls(&app.tls)?;
                helo.clear();
                user = None;
                recipients.clear();
            }
            "AUTH"
                if submission
                    && w.secure
                    && !helo.is_empty()
                    && sender.is_none()
                    && user.is_none() =>
            {
                let result = authenticate(&mut w, arg, &app);
                match result {
                    Ok(Some(u)) => {
                        user = Some(u);
                        w.send("235 2.7.0 Authenticated\r\n")?;
                    }
                    _ => {
                        auth_failures += 1;
                        w.send("535 5.7.8 Authentication failed\r\n")?;
                        if auth_failures >= 3 {
                            break;
                        }
                    }
                }
            }
            "MAIL" => {
                sender = None;
                recipients.clear();
                if helo.is_empty() {
                    w.send("503 5.5.1 Send EHLO first\r\n")?;
                    continue;
                }
                if submission && user.is_none() {
                    w.send("530 5.7.0 Authenticate first\r\n")?;
                    continue;
                }
                match path(arg, "FROM:") {
                    Ok((from, params)) => {
                        let valid = params.split_whitespace().all(|p| {
                            p.eq_ignore_ascii_case("BODY=8BITMIME")
                                || p.eq_ignore_ascii_case("BODY=7BIT")
                                || p.to_ascii_uppercase()
                                    .strip_prefix("SIZE=")
                                    .and_then(|s| s.parse::<usize>().ok())
                                    .is_some_and(|n| n <= app.config.limits.message_bytes)
                        });
                        if !valid {
                            w.send("555 5.5.4 Unsupported or excessive MAIL parameter\r\n")?;
                            continue;
                        }
                        if submission && user.as_deref() != Some(&from) {
                            w.send("553 5.7.1 Sender must match authenticated account\r\n")?;
                            continue;
                        }
                        if auth::blocked(&from, &app.config.policy) {
                            w.send("550 5.7.1 Sender blocked\r\n")?;
                            continue;
                        }
                        sender = Some(from);
                        w.send("250 2.1.0 Sender accepted\r\n")?;
                    }
                    Err(_) => w.send("501 5.5.2 Invalid sender\r\n")?,
                }
            }
            "RCPT" => {
                if sender.is_none() {
                    w.send("503 5.5.1 MAIL required\r\n")?;
                    continue;
                }
                if recipients.len() >= app.config.limits.recipients {
                    w.send("452 4.5.3 Too many recipients\r\n")?;
                    continue;
                }
                match path(arg, "TO:") {
                    Ok((to, params)) if !to.is_empty() && params.is_empty() => {
                        let local = to.rsplit_once('@').unwrap().1 == app.config.domain;
                        if local
                            && app
                                .read_store()?
                                .get::<User>(&format!("user/{to}"))?
                                .is_none()
                        {
                            w.send("550 5.1.1 Unknown recipient\r\n")?;
                        } else if !local && (!submission || !app.config.outbound_enabled()) {
                            w.send("550 5.7.1 Relay denied\r\n")?;
                        } else {
                            if !recipients.contains(&to) {
                                recipients.push(to);
                            }
                            w.send("250 2.1.5 Recipient accepted\r\n")?;
                        }
                    }
                    _ => w.send("501 5.5.2 Invalid recipient\r\n")?,
                }
            }
            "DATA" if arg.is_empty() => {
                if sender.is_none() || recipients.is_empty() {
                    w.send("503 5.5.1 MAIL and RCPT required\r\n")?;
                    continue;
                }
                let Some(_permit) = app.data.enter() else {
                    w.send("452 4.3.1 Transfer capacity busy\r\n")?;
                    continue;
                };
                w.send("354 End with CRLF.CRLF\r\n")?;
                w.deadline.set(Duration::from_secs(120));
                let raw = match data(&mut w, app.config.limits.message_bytes) {
                    Ok(b) => b,
                    Err(_) => {
                        w.send("552 5.3.4 Invalid or excessive message\r\n")?;
                        return Ok(());
                    }
                };
                w.deadline.set(Duration::from_secs(60));
                let from = sender.take().unwrap();
                let targets = std::mem::take(&mut recipients);
                let verdict = if submission {
                    match auth::validate(&raw) {
                        Ok(()) => {
                            let from = crate::mailauth::from_addresses(&raw).unwrap_or_default();
                            if from.len() == 1
                                && from[0].eq_ignore_ascii_case(user.as_ref().unwrap())
                            {
                                Verdict::Accept
                            } else {
                                Verdict::Reject("From must match authenticated account")
                            }
                        }
                        Err(_) => Verdict::Reject("invalid message headers or MIME structure"),
                    }
                } else {
                    app.checker
                        .check(&raw, ip, &helo, &from, &app.config)
                        .unwrap_or(Verdict::Reject("invalid message headers or MIME structure"))
                };
                match verdict {
                    Verdict::Temporary => {
                        w.send("451 4.7.0 Authentication lookup temporarily unavailable\r\n")?
                    }
                    Verdict::Reject(reason) => w.send(&format!("550 5.7.1 {reason}\r\n"))?,
                    v => {
                        let trace = format!(
                            "Received: from {} ([{}]) by {} with {}; {}\r\n",
                            helo,
                            ip,
                            app.config.hostname,
                            if w.secure { "ESMTPS" } else { "ESMTP" },
                            crate::datetime::Utc::now().to_rfc2822()
                        );
                        let mut body = trace.into_bytes();
                        body.extend_from_slice(&raw);
                        let signed = submission && app.signer.is_some();
                        if signed {
                            match app.signer.as_ref().unwrap().sign(&body) {
                                Ok(b) => body = b,
                                Err(e) => {
                                    eprintln!("submission signing refused: {e}");
                                    w.send("451 4.3.0 Signing temporarily unavailable\r\n")?;
                                    continue;
                                }
                            }
                        }
                        if submission
                            && (body.len() > app.config.limits.message_bytes
                                || auth::validate(&body).is_err())
                        {
                            w.send("552 5.3.4 Message exceeds limits after trace/signature headers\r\n")?;
                            continue;
                        }
                        if submission
                            && targets
                                .iter()
                                .any(|r| r.rsplit_once('@').unwrap().1 != app.config.domain)
                            && crate::relay::message_features(&body).is_err()
                        {
                            w.send("550 5.6.0 Unsupported outbound message format; use ASCII headers and CRLF lines\r\n")?;
                            continue;
                        }
                        match deliver(
                            &app,
                            &from,
                            &targets,
                            body,
                            v == Verdict::Quarantine,
                            signed,
                        ) {
                            Ok(id) => w.send(&format!("250 2.0.0 Queued {id}\r\n"))?,
                            Err(e) => {
                                eprintln!("delivery refused: {e}");
                                w.send("452 4.3.1 Storage temporarily unavailable or quota exceeded\r\n")?;
                            }
                        }
                    }
                }
            }
            "RSET" => {
                sender = None;
                recipients.clear();
                w.send("250 2.0.0 Reset\r\n")?;
            }
            "NOOP" => w.send("250 2.0.0 OK\r\n")?,
            "QUIT" => {
                w.send("221 2.0.0 Bye\r\n")?;
                break;
            }
            "HELP" => w.send("214 EHLO STARTTLS AUTH MAIL RCPT DATA RSET NOOP QUIT\r\n")?,
            _ => w.send("502 5.5.1 Command unavailable\r\n")?,
        }
    }
    Ok(())
}
fn authenticate(w: &mut Wire, arg: &str, app: &App) -> Result<Option<String>> {
    let p: Vec<_> = arg.split_whitespace().collect();
    ensure!(!p.is_empty(), "missing mechanism");
    let (user, password) = if p[0].eq_ignore_ascii_case("PLAIN") {
        let encoded = if p.len() == 2 {
            p[1].to_string()
        } else {
            w.send("334 \r\n")?;
            w.text(2048)?
        };
        let b = STANDARD.decode(encoded)?;
        let s = String::from_utf8(b)?;
        let f: Vec<_> = s.split('\0').collect();
        ensure!(
            f.len() == 3 && (f[0].is_empty() || f[0] == f[1]),
            "invalid AUTH PLAIN"
        );
        (f[1].to_string(), f[2].to_string())
    } else if p[0].eq_ignore_ascii_case("LOGIN") {
        let u = if p.len() == 2 {
            p[1].to_string()
        } else {
            w.send("334 VXNlcm5hbWU6\r\n")?;
            w.text(1024)?
        };
        w.send("334 UGFzc3dvcmQ6\r\n")?;
        let pass = w.text(2048)?;
        (
            String::from_utf8(STANDARD.decode(u)?)?,
            String::from_utf8(STANDARD.decode(pass)?)?,
        )
    } else {
        crate::bail!("unsupported AUTH")
    };
    if app.login(&user, &password)? {
        Ok(Some(config::address(&user)?))
    } else {
        Ok(None)
    }
}
pub fn data(w: &mut Wire, limit: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    loop {
        let line = w.line(1001)?;
        if line == b".\r\n" {
            break;
        }
        let line = if line.starts_with(b".") {
            &line[1..]
        } else {
            &line
        };
        ensure!(data.len() + line.len() <= limit, "message too big");
        ensure!(!line.contains(&0), "NUL unsupported");
        data.extend_from_slice(line);
    }
    Ok(data)
}
fn deliver(
    app: &App,
    from: &str,
    to: &[String],
    body: Vec<u8>,
    junk: bool,
    signed: bool,
) -> Result<String> {
    let id = store::random_id();
    let now = crate::datetime::Utc::now().timestamp();
    app.mail_commit(|t| {
        Ok((
            delivery_ops(t, app, from, to, &id, &body, junk, signed, false, now)?,
            (),
        ))
    })?;
    Ok(id)
}

/// One transaction constructs local deliveries, queue entries and an optional
/// Sent copy. All recipients and aggregate sender quota are checked before commit.
#[allow(clippy::too_many_arguments)]
pub(crate) fn delivery_ops(
    t: &redb::Table<&str, &[u8]>,
    app: &App,
    from: &str,
    to: &[String],
    id: &str,
    body: &[u8],
    junk: bool,
    signed: bool,
    sent: bool,
    now: i64,
) -> Result<Vec<Op>> {
    let external = to
        .iter()
        .filter(|s| s.rsplit_once('@').unwrap().1 != app.config.domain)
        .count();
    ensure!(
        external == 0 || app.config.outbound_enabled(),
        "Outbound delivery is not configured"
    );
    ensure!(
        store::scan::<QueueItem>(t, "queue/")?.len() + external <= app.config.limits.queue_messages,
        "Delivery queue is full"
    );
    let mut local = std::collections::BTreeMap::<&str, usize>::new();
    for r in to
        .iter()
        .filter(|s| s.rsplit_once('@').unwrap().1 == app.config.domain)
    {
        *local.entry(r).or_default() += 1;
    }
    if sent {
        *local.entry(from).or_default() += 1;
    }
    for (u, count) in local {
        let user: User = store::json(t, &format!("user/{u}"))?
            .ok_or_else(|| crate::error!("Unknown local recipient"))?;
        let all: Vec<(String, config::Message)> = store::scan(t, &format!("mail/{u}/"))?;
        ensure!(
            all.len() + count <= app.config.limits.mailbox_messages
                && all.iter().map(|(_, m)| m.size as u64).sum::<u64>()
                    + (count * body.len()) as u64
                    <= user.quota,
            "Mailbox quota exceeded"
        );
    }
    let mut ops = vec![Op {
        key: format!("blob/{id}"),
        value: Some(body.to_vec()),
    }];
    for rcpt in to {
        if rcpt.rsplit_once('@').unwrap().1 == app.config.domain {
            ops.extend(
                store::append_ops(
                    t,
                    rcpt,
                    if junk { "Junk" } else { "INBOX" },
                    id,
                    body.len(),
                    vec![],
                    now,
                    &app.config.limits,
                )?
                .0,
            );
        } else {
            ops.push(Op::json(
                format!("queue/{}", store::random_id()),
                &QueueItem {
                    blob: id.into(),
                    sender: from.into(),
                    recipient: rcpt.clone(),
                    attempts: 0,
                    next_try: now,
                    created: now,
                    status: "pending".into(),
                    last_error: String::new(),
                    dkim_signed: signed,
                },
            )?);
        }
    }
    if sent {
        ops.extend(
            store::append_ops(
                t,
                from,
                "Sent",
                id,
                body.len(),
                vec!["\\Seen".into()],
                now,
                &app.config.limits,
            )?
            .0,
        );
    }
    Ok(ops)
}
