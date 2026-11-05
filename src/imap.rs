use crate::encoding::STANDARD;
use crate::error::{Result, bail, ensure};
use crate::{
    app::App,
    config::{self, Folder, Message},
    net::{Wire, timeout},
    store::{self, Op},
};
use std::{
    collections::HashSet,
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};
use workglen_mime::{MessageParser, MimeHeaders, PartType};
const CAPS: &str = "IMAP4rev1 AUTH=PLAIN SASL-IR IDLE UIDPLUS MOVE UNSELECT CHILDREN SPECIAL-USE";
struct Selected {
    folder: String,
    readonly: bool,
    messages: Vec<Message>,
}
pub fn quote(s: &str) -> String {
    format!(
        "\"{}\"",
        s.chars()
            .map(|c| match c {
                '\\' => "\\\\".into(),
                '"' => "\\\"".into(),
                '\r' | '\n' | '\0' => " ".into(),
                c => c.to_string(),
            })
            .collect::<String>()
    )
}
/// Tokenize IMAP quoted strings and grouped lists/section specifiers without losing spaces in BODY[...].
pub fn tokens(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        if i == b.len() {
            break;
        }
        let mut x = Vec::new();
        if b[i] == b'"' {
            i += 1;
            let mut closed = false;
            while i < b.len() {
                if b[i] == b'"' {
                    i += 1;
                    closed = true;
                    break;
                }
                if b[i] == b'\\' {
                    i += 1;
                    ensure!(
                        i < b.len() && matches!(b[i], b'"' | b'\\'),
                        "invalid quoted escape"
                    );
                }
                ensure!(b[i] >= 32, "control in string");
                x.push(b[i]);
                i += 1;
            }
            ensure!(closed, "unclosed quote");
        } else {
            let mut paren = 0i32;
            let mut bracket = 0i32;
            let mut quoted = false;
            let mut escaped = false;
            while i < b.len() {
                let c = b[i];
                if c == b' ' && paren == 0 && bracket == 0 && !quoted {
                    break;
                }
                if escaped {
                    escaped = false;
                } else if quoted && c == b'\\' {
                    escaped = true;
                } else if c == b'"' {
                    quoted = !quoted;
                } else if !quoted {
                    match c {
                        b'(' => paren += 1,
                        b')' => {
                            paren -= 1;
                            ensure!(paren >= 0, "unexpected )");
                        }
                        b'[' => bracket += 1,
                        b']' => {
                            bracket -= 1;
                            ensure!(bracket >= 0, "unexpected ]");
                        }
                        _ => {}
                    }
                }
                x.push(c);
                i += 1;
            }
            ensure!(paren == 0 && bracket == 0 && !quoted, "unclosed grouping");
        }
        out.push(String::from_utf8(x)?);
        ensure!(out.len() <= 128, "too many arguments");
    }
    Ok(out)
}
fn list(s: &str) -> Result<Vec<String>> {
    tokens(
        s.strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .unwrap_or(s),
    )
}
pub fn flags(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for f in list(s)? {
        let canonical = match f.to_ascii_lowercase().as_str() {
            "\\seen" => "\\Seen",
            "\\answered" => "\\Answered",
            "\\flagged" => "\\Flagged",
            "\\deleted" => "\\Deleted",
            "\\draft" => "\\Draft",
            _ => bail!("unsupported flag"),
        };
        if !out.contains(&canonical.to_string()) {
            out.push(canonical.into());
        }
    }
    Ok(out)
}
pub fn in_set(set: &str, n: u32, max: u32) -> Result<bool> {
    let mut found = false;
    ensure!(set.len() <= 4096, "sequence set too large");
    for range in set.split(',') {
        let val = |s: &str| -> Result<u32> {
            if s == "*" {
                Ok(max)
            } else {
                let x: u32 = s.parse()?;
                ensure!(x > 0, "sequence zero");
                Ok(x)
            }
        };
        let (a, b) = range.split_once(':').unwrap_or((range, range));
        let (a, b) = (val(a)?, val(b)?);
        found |= n >= a.min(b) && n <= a.max(b);
    }
    Ok(found)
}
fn selected(s: &mut Option<Selected>) -> Result<&mut Selected> {
    s.as_mut()
        .ok_or_else(|| crate::error!("select a mailbox first"))
}
fn matching(s: &Selected, set: &str, uid: bool) -> Result<Vec<(usize, Message)>> {
    let max = if uid {
        s.messages.last().map(|m| m.uid).unwrap_or(0)
    } else {
        s.messages.len() as u32
    };
    let mut out = Vec::new();
    for (i, m) in s.messages.iter().enumerate() {
        if in_set(set, if uid { m.uid } else { i as u32 + 1 }, max)? {
            out.push((i + 1, m.clone()));
        }
    }
    Ok(out)
}
fn refresh(w: &mut Wire, app: &App, user: &str, s: &mut Selected) -> Result<()> {
    let current = app.read_store()?.messages(user, &s.folder)?;
    let keep: HashSet<_> = current.iter().map(|m| m.uid).collect();
    let mut i = 0;
    while i < s.messages.len() {
        if !keep.contains(&s.messages[i].uid) {
            s.messages.remove(i);
            w.send(&format!("* {} EXPUNGE\r\n", i + 1))?;
        } else {
            i += 1;
        }
    }
    for (i, m) in current.iter().enumerate() {
        if let Some(old) = s.messages.iter().find(|old| old.uid == m.uid)
            && old.flags != m.flags
        {
            w.send(&format!(
                "* {} FETCH (UID {} FLAGS ({}))\r\n",
                i + 1,
                m.uid,
                m.flags.join(" ")
            ))?;
        }
    }
    if current.len() != s.messages.len() {
        w.send(&format!("* {} EXISTS\r\n", current.len()))?;
    }
    s.messages = current;
    Ok(())
}
fn wildcard(pattern: &str, text: &str) -> bool {
    let mut star = None;
    let mut ti = 0;
    let bytes = text.as_bytes();
    let pat = pattern.as_bytes();
    let mut pi = 0;
    while ti < bytes.len() {
        if pi < pat.len() && pat[pi] == bytes[ti] {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && matches!(pat[pi], b'*' | b'%') {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((a, b)) = star {
            star = Some((a, b + 1));
            pi = a + 1;
            ti = b + 1;
        } else {
            return false;
        }
    }
    while pi < pat.len() && matches!(pat[pi], b'*' | b'%') {
        pi += 1;
    }
    pi == pat.len()
}

pub fn serve(tcp: TcpStream, app: Arc<App>) -> Result<()> {
    let mut w = Wire::accept(tcp, &app.tls)?;
    w.deadline.set(Duration::from_secs(60));
    if !app.primary() || !app.mail_enabled() {
        w.send("* BYE [UNAVAILABLE] Mail unavailable on this node\r\n")?;
        return Ok(());
    }
    w.send(&format!("* OK [CAPABILITY {CAPS}] Workglen Mail ready\r\n"))?;
    let mut user = None;
    let mut selection = None;
    let start = Instant::now();
    let mut failures = 0;
    for _ in 0..app.config.limits.commands {
        if (!app.primary() || !app.mail_enabled())
            || start.elapsed().as_secs() > app.config.limits.session_seconds
        {
            w.send("* BYE Session expired or mail unavailable\r\n")?;
            break;
        }
        w.deadline
            .set(Duration::from_secs(app.config.limits.io_seconds));
        let line = w.text(8192)?;
        app.require_mail()?;
        let args = match tokens(&line) {
            Ok(a) => a,
            Err(_) => {
                w.send("* BAD Invalid command syntax\r\n")?;
                continue;
            }
        };
        if args.len() < 2 {
            w.send("* BAD Missing command\r\n")?;
            continue;
        }
        let tag = &args[0];
        if tag.is_empty()
            || !tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            w.send("* BAD Invalid tag\r\n")?;
            continue;
        }
        let command = args[1].to_ascii_uppercase();
        let a = &args[2..];
        if command == "LOGOUT" {
            w.send(&format!(
                "* BYE Logging out\r\n{tag} OK LOGOUT completed\r\n"
            ))?;
            break;
        }
        let result = (|| -> Result<String> {
            if command == "CAPABILITY" {
                w.send(&format!("* CAPABILITY {CAPS}\r\n"))?;
                return Ok("CAPABILITY completed".into());
            }
            if command == "LOGIN" || command == "AUTHENTICATE" {
                ensure!(user.is_none(), "already authenticated");
                let (u, p) = if command == "LOGIN" {
                    ensure!(a.len() == 2, "LOGIN requires username password");
                    (a[0].clone(), a[1].clone())
                } else {
                    ensure!(
                        !a.is_empty() && a[0].eq_ignore_ascii_case("PLAIN"),
                        "only AUTHENTICATE PLAIN supported"
                    );
                    let v = if a.len() == 2 {
                        a[1].clone()
                    } else {
                        w.send("+ \r\n")?;
                        w.text(2048)?
                    };
                    let b = String::from_utf8(STANDARD.decode(v)?)?;
                    let f: Vec<_> = b.split('\0').collect();
                    ensure!(
                        f.len() == 3 && (f[0].is_empty() || f[0] == f[1]),
                        "invalid SASL"
                    );
                    (f[1].into(), f[2].into())
                };
                if !app.login(&u, &p)? {
                    failures += 1;
                    bail!("[AUTHENTICATIONFAILED] Invalid credentials");
                }
                user = Some(config::address(&u)?);
                return Ok("Authenticated".into());
            }
            let u = user
                .as_deref()
                .ok_or_else(|| crate::error!("authenticate first"))?;
            // EXPUNGE is forbidden as unsolicited data during FETCH, STORE or SEARCH.
            if !matches!(command.as_str(), "FETCH" | "STORE" | "SEARCH" | "UID")
                && let Some(s) = &mut selection
            {
                refresh(&mut w, &app, u, s)?;
            }
            match command.as_str() {
                "NOOP" | "CHECK" => Ok(format!("{command} completed")),
                "UNSELECT" => {
                    selection = None;
                    Ok("UNSELECT completed".into())
                }
                "LIST" | "LSUB" => {
                    ensure!(a.len() >= 2, "LIST reference pattern");
                    let pattern = format!("{}{}", a[0], a[1]);
                    for (k, f) in app.read_store()?.list::<Folder>(&format!("folder/{u}/"))? {
                        let name = &k[format!("folder/{u}/").len()..];
                        if wildcard(&pattern, name) && (command == "LIST" || f.subscribed) {
                            let special = match name {
                                "Sent" => " \\Sent",
                                "Trash" => " \\Trash",
                                "Drafts" => " \\Drafts",
                                "Junk" => " \\Junk",
                                _ => "",
                            };
                            w.send(&format!(
                                "* {command} (\\HasNoChildren{special}) \"/\" {}\r\n",
                                quote(name)
                            ))?;
                        }
                    }
                    if a[1].is_empty() {
                        w.send(&format!("* {command} (\\Noselect) \"/\" \"\"\r\n"))?;
                    }
                    Ok(format!("{command} completed"))
                }
                "CREATE" => {
                    ensure!(a.len() == 1, "CREATE mailbox");
                    let f = config::folder(&a[0])?;
                    app.mail_commit(|t| {
                        ensure!(
                            store::json::<Folder>(t, &store::folder_key(u, &f))?.is_none(),
                            "mailbox exists"
                        );
                        ensure!(
                            store::scan::<Folder>(t, &format!("folder/{u}/"))?.len() < 100,
                            "folder limit"
                        );
                        Ok((
                            vec![Op::json(store::folder_key(u, &f), &store::fresh_folder())?],
                            (),
                        ))
                    })?;
                    Ok("CREATE completed".into())
                }
                "SUBSCRIBE" | "UNSUBSCRIBE" => {
                    ensure!(a.len() == 1, "mailbox required");
                    let f = config::folder(&a[0])?;
                    app.mail_commit(|t| {
                        let k = store::folder_key(u, &f);
                        let mut v: Folder =
                            store::json(t, &k)?.ok_or_else(|| crate::error!("mailbox missing"))?;
                        v.subscribed = command == "SUBSCRIBE";
                        Ok((vec![Op::json(k, &v)?], ()))
                    })?;
                    Ok(format!("{command} completed"))
                }
                "DELETE" => {
                    ensure!(a.len() == 1, "DELETE mailbox");
                    let f = config::folder(&a[0])?;
                    ensure!(f != "INBOX", "cannot delete INBOX");
                    ensure!(
                        !selection.as_ref().is_some_and(|s| s.folder == f),
                        "unselect mailbox before deleting"
                    );
                    app.mail_commit(|t| {
                        ensure!(
                            store::json::<Folder>(t, &store::folder_key(u, &f))?.is_some(),
                            "mailbox missing"
                        );
                        let rows = store::scan::<Message>(t, &store::mail_prefix(u, &f))?;
                        let removed: Vec<_> = rows.into_iter().map(|(k, _)| k).collect();
                        let mut ops: Vec<_> = removed.iter().cloned().map(Op::del).collect();
                        ops.push(Op::del(store::folder_key(u, &f)));
                        ops.extend(store::gc_ops(t, &removed)?);
                        Ok((ops, ()))
                    })?;
                    Ok("DELETE completed".into())
                }
                "RENAME" => {
                    ensure!(a.len() == 2, "RENAME old new");
                    let old = config::folder(&a[0])?;
                    let new = config::folder(&a[1])?;
                    ensure!(old != "INBOX" && new != "INBOX", "INBOX rename unsupported");
                    app.mail_commit(|t| {
                        let f: Folder = store::json(t, &store::folder_key(u, &old))?
                            .ok_or_else(|| crate::error!("mailbox missing"))?;
                        ensure!(
                            store::json::<Folder>(t, &store::folder_key(u, &new))?.is_none(),
                            "destination exists"
                        );
                        let mut ops = vec![
                            Op::del(store::folder_key(u, &old)),
                            Op::json(store::folder_key(u, &new), &f)?,
                        ];
                        for (k, m) in store::scan::<Message>(t, &store::mail_prefix(u, &old))? {
                            ops.push(Op::del(k));
                            ops.push(Op::json(store::mail_key(u, &new, m.uid), &m)?);
                        }
                        Ok((ops, ()))
                    })?;
                    if let Some(s) = &mut selection
                        && s.folder == old
                    {
                        s.folder = new;
                    }
                    Ok("RENAME completed".into())
                }
                "SELECT" | "EXAMINE" => {
                    ensure!(a.len() == 1, "SELECT mailbox");
                    let f = config::folder(&a[0])?;
                    let info: Folder = app
                        .read_store()?
                        .get(&store::folder_key(u, &f))?
                        .ok_or_else(|| crate::error!("mailbox missing"))?;
                    let messages = app.read_store()?.messages(u, &f)?;
                    w.send(&format!("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags\r\n* {} EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY {}] Stable UIDs\r\n* OK [UIDNEXT {}] Next UID\r\n",messages.len(),info.validity,info.next_uid))?;
                    selection = Some(Selected {
                        folder: f,
                        readonly: command == "EXAMINE",
                        messages,
                    });
                    Ok(if command == "EXAMINE" {
                        "[READ-ONLY] EXAMINE completed"
                    } else {
                        "[READ-WRITE] SELECT completed"
                    }
                    .into())
                }
                "STATUS" => {
                    ensure!(a.len() == 2, "STATUS mailbox items");
                    let f = config::folder(&a[0])?;
                    let info: Folder = app
                        .read_store()?
                        .get(&store::folder_key(u, &f))?
                        .ok_or_else(|| crate::error!("mailbox missing"))?;
                    let m = app.read_store()?.messages(u, &f)?;
                    let mut fields = Vec::new();
                    for item in list(&a[1])? {
                        let item = item.to_ascii_uppercase();
                        let value = match item.as_str() {
                            "MESSAGES" => m.len() as u32,
                            "RECENT" => 0,
                            "UNSEEN" => m
                                .iter()
                                .filter(|m| !m.flags.contains(&"\\Seen".into()))
                                .count() as u32,
                            "UIDNEXT" => info.next_uid,
                            "UIDVALIDITY" => info.validity,
                            _ => bail!("unsupported STATUS item"),
                        };
                        fields.push(format!("{item} {value}"));
                    }
                    w.send(&format!(
                        "* STATUS {} ({})\r\n",
                        quote(&f),
                        fields.join(" ")
                    ))?;
                    Ok("STATUS completed".into())
                }
                "APPEND" => append(&mut w, &app, u, a),
                "IDLE" => {
                    w.send("+ idling\r\n")?;
                    let idle = Instant::now();
                    loop {
                        w.deadline.set(Duration::from_secs(1));
                        match w.text(64) {
                            Ok(l) => {
                                ensure!(l.eq_ignore_ascii_case("DONE"), "expected DONE");
                                break;
                            }
                            Err(e) if timeout(&e) => {}
                            Err(e) => return Err(e),
                        }
                        w.deadline.set(Duration::from_secs(5));
                        app.require_mail()?;
                        if let Some(s) = &mut selection {
                            refresh(&mut w, &app, u, s)?;
                        }
                        ensure!(
                            idle.elapsed() < Duration::from_secs(1500),
                            "IDLE expired; reconnect"
                        );
                    }
                    Ok("IDLE completed".into())
                }
                "CLOSE" => {
                    let s = selected(&mut selection)?;
                    if !s.readonly {
                        expunge(&app, u, s, None)?;
                    }
                    selection = None;
                    Ok("CLOSE completed".into())
                }
                "EXPUNGE" => {
                    let s = selected(&mut selection)?;
                    expunge(&app, u, s, None)?;
                    refresh(&mut w, &app, u, s)?;
                    Ok("EXPUNGE completed".into())
                }
                "FETCH" | "STORE" | "SEARCH" | "COPY" | "MOVE" | "UID" => {
                    let (uid, cmd, args) = if command == "UID" {
                        ensure!(!a.is_empty(), "UID subcommand required");
                        (true, a[0].to_ascii_uppercase(), &a[1..])
                    } else {
                        (false, command.clone(), a)
                    };
                    let s = selected(&mut selection)?;
                    match cmd.as_str() {
                        "FETCH" => fetch(&mut w, &app, u, s, args, uid),
                        "STORE" => store_flags(&mut w, &app, u, s, args, uid),
                        "SEARCH" => search(&mut w, &app, u, s, args, uid),
                        "COPY" | "MOVE" => copy_move(&mut w, &app, u, s, args, uid, cmd == "MOVE"),
                        "EXPUNGE" if uid => {
                            ensure!(args.len() == 1, "UID EXPUNGE set");
                            expunge(&app, u, s, Some(&args[0]))?;
                            refresh(&mut w, &app, u, s)?;
                            Ok("UID EXPUNGE completed".into())
                        }
                        _ => bail!("unsupported UID command"),
                    }
                }
                _ => bail!("unsupported command"),
            }
        })();
        w.deadline.set(Duration::from_secs(10));
        match result {
            Ok(text) => w.send(&format!("{tag} OK {text}\r\n"))?,
            Err(e) => {
                w.send(&format!(
                    "{tag} NO {}\r\n",
                    e.to_string().replace(['\r', '\n'], " ")
                ))?;
                if failures >= 3 {
                    break;
                }
            }
        }
    }
    Ok(())
}
fn append(w: &mut Wire, app: &App, u: &str, a: &[String]) -> Result<String> {
    ensure!(a.len() >= 2, "APPEND mailbox [flags] [date] literal");
    let f = config::folder(&a[0])?;
    let last = a.last().unwrap();
    let n: usize = last
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| crate::error!("synchronizing literal required"))?
        .parse()?;
    ensure!(n <= app.config.limits.message_bytes, "message too large");
    let _permit = app
        .data
        .enter()
        .ok_or_else(|| crate::error!("transfer capacity busy"))?;
    let mut fs = vec![];
    let mut date = crate::datetime::Utc::now()?.timestamp();
    for v in &a[1..a.len() - 1] {
        if v.starts_with('(') {
            fs = flags(v)?;
        } else {
            date =
                crate::datetime::DateTime::parse_from_str(v, "%d-%b-%Y %H:%M:%S %z")?.timestamp();
        }
    }
    ensure!(
        app.read_store()?
            .get::<Folder>(&store::folder_key(u, &f))?
            .is_some(),
        "[TRYCREATE] mailbox missing"
    );
    w.send("+ Ready for literal\r\n")?;
    w.deadline.set(Duration::from_secs(120));
    let mut body = vec![0; n];
    w.exact(&mut body)?;
    ensure!(w.text(8192)?.is_empty(), "unexpected data after literal");
    crate::auth::validate(&body)?;
    let id = store::random_id();
    let (validity, uid) = app.mail_commit(|t| {
        let (mut ops, validity, uid) =
            store::append_ops(t, u, &f, &id, body.len(), fs, date, &app.config.limits)?;
        ops.push(Op {
            key: format!("blob/{id}"),
            value: Some(body),
        });
        Ok((ops, (validity, uid)))
    })?;
    Ok(format!("[APPENDUID {validity} {uid}] APPEND completed"))
}
fn expunge(app: &App, u: &str, s: &Selected, set: Option<&str>) -> Result<()> {
    ensure!(!s.readonly, "mailbox is read-only");
    let max = s.messages.last().map(|m| m.uid).unwrap_or(0);
    app.mail_commit(|t| {
        let mut removed = Vec::new();
        for (k, m) in store::scan::<Message>(t, &store::mail_prefix(u, &s.folder))? {
            if m.flags.contains(&"\\Deleted".into())
                && (set.is_none() || in_set(set.unwrap(), m.uid, max)?)
            {
                removed.push(k);
            }
        }
        let mut ops: Vec<_> = removed.iter().cloned().map(Op::del).collect();
        ops.extend(store::gc_ops(t, &removed)?);
        Ok((ops, ()))
    })
}
fn store_flags(
    w: &mut Wire,
    app: &App,
    u: &str,
    s: &mut Selected,
    a: &[String],
    uid: bool,
) -> Result<String> {
    ensure!(
        a.len() == 3 && !s.readonly,
        "STORE set operation flags; mailbox must be writable"
    );
    let items = matching(s, &a[0], uid)?;
    let mode = a[1].to_ascii_uppercase();
    ensure!(
        matches!(
            mode.as_str(),
            "FLAGS" | "FLAGS.SILENT" | "+FLAGS" | "+FLAGS.SILENT" | "-FLAGS" | "-FLAGS.SILENT"
        ),
        "invalid STORE operation"
    );
    let fs = flags(&a[2])?;
    let updated = app.mail_commit(|t| {
        let mut ops = Vec::new();
        let mut updated = Vec::new();
        for (n, old) in &items {
            let k = store::mail_key(u, &s.folder, old.uid);
            if let Some(mut m) = store::json::<Message>(t, &k)? {
                if mode.starts_with('+') {
                    for f in &fs {
                        if !m.flags.contains(f) {
                            m.flags.push(f.clone());
                        }
                    }
                } else if mode.starts_with('-') {
                    m.flags.retain(|f| !fs.contains(f));
                } else {
                    m.flags = fs.clone();
                }
                ops.push(Op::json(k, &m)?);
                updated.push((*n, m));
            }
        }
        Ok((ops, updated))
    })?;
    for (n, m) in updated {
        if let Some(old) = s.messages.iter_mut().find(|old| old.uid == m.uid) {
            old.flags = m.flags.clone();
        }
        if !mode.ends_with(".SILENT") {
            w.send(&format!(
                "* {n} FETCH (UID {} FLAGS ({}))\r\n",
                m.uid,
                m.flags.join(" ")
            ))?;
        }
    }
    Ok("STORE completed".into())
}
fn copy_move(
    w: &mut Wire,
    app: &App,
    u: &str,
    s: &mut Selected,
    a: &[String],
    uid: bool,
    moving: bool,
) -> Result<String> {
    ensure!(a.len() == 2, "COPY/MOVE set mailbox");
    ensure!(!moving || !s.readonly, "mailbox is read-only");
    let dest = config::folder(&a[1])?;
    ensure!(dest != s.folder, "source and destination match");
    let items = matching(s, &a[0], uid)?;
    let (validity, old, new) = app.mail_commit(|t| {
        let key = store::folder_key(u, &dest);
        let mut folder: Folder = store::json(t, &key)?
            .ok_or_else(|| crate::error!("[TRYCREATE] destination missing"))?;
        let account: config::User = store::json(t, &format!("user/{u}"))?.unwrap();
        let all = store::scan::<Message>(t, &format!("mail/{u}/"))?;
        if !moving {
            ensure!(
                all.len() + items.len() <= app.config.limits.mailbox_messages
                    && all.iter().map(|(_, m)| m.size as u64).sum::<u64>()
                        + items.iter().map(|(_, m)| m.size as u64).sum::<u64>()
                        <= account.quota,
                "quota exceeded"
            );
        }
        let mut ops = Vec::new();
        let mut old = Vec::new();
        let mut new = Vec::new();
        for (_, m) in &items {
            let k = store::mail_key(u, &s.folder, m.uid);
            if let Some(mut current) = store::json::<Message>(t, &k)? {
                old.push(current.uid.to_string());
                current.uid = folder.next_uid;
                folder.next_uid = folder
                    .next_uid
                    .checked_add(1)
                    .ok_or_else(|| crate::error!("UID exhausted"))?;
                new.push(current.uid.to_string());
                ops.push(Op::json(store::mail_key(u, &dest, current.uid), &current)?);
                if moving {
                    ops.push(Op::del(k));
                }
            }
        }
        ops.push(Op::json(key, &folder)?);
        Ok((ops, (folder.validity, old.join(","), new.join(","))))
    })?;
    if moving {
        refresh(w, app, u, s)?;
    }
    if old.is_empty() {
        Ok("COPY/MOVE completed".into())
    } else {
        Ok(format!(
            "[COPYUID {validity} {old} {new}] COPY/MOVE completed"
        ))
    }
}
fn nstring(s: Option<&str>) -> String {
    s.map(quote).unwrap_or_else(|| "NIL".into())
}
fn addresses(a: Option<&workglen_mime::Address>) -> String {
    let Some(a) = a else {
        return "NIL".into();
    };
    let v: Vec<_> = a
        .iter()
        .map(|a| {
            let (local, domain) = a
                .address
                .as_deref()
                .and_then(|s| s.rsplit_once('@'))
                .unwrap_or(("", ""));
            format!(
                "({} NIL {} {})",
                nstring(a.name.as_deref()),
                quote(local),
                quote(domain)
            )
        })
        .collect();
    if v.is_empty() {
        "NIL".into()
    } else {
        format!("({})", v.join(" "))
    }
}
fn envelope(m: &workglen_mime::Message) -> String {
    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        nstring(m.header_raw("Date")),
        nstring(m.subject()),
        addresses(m.from()),
        addresses(m.sender().or(m.from())),
        addresses(m.reply_to().or(m.from())),
        addresses(m.to()),
        addresses(m.cc()),
        addresses(m.bcc()),
        nstring(m.header_raw("In-Reply-To")),
        nstring(m.header_raw("Message-ID"))
    )
}
fn parameters(ct: Option<&workglen_mime::ContentType>) -> String {
    let attrs = ct.and_then(|ct| ct.attributes.as_ref());
    match attrs {
        Some(a) if !a.is_empty() => format!(
            "({})",
            a.iter()
                .map(|a| format!(
                    "{} {}",
                    quote(&a.name.to_ascii_uppercase()),
                    quote(&a.value)
                ))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        _ => "NIL".into(),
    }
}
fn bodystructure(
    m: &workglen_mime::Message,
    id: usize,
    extended: bool,
    depth: usize,
) -> Result<String> {
    ensure!(depth < crate::auth::MAX_MIME_DEPTH, "MIME nesting too deep");
    let p = m
        .parts
        .get(id)
        .ok_or_else(|| crate::error!("missing MIME part"))?;
    let ct = p.content_type();
    let disposition = p
        .content_disposition()
        .map(|d| {
            format!(
                "({} {})",
                quote(&d.c_type.to_ascii_uppercase()),
                parameters(Some(d))
            )
        })
        .unwrap_or_else(|| "NIL".into());
    if let PartType::Multipart(parts) = &p.body {
        let mut output = String::from("(");
        for id in parts {
            output.push_str(&bodystructure(m, *id as usize, extended, depth + 1)?);
        }
        output.push(' ');
        output.push_str(&quote(
            &ct.and_then(|c| c.subtype())
                .unwrap_or("mixed")
                .to_ascii_uppercase(),
        ));
        if extended {
            output.push_str(&format!(" {} {disposition} NIL NIL", parameters(ct)));
        }
        output.push(')');
        return Ok(output);
    }
    let major = ct.map(|c| c.ctype()).unwrap_or("text");
    let minor = ct.and_then(|c| c.subtype()).unwrap_or("plain");
    let size = p.offset_end.saturating_sub(p.offset_body);
    let bytes = m
        .raw_message
        .get(p.offset_body as usize..p.offset_end as usize)
        .unwrap_or_default();
    let lines = bytes.iter().filter(|b| **b == b'\n').count();
    let mut out = format!(
        "({} {} {} {} {} {} {size}",
        quote(&major.to_ascii_uppercase()),
        quote(&minor.to_ascii_uppercase()),
        parameters(ct),
        nstring(p.content_id()),
        nstring(p.content_description()),
        quote(
            &p.content_transfer_encoding()
                .unwrap_or("7BIT")
                .to_ascii_uppercase()
        )
    );
    if major.eq_ignore_ascii_case("text") {
        out.push_str(&format!(" {lines}"));
    } else if let PartType::Message(nested) = &p.body {
        out.push_str(&format!(
            " {} {} {lines}",
            envelope(nested),
            bodystructure(nested, 0, extended, depth + 1)?
        ));
    }
    if extended {
        out.push_str(&format!(" NIL {disposition} NIL NIL"));
    }
    out.push(')');
    Ok(out)
}
fn header_subset(raw: &[u8], names: &[String], exclude: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut keep = false;
    for line in raw.split_inclusive(|b| *b == b'\n') {
        if line == b"\r\n" {
            break;
        }
        if !line.starts_with(b" ") && !line.starts_with(b"\t") {
            let name = line.split(|b| *b == b':').next().unwrap_or_default();
            let matched = names
                .iter()
                .any(|n| n.as_bytes().eq_ignore_ascii_case(name));
            keep = if exclude { !matched } else { matched };
        }
        if keep {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}
fn section(raw: &[u8], m: &workglen_mime::Message, s: &str) -> Result<Vec<u8>> {
    let upper = s.to_ascii_uppercase();
    if s.is_empty() {
        return Ok(raw.to_vec());
    }
    let root = m.root_part();
    if upper == "HEADER" {
        return Ok(raw[..root.offset_body as usize].to_vec());
    }
    if upper == "TEXT" {
        return Ok(raw[root.offset_body as usize..].to_vec());
    }
    if upper.starts_with("HEADER.FIELDS") {
        let i = s
            .find('(')
            .ok_or_else(|| crate::error!("header field list required"))?;
        return Ok(header_subset(
            raw,
            &list(&s[i..])?,
            upper.starts_with("HEADER.FIELDS.NOT"),
        ));
    }
    let mut iter = s.split('.').peekable();
    let mut part = 0usize;
    let mut first = true;
    while let Some(value) = iter.peek() {
        let Ok(n) = value.parse::<usize>() else {
            break;
        };
        ensure!(n > 0, "invalid part number");
        iter.next();
        match &m.parts[part].body {
            PartType::Multipart(ids) => {
                part = *ids
                    .get(n - 1)
                    .ok_or_else(|| crate::error!("part not found"))?
                    as usize;
            }
            _ if first && n == 1 => {}
            _ => bail!("nested part not found"),
        };
        first = false;
    }
    let p = &m.parts[part];
    let suffix = iter.collect::<Vec<_>>().join(".").to_ascii_uppercase();
    let range = match suffix.as_str() {
        "" => p.offset_body as usize..p.offset_end as usize,
        "MIME" => p.offset_header as usize..p.offset_body as usize,
        _ => bail!("unsupported MIME section"),
    };
    Ok(raw
        .get(range)
        .ok_or_else(|| crate::error!("invalid MIME offsets"))?
        .to_vec())
}
fn fetch(
    wire: &mut Wire,
    app: &App,
    u: &str,
    s: &mut Selected,
    a: &[String],
    uid: bool,
) -> Result<String> {
    ensure!(a.len() == 2, "FETCH set items");
    let attrs = match a[1].to_ascii_uppercase().as_str() {
        "ALL" => list("(FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)")?,
        "FAST" => list("(FLAGS INTERNALDATE RFC822.SIZE)")?,
        "FULL" => list("(FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY)")?,
        _ => list(&a[1])?,
    };
    let _permit = app
        .data
        .enter()
        .ok_or_else(|| crate::error!("transfer capacity busy"))?;
    for (n, mut message) in matching(s, &a[0], uid)? {
        app.require_mail()?;
        let raw = app.read_store()?.blob(&message.blob)?;
        crate::auth::mime_budget(&raw)?;
        let parsed = MessageParser::default()
            .parse(&raw)
            .ok_or_else(|| crate::error!("cannot parse message"))?;
        let mark_seen = attrs.iter().any(|a| {
            let a = a.to_ascii_uppercase();
            a == "RFC822" || a == "RFC822.TEXT" || a.starts_with("BODY[")
        });
        if mark_seen && !s.readonly && !message.flags.contains(&"\\Seen".into()) {
            message = app.mail_commit(|t| {
                let k = store::mail_key(u, &s.folder, message.uid);
                let mut current: Message =
                    store::json(t, &k)?.ok_or_else(|| crate::error!("message expunged"))?;
                if !current.flags.contains(&"\\Seen".into()) {
                    current.flags.push("\\Seen".into());
                }
                Ok((vec![Op::json(k, &current)?], current))
            })?;
            if let Some(old) = s.messages.iter_mut().find(|m| m.uid == message.uid) {
                old.flags = message.flags.clone();
            }
        }
        let mut w = Output(Vec::new());
        w.send(&format!("* {n} FETCH (UID {}", message.uid))?;
        for attr in &attrs {
            let upper = attr.to_ascii_uppercase();
            match upper.as_str() {
                "UID" => {}
                "FLAGS" => w.send(&format!(" FLAGS ({})", message.flags.join(" ")))?,
                "INTERNALDATE" => {
                    let d = crate::datetime::DateTime::from_timestamp(message.date, 0)
                        .unwrap_or_default();
                    w.send(&format!(
                        " INTERNALDATE {}",
                        quote(&d.format("%d-%b-%Y %H:%M:%S +0000").to_string())
                    ))?;
                }
                "RFC822.SIZE" => w.send(&format!(" RFC822.SIZE {}", raw.len()))?,
                "ENVELOPE" => w.send(&format!(" ENVELOPE {}", envelope(&parsed)))?,
                "BODY" | "BODYSTRUCTURE" => w.send(&format!(
                    " {upper} {}",
                    bodystructure(&parsed, 0, upper == "BODYSTRUCTURE", 0)?
                ))?,
                _ => {
                    let (label, mut bytes, partial) =
                        if matches!(upper.as_str(), "RFC822" | "RFC822.HEADER" | "RFC822.TEXT") {
                            let sec = match upper.as_str() {
                                "RFC822.HEADER" => "HEADER",
                                "RFC822.TEXT" => "TEXT",
                                _ => "",
                            };
                            (upper.clone(), section(&raw, &parsed, sec)?, None)
                        } else {
                            ensure!(
                                upper.starts_with("BODY[") || upper.starts_with("BODY.PEEK["),
                                "unsupported FETCH attribute"
                            );
                            let open = attr.find('[').unwrap();
                            let close = attr
                                .rfind(']')
                                .ok_or_else(|| crate::error!("bad BODY section"))?;
                            let suffix = &attr[close + 1..];
                            let partial = if suffix.is_empty() {
                                None
                            } else {
                                let (start, count) = suffix
                                    .strip_prefix('<')
                                    .and_then(|s| s.strip_suffix('>'))
                                    .and_then(|s| s.split_once('.'))
                                    .ok_or_else(|| crate::error!("invalid partial"))?;
                                Some((start.parse::<usize>()?, count.parse::<usize>()?))
                            };
                            (
                                format!("BODY[{}]", &attr[open + 1..close]),
                                section(&raw, &parsed, &attr[open + 1..close])?,
                                partial,
                            )
                        };
                    let label = if let Some((start, count)) = partial {
                        let from = start.min(bytes.len());
                        let to = from.saturating_add(count).min(bytes.len());
                        bytes = bytes[from..to].to_vec();
                        format!("{label}<{start}>")
                    } else {
                        label
                    };
                    w.send(&format!(" {label} {{{}}}\r\n", bytes.len()))?;
                    w.bytes(&bytes)?;
                }
            }
        }
        if mark_seen && !attrs.iter().any(|a| a.eq_ignore_ascii_case("FLAGS")) {
            w.send(&format!(" FLAGS ({})", message.flags.join(" ")))?;
        }
        w.send(")\r\n")?;
        wire.deadline.set(Duration::from_secs(120));
        wire.bytes(&w.0)?;
    }
    Ok("FETCH completed".into())
}
#[derive(Debug)]
enum Query {
    All,
    Flag(String, bool),
    Recent(bool),
    Not(Box<Query>),
    Or(Box<Query>, Box<Query>),
    And(Vec<Query>),
    Set(String, bool),
    Text(String, String),
    Header(String, String),
    Size(usize, bool),
    Date(crate::datetime::NaiveDate, String),
}
fn query_one(t: &[String], i: &mut usize, depth: usize) -> Result<Query> {
    ensure!(depth < 32 && *i < t.len(), "invalid SEARCH expression");
    let value = &t[*i];
    *i += 1;
    if value.starts_with('(') {
        return parse_query(&list(value)?, depth + 1);
    }
    let word = value.to_ascii_uppercase();
    let mut take = || -> Result<String> {
        ensure!(*i < t.len(), "missing SEARCH argument");
        let s = t[*i].clone();
        *i += 1;
        Ok(s)
    };
    Ok(match word.as_str() {
        "ALL" => Query::All,
        "NOT" => Query::Not(Box::new(query_one(t, i, depth + 1)?)),
        "OR" => {
            let a = query_one(t, i, depth + 1)?;
            let b = query_one(t, i, depth + 1)?;
            Query::Or(Box::new(a), Box::new(b))
        }
        "UID" => Query::Set(take()?, true),
        "SEEN" | "UNSEEN" | "ANSWERED" | "UNANSWERED" | "DELETED" | "UNDELETED" | "DRAFT"
        | "UNDRAFT" | "FLAGGED" | "UNFLAGGED" => {
            let positive = !word.starts_with("UN");
            let f = word.strip_prefix("UN").unwrap_or(&word);
            Query::Flag(format!("\\{f}"), positive)
        }
        "RECENT" | "NEW" => Query::Recent(true),
        "OLD" => Query::Recent(false),
        "KEYWORD" => Query::Flag(take()?, true),
        "UNKEYWORD" => Query::Flag(take()?, false),
        "FROM" | "TO" | "CC" | "BCC" | "SUBJECT" | "BODY" | "TEXT" => {
            Query::Text(word, take()?.to_lowercase())
        }
        "HEADER" => Query::Header(take()?, take()?.to_lowercase()),
        "LARGER" | "SMALLER" => Query::Size(take()?.parse()?, word == "LARGER"),
        "BEFORE" | "SINCE" | "ON" | "SENTBEFORE" | "SENTSINCE" | "SENTON" => Query::Date(
            crate::datetime::NaiveDate::parse_from_str(&take()?, "%d-%b-%Y")?,
            word,
        ),
        _ if word
            .bytes()
            .all(|b| b.is_ascii_digit() || b"*:,".contains(&b)) =>
        {
            Query::Set(word, false)
        }
        _ => bail!("unsupported SEARCH key"),
    })
}
fn parse_query(t: &[String], depth: usize) -> Result<Query> {
    let mut i = 0;
    let mut all = Vec::new();
    while i < t.len() {
        all.push(query_one(t, &mut i, depth)?);
    }
    ensure!(!all.is_empty(), "empty SEARCH");
    Ok(Query::And(all))
}
fn eval(
    q: &Query,
    m: &Message,
    n: u32,
    max_seq: u32,
    max_uid: u32,
    parsed: &workglen_mime::Message,
) -> Result<bool> {
    Ok(match q {
        Query::All => true,
        Query::Flag(f, yes) => m.flags.iter().any(|s| s.eq_ignore_ascii_case(f)) == *yes,
        Query::Recent(yes) => !*yes,
        Query::Not(q) => !eval(q, m, n, max_seq, max_uid, parsed)?,
        Query::Or(a, b) => {
            eval(a, m, n, max_seq, max_uid, parsed)? || eval(b, m, n, max_seq, max_uid, parsed)?
        }
        Query::And(qs) => {
            let mut ok = true;
            for q in qs {
                if !eval(q, m, n, max_seq, max_uid, parsed)? {
                    ok = false;
                    break;
                }
            }
            ok
        }
        Query::Set(s, uid) => in_set(
            s,
            if *uid { m.uid } else { n },
            if *uid { max_uid } else { max_seq },
        )?,
        Query::Size(size, larger) => {
            if *larger {
                m.size > *size
            } else {
                m.size < *size
            }
        }
        Query::Header(name, value) => parsed
            .header_raw(name.as_str())
            .is_some_and(|s| s.to_lowercase().contains(value)),
        Query::Text(field, value) => match field.as_str() {
            "BODY" => parsed.parts.iter().any(|p| {
                p.text_contents()
                    .is_some_and(|s| s.to_lowercase().contains(value))
            }),
            "TEXT" => {
                parsed
                    .headers_raw()
                    .any(|(_, s)| s.to_lowercase().contains(value))
                    || parsed.parts.iter().any(|p| {
                        p.text_contents()
                            .is_some_and(|s| s.to_lowercase().contains(value))
                    })
            }
            _ => parsed
                .header_raw(field.as_str())
                .is_some_and(|s| s.to_lowercase().contains(value)),
        },
        Query::Date(d, kind) => {
            let dt = if kind.starts_with("SENT") {
                parsed.date().and_then(|d| {
                    crate::datetime::NaiveDate::from_ymd_opt(
                        d.year as i32,
                        d.month as u32,
                        d.day as u32,
                    )
                })
            } else {
                crate::datetime::DateTime::from_timestamp(m.date, 0).map(|d| d.date_naive())
            };
            dt.is_some_and(|value| {
                if kind.ends_with("BEFORE") {
                    value < *d
                } else if kind.ends_with("SINCE") {
                    value >= *d
                } else {
                    value == *d
                }
            })
        }
    })
}
fn search(
    w: &mut Wire,
    app: &App,
    u: &str,
    s: &Selected,
    a: &[String],
    uid: bool,
) -> Result<String> {
    let _ = u;
    let args = if a.first().is_some_and(|s| s.eq_ignore_ascii_case("CHARSET")) {
        ensure!(
            a.len() > 2
                && (a[1].eq_ignore_ascii_case("UTF-8") || a[1].eq_ignore_ascii_case("US-ASCII")),
            "[BADCHARSET (UTF-8 US-ASCII)] unsupported charset"
        );
        &a[2..]
    } else {
        a
    };
    let q = parse_query(args, 0)?;
    let _permit = app
        .data
        .enter()
        .ok_or_else(|| crate::error!("transfer capacity busy"))?;
    let until = Instant::now() + Duration::from_secs(120);
    let mut found = Vec::new();
    for (i, m) in s.messages.iter().enumerate() {
        ensure!(Instant::now() < until, "SEARCH time budget exceeded");
        let raw = app.read_store()?.blob(&m.blob)?;
        crate::auth::mime_budget(&raw)?;
        if let Some(parsed) = MessageParser::default().parse(&raw)
            && eval(
                &q,
                m,
                (i + 1) as u32,
                s.messages.len() as u32,
                s.messages.last().map(|m| m.uid).unwrap_or(0),
                &parsed,
            )?
        {
            found.push(if uid {
                m.uid.to_string()
            } else {
                (i + 1).to_string()
            });
        }
    }
    w.send(&format!(
        "* SEARCH{}\r\n",
        if found.is_empty() {
            String::new()
        } else {
            format!(" {}", found.join(" "))
        }
    ))?;
    Ok("SEARCH completed".into())
}

struct Output(Vec<u8>);
impl Output {
    fn send(&mut self, s: &str) -> Result<()> {
        self.bytes(s.as_bytes())
    }
    fn bytes(&mut self, b: &[u8]) -> Result<()> {
        ensure!(
            self.0.len() + b.len() <= 24 * 1024 * 1024,
            "FETCH response exceeds budget"
        );
        self.0.extend_from_slice(b);
        Ok(())
    }
}
