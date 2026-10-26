//! Bounded mailbox-only HTTPS client, independently enabled from Mail.
//! Plain text display only; untrusted message HTML never becomes browser markup.
use crate::encoding::STANDARD;
use crate::error::{Result, ensure};
use crate::{
    app::App,
    config::{self, Folder, Message, User, Webmail},
    store::{self, Op},
    web::{LoginLimits, error, response, secure},
};
use pratique::crypto::sha2::{Hash, Sha256};
use pratique::http::server::{HttpConfig, Limits, Request, Response, Server, ServerBuilder};
use pratique::json_value::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use workglen_mime::{MessageParser, MimeHeaders};
const COOKIE: &str = "__Host-workglen_mail";
const MAX_BODY: usize = 6 * 1024 * 1024;
const TEXT_LIMIT: usize = 256 * 1024;
#[derive(Clone)]
struct Session {
    user: String,
    hash: String,
    csrf: String,
    until: Instant,
}
struct State {
    app: Arc<App>,
    config: Webmail,
    sessions: Mutex<HashMap<String, Session>>,
    attempts: Mutex<LoginLimits>,
}
fn fingerprint(s: &str) -> String {
    pratique::util::hex(&Sha256::digest(s.as_bytes()))
}
fn cookie(r: &Request) -> Option<String> {
    let mut values = r
        .header_all("cookie")
        .flat_map(|h| h.split(';'))
        .filter_map(|p| {
            let (k, v) = p.trim().split_once('=')?;
            (k == COOKIE).then_some(v)
        });
    let id = values.next()?;
    (values.next().is_none() && id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()))
        .then(|| id.into())
}
fn available(app: &App) -> Result<()> {
    app.require_mail()?;
    ensure!(
        crate::modules::state(&*app.read_store()?)?.webmail_enabled,
        "Webmail is disabled"
    );
    Ok(())
}
pub fn start(app: Arc<App>) -> Result<Option<Server>> {
    let Some(config) = app.config.webmail.clone() else {
        return Ok(None);
    };
    config.validate()?;
    if let Some(admin) = &app.config.web {
        ensure!(
            admin.listen != config.listen && admin.origin != config.origin,
            "Webmail requires its own HTTPS listener and origin"
        );
    }
    let addr = config.listen.to_string();
    let tls = Arc::new((*app.tls).clone().with_alpn(&["http/1.1"]));
    let state = State {
        app,
        config,
        sessions: Mutex::new(HashMap::new()),
        attempts: Mutex::new(LoginLimits::default()),
    };
    Ok(Some(
        ServerBuilder::new(move |mut r: Request| secure(state.handle(&mut r)))
            .tls(&addr, tls)
            .http_config(HttpConfig {
                max_request_line: 2048,
                max_header_bytes: 16384,
                max_headers: 32,
                max_body: Some(MAX_BODY as u64),
                max_requests_per_connection: 100,
                drain_limit: 8192,
                server_header: None,
                ..Default::default()
            })
            .limits(Limits {
                max_connections: 4,
                max_connections_per_ip: 4,
                max_h2_handlers: 1,
                idle_timeout: Duration::from_secs(5),
                body_wait: Duration::from_secs(20),
                head_timeout: Duration::from_secs(5),
                ..Default::default()
            })
            .start()?,
    ))
}
impl State {
    fn handle(&self, r: &mut Request) -> Response {
        if r.authority() != self.config.origin.strip_prefix("https://").unwrap() {
            return error(421, "Unexpected host");
        }
        if !matches!(r.method(), "GET" | "POST") {
            return error(405, "Method not allowed");
        }
        if r.method() == "GET" {
            let asset = match r.path() {
                "/" => Some(("text/html; charset=utf-8", include_str!("../web/mail.html"))),
                "/mail.css" => Some(("text/css; charset=utf-8", include_str!("../web/mail.css"))),
                "/mail.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../web/mail.js"),
                )),
                "/favicon.svg" => Some(("image/svg+xml", include_str!("../web/favicon.svg"))),
                _ => None,
            };
            if let Some((kind, text)) = asset {
                return Response::bytes(200, kind, text.as_bytes().to_vec());
            }
        } else if r.header("origin") != Some(self.config.origin.as_str()) {
            return error(403, "Origin rejected");
        } else if r
            .header("content-type")
            .and_then(|s| s.split(';').next())
            .map(str::trim)
            != Some("application/json")
        {
            return error(415, "Use application/json");
        }
        if let Err(e) = available(&self.app) {
            return error(503, &e.to_string());
        }
        if r.path() == "/api/login" && r.method() == "POST" {
            return self.login(r);
        }
        let id = cookie(r);
        let session = {
            let mut s = crate::resilience::reset_lock(&self.sessions);
            s.retain(|_, s| s.until > Instant::now());
            id.as_ref().and_then(|id| s.get(id).cloned())
        };
        let Some(session) = session else {
            return error(401, "Sign in to your mailbox");
        };
        let current = self
            .app
            .read_store()
            .and_then(|s| s.get::<User>(&format!("user/{}", session.user)));
        if !matches!(current,Ok(Some(u)) if crate::witness::same(&fingerprint(&u.password_hash), &session.hash))
        {
            if let Some(id) = id {
                crate::resilience::reset_lock(&self.sessions).remove(&id);
            }
            return error(401, "Your mailbox credentials changed. Sign in again.");
        }
        if r.method() == "POST"
            && !r
                .header("x-csrf-token")
                .is_some_and(|v| crate::witness::same(v, &session.csrf))
        {
            return error(403, "Session verification failed");
        }
        match (r.method(), r.path()) {
            ("GET", "/api/session") => {
                return response(
                    200,
                    json!({"user":session.user,"csrf":session.csrf,"admin_origin":self.app.config.web.as_ref().map(|w| &w.origin)}),
                );
            }
            ("POST", "/api/logout") => {
                if let Some(id) = id {
                    crate::resilience::reset_lock(&self.sessions).remove(&id);
                }
                return response(200, json!({"ok":true})).with_header(
                    "Set-Cookie",
                    &format!("{COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"),
                );
            }
            ("POST", "/api/mail") => {}
            _ => return error(404, "Not found"),
        }
        let Some(_permit) = self.app.data.enter() else {
            return error(503, "Mail is busy. Retry shortly.");
        };
        let command = r
            .read_body(MAX_BODY)
            .map_err(crate::error::Error::from)
            .and_then(|b| Ok(pratique::json_value::from_slice::<Command>(&b)?));
        match command.and_then(|c| self.execute(&session, c)) {
            Ok(r) => r,
            Err(e) => error(400, &e.to_string()),
        }
    }
    fn login(&self, r: &mut Request) -> Response {
        struct Login {
            username: String,
            password: String,
        }
        pratique::data_decode!(Login, deny_unknown=true, { username, password });

        let login = r
            .read_body(8192)
            .ok()
            .and_then(|b| pratique::json_value::from_slice::<Login>(&b).ok());
        let Some(login) = login else {
            return error(400, "Invalid sign-in request");
        };
        let Some(peer) = r.connection().peer else {
            return error(400, "Client address unavailable");
        };
        if !self
            .attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .admit(peer.ip(), Instant::now())
        {
            return error(429, "Too many sign-in attempts. Retry in one minute.")
                .with_header("Retry-After", "60");
        }
        if login.password.len() > 1024 || login.username.len() > 254 {
            return error(401, "Incorrect email or password");
        }
        let Ok(_guard) = crate::resilience::try_lock(&self.app.passwords) else {
            return error(503, "Sign-in is busy. Retry shortly.");
        };
        let user = config::address(&login.username).unwrap_or_default();
        let account = self
            .app
            .read_store()
            .and_then(|s| s.get::<User>(&format!("user/{user}")))
            .ok()
            .flatten();
        let hash = account
            .as_ref()
            .map(|a| a.password_hash.as_str())
            .unwrap_or(&self.app.dummy_hash);
        if !crate::auth::verify(&login.password, hash) || account.is_none() {
            return error(401, "Incorrect email or password");
        }
        let mut sessions = crate::resilience::reset_lock(&self.sessions);
        sessions.retain(|_, s| s.until > Instant::now());
        if let Some(id) = cookie(r) {
            sessions.remove(&id);
        }
        if sessions.len() >= 64 || sessions.values().filter(|s| s.user == user).count() >= 4 {
            return error(
                429,
                "Session limit reached. Sign out elsewhere or wait for expiry.",
            );
        }
        let id = format!("{}{}", store::random_id(), store::random_id());
        let csrf = store::random_id();
        let ttl = self.config.session_minutes * 60;
        sessions.insert(
            id.clone(),
            Session {
                user: user.clone(),
                hash: fingerprint(hash),
                csrf: csrf.clone(),
                until: Instant::now() + Duration::from_secs(ttl),
            },
        );
        response(200, json!({"user":user,"csrf":csrf,"admin_origin":self.app.config.web.as_ref().map(|w| &w.origin)})).with_header(
            "Set-Cookie",
            &format!("{COOKIE}={id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={ttl}"),
        )
    }
    fn commit<R>(
        &self,
        s: &Session,
        f: impl FnOnce(&redb::Table<&str, &[u8]>) -> Result<(Vec<Op>, R)>,
    ) -> Result<R> {
        self.app.mail_commit(|t| {
            let state: crate::modules::State =
                store::json(t, crate::modules::STATE_KEY)?.unwrap_or_default();
            ensure!(state.webmail_enabled, "Webmail is disabled");
            let user: User = store::json(t, &format!("user/{}", s.user))?
                .ok_or_else(|| crate::error!("Mailbox unavailable"))?;
            ensure!(
                crate::witness::same(&fingerprint(&user.password_hash), &s.hash),
                "Mailbox credentials changed"
            );
            f(t)
        })
    }
    fn execute(&self, s: &Session, c: Command) -> Result<Response> {
        let app = &self.app;
        let user = &s.user;
        let value = match c {
            Command::Folders => {
                let store = app.read_store()?;
                let folders = store.list::<Folder>(&format!("folder/{user}/"))?;
                let mut rows = Vec::new();
                for (key, f) in folders {
                    let name = key.strip_prefix(&format!("folder/{user}/")).unwrap();
                    let mails = store.messages(user, name)?;
                    rows.push(json!({"name":name,"validity":f.validity,"count":mails.len(),"unread":mails.iter().filter(|m|!m.flags.iter().any(|f|f=="\\Seen")).count()}));
                }
                json!(rows)
            }
            Command::List { folder, before } => {
                let folder = config::folder(&folder)?;
                let store = app.read_store()?;
                let f: Folder = store
                    .get(&store::folder_key(user, &folder))?
                    .ok_or_else(|| crate::error!("Folder unavailable"))?;
                let mut mails = store.messages(user, &folder)?;
                mails.retain(|m| before.is_none_or(|b| m.uid < b));
                mails.sort_by_key(|m| std::cmp::Reverse(m.uid));
                let more = mails.len() > 25;
                mails.truncate(25);
                let mut rows = Vec::new();
                for m in &mails {
                    let raw = store.blob(&m.blob)?;
                    let parsed = MessageParser::default()
                        .parse_headers(&raw)
                        .ok_or_else(|| crate::error!("Cannot read message"))?;
                    rows.push(json!({"uid":m.uid,"date":m.date,"size":m.size,"flags":m.flags,"subject":clip(parsed.subject().unwrap_or("(No subject)"),512),"from":addresses(parsed.from()),"to":addresses(parsed.to())}));
                }
                json!({"validity":f.validity,"messages":rows,"next":if more {mails.last().map(|m|m.uid)} else {None}})
            }
            Command::Read { message } => {
                let (meta, raw) = load(app, user, &message)?;
                let parsed = MessageParser::default()
                    .parse(&raw)
                    .ok_or_else(|| crate::error!("Cannot read message"))?;
                let text = parsed.body_text(0).unwrap_or_default();
                let attachments=parsed.attachments().enumerate().map(|(i,p)|json!({"index":i,"name":clip(p.attachment_name().unwrap_or("attachment"),200),"size":p.contents().len()})).collect::<Vec<_>>();
                json!({"uid":meta.uid,"subject":clip(parsed.subject().unwrap_or("(No subject)"),512),"from":addresses(parsed.from()),"to":addresses(parsed.to()),"cc":addresses(parsed.cc()),"reply_to":addresses(parsed.reply_to().or_else(||parsed.from())),"date":meta.date,"text":clip(&text,TEXT_LIMIT),"truncated":text.len()>TEXT_LIMIT,"attachments":attachments,"flags":meta.flags})
            }
            Command::Attachment { message, index } => {
                let (_, raw) = load(app, user, &message)?;
                let parsed = MessageParser::default()
                    .parse(&raw)
                    .ok_or_else(|| crate::error!("Cannot read message"))?;
                let p = parsed
                    .attachment(index)
                    .ok_or_else(|| crate::error!("Attachment unavailable"))?;
                return Ok(
                    Response::bytes(200, "application/octet-stream", p.contents().to_vec())
                        .with_header("Content-Disposition", "attachment; filename=attachment.bin"),
                );
            }
            Command::Flag {
                message,
                seen,
                starred,
            } => self.commit(s, |t| {
                let mut m = lookup(t, user, &message)?;
                for (flag, value) in [("\\Seen", seen), ("\\Flagged", starred)] {
                    if let Some(v) = value {
                        m.flags.retain(|f| f != flag);
                        if v {
                            m.flags.push(flag.into());
                        }
                    }
                }
                Ok((
                    vec![Op::json(
                        store::mail_key(user, &message.folder, message.uid),
                        &m,
                    )?],
                    json!({"ok":true}),
                ))
            })?,
            Command::Move { message, target } => {
                let target = config::folder(&target)?;
                ensure!(target != message.folder, "Already in this folder");
                self.commit(s, |t| {
                    let m = lookup(t, user, &message)?;
                    let fk = store::folder_key(user, &target);
                    let mut folder: Folder =
                        store::json(t, &fk)?.ok_or_else(|| crate::error!("Folder unavailable"))?;
                    let uid = folder.next_uid;
                    folder.next_uid = uid
                        .checked_add(1)
                        .ok_or_else(|| crate::error!("UID exhausted"))?;
                    let moved = Message { uid, ..m };
                    Ok((
                        vec![
                            Op::json(fk, &folder)?,
                            Op::json(store::mail_key(user, &target, uid), &moved)?,
                            Op::del(store::mail_key(user, &message.folder, message.uid)),
                        ],
                        json!({"ok":true}),
                    ))
                })?
            }
            Command::Send { draft } => self.send(s, draft)?,
        };
        Ok(response(200, value))
    }
    fn send(&self, s: &Session, draft: Draft) -> Result<Value> {
        ensure!(
            draft.id.len() == 32 && draft.id.bytes().all(|c| c.is_ascii_hexdigit()),
            "Invalid send identifier"
        );
        let receipt = format!("webmail/sent/{}/{}", s.user, draft.id);
        let digest = fingerprint(&pratique::json_value::to_string(&draft)?);
        // A retry uses the same request ID and payload, including after a lost response.
        if let Some(old) = self.app.read_store()?.get::<Receipt>(&receipt)? {
            ensure!(
                old.digest == digest,
                "Send identifier already used for a different message"
            );
            return Ok(json!({"queued":true,"id":old.blob}));
        }
        let to = recipients(&draft.to)?;
        let cc = recipients(&draft.cc)?;
        let bcc = recipients(&draft.bcc)?;
        let mut all = to
            .iter()
            .chain(&cc)
            .chain(&bcc)
            .cloned()
            .collect::<Vec<_>>();
        all.sort();
        all.dedup();
        ensure!(
            !all.is_empty() && all.len() <= self.app.config.limits.recipients,
            "Add recipients within the configured limit"
        );
        let mut reply = None;
        if let Some(reference) = &draft.reply {
            let (_, raw) = load(&self.app, &s.user, reference)?;
            let m = MessageParser::default()
                .parse(&raw)
                .ok_or_else(|| crate::error!("Cannot read replied-to message"))?;
            reply = m
                .message_id()
                .filter(|v| {
                    v.len() <= 500
                        && v.bytes()
                            .all(|c| c.is_ascii_graphic() && !b"<>".contains(&c))
                })
                .map(str::to_owned);
        }
        let id = store::random_id();
        let mut raw = compose(
            &s.user,
            &to,
            &cc,
            &draft,
            reply.as_deref(),
            &id,
            &self.app.config.hostname,
        )?;
        if let Some(signer) = &self.app.signer {
            raw = signer.sign(&raw)?;
        }
        ensure!(
            raw.len() <= self.app.config.limits.message_bytes,
            "Message exceeds server size limit"
        );
        crate::auth::validate(&raw)?;
        crate::relay::message_features(&raw)?;
        self.commit(s, |t| {
            if let Some(old) = store::json::<Receipt>(t, &receipt)? {
                ensure!(old.digest == digest, "Send identifier already used");
                return Ok((vec![], json!({"queued":true,"id":old.blob})));
            }
            let now = crate::datetime::Utc::now().timestamp();
            let mut ops = crate::smtp::delivery_ops(
                t,
                &self.app,
                &s.user,
                &all,
                &id,
                &raw,
                false,
                self.app.signer.is_some(),
                true,
                now,
            )?;
            // Keep the most recent 128 successful send receipts per mailbox.
            let mut previous = store::scan::<Receipt>(t, &format!("webmail/sent/{}/", s.user))?;
            previous.sort_by_key(|(_, r)| r.created);
            let remove = previous.len().saturating_sub(127);
            for (key, _) in previous.into_iter().take(remove) {
                ops.push(Op::del(key));
            }
            ops.push(Op::json(
                receipt.clone(),
                &Receipt {
                    blob: id.clone(),
                    digest: digest.clone(),
                    created: now,
                },
            )?);
            Ok((ops, json!({"queued":true,"id":id})))
        })
    }
}
enum Command {
    Folders,
    List {
        folder: String,
        before: Option<u32>,
    },
    Read {
        message: Reference,
    },
    Attachment {
        message: Reference,
        index: u32,
    },
    Flag {
        message: Reference,
        seen: Option<bool>,
        starred: Option<bool>,
    },
    Move {
        message: Reference,
        target: String,
    },
    Send {
        draft: Draft,
    },
}
impl pratique::data::Decode for Command {
    fn decode(n: pratique::data::Node) -> Result<Self, pratique::data::Error> {
        let sequence = matches!(n.kind, pratique::data::Kind::Array(_));
        let mut f = pratique::data::Fields::new(n, true)?;
        let action: String = f.field("action")?;
        let v = match action.as_str() {
            "folders" => Self::Folders,
            "list" => Self::List {
                folder: f.field("folder")?,
                before: f.field("before")?,
            },
            "read" => Self::Read {
                message: f.field("message")?,
            },
            "attachment" => Self::Attachment {
                message: f.field("message")?,
                index: f.field("index")?,
            },
            "flag" => Self::Flag {
                message: f.field("message")?,
                seen: f.field("seen")?,
                starred: f.field("starred")?,
            },
            "move" => Self::Move {
                message: f.field("message")?,
                target: f.field("target")?,
            },
            "send" => Self::Send {
                draft: f.field("draft")?,
            },
            _ => return Err(pratique::data::Error::new("unknown action").field("action")),
        };
        // The existing read-only unit command ignores its unused content. Keep that
        // wire behavior; data-bearing commands still reject unknown/trailing fields.
        if sequence || !matches!(v, Self::Folders) {
            f.finish()?;
        }
        Ok(v)
    }
}

struct Reference {
    folder: String,
    validity: u32,
    uid: u32,
}
pratique::data_encode!(Reference {
    folder,
    validity,
    uid
});
pratique::data_decode!(Reference, deny_unknown=true, { folder, validity, uid });

struct Draft {
    id: String,
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    subject: String,
    text: String,
    attachments: Vec<Attachment>,
    reply: Option<Reference>,
}
pratique::data_encode!(Draft {
    id,
    to,
    cc,
    bcc,
    subject,
    text,
    attachments,
    reply
});
pratique::data_decode!(Draft, deny_unknown=true, { id, to, cc = Default::default(), bcc = Default::default(), subject, text, attachments = Default::default(), reply });

struct Attachment {
    name: String,
    data: String,
}
pratique::data_encode!(Attachment { name, data });
pratique::data_decode!(Attachment, deny_unknown=true, { name, data });

struct Receipt {
    blob: String,
    digest: String,
    created: i64,
}
pratique::data_encode!(Receipt {
    blob,
    digest,
    created
});
pratique::data_decode!(Receipt, deny_unknown=false, { blob, digest, created });

fn lookup(
    t: &impl redb::ReadableTable<&'static str, &'static [u8]>,
    user: &str,
    r: &Reference,
) -> Result<Message> {
    ensure!(config::folder(&r.folder)? == r.folder, "Invalid folder");
    let f: Folder = store::json(t, &store::folder_key(user, &r.folder))?
        .ok_or_else(|| crate::error!("Folder unavailable"))?;
    ensure!(
        f.validity == r.validity,
        "Mailbox changed. Refresh before continuing."
    );
    store::json(t, &store::mail_key(user, &r.folder, r.uid))?
        .ok_or_else(|| crate::error!("Message unavailable"))
}
fn load(app: &App, user: &str, r: &Reference) -> Result<(Message, Vec<u8>)> {
    use redb::ReadableDatabase;
    let store = app.read_store()?;
    let tx = store.db.begin_read()?;
    let t = tx.open_table(store::KV)?;
    let m = lookup(&t, user, r)?;
    let raw = t
        .get(format!("blob/{}", m.blob).as_str())?
        .ok_or_else(|| crate::error!("Message unavailable"))?
        .value()
        .to_vec();
    Ok((m, raw))
}
fn clip(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}
fn addresses(a: Option<&workglen_mime::Address<'_>>) -> Vec<String> {
    a.map(|a| {
        a.iter()
            .filter_map(|v| v.address.as_deref())
            .take(50)
            .map(|v| clip(v, 254))
            .collect()
    })
    .unwrap_or_default()
}
fn recipients(a: &[String]) -> Result<Vec<String>> {
    ensure!(a.len() <= 25, "Too many recipients");
    a.iter().map(|v| config::address(v.trim())).collect()
}
fn b64(raw: &[u8]) -> String {
    let encoded = STANDARD.encode(raw);
    encoded
        .as_bytes()
        .chunks(76)
        .map(|c| format!("{}\r\n", std::str::from_utf8(c).unwrap()))
        .collect()
}
fn subject(s: &str) -> Result<String> {
    ensure!(
        s.len() <= 512 && !s.chars().any(char::is_control),
        "Invalid or excessive subject"
    );
    let mut words = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        let p = clip(rest, 42);
        words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(&p)));
        rest = &rest[p.len()..];
    }
    Ok(words.join("\r\n "))
}
fn compose(
    user: &str,
    to: &[String],
    cc: &[String],
    d: &Draft,
    reply: Option<&str>,
    id: &str,
    host: &str,
) -> Result<Vec<u8>> {
    ensure!(
        d.text.len() <= TEXT_LIMIT && !d.text.contains('\0'),
        "Message text exceeds 256 KiB or contains NUL"
    );
    ensure!(d.attachments.len() <= 10, "At most 10 attachments");
    let date = crate::datetime::Utc::now().to_rfc2822();
    let mut raw = format!(
        "Received: by {host} with HTTPS; {date}\r\nFrom: {user}\r\nTo: {}\r\n",
        if to.is_empty() {
            "undisclosed-recipients:;".into()
        } else {
            to.join(",\r\n ")
        }
    );
    if !cc.is_empty() {
        raw.push_str(&format!("Cc: {}\r\n", cc.join(",\r\n ")));
    }
    raw.push_str(&format!(
        "Subject: {}\r\nDate: {date}\r\nMessage-ID: <{id}@{host}>\r\nMIME-Version: 1.0\r\n",
        subject(&d.subject)?
    ));
    if let Some(r) = reply {
        raw.push_str(&format!("In-Reply-To: <{r}>\r\nReferences: <{r}>\r\n"));
    }
    let body = d
        .text
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n");
    let text = format!(
        "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        b64(body.as_bytes())
    );
    if d.attachments.is_empty() {
        raw.push_str(&text);
    } else {
        let boundary = format!("wg_{}", store::random_id());
        raw.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\n{text}"
        ));
        let mut total = 0;
        for a in &d.attachments {
            ensure!(
                !a.name.is_empty() && a.name.len() <= 200 && !a.name.chars().any(char::is_control),
                "Invalid attachment name"
            );
            let bytes = STANDARD.decode(&a.data)?;
            total += bytes.len();
            ensure!(
                total <= 3 * 1024 * 1024,
                "Attachments exceed 3 MiB combined"
            );
            let filename = a
                .name
                .bytes()
                .map(|c| format!("%{c:02X}"))
                .collect::<String>();
            raw.push_str(&format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment;\r\n filename*=UTF-8''{filename}\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",b64(&bytes)));
        }
        raw.push_str(&format!("\r\n--{boundary}--\r\n"));
    }
    if !raw.ends_with("\r\n") {
        raw.push_str("\r\n");
    }
    Ok(raw.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn draft() -> Draft {
        Draft {
            id: "a".repeat(32),
            to: vec!["b@example.test".into()],
            cc: vec![],
            bcc: vec!["secret@example.test".into()],
            subject: "Résumé — ☕".into(),
            text: "Hello\nUnicode café ☕".into(),
            attachments: vec![Attachment {
                name: "résumé.txt".into(),
                data: STANDARD.encode(b"private attachment"),
            }],
            reply: None,
        }
    }
    #[test]
    fn compose_preserves_unicode_and_hides_bcc() {
        let d = draft();
        let raw = compose(
            "a@example.test",
            &d.to,
            &[],
            &d,
            Some("prior@example.test"),
            &d.id,
            "mail.example.test",
        )
        .unwrap();
        crate::auth::validate(&raw).unwrap();
        crate::relay::message_features(&raw).unwrap();
        let m = MessageParser::default().parse(&raw).unwrap();
        assert_eq!(m.subject(), Some(d.subject.as_str()));
        assert_eq!(m.body_text(0).unwrap(), "Hello\r\nUnicode café ☕");
        assert_eq!(
            m.attachment(0).unwrap().attachment_name(),
            Some("résumé.txt")
        );
        assert_eq!(m.attachment(0).unwrap().contents(), b"private attachment");
        assert!(!String::from_utf8_lossy(&raw).contains("secret@example.test"));
    }
    #[test]
    fn compose_rejects_injected_headers_and_large_payloads() {
        let mut d = draft();
        d.subject = "test\r\nBcc: victim@example.test".into();
        assert!(
            compose(
                "a@example.test",
                &d.to,
                &[],
                &d,
                None,
                &d.id,
                "mail.example.test"
            )
            .is_err()
        );
        d.subject = "ok".into();
        d.attachments[0].name = "file\r\nX: injected".into();
        assert!(
            compose(
                "a@example.test",
                &d.to,
                &[],
                &d,
                None,
                &d.id,
                "mail.example.test"
            )
            .is_err()
        );
        assert!(recipients(&["a@example.test\r\nBcc: victim@example.test".into()]).is_err());
    }
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    impl pratique::data::Encode for Command {
        fn encode(&self) -> Result<pratique::data::Node, pratique::data::Error> {
            use pratique::data::{Kind, Node};
            let (a, mut fields) = match self {
                Self::Folders => ("folders", vec![]),
                Self::List { folder, before } => (
                    "list",
                    vec![
                        ("folder".into(), folder.encode()?),
                        ("before".into(), before.encode()?),
                    ],
                ),
                Self::Read { message } => ("read", vec![("message".into(), message.encode()?)]),
                Self::Attachment { message, index } => (
                    "attachment",
                    vec![
                        ("message".into(), message.encode()?),
                        ("index".into(), index.encode()?),
                    ],
                ),
                Self::Flag {
                    message,
                    seen,
                    starred,
                } => (
                    "flag",
                    vec![
                        ("message".into(), message.encode()?),
                        ("seen".into(), seen.encode()?),
                        ("starred".into(), starred.encode()?),
                    ],
                ),
                Self::Move { message, target } => (
                    "move",
                    vec![
                        ("message".into(), message.encode()?),
                        ("target".into(), target.encode()?),
                    ],
                ),
                Self::Send { draft } => ("send", vec![("draft".into(), draft.encode()?)]),
            };
            fields.insert(0, ("action".into(), a.encode()?));
            Ok(Node::new(Kind::Object(fields)))
        }
    }
    #[test]
    fn record_contract_command() {
        crate::data_contracts::check::<Command>(
            "src_webmail_Command",
            &[
                r###"{"action":"folders"}"###,
                r###"{"action":"list","folder":"Inbox"}"###,
                r###"{"action":"read","message":{"folder":"Inbox","validity":1,"uid":2}}"###,
                r###"{"action":"attachment","message":{"folder":"Inbox","validity":1,"uid":2},"index":0}"###,
                r###"{"action":"flag","message":{"folder":"Inbox","validity":1,"uid":2}}"###,
                r###"{"action":"move","message":{"folder":"Inbox","validity":1,"uid":2},"target":"Trash"}"###,
                r###"{"action":"send","draft":{"id":"x","to":[],"subject":"x","text":"y"}}"###,
                r###"{"action":"folders","extra":1}"###,
                r###"{"action":"unknown"}"###,
                r###"["folders"]"###,
                r###"["folders",1]"###,
                r###"["list","Inbox",null]"###,
                r###"["list","Inbox"]"###,
                r###"["list",{"folder":"Inbox"}]"###,
                r###"["read",{"folder":"Inbox","validity":1,"uid":2}]"###,
                r###"["flag",{"folder":"Inbox","validity":1,"uid":2},null,null]"###,
                r###"{"action":"list","folder":"Inbox","extra":1}"###,
                r###"{"action":"folders","action":"list"}"###,
            ],
        );
    }
    #[test]
    fn record_contract_reference() {
        crate::data_contracts::check::<Reference>(
            "src_webmail_Reference",
            &[
                r###"{"folder":"sample-\u00e9\ud83d\ude00","validity":4294967295,"uid":4294967295}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",4294967295,4294967295]"###,
                r###"{"folder":"sample-\u00e9\ud83d\ude00","validity":4294967295,"uid":4294967295,"unexpected_field":1}"###,
                r###"{"validity":4294967295,"uid":4294967295}"###,
                r###"{"folder":false,"validity":4294967295,"uid":4294967295}"###,
                r###"{"folder":"sample-\u00e9\ud83d\ude00","validity":4294967295,"uid":4294967295,"folder":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"folder":"sample-\u00e9\ud83d\ude00","uid":4294967295}"###,
                r###"{"folder":"sample-\u00e9\ud83d\ude00","validity":"wrong","uid":4294967295}"###,
                r###"{"folder":"sample-\u00e9\ud83d\ude00","validity":4294967295,"uid":4294967295,"validity":4294967295}"###,
                r###"{"folder":"sample-\u00e9\ud83d\ude00","validity":4294967295}"###,
                r###"{"folder":"sample-\u00e9\ud83d\ude00","validity":4294967295,"uid":"wrong"}"###,
                r###"{"folder":"sample-\u00e9\ud83d\ude00","validity":4294967295,"uid":4294967295,"uid":4294967295}"###,
            ],
        );
    }
    #[test]
    fn record_contract_draft() {
        crate::data_contracts::check::<Draft>(
            "src_webmail_Draft",
            &[
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],"sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",[],null]"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null,"unexpected_field":1}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":false,"to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null,"id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":"wrong","cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null,"to":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":"wrong","bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null,"cc":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":"wrong","subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null,"bcc":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":false,"text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null,"subject":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":false,"attachments":[],"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null,"text":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":"wrong","reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null,"attachments":[]}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[]}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":"wrong"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":null,"reply":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","to":["sample-\u00e9\ud83d\ude00"],"cc":["sample-\u00e9\ud83d\ude00"],"bcc":["sample-\u00e9\ud83d\ude00"],"subject":"sample-\u00e9\ud83d\ude00","text":"sample-\u00e9\ud83d\ude00","attachments":[],"reply":{"folder":"sample-\u00e9\ud83d\ude00","validity":4294967295,"uid":4294967295}}"###,
            ],
        );
    }
    #[test]
    fn record_contract_attachment() {
        crate::data_contracts::check::<Attachment>(
            "src_webmail_Attachment",
            &[
                r###"{"name":"sample-\u00e9\ud83d\ude00","data":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00"]"###,
                r###"{"name":"sample-\u00e9\ud83d\ude00","data":"sample-\u00e9\ud83d\ude00","unexpected_field":1}"###,
                r###"{"data":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"name":false,"data":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"name":"sample-\u00e9\ud83d\ude00","data":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"name":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"name":"sample-\u00e9\ud83d\ude00","data":false}"###,
                r###"{"name":"sample-\u00e9\ud83d\ude00","data":"sample-\u00e9\ud83d\ude00","data":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    #[test]
    fn record_contract_receipt() {
        crate::data_contracts::check::<Receipt>(
            "src_webmail_Receipt",
            &[
                r###"{"blob":"sample-\u00e9\ud83d\ude00","digest":"sample-\u00e9\ud83d\ude00","created":-9223372036854775808}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",-9223372036854775808]"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","digest":"sample-\u00e9\ud83d\ude00","created":-9223372036854775808,"unexpected_field":1}"###,
                r###"{"digest":"sample-\u00e9\ud83d\ude00","created":-9223372036854775808}"###,
                r###"{"blob":false,"digest":"sample-\u00e9\ud83d\ude00","created":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","digest":"sample-\u00e9\ud83d\ude00","created":-9223372036854775808,"blob":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","created":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","digest":false,"created":-9223372036854775808}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","digest":"sample-\u00e9\ud83d\ude00","created":-9223372036854775808,"digest":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","digest":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","digest":"sample-\u00e9\ud83d\ude00","created":"wrong"}"###,
                r###"{"blob":"sample-\u00e9\ud83d\ude00","digest":"sample-\u00e9\ud83d\ude00","created":-9223372036854775808,"created":-9223372036854775808}"###,
            ],
        );
    }
}
