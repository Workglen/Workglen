//! Optional, embedded administration interface over Pratique HTTPS.
//! Credentials, tokens, sessions and passwords never enter access logs or URLs.
use crate::error::{Result, ensure};
use crate::{admin, app::App, config::Web, rbac};
use pratique::http::server::{HttpConfig, Limits, Request, Response, Server, ServerBuilder};
use pratique::json_value::{Value, json};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const COOKIE: &str = "__Host-workglen_session";
const SESSION_LIMIT: usize = 16;
const LOGIN_SOURCE_LIMIT: usize = 1024;
const LOGIN_ATTEMPTS: u32 = 20;
const LOGIN_WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(crate) struct LoginLimits {
    sources: HashMap<IpAddr, (Instant, u32)>,
}
impl LoginLimits {
    pub(crate) fn admit(&mut self, source: IpAddr, now: Instant) -> bool {
        // Use only the actual socket peer, never untrusted forwarding headers.
        let source = source.to_canonical();
        self.sources
            .retain(|_, (start, _)| now.duration_since(*start) < LOGIN_WINDOW);
        if !self.sources.contains_key(&source) && self.sources.len() >= LOGIN_SOURCE_LIMIT {
            return false;
        }
        let bucket = self.sources.entry(source).or_insert((now, 0));
        if bucket.1 >= LOGIN_ATTEMPTS {
            return false;
        }
        bucket.1 += 1;
        true
    }
}
#[derive(Clone)]
struct Session {
    csrf: String,
    until: Instant,
    expires_at: i64,
    principal: rbac::Principal,
}
#[derive(Default)]
struct Sessions {
    values: HashMap<String, Session>,
}
impl Sessions {
    fn prune(&mut self, now: Instant) {
        self.values.retain(|_, s| s.until > now);
    }
    fn create(
        &mut self,
        ttl: Duration,
        now: Instant,
        principal: rbac::Principal,
    ) -> Result<(String, Session)> {
        self.prune(now);
        ensure!(
            self.values.len() < SESSION_LIMIT,
            "Too many active administrator sessions. Sign out elsewhere or wait for expiry."
        );
        let id = format!("{}{}", crate::store::random_id(), crate::store::random_id());
        let s = Session {
            principal,
            csrf: crate::store::random_id(),
            until: now + ttl,
            expires_at: crate::datetime::Utc::now()?.timestamp() + ttl.as_secs() as i64,
        };
        self.values.insert(id.clone(), s.clone());
        Ok((id, s))
    }
}
struct State {
    app: Arc<App>,
    config: Web,
    password_hash: String,
    sessions: Mutex<Sessions>,
    attempts: Mutex<LoginLimits>,
}
pub fn start(app: Arc<App>) -> Result<Option<Server>> {
    let Some(config) = app.config.web.clone() else {
        return Ok(None);
    };
    config.validate()?;
    let password_hash = crate::config::secret(&config.password_hash_file)?;
    argon2::PasswordHash::new(&password_hash)
        .map_err(|_| crate::error!("invalid web password hash"))?;
    let addr = config.listen.to_string();
    let tls = Arc::new((*app.tls).clone().with_alpn(&["http/1.1"]));
    let state = Arc::new(State {
        app,
        config,
        password_hash,
        sessions: Mutex::new(Sessions {
            values: HashMap::new(),
        }),
        attempts: Mutex::new(LoginLimits::default()),
    });
    let server = ServerBuilder::new(move |mut r: Request| {
        let response = state.handle(&mut r);
        secure(response)
    })
    .tls(&addr, tls)
    .http_config(HttpConfig {
        max_request_line: 2048,
        max_header_bytes: 16384,
        max_headers: 32,
        max_body: Some(crate::accounting::MAX_BODY as u64),
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
        body_wait: Duration::from_secs(10),
        head_timeout: Duration::from_secs(5),
        ..Default::default()
    })
    .start()?;
    Ok(Some(server))
}
pub(crate) fn secure(r: Response) -> Response {
    r.with_header("Cache-Control", "no-store")
     .with_header("X-Content-Type-Options", "nosniff")
     .with_header("X-Frame-Options", "DENY")
     .with_header("Referrer-Policy", "no-referrer")
     .with_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
     .with_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
}
pub(crate) fn response(status: u16, value: Value) -> Response {
    Response::bytes(
        status,
        "application/json; charset=utf-8",
        value.to_string().into_bytes(),
    )
}
pub(crate) fn error(status: u16, message: &str) -> Response {
    response(status, json!({"error":message}))
}
fn body<T: pratique::data::Decode>(r: &mut Request) -> Result<T> {
    Ok(pratique::json_value::from_slice(&r.read_body(8192)?)?)
}
fn cookie_id(r: &Request) -> Option<String> {
    let mut ids = r
        .header_all("cookie")
        .flat_map(|h| h.split(';'))
        .filter_map(|p| {
            let (k, v) = p.trim().split_once('=')?;
            (k == COOKIE).then_some(v)
        });
    let id = ids.next()?;
    if ids.next().is_some() || id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(id.into())
}
fn same_origin(origin: Option<&str>, expected: &str) -> bool {
    origin == Some(expected)
}
impl State {
    fn session(&self, id: Option<&str>) -> Option<Session> {
        let mut all = crate::resilience::reset_lock(&self.sessions);
        all.prune(Instant::now());
        id.and_then(|id| all.values.get(id).cloned())
    }
    fn handle(&self, r: &mut Request) -> Response {
        // Host validation also protects read routes against DNS rebinding. No proxy
        // headers are trusted; this listener always terminates TLS itself.
        let authority = self.config.origin.strip_prefix("https://").unwrap();
        if r.authority() != authority {
            return error(421, "Unexpected host");
        }
        if !matches!(r.method(), "GET" | "POST") {
            return error(405, "Method not allowed");
        }
        let path = r.path().to_string();
        if r.method() == "GET" {
            if path == "/app.js" {
                // One script request keeps the bounded administration listener usable
                // by browsers opening parallel HTTP/1 asset connections.
                let script = [
                    include_str!("../web/app.js"),
                    include_str!("../web/access.js"),
                    include_str!("../web/accounting.js"),
                    include_str!("../web/postings.js"),
                ]
                .join("\n");
                return Response::bytes(200, "text/javascript; charset=utf-8", script.into_bytes());
            }
            let asset = match path.as_str() {
                "/" => Some((
                    "text/html; charset=utf-8",
                    include_str!("../web/index.html"),
                )),
                "/app.css" => Some(("text/css; charset=utf-8", include_str!("../web/app.css"))),
                "/access.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../web/access.js"),
                )),
                "/postings.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../web/postings.js"),
                )),
                "/accounting.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../web/accounting.js"),
                )),
                "/app.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../web/app.js"),
                )),
                "/mail-security" => Some((
                    "text/html; charset=utf-8",
                    include_str!("../web/security/index.html"),
                )),
                "/delivery.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../web/security/delivery.js"),
                )),
                "/microsoft365.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../web/security/microsoft365.js"),
                )),
                "/security.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../web/security/security.js"),
                )),
                "/security.css" => Some((
                    "text/css; charset=utf-8",
                    include_str!("../web/security/security.css"),
                )),
                "/favicon.svg" => Some(("image/svg+xml", include_str!("../web/favicon.svg"))),
                _ => None,
            };
            if let Some((ct, asset)) = asset {
                return Response::bytes(200, ct, asset.as_bytes().to_vec());
            }
        } else {
            if !same_origin(r.header("origin"), &self.config.origin) {
                return error(403, "Origin rejected");
            }
            if r.header("content-type")
                .and_then(|v| v.split(';').next())
                .map(str::trim)
                != Some("application/json")
            {
                return error(415, "Use application/json");
            }
            if path == "/api/login" {
                return self.login(r);
            }
        }
        let id = cookie_id(r);
        let Some(session) = self.session(id.as_deref()) else {
            return error(401, "Sign in to continue");
        };
        let changing_access = path == "/api/access" && r.method() == "POST";
        let _read = (!changing_access).then(|| {
            self.app
                .authorization
                .read()
                .unwrap_or_else(|e| e.into_inner())
        });
        let _write = changing_access.then(|| {
            self.app
                .authorization
                .write()
                .unwrap_or_else(|e| e.into_inner())
        });
        let access = match rbac::resolve(&self.app, &session.principal) {
            Ok(Some(a)) => a,
            _ => {
                return error(
                    401,
                    "Your access changed or this node is not primary. Sign in again on the primary.",
                );
            }
        };
        if r.method() == "POST"
            && !r
                .header("x-csrf-token")
                .is_some_and(|v| crate::witness::same(v, &session.csrf))
        {
            return error(403, "Session verification failed. Reload and try again.");
        }
        if path == "/api/session" && r.method() == "GET" {
            return response(
                200,
                json!({"csrf":session.csrf,"username":access.username,"expires_at":session.expires_at,"permissions":access.permissions(),"books":access.books,"security_domains":access.security_domains,"security_mailboxes":access.security_mailboxes,"security_instances":access.security_instances}),
            );
        }
        if path == "/api/logout" && r.method() == "POST" {
            if let Some(id) = id {
                crate::resilience::reset_lock(&self.sessions)
                    .values
                    .remove(&id);
            }
            return response(200, json!({"ok":true})).with_header(
                "Set-Cookie",
                &format!("{COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"),
            );
        }
        if !matches!(
            (r.method(), path.as_str()),
            (
                "GET",
                "/api/security/remotes"
                    | "/api/modules"
                    | "/api/overview"
                    | "/api/users"
                    | "/api/queue"
                    | "/api/policy"
                    | "/api/backups"
                    | "/api/access"
                    | "/api/audit"
            ) | (
                "POST",
                "/api/security"
                    | "/api/accounting"
                    | "/api/modules"
                    | "/api/users"
                    | "/api/users/password"
                    | "/api/backups"
                    | "/api/access"
            )
        ) {
            return error(404, "Not found");
        }
        if r.method() == "POST"
            && (path.starts_with("/api/users") || path == "/api/modules")
            && !self.app.primary()
        {
            return error(409, "This node is read-only. Use the current primary.");
        }
        let required = match (r.method(), path.as_str()) {
            (_, "/api/access") => Some("access.manage"),
            (_, "/api/audit") => Some("audit.read"),
            ("GET", "/api/users" | "/api/policy") => Some("mail.read"),
            ("POST", "/api/users" | "/api/users/password") => Some("mail.manage"),
            (_, "/api/queue") => Some("queue.read"),
            ("GET", "/api/backups") => Some("backups.read"),
            ("POST", "/api/backups") => Some("backups.create"),
            _ => None,
        };
        if required.is_some_and(|p| !access.allows(p)) {
            return error(403, "Permission denied");
        }
        match self.api(r, &path, &access) {
            Ok(v) => response(200, v),
            Err(e) => error(
                if e.is::<rbac::Denied>() { 403 } else { 400 },
                &e.to_string(),
            ),
        }
    }
    fn login(&self, r: &mut Request) -> Response {
        struct Login {
            username: String,
            password: String,
        }
        pratique::data_decode!(Login, deny_unknown=true, { username, password });

        let Ok(login) = body::<Login>(r) else {
            return error(400, "Invalid sign-in request");
        };
        if login.password.len() > 1024 || login.username.len() > 64 {
            return error(401, "Incorrect username or password");
        }
        let Some(peer) = r.connection().peer else {
            return error(400, "Client address unavailable");
        };
        if !self
            .attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .admit(peer.ip(), Instant::now())
        {
            return error(
                429,
                "Too many sign-in attempts from this address. Retry in one minute.",
            )
            .with_header("Retry-After", "60");
        }
        // Do not queue all HTTP handlers behind expensive password work.
        let Ok(_password) = crate::resilience::try_lock(&self.app.passwords) else {
            return error(503, "Sign-in is busy. Retry shortly.").with_header("Retry-After", "1");
        };
        let principal = if login.username == self.config.username {
            if crate::auth::verify(&login.password, &self.password_hash) {
                Some(rbac::Principal::bootstrap(&self.config.username))
            } else {
                None
            }
        } else {
            if !self.app.primary() {
                return error(409, "Use the primary node for named-user sign-in");
            }
            rbac::authenticate(&self.app, &login.username, &login.password).unwrap_or(None)
        };
        let Some(principal) = principal else {
            return error(401, "Incorrect username or password");
        };
        let access = match rbac::resolve(&self.app, &principal) {
            Ok(Some(a)) => a,
            _ => return error(401, "Incorrect username or password"),
        };
        let mut sessions = crate::resilience::reset_lock(&self.sessions);
        if let Some(id) = cookie_id(r) {
            sessions.values.remove(&id);
        }
        let ttl = Duration::from_secs(self.config.session_minutes * 60);
        match sessions.create(ttl, Instant::now(), principal) {
            Ok((id, s)) => response(
                200,
                json!({"csrf":s.csrf,"username":access.username,"expires_at":s.expires_at,"permissions":access.permissions(),"books":access.books,"security_domains":access.security_domains,"security_mailboxes":access.security_mailboxes,"security_instances":access.security_instances}),
            )
            .with_header(
                "Set-Cookie",
                &format!(
                    "{COOKIE}={id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
                    ttl.as_secs()
                ),
            ),
            Err(e) => error(429, &e.to_string()),
        }
    }
    fn command(&self, command: &str) -> Result<Value> {
        let result = admin::execute(
            &self.app,
            admin::Request {
                command: command.into(),
                user: None,
                password_hash: None,
                expected_revision: None,
                accounting: None,
                access: None,
            },
        )?;
        Ok(pratique::json_value::from_str(&result)?)
    }
    fn api(&self, r: &mut Request, path: &str, access: &rbac::Access) -> Result<Value> {
        match (r.method(), path) {
            ("GET", "/api/security/remotes") => crate::security_remote::list(&self.app, access),
            ("POST", "/api/security") => {
                let request =
                    pratique::json_value::from_slice(&r.read_body(crate::accounting::MAX_BODY)?)?;
                crate::security_remote::execute(&self.app, access, request)
            }
            ("POST", "/api/accounting") => {
                let command: crate::accounting::model::Command =
                    pratique::json_value::from_slice(&r.read_body(crate::accounting::MAX_BODY)?)?;
                access.accounting(&command)?;
                let list = command.action == "books";
                let mut result = crate::accounting::execute(
                    &self.app,
                    command,
                    &format!("web:{}", access.username),
                )?;
                if list && let Some(rows) = result.as_array_mut() {
                    rows.retain(|v| v["id"].as_str().is_some_and(|id| access.book(id)));
                }
                Ok(result)
            }
            ("GET", "/api/access") => rbac::list(&self.app),
            ("GET", "/api/audit") => rbac::audit(&self.app),
            ("POST", "/api/access") => {
                let change = body(r)?;
                let _password = self.app.passwords.lock().unwrap_or_else(|e| e.into_inner());
                rbac::change(&self.app, &access.username, change)
            }
            ("GET", "/api/modules") => {
                let mut v = self.command("modules")?;
                if !access.allows("accounting.read") {
                    v["accounting"] = json!({"enabled":false,"ready":false,"configured":false,"message":"Accounting permission required"});
                }
                if let Some(modules) = v["modules"].as_array_mut() {
                    modules.retain(|m| match m["id"].as_str() {
                        Some("accounts") => access.allows("accounting.read"),
                        Some("mail" | "webmail") => {
                            access.allows("mail.read") || access.allows("system.read")
                        }
                        _ => access.allows("system.read"),
                    });
                }
                Ok(v)
            }
            ("POST", "/api/modules") => {
                struct Change {
                    id: String,
                    enabled: bool,
                    expected_revision: u64,
                }
                pratique::data_decode!(Change, deny_unknown=true, { id, enabled, expected_revision });

                let change: Change = body(r)?;
                access.require(if change.id == "accounts" {
                    "modules.accounts"
                } else {
                    "modules.mail"
                })?;
                let state = crate::modules::change(
                    &self.app,
                    &change.id,
                    change.enabled,
                    Some(change.expected_revision),
                )?;
                Ok(json!(state))
            }
            ("GET", "/api/overview") => {
                if !access.allows("system.read") {
                    return Ok(
                        json!({"primary":self.app.primary(),"domain":self.app.config.domain,"node":self.app.config.node_id(),"modules":crate::modules::state(&*self.app.read_store()?)?}),
                    );
                }
                let mut status = self.command("status")?;
                let accounts = admin::users(&self.app)?;
                let queue = self
                    .app
                    .read_store()?
                    .list::<crate::config::QueueItem>("queue/")?;
                status["accounts"] = json!(accounts.len());
                status["messages"] = json!(accounts.iter().map(|a| a.messages).sum::<u64>());
                status["mailbox_bytes"] = json!(accounts.iter().map(|a| a.used_bytes).sum::<u64>());
                status["queue_count"] = json!(queue.len());
                status["queue_failed"] =
                    json!(queue.iter().filter(|(_, q)| q.status == "failed").count());
                Ok(status)
            }
            ("GET", "/api/users") => self.command("users"),
            ("GET", "/api/queue") => self.command("queue"),
            ("GET", "/api/policy") => self.command("policy"),
            ("GET", "/api/backups") => self.command("backups"),
            ("POST", "/api/backups") => {
                let path = admin::execute(
                    &self.app,
                    admin::Request {
                        command: "backup".into(),
                        user: None,
                        password_hash: None,
                        expected_revision: None,
                        accounting: None,
                        access: None,
                    },
                )?;
                Ok(json!({"path":path}))
            }
            ("POST", "/api/users" | "/api/users/password") => {
                struct Account {
                    email: String,
                    password: String,
                }
                pratique::data_decode!(Account, deny_unknown=true, { email, password });

                let a: Account = body(r)?;
                let _password = self.app.passwords.lock().unwrap_or_else(|e| e.into_inner());
                let hash = crate::auth::hash(&a.password)?;
                admin::execute(
                    &self.app,
                    admin::Request {
                        command: if path.ends_with("password") {
                            "set-password"
                        } else {
                            "add-user"
                        }
                        .into(),
                        user: Some(a.email),
                        password_hash: Some(hash),
                        expected_revision: None,
                        accounting: None,
                        access: None,
                    },
                )?;
                Ok(json!({"ok":true}))
            }
            _ => unreachable!(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn login_limits_isolate_sources_and_expire() {
        let now = Instant::now();
        let mut limits = LoginLimits::default();
        let attacker: IpAddr = "127.0.0.2".parse().unwrap();
        let admin: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..LOGIN_ATTEMPTS {
            assert!(limits.admit(attacker, now));
        }
        assert!(!limits.admit(attacker, now));
        assert!(!limits.admit("::ffff:127.0.0.2".parse().unwrap(), now));
        assert!(limits.admit(admin, now));
        assert!(limits.admit(attacker, now + LOGIN_WINDOW));
    }
    #[test]
    fn login_source_table_has_a_fixed_bound_without_evicting_active_buckets() {
        let now = Instant::now();
        let mut limits = LoginLimits::default();
        for n in 0..LOGIN_SOURCE_LIMIT as u32 {
            assert!(limits.admit(std::net::Ipv4Addr::from(n).into(), now));
        }
        let newcomer: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(!limits.admit(newcomer, now));
        assert_eq!(limits.sources.len(), LOGIN_SOURCE_LIMIT);
        assert!(limits.admit(std::net::Ipv4Addr::from(0).into(), now));
        assert!(limits.admit(newcomer, now + LOGIN_WINDOW));
        assert_eq!(limits.sources.len(), 1);
    }
    #[test]
    fn sessions_expire_and_have_a_fixed_bound() {
        let mut sessions = Sessions {
            values: HashMap::new(),
        };
        let now = Instant::now();
        for _ in 0..SESSION_LIMIT {
            sessions
                .create(
                    Duration::from_secs(60),
                    now,
                    rbac::Principal::bootstrap("test"),
                )
                .unwrap();
        }
        assert!(
            sessions
                .create(
                    Duration::from_secs(60),
                    now,
                    rbac::Principal::bootstrap("test")
                )
                .is_err()
        );
        sessions.prune(now + Duration::from_secs(60));
        assert!(sessions.values.is_empty());
        assert!(
            sessions
                .create(
                    Duration::from_secs(60),
                    now,
                    rbac::Principal::bootstrap("test")
                )
                .is_ok()
        );
    }
    #[test]
    fn origin_is_exact_not_a_substring() {
        assert!(same_origin(
            Some("https://mail.test:8443"),
            "https://mail.test:8443"
        ));
        for origin in [
            None,
            Some("null"),
            Some("https://mail.test:8443.evil.test"),
            Some("http://mail.test:8443"),
        ] {
            assert!(!same_origin(origin, "https://mail.test:8443"));
        }
    }
}
