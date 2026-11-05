use super::{model::*, service::Service};
use crate::error::{Result, ensure};
use pratique::http::server::{HttpConfig, Limits, Request, Response, Server, ServerBuilder};
use pratique::json_value::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
const COOKIE: &str = "__Host-workglen_security";
#[derive(Clone)]
struct Session {
    username: String,
    csrf: String,
    revision: u64,
    expires: i64,
}
struct State {
    service: Arc<Service>,
    sessions: Mutex<HashMap<String, Session>>,
    limits: Mutex<crate::web::LoginLimits>,
    dummy_hash: String,
}
fn cookie(r: &Request) -> Result<String> {
    let values: Vec<_> = r
        .header_all("cookie")
        .flat_map(|h| h.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .filter(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v)
        .collect();
    ensure!(
        values.len() == 1 && values[0].len() == 64,
        "Sign in to continue"
    );
    Ok(values[0].into())
}
impl State {
    fn session(&self, r: &Request) -> Result<(String, Session, Actor)> {
        let id = cookie(r)?;
        let current_time = now()?;
        let mut all = crate::resilience::reset_lock(&self.sessions);
        all.retain(|_, s| s.expires > current_time);
        let session = all
            .get(&id)
            .ok_or_else(|| crate::error!("Sign in to continue"))?
            .clone();
        drop(all);
        let a = self.service.local_actor(&session.username)?;
        ensure!(
            a.revision == session.revision,
            "Permissions changed; sign in again"
        );
        Ok((id, session, a))
    }
    fn handle(&self, r: &mut Request) -> Result<Response> {
        ensure!(
            r.authority()
                == self
                    .service
                    .config
                    .origin
                    .strip_prefix("https://")
                    .unwrap_or(""),
            "Unexpected host"
        );
        let path = r.path().to_string();
        if r.method() == "GET" {
            let asset = match path.as_str() {
                "/" => Some((
                    "text/html; charset=utf-8",
                    include_str!("../../web/security/index.html"),
                )),
                "/delivery.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../../web/security/delivery.js"),
                )),
                "/microsoft365.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../../web/security/microsoft365.js"),
                )),
                "/security.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../../web/security/security.js"),
                )),
                "/security.css" => Some((
                    "text/css; charset=utf-8",
                    include_str!("../../web/security/security.css"),
                )),
                _ => None,
            };
            if let Some((mime, body)) = asset {
                return Ok(Response::bytes(200, mime, body.as_bytes().to_vec()));
            }
            if path == "/api/session" {
                let (_, s, a) = self.session(r)?;
                return Ok(crate::web::response(
                    200,
                    json!({"csrf":s.csrf,"actor":a,"admin_origin":if a.mailbox.is_none() { self.service.config.admin_origin.as_deref() } else { None }}),
                ));
            }
            return Ok(crate::web::error(404, "Not found"));
        }
        ensure!(r.method() == "POST", "Method not allowed");
        ensure!(
            r.header_all("content-type").count() == 1
                && r.header("content-type")
                    .is_some_and(|s| s.split(';').next() == Some("application/json")),
            "Use application/json"
        );
        let raw = r.read_body(MAX_BODY)?;
        if path == "/replication" {
            ensure!(
                r.header_all("x-workglen-replication-signature").count() == 1,
                "Replication signature required"
            );
            return Ok(crate::web::response(
                200,
                super::cluster_transport::receive(
                    &self.service,
                    &raw,
                    r.header("x-workglen-replication-signature").unwrap_or(""),
                )?,
            ));
        }
        if path == "/control" {
            ensure!(
                r.header_all("x-workglen-signature").count() == 1,
                "Management signature required"
            );
            return Ok(crate::web::response(
                200,
                self.service
                    .control(&raw, r.header("x-workglen-signature").unwrap_or(""))?,
            ));
        }
        ensure!(
            r.header_all("origin").count() == 1
                && r.header("origin") == Some(self.service.config.origin.as_str()),
            "Origin verification failed"
        );
        let d: Value = pratique::json_value::from_slice(&raw)?;
        if path == "/api/login" {
            let name = s(&d, "username")?;
            let password = s(&d, "password")?;
            ensure!(name.len() <= 128 && password.len() <= 1024, "Invalid login");
            ensure!(
                self.limits.lock().unwrap_or_else(|e| e.into_inner()).admit(
                    r.connection()
                        .peer
                        .ok_or_else(|| crate::error!("Missing peer address"))?
                        .ip(),
                    Instant::now()
                ),
                "Too many sign-in attempts; retry in a minute"
            );
            let u = if key(name).is_ok() {
                self.service.db.get(&format!("identity/{name}"))?
            } else {
                None
            };
            let valid = crate::auth::verify(
                password,
                u.as_ref()
                    .and_then(|v| v["hash"].as_str())
                    .unwrap_or(&self.dummy_hash),
            );
            ensure!(
                valid && u.as_ref().is_some_and(|v| v["enabled"] == true),
                "Incorrect username or password"
            );
            let a = self.service.local_actor(name)?;
            let id = format!("{}{}", id(), id());
            let current_time = now()?;
            let session = Session {
                username: name.into(),
                csrf: super::model::id(),
                revision: a.revision,
                expires: current_time + 1800,
            };
            let mut all = crate::resilience::reset_lock(&self.sessions);
            all.retain(|_, s| s.expires > current_time);
            ensure!(all.len() < 256, "Session capacity reached");
            all.insert(id.clone(), session.clone());
            return Ok(
                crate::web::response(200, json!({"csrf":session.csrf,"actor":a,"admin_origin":if a.mailbox.is_none() { self.service.config.admin_origin.as_deref() } else { None }})).with_header(
                    "Set-Cookie",
                    &format!(
                        "{COOKIE}={id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800"
                    ),
                ),
            );
        }
        let (id, session, a) = self.session(r)?;
        use subtle::ConstantTimeEq;
        ensure!(
            r.header_all("x-csrf-token").count() == 1
                && bool::from(
                    session
                        .csrf
                        .as_bytes()
                        .ct_eq(r.header("x-csrf-token").unwrap_or("").as_bytes())
                ),
            "Session verification failed"
        );
        if path == "/api/logout" {
            crate::resilience::reset_lock(&self.sessions).remove(&id);
            return Ok(crate::web::response(200, json!({"ok":true})).with_header(
                "Set-Cookie",
                &format!("{COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"),
            ));
        }
        if path == "/api/command" {
            return Ok(crate::web::response(
                200,
                self.service
                    .command(&a, pratique::json_value::from_value(d)?)?,
            ));
        }
        Ok(crate::web::error(404, "Not found"))
    }
}
pub fn start(service: Arc<Service>) -> Result<Server> {
    let addr = std::net::SocketAddr::from(service.config.https_listen).to_string();
    let tls = Arc::new((*service.tls()?).clone().with_alpn(&["http/1.1"]));
    let state = State {
        service,
        sessions: Mutex::new(HashMap::new()),
        limits: Mutex::new(Default::default()),
        dummy_hash: crate::auth::hash(&format!("{}{}", id(), id()))?,
    };
    Ok(ServerBuilder::new(move |mut r: Request| {
        let reply = match state.handle(&mut r) {
            Ok(r) => r,
            Err(e) => {
                let text = e.to_string();
                crate::web::error(400, &text)
            }
        };
        crate::web::secure(reply)
    })
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
        max_connections: 16,
        max_connections_per_ip: 8,
        max_h2_handlers: 1,
        idle_timeout: Duration::from_secs(5),
        body_wait: Duration::from_secs(30),
        head_timeout: Duration::from_secs(5),
        ..Default::default()
    })
    .start()?)
}
