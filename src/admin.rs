use crate::error::{Result, ensure};
use crate::{
    app::App,
    config::{QueueItem, User},
    store::{self, Op},
};
use std::{sync::Arc, time::Duration};
pub struct Request {
    pub command: String,
    pub accounting: Option<crate::accounting::model::Command>,
    pub access: Option<crate::rbac::Change>,
    pub user: Option<String>,
    pub password_hash: Option<String>,
    pub expected_revision: Option<u64>,
}
pratique::data_encode!(Request {
    command,
    accounting,
    access,
    user,
    password_hash,
    expected_revision
});
pratique::data_decode!(Request, deny_unknown=false, { command, accounting = Default::default(), access = Default::default(), user, password_hash, expected_revision = Default::default() });

pub fn request(c: &crate::config::Config, r: &Request) -> Result<String> {
    let mut w = crate::net::Wire::connect(c.admin_listen, &c.hostname, &c.tls_cert)?;
    w.deadline.set(Duration::from_secs(30));
    w.send(&format!(
        "{} {}\r\n",
        crate::config::secret(&c.admin_token_file)?,
        pratique::json_value::to_string(r)?
    ))?;
    let mut length = [0; 4];
    w.exact(&mut length)?;
    let len = u32::from_be_bytes(length) as usize;
    ensure!(len <= 1024 * 1024, "admin response too large");
    let mut bytes = vec![0; len];
    w.exact(&mut bytes)?;
    let result = String::from_utf8(bytes)?;
    ensure!(!result.starts_with("ERROR"), "{}", result.trim());
    Ok(result)
}
pub fn serve(app: Arc<App>) -> Result<()> {
    let listener = std::net::TcpListener::bind(app.config.admin_listen)?;
    let token = crate::config::secret(&app.config.admin_token_file)?;
    ensure!(token.len() >= 32, "admin token too short");
    for conn in listener.incoming() {
        let conn = match conn {
            Ok(c) => c,
            Err(_) => continue,
        };
        let result = crate::resilience::boundary("admin session", || {
            let mut stream = crate::net::Wire::accept(conn, &app.tls)?;
            stream.deadline.set(Duration::from_secs(30));
            let line = stream.text(crate::accounting::MAX_BODY + 2048)?;
            let (provided, line) = line
                .split_once(' ')
                .ok_or_else(|| crate::error!("bad admin request"))?;
            ensure!(
                crate::witness::same(provided, &token),
                "unauthorized admin request"
            );
            let r: Request = pratique::json_value::from_str(line)?;
            let text = match execute(&app, r) {
                Ok(r) => r,
                Err(e) => format!("ERROR {e}\n"),
            };
            stream.bytes(&(text.len() as u32).to_be_bytes())?;
            stream.bytes(text.as_bytes())
        });
        if let Err(e) = result {
            eprintln!("admin session: {e}");
        }
    }
    Ok(())
}

pub fn execute(app: &App, r: Request) -> Result<String> {
    if matches!(
        r.command.as_str(),
        "users" | "policy" | "queue" | "add-user" | "set-password"
    ) {
        ensure!(
            app.mail_enabled(),
            "Mail is disabled. Enable it in Modules or with the CLI."
        );
    }
    match r.command.as_str() {
        "access-list" => Ok(crate::rbac::list(app)?.to_string()),
        "access-audit" => Ok(crate::rbac::audit(app)?.to_string()),
        "access-set" => {
            let _guard = app.authorization.write().unwrap_or_else(|e| e.into_inner());
            Ok(crate::rbac::change(
                app,
                "local-owner",
                r.access
                    .ok_or_else(|| crate::error!("Missing access change"))?,
            )?
            .to_string())
        }
        "accounting" => Ok(pratique::json_value::to_string(
            &crate::accounting::execute(
                app,
                r.accounting
                    .ok_or_else(|| crate::error!("Missing accounting command"))?,
                "cli-admin",
            )?,
        )?),
        "modules" => Ok(pratique::json_value::to_string(&crate::modules::catalog(
            app,
        )?)?),
        "module-enable" | "module-disable" => {
            let state = crate::modules::change(
                app,
                r.user.as_deref().unwrap_or(""),
                r.command == "module-enable",
                r.expected_revision,
            )?;
            Ok(pratique::json_value::to_string(&state)?)
        }
        "status" => {
            let s = app.read_store()?;
            Ok(pratique::json_value::to_string_pretty(
                &pratique::json_value::json!({"admin_only":app.config.admin_only,"primary":app.primary(),"term":s.meta("term")?,"sequence":s.seq()?,"ready":s.meta("ready")?==1,"node":app.config.node_id(),"mode":app.config.mode,"hostname":app.config.hostname,"domain":app.config.domain,"peak_rss_kib":peak_rss_kib(),"replication":*app.replication_status.lock().unwrap_or_else(|e| e.into_inner()),"modules":crate::modules::state(&s)?,"limits":app.config.limits,"delivery":crate::relay::status(app),"tls":app.certificates.status()}),
            )?)
        }
        "users" => Ok(pratique::json_value::to_string(&users(app)?)?),
        "policy" => Ok(pratique::json_value::to_string(&app.config.policy)?),
        "backups" => Ok(pratique::json_value::to_string(&backups(app)?)?),
        "backup" => {
            let _backup = crate::resilience::try_lock(&app.backups)
                .map_err(|_| crate::error!("backup already in progress"))?;
            let path = std::path::Path::new(&app.config.data_dir)
                .join(format!("backup-{}.redb", store::random_id()));
            let partial = path.with_extension("partial");
            crate::backup::create(
                &*app.read_store()?,
                &app.config.replication.cluster_id,
                &partial,
            )?;
            std::fs::rename(&partial, &path)?;
            std::fs::File::open(&app.config.data_dir)?.sync_all()?;
            Ok(path.display().to_string())
        }
        "queue" => Ok(pratique::json_value::to_string_pretty(
            &*app.read_store()?.list::<QueueItem>("queue/")?,
        )?),
        "add-user" | "set-password" => {
            let u = crate::config::address(r.user.as_deref().unwrap_or(""))?;
            ensure!(
                u.rsplit_once('@').unwrap().1 == app.config.domain,
                "account must belong to configured domain"
            );
            let hash = r
                .password_hash
                .ok_or_else(|| crate::error!("missing password hash"))?;
            argon2::PasswordHash::new(&hash).map_err(|_| crate::error!("invalid password hash"))?;
            app.mail_commit(|t| {
                let key = format!("user/{u}");
                let old: Option<User> = store::json(t, &key)?;
                let mut ops = Vec::new();
                if r.command == "add-user" {
                    ensure!(old.is_none(), "account exists");
                    for f in ["INBOX", "Sent", "Drafts", "Trash", "Junk"] {
                        ops.push(Op::json(store::folder_key(&u, f), &store::fresh_folder())?);
                    }
                } else {
                    ensure!(old.is_some(), "account missing");
                }
                ops.push(Op::json(
                    key,
                    &User {
                        password_hash: hash,
                        quota: old
                            .map(|u| u.quota)
                            .unwrap_or(app.config.limits.quota_bytes),
                    },
                )?);
                Ok((ops, ()))
            })?;
            Ok("OK\n".into())
        }
        _ => crate::bail!("unknown admin command"),
    }
}

fn peak_rss_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|l| l.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Deliberately omit credentials. Count metadata in a single consistent read
/// transaction without loading message bodies into the dashboard process.
pub struct AccountSummary {
    pub email: String,
    pub quota: u64,
    pub used_bytes: u64,
    pub messages: u64,
    pub folders: u64,
}
pratique::data_encode!(AccountSummary {
    email,
    quota,
    used_bytes,
    messages,
    folders
});

pub fn users(app: &App) -> Result<Vec<AccountSummary>> {
    use redb::ReadableDatabase;
    let store = app.read_store()?;
    let tx = store.db.begin_read()?;
    let t = tx.open_table(store::KV)?;
    let mut out = std::collections::BTreeMap::new();
    for row in t.range("user/"..)? {
        let (k, v) = row?;
        let Some(email) = k.value().strip_prefix("user/") else {
            break;
        };
        let user: User = pratique::json_value::from_slice(v.value())?;
        out.insert(
            email.to_string(),
            AccountSummary {
                email: email.into(),
                quota: user.quota,
                used_bytes: 0,
                messages: 0,
                folders: 0,
            },
        );
    }
    for (prefix, mail) in [("mail/", true), ("folder/", false)] {
        for row in t.range(prefix..)? {
            let (k, v) = row?;
            let Some(rest) = k.value().strip_prefix(prefix) else {
                break;
            };
            // Email local parts may contain '/', so find the first '@' domain boundary.
            let Some(at) = rest.find('@') else { continue };
            let Some(slash) = rest[at..].find('/') else {
                continue;
            };
            if let Some(u) = out.get_mut(&rest[..at + slash]) {
                if mail {
                    let m: crate::config::Message = pratique::json_value::from_slice(v.value())?;
                    u.messages += 1;
                    u.used_bytes += m.size as u64;
                } else {
                    u.folders += 1;
                }
            }
        }
    }
    Ok(out.into_values().collect())
}
pub fn backups(app: &App) -> Result<Vec<pratique::json_value::Value>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&app.config.data_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("backup-") && name.ends_with(".redb") && entry.file_type()?.is_file() {
            let m = entry.metadata()?;
            out.push(pratique::json_value::json!({"name": name, "bytes": m.len(), "created": m.modified()?.duration_since(std::time::UNIX_EPOCH)?.as_secs()}));
        }
    }
    out.sort_by_key(|v| std::cmp::Reverse(v["created"].as_u64().unwrap_or(0)));
    Ok(out)
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    #[test]
    fn record_contract_request() {
        crate::data_contracts::check::<Request>(
            "src_admin_Request",
            &[
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",null,null,null,null,null]"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":null,"unexpected_field":1}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":null}"###,
                r###"{"command":false,"accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":null,"command":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","access":null,"user":null,"password_hash":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":"wrong","access":null,"user":null,"password_hash":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":null,"accounting":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":{"action":"sample-\u00e9\ud83d\ude00","book_id":null,"data":{"z":[1,true,null],"a":"sample"}},"access":null,"user":null,"password_hash":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"user":null,"password_hash":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":"wrong","user":null,"password_hash":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":null,"access":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null},"user":null,"password_hash":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"password_hash":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":"wrong","password_hash":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":null,"user":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":"sample-\u00e9\ud83d\ude00","password_hash":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":"wrong","expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":null,"password_hash":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":"sample-\u00e9\ud83d\ude00","expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":"wrong"}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":null,"expected_revision":null}"###,
                r###"{"command":"sample-\u00e9\ud83d\ude00","accounting":null,"access":null,"user":null,"password_hash":null,"expected_revision":18446744073709551615}"###,
            ],
        );
    }
}
