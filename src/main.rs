use std::{
    fs,
    io::{self, Read},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
};
use workglen_mail::error::{Result, ensure};
use workglen_mail::{
    app::App,
    config::{Config, Mode, Role},
    store::Store,
};
fn main() {
    if let Err(e) = run() {
        eprintln!("workglen: {e:#}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.get(1).is_some_and(|s| s.starts_with("setup-")) {
        return workglen_mail::setup::cli(&a[1..]);
    }
    if a.get(1).map(String::as_str) == Some("hash-password") {
        let mut p = String::new();
        io::stdin().take(1026).read_to_string(&mut p)?;
        println!(
            "{}",
            workglen_mail::auth::hash(p.trim_end_matches(['\r', '\n']))?
        );
        return Ok(());
    }
    ensure!(
        a.len() >= 3,
        "usage: workglen <check|init|serve|admin-serve|dkim-generate|dkim-dns|witness|add-user|set-password|status|users|policy|queue|backup|backups|modules|module-enable|module-disable|demote-single|add-user-offline> CONFIG [address] [--bootstrap]"
    );
    if a[1] == "witness" {
        return workglen_mail::witness::serve(&a[2]);
    }
    if a[1].starts_with("security-") {
        return workglen_mail::security::cli(&a[1..]);
    }
    let c = Config::load(&a[2])?;
    if a[1] == "check" {
        ensure!(a.len() == 3, "usage: workglen check CONFIG");
        if c.acme.is_none() {
            workglen_mail::net::server_config(&c.tls_cert, &c.tls_key)?;
        }
        ensure!(
            workglen_mail::config::secret(&c.admin_token_file)?.len() >= 32,
            "Admin token must have at least 32 characters"
        );
        if let Some(web) = &c.web {
            let hash = workglen_mail::config::secret(&web.password_hash_file)?;
            argon2::PasswordHash::new(&hash)
                .map_err(|_| workglen_mail::error!("Invalid Admin password hash"))?;
        }
        if let Some(accounting) = &c.accounting {
            workglen_mail::accounting::db::connection_config(accounting)?;
        }
        println!(
            "Configuration and credentials validated offline; no database or CA connection attempted"
        );
        return Ok(());
    }
    if a[1] == "admin-serve" {
        ensure!(c.admin_only, "admin-serve requires admin_only=true");
    }
    if matches!(a[1].as_str(), "dkim-generate" | "dkim-dns") {
        ensure!(
            a.len() == 3,
            "usage: workglen dkim-generate|dkim-dns CONFIG"
        );
        let d = c
            .dkim
            .as_ref()
            .ok_or_else(|| workglen_mail::error!("[dkim] configuration required"))?;
        let record = if a[1] == "dkim-generate" {
            workglen_mail::dkim::generate(d, &c.domain)?
        } else {
            workglen_mail::dkim::Signer::load(d, &c.domain)?.dns_record()
        };
        print!("{record}");
        return Ok(());
    }
    if a[1] == "accounting-init" {
        let db = workglen_mail::accounting::Db::new(
            c.accounting
                .clone()
                .ok_or_else(|| workglen_mail::error!("[accounting] configuration required"))?,
            c.replication.cluster_id.clone(),
        )?;
        println!("Initialized accounting database {}", db.initialize()?);
        return Ok(());
    }
    if matches!(a[1].as_str(), "access-list" | "access-set" | "access-audit") {
        let access = if a[1] == "access-set" {
            let mut bytes = Vec::new();
            io::stdin().take(16385).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 16384, "Access request too large");
            Some(pratique::json_value::from_slice(&bytes)?)
        } else {
            None
        };
        let r = workglen_mail::admin::Request {
            command: a[1].clone(),
            access,
            accounting: None,
            user: None,
            password_hash: None,
            expected_revision: None,
        };
        println!("{}", workglen_mail::admin::request(&c, &r)?);
        return Ok(());
    }
    if a[1] == "accounting" {
        ensure!(
            a.len() == 4,
            "usage: workglen accounting CONFIG COMMAND.json (or - for stdin)"
        );
        let mut bytes = Vec::new();
        if a[3] == "-" {
            io::stdin()
                .take((workglen_mail::accounting::MAX_BODY + 1) as u64)
                .read_to_end(&mut bytes)?;
        } else {
            fs::File::open(&a[3])?
                .take((workglen_mail::accounting::MAX_BODY + 1) as u64)
                .read_to_end(&mut bytes)?;
        }
        ensure!(
            bytes.len() <= workglen_mail::accounting::MAX_BODY,
            "Accounting command exceeds 4 MiB"
        );
        let request = workglen_mail::admin::Request {
            command: "accounting".into(),
            accounting: Some(pratique::json_value::from_slice(&bytes)?),
            access: None,
            user: None,
            password_hash: None,
            expected_revision: None,
        };
        println!("{}", workglen_mail::admin::request(&c, &request)?);
        return Ok(());
    }
    if a[1] == "export-recovery" {
        ensure!(
            a.len() == 5,
            "usage: workglen export-recovery CONFIG DB_PATH NEW_OUTPUT_DIRECTORY"
        );
        let n = workglen_mail::backup::export(Path::new(&a[3]), Path::new(&a[4]))?;
        println!("Exported {n} messages");
        return Ok(());
    }

    fs::create_dir_all(&c.data_dir)?;
    fs::set_permissions(&c.data_dir, fs::Permissions::from_mode(0o700))?;
    if matches!(
        a[1].as_str(),
        "add-user"
            | "set-password"
            | "status"
            | "users"
            | "policy"
            | "queue"
            | "backup"
            | "backups"
            | "modules"
            | "module-enable"
            | "module-disable"
    ) {
        if a[1].starts_with("module-") {
            ensure!(
                a.len() == 4,
                "usage: workglen module-enable|module-disable CONFIG mail|accounts"
            );
        }
        let modifying = a[1] == "add-user" || a[1] == "set-password";
        let hash = if modifying {
            ensure!(a.len() >= 4, "address required");
            let mut p = String::new();
            io::stdin().take(1026).read_to_string(&mut p)?;
            Some(workglen_mail::auth::hash(p.trim_end_matches(['\r', '\n']))?)
        } else {
            None
        };
        let r = workglen_mail::admin::Request {
            command: a[1].clone(),
            accounting: None,
            access: None,
            user: a.get(3).cloned(),
            password_hash: hash,
            expected_revision: None,
        };
        print!("{}", workglen_mail::admin::request(&c, &r)?);
        return Ok(());
    }
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(Path::new(&c.data_dir).join("server.lock"))?;
    lock.try_lock()?;
    let dbpath = Path::new(&c.data_dir).join("mail.redb");
    let existed = dbpath.exists();
    let store = Store::open(&dbpath, &c.replication.cluster_id)?;
    match a[1].as_str() {
        "init" => {
            if c.admin_only && !existed {
                store.write(|_| {
                    Ok((
                        vec![workglen_mail::store::Op::json(
                            workglen_mail::modules::STATE_KEY.into(),
                            &workglen_mail::modules::State {
                                mail_enabled: false,
                                webmail_enabled: false,
                                ..Default::default()
                            },
                        )?],
                        (),
                    ))
                })?;
            }
            if a.iter().any(|s| s == "--bootstrap") {
                ensure!(
                    !existed && c.role == Role::Primary,
                    "bootstrap only on a fresh initial primary; initialize replacements without --bootstrap"
                );
                store.set_meta("ready", 1)?;
            }
            println!(
                "Initialized {} (eligible={})",
                c.data_dir,
                store.meta("ready")? == 1
            );
            Ok(())
        }
        "demote-single" => {
            ensure!(
                c.mode == Mode::Single,
                "use a single-mode configuration for the retained node"
            );
            ensure!(
                a.len() == 4 && a[3] == "--peer-fenced",
                "stop and prevent ALL other mail nodes from restarting, then pass --peer-fenced; this is an operator assertion, not automatic fencing"
            );
            ensure!(
                existed && store.meta("deployment")? == 2 && store.meta("ready")? == 1,
                "demotion requires an existing, seeded dual-mode database"
            );
            let backup = Path::new(&c.data_dir)
                .join(format!("backup-{}.redb", workglen_mail::store::random_id()));
            let partial = backup.with_extension("partial");
            workglen_mail::backup::create(&store, &c.replication.cluster_id, &partial)?;
            fs::rename(&partial, &backup)?;
            fs::File::open(&c.data_dir)?.sync_all()?;
            store.demote_single()?;
            println!(
                "Converted to single mode. Preserved accounts, messages, folders and queue.\nBackup: {}\nStart this node with the single-mode configuration. Keep every former peer fenced.",
                backup.display()
            );
            Ok(())
        }
        "add-user-offline" => {
            ensure!(
                a.len() == 4 && store.meta("term")? == 0,
                "offline provisioning only before first server startup; use add-user on active server"
            );
            let u = workglen_mail::config::address(&a[3])?;
            ensure!(u.rsplit_once('@').unwrap().1 == c.domain, "wrong domain");
            let mut p = String::new();
            io::stdin().take(1026).read_to_string(&mut p)?;
            store.add_user(
                &u,
                &workglen_mail::auth::hash(p.trim_end_matches(['\r', '\n']))?,
                c.limits.quota_bytes,
            )?;
            println!("Account created");
            Ok(())
        }
        "serve" | "admin-serve" => {
            let app = App::new(c, store)?;
            let _web = workglen_mail::web::start(app.clone())?;
            let _webmail = workglen_mail::webmail::start(app.clone())?;
            workglen_mail::accounting::feeds::start(app.clone());
            if app.config.admin_only {
                eprintln!(
                    "Workglen local Admin started; Mail/SMTP/IMAP and replication workers are not running"
                );
                return workglen_mail::admin::serve(app);
            }
            if app.config.mode == Mode::Dual {
                let x = app.clone();
                std::thread::spawn(move || workglen_mail::witness::renew_loop(x));
                let x = app.clone();
                std::thread::spawn(move || workglen_mail::replication::send_loop(x));
                let x = app.clone();
                std::thread::spawn(move || {
                    if let Err(e) = workglen_mail::replication::listen(x) {
                        eprintln!("replication listener failed: {e}");
                        std::process::exit(1);
                    }
                });
            }
            let x = app.clone();
            std::thread::spawn(move || workglen_mail::relay::run(x));
            let x = app.clone();
            std::thread::spawn(move || {
                if let Err(e) = workglen_mail::admin::serve(x) {
                    eprintln!("admin listener failed: {e}");
                    std::process::exit(1);
                }
            });
            listener(app.clone(), app.config.smtp_listen.clone(), 0)?;
            listener(app.clone(), app.config.submission_listen.clone(), 1)?;
            listener(app.clone(), app.config.imap_listen.clone(), 2)?;
            eprintln!(
                "Workglen Mail started; node={}; mode={:?}",
                app.config.node_id(),
                app.config.mode
            );
            loop {
                std::thread::park();
            }
        }
        _ => workglen_mail::bail!("unknown command"),
    }
}
fn listener(app: Arc<App>, address: String, kind: u8) -> Result<()> {
    let listener = TcpListener::bind(address)?;
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else {
                continue;
            };
            let Some(permit) = app.connections.enter() else {
                continue;
            };
            let app = app.clone();
            let _ = std::thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || {
                    let result = workglen_mail::resilience::boundary("mail session", move || {
                        let _permit = permit;
                        if kind == 2 {
                            workglen_mail::imap::serve(tcp, app)
                        } else {
                            workglen_mail::smtp::serve(tcp, app, kind == 1)
                        }
                    });
                    if let Err(e) = result {
                        eprintln!("session ended: {e}");
                    }
                });
        }
    });
    Ok(())
}
