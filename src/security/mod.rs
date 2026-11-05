pub mod archive_zip;
pub mod cluster;
pub mod cluster_transport;
pub mod db;
pub mod model;
pub mod scan;
pub mod scan_worker;

pub mod service;

pub mod connectors;
pub mod destinations;
pub mod directory;
pub mod filesystem;
pub mod http;
pub mod learning;
pub mod transport;
pub mod worker;

pub mod xml;

/// Native security process profile within the Workglen executable.
pub fn cli(args: &[String]) -> crate::error::Result<()> {
    use crate::error::ensure;
    use std::io::Read;
    ensure!(
        args.len() >= 2,
        "usage: workglen security-init|security-serve|security-scan-worker|security-check|security-command|security-scan|security-audit-verify CONFIG [argument]; security-generate-key ABSOLUTE_PATH"
    );
    if args[0] == "security-generate-key" {
        ensure!(
            args.len() == 2,
            "usage: security-generate-key ABSOLUTE_PATH"
        );
        crate::encrypted_store::generate_key(std::path::Path::new(&args[1]))?;
        println!(
            "Created an owner-only storage key. Keep a separate protected backup; key contents are never printed."
        );
        return Ok(());
    }
    ensure!(
        matches!(
            args[0].as_str(),
            "security-init"
                | "security-serve"
                | "security-scan-worker"
                | "security-check"
                | "security-command"
                | "security-scan"
                | "security-audit-verify"
        ),
        "Unknown security command"
    );
    let config = model::Config::load(&args[1])?;
    if args[0] == "security-check" {
        crate::encrypted_store::Key::load(std::path::Path::new(&config.storage_key_file))?;
        if config.acme.is_none() {
            crate::net::server_config(&config.tls_cert, &config.tls_key)?;
        }
        println!(
            "Native configuration and storage key validated; manual TLS material checked, or ACME settings checked offline (issuance occurs during serve)"
        );
        return Ok(());
    }
    if args[0] == "security-scan" {
        let mut raw = Vec::new();
        std::io::stdin()
            .take((model::MAX_MESSAGE + 1) as u64)
            .read_to_end(&mut raw)?;
        let verdict = scan::evaluate(
            &raw,
            &model::rules(),
            &model::settings(),
            &pratique::json_value::json!({}),
        )?;
        println!("{}", pratique::json_value::to_string_pretty(&verdict)?);
        return Ok(());
    }
    if args[0] == "security-scan-worker" {
        ensure!(args.len() == 2, "usage: security-scan-worker CONFIG");
        return scan_worker::run(config);
    }
    let svc = service::Service::open(config)?;
    match args[0].as_str() {
        "security-init" => {
            ensure!(
                args.len() == 4,
                "usage: security-init CONFIG USERNAME PASSWORD_HASH_FILE"
            );
            svc.bootstrap(&args[2], &crate::config::secret(&args[3])?)?;
            println!("Initialized native security storage and administrator");
        }
        "security-serve" => {
            ensure!(
                svc.db.get("bootstrapped")?.is_some(),
                "Initialize security administrator first"
            );
            svc.start_tls()?;
            let _scan = scan_worker::start(svc.clone())?;
            let _http = http::start(svc.clone())?;
            let _replication = cluster_transport::start(&svc)?;
            let _smtp = transport::start(svc.clone())?;
            svc.work()?;
        }
        "security-command" => {
            let mut raw = Vec::new();
            std::io::stdin()
                .take((model::MAX_BODY + 1) as u64)
                .read_to_end(&mut raw)?;
            ensure!(raw.len() <= model::MAX_BODY, "Command too large");
            let c = pratique::json_value::from_slice(&raw)?;
            println!("{}", svc.command(&model::Actor::owner("local-console"), c)?);
        }
        "security-audit-verify" => println!("{}", svc.verify_audit()?),
        _ => crate::bail!("Unknown security command"),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
