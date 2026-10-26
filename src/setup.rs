//! Native provisioning helpers. All key material is local; existing files are refused.
use crate::error::{Result, ensure};
use crate::encoding::STANDARD;
use pratique::{
    asn1::write as der,
    crypto::{
        ecdsa::Curve,
        rand,
        sha2::{Hash, Sha256},
    },
    sign::SigningKey,
    tls::certs::CertifiedKey,
    x509::{Certificate, TrustStore},
    zeroize::Zeroizing,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

fn pem(label: &str, bytes: &[u8]) -> String {
    let b64 = STANDARD.encode(bytes);
    let lines = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n")
}
fn name(cn: &str) -> Vec<u8> {
    der::sequence(&[&der::set(&[&der::sequence(&[
        &der::oid_str("2.5.4.3"),
        &der::utf8_string(cn),
    ])])])
}
fn extension(oid: &str, critical: bool, bytes: &[u8]) -> Vec<u8> {
    let mut body = der::oid_str(oid);
    if critical {
        body.extend(der::boolean(true));
    }
    body.extend(der::octet_string(bytes));
    der::tlv(0x30, &body)
}
fn certificate(key: &SigningKey, issuer: &SigningKey, ca: bool, now: i64) -> Result<Vec<u8>> {
    const CA: &str = "Workglen Local Admin CA";
    let public = key.public_key_spki();
    let alg = issuer.x509_algorithm();
    let mut serial = [0u8; 16];
    rand::fill(&mut serial)?;
    serial[0] |= 1;
    let time = |t| -> Result<Vec<u8>> {
        let date = crate::datetime::DateTime::from_timestamp(t, 0)
            .ok_or_else(|| crate::error!("Invalid certificate date"))?;
        Ok(der::tlv(
            0x18,
            date.format("%Y%m%d%H%M%SZ").to_string().as_bytes(),
        ))
    };
    let constraints = if ca {
        der::sequence(&[&der::boolean(true), &der::integer(&[0])])
    } else {
        der::sequence(&[])
    };
    let mut extensions = extension("2.5.29.19", true, &constraints);
    extensions.extend(extension(
        "2.5.29.15",
        true,
        &if ca {
            der::bit_string(1, &[6])
        } else {
            der::bit_string(7, &[128])
        },
    ));
    extensions.extend(extension(
        "2.5.29.14",
        false,
        &der::octet_string(&Sha256::digest(&public)[..20]),
    ));
    extensions.extend(extension(
        "2.5.29.35",
        false,
        &der::sequence(&[&der::context(
            0,
            false,
            &Sha256::digest(&issuer.public_key_spki())[..20],
        )]),
    ));
    if !ca {
        extensions.extend(extension(
            "2.5.29.37",
            false,
            &der::sequence(&[&der::oid_str("1.3.6.1.5.5.7.3.1")]),
        ));
        let ip6 = std::net::Ipv6Addr::LOCALHOST.octets();
        extensions.extend(extension(
            "2.5.29.17",
            false,
            &der::sequence(&[
                &der::context(2, false, b"localhost"),
                &der::context(7, false, &[127, 0, 0, 1]),
                &der::context(7, false, &ip6),
            ]),
        ));
    }
    let tbs = der::sequence(&[
        &der::context(0, true, &der::integer(&[2])),
        &der::integer(&serial),
        &alg,
        &name(CA),
        &der::sequence(&[
            &time(now - 300)?,
            &time(now + if ca { 1825 * 86400 } else { 365 * 86400 })?,
        ]),
        &name(if ca { CA } else { "localhost" }),
        &public,
        &der::context(3, true, &der::tlv(0x30, &extensions)),
    ]);
    Ok(der::sequence(&[
        &tbs,
        &alg,
        &der::bit_string(0, &issuer.sign_x509(&tbs)?),
    ]))
}
fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}
pub fn local_tls(directory: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(directory)?;
    ensure!(
        meta.is_dir() && meta.mode() & 0o077 == 0,
        "TLS destination must be a private, real directory"
    );
    let names = [
        "local-ca.pem",
        "local-ca-key.pem",
        "local-leaf.pem",
        "local-cert.pem",
        "local-key.pem",
    ];
    for file in names {
        ensure!(
            fs::symlink_metadata(directory.join(file))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "TLS output already exists or cannot be inspected"
        );
    }
    let ca = SigningKey::generate_ecdsa(Curve::P256)?;
    let key = SigningKey::generate_ecdsa(Curve::P256)?;
    let now = crate::datetime::Utc::now().timestamp();
    let root = certificate(&ca, &ca, true, now)?;
    let leaf = certificate(&key, &ca, false, now)?;
    let mut trust = TrustStore::empty();
    trust.add_der(&root)?;
    for host in ["localhost", "127.0.0.1", "::1"] {
        trust.verify_server_chain(&[leaf.clone(), root.clone()], host, now)?;
    }
    let ca_pem = pem("CERTIFICATE", &root);
    let leaf_pem = pem("CERTIFICATE", &leaf);
    let chain = format!("{leaf_pem}{ca_pem}");
    let ca_key = ca.to_pkcs8_pem()?;
    let leaf_key = key.to_pkcs8_pem()?;
    CertifiedKey::from_pem(&chain, std::str::from_utf8(&leaf_key)?)?;
    for (file, data) in [
        (names[0], ca_pem.as_bytes()),
        (names[1], &ca_key),
        (names[2], leaf_pem.as_bytes()),
        (names[3], chain.as_bytes()),
        (names[4], &leaf_key),
    ] {
        write_new(&directory.join(file), data)?;
    }
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
pub fn check_tls(cert: &str, key: &str, host: &str) -> Result<()> {
    // Shared loader checks certificate/key matching and private-key permissions.
    crate::net::server_config(cert, key)?;
    let chain = fs::read_to_string(cert)?;
    let blocks = pratique::pem::parse(&chain);
    let first = blocks
        .iter()
        .find(|p| p.label == "CERTIFICATE")
        .ok_or_else(|| crate::error!("Missing certificate"))?;
    let leaf = Certificate::from_der(&first.data)?;
    let now = crate::datetime::Utc::now().timestamp();
    ensure!(
        leaf.not_before <= now && now < leaf.not_after && leaf.matches_hostname(host),
        "Certificate is expired, not yet valid or does not match gateway hostname"
    );
    Ok(())
}
pub fn cli(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("setup-local-tls") => {
            ensure!(args.len() == 2, "usage: setup-local-tls PRIVATE_DIRECTORY");
            local_tls(Path::new(&args[1]))?;
        }
        Some("setup-check-tls") => {
            ensure!(args.len() == 4, "usage: setup-check-tls CERT KEY HOST");
            check_tls(&args[1], &args[2], &args[3])?;
        }
        Some("setup-random") => {
            ensure!(args.len() == 3, "usage: setup-random hex|base64 BYTES");
            let n: usize = args[2].parse()?;
            ensure!((16..=64).contains(&n), "Random length must be 16..64 bytes");
            let mut bytes = Zeroizing::new(vec![0u8; n]);
            rand::fill(&mut bytes)?;
            let encoded = Zeroizing::new(match args[1].as_str() {
                "hex" => bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    .into_bytes(),
                "base64" => STANDARD.encode(&*bytes).into_bytes(),
                _ => crate::bail!("Use hex or base64 encoding"),
            });
            let mut out = std::io::stdout().lock();
            out.write_all(&encoded)?;
            out.write_all(b"\n")?;
        }
        _ => crate::bail!("Unknown setup command"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn local_chain_is_verified_private_and_never_replaced() {
        let dir = crate::test_support::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        local_tls(dir.path()).unwrap();
        let cert = dir.path().join("local-cert.pem");
        let key = dir.path().join("local-key.pem");
        check_tls(cert.to_str().unwrap(), key.to_str().unwrap(), "localhost").unwrap();
        assert!(
            check_tls(
                cert.to_str().unwrap(),
                key.to_str().unwrap(),
                "other.example"
            )
            .is_err()
        );
        let before = fs::read(&key).unwrap();
        assert!(local_tls(dir.path()).is_err());
        assert_eq!(before, fs::read(&key).unwrap());
        assert_eq!(fs::metadata(key).unwrap().mode() & 0o777, 0o600);
    }
}
