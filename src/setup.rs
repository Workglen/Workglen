//! Native provisioning helpers. All key material is local; existing files are refused.
use crate::encoding::STANDARD;
use crate::error::{Result, ensure};
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
fn local_name_constraints() -> Vec<u8> {
    let mut ip4 = Vec::from([127, 0, 0, 1]);
    ip4.extend([255; 4]);
    let mut ip6 = Vec::from(std::net::Ipv6Addr::LOCALHOST.octets());
    ip6.extend([255; 16]);
    let permitted = [
        der::sequence(&[&der::context(2, false, b"localhost")]),
        der::sequence(&[&der::context(7, false, &ip4)]),
        der::sequence(&[&der::context(7, false, &ip6)]),
    ];
    // A DNS constraint for "localhost" also covers subdomains under RFC 5280.
    // Excluding ".localhost" narrows this private trust anchor to the exact name.
    let excluded = der::sequence(&[&der::context(2, false, b".localhost")]);
    der::sequence(&[
        &der::context(0, true, &permitted.concat()),
        &der::context(1, true, &excluded),
    ])
}
fn certificate(
    key: &SigningKey,
    issuer: &SigningKey,
    ca: bool,
    now: i64,
    dns_names: &[&str],
    ip_addrs: &[std::net::IpAddr],
) -> Result<Vec<u8>> {
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
    if ca {
        extensions.extend(extension("2.5.29.30", true, &local_name_constraints()));
    }
    if !ca {
        extensions.extend(extension(
            "2.5.29.37",
            false,
            &der::sequence(&[&der::oid_str("1.3.6.1.5.5.7.3.1")]),
        ));
        let mut names = dns_names
            .iter()
            .map(|name| der::context(2, false, name.as_bytes()))
            .collect::<Vec<_>>();
        names.extend(ip_addrs.iter().map(|ip| {
            let bytes = match ip {
                std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            der::context(7, false, &bytes)
        }));
        extensions.extend(extension(
            "2.5.29.17",
            false,
            &der::sequence(&names.iter().map(Vec::as_slice).collect::<Vec<_>>()),
        ));
    }
    const LIFETIME: i64 = 365 * 86400;
    let not_before = now - 300;
    let tbs = der::sequence(&[
        &der::context(0, true, &der::integer(&[2])),
        &der::integer(&serial),
        &alg,
        &name(CA),
        &der::sequence(&[&time(not_before)?, &time(not_before + LIFETIME)?]),
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
fn local_ca(now: i64) -> Result<(SigningKey, Vec<u8>)> {
    let ca = SigningKey::generate_ecdsa(Curve::P256)?;
    let root = certificate(&ca, &ca, true, now, &[], &[])?;
    Ok((ca, root))
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
    for file in [
        "local-ca.pem",
        // Refuse even a partial legacy directory containing the retired CA key.
        "local-ca-key.pem",
        "local-leaf.pem",
        "local-cert.pem",
        "local-key.pem",
    ] {
        ensure!(
            fs::symlink_metadata(directory.join(file))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "TLS output already exists or cannot be inspected"
        );
    }
    let key = SigningKey::generate_ecdsa(Curve::P256)?;
    let now = crate::datetime::Utc::now()?.timestamp();
    let (ca, root) = local_ca(now)?;
    let leaf = certificate(
        &key,
        &ca,
        false,
        now,
        &["localhost"],
        &[
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ],
    )?;
    // The signing key's secret scalar is zeroizing memory. Drop the only CA
    // handle before writing any output; no CA private key is ever serialized.
    drop(ca);
    let mut trust = TrustStore::empty();
    trust.add_der(&root)?;
    for host in ["localhost", "127.0.0.1", "::1"] {
        trust.verify_server_chain(&[leaf.clone(), root.clone()], host, now)?;
    }
    let ca_pem = pem("CERTIFICATE", &root);
    let leaf_pem = pem("CERTIFICATE", &leaf);
    let chain = format!("{leaf_pem}{ca_pem}");
    let leaf_key = key.to_pkcs8_pem()?;
    CertifiedKey::from_pem(&chain, std::str::from_utf8(&leaf_key)?)?;
    for (file, data) in [
        ("local-ca.pem", ca_pem.as_bytes()),
        ("local-leaf.pem", leaf_pem.as_bytes()),
        ("local-cert.pem", chain.as_bytes()),
        ("local-key.pem", &leaf_key),
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
    let now = crate::datetime::Utc::now()?.timestamp();
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
        assert!(!dir.path().join("local-ca-key.pem").exists());
        let private_keys = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path();
                fs::read(&path)
                    .unwrap()
                    .windows(b"PRIVATE KEY".len())
                    .any(|window| window == b"PRIVATE KEY")
                    .then(|| path.file_name().unwrap().to_string_lossy().into_owned())
            })
            .collect::<Vec<_>>();
        assert_eq!(private_keys, ["local-key.pem"]);
    }

    #[test]
    fn local_ca_is_one_year_and_enforces_exact_loopback_names() {
        const YEAR: i64 = 365 * 86400;
        let now = 1_800_000_000;
        let (ca, root) = local_ca(now).unwrap();
        let parsed = Certificate::from_der(&root).unwrap();
        assert!(parsed.not_after - parsed.not_before <= YEAR);
        let constraint = parsed
            .extensions()
            .iter()
            .find(|extension| extension.oid_string() == "2.5.29.30")
            .expect("nameConstraints extension");
        assert!(constraint.critical);

        let mut trust = TrustStore::empty();
        trust.add_der(&root).unwrap();
        let issue = |dns: &[&str], ips: &[std::net::IpAddr]| {
            let key = SigningKey::generate_ecdsa(Curve::P256).unwrap();
            certificate(&key, &ca, false, now, dns, ips).unwrap()
        };
        for (leaf, host) in [
            (issue(&["localhost"], &[]), "localhost"),
            (
                issue(&[], &[std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]),
                "127.0.0.1",
            ),
            (
                issue(&[], &[std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)]),
                "::1",
            ),
        ] {
            trust
                .verify_server_chain(&[leaf, root.clone()], host, now)
                .unwrap();
        }
        for (leaf, host) in [
            (issue(&["evil.example"], &[]), "evil.example"),
            (
                issue(
                    &[],
                    &[std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))],
                ),
                "10.0.0.1",
            ),
            (issue(&["sub.localhost"], &[]), "sub.localhost"),
        ] {
            assert!(
                trust
                    .verify_server_chain(&[leaf, root.clone()], host, now)
                    .is_err()
            );
        }
    }
}
