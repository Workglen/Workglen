//! Outbound RFC 6376 signing through first-party canonicalization and Pratique RSA.
use crate::config::Dkim;
use crate::encoding::STANDARD;
use crate::error::{Result, ensure};
use pratique::{
    sign::SigningKey as NativeKey,
    x509::{PublicKey, parse_spki},
    zeroize::Zeroizing,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

pub struct Signer {
    key: NativeKey,
    domain: String,
    selector: String,
    name: String,
    public: String,
}
impl Signer {
    pub fn load(config: &Dkim, domain: &str) -> Result<Self> {
        let file = File::open(&config.key_file)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.len() <= 32768,
            "DKIM key must be a regular file <=32 KiB"
        );
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "DKIM key permissions must be 0600 or stricter"
        );
        let mut pem = Zeroizing::new(Vec::new());
        file.take(32769).read_to_end(&mut pem)?;
        ensure!(pem.len() <= 32768, "DKIM key exceeds 32 KiB");
        let key = NativeKey::from_pem(std::str::from_utf8(&pem)?)?;
        let spki = key.public_key_spki();
        let PublicKey::Rsa(rsa) = parse_spki(&spki)? else {
            crate::bail!("DKIM requires an RSA key");
        };
        ensure!(
            (2048..=4096).contains(&rsa.bits()),
            "DKIM requires a 2048..4096-bit RSA key"
        );
        let public = STANDARD.encode(&spki);
        Ok(Self {
            key,
            domain: domain.to_ascii_lowercase(),
            selector: config.selector.to_ascii_lowercase(),
            name: format!(
                "{}._domainkey.{}",
                config.selector.to_ascii_lowercase(),
                domain.to_ascii_lowercase()
            ),
            public,
        })
    }
    pub fn sign(&self, raw: &[u8]) -> Result<Vec<u8>> {
        crate::mailauth::dkim::sign(raw, &self.domain, &self.selector, &self.key)
    }

    pub fn dns_record(&self) -> String {
        let value = format!("v=DKIM1; k=rsa; p={}", self.public);
        let chunks = value
            .as_bytes()
            .chunks(200)
            .map(|c| format!("  \"{}\"", std::str::from_utf8(c).unwrap()))
            .collect::<Vec<_>>()
            .join("\n");
        format!("{} 300 IN TXT (\n{}\n)\n", self.name, chunks)
    }
}

pub fn generate(config: &Dkim, domain: &str) -> Result<String> {
    // Exclusive creation protects an existing selector's key from replacement.
    let der = pratique::crypto::rsa_generate::generate_pkcs8()?;
    let pem = pratique::sign::private_key_pem(&der);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&config.key_file)?;
    let written = file.write_all(&pem).and_then(|_| file.sync_all());
    written?;
    Ok(Signer::load(config, domain)?.dns_record())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_protection_and_signature_shape() {
        let dir = crate::test_support::tempdir().unwrap();
        let c = Dkim {
            selector: "mail2026".into(),
            key_file: dir.path().join("dkim.key").to_str().unwrap().into(),
        };
        let record = generate(&c, "example.test").unwrap();
        assert!(record.starts_with("mail2026._domainkey.example.test"));
        assert!(generate(&c, "example.test").is_err());
        let signer = Signer::load(&c, "example.test").unwrap();
        let body = b"From: alice@example.test\r\nSubject: Test\r\n\r\nMessage\r\n";
        let signed = signer.sign(body).unwrap();
        assert!(signed.ends_with(body));
        let header = String::from_utf8(signed[..signed.len() - body.len()].to_vec()).unwrap();
        assert!(header.contains("rsa-sha256"));
        assert!(header.contains("relaxed/relaxed"));
        assert!(!header.contains(" l="));
        assert_eq!(header.matches("From").count(), 2);
        std::fs::set_permissions(&c.key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Signer::load(&c, "example.test").is_err());
    }
    #[test]
    fn weak_keys_are_rejected() {
        let dir = crate::test_support::tempdir().unwrap();
        let path = dir.path().join("weak.key");
        // A mathematically valid toy RSA key (p=61, q=53, e=17), far below
        // the minimum. Public test integers, never a deployed/private fixture.
        let fields = [0u64, 3233, 17, 2753, 61, 53, 53, 49, 38]
            .map(|n| pratique::asn1::write::integer(&n.to_be_bytes()));
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        let der = pratique::asn1::write::sequence(&refs);
        let pem = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
            STANDARD.encode(der)
        );
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        f.write_all(pem.as_bytes()).unwrap();
        assert!(
            Signer::load(
                &Dkim {
                    selector: "old".into(),
                    key_file: path.to_str().unwrap().into()
                },
                "example.test"
            )
            .is_err()
        );
    }
}
