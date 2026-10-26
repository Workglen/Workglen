//! Mail-protocol signing keys backed exclusively by existing Pratique primitives.
pub use super::verify_dkim::{Algorithm, verify_bytes};
use crate::error::{Result, ensure};
use pratique::crypto::{
    ed25519_sign::Ed25519SigningKey,
    sha2::{Hash, Sha256},
};

pub enum SigningKey {
    Rsa(pratique::sign::SigningKey),
    Ed25519(Ed25519SigningKey),
}
impl SigningKey {
    pub fn rsa_der(der: &[u8]) -> Result<Self> {
        let key = pratique::sign::SigningKey::from_der(der)?;
        let pratique::x509::PublicKey::Rsa(public) =
            pratique::x509::parse_spki(&key.public_key_spki())?
        else {
            crate::bail!("RSA key required")
        };
        ensure!(
            (2048..=4096).contains(&public.bits()),
            "signing key must be RSA 2048..4096"
        );
        Ok(Self::Rsa(key))
    }
    pub fn ed25519(seed: &[u8; 32]) -> Self {
        Self::Ed25519(Ed25519SigningKey::from_seed(seed))
    }
    pub fn ed25519_checked(seed: &[u8; 32], public: &[u8]) -> Result<Self> {
        let key = Ed25519SigningKey::from_seed(seed);
        ensure!(key.public_key() == public, "Ed25519 public key mismatch");
        Ok(Self::Ed25519(key))
    }
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Rsa(_) => Algorithm::RsaSha256,
            Self::Ed25519(_) => Algorithm::Ed25519Sha256,
        }
    }
    pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Rsa(k) => k.sign_x509(input)?,
            Self::Ed25519(k) => k.sign(&Sha256::digest(input)).to_vec(),
        })
    }
    pub fn dns_record(&self) -> String {
        let (kind, public) = match self {
            Self::Rsa(k) => ("rsa", k.public_key_spki()),
            Self::Ed25519(k) => ("ed25519", k.public_key().to_vec()),
        };
        format!(
            "v=DKIM1;k={kind};p={}",
            crate::encoding::STANDARD.encode(public)
        )
    }
}
impl SigningKey {
    pub fn generate_ed25519_pkcs8() -> Result<Vec<u8>> {
        let key = Ed25519SigningKey::generate()?;
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend(key.seed());
        Ok(der)
    }
    pub fn ed25519_pkcs8(der: &[u8]) -> Result<Self> {
        use pratique::asn1::Der;
        let mut root = Der::new(der);
        let mut seq = root.sequence()?;
        root.finish()?;
        let version = seq.expect(0x02)?;
        ensure!(
            version.content == [0] || version.content == [1],
            "PKCS8 version"
        );
        let mut algorithm = seq.sequence()?;
        ensure!(
            algorithm.expect(0x06)?.content == [0x2b, 0x65, 0x70],
            "Ed25519 OID required"
        );
        algorithm.finish()?;
        let private = seq.expect(0x04)?;
        let mut inner = Der::new(private.content);
        let seed = inner.expect(0x04)?;
        inner.finish()?;
        let seed: &[u8; 32] = seed
            .content
            .try_into()
            .map_err(|_| crate::error!("Ed25519 seed length"))?;
        let key = Ed25519SigningKey::from_seed(seed);
        if seq.peek_tag() == Some(0xa0) {
            seq.expect(0xa0)?;
        }
        if seq.peek_tag() == Some(0x81) {
            let p = seq.expect(0x81)?;
            ensure!(
                version.content == [1]
                    && p.content.len() == 33
                    && p.content[0] == 0
                    && p.content[1..] == key.public_key()[..],
                "PKCS8 public key mismatch"
            );
        }
        seq.finish()?;
        Ok(Self::Ed25519(key))
    }
}
