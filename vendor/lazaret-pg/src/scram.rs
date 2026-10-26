use crate::{Error, Result, saslprep};
use pratique::{
    crypto::{
        hmac::Hmac,
        rand,
        sha2::{Hash, Sha256},
    },
    pem::{base64_decode_strict, base64_encode},
    zeroize::Zeroizing,
};
use std::collections::BTreeMap;

fn attributes(raw: &str) -> Result<BTreeMap<u8, &str>> {
    if raw.len() > 16384 || !raw.is_ascii() {
        return Err(Error::auth("invalid SCRAM message"));
    }
    let mut out = BTreeMap::new();
    for part in raw.split(',') {
        let b = part.as_bytes();
        if b.len() < 2
            || !b[0].is_ascii_alphabetic()
            || b[1] != b'='
            || out.insert(b[0], &part[2..]).is_some()
        {
            return Err(Error::auth("invalid or duplicate SCRAM attribute"));
        }
    }
    if out.contains_key(&b'm') {
        return Err(Error::auth("unsupported mandatory SCRAM extension"));
    }
    Ok(out)
}
fn decode(raw: &str) -> Result<Vec<u8>> {
    let value = base64_decode_strict(raw).ok_or_else(|| Error::auth("invalid SCRAM base64"))?;
    if base64_encode(&value) != raw {
        return Err(Error::auth("noncanonical SCRAM base64"));
    }
    Ok(value)
}
fn hmac(key: &[u8], body: &[u8]) -> Vec<u8> {
    Hmac::<Sha256>::mac(key, body)
}
pub(crate) fn salted(password: &[u8], salt: &[u8], iterations: u32) -> Result<Zeroizing<Vec<u8>>> {
    if !(1..=1_000_000).contains(&iterations) || salt.len() > 1024 {
        return Err(Error::auth("SCRAM work factor or salt exceeds limit"));
    }
    let mut initial = salt.to_vec();
    initial.extend_from_slice(&1u32.to_be_bytes());
    let mut u = Zeroizing::new(hmac(password, &initial));
    let mut result = Zeroizing::new(u.to_vec());
    for _ in 1..iterations {
        u = Zeroizing::new(hmac(password, &u));
        for (a, b) in result.iter_mut().zip(u.iter()) {
            *a ^= *b;
        }
    }
    Ok(result)
}
pub(crate) struct Scram {
    password: Zeroizing<Vec<u8>>,
    nonce: String,
    first: String,
    gs2: &'static str,
    binding: Vec<u8>,
    signature: Option<Zeroizing<Vec<u8>>>,
    pub verified: bool,
}
impl Scram {
    pub fn new(password: &[u8], binding: Option<&[u8]>, supports: bool) -> Result<Self> {
        let nonce =
            base64_encode(&rand::bytes::<18>().map_err(|_| Error::auth("OS entropy unavailable"))?);
        Self::with_nonce(password, binding, supports, &nonce, "")
    }
    fn with_nonce(
        password: &[u8],
        binding: Option<&[u8]>,
        supports: bool,
        nonce: &str,
        username: &str,
    ) -> Result<Self> {
        if password.len() > 16384 {
            return Err(Error::auth("password exceeds limit"));
        }
        let prepared = std::str::from_utf8(password)
            .ok()
            .and_then(saslprep::prepare)
            .map(|s| Zeroizing::new(s.into_bytes()));
        let password = prepared.unwrap_or_else(|| Zeroizing::new(password.to_vec()));
        let gs2 = if binding.is_some() {
            "p=tls-server-end-point,,"
        } else if supports {
            "y,,"
        } else {
            "n,,"
        };
        let username = username.replace('=', "=3D").replace(',', "=2C");
        Ok(Self {
            password,
            nonce: nonce.into(),
            first: format!("n={username},r={nonce}"),
            gs2,
            binding: binding.unwrap_or_default().to_vec(),
            signature: None,
            verified: false,
        })
    }
    pub fn uses_binding(&self) -> bool {
        self.gs2.starts_with("p=")
    }
    pub fn mechanism(&self) -> &'static str {
        if self.uses_binding() {
            "SCRAM-SHA-256-PLUS"
        } else {
            "SCRAM-SHA-256"
        }
    }
    pub fn first(&self) -> String {
        format!("{}{}", self.gs2, self.first)
    }
    pub fn final_message(&mut self, raw: &[u8]) -> Result<String> {
        if self.signature.is_some() || self.verified {
            return Err(Error::auth("duplicate SCRAM challenge"));
        }
        let raw = std::str::from_utf8(raw).map_err(|_| Error::auth("invalid SCRAM challenge"))?;
        let a = attributes(raw)?;
        let nonce = *a
            .get(&b'r')
            .ok_or_else(|| Error::auth("missing SCRAM nonce"))?;
        if !nonce.starts_with(&self.nonce)
            || nonce.len() <= self.nonce.len()
            || nonce.bytes().any(|b| !(0x21..=0x7e).contains(&b))
        {
            return Err(Error::auth("server nonce must extend client nonce"));
        }
        let raw_iterations = a
            .get(&b'i')
            .ok_or_else(|| Error::auth("missing SCRAM iterations"))?;
        if !raw_iterations.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::auth("invalid SCRAM iterations"));
        }
        let iterations = raw_iterations
            .parse()
            .map_err(|_| Error::auth("invalid SCRAM iterations"))?;
        let salt = decode(
            a.get(&b's')
                .ok_or_else(|| Error::auth("missing SCRAM salt"))?,
        )?;
        let salted = salted(&self.password, &salt, iterations)?;
        let client = Zeroizing::new(hmac(&salted, b"Client Key"));
        let stored = Zeroizing::new(Sha256::digest(&client));
        let mut cb = self.gs2.as_bytes().to_vec();
        cb.extend_from_slice(&self.binding);
        let final_bare = format!("c={},r={nonce}", base64_encode(&cb));
        let auth = format!("{},{raw},{final_bare}", self.first);
        let signature = Zeroizing::new(hmac(&stored, auth.as_bytes()));
        let proof = Zeroizing::new(
            client
                .iter()
                .zip(signature.iter())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>(),
        );
        let server_key = Zeroizing::new(hmac(&salted, b"Server Key"));
        self.signature = Some(Zeroizing::new(hmac(&server_key, auth.as_bytes())));
        Ok(format!("{final_bare},p={}", base64_encode(&proof)))
    }
    pub fn verify(&mut self, raw: &[u8]) -> Result<()> {
        if self.verified {
            return Err(Error::auth("duplicate SCRAM final message"));
        }
        let a = attributes(
            std::str::from_utf8(raw).map_err(|_| Error::auth("invalid SCRAM final message"))?,
        )?;
        if a.contains_key(&b'e') {
            return Err(Error::auth("server rejected SCRAM proof"));
        }
        let expected = self
            .signature
            .as_ref()
            .ok_or_else(|| Error::auth("SCRAM final before challenge"))?;
        let actual = decode(
            a.get(&b'v')
                .ok_or_else(|| Error::auth("missing SCRAM server proof"))?,
        )?;
        if !pratique::util::ct_eq(expected, &actual) {
            return Err(Error::auth("SCRAM server proof mismatch"));
        }
        self.verified = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("scram_vectors.rs");
    const NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
    const FIRST: &[u8] =
        b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    #[test]
    fn rfc7677_independent_vector() {
        let mut c = Scram::with_nonce(b"pencil", None, false, NONCE, "user").unwrap();
        assert_eq!(c.first(), format!("n,,n=user,r={NONCE}"));
        assert_eq!(
            c.final_message(FIRST).unwrap(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert!(
            c.verify(b"v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .is_err()
        );
        c.verify(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .unwrap();
        assert!(c.verified);
    }
    #[test]
    fn hostile_scram_rejected() {
        for raw in [
            "r=bad,s=AA==,i=4096",
            "r=rOprNGfwEbeRWgbNEkqOx,s=AA==,i=1000001",
            "r=rOprNGfwEbeRWgbNEkqOx,s=AA==,i=0",
            "r=rOprNGfwEbeRWgbNEkqOx,r=duplicate,s=AA==,i=1",
            "m=required,r=rOprNGfwEbeRWgbNEkqOx,s=AA==,i=1",
        ] {
            assert!(
                Scram::with_nonce(b"pencil", None, false, NONCE, "")
                    .unwrap()
                    .final_message(raw.as_bytes())
                    .is_err()
            );
        }
    }
}
