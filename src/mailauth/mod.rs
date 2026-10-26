//! First-party mail authentication components. Cryptography stays in Pratique.
pub mod dkim;

use std::future::Future;
pub trait Dns {
    fn lookup(
        &self,
        name: &str,
        kind: workglen_dns::RecordType,
    ) -> impl Future<Output = workglen_dns::Result<Vec<workglen_dns::RData>>>;
}
impl Dns for workglen_dns::Resolver {
    async fn lookup(
        &self,
        name: &str,
        kind: workglen_dns::RecordType,
    ) -> workglen_dns::Result<Vec<workglen_dns::RData>> {
        Ok(self
            .lookup(name, kind)
            .await?
            .answers()
            .iter()
            .map(|r| r.data.clone())
            .collect())
    }
}
#[cfg(feature = "arc")]
pub mod arc;
pub mod crypto;
pub mod dkim2;
pub mod dmarc;
pub mod spf;
pub mod verify_dkim;

/// The native MIME parser remains the authority for RFC 5322 address syntax.
pub fn from_addresses(raw: &[u8]) -> crate::error::Result<Vec<String>> {
    let message = workglen_mime::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| crate::error!("invalid RFC5322 message"))?;
    Ok(message
        .from()
        .into_iter()
        .flat_map(|a| a.iter())
        .filter_map(|a| a.address.as_deref().map(str::to_owned))
        .collect())
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
