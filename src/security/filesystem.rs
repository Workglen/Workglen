//! Safe application-facing filesystem capacity admission.

use crate::error::{Result, ensure};
use std::path::Path;

pub fn available(path: &Path) -> Result<u64> {
    Ok(pratique::sys::filesystem_available(path)?)
}

pub fn admit(path: &Path, message_bytes: usize, minimum_free_bytes: u64) -> Result<u64> {
    let available = available(path)?;
    let write_headroom = u64::try_from(message_bytes)?
        .saturating_mul(3)
        .saturating_add(4 * 1024 * 1024);
    ensure!(
        available.saturating_sub(write_headroom) >= minimum_free_bytes,
        "Host filesystem free-space reserve reached"
    );
    Ok(available)
}
