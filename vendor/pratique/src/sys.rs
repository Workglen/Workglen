//! What the library takes from the operating system: the clock and the CA bundle files. Behind the
//! `net` feature; the pure verification part of the crate is handed the time and the trust anchors.

use crate::error::{Result, cert};
use crate::x509::TrustStore;
use std::path::Path;

/// Loads the trust anchors from a PEM file (a CA bundle).
pub fn trust_store_from_pem_file(path: impl AsRef<Path>) -> Result<TrustStore> {
    let text = std::fs::read_to_string(path)?;
    let mut store = TrustStore::empty();
    store.add_pem(&text);
    if store.is_empty() {
        return cert("no usable certificates found in PEM file");
    }
    Ok(store)
}

/// Where the systems keep their CA bundle file, in the order they are looked for.
pub(crate) const BUNDLE_FILES: [&str; 8] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
];

/// Loads the operating system's CA bundle from its conventional file location.
///
/// Honors `SSL_CERT_FILE` first. Common Linux, macOS and BSD bundle paths follow. On Windows, which has no bundle file,
/// the certificate store is read when none of those exists ([`native_trust_store`]). On macOS the bundle file
/// (`/etc/ssl/cert.pem`) is used, which knows nothing of the Keychain's trust settings: [`native_trust_store`] reads those.
pub fn system_trust_store() -> Result<TrustStore> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(p) = std::env::var("SSL_CERT_FILE") {
        candidates.push(p);
    }
    for p in BUNDLE_FILES {
        candidates.push(p.to_string());
    }
    for c in &candidates {
        if let Ok(store) = trust_store_from_pem_file(c) {
            return Ok(store);
        }
    }
    if cfg!(windows) {
        return native_trust_store();
    }
    cert("could not find a system CA bundle; set SSL_CERT_FILE or load a PEM file explicitly")
}

/// The roots the operating system's own store trusts for TLS servers: the macOS Keychain's trust settings (the user's, the
/// administrator's and the system's), or the Windows certificate store less its `Disallowed` certificates; an error
/// elsewhere. See [`native_roots`](crate::native_roots) for what is taken and what is left out.
pub fn native_trust_store() -> Result<TrustStore> {
    let mut roots = crate::native_roots::native_roots().map_err(crate::error::Error::Tls)?;
    let store = roots.trust_store();
    if store.is_empty() {
        return cert("the operating system's store has no root trusted for TLS servers");
    }
    Ok(store)
}

/// Current time as Unix seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Bytes available to an unprivileged writer on the filesystem containing
/// `path`. This is a direct native query: it does not invoke a command or
/// depend on an installed runtime helper.
pub fn filesystem_available(path: impl AsRef<Path>) -> std::io::Result<u64> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let path = std::ffi::CString::new(path.as_ref().as_os_str().as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
        return filesystem_native::available(&path);
    }

    #[allow(unreachable_code)]
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native filesystem capacity is unsupported on this host",
    ))
}

#[cfg(target_os = "linux")]
mod filesystem_native {
    use std::os::raw::{c_char, c_int, c_ulong};

    #[repr(C)]
    struct StatVfs {
        block_size: c_ulong,
        fragment_size: c_ulong,
        blocks: c_ulong,
        blocks_free: c_ulong,
        blocks_available: c_ulong,
        files: c_ulong,
        files_free: c_ulong,
        files_available: c_ulong,
        filesystem_id: c_ulong,
        flags: c_ulong,
        name_max: c_ulong,
        spare: [c_int; 6],
    }

    extern "C" {
        fn statvfs(path: *const c_char, result: *mut StatVfs) -> c_int;
    }

    pub(super) fn available(path: &std::ffi::CStr) -> std::io::Result<u64> {
        let mut result = std::mem::MaybeUninit::<StatVfs>::uninit();
        // SAFETY: `path` is NUL terminated, `result` has the Linux statvfs
        // layout and remains valid for the call, and it is read only after a
        // successful return initialized the full structure.
        if unsafe { statvfs(path.as_ptr(), result.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let result = unsafe { result.assume_init() };
        Ok((result.blocks_available as u64).saturating_mul(result.fragment_size as u64))
    }
}

#[cfg(target_os = "macos")]
mod filesystem_native {
    use std::os::raw::{c_char, c_int};

    #[repr(C)]
    struct FileSystemId {
        values: [i32; 2],
    }

    #[repr(C)]
    struct StatFs {
        block_size: u32,
        io_size: i32,
        blocks: u64,
        blocks_free: u64,
        blocks_available: u64,
        files: u64,
        files_free: u64,
        filesystem_id: FileSystemId,
        owner: u32,
        filesystem_type: u32,
        flags: u32,
        filesystem_subtype: u32,
        filesystem_type_name: [c_char; 16],
        mounted_on: [c_char; 1024],
        mounted_from: [c_char; 1024],
        reserved: [u32; 8],
    }

    extern "C" {
        fn statfs(path: *const c_char, result: *mut StatFs) -> c_int;
    }

    pub(super) fn available(path: &std::ffi::CStr) -> std::io::Result<u64> {
        let mut result = std::mem::MaybeUninit::<StatFs>::uninit();
        // SAFETY: `path` is NUL terminated, `result` has the Darwin statfs
        // layout and remains valid for the call, and it is read only after a
        // successful return initialized the full structure.
        if unsafe { statfs(path.as_ptr(), result.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let result = unsafe { result.assume_init() };
        Ok(result
            .blocks_available
            .saturating_mul(u64::from(result.block_size)))
    }
}
