//! Test-only private directories. Included by the library test build and core
//! integration target, never by the deployed executable.
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub struct TempDir {
    path: PathBuf,
    identity: fs::Metadata,
}
impl TempDir {
    pub fn path(&self) -> &Path {
        &self.path
    }
    fn cleanup(&self) -> io::Result<()> {
        let current = match fs::symlink_metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if !current.is_dir() || current.file_type().is_symlink() {
            return Err(io::Error::other("test directory replaced; cleanup refused"));
        }
        #[cfg(unix)]
        if current.dev() != self.identity.dev() || current.ino() != self.identity.ino() {
            return Err(io::Error::other(
                "test directory identity changed; cleanup refused",
            ));
        }
        // std does not traverse child symlinks during recursive directory removal.
        fs::remove_dir_all(&self.path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
pub fn tempdir() -> io::Result<TempDir> {
    let parent = std::env::temp_dir();
    for _ in 0..128 {
        let random = pratique::crypto::rand::bytes::<16>()
            .map_err(|_| io::Error::other("OS entropy unavailable for test directory"))?;
        let path = parent.join(format!("workglen-test-{}", pratique::util::hex(&random)));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => {
                let identity = fs::symlink_metadata(&path)?;
                return Ok(TempDir { path, identity });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "test directory collision limit reached",
    ))
}
