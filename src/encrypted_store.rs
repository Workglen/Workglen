//! Authenticated, encrypted random-access storage for redb 3.1.
//!
//! redb sees a normal byte-addressed file. Physical writes are encrypted frames
//! in an append-only journal, committed by sync_data. This avoids overwriting
//! both redb commit slots inside one authenticated encryption sector. Compaction
//! writes a new encrypted file, fsyncs it, then atomically replaces the old file.
//! No plaintext database, journal or compaction file is written.
use pratique::crypto::{gcm::AesGcm, hmac::Hmac, sha2::Sha256};
use redb::StorageBackend;
use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use subtle::ConstantTimeEq;

const MAGIC: &[u8; 8] = b"WGCRYPT1";
const HEADER: usize = 72;
const BLOCK: usize = 4096;
const PREFIX: usize = 24; // encrypted payload length, sequence, random nonce
const TAG: usize = 16;
const MAX_LEN: u64 = 4 * 1024 * 1024 * 1024;
const MAX_FRAMES: u64 = 1 << 24;
const MAX_PENDING: usize = 65536;
const COMPACT_FLOOR: u64 = 16 * 1024 * 1024;
const NOFOLLOW: i32 = crate::net::OPEN_NOFOLLOW;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn crypto<T>(_: T) -> io::Error {
    invalid("Encrypted storage authentication or cryptographic operation failed")
}
fn random(out: &mut [u8]) -> io::Result<()> {
    pratique::crypto::rand::fill(out).map_err(crypto)
}
fn mac(key: &[u8], pieces: &[&[u8]]) -> io::Result<[u8; 32]> {
    let mut signer = Hmac::<Sha256>::new(key);
    for piece in pieces {
        signer.update(piece);
    }
    signer.finalize().try_into().map_err(crypto)
}

fn private_regular_file(
    path: &Path,
    file: &File,
    message: &'static str,
) -> io::Result<std::fs::Metadata> {
    // O_NOFOLLOW is the primary atomic defense. Verify the pathname as well so
    // unusual filesystems or platforms cannot silently weaken the boundary,
    // and so a rename between lookup and open fails closed.
    let path_meta = std::fs::symlink_metadata(path)?;
    let file_meta = file.metadata()?;
    if path_meta.file_type().is_symlink()
        || !path_meta.is_file()
        || !file_meta.is_file()
        || path_meta.mode() & 0o077 != 0
        || file_meta.mode() & 0o077 != 0
        || path_meta.nlink() != 1
        || file_meta.nlink() != 1
        || path_meta.dev() != file_meta.dev()
        || path_meta.ino() != file_meta.ino()
    {
        return Err(invalid(message));
    }
    Ok(file_meta)
}

/// A 256-bit random key, supplied by the operator or generated locally.
/// Debug never includes the key; APIs never serialize it.
pub struct Key([u8; 32]);
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key([redacted])")
    }
}
impl Key {
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW)
            .open(path)?;
        private_regular_file(
            path,
            &file,
            "Storage key must be a regular, owner-only file with one link",
        )?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file).take(67).read_to_end(&mut bytes)?;
        let mut key = [0; 32];
        if bytes.len() == 32 {
            key.copy_from_slice(&bytes);
        } else {
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
                return Err(invalid(
                    "Storage key must contain 32 random bytes or 64 hexadecimal digits",
                ));
            }
            for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
                key[i] = u8::from_str_radix(std::str::from_utf8(pair).map_err(crypto)?, 16)
                    .map_err(crypto)?;
            }
        }
        bytes.fill(0);
        if key == [0; 32] {
            return Err(invalid("An all-zero storage key is not allowed"));
        }
        Ok(Self(key))
    }
}

pub fn generate_key(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(invalid("Use an absolute storage key path"));
    }
    let mut key = [0; 32];
    random(&mut key)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW)
        .open(path)?;
    for byte in key {
        write!(file, "{byte:02x}")?;
    }
    writeln!(file)?;
    key.fill(0);
    file.sync_all()?;
    File::open(path.parent().ok_or_else(|| invalid("Key parent missing"))?)?.sync_all()
}

pub fn separate_key(data_dir: &Path, key_path: &Path) -> io::Result<()> {
    if key_path
        .canonicalize()?
        .starts_with(data_dir.canonicalize()?)
    {
        return Err(invalid(
            "Keep the storage key outside the database data directory",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Location {
    offset: u64,
    previous: [u8; TAG],
}
enum Change {
    Page(u64, Location),
    Length(u64),
}
struct State {
    file: File,
    path: PathBuf,
    id: [u8; 32],
    key: [u8; 32],
    pages: BTreeMap<u64, Location>,
    len: u64,
    end: u64,
    sequence: u64,
    previous: [u8; TAG],
    pending: usize,
    dirty: bool,
}
impl State {
    fn fresh(path: &Path, master: &Key) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(NOFOLLOW)
            .open(path)?;
        let mut id = [0; 32];
        random(&mut id)?;
        let key = mac(&master.0, &[b"workglen/redb/file-key/v1", &id])?;
        let tag = mac(&key, &[b"workglen/redb/header/v1", MAGIC, &id])?;
        let mut header = Vec::from(MAGIC.as_slice());
        header.extend(id);
        header.extend(tag);
        file.write_all_at(&header, 0)?;
        let mut s = Self {
            file,
            path: path.into(),
            id,
            key,
            pages: BTreeMap::new(),
            len: 0,
            end: HEADER as u64,
            sequence: 0,
            previous: tag[..TAG].try_into().unwrap(),
            pending: 0,
            dirty: true,
        };
        s.sync()?;
        Ok(s)
    }
    fn open(path: &Path, master: &Key) -> io::Result<Self> {
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let s = Self::fresh(path, master)?;
                File::open(
                    path.parent()
                        .ok_or_else(|| invalid("Database parent missing"))?,
                )?
                .sync_all()?;
                return Ok(s);
            }
            Err(e) => return Err(e),
        };
        let metadata = private_regular_file(
            path,
            &file,
            "Encrypted database must be a regular owner-only file with one link",
        )?;
        let mut header = [0; HEADER];
        file.read_exact_at(&mut header, 0)?;
        if &header[..8] != MAGIC {
            return Err(invalid(
                "Expected an encrypted Workglen database; plaintext stores are not opened",
            ));
        }
        let id: [u8; 32] = header[8..40].try_into().unwrap();
        let key = mac(&master.0, &[b"workglen/redb/file-key/v1", &id])?;
        let tag = mac(&key, &[b"workglen/redb/header/v1", MAGIC, &id])?;
        if !bool::from(tag.ct_eq(&header[40..])) {
            return Err(invalid(
                "Incorrect storage key or damaged encrypted database header",
            ));
        }
        let mut s = Self {
            file,
            path: path.into(),
            id,
            key,
            pages: BTreeMap::new(),
            len: 0,
            end: HEADER as u64,
            sequence: 0,
            previous: tag[..TAG].try_into().unwrap(),
            pending: 0,
            dirty: false,
        };
        let mut offset = HEADER as u64;
        let mut sequence = 0;
        let mut previous = s.previous;
        let mut pending = Vec::new();
        while offset < metadata.len() {
            if metadata.len() - offset < PREFIX as u64 {
                break; // incomplete uncommitted tail after a crash
            }
            let mut prefix = [0; PREFIX];
            s.file.read_exact_at(&mut prefix, offset)?;
            let length = u32::from_le_bytes(prefix[..4].try_into().unwrap()) as usize;
            if ![9, 9 + BLOCK].contains(&length) {
                return Err(invalid("Invalid encrypted storage frame length"));
            }
            let end = offset + (PREFIX + length + TAG) as u64;
            if end > metadata.len() {
                break;
            }
            sequence += 1;
            if sequence > MAX_FRAMES
                || u64::from_le_bytes(prefix[4..12].try_into().unwrap()) != sequence
            {
                return Err(invalid("Encrypted storage frame order or limit invalid"));
            }
            let location = Location { offset, previous };
            let (plain, tag) = s.frame(location)?;
            let value = u64::from_le_bytes(plain[1..9].try_into().unwrap());
            match plain[0] {
                1 if plain.len() == 9 + BLOCK && value < MAX_LEN / BLOCK as u64 => {
                    pending.push(Change::Page(value, location));
                }
                2 if plain.len() == 9 && value <= MAX_LEN => pending.push(Change::Length(value)),
                3 if plain.len() == 9 => {
                    for change in pending.drain(..) {
                        match change {
                            Change::Page(page, location) => {
                                if page * BLOCK as u64 >= s.len {
                                    return Err(invalid("Encrypted page outside logical storage"));
                                }
                                s.pages.insert(page, location);
                            }
                            Change::Length(len) => {
                                s.len = len;
                                s.pages.retain(|page, _| *page < len.div_ceil(BLOCK as u64));
                            }
                        }
                    }
                    if value != s.len {
                        return Err(invalid("Encrypted storage commit length mismatch"));
                    }
                    s.end = end;
                    s.sequence = sequence;
                    s.previous = tag;
                }
                _ => return Err(invalid("Invalid authenticated storage operation")),
            }
            if pending.len() > MAX_PENDING {
                return Err(invalid(
                    "Encrypted storage transaction exceeds supported bounds",
                ));
            }
            previous = tag;
            offset = end;
        }
        if s.sequence == 0 {
            return Err(invalid("Encrypted storage has no durable initialization"));
        }
        // Only fully authenticated frames through the last sync marker survive.
        // A complete corrupt frame is an error; it is never silently skipped.
        if s.end != metadata.len() {
            s.file.set_len(s.end)?;
            s.file.sync_all()?;
        }
        Ok(s)
    }
    fn aad(&self, prefix: &[u8], previous: &[u8]) -> Vec<u8> {
        [
            MAGIC.as_slice(),
            self.id.as_slice(),
            &prefix[..12],
            previous,
        ]
        .concat()
    }
    fn frame(&self, location: Location) -> io::Result<(Vec<u8>, [u8; TAG])> {
        let mut prefix = [0; PREFIX];
        self.file.read_exact_at(&mut prefix, location.offset)?;
        let size = u32::from_le_bytes(prefix[..4].try_into().unwrap()) as usize;
        if ![9, 9 + BLOCK].contains(&size) {
            return Err(invalid("Invalid encrypted frame size"));
        }
        let mut bytes = vec![0; size + TAG];
        self.file
            .read_exact_at(&mut bytes, location.offset + PREFIX as u64)?;
        let tag: [u8; TAG] = bytes[size..].try_into().unwrap();
        let plain = AesGcm::new(&self.key)
            .open(
                prefix[12..].try_into().unwrap(),
                &self.aad(&prefix, &location.previous),
                &bytes,
            )
            .ok_or_else(|| invalid("Encrypted storage authentication failed"))?;
        Ok((plain, tag))
    }
    fn append(&mut self, kind: u8, value: u64, data: &[u8]) -> io::Result<Location> {
        if kind != 3 && self.pending >= MAX_PENDING {
            return Err(invalid(
                "Encrypted storage transaction exceeds supported bounds",
            ));
        }
        if self.sequence >= MAX_FRAMES {
            return Err(invalid(
                "Encrypted storage frame limit reached; reopen for compaction",
            ));
        }
        let mut prefix = [0; PREFIX];
        prefix[..4].copy_from_slice(&((9 + data.len()) as u32).to_le_bytes());
        prefix[4..12].copy_from_slice(&(self.sequence + 1).to_le_bytes());
        random(&mut prefix[12..])?;
        let mut plain = vec![kind];
        plain.extend(value.to_le_bytes());
        plain.extend(data);
        let sealed = AesGcm::new(&self.key).seal(
            prefix[12..].try_into().unwrap(),
            &self.aad(&prefix, &self.previous),
            &plain,
        );
        let split = sealed.len() - TAG;
        let cipher = &sealed[..split];
        let tag: [u8; TAG] = sealed[split..].try_into().unwrap();
        plain.fill(0);
        let location = Location {
            offset: self.end,
            previous: self.previous,
        };
        let frame = [prefix.as_slice(), cipher, tag.as_slice()].concat();
        self.file.write_all_at(&frame, self.end)?;
        self.end += frame.len() as u64;
        self.sequence += 1;
        self.previous = tag;
        self.pending = if kind == 3 { 0 } else { self.pending + 1 };
        self.dirty = true;
        Ok(location)
    }
    fn page(&self, index: u64) -> io::Result<[u8; BLOCK]> {
        let mut page = [0; BLOCK];
        if let Some(location) = self.pages.get(&index) {
            let (mut plain, _) = self.frame(*location)?;
            if plain.len() != 9 + BLOCK
                || plain[0] != 1
                || u64::from_le_bytes(plain[1..9].try_into().unwrap()) != index
            {
                return Err(invalid("Encrypted page address mismatch"));
            }
            page.copy_from_slice(&plain[9..]);
            plain.fill(0);
        }
        Ok(page)
    }
    fn save_page(&mut self, index: u64, page: &[u8; BLOCK]) -> io::Result<()> {
        let location = self.append(1, index, page)?;
        self.pages.insert(index, location);
        Ok(())
    }
    fn resize(&mut self, len: u64) -> io::Result<()> {
        if len > MAX_LEN {
            return Err(invalid(
                "Encrypted storage exceeds the 4 GiB logical file limit",
            ));
        }
        if len == self.len {
            return Ok(());
        }
        if len < self.len && !len.is_multiple_of(BLOCK as u64) {
            let index = len / BLOCK as u64;
            let mut page = self.page(index)?;
            page[(len % BLOCK as u64) as usize..].fill(0);
            self.save_page(index, &page)?;
        }
        self.append(2, len, &[])?;
        self.len = len;
        self.pages
            .retain(|page, _| *page < len.div_ceil(BLOCK as u64));
        Ok(())
    }
    fn sync(&mut self) -> io::Result<()> {
        if self.dirty {
            self.append(3, self.len, &[])?;
            self.file.sync_all()?;
            self.dirty = false;
        }
        Ok(())
    }
    fn needs_compaction(&self) -> bool {
        self.sequence > MAX_FRAMES / 2
            || self.end > COMPACT_FLOOR.max((self.pages.len() as u64 + 1) * (BLOCK + 49) as u64 * 3)
    }
    fn compact(&mut self, master: &Key) -> io::Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| invalid("Database parent missing"))?;
        let temp = parent.join(format!(".encrypted-{}.tmp", crate::store::random_id()));
        let result = (|| {
            let mut replacement = Self::fresh(&temp, master)?;
            replacement.resize(self.len)?;
            // Compaction checkpoints bound startup recovery memory. The replacement
            // is not visible until every page and final commit have been synced.
            for (i, index) in self.pages.keys().copied().enumerate() {
                replacement.save_page(index, &self.page(index)?)?;
                if i.is_multiple_of(4096) {
                    replacement.sync()?;
                }
            }
            replacement.sync()?;
            std::fs::rename(&temp, &self.path)?;
            replacement.path = self.path.clone();
            *self = replacement;
            File::open(self.path.parent().unwrap())?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
        }
        result
    }
}

pub struct EncryptedBackend {
    state: Mutex<State>,
    master: Key,
    health: StoreHealth,
    _lock: File,
}
#[derive(Clone, Debug)]
pub struct StoreHealth(Arc<AtomicBool>);
impl StoreHealth {
    pub fn healthy(&self) -> bool {
        !self.0.load(Ordering::Acquire)
    }
    fn fail(&self) {
        self.0.store(true, Ordering::Release);
    }
}
impl fmt::Debug for EncryptedBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptedBackend(AES-256-GCM)")
    }
}
impl EncryptedBackend {
    pub fn open(path: &Path, key: Key) -> io::Result<Self> {
        Self::open_with_health(path, key).map(|(backend, _)| backend)
    }
    pub fn open_with_health(path: &Path, key: Key) -> io::Result<(Self, StoreHealth)> {
        let lock_path = path.with_extension("redb.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(NOFOLLOW)
            .open(lock_path)?;
        lock.try_lock().map_err(io::Error::from)?;
        let mut state = State::open(path, &key)?;
        if state.needs_compaction() {
            state.compact(&key)?;
        }
        let health = StoreHealth(Arc::new(AtomicBool::new(false)));
        Ok((
            Self {
                state: Mutex::new(state),
                master: key,
                health: health.clone(),
                _lock: lock,
            },
            health,
        ))
    }
    fn state(&self) -> io::Result<MutexGuard<'_, State>> {
        if !self.health.healthy() {
            return Err(invalid(
                "Encrypted storage failed; stop and investigate before reopening",
            ));
        }
        self.state.lock().map_err(|_| {
            self.health.fail();
            invalid("Encrypted storage lock poisoned")
        })
    }
    fn mutate(&self, operation: impl FnOnce(&mut State) -> io::Result<()>) -> io::Result<()> {
        let mut state = self.state()?;
        let result = operation(&mut state);
        if result.is_err() {
            self.health.fail();
        }
        result
    }
}
impl StorageBackend for EncryptedBackend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.state()?.len)
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.mutate(|s| {
            let end = offset
                .checked_add(out.len() as u64)
                .ok_or_else(|| invalid("Read overflow"))?;
            if end > s.len {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            let mut at = offset;
            let mut done = 0;
            while done < out.len() {
                let page = s.page(at / BLOCK as u64)?;
                let start = (at % BLOCK as u64) as usize;
                let count = (BLOCK - start).min(out.len() - done);
                out[done..done + count].copy_from_slice(&page[start..start + count]);
                done += count;
                at += count as u64;
            }
            Ok(())
        })
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.mutate(|s| s.resize(len))
    }
    fn sync_data(&self) -> io::Result<()> {
        self.mutate(|s| {
            s.sync()?;
            if s.needs_compaction() {
                s.compact(&self.master)?;
            }
            Ok(())
        })
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.mutate(|s| {
            let end = offset
                .checked_add(data.len() as u64)
                .ok_or_else(|| invalid("Write overflow"))?;
            if end > MAX_LEN {
                return Err(invalid("Encrypted storage write exceeds supported limit"));
            }
            if data.is_empty() {
                return Ok(());
            }
            if end > s.len {
                s.resize(end)?;
            }
            let mut done = 0;
            while done < data.len() {
                let at = offset + done as u64;
                let index = at / BLOCK as u64;
                let start = (at % BLOCK as u64) as usize;
                let count = (BLOCK - start).min(data.len() - done);
                let mut page = if start == 0 && count == BLOCK {
                    [0; BLOCK]
                } else {
                    s.page(index)?
                };
                page[start..start + count].copy_from_slice(&data[done..done + count]);
                s.save_page(index, &page)?;
                done += count;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
