use super::*;
use redb::ReadableDatabase;
use std::os::unix::fs::{PermissionsExt, symlink};

fn open(path: &Path, key: &Path) -> EncryptedBackend {
    EncryptedBackend::open(path, Key::load(key).unwrap()).unwrap()
}
fn fixture() -> (crate::test_support::TempDir, PathBuf, PathBuf) {
    let dir = crate::test_support::tempdir().unwrap();
    let key = dir.path().join("storage.key");
    let db = dir.path().join("database.redb");
    generate_key(&key).unwrap();
    (dir, db, key)
}

#[test]
fn generated_and_supplied_keys_are_private_and_not_overwritten() {
    let (_dir, _, key) = fixture();
    let bytes = std::fs::read(&key).unwrap();
    assert_eq!(bytes.len(), 65);
    assert_eq!(std::fs::metadata(&key).unwrap().mode() & 0o777, 0o600);
    assert!(generate_key(&key).is_err());
    assert_eq!(std::fs::read(&key).unwrap(), bytes);
    assert_eq!(format!("{:?}", Key::load(&key).unwrap()), "Key([redacted])");
    std::fs::write(&key, [7u8; 32]).unwrap();
    assert_eq!(Key::load(&key).unwrap().0, [7; 32]);
    std::fs::write(&key, b"not a random 256-bit key").unwrap();
    assert!(Key::load(&key).is_err());
    std::fs::write(&key, [0u8; 32]).unwrap();
    assert!(Key::load(&key).is_err());
}

#[test]
fn unsafe_key_files_are_rejected() {
    let (dir, _, key) = fixture();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Key::load(&key).is_err());
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let alias = dir.path().join("alias");
    symlink(&key, &alias).unwrap();
    assert!(Key::load(&alias).is_err());
    assert!(separate_key(dir.path(), &alias).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::hard_link(&key, &alias).unwrap();
    assert!(Key::load(&key).is_err());
    assert!(Key::load(&dir.path().join("missing")).is_err());
}

#[test]
fn unsafe_database_files_are_rejected() {
    let (dir, path, key) = fixture();
    drop(open(&path, &key));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(EncryptedBackend::open(&path, Key::load(&key).unwrap()).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let alias = dir.path().join("database-alias");
    symlink(&path, &alias).unwrap();
    assert!(EncryptedBackend::open(&alias, Key::load(&key).unwrap()).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(EncryptedBackend::open(&path, Key::load(&key).unwrap()).is_err());
}

#[test]
fn encrypted_redb_roundtrip_hides_keys_values_and_headers() {
    use redb::TableDefinition;
    const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("sensitive-metadata");
    let (_dir, path, key) = fixture();
    let address = "private-mailbox@secret.example";
    let mime = b"From: confidential@secret.example\r\nSubject: exclusive-quarantine-canary\r\n\r\nSensitive attachment\r\n";
    {
        let db = redb::Database::builder()
            .create_with_backend(open(&path, &key))
            .unwrap();
        let tx = db.begin_write().unwrap();
        tx.open_table(TABLE)
            .unwrap()
            .insert(address, mime.as_slice())
            .unwrap();
        tx.commit().unwrap();
    }
    let ciphertext = std::fs::read(&path).unwrap();
    assert!(ciphertext.starts_with(MAGIC));
    for canary in [address.as_bytes(), mime.as_slice(), b"sensitive-metadata"] {
        assert!(!ciphertext.windows(canary.len()).any(|w| w == canary));
    }
    let db = redb::Database::builder()
        .create_with_backend(open(&path, &key))
        .unwrap();
    let tx = db.begin_read().unwrap();
    assert_eq!(
        tx.open_table(TABLE)
            .unwrap()
            .get(address)
            .unwrap()
            .unwrap()
            .value(),
        mime
    );
}

#[test]
fn wrong_key_corruption_and_plaintext_are_rejected_without_replacement() {
    let (dir, path, key) = fixture();
    let b = open(&path, &key);
    b.write(0, b"private payload").unwrap();
    b.sync_data().unwrap();
    drop(b);
    let original = std::fs::read(&path).unwrap();
    let wrong = dir.path().join("wrong.key");
    generate_key(&wrong).unwrap();
    assert!(EncryptedBackend::open(&path, Key::load(&wrong).unwrap()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    // Change a tag of a complete durable frame: no rollback to an older value.
    let mut changed = original.clone();
    let last = changed.len() - 1;
    changed[last] ^= 0x80;
    std::fs::write(&path, &changed).unwrap();
    assert!(EncryptedBackend::open(&path, Key::load(&key).unwrap()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), changed);
    std::fs::write(
        &path,
        b"plaintext database content is not a supported input",
    )
    .unwrap();
    assert!(EncryptedBackend::open(&path, Key::load(&key).unwrap()).is_err());
}

#[test]
fn random_access_and_resize_match_a_plain_file_without_persisting_plaintext() {
    let (_dir, path, key) = fixture();
    let mut backend = open(&path, &key);
    let mut expected = Vec::new();
    let mut seed = 17u64;
    for iteration in 0..160 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        if iteration % 4 == 0 {
            let len = (seed % 20000) as usize;
            backend.set_len(len as u64).unwrap();
            expected.resize(len, 0);
        } else {
            let at = (seed % 16000) as usize;
            let data = vec![(seed >> 32) as u8; 77 + (seed % 4300) as usize];
            backend.write(at as u64, &data).unwrap();
            if at + data.len() > expected.len() {
                expected.resize(at + data.len(), 0);
            }
            expected[at..at + data.len()].copy_from_slice(&data);
        }
        if iteration % 7 == 0 {
            backend.sync_data().unwrap();
            drop(backend);
            backend = open(&path, &key);
        }
        let mut actual = vec![0; expected.len()];
        backend.read(0, &mut actual).unwrap();
        assert_eq!(actual, expected, "iteration {iteration}");
        assert_eq!(backend.len().unwrap(), expected.len() as u64);
    }
    assert!(backend.read(expected.len() as u64, &mut [0]).is_err());
}

#[test]
fn restart_discards_unsynced_and_partially_written_tail() {
    let (_dir, path, key) = fixture();
    let b = open(&path, &key);
    b.write(0, b"committed").unwrap();
    b.sync_data().unwrap();
    let durable_size = std::fs::metadata(&path).unwrap().len();
    b.write(0, b"unflushed").unwrap();
    drop(b);
    let b = open(&path, &key);
    let mut data = [0; 9];
    b.read(0, &mut data).unwrap();
    assert_eq!(&data, b"committed");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), durable_size);
    b.write(0, b"unflushed").unwrap();
    drop(b);
    let f = OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(f.metadata().unwrap().len() - 5).unwrap();
    let b = open(&path, &key);
    b.read(0, &mut data).unwrap();
    assert_eq!(&data, b"committed");
}

#[test]
fn ciphertext_cannot_be_transplanted_between_databases() {
    let (dir, first, key) = fixture();
    let second = dir.path().join("second.redb");
    for path in [&first, &second] {
        let b = open(path, &key);
        b.write(0, b"same value").unwrap();
        b.sync_data().unwrap();
    }
    let a = std::fs::read(&first).unwrap();
    let mut b = std::fs::read(&second).unwrap();
    assert_ne!(a, b);
    b[HEADER..].copy_from_slice(&a[HEADER..]);
    std::fs::write(&second, b).unwrap();
    assert!(EncryptedBackend::open(&second, Key::load(&key).unwrap()).is_err());
}

#[test]
fn recovery_uses_a_fresh_nonce_when_rewriting_an_aborted_sequence() {
    let (_dir, path, key) = fixture();
    let b = open(&path, &key);
    b.set_len(BLOCK as u64).unwrap();
    b.sync_data().unwrap();
    let offset = std::fs::metadata(&path).unwrap().len() as usize;
    b.write(0, b"uncommitted first value").unwrap();
    let first = std::fs::read(&path).unwrap();
    drop(b);
    let b = open(&path, &key);
    b.write(0, b"different second value").unwrap();
    let second = std::fs::read(&path).unwrap();
    assert_eq!(
        &first[offset + 4..offset + 12],
        &second[offset + 4..offset + 12]
    );
    assert_ne!(
        &first[offset + 12..offset + PREFIX],
        &second[offset + 12..offset + PREFIX]
    );
}

#[test]
fn automatic_compaction_preserves_durable_contents_and_uses_a_new_file_key() {
    let (_dir, path, key) = fixture();
    let b = open(&path, &key);
    let before = std::fs::read(&path).unwrap()[8..40].to_vec();
    let block = [0x61; BLOCK];
    for _ in 0..4200 {
        b.write(0, &block).unwrap();
    }
    assert!(std::fs::metadata(&path).unwrap().len() > COMPACT_FLOOR);
    b.sync_data().unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() < COMPACT_FLOOR);
    assert_ne!(&std::fs::read(&path).unwrap()[8..40], before);
    drop(b);
    let b = open(&path, &key);
    let mut actual = [0; BLOCK];
    b.read(0, &mut actual).unwrap();
    assert_eq!(actual, block);
}

#[test]
fn exclusive_lock_and_bounds_fail_closed() {
    let (_dir, path, key) = fixture();
    let b = open(&path, &key);
    assert!(EncryptedBackend::open(&path, Key::load(&key).unwrap()).is_err());
    assert!(b.set_len(MAX_LEN + 1).is_err());
    assert!(b.write(0, b"no writes after failure").is_err());
    drop(b);
    let b = open(&path, &key);
    assert_eq!(b.len().unwrap(), 0);
}
