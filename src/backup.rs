use crate::encrypted_store::Key;
use crate::error::{Result, ensure};
use crate::store::{KV, META, Store};
use redb::{ReadableDatabase, ReadableTable};
use std::{fs, io::Write, os::unix::fs::PermissionsExt, path::Path};
/// Consistent logical copy from one MVCC read transaction. Never copy the live database file.
pub fn create(store: &Store, cluster: &str, path: &Path) -> Result<()> {
    ensure!(!path.exists(), "backup destination exists");
    let target = Store::open(path, cluster)?;
    copy(store, &target)?;
    drop(target);
    sync(path)
}
/// Encrypted logical backup for the local Admin store. The encryption key is
/// intentionally not copied into the data directory or backup artifact.
pub fn create_encrypted(store: &Store, cluster: &str, path: &Path, key: Key) -> Result<()> {
    ensure!(!path.exists(), "backup destination exists");
    let target = Store::open_admin(path, cluster, key)?;
    copy(store, &target)?;
    drop(target);
    sync(path)
}
fn copy(store: &Store, target: &Store) -> Result<()> {
    let tx = store.db.begin_read()?;
    let meta = tx.open_table(META)?;
    for row in tx.open_table(KV)?.iter()? {
        let (k, v) = row?;
        let write = target.db.begin_write()?;
        {
            write.open_table(KV)?.insert(k.value(), v.value())?;
        }
        write.commit()?;
    }
    for key in ["seq", "term", "ready", "deployment"] {
        target.set_meta(key, meta.get(key)?.map(|v| v.value()).unwrap_or(0))?;
    }
    Ok(())
}
fn sync(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
/// Restore an encrypted Admin backup into a new database path. Callers must
/// atomically rename the completed path and must never overwrite a live store.
pub fn restore_admin(
    backup: &Path,
    destination: &Path,
    cluster: &str,
    key_path: &Path,
) -> Result<()> {
    ensure!(
        backup != destination,
        "backup and restore destination must differ"
    );
    ensure!(!destination.exists(), "restore destination must be new");
    let source = Store::open_admin(backup, cluster, Key::load(key_path)?)?;
    create_encrypted(&source, cluster, destination, Key::load(key_path)?)
}
/// Read-only extraction of messages and mailbox/queue metadata from a preserved database.
pub fn export(path: &Path, destination: &Path) -> Result<usize> {
    ensure!(!destination.exists(), "export destination must be new");
    fs::create_dir_all(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    let db = redb::ReadOnlyDatabase::open(path)?;
    let tx = db.begin_read()?;
    let table = tx.open_table(KV)?;
    let mut manifest = fs::File::create(destination.join("metadata.jsonl"))?;
    let mut count = 0;
    for row in table.iter()? {
        let (k, v) = row?;
        let key = k.value();
        if let Some(id) = key.strip_prefix("blob/") {
            ensure!(
                id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid stored blob id"
            );
            let file = destination.join(format!("{id}.eml"));
            fs::write(&file, v.value())?;
            fs::set_permissions(file, fs::Permissions::from_mode(0o600))?;
            count += 1;
        } else if key.starts_with("mail/")
            || key.starts_with("folder/")
            || key.starts_with("queue/")
        {
            let value: pratique::json_value::Value = pratique::json_value::from_slice(v.value())?;
            writeln!(
                manifest,
                "{}",
                pratique::json_value::json!({"key":key,"value":value})
            )?;
        }
    }
    fs::set_permissions(
        destination.join("metadata.jsonl"),
        fs::Permissions::from_mode(0o600),
    )?;
    Ok(count)
}
