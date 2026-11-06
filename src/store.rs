use crate::error::{Result, ensure};
use crate::{
    config::{Folder, Limits, Message, QueueItem, User},
    encrypted_store::{EncryptedBackend, Key},
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::{path::Path, sync::Arc};

pub const KV: TableDefinition<&str, &[u8]> = TableDefinition::new("data");
pub const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("replication_log");
pub const META: TableDefinition<&str, u64> = TableDefinition::new("metadata");
#[derive(Clone, Debug, PartialEq)]
pub struct Op {
    pub key: String,
    pub value: Option<Vec<u8>>,
}
pratique::data_encode!(Op { key, value });
pratique::data_decode!(Op, deny_unknown=false, { key, value });

impl Op {
    pub fn json(key: String, v: &impl pratique::data::Encode) -> Result<Self> {
        Ok(Self {
            key,
            value: Some(pratique::json_value::to_vec(v)?),
        })
    }
    pub fn del(key: String) -> Self {
        Self { key, value: None }
    }
}
#[derive(Clone)]
pub struct Store {
    pub db: Arc<Database>,
}
pub fn json<T: pratique::data::Decode>(
    t: &impl ReadableTable<&'static str, &'static [u8]>,
    k: &str,
) -> Result<Option<T>> {
    t.get(k)?
        .map(|x| pratique::json_value::from_slice(x.value()).map_err(Into::into))
        .transpose()
}
pub fn scan<T: pratique::data::Decode>(
    t: &impl ReadableTable<&'static str, &'static [u8]>,
    prefix: &str,
) -> Result<Vec<(String, T)>> {
    let mut out = Vec::new();
    for row in t.range(prefix..)? {
        let (k, v) = row?;
        if !k.value().starts_with(prefix) {
            break;
        }
        out.push((
            k.value().into(),
            pratique::json_value::from_slice(v.value())?,
        ));
    }
    Ok(out)
}
pub fn random_id() -> String {
    let mut b = [0; 16];
    pratique::crypto::rand::fill(&mut b).expect("OS random unavailable");
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn folder_key(u: &str, f: &str) -> String {
    format!("folder/{u}/{f}")
}
pub fn mail_prefix(u: &str, f: &str) -> String {
    format!("mail/{u}/{f}/")
}
pub fn mail_key(u: &str, f: &str, uid: u32) -> String {
    format!("{}{:010}", mail_prefix(u, f), uid)
}
pub fn fresh_folder() -> Folder {
    let mut b = [0; 4];
    pratique::crypto::rand::fill(&mut b).expect("OS random unavailable");
    Folder {
        validity: u32::from_be_bytes(b).max(1),
        next_uid: 1,
        subscribed: true,
    }
}
impl Store {
    /// Persist the deployment boundary. A clustered database may never silently
    /// become an unfenced writer by changing a configuration flag.
    pub fn demote_single(&self) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(META)?;
            ensure!(
                t.get("deployment")?.map(|v| v.value()) == Some(2),
                "database is not in dual mode"
            );
            ensure!(
                t.get("ready")?.map(|v| v.value()) == Some(1),
                "cannot demote an unseeded database"
            );
            t.insert("deployment", 1)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn enter_mode(&self, mode: crate::config::Mode) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(META)?;
            let old = t.get("deployment")?.map(|v| v.value()).unwrap_or(0);
            if mode == crate::config::Mode::Single {
                ensure!(
                    old != 2,
                    "database has joined dual mode; refusing unsafe downgrade to single mode"
                );
                ensure!(
                    t.get("ready")?.map(|v| v.value()) == Some(1),
                    "single mode requires an initialized primary; run init --bootstrap on a fresh database"
                );
                // An epoch without its deployment marker is inconsistent state;
                // never turn it into an unfenced single-node writer.
                ensure!(
                    old == 1 || t.get("term")?.map(|v| v.value()).unwrap_or(0) == 0,
                    "existing clustered database cannot enter single mode"
                );
                t.insert("deployment", 1)?;
            } else {
                t.insert("deployment", 2)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn open(path: &Path, cluster: &str) -> Result<Self> {
        let mut builder = Database::builder();
        builder.set_cache_size(16 * 1024 * 1024);
        let db = Arc::new(builder.create(path)?);
        Self::initialize(db, cluster, None)
    }
    pub fn open_admin(path: &Path, cluster: &str, key: Key) -> Result<Self> {
        let existed = path.exists();
        let mut builder = Database::builder();
        builder.set_cache_size(16 * 1024 * 1024);
        let db = Arc::new(builder.create_with_backend(EncryptedBackend::open(path, key)?)?);
        Self::initialize(db, cluster, Some(existed))
    }
    fn initialize(db: Arc<Database>, cluster: &str, admin_existed: Option<bool>) -> Result<Self> {
        {
            let tx = db.begin_write()?;
            {
                let mut t = tx.open_table(KV)?;
                if let Some(c) = t.get("cluster")? {
                    ensure!(
                        c.value() == cluster.as_bytes(),
                        "database belongs to a different cluster"
                    );
                }
                t.insert("cluster", cluster.as_bytes())?;
                if let Some(existed) = admin_existed {
                    let kind_is_admin = t
                        .get("system/store-kind")?
                        .as_ref()
                        .is_some_and(|v| v.value() == b"admin");
                    if existed {
                        ensure!(
                            kind_is_admin,
                            "encrypted database is not a Workglen Admin store"
                        );
                    }
                    t.insert("system/store-kind", b"admin".as_slice())?;
                }
                let _ = tx.open_table(LOG)?;
                let mut m = tx.open_table(META)?;
                if m.get("seq")?.is_none() {
                    m.insert("seq", 0)?;
                }
            }
            tx.commit()?;
        }
        Ok(Self { db })
    }
    pub fn seq(&self) -> Result<u64> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(META)?;
        Ok(t.get("seq")?.unwrap().value())
    }
    pub fn get<T: pratique::data::Decode>(&self, k: &str) -> Result<Option<T>> {
        let tx = self.db.begin_read()?;
        json(&tx.open_table(KV)?, k)
    }
    pub fn list<T: pratique::data::Decode>(&self, p: &str) -> Result<Vec<(String, T)>> {
        let tx = self.db.begin_read()?;
        scan(&tx.open_table(KV)?, p)
    }
    pub fn blob(&self, id: &str) -> Result<Vec<u8>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(KV)?;
        Ok(t.get(format!("blob/{id}").as_str())?
            .ok_or_else(|| crate::error!("missing message body"))?
            .value()
            .to_vec())
    }
    pub fn write<R>(
        &self,
        f: impl FnOnce(&redb::Table<&str, &[u8]>) -> Result<(Vec<Op>, R)>,
    ) -> Result<(u64, R)> {
        let tx = self.db.begin_write()?;
        let (seq, result) = {
            let mut t = tx.open_table(KV)?;
            let (ops, result) = f(&t)?;
            let mut m = tx.open_table(META)?;
            let seq = m
                .get("seq")?
                .unwrap()
                .value()
                .checked_add(1)
                .ok_or_else(|| crate::error!("sequence exhausted"))?;
            let bytes = crate::replication_codec::encode(&ops)?;
            apply(&mut t, &ops)?;
            let mut log = tx.open_table(LOG)?;
            log.insert(seq, bytes.as_slice())?;
            m.insert("seq", seq)?;
            (seq, result)
        };
        tx.commit()?;
        Ok((seq, result))
    }
    pub fn log(&self, seq: u64) -> Result<Option<Vec<u8>>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(LOG)?;
        Ok(t.get(seq)?.map(|x| x.value().to_vec()))
    }
    pub fn replay(&self, seq: u64, bytes: &[u8]) -> Result<()> {
        let ops = crate::replication_codec::decode(bytes)?;
        let tx = self.db.begin_write()?;
        {
            let mut m = tx.open_table(META)?;
            let old = m.get("seq")?.unwrap().value();
            ensure!(
                seq == old + 1,
                "replication sequence gap: expected {}, got {seq}",
                old + 1
            );
            let mut t = tx.open_table(KV)?;
            apply(&mut t, &ops)?;
            m.insert("seq", seq)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn prune(&self, through: u64) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(LOG)?;
            let keys = t
                .range(..=through)?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<Result<Vec<_>, _>>()?;
            for k in keys {
                t.remove(k)?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    pub fn add_user(&self, address: &str, password_hash: &str, quota: u64) -> Result<u64> {
        Ok(self
            .write(|t| {
                ensure!(
                    t.get(format!("user/{address}").as_str())?.is_none(),
                    "account already exists"
                );
                let mut ops = vec![Op::json(
                    format!("user/{address}"),
                    &User {
                        password_hash: password_hash.into(),
                        quota,
                    },
                )?];
                for f in ["INBOX", "Sent", "Drafts", "Trash", "Junk"] {
                    ops.push(Op::json(folder_key(address, f), &fresh_folder())?);
                }
                Ok((ops, ()))
            })?
            .0)
    }
    pub fn messages(&self, u: &str, f: &str) -> Result<Vec<Message>> {
        Ok(self
            .list(&mail_prefix(u, f))?
            .into_iter()
            .map(|(_, v)| v)
            .collect())
    }
}
fn apply(t: &mut redb::Table<&str, &[u8]>, ops: &[Op]) -> Result<()> {
    for op in ops {
        ensure!(
            op.key != "cluster" && op.key.len() <= 1024,
            "invalid replication key"
        );
        match &op.value {
            Some(v) => {
                t.insert(op.key.as_str(), v.as_slice())?;
            }
            None => {
                t.remove(op.key.as_str())?;
            }
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)] // Explicit transactional append inputs; no hidden mutable state.
pub fn append_ops(
    t: &redb::Table<&str, &[u8]>,
    u: &str,
    f: &str,
    blob: &str,
    size: usize,
    flags: Vec<String>,
    date: i64,
    limits: &Limits,
) -> Result<(Vec<Op>, u32, u32)> {
    let user: User = json(t, &format!("user/{u}"))?.ok_or_else(|| crate::error!("unknown user"))?;
    let all: Vec<(String, Message)> = scan(t, &format!("mail/{u}/"))?;
    ensure!(
        all.len() < limits.mailbox_messages
            && all.iter().map(|(_, m)| m.size as u64).sum::<u64>() + size as u64 <= user.quota,
        "mailbox quota exceeded"
    );
    let k = folder_key(u, f);
    let mut folder: Folder = json(t, &k)?.ok_or_else(|| crate::error!("folder not found"))?;
    let uid = folder.next_uid;
    folder.next_uid = uid
        .checked_add(1)
        .ok_or_else(|| crate::error!("UID exhausted"))?;
    let validity = folder.validity;
    Ok((
        vec![
            Op::json(k, &folder)?,
            Op::json(
                mail_key(u, f, uid),
                &Message {
                    blob: blob.into(),
                    uid,
                    flags,
                    size,
                    date,
                },
            )?,
        ],
        validity,
        uid,
    ))
}
pub fn gc_ops(t: &redb::Table<&str, &[u8]>, removed: &[String]) -> Result<Vec<Op>> {
    let mut used = std::collections::HashSet::new();
    for (k, m) in scan::<Message>(t, "mail/")? {
        if !removed.contains(&k) {
            used.insert(m.blob);
        }
    }
    for (k, q) in scan::<QueueItem>(t, "queue/")? {
        if !removed.contains(&k) {
            used.insert(q.blob);
        }
    }
    let mut ops = Vec::new();
    for row in t.range("blob/"..)? {
        let (k, _) = row?;
        if !k.value().starts_with("blob/") {
            break;
        }
        let id = &k.value()[5..];
        if !used.contains(id) {
            ops.push(Op::del(k.value().into()));
        }
    }
    Ok(ops)
}

impl Store {
    pub fn meta(&self, key: &str) -> Result<u64> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(META)?;
        Ok(t.get(key)?.map(|v| v.value()).unwrap_or(0))
    }
    pub fn set_meta(&self, key: &str, value: u64) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            tx.open_table(META)?.insert(key, value)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn begin_term(&self, term: u64) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut m = tx.open_table(META)?;
            m.insert("term", term)?;
            let mut table = tx.open_table(KV)?;
            // Failover can expose a shorter history. New UIDVALIDITY invalidates stale client caches.
            let folders = scan::<Folder>(&table, "folder/")?;
            for (key, mut folder) in folders {
                folder.validity = folder
                    .validity
                    .checked_add(1)
                    .ok_or_else(|| crate::error!("UIDVALIDITY exhausted"))?;
                let value = pratique::json_value::to_vec(&folder)?;
                table.insert(key.as_str(), value.as_slice())?;
            }
        }
        tx.delete_table(LOG)?;
        {
            let _ = tx.open_table(LOG)?;
        }
        tx.commit()?;
        Ok(())
    }
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    #[test]
    fn record_contract_op() {
        crate::data_contracts::check::<Op>(
            "src_store_Op",
            &[
                r###"{"key":"sample-\u00e9\ud83d\ude00","value":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",null]"###,
                r###"{"key":"sample-\u00e9\ud83d\ude00","value":null,"unexpected_field":1}"###,
                r###"{"key":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"value":null}"###,
                r###"{"key":false,"value":null}"###,
                r###"{"key":"sample-\u00e9\ud83d\ude00","value":null,"key":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"key":"sample-\u00e9\ud83d\ude00","value":"wrong"}"###,
                r###"{"key":"sample-\u00e9\ud83d\ude00","value":null,"value":null}"###,
                r###"{"key":"sample-\u00e9\ud83d\ude00","value":[255]}"###,
            ],
        );
    }
}
