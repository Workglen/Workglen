use super::model::*;
use crate::error::{Result, ensure};
use pratique::json_value::{Value, json};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;
pub const DATA: TableDefinition<&str, &[u8]> = TableDefinition::new("security");
pub type Table<'a> = redb::Table<'a, &'static str, &'static [u8]>;
pub struct Db {
    db: Database,
}
impl Db {
    pub fn open(path: &Path, key: crate::encrypted_store::Key) -> Result<Self> {
        let mut builder = Database::builder();
        builder.set_cache_size(16 * 1024 * 1024);
        let db = Self {
            db: builder
                .create_with_backend(crate::encrypted_store::EncryptedBackend::open(path, key)?)?,
        };
        db.write(|_| Ok(()))?;
        Ok(db)
    }
    pub fn write<T>(&self, f: impl FnOnce(&mut Table) -> Result<T>) -> Result<T> {
        let tx = self.db.begin_write()?;
        let result = {
            let mut table = tx.open_table(DATA)?;
            f(&mut table)?
        };
        tx.commit()?;
        Ok(result)
    }
    pub fn get(&self, key: &str) -> Result<Option<Value>> {
        let tx = self.db.begin_read()?;
        get(&tx.open_table(DATA)?, key)
    }
}
pub fn get(
    t: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<Value>> {
    crate::store::json(t, key)
}
pub fn must(t: &impl ReadableTable<&'static str, &'static [u8]>, key: &str) -> Result<Value> {
    get(t, key)?.ok_or_else(|| {
        crate::error!(
            "Record not found: {}",
            key.split('/').next().unwrap_or("record")
        )
    })
}
pub fn put(t: &mut Table, key: &str, value: &Value) -> Result<()> {
    ensure!(!key.starts_with("audit/"), "Audit events are append-only");
    t.insert(key, pratique::json_value::to_vec(value)?.as_slice())?;
    Ok(())
}
pub fn remove(t: &mut Table, key: &str) -> Result<()> {
    ensure!(!key.starts_with("audit/"), "Audit events are append-only");
    t.remove(key)?;
    Ok(())
}
pub fn list(
    t: &impl ReadableTable<&'static str, &'static [u8]>,
    prefix: &str,
) -> Result<Vec<Value>> {
    Ok(crate::store::scan::<Value>(t, prefix)?
        .into_iter()
        .map(|(_, v)| v)
        .collect())
}
pub fn keyed(
    t: &impl ReadableTable<&'static str, &'static [u8]>,
    prefix: &str,
) -> Result<Vec<(String, Value)>> {
    crate::store::scan(t, prefix)
}
pub fn blob(t: &mut Table, raw: &[u8]) -> Result<String> {
    let h = hash(raw);
    t.insert(format!("blob/{h}").as_str(), raw)?;
    Ok(h)
}
pub fn body(
    t: &impl ReadableTable<&'static str, &'static [u8]>,
    message: &Value,
) -> Result<Vec<u8>> {
    Ok(t.get(format!("blob/{}", s(message, "hash")?).as_str())?
        .ok_or_else(|| crate::error!("Content has expired"))?
        .value()
        .to_vec())
}
pub fn audit(t: &mut Table, actor: &str, action: &str, scope: &str, data: Value) -> Result<()> {
    let seq = get(t, "audit_sequence")?
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        + 1;
    let previous = get(t, "audit_head")?
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "0".repeat(64));
    let mut event = json!({"seq":seq,"at":now(),"actor":actor,"action":action,"scope":scope,"data":data,"previous":previous});
    let h = hash(&pratique::json_value::to_vec(&event)?);
    event["hash"] = json!(h);
    t.insert(
        format!("audit/{seq:020}").as_str(),
        pratique::json_value::to_vec(&event)?.as_slice(),
    )?;
    put(t, "audit_sequence", &json!(seq))?;
    put(t, "audit_head", &json!(h))?;
    Ok(())
}
pub fn job(t: &mut Table, kind: &str, data: Value, id: &str) -> Result<String> {
    let key = format!("job/{id}");
    if get(t, &key)?.is_none() {
        put(
            t,
            &key,
            &json!({"id":id,"kind":kind,"state":"queued","due":now(),"attempts":0,"error":"","data":data}),
        )?;
    }
    Ok(id.into())
}
pub fn message(t: &impl ReadableTable<&'static str, &'static [u8]>, id: &str) -> Result<Value> {
    key(id)?;
    must(t, &format!("message/{id}"))
}
pub fn save_message(t: &mut Table, v: &Value) -> Result<()> {
    put(t, &format!("message/{}", s(v, "id")?), v)
}
