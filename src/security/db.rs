use super::model::*;
use crate::error::{Result, ensure};
use pratique::json_value::{Value, json};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;
pub const DATA: TableDefinition<&str, &[u8]> = TableDefinition::new("security");
const CAPACITY_KEY: &str = "system/capacity";
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
fn record_usage(key: &str, value: &Value) -> (i128, i128) {
    if key.starts_with("message/") {
        let live =
            !["expired", "discarded", "delivered"].contains(&value["state"].as_str().unwrap_or(""));
        return (i128::from(live), 0);
    }
    if key.starts_with("job/") {
        let pending = !["succeeded", "cancelled"].contains(&value["state"].as_str().unwrap_or(""));
        return (0, i128::from(pending));
    }
    if key.starts_with("ingress/") {
        let reserved = value["recipients"].as_array().map_or(0, Vec::len) as i128;
        return (reserved, reserved);
    }
    (0, 0)
}
fn capacity_number(value: &Value, field: &str) -> Result<i128> {
    Ok(i128::from(value[field].as_u64().ok_or_else(|| {
        crate::error!("Invalid durable capacity ledger")
    })?))
}
fn adjust_capacity(t: &mut Table, messages: i128, jobs: i128, bytes: i128) -> Result<()> {
    if messages == 0 && jobs == 0 && bytes == 0 {
        return Ok(());
    }
    let mut usage =
        get(t, CAPACITY_KEY)?.unwrap_or_else(|| json!({"messages":0,"jobs":0,"bytes":0}));
    for (field, change) in [("messages", messages), ("jobs", jobs), ("bytes", bytes)] {
        let next = capacity_number(&usage, field)? + change;
        ensure!(
            (0..=i128::from(u64::MAX)).contains(&next),
            "Durable capacity ledger overflow"
        );
        usage[field] = json!(next as u64);
    }
    t.insert(
        CAPACITY_KEY,
        pratique::json_value::to_vec(&usage)?.as_slice(),
    )?;
    Ok(())
}
fn adjust_counter(t: &mut Table, key: &str, change: i128) -> Result<()> {
    if change == 0 {
        return Ok(());
    }
    let current = match get(t, key)? {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| crate::error!("Invalid durable status counter"))?,
        None => 0,
    };
    let next = i128::from(current) + change;
    ensure!(
        (0..=i128::from(u64::MAX)).contains(&next),
        "Durable status counter overflow"
    );
    if next == 0 {
        t.remove(key)?;
    } else {
        t.insert(
            key,
            pratique::json_value::to_vec(&json!(next as u64))?.as_slice(),
        )?;
    }
    Ok(())
}
fn adjust_status(t: &mut Table, key: &str, value: &Value, change: i128) -> Result<()> {
    let kind = if key.starts_with("message/") {
        "message"
    } else if key.starts_with("job/") {
        "job"
    } else if key.starts_with("ingress/") {
        "ingress"
    } else {
        return Ok(());
    };
    adjust_counter(t, &format!("status/{kind}/{}", s(value, "state")?), change)?;
    if kind == "ingress" {
        adjust_counter(
            t,
            "status/ingress_recipients",
            change * arr(value, "recipients")?.len() as i128,
        )?;
    }
    Ok(())
}
fn ordered_time(value: i64) -> u64 {
    (value as u64) ^ (1u64 << 63)
}
fn ingress_due_key(value: &Value) -> Result<Option<String>> {
    let state = s(value, "state")?;
    if !["queued", "retrying", "leased"].contains(&state) {
        return Ok(None);
    }
    let eligible = if state == "leased" {
        value["lease_until"]
            .as_i64()
            .ok_or_else(|| crate::error!("Invalid scan lease time"))?
    } else {
        value["due"]
            .as_i64()
            .ok_or_else(|| crate::error!("Invalid scan due time"))?
    };
    let arrived = value["arrived"]
        .as_i64()
        .ok_or_else(|| crate::error!("Invalid scan arrival time"))?;
    let scan_owner = s(value, "scan_owner")?;
    key(scan_owner)?;
    Ok(Some(format!(
        "ingress_due/{scan_owner}/{:020}/{:020}/{}",
        ordered_time(eligible),
        ordered_time(arrived),
        s(value, "id")?
    )))
}
fn ingress_arrival_key(value: &Value) -> Result<String> {
    let arrived = value["arrived"]
        .as_i64()
        .ok_or_else(|| crate::error!("Invalid scan arrival time"))?;
    Ok(format!(
        "ingress_arrival/{:020}/{}",
        ordered_time(arrived),
        s(value, "id")?
    ))
}
fn job_due_key(value: &Value) -> Result<Option<String>> {
    if !["queued", "retrying"].contains(&s(value, "state")?) {
        return Ok(None);
    }
    let partition = s(value, "delivery_partition")?;
    let owner = s(value, "delivery_owner")?;
    key(partition)?;
    key(owner)?;
    Ok(Some(format!(
        "job_due/{partition}/{:020}/{owner}/{:020}/{}",
        n(value, "delivery_term")?,
        ordered_time(
            value["due"]
                .as_i64()
                .ok_or_else(|| crate::error!("Invalid delivery due time"))?
        ),
        s(value, "id")?
    )))
}
fn remove_job_indexes(t: &mut Table, value: &Value) -> Result<()> {
    if let Some(key) = job_due_key(value)? {
        t.remove(key.as_str())?;
    }
    Ok(())
}
fn insert_job_indexes(t: &mut Table, value: &Value) -> Result<()> {
    if let Some(key) = job_due_key(value)? {
        let marker = pratique::json_value::to_vec(&json!({
            "id":s(value,"id")?,"due":value["due"]
        }))?;
        t.insert(key.as_str(), marker.as_slice())?;
    }
    Ok(())
}
fn remove_ingress_indexes(t: &mut Table, value: &Value) -> Result<()> {
    if let Some(key) = ingress_due_key(value)? {
        t.remove(key.as_str())?;
    }
    if value["state"] == "leased" {
        t.remove(format!("ingress_lease/{}", s(value, "id")?).as_str())?;
    }
    t.remove(ingress_arrival_key(value)?.as_str())?;
    Ok(())
}
fn insert_ingress_indexes(t: &mut Table, value: &Value) -> Result<()> {
    let marker = pratique::json_value::to_vec(&json!({
        "id":s(value,"id")?,"arrived":value["arrived"]
    }))?;
    if let Some(key) = ingress_due_key(value)? {
        t.insert(key.as_str(), marker.as_slice())?;
    }
    if value["state"] == "leased" {
        t.insert(
            format!("ingress_lease/{}", s(value, "id")?).as_str(),
            marker.as_slice(),
        )?;
    }
    t.insert(ingress_arrival_key(value)?.as_str(), marker.as_slice())?;
    Ok(())
}
pub fn put(t: &mut Table, key: &str, value: &Value) -> Result<()> {
    ensure!(!key.starts_with("audit/"), "Audit events are append-only");
    if key == CAPACITY_KEY {
        t.insert(key, pratique::json_value::to_vec(value)?.as_slice())?;
        return Ok(());
    }
    let old =
        if key.starts_with("message/") || key.starts_with("job/") || key.starts_with("ingress/") {
            get(t, key)?
        } else {
            None
        };
    if key.starts_with("ingress/")
        && let Some(old) = &old
    {
        remove_ingress_indexes(t, old)?;
    }
    if key.starts_with("job/")
        && let Some(old) = &old
    {
        remove_job_indexes(t, old)?;
    }
    t.insert(key, pratique::json_value::to_vec(value)?.as_slice())?;
    if key.starts_with("ingress/") {
        insert_ingress_indexes(t, value)?;
    }
    if key.starts_with("job/") {
        insert_job_indexes(t, value)?;
    }
    if let Some(old) = &old {
        adjust_status(t, key, old, -1)?;
    }
    adjust_status(t, key, value, 1)?;
    let old_usage = old.as_ref().map_or((0, 0), |old| record_usage(key, old));
    let new_usage = record_usage(key, value);
    adjust_capacity(t, new_usage.0 - old_usage.0, new_usage.1 - old_usage.1, 0)?;
    Ok(())
}
pub fn remove(t: &mut Table, key: &str) -> Result<()> {
    ensure!(!key.starts_with("audit/"), "Audit events are append-only");
    if key.starts_with("blob/") {
        let bytes = t.get(key)?.map_or(0, |value| value.value().len());
        t.remove(key)?;
        adjust_capacity(t, 0, 0, -(bytes as i128))?;
        return Ok(());
    }
    let old =
        if key.starts_with("message/") || key.starts_with("job/") || key.starts_with("ingress/") {
            get(t, key)?
        } else {
            None
        };
    if key.starts_with("ingress/")
        && let Some(old) = &old
    {
        remove_ingress_indexes(t, old)?;
    }
    if key.starts_with("job/")
        && let Some(old) = &old
    {
        remove_job_indexes(t, old)?;
    }
    t.remove(key)?;
    if let Some(old) = &old {
        adjust_status(t, key, old, -1)?;
    }
    let old_usage = old.as_ref().map_or((0, 0), |old| record_usage(key, old));
    adjust_capacity(t, -old_usage.0, -old_usage.1, 0)?;
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
fn raw_keys(t: &Table, prefix: &str) -> Result<Vec<String>> {
    let end = format!("{prefix}\u{10ffff}");
    let mut keys = Vec::new();
    for entry in t.range(prefix..end.as_str())? {
        keys.push(entry?.0.value().to_string());
    }
    Ok(keys)
}
pub fn blob(t: &mut Table, raw: &[u8]) -> Result<String> {
    let h = hash(raw);
    let key = format!("blob/{h}");
    let old_bytes = t.get(key.as_str())?.map_or(0, |value| value.value().len());
    t.insert(key.as_str(), raw)?;
    adjust_capacity(t, 0, 0, raw.len() as i128 - old_bytes as i128)?;
    Ok(h)
}

pub fn capacity_usage(t: &impl ReadableTable<&'static str, &'static [u8]>) -> Result<Value> {
    Ok(get(t, CAPACITY_KEY)?.unwrap_or_else(|| json!({"messages":0,"jobs":0,"bytes":0})))
}

pub fn state_counts(
    t: &impl ReadableTable<&'static str, &'static [u8]>,
    kind: &str,
) -> Result<Value> {
    key(kind)?;
    let prefix = format!("status/{kind}/");
    let mut counts = json!({});
    for (key, count) in keyed(t, &prefix)? {
        let state = key
            .strip_prefix(&prefix)
            .ok_or_else(|| crate::error!("Invalid durable status counter"))?;
        counts[state] = count;
    }
    Ok(counts)
}

pub fn ingress_recipient_count(t: &impl ReadableTable<&'static str, &'static [u8]>) -> Result<u64> {
    match get(t, "status/ingress_recipients")? {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| crate::error!("Invalid durable ingress recipient counter")),
        None => Ok(0),
    }
}

pub fn oldest_ingress_arrival(t: &Table) -> Result<Option<i64>> {
    let mut arrivals = t.range("ingress_arrival/".."ingress_arrival0")?;
    arrivals
        .next()
        .transpose()?
        .map(|(_, value)| {
            pratique::json_value::from_slice::<Value>(value.value())?["arrived"]
                .as_i64()
                .ok_or_else(|| crate::error!("Invalid indexed scan arrival"))
        })
        .transpose()
}

pub fn next_delivery_job(t: &Table, current_time: i64) -> Result<Option<Value>> {
    let local = super::cluster::node_id(t)?;
    let mut selected: Option<(i64, String)> = None;
    for ownership in list(t, "ownership/")? {
        if ownership["owner"] != local || ownership["state"] != "stable" {
            continue;
        }
        let partition = s(&ownership, "partition")?;
        let term = n(&ownership, "term")?;
        key(partition)?;
        let prefix = format!("job_due/{partition}/{term:020}/{local}/");
        let end = format!("{prefix}\u{10ffff}");
        let marker = {
            let mut due = t.range(prefix.as_str()..end.as_str())?;
            due.next()
                .transpose()?
                .map(|(index, marker)| -> Result<(String, Value)> {
                    Ok((
                        index.value().to_string(),
                        pratique::json_value::from_slice::<Value>(marker.value())?,
                    ))
                })
                .transpose()?
        };
        let Some((index, marker)) = marker else {
            continue;
        };
        let due = marker["due"]
            .as_i64()
            .ok_or_else(|| crate::error!("Invalid indexed delivery time"))?;
        if due > current_time {
            continue;
        }
        let id = s(&marker, "id")?.to_string();
        let job = must(t, &format!("job/{id}"))?;
        ensure!(
            job_due_key(&job)?.as_deref() == Some(index.as_str()),
            "Invalid durable delivery index"
        );
        ensure!(
            super::cluster::delivery_owned(t, &job)?,
            "Indexed delivery ownership mismatch"
        );
        if selected
            .as_ref()
            .is_none_or(|candidate| (due, &id) < (candidate.0, &candidate.1))
        {
            selected = Some((due, id));
        }
    }
    selected
        .map(|(_, id)| must(t, &format!("job/{id}")))
        .transpose()
}

pub fn rebuild_derived(t: &mut Table) -> Result<()> {
    let message_records = list(t, "message/")?;
    let job_records = list(t, "job/")?;
    let messages = message_records
        .iter()
        .map(|value| record_usage("message/", value).0 as u64)
        .try_fold(0u64, |total, value| {
            total
                .checked_add(value)
                .ok_or_else(|| crate::error!("Durable capacity ledger overflow"))
        })?;
    let jobs = job_records
        .iter()
        .map(|value| record_usage("job/", value).1 as u64)
        .try_fold(0u64, |total, value| {
            total
                .checked_add(value)
                .ok_or_else(|| crate::error!("Durable capacity ledger overflow"))
        })?;
    let ingress = list(t, "ingress/")?;
    let reserved = ingress
        .iter()
        .map(|value| record_usage("ingress/", value).0 as u64)
        .try_fold(0u64, |total, value| {
            total
                .checked_add(value)
                .ok_or_else(|| crate::error!("Durable capacity ledger overflow"))
        })?;
    let bytes = {
        let mut bytes = 0u64;
        for entry in t.range("blob/".."blob0")? {
            bytes = bytes
                .checked_add(entry?.1.value().len() as u64)
                .ok_or_else(|| crate::error!("Durable capacity ledger overflow"))?;
        }
        bytes
    };
    let total_messages = messages
        .checked_add(reserved)
        .ok_or_else(|| crate::error!("Durable capacity ledger overflow"))?;
    let total_jobs = jobs
        .checked_add(reserved)
        .ok_or_else(|| crate::error!("Durable capacity ledger overflow"))?;
    put(
        t,
        CAPACITY_KEY,
        &json!({"messages":total_messages,"jobs":total_jobs,"bytes":bytes}),
    )?;
    for prefix in [
        "ingress_due/",
        "ingress_lease/",
        "ingress_arrival/",
        "job_due/",
        "status/",
    ] {
        for key in raw_keys(t, prefix)? {
            t.remove(key.as_str())?;
        }
    }
    for value in &message_records {
        adjust_status(t, "message/", value, 1)?;
    }
    for value in &job_records {
        adjust_status(t, "job/", value, 1)?;
        insert_job_indexes(t, value)?;
    }
    for value in &ingress {
        adjust_status(t, "ingress/", value, 1)?;
        insert_ingress_indexes(t, value)?;
    }
    Ok(())
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
    let mut event = json!({"seq":seq,"at":now()?,"actor":actor,"action":action,"scope":scope,"data":data,"previous":previous});
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
        let metadata = super::cluster::local_delivery_metadata(t)?;
        let partition = data["delivery_partition"]
            .as_str()
            .or_else(|| metadata["delivery_partition"].as_str())
            .ok_or_else(|| crate::error!("Missing delivery partition"))?
            .to_string();
        let owner = data["delivery_owner"]
            .as_str()
            .or_else(|| metadata["delivery_owner"].as_str())
            .ok_or_else(|| crate::error!("Missing delivery owner"))?
            .to_string();
        let term = data["delivery_term"]
            .as_u64()
            .or_else(|| metadata["delivery_term"].as_u64())
            .ok_or_else(|| crate::error!("Missing delivery term"))?;
        put(
            t,
            &key,
            &json!({"id":id,"kind":kind,"state":"queued","due":now()?,"attempts":0,"error":"","data":data,"delivery_partition":partition,"delivery_owner":owner,"delivery_term":term}),
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
