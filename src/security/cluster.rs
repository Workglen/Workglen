//! Durable node identity, ordered replication state and ownership fencing.
use super::{db::*, model::*};
use crate::error::{Result, ensure};
use pratique::json_value::{Value, json};
use redb::ReadableTable;

pub const PROTOCOL_VERSION: u64 = 1;
pub const MIN_PROTOCOL_VERSION: u64 = 1;
const NODE_KEY: &str = "system/cluster_node";
const REPLICATION_CONFIG_KEY: &str = "system/replication_config";
const MAX_BATCH_OPERATIONS: usize = 64;
const MAX_BATCH_BYTES: usize = 32 * 1024 * 1024;
const MAX_STATE_OPERATION_BYTES: usize = 8 * 1024 * 1024;
const NODE_MODE_KEY: &str = "system/cluster_node_mode";

pub fn initialize(t: &mut Table, config: &Config) -> Result<()> {
    let identity = json!({
        "protocol":PROTOCOL_VERSION,
        "cluster_id":config.workspace,
        "node_id":config.instance,
        "placement_generation":1
    });
    if let Some(existing) = get(t, NODE_KEY)? {
        ensure!(existing == identity, "Cluster/node identity changed");
    } else {
        put(t, NODE_KEY, &identity)?;
    }
    let ownership_key = format!("ownership/{}", config.instance);
    if let Some(existing) = get(t, &ownership_key)? {
        ensure!(
            existing["partition"] == config.instance
                && existing["owner"] == config.instance
                && existing["term"].as_u64().is_some(),
            "Invalid durable delivery ownership"
        );
    } else {
        put(
            t,
            &ownership_key,
            &json!({
                "partition":config.instance,
                "owner":config.instance,
                "term":1,
                "state":"stable",
                "updated":now()?
            }),
        )?;
    }
    if let Some(replication) = &config.replication {
        let configured = json!({
            "peers":replication.peers.iter().map(|peer| peer.node_id.clone()).collect::<Vec<_>>(),
            "durable_copies":replication.durable_copies,
            "acknowledgement_timeout_seconds":replication.acknowledgement_timeout_seconds,
            "degraded_acceptance":replication.degraded_acceptance,
            "max_degraded_operations":replication.max_degraded_operations,
            "max_degraded_bytes":replication.max_degraded_bytes
        });
        if let Some(existing) = get(t, REPLICATION_CONFIG_KEY)? {
            ensure!(
                existing == configured,
                "Replication configuration changed; use an audited cluster reconfiguration procedure"
            );
        } else {
            put(t, REPLICATION_CONFIG_KEY, &configured)?;
        }
    } else {
        ensure!(
            get(t, REPLICATION_CONFIG_KEY)?.is_none_or(|existing| existing["test_only"] == true),
            "Replication cannot be disabled by removing configuration"
        );
    }
    if get(t, NODE_MODE_KEY)?.is_none() {
        put(
            t,
            NODE_MODE_KEY,
            &json!({
                "mode":"active",
                "acceptance_eligible":true,
                "scanner_eligible":true,
                "delivery_eligible":true,
                "updated":now()?
            }),
        )?;
    }
    Ok(())
}

pub fn node_id(t: &Table) -> Result<String> {
    Ok(s(&must(t, NODE_KEY)?, "node_id")?.to_string())
}

fn identity(t: &Table) -> Result<Value> {
    must(t, NODE_KEY)
}

fn ownership(t: &Table, partition: &str) -> Result<Value> {
    must(t, &format!("ownership/{partition}"))
}

pub fn stamp_ingress(t: &Table, record: &mut Value) -> Result<bool> {
    if record["origin_node"].as_str().is_some() {
        return Ok(false);
    }
    let node = node_id(t)?;
    let owner = ownership(t, &node)?;
    record["origin_node"] = json!(node);
    record["origin_sequence"] = json!(0);
    record["delivery_partition"] = owner["partition"].clone();
    record["delivery_owner"] = owner["owner"].clone();
    record["delivery_term"] = owner["term"].clone();
    record["scan_owner"] = owner["owner"].clone();
    record["scan_generation"] = json!(1);
    Ok(true)
}

pub fn local_delivery_metadata(t: &Table) -> Result<Value> {
    let node = node_id(t)?;
    let owner = ownership(t, &node)?;
    Ok(json!({
        "origin_node":node,
        "delivery_partition":owner["partition"],
        "delivery_owner":owner["owner"],
        "delivery_term":owner["term"],
        "scan_owner":node,
        "scan_generation":1
    }))
}

pub fn acceptance_eligible(t: &Table) -> Result<bool> {
    Ok(must(t, NODE_MODE_KEY)?["acceptance_eligible"] == true)
}

pub fn scanner_eligible(t: &Table) -> Result<bool> {
    Ok(must(t, NODE_MODE_KEY)?["scanner_eligible"] == true)
}

pub fn delivery_eligible(t: &Table) -> Result<bool> {
    Ok(must(t, NODE_MODE_KEY)?["delivery_eligible"] == true)
}

pub fn new_ingress_metadata(t: &mut Table) -> Result<Value> {
    let mut metadata = local_delivery_metadata(t)?;
    let replication_enabled = get(t, REPLICATION_CONFIG_KEY)?.is_some();
    let sequence = if replication_enabled {
        let next = get(t, "system/replication_origin_sequence")?
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| crate::error!("Replication origin sequence overflow"))?;
        put(t, "system/replication_origin_sequence", &json!(next))?;
        next
    } else {
        0
    };
    metadata["origin_sequence"] = json!(sequence);
    Ok(metadata)
}

pub fn record_acceptance(t: &mut Table, record: &Value) -> Result<()> {
    let sequence = n(record, "origin_sequence")?;
    if sequence == 0 {
        return Ok(());
    }
    let origin = s(record, "origin_node")?;
    ensure!(
        origin == node_id(t)?,
        "Only local acceptance can be exported"
    );
    let raw_bytes = u64::try_from(body(t, record)?.len())?;
    let record_bytes = u64::try_from(pratique::json_value::to_vec(record)?.len())?;
    let transfer_bytes = raw_bytes
        .checked_add(record_bytes)
        .ok_or_else(|| crate::error!("Replication byte counter overflow"))?;
    let state_key = format!("replication_out_state/{origin}");
    let previous = get(t, &state_key)?
        .unwrap_or_else(|| json!({"last_sequence":0,"cumulative_bytes":0,"oldest_at":null}));
    ensure!(
        n(&previous, "last_sequence")?
            .checked_add(1)
            .is_some_and(|next| next == sequence),
        "Replication outbox sequence gap"
    );
    let cumulative_bytes = n(&previous, "cumulative_bytes")?
        .checked_add(transfer_bytes)
        .ok_or_else(|| crate::error!("Replication byte counter overflow"))?;
    let accepted_at = now()?;
    put(
        t,
        &format!("replication_out/{origin}/{sequence:020}"),
        &json!({
            "protocol":PROTOCOL_VERSION,
            "cluster_id":identity(t)?["cluster_id"],
            "origin":origin,
            "sequence":sequence,
            "kind":"accept",
            "hash":record["hash"],
            "bytes":raw_bytes,
            "transfer_bytes":transfer_bytes,
            "cumulative_bytes":cumulative_bytes,
            "accepted_at":accepted_at,
            "record":record
        }),
    )?;
    put(
        t,
        &state_key,
        &json!({
            "last_sequence":sequence,
            "cumulative_bytes":cumulative_bytes,
            "oldest_at":if previous["last_sequence"] == 0 { json!(accepted_at) } else { previous["oldest_at"].clone() }
        }),
    )
}

pub fn export_acceptance(t: &Table, sequence: u64) -> Result<Option<(Value, Vec<u8>)>> {
    let origin = node_id(t)?;
    let Some(operation) = get(t, &format!("replication_out/{origin}/{sequence:020}"))? else {
        return Ok(None);
    };
    ensure!(
        operation["kind"] == "accept",
        "Unsupported replication operation"
    );
    let raw = body(t, &operation["record"])?;
    Ok(Some((operation, raw)))
}

pub fn export_batch(
    t: &Table,
    after_sequence: u64,
    max_operations: usize,
    max_bytes: usize,
) -> Result<Vec<(Value, Vec<u8>)>> {
    ensure!(
        (1..=MAX_BATCH_OPERATIONS).contains(&max_operations),
        "Invalid replication batch operation limit"
    );
    ensure!(
        (1..=MAX_BATCH_BYTES).contains(&max_bytes),
        "Invalid replication batch byte limit"
    );
    let mut sequence = after_sequence
        .checked_add(1)
        .ok_or_else(|| crate::error!("Replication sequence overflow"))?;
    let mut total_bytes = 0usize;
    let mut batch = Vec::new();
    while batch.len() < max_operations {
        let Some((operation, raw)) = export_acceptance(t, sequence)? else {
            break;
        };
        let operation_bytes = pratique::json_value::to_vec(&operation)?.len();
        let bytes = operation_bytes
            .checked_add(raw.len())
            .ok_or_else(|| crate::error!("Replication batch byte overflow"))?;
        if !batch.is_empty() && total_bytes.saturating_add(bytes) > max_bytes {
            break;
        }
        ensure!(
            bytes <= max_bytes,
            "Replication operation exceeds batch limit"
        );
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or_else(|| crate::error!("Replication batch byte overflow"))?;
        batch.push((operation, raw));
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| crate::error!("Replication sequence overflow"))?;
    }
    Ok(batch)
}

pub fn expected_sequence(t: &Table, origin: &str) -> Result<u64> {
    key(origin)?;
    get(t, &format!("replication_applied/{origin}"))?
        .and_then(|value| value.as_u64())
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| crate::error!("Replication sequence overflow"))
}

pub fn required_peers(t: &Table) -> Result<Vec<String>> {
    let Some(config) = get(t, REPLICATION_CONFIG_KEY)? else {
        return Ok(Vec::new());
    };
    arr(&config, "peers")?
        .iter()
        .map(|peer| {
            let peer = peer
                .as_str()
                .ok_or_else(|| crate::error!("Invalid replication peer"))?;
            key(peer)?;
            Ok(peer.to_string())
        })
        .collect()
}

pub fn enabled(t: &Table) -> Result<bool> {
    Ok(get(t, REPLICATION_CONFIG_KEY)?.is_some())
}

pub fn durable_copies(t: &Table) -> Result<u64> {
    Ok(get(t, REPLICATION_CONFIG_KEY)?
        .map(|config| n(&config, "durable_copies"))
        .transpose()?
        .unwrap_or(1))
}

pub fn acknowledgement_timeout(t: &Table) -> Result<u64> {
    Ok(get(t, REPLICATION_CONFIG_KEY)?
        .map(|config| n(&config, "acknowledgement_timeout_seconds"))
        .transpose()?
        .unwrap_or(0))
}

pub fn acceptance_acknowledged(t: &Table, sequence: u64) -> Result<bool> {
    if sequence == 0 {
        return Ok(true);
    }
    let origin = node_id(t)?;
    let mut copies = 1u64;
    for peer in required_peers(t)? {
        let acknowledged = get(t, &format!("replication_ack/{peer}/{origin}"))?
            .and_then(|value| value["sequence"].as_u64())
            .unwrap_or(0);
        if acknowledged >= sequence {
            copies = copies
                .checked_add(1)
                .ok_or_else(|| crate::error!("Replication copy count overflow"))?;
        }
    }
    Ok(copies >= durable_copies(t)?)
}

fn replication_debt(t: &Table) -> Result<(u64, u64)> {
    let origin = node_id(t)?;
    let out = get(t, &format!("replication_out_state/{origin}"))?
        .unwrap_or_else(|| json!({"last_sequence":0,"cumulative_bytes":0}));
    let tail_sequence = n(&out, "last_sequence")?;
    let tail_bytes = n(&out, "cumulative_bytes")?;
    let mut operations = 0u64;
    let mut bytes = 0u64;
    for peer in required_peers(t)? {
        let ack = get(t, &format!("replication_ack/{peer}/{origin}"))?
            .unwrap_or_else(|| json!({"sequence":0,"cumulative_bytes":0}));
        operations = operations
            .checked_add(tail_sequence.saturating_sub(n(&ack, "sequence")?))
            .ok_or_else(|| crate::error!("Replication debt overflow"))?;
        bytes = bytes
            .checked_add(tail_bytes.saturating_sub(n(&ack, "cumulative_bytes")?))
            .ok_or_else(|| crate::error!("Replication debt overflow"))?;
    }
    Ok((operations, bytes))
}

fn state_replication_debt(t: &Table) -> Result<(u64, u64)> {
    let origin = node_id(t)?;
    let out = get(t, &format!("replication_state_out_state/{origin}"))?
        .unwrap_or_else(|| json!({"last_sequence":0,"cumulative_bytes":0}));
    let tail_sequence = n(&out, "last_sequence")?;
    let tail_bytes = n(&out, "cumulative_bytes")?;
    let mut operations = 0u64;
    let mut bytes = 0u64;
    for peer in required_peers(t)? {
        let ack = get(t, &format!("replication_state_ack/{peer}/{origin}"))?
            .unwrap_or_else(|| json!({"sequence":0,"cumulative_bytes":0}));
        operations = operations
            .checked_add(tail_sequence.saturating_sub(n(&ack, "sequence")?))
            .ok_or_else(|| crate::error!("Replication state debt overflow"))?;
        bytes = bytes
            .checked_add(tail_bytes.saturating_sub(n(&ack, "cumulative_bytes")?))
            .ok_or_else(|| crate::error!("Replication state debt overflow"))?;
    }
    Ok((operations, bytes))
}

pub fn degraded_acceptance_allowed(t: &Table) -> Result<bool> {
    let Some(config) = get(t, REPLICATION_CONFIG_KEY)? else {
        return Ok(false);
    };
    if config["degraded_acceptance"] != true {
        return Ok(false);
    }
    let (operations, bytes) = replication_debt(t)?;
    Ok(operations <= n(&config, "max_degraded_operations")?
        && bytes <= n(&config, "max_degraded_bytes")?)
}

pub fn complete_acceptance(t: &mut Table, ids: &[String], degraded: bool) -> Result<()> {
    ensure!(!ids.is_empty(), "Missing replicated acceptance");
    for id in ids {
        key(id)?;
        let mut record = must(t, &format!("ingress/{id}"))?;
        ensure!(
            record["state"] == "awaiting-replication",
            "Acceptance is no longer waiting for replication"
        );
        let sequence = n(&record, "origin_sequence")?;
        ensure!(
            degraded || acceptance_acknowledged(t, sequence)?,
            "Required durable copies have not acknowledged the message"
        );
        record["state"] = json!("queued");
        record["due"] = json!(now()?);
        record["replication_degraded"] = json!(degraded);
        record["replication_ready_at"] = json!(now()?);
        put(t, &format!("ingress/{id}"), &record)?;
        audit(
            t,
            "replication",
            if degraded {
                "acceptance-degraded"
            } else {
                "acceptance-replicated"
            },
            "",
            json!({"ingress":id,"origin_sequence":sequence}),
        )?;
        record_ingress_state(t, id)?;
    }
    Ok(())
}

pub fn defer_acceptance(t: &mut Table, ids: &[String], reason: &str) -> Result<()> {
    ensure!(reason.len() <= 200, "Invalid replication failure reason");
    for id in ids {
        key(id)?;
        let mut record = must(t, &format!("ingress/{id}"))?;
        if record["state"] == "awaiting-replication" {
            let sequence = n(&record, "origin_sequence")?;
            record["state"] = json!("replication-deferred");
            record["error"] = json!(reason);
            put(t, &format!("ingress/{id}"), &record)?;
            put(
                t,
                &format!("replication_deferred/{sequence:020}/{id}"),
                &json!({"id":id,"origin_sequence":sequence}),
            )?;
            audit(
                t,
                "replication",
                "acceptance-not-acknowledged",
                "",
                json!({"ingress":id,"origin_sequence":record["origin_sequence"]}),
            )?;
        }
    }
    Ok(())
}

/// Retires messages that were deliberately not accepted by SMTP after their
/// acceptance record eventually reached the configured durable-copy quorum.
/// The original acceptance log and blob remain available for ordered replay;
/// a replicated tombstone prevents either node from later processing the mail.
pub fn retire_deferred_acceptances(t: &mut Table) -> Result<u64> {
    let local = node_id(t)?;
    let mut retired = 0u64;
    for (marker_key, marker) in keyed(t, "replication_deferred/")? {
        let id = s(&marker, "id")?;
        key(id)?;
        let sequence = n(&marker, "origin_sequence")?;
        if !acceptance_acknowledged(t, sequence)? {
            break;
        }
        let ingress = must(t, &format!("ingress/{id}"))?;
        ensure!(
            ingress["state"] == "replication-deferred"
                && ingress["origin_node"] == local
                && ingress["origin_sequence"] == sequence,
            "Invalid deferred acceptance retirement marker"
        );
        remove(t, &format!("ingress/{id}"))?;
        let state_sequence = record_ingress_state(t, id)?;
        remove(t, &marker_key)?;
        audit(
            t,
            "replication",
            "unaccepted-replica-retired",
            "",
            json!({
                "ingress":id,
                "origin_sequence":sequence,
                "state_sequence":state_sequence
            }),
        )?;
        retired = retired
            .checked_add(1)
            .ok_or_else(|| crate::error!("Deferred acceptance retirement overflow"))?;
    }
    Ok(retired)
}

pub fn acknowledge(t: &mut Table, peer: &str, sequence: u64) -> Result<u64> {
    key(peer)?;
    ensure!(
        required_peers(t)?.iter().any(|required| required == peer),
        "Replication peer is not configured"
    );
    let origin = node_id(t)?;
    let ack_key = format!("replication_ack/{peer}/{origin}");
    let current = get(t, &ack_key)?
        .and_then(|value| value["sequence"].as_u64())
        .unwrap_or(0);
    if sequence <= current {
        return Ok(current);
    }
    let operation = get(t, &format!("replication_out/{origin}/{sequence:020}"))?
        .ok_or_else(|| crate::error!("Replication acknowledgment exceeds local outbox"))?;
    let cumulative_bytes = n(&operation, "cumulative_bytes")?;
    put(
        t,
        &ack_key,
        &json!({
            "peer":peer,
            "origin":origin,
            "sequence":sequence,
            "cumulative_bytes":cumulative_bytes,
            "at":now()?
        }),
    )?;
    Ok(sequence)
}

fn next_state_sequence(t: &mut Table) -> Result<u64> {
    let next = get(t, "system/replication_state_sequence")?
        .and_then(|value| value.as_u64())
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| crate::error!("Replication state sequence overflow"))?;
    put(t, "system/replication_state_sequence", &json!(next))?;
    Ok(next)
}

fn append_state_operation(
    t: &mut Table,
    kind: &str,
    object_id: &str,
    payload: Value,
) -> Result<u64> {
    if !enabled(t)? {
        return Ok(0);
    }
    key(object_id)?;
    ensure!(
        ["ingress-state", "message-state", "ownership-state"].contains(&kind),
        "Invalid replicated state operation"
    );
    let origin = node_id(t)?;
    let sequence = next_state_sequence(t)?;
    let state_key = format!("replication_state_out_state/{origin}");
    let previous = get(t, &state_key)?
        .unwrap_or_else(|| json!({"last_sequence":0,"cumulative_bytes":0,"oldest_at":null}));
    ensure!(
        n(&previous, "last_sequence")?.saturating_add(1) == sequence,
        "Replication state outbox sequence gap"
    );
    let operation_hash = hash(&pratique::json_value::to_vec(&payload)?);
    let mut operation = json!({
        "protocol":PROTOCOL_VERSION,
        "cluster_id":identity(t)?["cluster_id"],
        "origin":origin,
        "sequence":sequence,
        "kind":kind,
        "object_id":object_id,
        "payload":payload,
        "hash":operation_hash,
        "created_at":now()?
    });
    let transfer_bytes = pratique::json_value::to_vec(&operation)?.len();
    ensure!(
        transfer_bytes <= MAX_STATE_OPERATION_BYTES,
        "Replicated state operation exceeds the bounded wire profile"
    );
    let cumulative_bytes = n(&previous, "cumulative_bytes")?
        .checked_add(u64::try_from(transfer_bytes)?)
        .ok_or_else(|| crate::error!("Replication state byte counter overflow"))?;
    operation["transfer_bytes"] = json!(transfer_bytes);
    operation["cumulative_bytes"] = json!(cumulative_bytes);
    put(
        t,
        &format!("replication_state_out/{origin}/{sequence:020}"),
        &operation,
    )?;
    put(
        t,
        &state_key,
        &json!({
            "last_sequence":sequence,
            "cumulative_bytes":cumulative_bytes,
            "oldest_at":if previous["last_sequence"] == 0 { operation["created_at"].clone() } else { previous["oldest_at"].clone() }
        }),
    )?;
    Ok(sequence)
}

pub fn record_ingress_state(t: &mut Table, ingress_id: &str) -> Result<u64> {
    if !enabled(t)? {
        return Ok(0);
    }
    key(ingress_id)?;
    let ingress = get(t, &format!("ingress/{ingress_id}"))?;
    if let Some(record) = &ingress {
        let local = node_id(t)?;
        ensure!(
            record["origin_node"] == local || record["scan_owner"] == local,
            "Only an authoritative ingress owner may replicate state"
        );
    }
    append_state_operation(t, "ingress-state", ingress_id, json!({"ingress":ingress}))
}

pub fn record_message_state(t: &mut Table, message_id: &str) -> Result<u64> {
    if !enabled(t)? {
        return Ok(0);
    }
    key(message_id)?;
    let message = get(t, &format!("message/{message_id}"))?;
    if let Some(record) = &message {
        let local = node_id(t)?;
        ensure!(
            record["origin_node"] == local
                || record["scan_owner"] == local
                || record["delivery_owner"] == local,
            "Only an authoritative message owner may replicate state"
        );
    }
    let jobs = list(t, "job/")?
        .into_iter()
        .filter(|job| job["data"]["message"] == message_id)
        .collect::<Vec<_>>();
    ensure!(jobs.len() <= 16, "Too many jobs for one replicated message");
    append_state_operation(
        t,
        "message-state",
        message_id,
        json!({"message":message,"jobs":jobs}),
    )
}

pub fn record_ownership_state(t: &mut Table, partition: &str) -> Result<u64> {
    if !enabled(t)? {
        return Ok(0);
    }
    key(partition)?;
    let ownership = must(t, &format!("ownership/{partition}"))?;
    append_state_operation(
        t,
        "ownership-state",
        partition,
        json!({"ownership":ownership}),
    )
}

fn rewrite_partition_owner(t: &mut Table, partition: &str, owner: &str, term: u64) -> Result<()> {
    for mut ingress in list(t, "ingress/")? {
        if ingress["delivery_partition"] == partition {
            ingress["delivery_owner"] = json!(owner);
            ingress["delivery_term"] = json!(term);
            put(t, &format!("ingress/{}", s(&ingress, "id")?), &ingress)?;
        }
    }
    for mut message in list(t, "message/")? {
        if message["delivery_partition"] == partition {
            message["delivery_owner"] = json!(owner);
            message["delivery_term"] = json!(term);
            save_message(t, &message)?;
        }
    }
    for mut job in list(t, "job/")? {
        if job["delivery_partition"] == partition {
            job["delivery_owner"] = json!(owner);
            job["delivery_term"] = json!(term);
            job["data"]["delivery_owner"] = json!(owner);
            job["data"]["delivery_term"] = json!(term);
            put(t, &format!("job/{}", s(&job, "id")?), &job)?;
        }
    }
    Ok(())
}

pub fn begin_drain(
    t: &mut Table,
    actor: &str,
    partition: &str,
    new_owner: &str,
    expected_term: u64,
) -> Result<Value> {
    key(partition)?;
    key(new_owner)?;
    let local = node_id(t)?;
    ensure!(
        partition == local,
        "Only the local origin partition can be drained here"
    );
    ensure!(
        required_peers(t)?.iter().any(|peer| peer == new_owner),
        "Handoff target is not a configured replication peer"
    );
    let mut current = ownership(t, partition)?;
    ensure!(
        current["owner"] == local
            && current["state"] == "stable"
            && n(&current, "term")? == expected_term,
        "Ownership changed; refresh cluster state"
    );
    let pending_term = expected_term
        .checked_add(1)
        .ok_or_else(|| crate::error!("Ownership term overflow"))?;
    current["state"] = json!("draining");
    current["pending_owner"] = json!(new_owner);
    current["pending_term"] = json!(pending_term);
    current["updated"] = json!(now()?);
    put(t, &format!("ownership/{partition}"), &current)?;
    let mut mode = must(t, NODE_MODE_KEY)?;
    mode["mode"] = json!("draining");
    mode["acceptance_eligible"] = json!(false);
    mode["updated"] = json!(now()?);
    put(t, NODE_MODE_KEY, &mode)?;
    let sequence = record_ownership_state(t, partition)?;
    current["drain_state_sequence"] = json!(sequence);
    put(t, &format!("ownership/{partition}"), &current)?;
    audit(
        t,
        actor,
        "cluster-drain",
        "",
        json!({"partition":partition,"owner":local,"term":expected_term,"pending_owner":new_owner,"pending_term":pending_term,"state_sequence":sequence}),
    )?;
    Ok(current)
}

pub fn complete_handoff(
    t: &mut Table,
    actor: &str,
    partition: &str,
    new_owner: &str,
    expected_term: u64,
) -> Result<Value> {
    key(partition)?;
    key(new_owner)?;
    let local = node_id(t)?;
    let current = ownership(t, partition)?;
    ensure!(
        current["owner"] == local
            && current["state"] == "draining"
            && current["pending_owner"] == new_owner
            && current["pending_term"] == expected_term,
        "Planned handoff state changed"
    );
    ensure!(
        state_acknowledged(t, n(&current, "drain_state_sequence")?)?,
        "Drain state has not been acknowledged by the required replica set"
    );
    ensure!(
        !list(t, "job/")?
            .iter()
            .any(|job| { job["delivery_partition"] == partition && job["state"] == "running" }),
        "A downstream delivery is still running"
    );
    rewrite_partition_owner(t, partition, new_owner, expected_term)?;
    let next = json!({
        "partition":partition,
        "owner":new_owner,
        "term":expected_term,
        "state":"stable",
        "updated":now()?,
        "previous_owner":local
    });
    put(t, &format!("ownership/{partition}"), &next)?;
    let sequence = record_ownership_state(t, partition)?;
    audit(
        t,
        actor,
        "cluster-handoff",
        "",
        json!({"partition":partition,"previous_owner":local,"owner":new_owner,"term":expected_term,"state_sequence":sequence}),
    )?;
    Ok(json!({"ownership":next,"state_sequence":sequence}))
}

pub fn cancel_handoff(
    t: &mut Table,
    actor: &str,
    partition: &str,
    expected_owner: &str,
    expected_term: u64,
    expected_pending_owner: &str,
    expected_pending_term: u64,
) -> Result<Value> {
    key(partition)?;
    key(expected_owner)?;
    key(expected_pending_owner)?;
    let local = node_id(t)?;
    let current = ownership(t, partition)?;
    ensure!(
        expected_owner == local
            && current["owner"] == expected_owner
            && current["term"] == expected_term
            && current["state"] == "draining"
            && current["pending_owner"] == expected_pending_owner
            && current["pending_term"] == expected_pending_term,
        "Planned handoff state changed; refresh cluster state"
    );

    let next = json!({
        "partition":partition,
        "owner":local,
        "term":expected_term,
        "state":"stable",
        "updated":now()?,
        "cancelled_pending_owner":expected_pending_owner,
        "cancelled_pending_term":expected_pending_term
    });
    put(t, &format!("ownership/{partition}"), &next)?;
    let sequence = record_ownership_state(t, partition)?;

    let mut mode = must(t, NODE_MODE_KEY)?;
    mode["mode"] = json!("active");
    mode["acceptance_eligible"] = json!(true);
    mode["updated"] = json!(now()?);
    put(t, NODE_MODE_KEY, &mode)?;
    audit(
        t,
        actor,
        "cluster-handoff-cancel",
        "",
        json!({
            "partition":partition,
            "owner":local,
            "term":expected_term,
            "cancelled_pending_owner":expected_pending_owner,
            "cancelled_pending_term":expected_pending_term,
            "state_sequence":sequence
        }),
    )?;
    Ok(json!({"ownership":next,"node_mode":mode,"state_sequence":sequence}))
}

pub fn operator_takeover(
    t: &mut Table,
    actor: &str,
    partition: &str,
    expected_term: u64,
) -> Result<Value> {
    key(partition)?;
    let local = node_id(t)?;
    let current = ownership(t, partition)?;
    ensure!(
        current["owner"] != local && n(&current, "term")? == expected_term,
        "Ownership changed or is already local"
    );
    let next_term = expected_term
        .checked_add(1)
        .ok_or_else(|| crate::error!("Ownership term overflow"))?;
    rewrite_partition_owner(t, partition, &local, next_term)?;
    let next = json!({
        "partition":partition,
        "owner":local,
        "term":next_term,
        "state":"stable",
        "updated":now()?,
        "fenced_owner":current["owner"],
        "operator_takeover":true
    });
    put(t, &format!("ownership/{partition}"), &next)?;
    let sequence = record_ownership_state(t, partition)?;
    audit(
        t,
        actor,
        "cluster-takeover",
        "",
        json!({"partition":partition,"fenced_owner":current["owner"],"owner":local,"term":next_term,"state_sequence":sequence,"risk_acknowledged":true}),
    )?;
    Ok(json!({"ownership":next,"state_sequence":sequence}))
}

pub fn rejoin(t: &mut Table, actor: &str) -> Result<Value> {
    let (operations, bytes) = replication_debt(t)?;
    let (state_operations, state_bytes) = state_replication_debt(t)?;
    ensure!(
        operations == 0 && bytes == 0 && state_operations == 0 && state_bytes == 0,
        "Acceptance and state replication debt must be zero before rejoin"
    );
    let mut mode = must(t, NODE_MODE_KEY)?;
    mode["mode"] = json!("active");
    mode["acceptance_eligible"] = json!(true);
    mode["scanner_eligible"] = json!(true);
    mode["delivery_eligible"] = json!(true);
    mode["updated"] = json!(now()?);
    put(t, NODE_MODE_KEY, &mode)?;
    audit(t, actor, "cluster-rejoin", "", json!({"node":node_id(t)?}))?;
    Ok(mode)
}

pub fn begin_resync(t: &mut Table, actor: &str, peer: &str) -> Result<Value> {
    key(peer)?;
    ensure!(
        required_peers(t)?
            .iter()
            .any(|configured| configured == peer),
        "Resync target is not a configured peer"
    );
    let origin = node_id(t)?;
    remove(t, &format!("replication_ack/{peer}/{origin}"))?;
    remove(t, &format!("replication_state_ack/{peer}/{origin}"))?;
    let mut mode = must(t, NODE_MODE_KEY)?;
    mode["mode"] = json!("resynchronizing");
    mode["acceptance_eligible"] = json!(false);
    mode["updated"] = json!(now()?);
    mode["resync_peer"] = json!(peer);
    put(t, NODE_MODE_KEY, &mode)?;
    audit(
        t,
        actor,
        "cluster-resync",
        "",
        json!({"node":origin,"peer":peer,"acceptance_paused":true,"bootstrap":"ordered-log-replay"}),
    )?;
    Ok(mode)
}

pub fn export_state_batch(
    t: &Table,
    after_sequence: u64,
    max_operations: usize,
    max_bytes: usize,
) -> Result<Vec<Value>> {
    ensure!(
        (1..=MAX_BATCH_OPERATIONS).contains(&max_operations),
        "Invalid replication state batch operation limit"
    );
    ensure!(
        (1..=MAX_BATCH_BYTES).contains(&max_bytes),
        "Invalid replication state batch byte limit"
    );
    let origin = node_id(t)?;
    let mut sequence = after_sequence
        .checked_add(1)
        .ok_or_else(|| crate::error!("Replication state sequence overflow"))?;
    let mut bytes = 0usize;
    let mut batch = Vec::new();
    while batch.len() < max_operations {
        let Some(operation) = get(t, &format!("replication_state_out/{origin}/{sequence:020}"))?
        else {
            break;
        };
        let operation_bytes = pratique::json_value::to_vec(&operation)?.len();
        if !batch.is_empty() && bytes.saturating_add(operation_bytes) > max_bytes {
            break;
        }
        ensure!(
            operation_bytes <= max_bytes,
            "Replication state operation exceeds batch limit"
        );
        bytes = bytes
            .checked_add(operation_bytes)
            .ok_or_else(|| crate::error!("Replication state batch byte overflow"))?;
        batch.push(operation);
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| crate::error!("Replication state sequence overflow"))?;
    }
    Ok(batch)
}

pub fn expected_state_sequence(t: &Table, origin: &str) -> Result<u64> {
    key(origin)?;
    get(t, &format!("replication_state_applied/{origin}"))?
        .and_then(|value| value.as_u64())
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| crate::error!("Replication state sequence overflow"))
}

pub fn acknowledge_state(t: &mut Table, peer: &str, sequence: u64) -> Result<u64> {
    key(peer)?;
    ensure!(
        required_peers(t)?.iter().any(|required| required == peer),
        "Replication peer is not configured"
    );
    let origin = node_id(t)?;
    let ack_key = format!("replication_state_ack/{peer}/{origin}");
    let current = get(t, &ack_key)?
        .and_then(|value| value["sequence"].as_u64())
        .unwrap_or(0);
    if sequence <= current {
        return Ok(current);
    }
    let operation = get(t, &format!("replication_state_out/{origin}/{sequence:020}"))?
        .ok_or_else(|| crate::error!("Replication state acknowledgment exceeds local outbox"))?;
    put(
        t,
        &ack_key,
        &json!({
            "peer":peer,
            "origin":origin,
            "sequence":sequence,
            "cumulative_bytes":operation["cumulative_bytes"],
            "at":now()?
        }),
    )?;
    Ok(sequence)
}

pub fn state_acknowledged(t: &Table, sequence: u64) -> Result<bool> {
    if sequence == 0 {
        return Ok(true);
    }
    let origin = node_id(t)?;
    let mut copies = 1u64;
    for peer in required_peers(t)? {
        let acknowledged = get(t, &format!("replication_state_ack/{peer}/{origin}"))?
            .and_then(|value| value["sequence"].as_u64())
            .unwrap_or(0);
        if acknowledged >= sequence {
            copies += 1;
        }
    }
    Ok(copies >= durable_copies(t)?)
}

pub fn apply_state(t: &mut Table, operation: &Value) -> Result<u64> {
    ensure!(
        operation["protocol"] == PROTOCOL_VERSION,
        "Replication state protocol mismatch"
    );
    let local = identity(t)?;
    ensure!(
        operation["cluster_id"] == local["cluster_id"],
        "Replication state cluster mismatch"
    );
    let origin = s(operation, "origin")?;
    key(origin)?;
    ensure!(
        origin != s(&local, "node_id")?,
        "Replication state loop refused"
    );
    let sequence = n(operation, "sequence")?;
    let payload = &operation["payload"];
    ensure!(
        operation["hash"] == hash(&pratique::json_value::to_vec(payload)?),
        "Replication state hash mismatch"
    );
    let applied_key = format!("replication_state_applied/{origin}");
    let applied = get(t, &applied_key)?
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    if sequence <= applied {
        let seen = must(
            t,
            &format!("replication_state_seen/{origin}/{sequence:020}"),
        )?;
        ensure!(
            seen == operation["hash"],
            "Replication state replay conflict"
        );
        return Ok(applied);
    }
    ensure!(sequence == applied + 1, "Replication state sequence gap");
    let object_id = s(operation, "object_id")?;
    key(object_id)?;
    match s(operation, "kind")? {
        "ingress-state" => {
            if payload["ingress"].is_null() {
                remove(t, &format!("ingress/{object_id}"))?;
            } else {
                let ingress = &payload["ingress"];
                ensure!(
                    ingress["id"] == object_id
                        && (ingress["origin_node"] == origin || ingress["scan_owner"] == origin),
                    "Replicated ingress state identity mismatch"
                );
                ensure!(
                    t.get(format!("blob/{}", s(ingress, "hash")?).as_str())?
                        .is_some(),
                    "Replicated ingress state is missing content"
                );
                put(t, &format!("ingress/{object_id}"), ingress)?;
            }
        }
        "message-state" => {
            if payload["message"].is_null() {
                remove(t, &format!("message/{object_id}"))?;
            } else {
                let message = &payload["message"];
                ensure!(
                    message["id"] == object_id
                        && (message["origin_node"] == origin
                            || message["scan_owner"] == origin
                            || message["delivery_owner"] == origin),
                    "Replicated message state identity mismatch"
                );
                ensure!(
                    t.get(format!("blob/{}", s(message, "hash")?).as_str())?
                        .is_some(),
                    "Replicated message state is missing content"
                );
                save_message(t, message)?;
            }
            let jobs = arr(payload, "jobs")?;
            ensure!(jobs.len() <= 16, "Too many replicated message jobs");
            let incoming_ids = jobs
                .iter()
                .map(|job| s(job, "id"))
                .collect::<Result<std::collections::BTreeSet<_>>>()?;
            for job in list(t, "job/")? {
                if job["data"]["message"] == object_id && !incoming_ids.contains(s(&job, "id")?) {
                    remove(t, &format!("job/{}", s(&job, "id")?))?;
                }
            }
            for job in jobs {
                ensure!(
                    job["data"]["message"] == object_id,
                    "Replicated job identity mismatch"
                );
                put(t, &format!("job/{}", s(job, "id")?), job)?;
            }
        }
        "ownership-state" => {
            let incoming = &payload["ownership"];
            ensure!(
                incoming["partition"] == object_id,
                "Replicated ownership identity mismatch"
            );
            let incoming_term = n(incoming, "term")?;
            if let Some(current) = get(t, &format!("ownership/{object_id}"))? {
                let current_term = n(&current, "term")?;
                ensure!(
                    incoming_term >= current_term,
                    "Stale replicated ownership term"
                );
                if incoming_term == current_term {
                    ensure!(
                        current["owner"] == incoming["owner"]
                            || (current["owner"] == origin && incoming["state"] == "draining"),
                        "Conflicting replicated ownership term"
                    );
                } else {
                    ensure!(
                        current["owner"] == origin
                            || incoming["owner"] == origin
                            || current["state"] == "draining",
                        "Unauthorized replicated ownership transition"
                    );
                }
            }
            rewrite_partition_owner(t, object_id, s(incoming, "owner")?, incoming_term)?;
            put(t, &format!("ownership/{object_id}"), incoming)?;
        }
        _ => crate::bail!("Unsupported replication state operation"),
    }
    put(t, &applied_key, &json!(sequence))?;
    put(
        t,
        &format!("replication_state_seen/{origin}/{sequence:020}"),
        &operation["hash"],
    )?;
    audit(
        t,
        "replication",
        "replica-state-applied",
        "",
        json!({"origin":origin,"sequence":sequence,"kind":operation["kind"],"object_id":object_id}),
    )?;
    Ok(sequence)
}

pub fn rebuild_replication_state(t: &mut Table) -> Result<()> {
    let origin = node_id(t)?;
    let operations = list(t, &format!("replication_out/{origin}/"))?;
    let mut last_sequence = 0u64;
    let mut cumulative_bytes = 0u64;
    let mut oldest_at = Value::Null;
    for operation in operations {
        let sequence = n(&operation, "sequence")?;
        let expected_sequence = last_sequence
            .checked_add(1)
            .ok_or_else(|| crate::error!("Replication sequence overflow"))?;
        ensure!(
            operation["origin"] == origin && sequence == expected_sequence,
            "Invalid replication outbox sequence"
        );
        let operation_cumulative = n(&operation, "cumulative_bytes")?;
        let expected_cumulative = cumulative_bytes
            .checked_add(n(&operation, "transfer_bytes")?)
            .ok_or_else(|| crate::error!("Replication byte counter overflow"))?;
        ensure!(
            operation_cumulative == expected_cumulative,
            "Invalid replication outbox byte counter"
        );
        if last_sequence == 0 {
            oldest_at = operation["accepted_at"].clone();
        }
        last_sequence = sequence;
        cumulative_bytes = operation_cumulative;
    }
    let state_key = format!("replication_out_state/{origin}");
    if last_sequence == 0 {
        remove(t, &state_key)?;
    } else {
        put(
            t,
            &state_key,
            &json!({
                "last_sequence":last_sequence,
                "cumulative_bytes":cumulative_bytes,
                "oldest_at":oldest_at
            }),
        )?;
    }
    Ok(())
}

pub fn apply_acceptance(t: &mut Table, operation: &Value, raw: &[u8]) -> Result<u64> {
    ensure!(
        operation["protocol"] == PROTOCOL_VERSION && operation["kind"] == "accept",
        "Replication protocol mismatch"
    );
    let local = identity(t)?;
    ensure!(
        operation["cluster_id"] == local["cluster_id"],
        "Replication cluster mismatch"
    );
    let origin = s(operation, "origin")?;
    key(origin)?;
    ensure!(origin != s(&local, "node_id")?, "Replication loop refused");
    let sequence = n(operation, "sequence")?;
    ensure!(sequence > 0, "Invalid replication sequence");
    ensure!(
        operation["bytes"].as_u64() == Some(raw.len() as u64) && operation["hash"] == hash(raw),
        "Replicated content hash or length mismatch"
    );
    let record = &operation["record"];
    ensure!(
        record["origin_node"] == origin
            && record["origin_sequence"] == sequence
            && record["hash"] == operation["hash"],
        "Replicated acceptance identity mismatch"
    );
    let applied_key = format!("replication_applied/{origin}");
    let applied = get(t, &applied_key)?
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let receipt_key = format!("replication_seen/{origin}/{sequence:020}");
    let operation_hash = hash(&pratique::json_value::to_vec(operation)?);
    if sequence <= applied {
        if let Some(receipt) = get(t, &receipt_key)? {
            ensure!(
                receipt.as_str() == Some(&operation_hash),
                "Replicated acceptance replay conflict"
            );
        } else {
            // Upgrade compatibility for an acceptance applied before immutable
            // replay receipts existed. A still-live record can safely seed it;
            // a tombstoned record fails closed and requires operator resync.
            let existing = must(t, &format!("ingress/{}", s(record, "id")?))?;
            ensure!(
                existing["hash"] == record["hash"]
                    && existing["origin_node"] == origin
                    && existing["origin_sequence"] == sequence,
                "Replicated acceptance replay conflict"
            );
            put(t, &receipt_key, &json!(operation_hash))?;
        }
        return Ok(applied);
    }
    ensure!(sequence == applied + 1, "Replication sequence gap");
    let partition = s(record, "delivery_partition")?;
    ensure!(
        partition == origin,
        "Initial delivery partition must match origin"
    );
    let ownership_key = format!("ownership/{partition}");
    if let Some(existing) = get(t, &ownership_key)? {
        ensure!(
            existing["owner"] == record["delivery_owner"]
                && existing["term"] == record["delivery_term"],
            "Replicated delivery ownership conflict"
        );
    } else {
        put(
            t,
            &ownership_key,
            &json!({
                "partition":partition,
                "owner":record["delivery_owner"],
                "term":record["delivery_term"],
                "state":"stable",
                "updated":now()?
            }),
        )?;
    }
    let ingress_key = format!("ingress/{}", s(record, "id")?);
    ensure!(
        get(t, &ingress_key)?.is_none(),
        "Replicated acceptance ID conflict"
    );
    ensure!(
        blob(t, raw)? == s(record, "hash")?,
        "Replicated blob hash mismatch"
    );
    put(t, &ingress_key, record)?;
    put(t, &receipt_key, &json!(operation_hash))?;
    put(t, &applied_key, &json!(sequence))?;
    audit(
        t,
        "replication",
        "replica-accepted",
        "",
        json!({"origin":origin,"sequence":sequence,"ingress":record["id"],"hash":record["hash"]}),
    )?;
    Ok(sequence)
}

#[cfg(test)]
pub fn enable_replication(t: &mut Table, peers: &[String]) -> Result<()> {
    ensure!(
        !peers.is_empty(),
        "At least one replication peer is required"
    );
    let local = node_id(t)?;
    let mut unique = std::collections::BTreeSet::new();
    for peer in peers {
        key(peer)?;
        ensure!(peer != &local, "Replication peer cannot be local node");
        ensure!(unique.insert(peer.clone()), "Duplicate replication peer");
    }
    put(
        t,
        REPLICATION_CONFIG_KEY,
        &json!({
            "peers":unique.into_iter().collect::<Vec<_>>(),
            "durable_copies":2,
            "acknowledgement_timeout_seconds":1,
            "degraded_acceptance":false,
            "max_degraded_operations":0,
            "max_degraded_bytes":0,
            "test_only":true
        }),
    )
}

pub fn scan_owned(t: &Table, record: &Value) -> Result<bool> {
    let local = node_id(t)?;
    Ok(record["scan_owner"].as_str().unwrap_or(&local) == local)
}

pub fn delivery_owned(t: &Table, record: &Value) -> Result<bool> {
    let local = node_id(t)?;
    let partition = record["delivery_partition"].as_str().unwrap_or(&local);
    let owner = ownership(t, partition)?;
    let record_owner = record["delivery_owner"].as_str().unwrap_or(&local);
    let record_term = record["delivery_term"]
        .as_u64()
        .unwrap_or_else(|| owner["term"].as_u64().unwrap_or(0));
    Ok(owner["owner"] == local
        && owner["owner"] == record_owner
        && owner["term"].as_u64() == Some(record_term)
        && owner["state"] == "stable")
}

pub fn status(t: &Table, accepting: bool) -> Result<Value> {
    let node = must(t, NODE_KEY)?;
    let node_id = s(&node, "node_id")?;
    let partitions = list(t, "ownership/")?;
    let owned: Vec<Value> = partitions
        .iter()
        .filter(|ownership| ownership["owner"] == node_id)
        .cloned()
        .collect();
    let out = get(t, &format!("replication_out_state/{node_id}"))?
        .unwrap_or_else(|| json!({"last_sequence":0,"cumulative_bytes":0,"oldest_at":null}));
    let tail_sequence = n(&out, "last_sequence")?;
    let tail_bytes = n(&out, "cumulative_bytes")?;
    let state_out = get(t, &format!("replication_state_out_state/{node_id}"))?
        .unwrap_or_else(|| json!({"last_sequence":0,"cumulative_bytes":0,"oldest_at":null}));
    let state_tail_sequence = n(&state_out, "last_sequence")?;
    let state_tail_bytes = n(&state_out, "cumulative_bytes")?;
    let mut peers = Vec::new();
    let mut debt_operations = 0u64;
    let mut debt_bytes = 0u64;
    let mut oldest_seconds: Option<u64> = None;
    for peer in required_peers(t)? {
        let ack = get(t, &format!("replication_ack/{peer}/{node_id}"))?
            .unwrap_or_else(|| json!({"sequence":0,"cumulative_bytes":0,"at":null}));
        let acknowledged = n(&ack, "sequence")?;
        let acknowledged_bytes = n(&ack, "cumulative_bytes")?;
        ensure!(
            acknowledged <= tail_sequence && acknowledged_bytes <= tail_bytes,
            "Invalid replication acknowledgment state"
        );
        if acknowledged == 0 {
            ensure!(
                acknowledged_bytes == 0,
                "Invalid replication acknowledgment byte position"
            );
        } else {
            let operation = must(t, &format!("replication_out/{node_id}/{acknowledged:020}"))?;
            ensure!(
                operation["cumulative_bytes"].as_u64() == Some(acknowledged_bytes),
                "Invalid replication acknowledgment byte position"
            );
        }
        let lag_operations = tail_sequence - acknowledged;
        let lag_bytes = tail_bytes - acknowledged_bytes;
        let state_ack = get(t, &format!("replication_state_ack/{peer}/{node_id}"))?
            .unwrap_or_else(|| json!({"sequence":0,"cumulative_bytes":0,"at":null}));
        let state_acknowledged = n(&state_ack, "sequence")?;
        let state_acknowledged_bytes = n(&state_ack, "cumulative_bytes")?;
        ensure!(
            state_acknowledged <= state_tail_sequence
                && state_acknowledged_bytes <= state_tail_bytes,
            "Invalid replication state acknowledgment"
        );
        let outbound_health = get(t, &format!("replication_peer_health/{peer}/outbound"))?;
        let inbound_health = get(t, &format!("replication_peer_health/{peer}/inbound"))?;
        debt_operations = debt_operations
            .checked_add(lag_operations)
            .ok_or_else(|| crate::error!("Replication debt overflow"))?;
        debt_bytes = debt_bytes
            .checked_add(lag_bytes)
            .ok_or_else(|| crate::error!("Replication debt overflow"))?;
        if lag_operations > 0 {
            let next_sequence = acknowledged
                .checked_add(1)
                .ok_or_else(|| crate::error!("Replication sequence overflow"))?;
            let next = must(t, &format!("replication_out/{node_id}/{next_sequence:020}"))?;
            let oldest = next["accepted_at"]
                .as_i64()
                .ok_or_else(|| crate::error!("Invalid replication operation time"))?;
            let age = now()?.saturating_sub(oldest).max(0) as u64;
            oldest_seconds = Some(oldest_seconds.unwrap_or(0).max(age));
        }
        peers.push(json!({
            "node_id":peer,
            "acknowledged_sequence":acknowledged,
            "outbound_sequence":tail_sequence,
            "lag_operations":lag_operations,
            "lag_bytes":lag_bytes,
            "last_acknowledged_at":ack["at"],
            "state_acknowledged_sequence":state_acknowledged,
            "state_outbound_sequence":state_tail_sequence,
            "state_lag_operations":state_tail_sequence-state_acknowledged,
            "state_lag_bytes":state_tail_bytes-state_acknowledged_bytes,
            "last_state_acknowledged_at":state_ack["at"],
            "outbound_health":outbound_health,
            "inbound_health":inbound_health
        }));
    }
    let inbound: Vec<Value> = keyed(t, "replication_applied/")?
        .into_iter()
        .map(|(key, sequence)| {
            json!({
                "origin":key.strip_prefix("replication_applied/").unwrap_or(""),
                "applied_sequence":sequence
            })
        })
        .collect();
    let mode = must(t, NODE_MODE_KEY)?;
    let configured = !required_peers(t)?.is_empty();
    let state_debt_operations = peers
        .iter()
        .map(|peer| peer["state_lag_operations"].as_u64().unwrap_or(0))
        .sum::<u64>();
    let state_debt_bytes = peers
        .iter()
        .map(|peer| peer["state_lag_bytes"].as_u64().unwrap_or(0))
        .sum::<u64>();
    let current = now()?;
    let synchronized = configured
        && debt_operations == 0
        && state_debt_operations == 0
        && peers.iter().all(|peer| {
            ["outbound_health", "inbound_health"]
                .iter()
                .all(|direction| {
                    let health = &peer[*direction];
                    health["ok"] == true
                        && health["at"]
                            .as_i64()
                            .is_some_and(|at| (0..=30).contains(&current.saturating_sub(at)))
                })
        });
    Ok(json!({
        "protocol_version":PROTOCOL_VERSION,
        "minimum_protocol_version":MIN_PROTOCOL_VERSION,
        "cluster_id":node["cluster_id"],
        "node_id":node_id,
        "topology":if configured { "authenticated-peer-log" } else { "standalone-foundation" },
        "synchronized":synchronized,
        "placement_generation":node["placement_generation"],
        "accepting":accepting && mode["acceptance_eligible"] == true,
        "node_mode":mode,
        "scanner_eligible":mode["scanner_eligible"],
        "delivery_eligible":mode["delivery_eligible"],
        "partitions":partitions,
        "owned_partitions":owned,
        "peers":peers,
        "inbound":inbound,
        "replication_debt":{"operations":debt_operations,"bytes":debt_bytes,"oldest_seconds":oldest_seconds},
        "state_replication_debt":{"operations":state_debt_operations,"bytes":state_debt_bytes},
        "health":if configured { "peer-transport" } else { "foundation" }
    }))
}
