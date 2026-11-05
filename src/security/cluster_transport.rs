//! Authenticated, bounded HTTPS transport for the Mail Security replication log.
//!
//! TLS authenticates the receiving node and a per-peer HMAC authenticates the
//! sending node. The protocol deliberately reuses the existing HTTPS listener,
//! so the native gateway still has a single management/replication endpoint and
//! no additional runtime service.

use super::{
    db::{get, keyed, put},
    model::{ReplicationPeer, id, key, n, now, s},
    service::Service,
};
use crate::{
    encoding::STANDARD,
    error::{Result, ensure},
};
use pratique::{
    crypto::{hmac::Hmac, sha2::Sha256},
    json_value::{Value, json},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_BATCH_OPERATIONS: usize = 8;
const MAX_BATCH_BYTES: usize = 15 * 1024 * 1024;
const MAX_WIRE_BODY: usize = 21 * 1024 * 1024;

fn signature(key: &str, raw: &[u8]) -> String {
    Hmac::<Sha256>::mac(key.as_bytes(), raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn peer<'a>(service: &'a Service, node: &str) -> Result<&'a ReplicationPeer> {
    key(node)?;
    service
        .config
        .replication
        .as_ref()
        .and_then(|config| config.peers.iter().find(|peer| peer.node_id == node))
        .ok_or_else(|| crate::error!("Replication peer is not configured"))
}

fn client(peer: &ReplicationPeer, timeout: Duration) -> Result<pratique::Client> {
    let client = if let Some(path) = &peer.ca_file {
        pratique::Client::with_tls_config(pratique::tls::ClientConfig::new(
            pratique::sys::trust_store_from_pem_file(path)?,
        ))
    } else {
        pratique::Client::new()?
    };
    Ok(client
        .follow_redirects(false)
        .max_redirects(0)
        .connect_timeout(timeout.min(Duration::from_secs(3)))
        .timeout(timeout)
        .total_timeout(timeout)
        .max_body_bytes(1024 * 1024)
        .max_decoded_bytes(1024 * 1024))
}

fn acknowledged(service: &Service, peer: &str) -> Result<u64> {
    service.db.write(|table| {
        let origin = super::cluster::node_id(table)?;
        Ok(get(table, &format!("replication_ack/{peer}/{origin}"))?
            .and_then(|value| value["sequence"].as_u64())
            .unwrap_or(0))
    })
}

fn state_acknowledged(service: &Service, peer: &str) -> Result<u64> {
    service.db.write(|table| {
        let origin = super::cluster::node_id(table)?;
        Ok(
            get(table, &format!("replication_state_ack/{peer}/{origin}"))?
                .and_then(|value| value["sequence"].as_u64())
                .unwrap_or(0),
        )
    })
}

fn record_contact(service: &Service, peer: &str, direction: &str, error: Option<&str>) {
    let _ = service.db.write(|table| {
        put(
            table,
            &format!("replication_peer_health/{peer}/{direction}"),
            &json!({
                "peer":peer,
                "direction":direction,
                "at":now()?,
                "ok":error.is_none(),
                "error":error.unwrap_or("")
            }),
        )
    });
}

fn supported_range(value: &Value) -> Result<(u64, u64, u64)> {
    let protocol = value["protocol"]
        .as_u64()
        .ok_or_else(|| crate::error!("Missing replication protocol"))?;
    let wire_minimum = value["minimum_protocol"].as_u64().unwrap_or(protocol);
    let wire_maximum = value["maximum_protocol"].as_u64().unwrap_or(protocol);
    let minimum = value["supported_minimum_protocol"]
        .as_u64()
        .unwrap_or(wire_minimum);
    let maximum = value["supported_maximum_protocol"]
        .as_u64()
        .unwrap_or(wire_maximum);
    ensure!(
        wire_minimum <= protocol
            && protocol <= wire_maximum
            && minimum <= protocol
            && protocol <= maximum
            && minimum <= maximum
            && (super::cluster::MIN_PROTOCOL_VERSION..=super::cluster::PROTOCOL_VERSION)
                .contains(&protocol)
            && minimum <= super::cluster::PROTOCOL_VERSION
            && maximum >= super::cluster::MIN_PROTOCOL_VERSION,
        "Incompatible replication protocol window"
    );
    Ok((protocol, minimum, maximum))
}

fn selected_peer_protocol(service: &Service, peer: &str) -> Result<u64> {
    service.db.write(|table| {
        let maximum = get(table, &format!("replication_peer_protocol/{peer}"))?
            .and_then(|value| value["maximum_protocol"].as_u64())
            .unwrap_or(super::cluster::MIN_PROTOCOL_VERSION);
        let selected = maximum.min(super::cluster::PROTOCOL_VERSION);
        ensure!(
            selected >= super::cluster::MIN_PROTOCOL_VERSION,
            "Replication peer has no compatible protocol"
        );
        Ok(selected)
    })
}

fn record_peer_protocol(
    service: &Service,
    peer: &str,
    direction: &str,
    selected: u64,
    minimum: u64,
    maximum: u64,
) -> Result<()> {
    service.db.write(|table| {
        put(
            table,
            &format!("replication_peer_protocol/{peer}"),
            &json!({
                "peer":peer,
                "direction":direction,
                "selected_protocol":selected,
                "minimum_protocol":minimum,
                "maximum_protocol":maximum,
                "compatible":minimum <= super::cluster::PROTOCOL_VERSION
                    && maximum >= super::cluster::MIN_PROTOCOL_VERSION,
                "at":now()?
            }),
        )
    })
}

pub(super) fn sync_peer_once(
    service: &Service,
    peer_config: &ReplicationPeer,
    timeout: Duration,
) -> Result<u64> {
    let protocol = selected_peer_protocol(service, &peer_config.node_id)?;
    let after = acknowledged(service, &peer_config.node_id)?;
    let batch = service.replication_export_batch(after, MAX_BATCH_OPERATIONS, MAX_BATCH_BYTES)?;
    let state_after = state_acknowledged(service, &peer_config.node_id)?;
    let state_batch = if batch.is_empty() {
        service.replication_export_state_batch(
            state_after,
            MAX_BATCH_OPERATIONS,
            8 * 1024 * 1024,
        )?
    } else {
        Vec::new()
    };
    let operations = batch
        .iter()
        .map(|(operation, raw)| {
            json!({
                "operation":operation,
                "raw":STANDARD.encode(raw)
            })
        })
        .collect::<Vec<_>>();
    let envelope = json!({
        "protocol":protocol,
        "minimum_protocol":super::cluster::MIN_PROTOCOL_VERSION,
        "maximum_protocol":super::cluster::PROTOCOL_VERSION,
        "supported_minimum_protocol":super::cluster::MIN_PROTOCOL_VERSION,
        "supported_maximum_protocol":super::cluster::PROTOCOL_VERSION,
        "cluster_id":service.config.workspace,
        "source_node":service.config.instance,
        "target_node":peer_config.node_id,
        "at":now()?,
        "nonce":id(),
        "operations":operations,
        "state_operations":state_batch
    });
    let raw = pratique::json_value::to_vec(&envelope)?;
    ensure!(
        raw.len() <= MAX_WIRE_BODY,
        "Replication batch exceeds wire limit"
    );
    let secret = crate::config::secret(&peer_config.key_file)?;
    let response = client(peer_config, timeout)?
        .request("POST", &format!("{}/replication", peer_config.origin))
        .header("Content-Type", "application/json")
        .header(
            "X-Workglen-Replication-Signature",
            &signature(&secret, &raw),
        )
        .body(raw)
        .send()
        .map_err(|_| crate::error!("Replication peer unavailable"))?;
    let value: Value = pratique::json_value::from_slice(&response.body)?;
    ensure!(
        response.status == 200,
        "{}",
        value["error"]
            .as_str()
            .unwrap_or("Replication peer refused the batch")
    );
    let (response_protocol, peer_minimum, peer_maximum) = supported_range(&value)?;
    ensure!(
        response_protocol == protocol
            && value["cluster_id"] == service.config.workspace
            && value["source_node"] == peer_config.node_id
            && value["target_node"] == service.config.instance,
        "Invalid replication acknowledgement identity"
    );
    record_peer_protocol(
        service,
        &peer_config.node_id,
        "outbound",
        response_protocol,
        peer_minimum,
        peer_maximum,
    )?;
    let sequence = n(&value, "acknowledged_sequence")?;
    if sequence > 0 {
        service.replication_acknowledge(&peer_config.node_id, sequence)?;
    }
    let state_sequence = n(&value, "acknowledged_state_sequence")?;
    if state_sequence > 0 {
        service.replication_acknowledge_state(&peer_config.node_id, state_sequence)?;
    }
    record_contact(service, &peer_config.node_id, "outbound", None);
    Ok(sequence)
}

fn sync_configured(service: &Service, deadline: Instant) {
    let Some(replication) = &service.config.replication else {
        return;
    };
    let _guard = service
        .replication_sync
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for peer in &replication.peers {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if let Err(error) = sync_peer_once(service, peer, remaining) {
            record_contact(service, &peer.node_id, "outbound", Some(&error.to_string()));
        }
    }
    if let Err(error) = service
        .db
        .write(super::cluster::retire_deferred_acceptances)
    {
        let error = format!("Deferred acceptance cleanup failed: {error}");
        for peer in &replication.peers {
            record_contact(service, &peer.node_id, "outbound", Some(&error));
        }
    }
}

pub(super) fn wait_for_acceptance(service: &Service, ids: &[String]) -> Result<bool> {
    let replication = service
        .config
        .replication
        .as_ref()
        .ok_or_else(|| crate::error!("Replication is not configured"))?;
    let target = service.db.write(|table| {
        ids.iter().try_fold(0u64, |target, id| {
            key(id)?;
            let record = super::db::must(table, &format!("ingress/{id}"))?;
            Ok(target.max(n(&record, "origin_sequence")?))
        })
    })?;
    let deadline =
        Instant::now() + Duration::from_secs(replication.acknowledgement_timeout_seconds);
    loop {
        let ready = service
            .db
            .write(|table| super::cluster::acceptance_acknowledged(table, target))?;
        if ready {
            return Ok(false);
        }
        if Instant::now() >= deadline {
            break;
        }
        sync_configured(service, deadline);
        if Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    if service
        .db
        .write(|table| super::cluster::degraded_acceptance_allowed(table))?
    {
        return Ok(true);
    }
    Err(crate::error!(
        "Required replication acknowledgement unavailable; message held without SMTP acceptance"
    ))
}

pub(super) fn wait_for_state(service: &Service, sequence: u64) -> Result<()> {
    let Some(replication) = &service.config.replication else {
        return Ok(());
    };
    if sequence == 0 {
        return Ok(());
    }
    let deadline =
        Instant::now() + Duration::from_secs(replication.acknowledgement_timeout_seconds);
    loop {
        if service
            .db
            .write(|table| super::cluster::state_acknowledged(table, sequence))?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            break;
        }
        sync_configured(service, deadline);
        if Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    Err(crate::error!(
        "Delivery state was not durably replicated; downstream delivery was not attempted"
    ))
}

pub(super) fn receive(service: &Service, raw: &[u8], supplied_signature: &str) -> Result<Value> {
    ensure!(raw.len() <= MAX_WIRE_BODY, "Replication request too large");
    let envelope: Value = pratique::json_value::from_slice(raw)?;
    let (protocol, peer_minimum, peer_maximum) = supported_range(&envelope)?;
    ensure!(
        envelope["cluster_id"] == service.config.workspace
            && envelope["target_node"] == service.config.instance,
        "Wrong replication protocol, cluster or target"
    );
    let source = s(&envelope, "source_node")?;
    let peer = peer(service, source)?;
    use subtle::ConstantTimeEq;
    let secret = crate::config::secret(&peer.key_file)?;
    let expected = signature(&secret, raw);
    ensure!(
        bool::from(expected.as_bytes().ct_eq(supplied_signature.as_bytes())),
        "Replication signature invalid"
    );
    let sent_at = envelope["at"]
        .as_i64()
        .ok_or_else(|| crate::error!("Invalid replication timestamp"))?;
    ensure!(
        now()?.abs_diff(sent_at) <= 60,
        "Expired replication request"
    );
    let nonce = s(&envelope, "nonce")?;
    ensure!(
        nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid replication nonce"
    );
    service.db.write(|table| {
        for (record_key, expires) in keyed(table, "replication_nonce/")? {
            if expires.as_i64().unwrap_or(0) < now()? {
                super::db::remove(table, &record_key)?;
            }
        }
        ensure!(
            keyed(table, "replication_nonce/")?.len() < 10_000,
            "Replication nonce capacity reached"
        );
        let nonce_key = format!("replication_nonce/{source}/{nonce}");
        ensure!(
            get(table, &nonce_key)?.is_none(),
            "Replication replay rejected"
        );
        put(table, &nonce_key, &json!(now()? + 120))
    })?;
    record_peer_protocol(
        service,
        source,
        "inbound",
        protocol,
        peer_minimum,
        peer_maximum,
    )?;

    let encoded = envelope["operations"]
        .as_array()
        .ok_or_else(|| crate::error!("Missing replication operations"))?;
    ensure!(
        encoded.len() <= MAX_BATCH_OPERATIONS,
        "Too many replication operations"
    );
    let mut total = 0usize;
    let mut operations = Vec::with_capacity(encoded.len());
    for item in encoded {
        let operation = item["operation"].clone();
        ensure!(
            s(&operation, "origin")? == source,
            "Replication origin mismatch"
        );
        let content = STANDARD.decode(s(item, "raw")?)?;
        total = total
            .checked_add(content.len())
            .ok_or_else(|| crate::error!("Replication batch size overflow"))?;
        ensure!(
            total <= MAX_BATCH_BYTES,
            "Replication content exceeds batch limit"
        );
        operations.push((operation, content));
    }
    let state_encoded = envelope["state_operations"]
        .as_array()
        .ok_or_else(|| crate::error!("Missing replication state operations"))?;
    ensure!(
        state_encoded.len() <= MAX_BATCH_OPERATIONS,
        "Too many replication state operations"
    );
    let mut state_total = 0usize;
    let mut state_operations = Vec::with_capacity(state_encoded.len());
    for operation in state_encoded {
        ensure!(
            s(operation, "origin")? == source,
            "Replication state origin mismatch"
        );
        state_total = state_total
            .checked_add(pratique::json_value::to_vec(operation)?.len())
            .ok_or_else(|| crate::error!("Replication state batch size overflow"))?;
        ensure!(
            state_total <= 8 * 1024 * 1024,
            "Replication state exceeds batch limit"
        );
        state_operations.push(operation.clone());
    }
    let acknowledged = if operations.is_empty() {
        service
            .replication_expected_sequence(source)?
            .saturating_sub(1)
    } else {
        service.replication_apply_batch(&operations)?
    };
    let acknowledged_state = if state_operations.is_empty() {
        service
            .replication_expected_state_sequence(source)?
            .saturating_sub(1)
    } else {
        service.replication_apply_state_batch(&state_operations)?
    };
    record_contact(service, source, "inbound", None);
    let response_minimum = if protocol == super::cluster::MIN_PROTOCOL_VERSION {
        protocol
    } else {
        super::cluster::MIN_PROTOCOL_VERSION
    };
    Ok(json!({
        "protocol":protocol,
        "minimum_protocol":response_minimum,
        "maximum_protocol":protocol,
        "supported_minimum_protocol":super::cluster::MIN_PROTOCOL_VERSION,
        "supported_maximum_protocol":super::cluster::PROTOCOL_VERSION,
        "cluster_id":service.config.workspace,
        "source_node":service.config.instance,
        "target_node":source,
        "acknowledged_sequence":acknowledged,
        "expected_sequence":acknowledged.saturating_add(1),
        "acknowledged_state_sequence":acknowledged_state,
        "expected_state_sequence":acknowledged_state.saturating_add(1)
    }))
}

pub(super) fn start(service: &Arc<Service>) -> Result<Option<std::thread::JoinHandle<()>>> {
    if service.config.replication.is_none() {
        return Ok(None);
    }
    let weak = Arc::downgrade(service);
    Ok(Some(
        std::thread::Builder::new()
            .name("security-replication".into())
            .spawn(move || {
                while let Some(service) = weak.upgrade() {
                    sync_configured(&service, Instant::now() + Duration::from_secs(5));
                    drop(service);
                    std::thread::sleep(Duration::from_millis(250));
                }
            })?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn replicated_service() -> (crate::test_support::TempDir, Arc<Service>, String) {
        let directory = crate::test_support::tempdir().unwrap();
        let control_key = directory.path().join("control.key");
        let peer_key = directory.path().join("peer.key");
        let storage_key = directory.path().join("storage.key");
        std::fs::write(&control_key, "c".repeat(64)).unwrap();
        std::fs::write(&peer_key, "p".repeat(64)).unwrap();
        for path in [&control_key, &peer_key] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        crate::encrypted_store::generate_key(&storage_key).unwrap();
        let config: super::super::model::Config = pratique::json_value::from_value(json!({
            "data_dir":directory.path().join("data"),
            "storage_key_file":storage_key,
            "workspace":"compatibility-cluster",
            "instance":"node-b",
            "origin":"https://node-b.example.test:8445",
            "hostname":"node-b.example.test",
            "tls_cert":"unused",
            "tls_key":"unused",
            "control_key_file":control_key,
            "smtp_listen":["127.0.0.1",2525],
            "https_listen":["127.0.0.1",8445],
            "routes":{},
            "connectors":{},
            "replication":{
                "peers":[{
                    "node_id":"node-a",
                    "origin":"https://node-a.example.test:8445",
                    "key_file":peer_key
                }],
                "durable_copies":2,
                "acknowledgement_timeout_seconds":1,
                "degraded_acceptance":false,
                "max_degraded_operations":0,
                "max_degraded_bytes":0
            }
        }))
        .unwrap();
        (directory, Service::open(config).unwrap(), "p".repeat(64))
    }

    #[test]
    fn replication_protocol_window_accepts_n_minus_one_and_rejects_gaps() {
        assert_eq!(
            supported_range(&json!({
                "protocol":1,
                "minimum_protocol":1,
                "maximum_protocol":1
            }))
            .unwrap(),
            (1, 1, 1)
        );
        assert_eq!(
            supported_range(&json!({
                "protocol":1,
                "minimum_protocol":1,
                "maximum_protocol":1,
                "supported_minimum_protocol":1,
                "supported_maximum_protocol":2
            }))
            .unwrap(),
            (1, 1, 2)
        );
        assert_eq!(
            supported_range(&json!({
                "protocol":2,
                "minimum_protocol":1,
                "maximum_protocol":2
            }))
            .unwrap(),
            (2, 1, 2)
        );
        assert!(
            supported_range(&json!({
                "protocol":3,
                "minimum_protocol":3,
                "maximum_protocol":3
            }))
            .is_err()
        );
    }

    #[test]
    fn current_replication_receiver_serves_a_legacy_peer_and_then_negotiates_current() {
        let (_directory, service, secret) = replicated_service();
        let request = |protocol: u64, maximum: u64| {
            json!({
                "protocol":protocol,
                "minimum_protocol":1,
                "maximum_protocol":maximum,
                "supported_minimum_protocol":1,
                "supported_maximum_protocol":maximum,
                "cluster_id":"compatibility-cluster",
                "source_node":"node-a",
                "target_node":"node-b",
                "at":now().unwrap(),
                "nonce":id(),
                "operations":[],
                "state_operations":[]
            })
        };
        let legacy_raw = pratique::json_value::to_vec(&request(1, 1)).unwrap();
        let legacy = receive(&service, &legacy_raw, &signature(&secret, &legacy_raw)).unwrap();
        assert_eq!(legacy["protocol"], 1);
        assert_eq!(legacy["minimum_protocol"], 1);
        assert_eq!(legacy["maximum_protocol"], 1);
        assert_eq!(
            legacy["supported_maximum_protocol"],
            super::super::cluster::PROTOCOL_VERSION
        );
        assert_eq!(selected_peer_protocol(&service, "node-a").unwrap(), 1);

        let current_raw = pratique::json_value::to_vec(&request(2, 2)).unwrap();
        let current = receive(&service, &current_raw, &signature(&secret, &current_raw)).unwrap();
        assert_eq!(current["protocol"], 2);
        assert_eq!(current["minimum_protocol"], 1);
        assert_eq!(current["maximum_protocol"], 2);
        assert_eq!(selected_peer_protocol(&service, "node-a").unwrap(), 2);
    }
}
