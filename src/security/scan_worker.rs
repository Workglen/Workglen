//! Local-only, versioned handoff between durable SMTP acceptance and scanning.
//!
//! `security-serve` remains the sole owner of encrypted storage. A separately
//! restartable role in the same native executable receives bounded work over an
//! owner-only Unix socket. Losing or replacing that worker never stops SMTP
//! acceptance; unacknowledged leases become eligible again.

use super::{db::*, learning, model::*, scan, service::Service};
use crate::error::{Result, ensure};
use pratique::json_value::{Value, json};
use std::{
    io::{Read, Write},
    net::{IpAddr, Shutdown},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub(super) const PROTOCOL_VERSION: u64 = 2;
pub(super) const MIN_PROTOCOL_VERSION: u64 = 1;
const COMPATIBILITY_HELLO_PROTOCOL: u64 = 1;
const LEASE_SECONDS: i64 = 180;
const MAX_LEASE_SECONDS: i64 = 600;
const MAX_LEASE_EXPIRIES: u64 = 3;
const HEARTBEAT_SECONDS: u64 = 30;
const MAX_HELLO: usize = 4096;
const MAX_JOB: usize = 1024 * 1024;
const MAX_INSPECTION: usize = 3 * 1024 * 1024;
const MAX_RESULT: usize = 1024 * 1024;
const MAX_EVIDENCE: usize = 64 * 1024;
const LIGHT_INPUT_BYTES: usize = 256 * 1024;
const LIGHT_HEADER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanLane {
    Any,
    Light,
    Heavy,
}

impl ScanLane {
    fn parse(value: Option<&str>) -> Result<Self> {
        match value.unwrap_or("any") {
            "any" => Ok(Self::Any),
            "light" => Ok(Self::Light),
            "heavy" => Ok(Self::Heavy),
            _ => crate::bail!("Invalid scan lane"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Light => "light",
            Self::Heavy => "heavy",
        }
    }
}

pub(super) fn lane_worker_counts(threads: u64) -> (u64, u64, u64) {
    if threads == 1 {
        (0, 0, 1)
    } else {
        (1, threads.saturating_sub(1), 0)
    }
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Assign only clearly bounded, single-part messages to the latency lane. This
/// is a scheduling hint; both lanes run the identical complete analysis profile.
/// Ambiguous or legacy records always take the resource-capped heavy lane.
pub(super) fn scheduling_lane(raw: &[u8]) -> &'static str {
    if raw.len() > LIGHT_INPUT_BYTES || raw.contains(&0) {
        return "heavy";
    }
    let probe = &raw[..raw.len().min(LIGHT_HEADER_BYTES)];
    let Some(header_end) = probe
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .or_else(|| probe.windows(2).position(|window| window == b"\n\n"))
    else {
        return "heavy";
    };
    let headers = &probe[..header_end];
    for marker in [
        b"content-type: multipart/".as_slice(),
        b"content-type: application/".as_slice(),
        b"content-type: message/".as_slice(),
        b"content-type: image/".as_slice(),
        b"content-type: audio/".as_slice(),
        b"content-type: video/".as_slice(),
        b"content-disposition:".as_slice(),
        b"content-transfer-encoding: base64".as_slice(),
        b"content-transfer-encoding: quoted-printable".as_slice(),
    ] {
        if contains_ascii_case_insensitive(headers, marker) {
            return "heavy";
        }
    }
    "light"
}

pub fn socket_path(config: &Config) -> PathBuf {
    // Keep the component deliberately short: sockaddr_un has a small fixed path
    // field on both Linux and macOS, while test and restored data roots can be long.
    Path::new(&config.data_dir).join("s")
}

pub fn analysis_settings(settings: &Value) -> Result<Value> {
    for key in [
        "protected_people",
        "protected_domains",
        "mixed_script_check",
        "scan_input_bytes",
        "scan_decoded_bytes",
        "scan_parts",
        "scan_concurrency",
    ] {
        ensure!(settings.get(key).is_some(), "Analysis setting missing");
    }
    Ok(json!({
        "protected_people":settings["protected_people"],
        "protected_domains":settings["protected_domains"],
        "mixed_script_check":settings["mixed_script_check"],
        "scan_input_bytes":settings["scan_input_bytes"],
        "scan_decoded_bytes":settings["scan_decoded_bytes"],
        "scan_parts":settings["scan_parts"],
        "scan_concurrency":settings["scan_concurrency"]
    }))
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8], limit: usize) -> Result<()> {
    ensure!(
        bytes.len() <= limit && bytes.len() <= u32::MAX as usize,
        "Local scan frame too large"
    );
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream, limit: usize) -> Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    ensure!(len <= limit, "Local scan frame exceeds limit");
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_json(stream: &mut UnixStream, value: &Value, limit: usize) -> Result<()> {
    write_frame(stream, &pratique::json_value::to_vec(value)?, limit)
}

fn read_json(stream: &mut UnixStream, limit: usize) -> Result<Value> {
    Ok(pratique::json_value::from_slice(&read_frame(
        stream, limit,
    )?)?)
}

fn protocol_range(value: &Value) -> Result<(u64, u64, u64)> {
    let protocol = value["protocol"]
        .as_u64()
        .ok_or_else(|| crate::error!("Missing scan protocol"))?;
    let minimum = value["minimum_protocol"].as_u64().unwrap_or(protocol);
    let maximum = value["maximum_protocol"].as_u64().unwrap_or(protocol);
    ensure!(
        minimum <= protocol
            && protocol <= maximum
            && minimum <= maximum
            && (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&protocol)
            && minimum <= PROTOCOL_VERSION
            && maximum >= MIN_PROTOCOL_VERSION,
        "Unsupported scan protocol"
    );
    Ok((protocol, minimum, maximum))
}

fn verify_versions(value: &Value) -> Result<u64> {
    let (protocol, _, _) = protocol_range(value)?;
    ensure!(
        value["api_version"] == scan::ANALYSIS_API_VERSION
            && value["profile_version"] == scan::ANALYSIS_PROFILE_VERSION
            && value["coverage_version"] == scan::COVERAGE_VERSION,
        "Unsupported analysis profile"
    );
    Ok(protocol)
}

fn negotiate_versions(value: &Value) -> Result<u64> {
    let (_, remote_minimum, remote_maximum) = protocol_range(value)?;
    let selected = PROTOCOL_VERSION.min(remote_maximum);
    ensure!(
        selected >= MIN_PROTOCOL_VERSION.max(remote_minimum),
        "No compatible scan protocol"
    );
    Ok(selected)
}

fn scan_record(t: &Table, id: &str, token: &str) -> Result<Value> {
    key(id)?;
    key(token)?;
    let record = must(t, &format!("ingress/{id}"))?;
    ensure!(
        record["state"] == "leased" && record["lease_token"] == token,
        "Stale scan lease"
    );
    Ok(record)
}

fn cancellation_requested(value: &Value) -> Result<bool> {
    let cancellation = value
        .as_object()
        .ok_or_else(|| crate::error!("Missing scan cancellation context"))?;
    let mode = cancellation
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| crate::error!("Invalid scan cancellation mode"))?;
    ensure!(
        ["none", "cooperative"].contains(&mode),
        "Invalid scan cancellation mode"
    );
    let requested = cancellation
        .get("requested")
        .and_then(Value::as_bool)
        .ok_or_else(|| crate::error!("Invalid scan cancellation state"))?;
    ensure!(
        mode != "none" || !requested,
        "No-op cancellation was requested"
    );
    Ok(requested)
}

impl Service {
    #[cfg(test)]
    pub(super) fn claim_scan(&self) -> Result<Option<(Value, Vec<u8>)>> {
        self.claim_scan_for_protocol(PROTOCOL_VERSION, ScanLane::Any)
    }

    #[cfg(test)]
    pub(super) fn claim_scan_lane(&self, lane: &str) -> Result<Option<(Value, Vec<u8>)>> {
        self.claim_scan_for_protocol(PROTOCOL_VERSION, ScanLane::parse(Some(lane))?)
    }

    fn claim_scan_for_protocol(
        &self,
        protocol: u64,
        requested_lane: ScanLane,
    ) -> Result<Option<(Value, Vec<u8>)>> {
        self.db.write(|t| {
            use redb::ReadableTable;

            if !super::cluster::scanner_eligible(t)? {
                return Ok(None);
            }

            let current = now()?;
            let settings = must(t, "settings")?;
            let limit = usize::try_from(n(&settings, "scan_concurrency")?)?;
            let mut leased = 0usize;
            for marker in list(t, "ingress_lease/")? {
                let row = must(t, &format!("ingress/{}", s(&marker, "id")?))?;
                if super::cluster::scan_owned(t, &row)?
                    && row["lease_until"].as_i64().unwrap_or(0) > current
                {
                    leased += 1;
                }
            }
            if leased >= limit {
                return Ok(None);
            }
            let marker_for = |lane: &str| -> Result<Option<Value>> {
                let node = super::cluster::node_id(t)?;
                let prefix = format!("ingress_due/{node}/{lane}/");
                let end = format!("{prefix}\u{10ffff}");
                let mut due = t.range(prefix.as_str()..end.as_str())?;
                Ok(due
                    .next()
                    .transpose()?
                    .map(|(_, value)| pratique::json_value::from_slice::<Value>(value.value()))
                    .transpose()?)
            };
            let eligible_record = |lane: &str| -> Result<Option<Value>> {
                let Some(marker) = marker_for(lane)? else {
                    return Ok(None);
                };
                let record = must(t, &format!("ingress/{}", s(&marker, "id")?))?;
                let eligible = if record["state"] == "leased" {
                    record["lease_until"].as_i64()
                } else {
                    record["due"].as_i64()
                }
                .ok_or_else(|| crate::error!("Invalid indexed scan time"))?;
                Ok((eligible <= current).then_some(record))
            };
            let marker = match requested_lane {
                ScanLane::Light => eligible_record("light")?,
                ScanLane::Heavy => match eligible_record("heavy")? {
                    Some(record) => Some(record),
                    None => eligible_record("light")?,
                },
                ScanLane::Any => {
                    let light = eligible_record("light")?;
                    let heavy = eligible_record("heavy")?;
                    [light, heavy].into_iter().flatten().min_by_key(|record| {
                        (
                            if record["state"] == "leased" {
                                record["lease_until"].as_i64().unwrap_or(i64::MAX)
                            } else {
                                record["due"].as_i64().unwrap_or(i64::MAX)
                            },
                            record["arrived"].as_i64().unwrap_or(i64::MAX),
                            record["id"].as_str().unwrap_or("").to_string(),
                        )
                    })
                }
            };
            let Some(marker) = marker else {
                return Ok(None);
            };
            let mut record = marker;
            ensure!(
                super::cluster::scan_owned(t, &record)?,
                "Scan ownership changed"
            );
            if record["state"] == "leased" {
                let expiries = record["lease_expiries"]
                    .as_u64()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| crate::error!("Scan lease expiry counter overflow"))?;
                record["lease_expiries"] = json!(expiries);
                if expiries >= MAX_LEASE_EXPIRIES {
                    let token = s(&record, "lease_token")?.to_string();
                    let result =
                        Self::incomplete_result(&record, &token, "scan-attempts-exhausted")?;
                    Self::finalize_locked(t, &record, &result, PROTOCOL_VERSION)?;
                    return Ok(None);
                }
            }
            let token = id();
            record["state"] = json!("leased");
            record["lease_token"] = json!(token);
            record["lease_until"] = json!(current + LEASE_SECONDS);
            record["leased_at"] = json!(current);
            record["attempts"] = json!(n(&record, "attempts")? + 1);
            record["error"] = json!("");
            put(t, &format!("ingress/{}", s(&record, "id")?), &record)?;

            let version = n(&record, "rule_version")?;
            let rules = must(t, &format!("rule/{version}"))?;
            let shadow = if let Some(version) = record["shadow_version"].as_u64() {
                let rules = must(t, &format!("rule/{version}"))?;
                json!({"version":version,"rules":rules["rules"]})
            } else {
                Value::Null
            };
            let raw = body(t, &record)?;
            let job = json!({
                "protocol":protocol,
                "minimum_protocol":MIN_PROTOCOL_VERSION,
                "maximum_protocol":PROTOCOL_VERSION,
                "api_version":record["api_version"],
                "profile_version":record["profile_version"],
                "coverage_version":record["coverage_version"],
                "id":record["id"],
                "token":record["lease_token"],
                "scan_generation":record["scan_generation"],
                "scan_lane":record["scan_lane"].as_str().unwrap_or("heavy"),
                "hash":record["hash"],
                "sender":record["envelope_from"],
                "source_ip":record["source_ip"],
                "helo":record["helo"],
                "hostname":self.config.hostname,
                "settings":record["analysis_settings"],
                "rule_version":version,
                "rules":rules["rules"],
                "shadow":shadow,
                "cancellation":{"mode":"cooperative","requested":false},
                "deadline_seconds":30
            });
            Ok(Some((job, raw)))
        })
    }

    #[cfg(test)]
    pub(super) fn renew_scan(&self, id: &str, token: &str) -> Result<Value> {
        self.renew_scan_for_protocol(id, token, PROTOCOL_VERSION)
    }

    fn renew_scan_for_protocol(&self, id: &str, token: &str, protocol: u64) -> Result<Value> {
        self.db.write(|t| {
            let mut record = scan_record(t, id, token)?;
            let requested = record["cancel_requested"].as_bool().unwrap_or(false);
            let current = now()?;
            let leased_at = record["leased_at"]
                .as_i64()
                .ok_or_else(|| crate::error!("Invalid scan lease start"))?;
            let lease_expired =
                leased_at <= 0 || current < leased_at || current - leased_at > MAX_LEASE_SECONDS;
            if !requested && !lease_expired {
                record["lease_until"] = json!(current + LEASE_SECONDS);
                put(t, &format!("ingress/{id}"), &record)?;
            }
            Ok(json!({
                "protocol":protocol,
                "minimum_protocol":MIN_PROTOCOL_VERSION,
                "maximum_protocol":PROTOCOL_VERSION,
                "api_version":scan::ANALYSIS_API_VERSION,
                "profile_version":scan::ANALYSIS_PROFILE_VERSION,
                "coverage_version":scan::COVERAGE_VERSION,
                "renewed":!requested && !lease_expired,
                "lease_until":record["lease_until"],
                "cancellation":{"mode":"cooperative","requested":requested}
            }))
        })
    }

    pub(super) fn scan_learning_score(
        &self,
        id: &str,
        token: &str,
        inspected: &Value,
    ) -> Result<f64> {
        self.db.write(|t| {
            scan_record(t, id, token)?;
            learning::score_inspected(t, inspected)
        })
    }

    pub(super) fn retry_scan(&self, id: &str, token: &str, code: &str) -> Result<()> {
        ensure!(
            ["authentication-temporary", "worker-temporary"].contains(&code),
            "Invalid retry code"
        );
        let retried = self.db.write(|t| {
            let mut record = scan_record(t, id, token)?;
            let current = now()?;
            let max_age = i64::try_from(n(&must(t, "settings")?, "scan_retry_max_seconds")?)?;
            let arrived = record["arrived"]
                .as_i64()
                .ok_or_else(|| crate::error!("Invalid scan arrival time"))?;
            if current < arrived || current - arrived >= max_age {
                let result = Self::incomplete_result(&record, token, "authentication-unavailable")?;
                Self::finalize_locked(t, &record, &result, PROTOCOL_VERSION)?;
                return Ok(false);
            }
            let attempts = n(&record, "attempts")?;
            let delay = (60i64 * 2i64.pow(attempts.saturating_sub(1).min(4) as u32)).min(900);
            record["state"] = json!("retrying");
            record["due"] = json!(current + delay);
            if record["first_retry_at"].is_null() {
                record["first_retry_at"] = json!(current);
            }
            record["lease_token"] = Value::Null;
            record["lease_until"] = json!(0);
            record["leased_at"] = json!(0);
            record["error"] = json!(code);
            put(t, &format!("ingress/{id}"), &record)?;
            super::cluster::record_ingress_state(t, id)?;
            audit(
                t,
                "scanner",
                "scan-retry",
                "",
                json!({"ingress":id,"reason":code,"attempt":attempts}),
            )?;
            Ok(true)
        })?;
        if retried {
            self.record_scan_retry();
        }
        Ok(())
    }

    fn validate_verdict(verdict: &Value) -> Result<()> {
        ensure!(verdict.is_object(), "Invalid scan verdict");
        let action = s(verdict, "action")?;
        ensure!(
            ["deliver", "quarantine"].contains(&action),
            "Invalid scan action"
        );
        ensure!(
            verdict["releasable"].is_boolean(),
            "Invalid release decision"
        );
        ensure!(
            s(verdict, "subject")?.len() <= 500,
            "Invalid scanned subject"
        );
        let sender = s(verdict, "sender")?;
        ensure!(
            sender.is_empty() || address(sender).is_ok(),
            "Invalid scanned sender"
        );
        ensure!(
            arr(verdict, "matches")?.len() <= 1000,
            "Too many scan findings"
        );
        let coverage = verdict["coverage"]
            .as_object()
            .ok_or_else(|| crate::error!("Missing scan coverage"))?;
        ensure!(
            coverage.get("complete").and_then(Value::as_bool).is_some(),
            "Missing scan completeness"
        );
        ensure!(
            verdict["coverage"]["api_version"] == scan::ANALYSIS_API_VERSION
                && verdict["coverage"]["profile_version"] == scan::ANALYSIS_PROFILE_VERSION
                && verdict["coverage"]["coverage_version"] == scan::COVERAGE_VERSION,
            "Coverage report version mismatch"
        );
        let incomplete = arr(&verdict["coverage"], "incompleteness_reasons")?;
        ensure!(incomplete.len() <= 256, "Too many incompleteness reasons");
        ensure!(
            incomplete.iter().all(|reason| reason
                .as_str()
                .is_some_and(|reason| !reason.is_empty() && reason.len() <= 500)),
            "Invalid incompleteness reason"
        );
        ensure!(
            verdict["coverage"]["complete"] != true || incomplete.is_empty(),
            "Complete report contains incompleteness reasons"
        );
        ensure!(
            verdict["coverage"]["complete"] == true
                || (!incomplete.is_empty() && action == "quarantine"),
            "Incomplete report must quarantine with reasons"
        );
        ensure!(
            action != "deliver" || verdict["coverage"]["complete"] == true,
            "Incomplete scan cannot deliver"
        );
        let requested = cancellation_requested(&verdict["coverage"]["cancellation"])?;
        ensure!(
            verdict["coverage"]["complete"] != true || !requested,
            "Complete report was cancelled"
        );
        ensure!(
            verdict["coverage"]["complete"] != true
                || verdict["coverage"]["input_bytes"].as_u64().is_some(),
            "Complete report lacks its supplied byte view"
        );
        ensure!(
            verdict["api_version"] == scan::ANALYSIS_API_VERSION
                && verdict["profile_version"] == scan::ANALYSIS_PROFILE_VERSION
                && verdict["coverage_version"] == scan::COVERAGE_VERSION,
            "Scan report version mismatch"
        );
        ensure!(
            s(verdict, "engine")? == scan::ENGINE,
            "Invalid scan engine identity"
        );
        ensure!(
            pratique::json_value::to_vec(verdict)?.len() <= MAX_RESULT,
            "Scan verdict too large"
        );
        Ok(())
    }

    pub(super) fn finalize_scan(&self, id: &str, token: &str, result: &Value) -> Result<()> {
        let protocol = verify_versions(result)?;
        ensure!(
            result["status"] == "complete" && result["id"] == id && result["token"] == token,
            "Invalid scan result"
        );
        let verdict = &result["verdict"];
        Self::validate_verdict(verdict)?;
        ensure!(
            verdict["coverage"]["input_hash"] == result["hash"],
            "Coverage input hash mismatch"
        );
        let evidence_object = result["evidence"]
            .as_object()
            .ok_or_else(|| crate::error!("Invalid scan evidence"))?;
        ensure!(
            evidence_object.keys().all(|key| [
                "authentication_action",
                "source_ip",
                "helo",
                "engine",
                "learned_spam_score",
                "api_version",
                "profile_version",
                "coverage_version",
            ]
            .contains(&key.as_str())),
            "Unexpected scan evidence field"
        );
        ensure!(
            pratique::json_value::to_vec(&result["evidence"])?.len() <= MAX_EVIDENCE,
            "Scan evidence too large"
        );
        let authentication_action = s(&result["evidence"], "authentication_action")?;
        ensure!(
            ["pass-policy", "quarantine", "incomplete"].contains(&authentication_action),
            "Invalid authentication evidence"
        );
        ensure!(
            result["evidence"]["engine"] == scan::ENGINE,
            "Invalid evidence engine"
        );
        if authentication_action != "incomplete" {
            ensure!(
                result["evidence"]["learned_spam_score"]
                    .as_f64()
                    .is_some_and(|score| (-3.0..=5.0).contains(&score)),
                "Invalid learning evidence"
            );
        }
        if !result["shadow"].is_null() {
            Self::validate_verdict(&result["shadow"]["verdict"])?;
            ensure!(
                result["shadow"]["verdict"]["coverage"]["input_hash"] == result["hash"],
                "Shadow coverage input hash mismatch"
            );
        }

        self.db.write(|t| {
            let record = scan_record(t, id, token)?;
            Self::finalize_locked(t, &record, result, protocol)
        })
    }

    fn finalize_locked(
        t: &mut Table<'_>,
        record: &Value,
        result: &Value,
        protocol: u64,
    ) -> Result<()> {
        let id = s(record, "id")?;
        let verdict = &result["verdict"];
        ensure!(
            (protocol == MIN_PROTOCOL_VERSION && result["scan_generation"].is_null())
                || result["scan_generation"] == record["scan_generation"],
            "Stale scan generation"
        );
        ensure!(record["hash"] == result["hash"], "Scan input hash mismatch");
        let input_bytes = u64::try_from(body(t, record)?.len())?;
        ensure!(
            verdict["coverage"]["complete"] != true
                || verdict["coverage"]["input_bytes"] == input_bytes,
            "Scan byte view mismatch"
        );
        if !result["shadow"].is_null() {
            ensure!(
                result["shadow"]["verdict"]["coverage"]["complete"] != true
                    || result["shadow"]["verdict"]["coverage"]["input_bytes"] == input_bytes,
                "Shadow scan byte view mismatch"
            );
        }
        ensure!(
            record["rule_version"] == result["rule_version"],
            "Scan rule version mismatch"
        );
        ensure!(
            result["evidence"]["source_ip"] == record["source_ip"]
                && result["evidence"]["helo"] == record["helo"],
            "Scan source evidence mismatch"
        );
        match record["shadow_version"].as_u64() {
            Some(version) => ensure!(
                result["shadow"]["version"] == version,
                "Shadow rule version mismatch"
            ),
            None => ensure!(result["shadow"].is_null(), "Unexpected shadow verdict"),
        }
        ensure!(
            record["profile_version"] == result["profile_version"]
                && record["api_version"] == result["api_version"]
                && record["coverage_version"] == result["coverage_version"],
            "Scan profile changed"
        );
        let mut evidence = result["evidence"].clone();
        evidence["api_version"] = result["api_version"].clone();
        evidence["profile_version"] = result["profile_version"].clone();
        evidence["coverage_version"] = result["coverage_version"].clone();
        let mut message_ids = Vec::new();
        for recipient in arr(record, "recipients")? {
            let recipient = recipient
                .as_str()
                .ok_or_else(|| crate::error!("Invalid queued recipient"))?;
            let message_id = super::model::id();
            let mut message = json!({
                "id":message_id,
                "ingress_id":id,
                "recipient":recipient,
                "arrived":record["arrived"],
                "state":if verdict["action"]=="quarantine"{"quarantined"}else{"queued"},
                "revision":1,
                "hash":record["hash"],
                "envelope_from":record["envelope_from"],
                "subject":verdict["subject"],
                "sender":verdict["sender"],
                "releasable":verdict["releasable"],
                "verdict":verdict,
                "engines":evidence,
                "rule_version":record["rule_version"],
                "expires":record["expires"],
                "hold":false,
                "route":record["routes"][recipient],
                "origin_node":record["origin_node"],
                "origin_sequence":record["origin_sequence"],
                "delivery_partition":record["delivery_partition"],
                "delivery_owner":record["delivery_owner"],
                "delivery_term":record["delivery_term"],
                "scan_owner":record["scan_owner"],
                "scan_generation":record["scan_generation"]
            });
            if !result["shadow"].is_null() {
                message["shadow"] = json!({
                    "version":result["shadow"]["version"],
                    "verdict":result["shadow"]["verdict"]
                });
            }
            save_message(t, &message)?;
            if message["state"] == "queued" {
                job(
                    t,
                    "delivery",
                    json!({
                        "recipient":recipient,
                        "message":message_id,
                        "delivery_partition":record["delivery_partition"],
                        "delivery_owner":record["delivery_owner"],
                        "delivery_term":record["delivery_term"]
                    }),
                    &format!("delivery-{message_id}"),
                )?;
            }
            audit(
                t,
                "scanner",
                "scan-complete",
                recipient,
                json!({
                    "id":message_id,
                    "ingress":id,
                    "hash":record["hash"],
                    "state":message["state"],
                    "version":record["rule_version"],
                    "engine":verdict["engine"],
                    "api_version":result["api_version"],
                    "profile_version":result["profile_version"],
                    "coverage_version":result["coverage_version"]
                }),
            )?;
            super::cluster::record_message_state(t, &message_id)?;
            message_ids.push(message_id);
        }
        remove(t, &format!("ingress/{id}"))?;
        super::cluster::record_ingress_state(t, id)?;
        Ok(())
    }

    fn incomplete_result(record: &Value, token: &str, code: &str) -> Result<Value> {
        ensure!(
            [
                "authentication-invalid",
                "authentication-unavailable",
                "inspection-error",
                "operator-stopped",
                "scan-attempts-exhausted",
                "worker-cancelled",
            ]
            .contains(&code),
            "Invalid incomplete code"
        );
        let id = s(record, "id")?;
        let reason = match code {
            "authentication-invalid" => "Message structure prevented sender authentication",
            "authentication-unavailable" => {
                "Sender authentication remained unavailable beyond the retry limit"
            }
            "operator-stopped" => "An administrator stopped analysis and required quarantine",
            "scan-attempts-exhausted" => {
                "Analysis repeatedly lost its worker lease and was stopped safely"
            }
            "worker-cancelled" => "Analysis was cancelled before the supplied profile completed",
            _ => "Message inspection could not complete under the supplied analysis profile",
        };
        Ok(json!({
            "protocol":PROTOCOL_VERSION,
            "api_version":record["api_version"],
            "profile_version":record["profile_version"],
            "coverage_version":record["coverage_version"],
            "status":"complete",
            "id":id,
            "token":token,
            "scan_generation":record["scan_generation"],
            "hash":record["hash"],
            "rule_version":record["rule_version"],
            "verdict":{
                "action":"quarantine",
                "releasable":false,
                "matches":[{"rule":"mandatory-incomplete","type":"attachment_safety","action":"quarantine","reason":reason,"signals":[],"score":null}],
                "coverage":{"engine":scan::ENGINE,"api_version":scan::ANALYSIS_API_VERSION,"profile_version":scan::ANALYSIS_PROFILE_VERSION,"coverage_version":scan::COVERAGE_VERSION,"complete":false,"incompleteness_reasons":[reason],"input_hash":record["hash"],"input_bytes":null,"cancellation":{"mode":"cooperative","requested":matches!(code,"worker-cancelled"|"operator-stopped")},"text":false,"archive_formats":[],"expanded_bytes":0,"members":0,"ocr":false,"full_antivirus":false},
                "subject":"Inspection incomplete",
                "sender":record["envelope_from"],
                "spam_score":null,
                "engine":scan::ENGINE,
                "api_version":scan::ANALYSIS_API_VERSION,
                "profile_version":scan::ANALYSIS_PROFILE_VERSION,
                "coverage_version":scan::COVERAGE_VERSION
            },
            "shadow":null,
            "evidence":{"authentication_action":"incomplete","source_ip":record["source_ip"],"helo":record["helo"],"engine":scan::ENGINE}
        }))
    }

    fn finalize_incomplete(&self, id: &str, token: &str, code: &str) -> Result<()> {
        self.db.write(|t| {
            let record = scan_record(t, id, token)?;
            let result = Self::incomplete_result(&record, token, code)?;
            Self::finalize_locked(t, &record, &result, PROTOCOL_VERSION)
        })
    }

    pub(super) fn stop_scan_locked(t: &mut Table<'_>, id: &str) -> Result<Value> {
        key(id)?;
        let mut record = must(t, &format!("ingress/{id}"))?;
        ensure!(
            super::cluster::scan_owned(t, &record)?,
            "Receive record is owned by another node"
        );
        let state = s(&record, "state")?;
        ensure!(
            ["queued", "retrying", "leased"].contains(&state),
            "Receive record is not active"
        );
        if state == "leased" {
            record["cancel_requested"] = json!(true);
            record["error"] = json!("operator-stop-requested");
            put(t, &format!("ingress/{id}"), &record)?;
            super::cluster::record_ingress_state(t, id)?;
            return Ok(json!({"id":id,"state":"cancellation-requested"}));
        }
        let token = super::model::id();
        let result = Self::incomplete_result(&record, &token, "operator-stopped")?;
        Self::finalize_locked(t, &record, &result, PROTOCOL_VERSION)?;
        Ok(json!({"id":id,"state":"quarantined"}))
    }
}

pub(super) fn handle(service: &Service, mut stream: UnixStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(240)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let hello = read_json(&mut stream, MAX_HELLO)?;
    verify_versions(&hello)?;
    let protocol = negotiate_versions(&hello)?;
    let role = s(&hello, "role")?;
    ensure!(
        ["capacity", "heartbeat", "scanner"].contains(&role),
        "Invalid local scan role"
    );
    service.mark_scanner_seen()?;
    if role == "capacity" {
        let settings = service.settings()?;
        let threads = n(&settings, "scan_concurrency")?;
        let (light_threads, heavy_threads, any_threads) = lane_worker_counts(threads);
        write_json(
            &mut stream,
            &json!({
                "protocol":protocol,
                "minimum_protocol":MIN_PROTOCOL_VERSION,
                "maximum_protocol":PROTOCOL_VERSION,
                "api_version":scan::ANALYSIS_API_VERSION,
                "profile_version":scan::ANALYSIS_PROFILE_VERSION,
                "coverage_version":scan::COVERAGE_VERSION,
                "threads":threads,
                "light_threads":light_threads,
                "heavy_threads":heavy_threads,
                "any_threads":any_threads
            }),
            MAX_HELLO,
        )?;
        return Ok(());
    }
    if role == "heartbeat" {
        let response =
            service.renew_scan_for_protocol(s(&hello, "id")?, s(&hello, "token")?, protocol)?;
        write_json(&mut stream, &response, MAX_HELLO)?;
        return Ok(());
    }
    let lane = if protocol >= 2 {
        ScanLane::parse(hello["lane"].as_str())?
    } else {
        ScanLane::Any
    };
    let Some((job, raw)) = service.claim_scan_for_protocol(protocol, lane)? else {
        write_json(
            &mut stream,
            &json!({
                "empty":true,
                "protocol":protocol,
                "minimum_protocol":MIN_PROTOCOL_VERSION,
                "maximum_protocol":PROTOCOL_VERSION
            }),
            MAX_HELLO,
        )?;
        return Ok(());
    };
    write_json(&mut stream, &job, MAX_JOB)?;
    write_frame(&mut stream, &raw, MAX_MESSAGE)?;

    let inspected = read_json(&mut stream, MAX_INSPECTION)?;
    ensure!(
        verify_versions(&inspected)? == protocol,
        "Scan connection protocol changed"
    );
    let id = s(&job, "id")?;
    let token = s(&job, "token")?;
    ensure!(
        inspected["id"] == id
            && inspected["token"] == token
            && inspected["hash"] == job["hash"]
            && ((protocol == MIN_PROTOCOL_VERSION && inspected["scan_generation"].is_null())
                || inspected["scan_generation"] == job["scan_generation"]),
        "Scan reply identity mismatch"
    );
    match s(&inspected, "status")? {
        "retry" => {
            service.retry_scan(id, token, s(&inspected, "reason")?)?;
            write_json(&mut stream, &json!({"stored":true}), MAX_HELLO)?;
        }
        "incomplete" => {
            service.finalize_incomplete(id, token, s(&inspected, "reason")?)?;
            write_json(&mut stream, &json!({"stored":true}), MAX_HELLO)?;
        }
        "inspected" => {
            let inspection = &inspected["inspection"];
            ensure!(inspection.is_object(), "Missing bounded inspection result");
            let score = service.scan_learning_score(id, token, inspection)?;
            write_json(&mut stream, &json!({"learned_spam_score":score}), MAX_HELLO)?;
            let result = read_json(&mut stream, MAX_RESULT)?;
            if result["status"] == "incomplete" {
                ensure!(
                    verify_versions(&result)? == protocol,
                    "Scan connection protocol changed"
                );
                ensure!(
                    result["id"] == id
                        && result["token"] == token
                        && result["hash"] == job["hash"]
                        && ((protocol == MIN_PROTOCOL_VERSION
                            && result["scan_generation"].is_null())
                            || result["scan_generation"] == job["scan_generation"]),
                    "Incomplete scan reply identity mismatch"
                );
                service.finalize_incomplete(id, token, s(&result, "reason")?)?;
            } else {
                service.finalize_scan(id, token, &result)?;
            }
            write_json(&mut stream, &json!({"stored":true}), MAX_HELLO)?;
        }
        _ => crate::bail!("Invalid scan reply state"),
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

pub fn start(service: Arc<Service>) -> Result<std::thread::JoinHandle<()>> {
    let path = socket_path(&service.config);
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        ensure!(
            metadata.file_type().is_socket(),
            "Refusing to replace non-socket scan path"
        );
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let gate = crate::net::Gate::new(32);
    Ok(std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Some(permit) = gate.enter() else { continue };
            let service = service.clone();
            std::thread::spawn(move || {
                let _permit = permit;
                let _ = crate::resilience::boundary("security scan handoff", || {
                    handle(&service, stream)
                });
            });
        }
    }))
}

fn send_state(stream: &mut UnixStream, job: &Value, status: &str, reason: &str) -> Result<()> {
    write_json(
        stream,
        &json!({
            "protocol":job["protocol"],
            "minimum_protocol":MIN_PROTOCOL_VERSION,
            "maximum_protocol":PROTOCOL_VERSION,
            "api_version":scan::ANALYSIS_API_VERSION,
            "profile_version":scan::ANALYSIS_PROFILE_VERSION,
            "coverage_version":scan::COVERAGE_VERSION,
            "id":job["id"],
            "token":job["token"],
            "scan_generation":job["scan_generation"],
            "hash":job["hash"],
            "status":status,
            "reason":reason
        }),
        MAX_INSPECTION,
    )?;
    let acknowledgement = read_json(stream, MAX_HELLO)?;
    ensure!(
        acknowledgement["stored"] == true,
        "Scan disposition was not stored"
    );
    Ok(())
}

fn heartbeat_once(path: &Path, id: &str, token: &str) -> Result<bool> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write_json(
        &mut stream,
        &json!({
            "protocol":COMPATIBILITY_HELLO_PROTOCOL,
            "minimum_protocol":MIN_PROTOCOL_VERSION,
            "maximum_protocol":PROTOCOL_VERSION,
            "api_version":scan::ANALYSIS_API_VERSION,
            "profile_version":scan::ANALYSIS_PROFILE_VERSION,
            "coverage_version":scan::COVERAGE_VERSION,
            "role":"heartbeat",
            "id":id,
            "token":token
        }),
        MAX_HELLO,
    )?;
    let response = read_json(&mut stream, MAX_HELLO)?;
    verify_versions(&response)?;
    ensure!(response["renewed"].is_boolean(), "Invalid lease renewal");
    let requested = cancellation_requested(&response["cancellation"])?;
    Ok(response["renewed"] == true && !requested)
}

struct Heartbeat {
    stop: Arc<(Mutex<bool>, Condvar)>,
    cancelled: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Heartbeat {
    fn start(path: PathBuf, id: String, token: String) -> Self {
        Self::start_with_interval(path, id, token, Duration::from_secs(HEARTBEAT_SECONDS))
    }

    fn start_with_interval(path: PathBuf, id: String, token: String, interval: Duration) -> Self {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker_cancelled = cancelled.clone();
        let thread = std::thread::spawn(move || {
            let mut failures = 0u8;
            loop {
                let (lock, wake) = &*worker_stop;
                let Ok(guard) = lock.lock() else {
                    worker_cancelled.store(true, Ordering::Release);
                    return;
                };
                let Ok((guard, _)) = wake.wait_timeout(guard, interval) else {
                    worker_cancelled.store(true, Ordering::Release);
                    return;
                };
                if *guard {
                    return;
                }
                drop(guard);
                match heartbeat_once(&path, &id, &token) {
                    Ok(true) => failures = 0,
                    Ok(false) => {
                        worker_cancelled.store(true, Ordering::Release);
                        return;
                    }
                    Err(_) => {
                        failures = failures.saturating_add(1);
                        if failures >= 2 {
                            worker_cancelled.store(true, Ordering::Release);
                            return;
                        }
                    }
                }
            }
        });
        Self {
            stop,
            cancelled,
            thread: Some(thread),
        }
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        let (lock, wake) = &*self.stop;
        if let Ok(mut stop) = lock.lock() {
            *stop = true;
            wake.notify_all();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn scan_once(config: &Config, checker: &crate::auth::Checker, lane: ScanLane) -> Result<bool> {
    let stream = match UnixStream::connect(socket_path(config)) {
        Ok(stream) => stream,
        Err(_) => return Ok(false),
    };
    scan_stream_inner(checker, stream, Some(socket_path(config)), lane)
}

#[cfg(test)]
pub(super) fn scan_stream(checker: &crate::auth::Checker, stream: UnixStream) -> Result<bool> {
    scan_stream_inner(checker, stream, None, ScanLane::Any)
}

fn scan_stream_inner(
    checker: &crate::auth::Checker,
    mut stream: UnixStream,
    heartbeat_path: Option<PathBuf>,
    lane: ScanLane,
) -> Result<bool> {
    stream.set_read_timeout(Some(Duration::from_secs(240)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    write_json(
        &mut stream,
        &json!({
            "protocol":COMPATIBILITY_HELLO_PROTOCOL,
            "minimum_protocol":MIN_PROTOCOL_VERSION,
            "maximum_protocol":PROTOCOL_VERSION,
            "api_version":scan::ANALYSIS_API_VERSION,
            "profile_version":scan::ANALYSIS_PROFILE_VERSION,
            "coverage_version":scan::COVERAGE_VERSION,
            "role":"scanner",
            "lane":lane.name()
        }),
        MAX_HELLO,
    )?;
    let job = read_json(&mut stream, MAX_JOB)?;
    if job["empty"] == true {
        return Ok(false);
    }
    let protocol = verify_versions(&job)?;
    ensure!(
        protocol == MIN_PROTOCOL_VERSION
            || lane == ScanLane::Any
            || job["scan_lane"] == lane.name(),
        "Scan lane mismatch"
    );
    ensure!(
        !cancellation_requested(&job["cancellation"])?,
        "Scan was cancelled before it started"
    );
    let raw = read_frame(&mut stream, MAX_MESSAGE)?;
    ensure!(
        hash(&raw) == s(&job, "hash")?,
        "Local scan input hash mismatch"
    );

    let heartbeat = match heartbeat_path {
        Some(path) => Some(Heartbeat::start(
            path,
            s(&job, "id")?.to_string(),
            s(&job, "token")?.to_string(),
        )),
        None => None,
    };

    let ip: IpAddr = s(&job, "source_ip")?.parse()?;
    let policy = crate::config::Policy {
        quarantine_dmarc: true,
        ..Default::default()
    };
    let auth_result = checker.check_context(
        &raw,
        crate::auth::AuthContext {
            ip,
            helo: s(&job, "helo")?,
            from: s(&job, "sender")?,
            hostname: s(&job, "hostname")?,
            policy: &policy,
            seconds: 20,
        },
    );
    if heartbeat.as_ref().is_some_and(Heartbeat::cancelled) {
        send_state(&mut stream, &job, "incomplete", "worker-cancelled")?;
        return Ok(true);
    }
    let auth = match auth_result {
        Ok(crate::auth::Verdict::Temporary) => {
            send_state(&mut stream, &job, "retry", "authentication-temporary")?;
            return Ok(true);
        }
        Err(_) => {
            send_state(&mut stream, &job, "incomplete", "authentication-invalid")?;
            return Ok(true);
        }
        Ok(verdict) => verdict,
    };

    let inspection_result = scan::inspect_with_settings(&raw, &job["settings"]);
    if heartbeat.as_ref().is_some_and(Heartbeat::cancelled) {
        send_state(&mut stream, &job, "incomplete", "worker-cancelled")?;
        return Ok(true);
    }
    let mut inspection = match inspection_result {
        Ok(inspection) => inspection,
        Err(_) => {
            send_state(&mut stream, &job, "incomplete", "inspection-error")?;
            return Ok(true);
        }
    };
    inspection["coverage"]["input_hash"] = job["hash"].clone();
    inspection["coverage"]["cancellation"] = job["cancellation"].clone();
    write_json(
        &mut stream,
        &json!({
            "protocol":protocol,
            "minimum_protocol":MIN_PROTOCOL_VERSION,
            "maximum_protocol":PROTOCOL_VERSION,
            "api_version":scan::ANALYSIS_API_VERSION,
            "profile_version":scan::ANALYSIS_PROFILE_VERSION,
            "coverage_version":scan::COVERAGE_VERSION,
            "id":job["id"],
            "token":job["token"],
            "scan_generation":job["scan_generation"],
            "hash":job["hash"],
            "status":"inspected",
            "inspection":inspection
        }),
        MAX_INSPECTION,
    )?;
    let learning = read_json(&mut stream, MAX_HELLO)?;
    if heartbeat.as_ref().is_some_and(Heartbeat::cancelled) {
        send_state(&mut stream, &job, "incomplete", "worker-cancelled")?;
        return Ok(true);
    }
    let mut evidence = json!({
        "authentication_action":if matches!(auth,crate::auth::Verdict::Quarantine|crate::auth::Verdict::Reject(_)){"quarantine"}else{"pass-policy"},
        "source_ip":ip.to_string(),
        "helo":job["helo"],
        "engine":scan::ENGINE,
        "learned_spam_score":learning["learned_spam_score"]
    });
    ensure!(
        evidence["learned_spam_score"].as_f64().is_some(),
        "Missing learning result"
    );
    let verdict =
        scan::evaluate_inspected(&inspection, &job["rules"], &job["settings"], &evidence)?;
    let shadow = if job["shadow"].is_null() {
        Value::Null
    } else {
        json!({
            "version":job["shadow"]["version"],
            "verdict":scan::evaluate_inspected(&inspection,&job["shadow"]["rules"],&job["settings"],&evidence)?
        })
    };
    if heartbeat.as_ref().is_some_and(Heartbeat::cancelled) {
        send_state(&mut stream, &job, "incomplete", "worker-cancelled")?;
        return Ok(true);
    }
    evidence["api_version"] = json!(scan::ANALYSIS_API_VERSION);
    evidence["profile_version"] = json!(scan::ANALYSIS_PROFILE_VERSION);
    evidence["coverage_version"] = json!(scan::COVERAGE_VERSION);
    write_json(
        &mut stream,
        &json!({
            "protocol":protocol,
            "minimum_protocol":MIN_PROTOCOL_VERSION,
            "maximum_protocol":PROTOCOL_VERSION,
            "api_version":scan::ANALYSIS_API_VERSION,
            "profile_version":scan::ANALYSIS_PROFILE_VERSION,
            "coverage_version":scan::COVERAGE_VERSION,
            "status":"complete",
            "id":job["id"],
            "token":job["token"],
            "scan_generation":job["scan_generation"],
            "hash":job["hash"],
            "rule_version":job["rule_version"],
            "verdict":verdict,
            "shadow":shadow,
            "evidence":evidence
        }),
        MAX_RESULT,
    )?;
    let acknowledgement = read_json(&mut stream, MAX_HELLO)?;
    ensure!(
        acknowledgement["stored"] == true,
        "Scan result was not stored"
    );
    Ok(true)
}

pub fn run(config: Config) -> Result<()> {
    let config = Arc::new(config);
    let threads = loop {
        if let Ok(mut stream) = UnixStream::connect(socket_path(&config)) {
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            write_json(
                &mut stream,
                &json!({
                    "protocol":COMPATIBILITY_HELLO_PROTOCOL,
                    "minimum_protocol":MIN_PROTOCOL_VERSION,
                    "maximum_protocol":PROTOCOL_VERSION,
                    "api_version":scan::ANALYSIS_API_VERSION,
                    "profile_version":scan::ANALYSIS_PROFILE_VERSION,
                    "coverage_version":scan::COVERAGE_VERSION,
                    "role":"capacity"
                }),
                MAX_HELLO,
            )?;
            let response = read_json(&mut stream, MAX_HELLO)?;
            verify_versions(&response)?;
            if let Some(threads) = response["threads"].as_u64()
                && (1..=16).contains(&threads)
            {
                break usize::try_from(threads)?;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    let (light_threads, heavy_threads, any_threads) = lane_worker_counts(u64::try_from(threads)?);
    let lanes = std::iter::repeat_n(ScanLane::Heavy, usize::try_from(heavy_threads)?)
        .chain(std::iter::repeat_n(
            ScanLane::Light,
            usize::try_from(light_threads)?,
        ))
        .chain(std::iter::repeat_n(
            ScanLane::Any,
            usize::try_from(any_threads)?,
        ))
        .collect::<Vec<_>>();
    let checkers = lanes
        .into_iter()
        .map(|lane| Ok((crate::auth::Checker::new(config.dns_server)?, lane)))
        .collect::<Result<Vec<_>>>()?;
    for (checker, lane) in checkers {
        let config = config.clone();
        std::thread::spawn(move || {
            loop {
                let worked = crate::resilience::boundary("security scanner worker", || {
                    scan_once(&config, &checker, lane)
                });
                match worked {
                    Ok(true) => {}
                    Ok(false) => std::thread::sleep(Duration::from_secs(1)),
                    Err(_) => std::thread::sleep(Duration::from_secs(2)),
                }
            }
        });
    }
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_allocation_reserves_one_light_worker_and_scales_heavy_work() {
        assert_eq!(lane_worker_counts(1), (0, 0, 1));
        assert_eq!(lane_worker_counts(2), (1, 1, 0));
        assert_eq!(lane_worker_counts(3), (1, 2, 0));
        assert_eq!(lane_worker_counts(4), (1, 3, 0));
        assert_eq!(lane_worker_counts(16), (1, 15, 0));
    }

    fn version(protocol: u64, minimum: Option<u64>, maximum: Option<u64>) -> Value {
        let mut value = json!({
            "protocol":protocol,
            "api_version":scan::ANALYSIS_API_VERSION,
            "profile_version":scan::ANALYSIS_PROFILE_VERSION,
            "coverage_version":scan::COVERAGE_VERSION
        });
        if let Some(minimum) = minimum {
            value["minimum_protocol"] = json!(minimum);
        }
        if let Some(maximum) = maximum {
            value["maximum_protocol"] = json!(maximum);
        }
        value
    }

    #[test]
    fn current_worker_negotiates_current_and_legacy_protocols() {
        assert_eq!(
            negotiate_versions(&version(1, Some(1), Some(PROTOCOL_VERSION))).unwrap(),
            PROTOCOL_VERSION
        );
        assert_eq!(negotiate_versions(&version(1, None, None)).unwrap(), 1);
        assert!(verify_versions(&version(PROTOCOL_VERSION + 1, None, None)).is_err());
        assert!(
            negotiate_versions(&version(
                PROTOCOL_VERSION + 1,
                Some(PROTOCOL_VERSION + 1),
                Some(PROTOCOL_VERSION + 1)
            ))
            .is_err()
        );
    }

    #[test]
    fn current_worker_starts_with_a_legacy_compatible_hello() {
        let checker = crate::auth::Checker::new(None).unwrap();
        let (worker, mut legacy_server) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let hello = read_json(&mut legacy_server, MAX_HELLO).unwrap();
            assert_eq!(hello["protocol"], 1);
            assert_eq!(hello["minimum_protocol"], 1);
            assert_eq!(hello["maximum_protocol"], PROTOCOL_VERSION);
            write_json(&mut legacy_server, &json!({"empty":true}), MAX_HELLO).unwrap();
        });
        assert!(!scan_stream(&checker, worker).unwrap());
        server.join().unwrap();
    }

    #[test]
    fn only_clearly_simple_messages_enter_the_light_lane() {
        assert_eq!(
            scheduling_lane(b"From: sender@example.invalid\r\nSubject: simple\r\n\r\nhello"),
            "light"
        );
        for raw in [
            b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x--"
                .as_slice(),
            b"Content-Type: application/octet-stream\r\n\r\ndata".as_slice(),
            b"Content-Transfer-Encoding: BASE64\r\n\r\nZGF0YQ==".as_slice(),
            b"malformed headers without a separator".as_slice(),
        ] {
            assert_eq!(scheduling_lane(raw), "heavy");
        }
        let mut large = b"Subject: large\r\n\r\n".to_vec();
        large.resize(LIGHT_INPUT_BYTES + 1, b'x');
        assert_eq!(scheduling_lane(&large), "heavy");
    }

    #[test]
    fn local_frames_are_bounded_and_round_trip() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || write_frame(&mut writer, b"bounded", 32).unwrap());
        assert_eq!(read_frame(&mut reader, 32).unwrap(), b"bounded");
        thread.join().unwrap();
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let thread =
            std::thread::spawn(move || write_frame(&mut writer, b"too-large", 32).unwrap());
        assert!(read_frame(&mut reader, 4).is_err());
        thread.join().unwrap();
    }

    #[test]
    fn heartbeat_cancels_after_repeated_renewal_failure_and_drops_promptly() {
        let directory = crate::test_support::tempdir().unwrap();
        let heartbeat = Heartbeat::start_with_interval(
            directory.path().join("absent-socket"),
            "ingress".into(),
            "token".into(),
            Duration::from_millis(2),
        );
        for _ in 0..100 {
            if heartbeat.cancelled() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(heartbeat.cancelled());
        let started = std::time::Instant::now();
        drop(heartbeat);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
