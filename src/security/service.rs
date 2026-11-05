use super::{db::*, model::*, scan};

use crate::error::{Result, bail, ensure};

use crate::encoding::STANDARD;

use pratique::json_value::{Value, json};

use std::{
    collections::BTreeSet,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
};

pub struct Service {
    pub config: Config,
    pub db: Arc<Db>,
    pub(super) acceptance: super::transport::AcceptanceBatcher,
    pub checker: crate::auth::Checker,
    pub certificates: std::sync::OnceLock<crate::certificates::ManagedTls>,
    scan_active: AtomicUsize,
    scanner_seen: AtomicI64,
    started_at: i64,
    smtp_accepted: AtomicU64,
    smtp_deferred: AtomicU64,
    scan_retries: AtomicU64,
    delivery_workers: AtomicUsize,
    delivery_active: AtomicUsize,
    delivery_attempts: AtomicU64,
    delivery_succeeded: AtomicU64,
    delivery_deferred: AtomicU64,
    pub(super) replication_sync: std::sync::Mutex<()>,
    _lock: std::fs::File,
}
pub(super) struct DeliveryPermit<'a>(&'a AtomicUsize);
impl Drop for DeliveryPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
struct ScanPermit<'a>(&'a AtomicUsize);
impl Drop for ScanPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
fn acquire_scan(active: &AtomicUsize, limit: usize) -> Result<ScanPermit<'_>> {
    let acquired = active.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (current < limit).then_some(current + 1)
    });
    ensure!(acquired.is_ok(), "Scan concurrency budget reached");
    Ok(ScanPermit(active))
}

fn operational_alerts(
    scanner: &Value,
    jobs: &Value,
    storage_host: &Value,
    cluster: &Value,
    current: i64,
) -> Value {
    let mut alerts = Vec::new();
    let receive_records = scanner["receive_records"].as_u64().unwrap_or(0);
    let oldest_pending = scanner["oldest_pending_seconds"].as_u64().unwrap_or(0);
    if receive_records > 0 && scanner["online"] != true {
        alerts.push(json!({
            "id":"scanner-unavailable",
            "severity":"critical",
            "category":"scanning",
            "title":"Scanner unavailable with accepted mail waiting",
            "detail":format!("{receive_records} receive record(s) are durably queued; SMTP acceptance can continue within configured capacity."),
            "value":receive_records
        }));
    }
    if oldest_pending >= 300 {
        alerts.push(json!({
            "id":"scan-backlog-age",
            "severity":if oldest_pending >= 900 { "critical" } else { "warning" },
            "category":"scanning",
            "title":"Receive queue age exceeds the operating threshold",
            "detail":format!("The oldest accepted record has waited {oldest_pending} seconds for analysis."),
            "value":oldest_pending,
            "unit":"seconds"
        }));
    }
    for (state, severity, title) in [
        (
            "uncertain",
            "critical",
            "Delivery acknowledgements need review",
        ),
        ("failed", "warning", "Delivery jobs have failed"),
    ] {
        let count = jobs[state].as_u64().unwrap_or(0);
        if count > 0 {
            alerts.push(json!({
                "id":format!("delivery-{state}"),
                "severity":severity,
                "category":"delivery",
                "title":title,
                "detail":format!("{count} delivery job(s) are {state}; review before retrying to avoid duplicate delivery."),
                "value":count
            }));
        }
    }
    if matches!(storage_host["state"].as_str(), Some("warning" | "critical")) {
        let severity = storage_host["state"].as_str().unwrap_or("warning");
        alerts.push(json!({
            "id":"host-storage-reserve",
            "severity":severity,
            "category":"storage",
            "title":"Host storage reserve needs attention",
            "detail":format!(
                "{} bytes remain; SMTP admission fails closed below the {} byte reserve.",
                storage_host["available_bytes"].as_u64().unwrap_or(0),
                storage_host["minimum_free_bytes"].as_u64().unwrap_or(0)
            ),
            "value":storage_host["available_bytes"],
            "unit":"bytes"
        }));
    }
    let replication_debt = &cluster["replication_debt"];
    let debt_operations = replication_debt["operations"].as_u64().unwrap_or(0);
    let oldest_debt = replication_debt["oldest_seconds"].as_u64().unwrap_or(0);
    if debt_operations > 0 {
        alerts.push(json!({
            "id":"acceptance-replication-debt",
            "severity":if oldest_debt >= 60 { "critical" } else { "warning" },
            "category":"replication",
            "title":"Accepted mail is waiting for replica acknowledgement",
            "detail":format!("{debt_operations} acceptance operation(s) are outstanding; oldest age is {oldest_debt} seconds."),
            "value":debt_operations
        }));
    }
    let state_operations = cluster["state_replication_debt"]["operations"]
        .as_u64()
        .unwrap_or(0);
    if state_operations > 0 {
        alerts.push(json!({
            "id":"state-replication-debt",
            "severity":"warning",
            "category":"replication",
            "title":"Processing state has not converged",
            "detail":format!("{state_operations} processing-state operation(s) are waiting for replica acknowledgement."),
            "value":state_operations
        }));
    }
    if let Some(peers) = cluster["peers"].as_array() {
        for peer in peers {
            let peer_id = peer["node_id"].as_str().unwrap_or("unknown");
            let health = [&peer["outbound_health"], &peer["inbound_health"]];
            let missing = health.iter().any(|value| value.is_null());
            let failed = health.iter().any(|value| value["ok"] == false);
            let stale = health.iter().any(|value| {
                value["at"]
                    .as_i64()
                    .is_none_or(|at| current.saturating_sub(at) > 30)
            });
            if missing || failed || stale {
                let (severity, title, detail) = if failed {
                    (
                        "critical",
                        "Authenticated peer exchange is failing",
                        format!(
                            "Gateway {peer_id} reported a failed inbound or outbound peer exchange."
                        ),
                    )
                } else if missing {
                    (
                        "warning",
                        "Peer synchronization is not established",
                        format!(
                            "Gateway {peer_id} has not recorded fresh authenticated contact in both directions."
                        ),
                    )
                } else {
                    (
                        "warning",
                        "Authenticated peer contact is stale",
                        format!(
                            "Gateway {peer_id} has not completed bidirectional authenticated contact within 30 seconds."
                        ),
                    )
                };
                alerts.push(json!({
                    "id":format!("peer-contact-{peer_id}"),
                    "severity":severity,
                    "category":"replication",
                    "title":title,
                    "detail":detail
                }));
            }
        }
    }
    json!({"version":1,"items":alerts})
}

pub fn event(
    t: &mut Table,
    a: &Actor,
    action: &str,
    rid: &str,
    scope: &str,
    mut data: Value,
) -> Result<()> {
    data["request_id"] = json!(rid);

    audit(t, &a.id, action, scope, data)
}

pub fn public(m: &Value) -> Value {
    let reasons = m["verdict"]["matches"]
        .as_array()
        .map(|matches| {
            matches
                .iter()
                .filter_map(|matched| matched["reason"].as_str().map(str::to_string))
                .take(8)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "id":m["id"],
        "ingress_id":m["ingress_id"],
        "recipient":m["recipient"],
        "arrived":m["arrived"],
        "state":m["state"],
        "revision":m["revision"],
        "subject":m["subject"],
        "sender":m["sender"],
        "releasable":m["releasable"],
        "expires":m["expires"],
        "hold":m["hold"],
        "rule_version":m["rule_version"],
        "origin_node":m["origin_node"],
        "scan_owner":m["scan_owner"],
        "delivery_owner":m["delivery_owner"],
        "decision":m["verdict"]["action"],
        "coverage_complete":m["verdict"]["coverage"]["complete"],
        "reasons":reasons
    })
}

fn list_filters(d: &Value, field: &str, allowed: &[&str]) -> Result<BTreeSet<String>> {
    let Some(values) = d[field].as_array() else {
        ensure!(d[field].is_null(), "{field} must be an array");
        return Ok(BTreeSet::new());
    };
    ensure!(values.len() <= allowed.len(), "Too many {field} filters");
    values
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| crate::error!("{field} filter must be text"))?;
            ensure!(allowed.contains(&value), "Unknown {field} filter");
            Ok(value.to_string())
        })
        .collect()
}

fn list_query(d: &Value) -> Result<String> {
    let query = d["search"].as_str().unwrap_or("");
    ensure!(query.len() <= 200, "Search is too long");
    Ok(query.to_lowercase())
}

fn list_limit(d: &Value) -> Result<usize> {
    let limit = d["limit"].as_u64().unwrap_or(100);
    ensure!(
        (1..=200).contains(&limit),
        "List limit must be between 1 and 200"
    );
    Ok(usize::try_from(limit)?)
}

fn list_cursor(d: &Value, descending: bool) -> Result<(i64, String)> {
    if d["cursor"].is_null() {
        return Ok((if descending { i64::MAX } else { i64::MIN }, String::new()));
    }
    ensure!(d["cursor"].as_object().is_some(), "Invalid list cursor");
    let at = d["cursor"]["at"]
        .as_i64()
        .ok_or_else(|| crate::error!("Invalid list cursor time"))?;
    let id = d["cursor"]["id"]
        .as_str()
        .ok_or_else(|| crate::error!("Invalid list cursor identity"))?;
    key(id)?;
    Ok((at, id.to_string()))
}

fn job_public(t: &Table, job: &Value) -> Result<Value> {
    let message = job["data"]["message"].as_str();
    let route = match message {
        Some(id) => get(t, &format!("message/{id}"))?
            .map(|message| message["route"].clone())
            .unwrap_or(Value::Null),
        None => Value::Null,
    };
    Ok(json!({
        "id":job["id"],
        "kind":job["kind"],
        "state":job["state"],
        "due":job["due"],
        "attempts":job["attempts"],
        "error":job["error"],
        "recipient":job["data"]["recipient"],
        "message":job["data"]["message"],
        "plan":job["data"]["plan"],
        "released":job["data"]["released"],
        "route":route,
        "delivery_partition":job["delivery_partition"],
        "delivery_owner":job["delivery_owner"],
        "delivery_term":job["delivery_term"]
    }))
}

pub fn active(t: &Table) -> Result<Value> {
    let id = must(t, "active")?;

    ensure!(id.is_u64(), "No active rules");

    must(t, &format!("rule/{id}"))
}

pub(super) fn capacity_check(
    t: &Table,
    settings: &Value,
    bytes: usize,
    count: usize,
    jobs: usize,
) -> Result<()> {
    let usage = capacity_usage(t)?;
    let count = n(&usage, "messages")?
        .checked_add(u64::try_from(count)?)
        .ok_or_else(|| crate::error!("Message capacity overflow"))?;
    ensure!(
        count <= n(settings, "max_messages")?,
        "Message capacity reached"
    );
    let used = n(&usage, "bytes")?
        .checked_add(u64::try_from(bytes)?)
        .ok_or_else(|| crate::error!("Content capacity overflow"))?;
    ensure!(
        used <= n(settings, "max_bytes")?,
        "Content capacity reached"
    );
    let pending = n(&usage, "jobs")?
        .checked_add(u64::try_from(jobs)?)
        .ok_or_else(|| crate::error!("Job capacity overflow"))?;
    ensure!(pending <= n(settings, "max_jobs")?, "Job capacity reached");
    Ok(())
}

impl Service {
    pub fn open(config: Config) -> Result<Arc<Self>> {
        config.validate()?;

        std::fs::create_dir_all(&config.data_dir)?;

        std::fs::set_permissions(&config.data_dir, std::fs::Permissions::from_mode(0o700))?;

        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(std::path::Path::new(&config.data_dir).join("security.lock"))?;

        lock.try_lock()?;

        crate::encrypted_store::separate_key(
            std::path::Path::new(&config.data_dir),
            std::path::Path::new(&config.storage_key_file),
        )?;
        let storage_key =
            crate::encrypted_store::Key::load(std::path::Path::new(&config.storage_key_file))?;
        let db = Arc::new(Db::open(&config.db_path(), storage_key)?);

        std::fs::set_permissions(config.db_path(), std::fs::Permissions::from_mode(0o600))?;

        db.write(|t|{
let binding=json!({
"workspace":config.workspace,"instance":config.instance,"schema":2}
);
if let Some(old)=get(t,"installation")?{
ensure!(old==binding,"Store workspace, instance or schema mismatch");
}
else{
ensure!(get(t,"settings")?.is_none(),"Unbound database");
put(t,"installation",&binding)?;
put(t,"settings",&settings())?;
put(t,"rule/1",&json!({
"id":1,"state":"development","rules":rules(),"author":"bootstrap","created":now()?}
))?;
put(t,"rule_next",&json!(2))?;
put(t,"active",&Value::Null)?;
audit(t,"bootstrap","initialize","",json!({
"schema":2,"engine":scan::ENGINE}
))?;
}
super::cluster::initialize(t,&config)?;
for mut j in list(t,"job/")?{
if j["state"]=="running"{
j["state"]=json!("uncertain");
j["error"]=json!("Service restarted during an external operation; review before retry");
put(t,&format!("job/{}",s(&j,"id")?),&j)?;
audit(t,"recovery","job-uncertain",s(&j["data"],"recipient")?,json!({
"job":j["id"]}
))?;
}
}
for mut ingress in list(t,"ingress/")?{
let mut changed=super::cluster::stamp_ingress(t,&mut ingress)?;
if ingress["state"]=="leased"{
ingress["state"]=json!("queued");
ingress["due"]=json!(now()?);
ingress["lease_token"]=Value::Null;
ingress["lease_until"]=json!(0);
ingress["cancel_requested"]=json!(false);
ingress["error"]=json!("service-restarted");
changed=true;
audit(t,"recovery","scan-lease-requeued","",json!({
"ingress":ingress["id"]
}
))?;
}
if changed{
put(t,&format!("ingress/{}",s(&ingress,"id")?),&ingress)?;
}
}
if let Some(mut task) = get(t, "destination/current")?
    && task["state"] == "running" {
    task["state"] = json!("failed");
    task["error"] = json!("Connection check interrupted. Test again; saved destinations are unchanged.");
    put(t, "destination/current", &task)?;
    audit(t, "recovery", "delivery-check-interrupted", "", json!({"id":task["id"]}))?;
}
if let Some(mut task) = get(t, "directory/current")?
    && task["state"] == "running" {
        task["state"] = json!("failed");
        task["error"] = json!("Discovery interrupted by restart. Discover again; accepted recipients are unchanged.");
        put(t, "directory/current", &task)?;
        audit(t, "recovery", "recipient-discovery-interrupted", "", json!({"id":task["id"]}))?;
}
super::cluster::rebuild_replication_state(t)?;
rebuild_derived(t)?;
Ok(())}
)?;

        let checker = crate::auth::Checker::new(config.dns_server)?;

        Ok(Arc::new(Self {
            config,
            acceptance: super::transport::AcceptanceBatcher::new(db.clone())?,
            db,
            checker,
            certificates: std::sync::OnceLock::new(),
            scan_active: AtomicUsize::new(0),
            scanner_seen: AtomicI64::new(0),
            started_at: now()?,
            smtp_accepted: AtomicU64::new(0),
            smtp_deferred: AtomicU64::new(0),
            scan_retries: AtomicU64::new(0),
            delivery_workers: AtomicUsize::new(0),
            delivery_active: AtomicUsize::new(0),
            delivery_attempts: AtomicU64::new(0),
            delivery_succeeded: AtomicU64::new(0),
            delivery_deferred: AtomicU64::new(0),
            replication_sync: std::sync::Mutex::new(()),
            _lock: lock,
        }))
    }

    pub(super) fn mark_scanner_seen(&self) -> Result<()> {
        self.scanner_seen.store(now()?, Ordering::Release);
        Ok(())
    }

    pub(super) fn record_smtp_result(&self, accepted: bool) {
        if accepted {
            self.smtp_accepted.fetch_add(1, Ordering::Relaxed);
        } else {
            self.smtp_deferred.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn record_scan_retry(&self) {
        self.scan_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn set_delivery_workers(&self, workers: usize) {
        self.delivery_workers.store(workers, Ordering::Release);
    }

    pub(super) fn begin_delivery(&self) -> DeliveryPermit<'_> {
        self.delivery_attempts.fetch_add(1, Ordering::Relaxed);
        self.delivery_active.fetch_add(1, Ordering::Relaxed);
        DeliveryPermit(&self.delivery_active)
    }

    pub(super) fn record_delivery_result(&self, succeeded: bool) {
        if succeeded {
            self.delivery_succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.delivery_deferred.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    pub(super) fn replication_export(&self, sequence: u64) -> Result<Option<(Value, Vec<u8>)>> {
        self.db
            .write(|t| super::cluster::export_acceptance(t, sequence))
    }

    pub(super) fn replication_export_batch(
        &self,
        after_sequence: u64,
        max_operations: usize,
        max_bytes: usize,
    ) -> Result<Vec<(Value, Vec<u8>)>> {
        self.db
            .write(|t| super::cluster::export_batch(t, after_sequence, max_operations, max_bytes))
    }

    pub(super) fn replication_expected_sequence(&self, origin: &str) -> Result<u64> {
        self.db
            .write(|t| super::cluster::expected_sequence(t, origin))
    }

    pub(super) fn replication_acknowledge(&self, peer: &str, sequence: u64) -> Result<u64> {
        self.db
            .write(|t| super::cluster::acknowledge(t, peer, sequence))
    }

    #[cfg(test)]
    pub(super) fn replication_apply(&self, operation: &Value, raw: &[u8]) -> Result<u64> {
        self.db.write(|t| {
            let record = &operation["record"];
            ensure!(
                record["api_version"] == scan::ANALYSIS_API_VERSION
                    && record["profile_version"] == scan::ANALYSIS_PROFILE_VERSION
                    && record["coverage_version"] == scan::COVERAGE_VERSION,
                "Replicated analysis profile mismatch"
            );
            must(t, &format!("rule/{}", n(record, "rule_version")?))?;
            let origin = s(operation, "origin")?;
            let sequence = n(operation, "sequence")?;
            let applied = get(t, &format!("replication_applied/{origin}"))?
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            if sequence > applied {
                let settings = must(t, "settings")?;
                let recipients = arr(record, "recipients")?.len();
                self.capacity(t, &settings, raw.len(), recipients, recipients)?;
            }
            super::cluster::apply_acceptance(t, operation, raw)
        })
    }

    pub(super) fn replication_apply_batch(&self, operations: &[(Value, Vec<u8>)]) -> Result<u64> {
        ensure!(!operations.is_empty(), "Replication batch is empty");
        self.db.write(|t| {
            let origin = s(&operations[0].0, "origin")?;
            let mut applied = get(t, &format!("replication_applied/{origin}"))?
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            for (operation, raw) in operations {
                ensure!(
                    s(operation, "origin")? == origin,
                    "Mixed replication origins"
                );
                let record = &operation["record"];
                ensure!(
                    record["api_version"] == scan::ANALYSIS_API_VERSION
                        && record["profile_version"] == scan::ANALYSIS_PROFILE_VERSION
                        && record["coverage_version"] == scan::COVERAGE_VERSION,
                    "Replicated analysis profile mismatch"
                );
                must(t, &format!("rule/{}", n(record, "rule_version")?))?;
                let sequence = n(operation, "sequence")?;
                if sequence > applied {
                    let settings = must(t, "settings")?;
                    let recipients = arr(record, "recipients")?.len();
                    self.capacity(t, &settings, raw.len(), recipients, recipients)?;
                }
                applied = super::cluster::apply_acceptance(t, operation, raw)?;
            }
            Ok(applied)
        })
    }

    pub(super) fn replication_export_state_batch(
        &self,
        after_sequence: u64,
        max_operations: usize,
        max_bytes: usize,
    ) -> Result<Vec<Value>> {
        self.db.write(|table| {
            super::cluster::export_state_batch(table, after_sequence, max_operations, max_bytes)
        })
    }

    pub(super) fn replication_expected_state_sequence(&self, origin: &str) -> Result<u64> {
        self.db
            .write(|table| super::cluster::expected_state_sequence(table, origin))
    }

    pub(super) fn replication_acknowledge_state(&self, peer: &str, sequence: u64) -> Result<u64> {
        self.db
            .write(|table| super::cluster::acknowledge_state(table, peer, sequence))
    }

    pub(super) fn replication_apply_state_batch(&self, operations: &[Value]) -> Result<u64> {
        ensure!(!operations.is_empty(), "Replication state batch is empty");
        self.db.write(|table| {
            let origin = s(&operations[0], "origin")?;
            let mut applied = 0;
            for operation in operations {
                ensure!(s(operation, "origin")? == origin, "Mixed state origins");
                applied = super::cluster::apply_state(table, operation)?;
            }
            Ok(applied)
        })
    }

    pub fn start_tls(self: &Arc<Self>) -> Result<()> {
        ensure!(self.certificates.get().is_none(), "TLS already started");
        let db = self.db.clone();
        let manager = crate::certificates::ManagedTls::start(
            &self.config.tls_cert,
            &self.config.tls_key,
            self.config.acme.as_ref(),
            move |kind| {
                if let Err(e) = db.write(|t| {
                    audit(
                        t,
                        "certificate-manager",
                        "tls-certificate-event",
                        "",
                        json!({"event":kind}),
                    )
                }) {
                    eprintln!("TLS audit write failed: {e}");
                }
            },
        )?;
        self.certificates
            .set(manager)
            .map_err(|_| crate::error!("TLS already started"))
    }

    pub fn tls(&self) -> Result<Arc<pratique::tls::server::ServerConfig>> {
        Ok(self
            .certificates
            .get()
            .ok_or_else(|| crate::error!("TLS has not started"))?
            .tls
            .clone())
    }

    fn tls_status(&self) -> Result<Value> {
        self.certificates.get().map(|c| c.status()).unwrap_or_else(|| Ok(json!({"mode":if self.config.acme.is_some(){"letsencrypt"}else{"manual"},"ready":false,"running":false})))
    }

    pub fn settings(&self) -> Result<Value> {
        self.db
            .get("settings")?
            .ok_or_else(|| crate::error!("Settings missing"))
    }

    pub fn bootstrap(&self, name: &str, password_hash: &str) -> Result<()> {
        key(name)?;

        argon2::PasswordHash::new(password_hash)
            .map_err(|_| crate::error!("Invalid password hash"))?;

        self.db.write(|t| {
            ensure!(get(t, "bootstrapped")?.is_none(), "Already bootstrapped");

            let mut actor = pratique::json_value::to_value(Actor::owner(name))?;

            actor["revision"] = json!(1);

            actor["enabled"] = json!(true);

            actor["hash"] = json!(password_hash);

            put(t, &format!("identity/{name}"), &actor)?;

            put(t, "bootstrapped", &json!(true))?;

            audit(
                t,
                "local-console",
                "bootstrap-identity",
                "",
                json!({
                "identity":name}
                ),
            )
        })
    }

    pub fn local_actor(&self, name: &str) -> Result<Actor> {
        key(name)?;

        let u = self
            .db
            .get(&format!("identity/{name}"))?
            .ok_or_else(|| crate::error!("Sign in to continue"))?;

        ensure!(u["enabled"] == true, "Identity disabled");

        Ok(pratique::json_value::from_value(u)?)
    }

    pub fn control(&self, raw: &[u8], signature: &str) -> Result<Value> {
        ensure!(raw.len() <= MAX_BODY, "Command too large");

        use pratique::crypto::{hmac::Hmac, sha2::Sha256};
        use subtle::ConstantTimeEq;
        let key = crate::config::secret(&self.config.control_key_file)?;
        let expected = Hmac::<Sha256>::mac(key.as_bytes(), raw)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>();

        ensure!(
            bool::from(expected.as_bytes().ct_eq(signature.as_bytes())),
            "Control signature invalid"
        );

        let e: Value = pratique::json_value::from_slice(raw)?;

        ensure!(
            e["version"] == 1
                && e["workspace"] == self.config.workspace
                && e["audience"] == self.config.instance,
            "Wrong protocol, workspace or audience"
        );

        let at = e["at"]
            .as_i64()
            .ok_or_else(|| crate::error!("Invalid timestamp"))?;

        ensure!(now()?.abs_diff(at) <= 60, "Expired command");

        let nonce = s(&e, "nonce")?;

        ensure!(
            nonce.len() == 32 && nonce.bytes().all(|x| x.is_ascii_hexdigit()),
            "Invalid nonce"
        );

        let a: Actor = pratique::json_value::from_value(e["actor"].clone())?;

        ensure!(
            !a.id.is_empty() && a.id.len() <= 128 && a.mailbox.is_none(),
            "Invalid control actor"
        );

        let trust = self
            .config
            .trusted_admin
            .clone()
            .unwrap_or_else(|| Actor::owner("central"));

        ensure!(
            a.permissions.iter().all(|p| trust.permissions.contains(p)),
            "Issuer permission ceiling exceeded"
        );

        for (scope, ceiling) in [
            (&a.domains, &trust.domains),
            (&a.mailboxes, &trust.mailboxes),
        ] {
            ensure!(
                ceiling.contains(&"*".into()) || scope.iter().all(|s| ceiling.contains(s)),
                "Issuer scope ceiling exceeded"
            );
        }

        self.db.write(|t| {
            for (k, v) in keyed(t, "nonce/")? {
                if v.as_i64().unwrap_or(0) < now()? {
                    remove(t, &k)?;
                }
            }

            ensure!(
                list(t, "nonce/")?.len() < 10000,
                "Control request capacity reached"
            );

            let k = format!("nonce/{nonce}");

            ensure!(get(t, &k)?.is_none(), "Replay rejected");

            put(t, &k, &json!(now()? + 120))
        })?;

        self.command(&a, pratique::json_value::from_value(e["command"].clone())?)
    }

    pub fn command(&self, a: &Actor, c: Command) -> Result<Value> {
        let permission = permission(&c.action).ok_or_else(|| crate::error!("Unknown command"))?;

        if a.mailbox.is_some() {
            ensure!(
                ["digest-review", "digest-action", "content"].contains(&c.action.as_str()),
                "Mailbox endpoint only supports digest review"
            );
        } else {
            a.require(permission, None)?;
        }

        ensure!(
            (16..=64).contains(&c.request_id.len())
                && c.request_id
                    .bytes()
                    .all(|x| x.is_ascii_hexdigit() || x == b'-'),
            "Stable request ID required"
        );

        let fingerprint = hash(&pratique::json_value::to_vec(&json!({
        "actor":a,"command":c}
        ))?);

        self.db.write(|t| {
            let receipt_key = format!("receipt/{}", c.request_id);

            if let Some(r) = get(t, &receipt_key)? {
                ensure!(
                    r["hash"] == fingerprint,
                    "Request ID reused for a different command"
                );

                return Ok(r["result"].clone());
            }

            let result = self.execute(t, a, &c.action, &c.data, &c.request_id)?;

            if ![
                "status",
                "setup",
                "recipient-discovery",
                "delivery-status",
                "rules",
                "ingress",
                "messages",
                "message-detail",
                "content",
                "digests",
                "digest-review",
                "jobs",
                "audit",
                "identities",
                "remediation-review",
                "learning",
                "cluster-reconcile",
            ]
            .contains(&c.action.as_str())
            {
                ensure!(
                    list(t, "receipt/")?.len() < 100000,
                    "Command receipt capacity reached; maintenance required"
                );

                put(
                    t,
                    &receipt_key,
                    &json!({
                    "hash":fingerprint,"result":result,"at":now()?}
                    ),
                )?;
            }

            Ok(result)
        })
    }

    fn execute(
        &self,
        t: &mut Table,
        a: &Actor,
        action: &str,
        d: &Value,
        rid: &str,
    ) -> Result<Value> {
        let settings = must(t, "settings")?;

        match action {
            "delivery-discover" | "delivery-test" => self.destination_start(t, a, action, d, rid),
            "delivery-status" => self.destination_status(t, a),
            "delivery-save" => self.destination_save(t, a, d, rid),
            "recipient-discover" => self.directory_start(t, a, d, rid),
            "recipient-discovery" => self.directory_status(t, a),
            "recipient-apply" => {
                let (task, changes) = self.directory_changes(t, a, d)?;
                let result = self.execute(
                    t,
                    a,
                    "configure",
                    &json!({
                        "expected_revision":d["expected_revision"], "settings":changes
                    }),
                    rid,
                )?;
                event(
                    t,
                    a,
                    action,
                    rid,
                    "",
                    json!({"discovery":task["id"],
                    "source":"microsoft365", "discovered":arr(&task,"addresses")?.len(),
                    "removed":0, "revision":result["revision"]}),
                )?;
                let mut task = task;
                task["state"] = json!("applied");
                put(t, "directory/current", &task)?;
                Ok(result)
            }
            "status" => {
                let global = a.global(&settings).is_ok();
                let usage = capacity_usage(t)?;
                let (
                    mut counts,
                    jobs,
                    bytes,
                    receive_records,
                    pending_recipients,
                    oldest_arrival,
                    receive_states,
                ) = if global {
                    let receive_states = state_counts(t, "ingress")?;
                    let receive_records = receive_states
                        .as_object()
                        .ok_or_else(|| crate::error!("Invalid ingress status counters"))?
                        .values()
                        .try_fold(0u64, |total, value| -> Result<u64> {
                            let count = value
                                .as_u64()
                                .ok_or_else(|| crate::error!("Invalid ingress status counter"))?;
                            total
                                .checked_add(count)
                                .ok_or_else(|| crate::error!("Ingress status counter overflow"))
                        })?;
                    (
                        state_counts(t, "message")?,
                        state_counts(t, "job")?,
                        n(&usage, "bytes")?,
                        receive_records,
                        ingress_recipient_count(t)?,
                        oldest_ingress_arrival(t)?,
                        receive_states,
                    )
                } else {
                    let mut counts = json!({});
                    let mut jobs = json!({});
                    let mut hashes = BTreeSet::new();
                    for message in list(t, "message/")? {
                        if a.visible(s(&message, "recipient")?) {
                            let state = s(&message, "state")?;
                            counts[state] = json!(counts[state].as_u64().unwrap_or(0) + 1);
                            hashes.insert(s(&message, "hash")?.to_string());
                        }
                    }
                    let mut receive_records = 0u64;
                    let mut pending_recipients = 0u64;
                    let mut oldest_arrival: Option<i64> = None;
                    let mut receive_states = json!({});
                    for pending in list(t, "ingress/")? {
                        let visible = arr(&pending, "recipients")?
                            .iter()
                            .filter_map(Value::as_str)
                            .filter(|recipient| a.visible(recipient))
                            .count() as u64;
                        if visible > 0 {
                            hashes.insert(s(&pending, "hash")?.to_string());
                            receive_records += 1;
                            pending_recipients += visible;
                            oldest_arrival =
                                Some(oldest_arrival.map_or(
                                    pending["arrived"].as_i64().unwrap_or(0),
                                    |oldest| {
                                        oldest.min(pending["arrived"].as_i64().unwrap_or(oldest))
                                    },
                                ));
                            let state = s(&pending, "state")?;
                            receive_states[state] =
                                json!(receive_states[state].as_u64().unwrap_or(0) + 1);
                        }
                    }
                    for job in list(t, "job/")? {
                        if a.visible(s(&job["data"], "recipient")?) {
                            let state = s(&job, "state")?;
                            jobs[state] = json!(jobs[state].as_u64().unwrap_or(0) + 1);
                        }
                    }
                    use redb::ReadableTable;
                    let bytes = hashes
                        .iter()
                        .filter_map(|hash| {
                            t.get(format!("blob/{hash}").as_str())
                                .ok()
                                .flatten()
                                .map(|blob| blob.value().len() as u64)
                        })
                        .sum();
                    (
                        counts,
                        jobs,
                        bytes,
                        receive_records,
                        pending_recipients,
                        oldest_arrival,
                        receive_states,
                    )
                };
                if pending_recipients > 0 {
                    counts["pending-scan"] = json!(pending_recipients);
                }

                let current = now()?;
                let scanner_seen = self.scanner_seen.load(Ordering::Acquire);
                let scanner_last_seen = (scanner_seen > 0).then_some(scanner_seen);
                let scanner_online = scanner_last_seen
                    .is_some_and(|seen| (0..=45).contains(&current.saturating_sub(seen)));
                let scanner = json!({
                    "online":scanner_online,
                    "last_seen":scanner_last_seen,
                    "stale_after_seconds":45,
                    "configured_workers":settings["scan_concurrency"],
                    "active":self.scan_active.load(Ordering::Relaxed),
                    "receive_records":receive_records,
                    "pending_recipients":pending_recipients,
                    "oldest_pending_seconds":oldest_arrival.map(|arrival| current.saturating_sub(arrival).max(0)),
                    "states":receive_states,
                    "retries_since_start":self.scan_retries.load(Ordering::Relaxed),
                    "protocol_version":super::scan_worker::PROTOCOL_VERSION,
                    "api_version":scan::ANALYSIS_API_VERSION,
                    "profile_version":scan::ANALYSIS_PROFILE_VERSION,
                    "coverage_version":scan::COVERAGE_VERSION
                });

                let capacity = if global {
                    json!({
                        "messages":{"used":usage["messages"],"limit":settings["max_messages"]},
                        "jobs":{"used":usage["jobs"],"limit":settings["max_jobs"]},
                        "bytes":{"used":usage["bytes"],"limit":settings["max_bytes"]}
                    })
                } else {
                    Value::Null
                };
                let storage_host = if global {
                    let available =
                        super::filesystem::available(std::path::Path::new(&self.config.data_dir))?;
                    let minimum = n(&settings, "min_free_bytes")?;
                    json!({
                        "available_bytes":available,
                        "minimum_free_bytes":minimum,
                        "state":if available < minimum { "critical" } else if available < minimum.saturating_mul(2) { "warning" } else { "healthy" },
                        "admission":"fail-closed"
                    })
                } else {
                    Value::Null
                };
                let cluster = super::cluster::status(t, settings["enabled"] == true)?;
                let alerts = operational_alerts(&scanner, &jobs, &storage_host, &cluster, current);

                Ok(json!({
                "instance":self.config.instance,"workspace":self.config.workspace,"version":1,"storage_schema":2,"tls":self.tls_status()?,"storage_encryption":{"enabled":true,"cipher":"AES-256-GCM","key_custody":"installation-managed"},"storage_host":storage_host,"at":current,"enabled":settings["enabled"],"active":must(t,"active")?,"messages":counts,"jobs":jobs,"bytes":bytes,"scanner":scanner,"delivery":{"configured_workers":settings["delivery_concurrency"],"running_workers":self.delivery_workers.load(Ordering::Acquire),"active":self.delivery_active.load(Ordering::Relaxed),"attempts_since_start":self.delivery_attempts.load(Ordering::Relaxed),"succeeded_since_start":self.delivery_succeeded.load(Ordering::Relaxed),"deferred_since_start":self.delivery_deferred.load(Ordering::Relaxed)},"cluster":cluster,"alerts":alerts,"smtp":{"since":self.started_at,"accepted":self.smtp_accepted.load(Ordering::Relaxed),"deferred":self.smtp_deferred.load(Ordering::Relaxed),"acceptance_storage":self.acceptance.status()},"capacity":capacity,"capabilities":["native-inspection","smtp-gateway","rules","quarantine","digests","workglen","graph","ews","ai-instructions","authenticated-peer-replication","replicated-processing-state","fenced-ownership-operations","native-free-space-admission","cluster-replication-telemetry","content-hash-reconciliation","safe-node-exclusion","derived-operational-alerts","bounded-acceptance-group-commit","indexed-concurrent-delivery","bounded-operational-lists","message-journey"],"engine":scan::ENGINE}
                ))
            }

            "cluster-reconcile" => {
                a.global(&settings)?;
                super::cluster::reconciliation(t)
            }

            "cluster-compact" => {
                a.global(&settings)?;
                ensure!(
                    d["confirm"] == true,
                    "Confirm bounded replication compaction"
                );
                super::cluster::compact_logs(t, &a.id)
            }

            "cluster-drain" => {
                a.global(&settings)?;
                ensure!(d["confirm"] == true, "Confirm cluster drain");
                super::cluster::begin_drain(
                    t,
                    &a.id,
                    s(d, "partition")?,
                    s(d, "new_owner")?,
                    n(d, "expected_term")?,
                )
            }

            "cluster-handoff" => {
                a.global(&settings)?;
                ensure!(d["confirm"] == true, "Confirm ownership handoff");
                super::cluster::complete_handoff(
                    t,
                    &a.id,
                    s(d, "partition")?,
                    s(d, "new_owner")?,
                    n(d, "expected_term")?,
                )
            }

            "cluster-handoff-cancel" => {
                a.global(&settings)?;
                ensure!(d["confirm"] == true, "Confirm planned handoff cancellation");
                super::cluster::cancel_handoff(
                    t,
                    &a.id,
                    s(d, "partition")?,
                    s(d, "expected_owner")?,
                    n(d, "expected_term")?,
                    s(d, "expected_pending_owner")?,
                    n(d, "expected_pending_term")?,
                )
            }

            "cluster-takeover" => {
                a.global(&settings)?;
                ensure!(
                    d["confirm"] == true
                        && d["old_owner_fenced"] == true
                        && d["acknowledge_incomplete_replication"] == true,
                    "Confirm the old owner is fenced and acknowledge incomplete-replication risk"
                );
                let partition = s(d, "partition")?;
                let current = must(t, &format!("ownership/{partition}"))?;
                ensure!(
                    current["owner"] == s(d, "expected_owner")?
                        && current["term"] == d["expected_term"],
                    "Ownership changed; refresh cluster state"
                );
                super::cluster::operator_takeover(t, &a.id, partition, n(d, "expected_term")?)
            }

            "cluster-rejoin" => {
                a.global(&settings)?;
                ensure!(d["confirm"] == true, "Confirm cluster rejoin");
                super::cluster::rejoin(t, &a.id)
            }

            "cluster-exclude" => {
                a.global(&settings)?;
                ensure!(d["confirm"] == true, "Confirm safe node exclusion");
                super::cluster::exclude(t, &a.id)
            }

            "cluster-resync" => {
                a.global(&settings)?;
                ensure!(
                    d["confirm"] == true && d["acknowledge_acceptance_pause"] == true,
                    "Confirm resynchronization and its acceptance pause"
                );
                super::cluster::begin_resync(t, &a.id, s(d, "peer")?)
            }

            "setup" => {
                a.global(&settings)?;

                Ok(json!({
                "settings":settings,"admin_origin":self.config.admin_origin,"recipient_directory":{"configured":self.config.recipient_directory.is_some(),"provider":"microsoft365","mode":"review-and-add"},"routes":self.destination_summaries(&settings)?,"connector_profiles":self.config.connectors.iter().map(|(k,c)|(k.clone(),json!({
                "type":c.r#type,"mailboxes":c.mailboxes}
                ))).collect::<pratique::json_value::Map<_,_>>(),"origin":self.config.origin,"instance":self.config.instance,"tls":self.tls_status()?,"storage_encryption":{"enabled":true,"cipher":"AES-256-GCM","key_custody":"installation-managed"},"tests":get(t,"connection_tests")?.unwrap_or(json!({
                }
                )),"native_scanner":{
                "engine":scan::ENGINE,"archives":["ZIP stored/deflate","TAR/USTAR/PAX/GNU names","GZIP/TAR.GZ","RAR4/5 stored members","7z Copy/DEFLATE/LZMA1/LZMA2","BZIP2","XZ single-filter LZMA2","LZMA-alone"],"unsupported":"Compressed/encrypted/solid/multi-volume archives and unsupported features are administrator-only quarantine","external_services":false}
                }
                ))
            }

            "configure" => {
                a.global(&settings)?;

                ensure!(
                    d["expected_revision"] == settings["revision"],
                    "Configuration changed; reload"
                );

                let changes = d["settings"]
                    .as_object()
                    .ok_or_else(|| crate::error!("Settings must be an object"))?;

                let mut new = settings.clone();

                for (k, v) in changes {
                    ensure!(
                        settings.get(k).is_some()
                            && !["revision", "retrospective_default", "delivery_destinations"]
                                .contains(&k.as_str()),
                        "Unknown or protected setting"
                    );

                    new[k] = v.clone();
                }

                self.validate_settings(&new)?;

                a.global(&new)?;

                if new["enabled"] == true
                    && (settings["enabled"] != true
                        || self.connection_fingerprint(&new)?
                            != self.connection_fingerprint(&settings)?)
                {
                    active(t)?;

                    let tests = must(t, "connection_tests")?;

                    ensure!(
                        tests["ok"] == true
                            && tests["fingerprint"] == self.connection_fingerprint(&new)?
                            && now()?.saturating_sub(tests["at"].as_i64().unwrap_or(0)) < 3600,
                        "Run successful connection tests for these settings first"
                    );
                }

                new["revision"] = json!(n(&settings, "revision")? + 1);

                put(t, "settings", &new)?;

                event(
                    t,
                    a,
                    action,
                    rid,
                    "",
                    json!({
                    "before":settings,"after":new}
                    ),
                )?;

                Ok(json!({
                "revision":new["revision"],"enabled":new["enabled"]}
                ))
            }

            "connection-test" => {
                a.global(&settings)?;

                let result = self.connection_tests(&settings)?;

                put(t, "connection_tests", &result)?;

                event(
                    t,
                    a,
                    action,
                    rid,
                    "",
                    json!({
                    "ok":result["ok"]}
                    ),
                )?;

                Ok(result)
            }

            "rules" => {
                let mut rows = list(t, "rule/")?;

                rows.sort_by_key(|v| std::cmp::Reverse(v["id"].as_u64().unwrap_or(0)));

                rows.truncate(100);

                for v in &mut rows {
                    if v.get("test").is_some()
                        && (a.global(&settings).is_err()
                            || (!a.permissions.contains(&"content".into())
                                && v["test"]["actor"] != a.id))
                    {
                        v["test"].as_object_mut().unwrap().remove("messages");

                        v["test"]["sample_details_restricted"] = json!(true);
                    }
                }

                Ok(json!({
                "active":must(t,"active")?,"versions":rows}
                ))
            }

            "draft" => {
                a.global(&settings)?;

                scan::validate_rules(&d["rules"])?;

                let version = must(t, "rule_next")?.as_u64().unwrap_or(0);

                ensure!(version < 10000, "Rule history capacity reached");

                let v = json!({
                "id":version,"state":"development","rules":d["rules"],"author":a.id,"created":now()?,"based_on":d["based_on"]}
                );

                put(t, &format!("rule/{version}"), &v)?;

                put(t, "rule_next", &json!(version + 1))?;

                event(
                    t,
                    a,
                    action,
                    rid,
                    "",
                    json!({
                    "version":version}
                    ),
                )?;

                Ok(v)
            }

            "test" => {
                a.global(&settings)?;

                let version = n(d, "version")?;

                let mut v = must(t, &format!("rule/{version}"))?;

                ensure!(
                    v["state"] == "development",
                    "Only Development can enter Test"
                );

                let ids = d["message_ids"].as_array().cloned().unwrap_or_default();

                let samples = d["samples"].as_array().cloned().unwrap_or_default();

                ensure!(
                    (1..=50).contains(&(ids.len() + samples.len())),
                    "Select 1–50 samples"
                );

                let mut corpus = Vec::new();

                for i in ids {
                    let m = message(
                        t,
                        i.as_str()
                            .ok_or_else(|| crate::error!("Invalid sample ID"))?,
                    )?;

                    a.require("content", Some(s(&m, "recipient")?))?;

                    corpus.push((m["id"].clone(), body(t, &m)?, m["engines"].clone()));
                }

                for (i, b) in samples.iter().enumerate() {
                    corpus.push((
                        json!(format!("sample-{i}")),
                        STANDARD.decode(
                            b.as_str()
                                .ok_or_else(|| crate::error!("Invalid encoded sample"))?,
                        )?,
                        json!({}),
                    ));
                }

                let old = active(t).ok();

                let mut report = Vec::new();

                for (id, raw, e) in corpus {
                    let new = self.evaluate(t, &raw, &v["rules"], &settings, &e)?;

                    let old = old
                        .as_ref()
                        .map(|v| self.evaluate(t, &raw, &v["rules"], &settings, &e))
                        .transpose()?;

                    report.push(json!({
"id":id,"hash":hash(&raw),"changed":old.as_ref().is_none_or(|x|x["action"]!=new["action"]),"proposed":new,"active":old}
));
                }

                v["state"] = json!("test");

                v["tested_at"] = json!(now()?);

                v["test"] = json!({
                "actor":a.id,"messages":report,"count":report.len(),"complete":true,"scope":"selected samples only","settings_revision":settings["revision"],"engine":scan::ENGINE}
                );

                put(t, &format!("rule/{version}"), &v)?;

                put(t, "shadow", &json!(version))?;

                event(
                    t,
                    a,
                    action,
                    rid,
                    "",
                    json!({
                    "version":version,"count":report.len()}
                    ),
                )?;

                Ok(v)
            }

            "activate" | "rollback" => {
                a.global(&settings)?;

                let previous = must(t, "active")?;

                ensure!(d["expected_active"] == previous, "Active version changed");

                ensure!(d["confirm"] == true, "Confirm activation");

                let version = n(d, "version")?;

                let mut v = must(t, &format!("rule/{version}"))?;

                ensure!(
                    v["state"] == "test" || v["state"] == "active",
                    "Test version before activation"
                );

                if action == "rollback" {
                    ensure!(
                        v.get("published_at").is_some(),
                        "Rollback requires a previously published version"
                    );
                }

                v["state"] = json!("active");

                if v.get("published_at").is_none() {
                    v["published_at"] = json!(now()?);
                }

                v["activated_by"] = json!(a.id);

                put(t, &format!("rule/{version}"), &v)?;

                put(t, "active", &json!(version))?;

                event(
                    t,
                    a,
                    action,
                    rid,
                    "",
                    json!({
                    "previous":previous,"version":version,"retrospective":false}
                    ),
                )?;

                Ok(json!({
                "active":version,"previous":previous,"retrospective":false}
                ))
            }

            "ingress" => {
                let states = list_filters(d, "states", &["queued", "leased", "retrying"])?;
                let query = list_query(d)?;
                let node = d["node"].as_str().unwrap_or("");
                ensure!(
                    node.is_empty() || node.len() <= 100,
                    "Node filter is too long"
                );
                let limit = list_limit(d)?;
                let (after, last) = list_cursor(d, false)?;
                let mut rows = list(t, "ingress/")?;
                rows.sort_by(|a, b| {
                    (a["arrived"].as_i64(), a["id"].as_str())
                        .cmp(&(b["arrived"].as_i64(), b["id"].as_str()))
                });
                let candidates: Vec<_> = rows
                    .into_iter()
                    .filter(|record| {
                        record["arrived"].as_i64().unwrap_or(0) > after
                            || (record["arrived"] == after
                                && record["id"].as_str().unwrap_or("") > last.as_str())
                    })
                    .collect();
                let mut result = Vec::new();
                let mut cursor = Value::Null;
                let mut scanned = 0;
                for record in &candidates {
                    scanned += 1;
                    cursor = json!({"at":record["arrived"],"id":record["id"]});
                    let recipients = arr(record, "recipients")?
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|recipient| a.visible(recipient))
                        .map(str::to_string)
                        .collect::<Vec<_>>();
                    let state_match = states.is_empty() || states.contains(s(record, "state")?);
                    let query_match = format!(
                        "{} {} {}",
                        s(record, "id")?,
                        s(record, "envelope_from")?,
                        recipients.join(" ")
                    )
                    .to_lowercase()
                    .contains(&query);
                    let node_match = node.is_empty()
                        || record["origin_node"] == node
                        || record["scan_owner"] == node
                        || record["delivery_owner"] == node;
                    if !recipients.is_empty() && state_match && query_match && node_match {
                        result.push(json!({
                            "id":record["id"],
                            "state":record["state"],
                            "arrived":record["arrived"],
                            "due":record["due"],
                            "attempts":record["attempts"],
                            "lease_until":record["lease_until"],
                            "error":record["error"],
                            "sender":record["envelope_from"],
                            "recipients":recipients,
                            "rule_version":record["rule_version"],
                            "api_version":record["api_version"],
                            "profile_version":record["profile_version"],
                            "coverage_version":record["coverage_version"],
                            "origin_node":record["origin_node"],
                            "scan_owner":record["scan_owner"],
                            "scan_generation":record["scan_generation"],
                            "delivery_owner":record["delivery_owner"],
                            "delivery_partition":record["delivery_partition"],
                            "replication":if record["origin_sequence"].as_u64().unwrap_or(0)>0{"tracked"}else{"standalone"}
                        }));
                    }
                    if result.len() == limit || scanned == 2000 {
                        break;
                    }
                }
                if scanned == candidates.len() {
                    cursor = Value::Null;
                }
                let (totals, total_recipients) = if a.global(&settings).is_ok() {
                    (state_counts(t, "ingress")?, ingress_recipient_count(t)?)
                } else {
                    let mut totals = json!({});
                    let mut total_recipients = 0u64;
                    for record in list(t, "ingress/")? {
                        let visible = arr(&record, "recipients")?
                            .iter()
                            .filter_map(Value::as_str)
                            .filter(|recipient| a.visible(recipient))
                            .count() as u64;
                        if visible > 0 {
                            let state = s(&record, "state")?;
                            totals[state] = json!(totals[state].as_u64().unwrap_or(0) + 1);
                            total_recipients = total_recipients.saturating_add(visible);
                        }
                    }
                    (totals, total_recipients)
                };
                Ok(json!({
                    "instance":self.config.instance,
                    "records":result,
                    "totals":totals,
                    "total_recipients":total_recipients,
                    "limit":limit,
                    "next_cursor":cursor,
                    "scan_limit":2000
                }))
            }

            "messages" => {
                let states = list_filters(
                    d,
                    "states",
                    &[
                        "queued",
                        "quarantined",
                        "release-queued",
                        "delivered",
                        "discarded",
                        "expired",
                    ],
                )?;
                let query = list_query(d)?;
                let reason = d["reason"].as_str().unwrap_or("").to_lowercase();
                ensure!(reason.len() <= 100, "Reason filter is too long");
                let node = d["node"].as_str().unwrap_or("");
                ensure!(
                    node.is_empty() || node.len() <= 100,
                    "Node filter is too long"
                );
                let hold = d["hold"].as_bool();
                ensure!(
                    hold.is_some() || d["hold"].is_null(),
                    "Hold filter must be boolean"
                );
                let releasable = d["releasable"].as_bool();
                ensure!(
                    releasable.is_some() || d["releasable"].is_null(),
                    "Release eligibility filter must be boolean"
                );
                let limit = list_limit(d)?;
                let mut rows = list(t, "message/")?;
                rows.sort_by(|a, b| {
                    (b["arrived"].as_i64(), b["id"].as_str())
                        .cmp(&(a["arrived"].as_i64(), a["id"].as_str()))
                });
                let (mut before, last) = list_cursor(d, true)?;
                if d["cursor"].is_null() {
                    before = d["before"].as_i64().unwrap_or(now()? + 1);
                }
                let mut result = Vec::new();
                let mut cursor = Value::Null;
                let mut scanned = 0;
                let candidates: Vec<_> = rows
                    .into_iter()
                    .filter(|m| {
                        m["arrived"].as_i64().unwrap_or(0) < before
                            || (m["arrived"] == before
                                && m["id"].as_str().unwrap_or("") < last.as_str())
                    })
                    .collect();
                for m in &candidates {
                    scanned += 1;
                    cursor = json!({
                    "at":m["arrived"],"id":m["id"]}
                    );
                    let visible = a.visible(s(m, "recipient")?);
                    let state_match = states.is_empty() || states.contains(s(m, "state")?);
                    let query_match = format!(
                        "{} {} {}",
                        s(m, "subject")?,
                        s(m, "sender")?,
                        s(m, "recipient")?
                    )
                    .to_lowercase()
                    .contains(&query);
                    let reason_match = reason.is_empty()
                        || m["verdict"]["matches"].as_array().is_some_and(|matches| {
                            matches.iter().any(|matched| {
                                matched["reason"]
                                    .as_str()
                                    .is_some_and(|value| value.to_lowercase().contains(&reason))
                            })
                        });
                    let node_match = node.is_empty()
                        || m["origin_node"] == node
                        || m["scan_owner"] == node
                        || m["delivery_owner"] == node;
                    let hold_match = hold.is_none_or(|value| m["hold"] == value);
                    let release_match = releasable.is_none_or(|value| m["releasable"] == value);
                    if visible
                        && state_match
                        && query_match
                        && reason_match
                        && node_match
                        && hold_match
                        && release_match
                    {
                        result.push(public(m));
                    }
                    if result.len() == limit || scanned == 2000 {
                        break;
                    }
                }
                if scanned == candidates.len() {
                    cursor = Value::Null;
                }
                let totals = if a.global(&settings).is_ok() {
                    state_counts(t, "message")?
                } else {
                    let mut totals = json!({});
                    for message in list(t, "message/")? {
                        if a.visible(s(&message, "recipient")?) {
                            let state = s(&message, "state")?;
                            totals[state] = json!(totals[state].as_u64().unwrap_or(0) + 1);
                        }
                    }
                    totals
                };
                Ok(json!({
                "instance":self.config.instance,"messages":result,"totals":totals,"limit":limit,"next_cursor":cursor,"scan_limit":2000}
                ))
            }

            "message-detail" => {
                let message = message(t, s(d, "id")?)?;
                a.require("read", Some(s(&message, "recipient")?))?;
                let mut jobs = list(t, "job/")?
                    .into_iter()
                    .filter(|job| job["data"]["message"] == message["id"])
                    .map(|job| job_public(t, &job))
                    .collect::<Result<Vec<_>>>()?;
                jobs.sort_by_key(|job| job["due"].as_i64());
                let job_ids = jobs
                    .iter()
                    .filter_map(|job| job["id"].as_str())
                    .collect::<BTreeSet<_>>();
                let ingress = message["ingress_id"].as_str();
                let id = s(&message, "id")?;
                let mut events = list(t, "audit/")?
                    .into_iter()
                    .filter(|event| {
                        event["scope"].as_str().is_some_and(|scope| {
                            (scope.is_empty() && a.global(&settings).is_ok())
                                || (!scope.is_empty() && a.visible(scope))
                        }) && (event["data"]["id"] == id
                            || event["data"]["message"] == id
                            || ingress.is_some_and(|value| event["data"]["ingress"] == value)
                            || event["data"]["job"]
                                .as_str()
                                .is_some_and(|value| job_ids.contains(value)))
                    })
                    .collect::<Vec<_>>();
                if events.len() > 50 {
                    events.drain(..events.len() - 50);
                }
                Ok(json!({
                    "instance":self.config.instance,
                    "message":public(&message),
                    "verdict":message["verdict"],
                    "evidence":message["engines"],
                    "route":message["route"],
                    "jobs":jobs,
                    "events":events
                }))
            }

            "content" => {
                let m = message(t, s(d, "id")?)?;

                a.require("content", Some(s(&m, "recipient")?))?;

                let parsed = scan::inspect_with_settings(&body(t, &m)?, &settings)?;

                event(
                    t,
                    a,
                    action,
                    rid,
                    s(&m, "recipient")?,
                    json!({
                    "id":m["id"]}
                    ),
                )?;

                Ok(json!({
                "id":m["id"],"text":parsed["text"].as_str().unwrap_or("").chars().take(200000).collect::<String>(),"hash":m["hash"],"rendering":"inert text only"}
                ))
            }

            "release" | "discard" | "hold" | "reevaluate" => {
                let mut m = message(t, s(d, "id")?)?;

                a.require(permission(action).unwrap(), Some(s(&m, "recipient")?))?;

                ensure!(m["revision"] == d["revision"], "Message changed; refresh");

                ensure!(
                    if action == "hold" {
                        m["state"] != "expired"
                    } else {
                        m["state"] == "quarantined"
                    },
                    "Message unavailable"
                );

                match action {
                    "hold" => {
                        ensure!(d["hold"].is_boolean(), "Hold must be true or false");

                        m["hold"] = d["hold"].clone();
                    }

                    "reevaluate" => {
                        let v = active(t)?;

                        m["verdict"] =
                            self.evaluate(t, &body(t, &m)?, &v["rules"], &settings, &m["engines"])?;

                        m["releasable"] = m["verdict"]["releasable"].clone();

                        m["rule_version"] = v["id"].clone();
                    }

                    "release" => self.release(t, a, &mut m, &settings)?,
                    _ => {
                        ensure!(m["hold"] != true, "Retention hold prevents discard");

                        m["state"] = json!("discarded");
                    }
                }

                m["revision"] = json!(n(&m, "revision")? + 1);

                save_message(t, &m)?;

                event(
                    t,
                    a,
                    action,
                    rid,
                    s(&m, "recipient")?,
                    json!({
                    "id":m["id"],"state":m["state"],"revision":m["revision"],"hold":m["hold"],"rule_version":m["rule_version"]}
                    ),
                )?;

                super::cluster::record_message_state(t, s(&m, "id")?)?;

                Ok(public(&m))
            }

            "digests" => {
                let mut rows = list(t, "digest/")?;

                rows.retain(|v| v["recipient"].as_str().is_some_and(|r| a.visible(r)));

                rows.sort_by_key(|v| std::cmp::Reverse(v["created"].as_i64()));

                rows.truncate(100);

                Ok(json!(rows))
            }

            "digest-create" => {
                let recipient = address(s(d, "recipient")?)?;

                a.require("jobs", Some(&recipient))?;

                self.create_digest(t, &recipient, &settings)
            }

            "digest-review" | "digest-action" => {
                key(s(d, "id")?)?;

                let mut snap = must(t, &format!("digest/{}", s(d, "id")?))?;

                let recipient = s(&snap, "recipient")?.to_string();

                a.require("read", Some(&recipient))?;

                ensure!(
                    snap["expires"].as_i64().unwrap_or(0) > now()?,
                    "Digest expired"
                );

                if action == "digest-review" {
                    let mut rows = Vec::new();

                    for i in arr(&snap, "ids")? {
                        rows.push(public(&message(t, i.as_str().unwrap_or(""))?));
                    }

                    snap["messages"] = json!(rows);

                    return Ok(snap);
                }

                let mode = s(d, "mode")?;

                ensure!(
                    ["release", "discard", "discard-all"].contains(&mode) && d["confirm"] == true,
                    "Confirm digest action"
                );

                let ids = if mode == "discard-all" {
                    arr(&snap, "releasable")?
                } else {
                    arr(d, "ids")?
                };

                ensure!(
                    ids.len() <= 200
                        && ids
                            .iter()
                            .all(|i| arr(&snap, "releasable").unwrap().contains(i)),
                    "Only listed releasable spam is eligible"
                );

                let mut result = Vec::new();

                let mut seen = BTreeSet::new();

                for i in ids {
                    let id = i.as_str().ok_or_else(|| crate::error!("Invalid ID"))?;

                    if !seen.insert(id) {
                        continue;
                    }

                    let mut m = message(t, id)?;

                    ensure!(m["recipient"] == recipient, "Recipient mismatch");

                    if m["state"] != "quarantined" {
                        result.push(json!({
                        "id":id,"status":m["state"]}
                        ));

                        continue;
                    }

                    if m["releasable"] != true || m["hold"] == true {
                        result.push(json!({
                        "id":id,"status":"administrator-review"}
                        ));

                        continue;
                    }

                    a.require(
                        if mode == "release" {
                            "release"
                        } else {
                            "discard"
                        },
                        Some(&recipient),
                    )?;

                    let v = active(t)?;

                    let current =
                        self.evaluate(t, &body(t, &m)?, &v["rules"], &settings, &m["engines"])?;

                    if nonspam(&current) {
                        m["verdict"] = current;

                        m["releasable"] = json!(false);

                        m["rule_version"] = v["id"].clone();

                        result.push(json!({
                        "id":id,"status":"administrator-review"}
                        ));
                    } else {
                        if mode == "release" {
                            self.release(t, a, &mut m, &settings)?;
                        } else {
                            m["state"] = json!("discarded");
                        }

                        result.push(json!({
                        "id":id,"status":m["state"]}
                        ));
                    }

                    m["revision"] = json!(n(&m, "revision")? + 1);

                    save_message(t, &m)?;
                    super::cluster::record_message_state(t, id)?;
                }

                event(
                    t,
                    a,
                    action,
                    rid,
                    &recipient,
                    json!({
                    "digest":snap["id"],"mode":mode,"ids":ids}
                    ),
                )?;

                Ok(json!(result))
            }

            "jobs" => {
                let states = list_filters(
                    d,
                    "states",
                    &[
                        "queued",
                        "retrying",
                        "running",
                        "failed",
                        "uncertain",
                        "succeeded",
                        "cancelled",
                    ],
                )?;
                let kinds = list_filters(d, "kinds", &["delivery", "digest", "remediation"])?;
                let query = list_query(d)?;
                let node = d["node"].as_str().unwrap_or("");
                ensure!(
                    node.is_empty() || node.len() <= 100,
                    "Node filter is too long"
                );
                let limit = list_limit(d)?;
                let (before, last) = list_cursor(d, true)?;
                let mut rows = list(t, "job/")?;
                rows.sort_by(|a, b| {
                    (b["due"].as_i64(), b["id"].as_str())
                        .cmp(&(a["due"].as_i64(), a["id"].as_str()))
                });
                let mut result = Vec::new();
                let mut cursor = Value::Null;
                let mut scanned = 0;
                let candidates: Vec<_> = rows
                    .into_iter()
                    .filter(|job| {
                        job["due"].as_i64().unwrap_or(0) < before
                            || (job["due"] == before
                                && job["id"].as_str().unwrap_or("") < last.as_str())
                    })
                    .collect();
                for job in &candidates {
                    scanned += 1;
                    cursor = json!({"at":job["due"],"id":job["id"]});
                    let Some(recipient) = job["data"]["recipient"].as_str() else {
                        continue;
                    };
                    let state_match = states.is_empty() || states.contains(s(job, "state")?);
                    let kind_match = kinds.is_empty() || kinds.contains(s(job, "kind")?);
                    let node_match = node.is_empty()
                        || job["delivery_owner"] == node
                        || job["delivery_partition"] == node;
                    let query_match = format!(
                        "{} {} {} {}",
                        s(job, "id")?,
                        recipient,
                        s(job, "kind")?,
                        job["error"].as_str().unwrap_or("")
                    )
                    .to_lowercase()
                    .contains(&query);
                    if a.visible(recipient)
                        && state_match
                        && kind_match
                        && node_match
                        && query_match
                    {
                        result.push(job_public(t, job)?);
                    }
                    if result.len() == limit || scanned == 2000 {
                        break;
                    }
                }
                if scanned == candidates.len() {
                    cursor = Value::Null;
                }
                let totals = if a.global(&settings).is_ok() {
                    state_counts(t, "job")?
                } else {
                    let mut totals = json!({});
                    for job in list(t, "job/")? {
                        if job["data"]["recipient"]
                            .as_str()
                            .is_some_and(|recipient| a.visible(recipient))
                        {
                            let state = s(&job, "state")?;
                            totals[state] = json!(totals[state].as_u64().unwrap_or(0) + 1);
                        }
                    }
                    totals
                };
                Ok(json!({
                    "instance":self.config.instance,
                    "jobs":result,
                    "totals":totals,
                    "limit":limit,
                    "next_cursor":cursor,
                    "scan_limit":2000
                }))
            }

            "job-retry" | "job-cancel" => {
                key(s(d, "id")?)?;

                let k = format!("job/{}", s(d, "id")?);

                let mut j = must(t, &k)?;

                a.require("jobs", Some(s(&j["data"], "recipient")?))?;

                ensure!(
                    ["failed", "uncertain", "queued", "retrying"].contains(&s(&j, "state")?),
                    "Job cannot change in this state"
                );

                let uncertain = j["state"] == "uncertain";

                ensure!(
                    !uncertain || d["acknowledge_duplicate_risk"] == true,
                    "Acknowledge uncertain delivery/removal risk"
                );

                if action == "job-cancel"
                    && j["kind"] == "delivery"
                    && j["data"]["released"] == true
                    && !uncertain
                {
                    let mut m = message(t, s(&j["data"], "message")?)?;

                    if m["state"] == "release-queued" {
                        m["state"] = json!("quarantined");

                        m["revision"] = json!(n(&m, "revision")? + 1);

                        save_message(t, &m)?;
                    }
                }

                j["state"] = json!(if action == "job-retry" {
                    "queued"
                } else {
                    "cancelled"
                });

                j["due"] = json!(now()?);

                j["attempts"] = json!(0);

                put(t, &k, &j)?;

                event(
                    t,
                    a,
                    action,
                    rid,
                    s(&j["data"], "recipient")?,
                    json!({
                    "job":j["id"],"state":j["state"]}
                    ),
                )?;

                if j["kind"] == "delivery" {
                    super::cluster::record_message_state(t, s(&j["data"], "message")?)?;
                }

                Ok(json!({
                "state":j["state"]}
                ))
            }

            "audit" => {
                let after = d["after"].as_u64().unwrap_or(0);

                let rows: Vec<_> = list(t, "audit/")?
                    .into_iter()
                    .filter(|e| e["seq"].as_u64().unwrap_or(0) > after)
                    .take(1000)
                    .collect();

                let next = rows
                    .last()
                    .map(|v| v["seq"].clone())
                    .unwrap_or(json!(after));

                let events: Vec<_> = rows
                    .into_iter()
                    .filter(|e| {
                        e["scope"].as_str().is_some_and(|s| {
                            if s.is_empty() {
                                a.domains.contains(&"*".into()) && a.mailboxes.contains(&"*".into())
                            } else {
                                a.visible(s)
                            }
                        })
                    })
                    .collect();

                Ok(json!({
                "events":events,"next_after":next,"filtered":true}
                ))
            }

            "identities" => {
                a.global(&settings)?;

                let mut rows = Vec::new();

                for (k, mut v) in keyed(t, "identity/")? {
                    v.as_object_mut().unwrap().remove("hash");

                    v["username"] = json!(k.trim_start_matches("identity/"));

                    rows.push(v);
                }

                Ok(json!(rows))
            }

            "identity-set" => {
                a.global(&settings)?;

                let name = s(d, "username")?;

                key(name)?;

                let k = format!("identity/{name}");

                let old = get(t, &k)?.unwrap_or(Value::Null);

                ensure!(
                    d["expected_revision"] == old["revision"],
                    "Identity changed"
                );

                let mut u = d.clone();

                u["id"] = json!(name);

                let actor: Actor = pratique::json_value::from_value(u.clone())?;

                ensure!(
                    actor
                        .permissions
                        .iter()
                        .all(|p| PERMISSIONS.contains(&p.as_str())),
                    "Unknown permission"
                );

                for d in &actor.domains {
                    ensure!(d == "*" || crate::config::domain(d), "Invalid domain scope");
                }

                for m in &actor.mailboxes {
                    if m != "*" {
                        address(m)?;
                    }
                }

                if let Some(m) = &actor.mailbox {
                    address(m)?;

                    ensure!(
                        settings["mailboxes"].get(m).is_some(),
                        "Mailbox must be administered"
                    );
                }

                ensure!(d["enabled"].is_boolean(), "Invalid enabled value");

                let new_hash = if let Some(p) = d["password"].as_str().filter(|s| !s.is_empty()) {
                    crate::auth::hash(p)?
                } else {
                    s(&old, "hash")?.into()
                };

                ensure!(
                    name != a.id
                        || (d["enabled"] == true
                            && actor.mailbox.is_none()
                            && actor.permissions.contains(&"configure".into())
                            && actor.domains.contains(&"*".into())
                            && actor.mailboxes.contains(&"*".into())),
                    "Do not remove your own administration access"
                );

                let mut saved = pratique::json_value::to_value(actor)?;

                saved["enabled"] = d["enabled"].clone();

                saved["revision"] = json!(old["revision"].as_u64().unwrap_or(0) + 1);

                let mut before = old.clone();

                if let Some(o) = before.as_object_mut() {
                    o.remove("hash");
                }

                event(
                    t,
                    a,
                    action,
                    rid,
                    "",
                    json!({
                    "identity":name,"before":before,"after":saved,"password_changed":d["password"].as_str().is_some_and(|s|!s.is_empty())}
                    ),
                )?;

                saved["hash"] = json!(new_hash);

                put(t, &k, &saved)?;

                Ok(json!({
                "revision":saved["revision"]}
                ))
            }

            "learning" | "learn" | "learning-reset" => {
                super::learning::command(t, a, action, d, rid)
            }

            _ if action.starts_with("remediation-") => {
                super::connectors::command(self, t, a, action, d, rid)
            }

            _ => bail!("Unsupported action"),
        }
    }

    pub fn validate_settings(&self, v: &Value) -> Result<()> {
        let destinations = self.delivery_routes(v)?;
        ensure!(v["enabled"].is_boolean(), "Invalid enabled flag");

        let domains = arr(v, "domains")?;

        ensure!(
            (1..=100).contains(&domains.len())
                && domains
                    .iter()
                    .all(|d| d.as_str().is_some_and(crate::config::domain)),
            "Add 1–100 accepted domains"
        );

        let routes = v["routes"]
            .as_object()
            .ok_or_else(|| crate::error!("Invalid routes"))?;

        ensure!(
            routes.len() == domains.len()
                && domains.iter().all(|d| routes
                    .get(d.as_str().unwrap())
                    .and_then(Value::as_str)
                    .is_some_and(|r| destinations.contains_key(r))),
            "Choose a saved delivery destination for every domain in Setup → Mail flow"
        );

        let boxes = v["mailboxes"]
            .as_object()
            .ok_or_else(|| crate::error!("Invalid mailboxes"))?;

        ensure!(
            (1..=10000).contains(&boxes.len()),
            "Add 1–10,000 recipients"
        );

        for (a, p) in boxes {
            ensure!(
                address(a)? == *a && domains.contains(&json!(a.rsplit('@').next().unwrap_or(""))),
                "Recipient outside accepted domains"
            );

            let obj = p
                .as_object()
                .ok_or_else(|| crate::error!("Invalid mailbox preference"))?;

            ensure!(
                obj.keys()
                    .all(|k| ["enabled", "digest_hours"].contains(&k.as_str()))
                    && p.get("enabled").is_none_or(Value::is_boolean)
                    && p.get("digest_hours")
                        .is_none_or(|v| v.as_u64().is_some_and(|x| x <= 168)),
                "Invalid mailbox preferences"
            );
        }

        ensure!(
            (1..=365).contains(&n(v, "retention_days")?) && n(v, "digest_hours")? <= 168,
            "Invalid retention or digest interval"
        );

        ensure!(
            (100..=1000000).contains(&n(v, "max_messages")?)
                && (MAX_MESSAGE as u64..=1024u64.pow(3)).contains(&n(v, "max_bytes")?)
                && (100..=1000000).contains(&n(v, "max_jobs")?)
                && (64 * 1024u64.pow(2)..=1024u64.pow(4)).contains(&n(v, "min_free_bytes")?),
            "Invalid capacity"
        );
        ensure!(
            (1024..=MAX_MESSAGE as u64).contains(&n(v, "scan_input_bytes")?)
                && (1024u64.pow(2)..=256 * 1024u64.pow(2)).contains(&n(v, "scan_decoded_bytes")?)
                && (1..=1000).contains(&n(v, "scan_parts")?)
                && (1..=16).contains(&n(v, "scan_concurrency")?)
                && (1..=16).contains(&n(v, "delivery_concurrency")?)
                && v["mixed_script_check"].is_boolean(),
            "Invalid worker limits or mixed-script policy"
        );

        if !s(v, "digest_sender")?.is_empty() {
            address(s(v, "digest_sender")?)?;
        }

        ensure!(
            arr(v, "protected_people")?.len() <= 500 && arr(v, "protected_domains")?.len() <= 500,
            "Protected identity capacity"
        );

        for p in arr(v, "protected_people")? {
            address(s(p, "address")?)?;

            ensure!(
                !s(p, "name")?.is_empty() && s(p, "name")?.len() <= 128,
                "Invalid protected name"
            );
        }

        for d in arr(v, "protected_domains")? {
            ensure!(
                d.as_str().is_some_and(crate::config::domain),
                "Invalid protected domain"
            );
        }

        for (name, enabled) in v["connectors"]
            .as_object()
            .ok_or_else(|| crate::error!("Invalid connectors"))?
        {
            ensure!(
                self.config.connectors.contains_key(name) && enabled.is_boolean(),
                "Choose a provisioned connector"
            );
        }

        Ok(())
    }

    pub fn connection_fingerprint(&self, v: &Value) -> Result<String> {
        Ok(hash(&pratique::json_value::to_vec(&json!({
        "domains":v["domains"],"routes":v["routes"],"mailboxes":v["mailboxes"],"connectors":v["connectors"],"route_config":self.delivery_routes(v)?,"connector_config":self.config.connectors,"engine":scan::ENGINE}
        ))?))
    }

    pub fn connection_tests(&self, v: &Value) -> Result<Value> {
        let mut results = Vec::new();
        let destinations = self.delivery_routes(v)?;

        let names: BTreeSet<_> = v["routes"]
            .as_object()
            .map(|o| o.values().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        for name in names {
            let ok = super::transport::probe(
                destinations
                    .get(name)
                    .ok_or_else(|| crate::error!("Unknown route"))?,
            )
            .is_ok();

            results.push(json!({
            "name":name,"ok":ok,"detail":if ok{
            "TLS greeting and authentication succeeded; no mail sent"}
            else{
            "SMTP connection failed; check host, certificate and credentials"}
            }
            ));
        }

        let sample=b"From: test@example.invalid\r\nSubject: Native scan self-check\r\n\r\nHarmless content.\r\n";

        let ok = scan::evaluate(sample, &rules(), v, &json!({})).is_ok();

        results.push(json!({
"name":"native-inspection","ok":ok,"detail":"Embedded detector self-check; no external scanner"}
));

        for (name, enabled) in v["connectors"]
            .as_object()
            .ok_or_else(|| crate::error!("Invalid connectors"))?
        {
            if enabled.as_bool() == Some(true) {
                let ok = super::connectors::probe(self, name).is_ok();

                results.push(json!({
"name":name,"ok":ok,"detail":"Read-only mailbox connection test; no content removed"}
));
            }
        }

        Ok(json!({
        "ok":results.iter().all(|v|v["ok"]==true),"results":results,"at":now()?,"fingerprint":self.connection_fingerprint(v)?}
        ))
    }

    pub fn capacity(
        &self,
        t: &Table,
        v: &Value,
        bytes: usize,
        count: usize,
        jobs: usize,
    ) -> Result<()> {
        capacity_check(t, v, bytes, count, jobs)
    }

    pub fn release(&self, t: &mut Table, a: &Actor, m: &mut Value, settings: &Value) -> Result<()> {
        let v = active(t)?;

        if m.get("ingress_id").is_some() {
            ensure!(
                m["engines"]["engine"] == scan::ENGINE
                    && m["engines"]["api_version"] == scan::ANALYSIS_API_VERSION
                    && m["engines"]["profile_version"] == scan::ANALYSIS_PROFILE_VERSION
                    && m["engines"]["coverage_version"] == scan::COVERAGE_VERSION,
                "Complete the scanner/control upgrade before re-evaluating this message"
            );
        }

        let verdict = self.evaluate(t, &body(t, m)?, &v["rules"], settings, &m["engines"])?;

        ensure!(
            !nonspam(&verdict),
            "Current mandatory/security checks prevent release; administrator review required"
        );

        if a.mailbox.is_some() {
            ensure!(m["releasable"] == true, "Administrator-only item");
        }

        self.capacity(t, settings, 0, 0, 1)?;

        let jid = format!("release-{}-{}", s(m, "id")?, n(m, "revision")?);

        job(
            t,
            "delivery",
            json!({
            "recipient":m["recipient"],"message":m["id"],"released":true}
            ),
            &jid,
        )?;

        m["state"] = json!("release-queued");

        m["release_job"] = json!(jid);

        Ok(())
    }

    pub fn create_digest(&self, t: &mut Table, recipient: &str, v: &Value) -> Result<Value> {
        ensure!(
            v["mailboxes"].get(recipient).is_some() && !s(v, "digest_sender")?.is_empty(),
            "Configure digest sender and mailbox first"
        );

        let mut rows: Vec<_> = list(t, "message/")?
            .into_iter()
            .filter(|m| m["recipient"] == recipient && m["state"] == "quarantined")
            .collect();

        rows.sort_by(|a, b| {
            (b["arrived"].as_i64(), b["id"].as_str())
                .cmp(&(a["arrived"].as_i64(), a["id"].as_str()))
        });

        if rows.is_empty() {
            return Ok(json!({
            "empty":true}
            ));
        }

        let truncated = rows.len() > 200;

        rows.truncate(200);

        self.capacity(t, v, 0, 0, 1)?;

        let id = id();

        let snap = json!({
        "id":id,"recipient":recipient,"created":now()?,"expires":now()?+7*86400,"truncated":truncated,"ids":rows.iter().map(|m|m["id"].clone()).collect::<Vec<_>>(),"releasable":rows.iter().filter(|m|m["releasable"]==true&&m["hold"]!=true).map(|m|m["id"].clone()).collect::<Vec<_>>()}
        );

        put(t, &format!("digest/{id}"), &snap)?;

        job(
            t,
            "digest",
            json!({
            "recipient":recipient,"digest":id}
            ),
            &format!("digest-{id}"),
        )?;

        audit(
            t,
            "scheduler",
            "digest-created",
            recipient,
            json!({
            "digest":id,"count":rows.len()}
            ),
        )?;

        Ok(snap)
    }

    pub fn evaluate(
        &self,
        t: &Table,
        raw: &[u8],
        rules: &Value,
        settings: &Value,
        evidence: &Value,
    ) -> Result<Value> {
        let _permit = acquire_scan(
            &self.scan_active,
            usize::try_from(n(settings, "scan_concurrency")?)?,
        )?;
        let mut evidence = if evidence.is_object() {
            evidence.clone()
        } else {
            json!({})
        };

        evidence["learned_spam_score"] = json!(super::learning::score(t, raw, settings)?);

        scan::evaluate(raw, rules, settings, &evidence)
    }

    pub fn verify_audit(&self) -> Result<Value> {
        self.db.write(|t| {
            let mut previous = "0".repeat(64);

            let mut seq = 0;

            for mut e in list(t, "audit/")? {
                seq += 1;

                ensure!(
                    e["seq"] == seq && e["previous"] == previous,
                    "Audit sequence or chain mismatch"
                );

                let expected = s(&e, "hash")?.to_string();

                e.as_object_mut().unwrap().remove("hash");

                ensure!(
                    hash(&pratique::json_value::to_vec(&e)?) == expected,
                    "Audit event hash mismatch"
                );

                previous = expected;
            }

            ensure!(
                get(t, "audit_head")?.unwrap_or(json!("0".repeat(64))) == previous,
                "Audit head mismatch"
            );

            Ok(json!({
            "events":seq,"head":previous,"verified":true}
            ))
        })
    }
}

pub fn nonspam(v: &Value) -> bool {
    v["matches"].as_array().is_some_and(|a| {
        a.iter()
            .any(|m| m["action"] == "quarantine" && m["type"] != "spam")
    })
}

#[cfg(test)]
mod scanner_budget_tests {
    use super::*;

    #[test]
    fn scan_permits_bound_concurrency_and_release_on_drop() {
        let active = AtomicUsize::new(0);
        let first = acquire_scan(&active, 2).unwrap();
        let _second = acquire_scan(&active, 2).unwrap();
        assert_eq!(active.load(Ordering::Relaxed), 2);
        assert!(acquire_scan(&active, 2).is_err());
        assert_eq!(active.load(Ordering::Relaxed), 2);
        drop(first);
        assert_eq!(active.load(Ordering::Relaxed), 1);
        let _replacement = acquire_scan(&active, 2).unwrap();
        assert_eq!(active.load(Ordering::Relaxed), 2);
    }
}
