use super::{db::*, model::*, service::Service, transport};
use crate::encoding::STANDARD;
use crate::error::{Result, ensure};
use pratique::json_value::{Value, json};
impl Service {
    pub fn digest_body(&self, t: &Table, snap: &Value, settings: &Value) -> Result<Vec<u8>> {
        let sender = s(settings, "digest_sender")?;
        address(sender)?;
        let recipient = s(snap, "recipient")?;
        address(recipient)?;
        let mut text = format!(
            "Your quarantine summary\n\nReview safely: {}/?digest={}\nSign in as the mailbox holder. Opening this link makes no changes.\n\n",
            self.config.origin,
            s(snap, "id")?
        );
        for id in arr(snap, "ids")? {
            let m = message(t, id.as_str().unwrap_or(""))?;
            let eligible = arr(snap, "releasable")?.contains(id);
            let summary = format!("{} | {}", s(&m, "sender")?, s(&m, "subject")?)
                .replace(|c: char| c.is_control(), " ");
            text.push_str(&format!(
                "{}\n{}\nRetention ends (UTC): {}\n\n",
                if eligible {
                    "Spam — release available"
                } else {
                    "Blocked — administrator review required"
                },
                summary,
                crate::datetime::DateTime::from_timestamp(m["expires"].as_i64().unwrap_or(0), 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default()
            ));
        }
        if snap["truncated"] == true {
            text.push_str("This summary shows the newest 200 items. Ask your administrator to review the remaining backlog.\n\n");
        }
        text.push_str("After sign-in: Release selected, Discard selected, Discard all listed spam.\nBulk discard affects only eligible spam listed in this summary.\n");
        let encoded = STANDARD.encode(text);
        let lines = encoded
            .as_bytes()
            .chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        Ok(format!("From: {sender}\r\nTo: {recipient}\r\nSubject: Workglen quarantine summary\r\nMessage-ID: <{}@{}>\r\nDate: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{lines}\r\n",s(snap,"id")?,sender.rsplit('@').next().unwrap_or(""),crate::datetime::Utc::now().to_rfc2822()).into_bytes())
    }
    pub fn maintenance(&self) -> Result<()> {
        self.db.write(|t| {
            let current_time = now()?;
            let settings = must(t, "settings")?;
            for (recipient, prefs) in settings["mailboxes"]
                .as_object()
                .ok_or_else(|| crate::error!("Invalid mailboxes"))?
            {
                let hours = prefs["digest_hours"]
                    .as_u64()
                    .unwrap_or(n(&settings, "digest_hours")?);
                if prefs["enabled"] == false
                    || hours == 0
                    || s(&settings, "digest_sender")?.is_empty()
                {
                    continue;
                }
                let k = format!("digest_due/{recipient}");
                if get(t, &k)?.and_then(|v| v.as_i64()).unwrap_or(0) <= current_time {
                    self.create_digest(t, recipient, &settings)?;
                    put(t, &k, &json!(now()? + hours as i64 * 3600))?;
                }
            }
            let mut keep = std::collections::BTreeSet::new();
            for pending in list(t, "ingress/")? {
                keep.insert(format!("blob/{}", s(&pending, "hash")?));
            }
            for mut m in list(t, "message/")? {
                if ["quarantined", "discarded", "delivered"].contains(&s(&m, "state")?)
                    && m["hold"] != true
                    && m["expires"].as_i64().unwrap_or(i64::MAX) <= current_time
                {
                    m["state"] = json!("expired");
                    m["revision"] = json!(n(&m, "revision")? + 1);
                    save_message(t, &m)?;
                    audit(
                        t,
                        "retention",
                        "expired",
                        s(&m, "recipient")?,
                        json!({"id":m["id"]}),
                    )?;
                    super::cluster::record_message_state(t, s(&m, "id")?)?;
                }
                if m["state"] != "expired" {
                    keep.insert(format!("blob/{}", s(&m, "hash")?));
                }
            }
            use redb::ReadableTable;
            let keys: Vec<String> = t
                .range("blob/".."blob0")?
                .map(|r| r.map(|(k, _)| k.value().to_string()))
                .collect::<std::result::Result<_, _>>()?;
            for k in keys {
                if !keep.contains(&k) {
                    remove(t, &k)?;
                }
            }
            for (k, v) in keyed(t, "nonce/")? {
                if v.as_i64().unwrap_or(0) < now()? {
                    remove(t, &k)?;
                }
            }
            Ok(())
        })
    }
    pub(super) fn claim_delivery(&self) -> Result<Option<Value>> {
        self.db.write(|t| {
            if !super::cluster::delivery_eligible(t)? {
                return Ok(None);
            }
            let Some(mut job) = next_delivery_job(t, now()?)? else {
                return Ok(None);
            };
            job["state"] = json!("running");
            job["attempts"] = json!(n(&job, "attempts")? + 1);
            put(t, &format!("job/{}", s(&job, "id")?), &job)?;
            audit(
                t,
                "worker",
                "job-start",
                s(&job["data"], "recipient")?,
                json!({"job":job["id"],"attempt":job["attempts"]}),
            )?;
            let state_sequence = if job["kind"] == "delivery" {
                super::cluster::record_message_state(t, s(&job["data"], "message")?)?
            } else {
                0
            };
            job["replication_state_sequence"] = json!(state_sequence);
            Ok(Some(job))
        })
    }
    pub fn worker_once(&self) -> Result<bool> {
        let Some(mut j) = self.claim_delivery()? else {
            return Ok(false);
        };
        let _permit = self.begin_delivery();
        let result = crate::resilience::boundary("security job", || -> Result<()> {
            super::cluster_transport::wait_for_state(
                self,
                j["replication_state_sequence"].as_u64().unwrap_or(0),
            )?;
            if j["kind"] == "remediation" {
                return super::connectors::execute(self, &j["data"]);
            }
            let (raw, sender, route) = self.db.write(|t| {
                let settings = must(t, "settings")?;
                if j["kind"] == "delivery" {
                    let m = message(t, s(&j["data"], "message")?)?;
                    ensure!(
                        super::cluster::delivery_owned(t, &m)?,
                        "Delivery ownership changed"
                    );
                    ensure!(
                        m["state"] == "queued" || m["state"] == "release-queued",
                        "Message no longer queued"
                    );
                    let raw = body(t, &m)?;
                    if j["data"]["released"] == true {
                        if m.get("ingress_id").is_some() {
                            ensure!(
                                m["engines"]["engine"] == super::scan::ENGINE
                                    && m["engines"]["api_version"]
                                        == super::scan::ANALYSIS_API_VERSION
                                    && m["engines"]["profile_version"]
                                        == super::scan::ANALYSIS_PROFILE_VERSION
                                    && m["engines"]["coverage_version"]
                                        == super::scan::COVERAGE_VERSION,
                                "Scanner/control versions differ; review before release"
                            );
                        }
                        let v = super::service::active(t)?;
                        ensure!(
                            !super::service::nonspam(&self.evaluate(
                                t,
                                &raw,
                                &v["rules"],
                                &settings,
                                &m["engines"]
                            )?),
                            "Current checks prevent queued release"
                        );
                    }
                    Ok((
                        transport::delivery_copy(&raw, &m, &self.config.hostname)?,
                        s(&m, "envelope_from")?.to_string(),
                        s(&m, "route")?.to_string(),
                    ))
                } else {
                    ensure!(j["kind"] == "digest", "Unknown job kind");
                    let snap = must(t, &format!("digest/{}", s(&j["data"], "digest")?))?;
                    ensure!(
                        snap["expires"].as_i64().unwrap_or(0) > now()?,
                        "Digest expired before delivery"
                    );
                    let r = s(&j["data"], "recipient")?;
                    Ok((
                        self.digest_body(t, &snap, &settings)?,
                        s(&settings, "digest_sender")?.to_string(),
                        settings["routes"][r.rsplit('@').next().unwrap_or("")]
                            .as_str()
                            .ok_or_else(|| crate::error!("Route missing"))?
                            .to_string(),
                    ))
                }
            })?;
            let settings = self
                .db
                .get("settings")?
                .ok_or_else(|| crate::error!("Settings missing"))?;
            transport::send(
                self.delivery_routes(&settings)?
                    .get(&route)
                    .ok_or_else(|| crate::error!("Route removed"))?,
                &sender,
                s(&j["data"], "recipient")?,
                &raw,
            )
        });
        let mut state = "succeeded";
        let mut error = "";
        let mut delay = (30i64 * 2i64.pow(n(&j, "attempts")?.min(7) as u32)).min(3600);
        if let Err(e) = result {
            if e.downcast_ref::<transport::Uncertain>().is_some()
                || e.downcast_ref::<crate::resilience::IsolatedPanic>()
                    .is_some()
            {
                state = "uncertain";
                error = "Remote acknowledgment uncertain; review before retry";
            } else {
                state = if n(&j, "attempts")? >= 5 {
                    "failed"
                } else {
                    "retrying"
                };
                error = "Operation failed; verify service health, current policy and configuration";
                if let Some(r) = e.downcast_ref::<transport::RetryAfter>() {
                    delay = r.0.clamp(30, 86400);
                }
            }
        }
        self.db.write(|t| {
            j["state"] = json!(state);
            j["error"] = json!(error);
            j["due"] = json!(now()? + delay);
            put(t, &format!("job/{}", s(&j, "id")?), &j)?;
            if state == "succeeded" && j["kind"] == "delivery" {
                let mut m = message(t, s(&j["data"], "message")?)?;
                m["state"] = json!("delivered");
                m["revision"] = json!(n(&m, "revision")? + 1);
                save_message(t, &m)?;
            }
            if j["kind"] == "delivery" {
                super::cluster::record_message_state(t, s(&j["data"], "message")?)?;
            }
            if j["kind"] == "remediation" {
                let k = format!("plan/{}", s(&j["data"], "plan")?);
                let mut plan = must(t, &k)?;
                let i = n(&j["data"], "index")? as usize;
                if state != "succeeded" {
                    plan["items"][i]["status"] = json!(state);
                    plan["items"][i]["error"] = json!(error);
                }
                let matched: Vec<_> = arr(&plan, "items")?
                    .iter()
                    .filter(|x| x["matched"] == true)
                    .collect();
                let total = matched.len();
                let removed = matched.iter().filter(|x| x["status"] == "removed").count();
                let review = matched
                    .iter()
                    .filter(|x| {
                        ["failed", "uncertain", "cancelled"]
                            .contains(&x["status"].as_str().unwrap_or(""))
                    })
                    .count();
                plan["progress"] = json!({"total":total,"removed":removed,"needs_review":review});
                plan["state"] = json!(if removed == total {
                    "completed"
                } else if review > 0 {
                    "needs-review"
                } else {
                    "in-progress"
                });
                put(t, &k, &plan)?;
            }
            audit(
                t,
                "worker",
                "job-result",
                s(&j["data"], "recipient")?,
                json!({"job":j["id"],"state":state,"error":error}),
            )?;
            Ok(())
        })?;
        self.record_delivery_result(state == "succeeded");
        Ok(true)
    }
    pub fn work(self: std::sync::Arc<Self>) -> Result<()> {
        let destinations = self.clone();
        std::thread::spawn(move || {
            loop {
                if crate::resilience::boundary("destination worker", || {
                    destinations.destination_once()
                })
                .is_err()
                {
                    eprintln!("delivery destination check requires review");
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        });
        let directory = self.clone();
        std::thread::spawn(move || {
            loop {
                if crate::resilience::boundary("directory worker", || directory.directory_once())
                    .is_err()
                {
                    eprintln!("recipient discovery requires review");
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        });
        let delivery_workers = usize::try_from(n(&self.settings()?, "delivery_concurrency")?)?;
        for index in 0..delivery_workers {
            let delivery = self.clone();
            std::thread::Builder::new()
                .name(format!("security-delivery-{}", index + 1))
                .spawn(move || {
                    loop {
                        match crate::resilience::boundary("security worker", || {
                            delivery.worker_once()
                        }) {
                            Ok(true) => {}
                            Ok(false) => std::thread::sleep(std::time::Duration::from_millis(500)),
                            Err(_) => {
                                eprintln!("security worker requires review");
                                std::thread::sleep(std::time::Duration::from_secs(5));
                            }
                        }
                    }
                })?;
        }
        self.set_delivery_workers(delivery_workers);
        let mut next = std::time::Instant::now();
        loop {
            if std::time::Instant::now() >= next {
                if crate::resilience::boundary("security maintenance", || self.maintenance())
                    .is_err()
                {
                    eprintln!("security maintenance requires review");
                }
                next = std::time::Instant::now() + std::time::Duration::from_secs(60);
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}
