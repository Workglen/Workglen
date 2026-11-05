//! Central administration of independently hosted Mail Security instances.
//! Endpoints and keys are installation-owned; a browser cannot choose an arbitrary URL.
use crate::error::{Result, ensure};
use crate::{app::App, rbac::Access};
use pratique::crypto::{hmac::Hmac, sha2::Sha256};
use pratique::json_value::{Value, json};
use std::time::Duration;
#[derive(Clone, Debug)]
pub struct Remote {
    pub id: String,
    pub label: String,
    pub origin: String,
    pub key_file: String,
    pub ca_file: Option<String>,
}
pratique::data_decode!(Remote, deny_unknown=true, { id, label, origin, key_file, ca_file });

impl Remote {
    pub fn validate(&self) -> Result<()> {
        crate::accounting::model::key(&self.id)?;
        let u = crate::url::Url::parse(&self.origin)?;
        ensure!(
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.path() == "/"
                && u.query().is_none()
                && u.fragment().is_none()
                && u.origin().ascii_serialization() == self.origin,
            "Remote security origin must be canonical HTTPS"
        );
        ensure!(self.label.len() <= 100, "Remote label too long");
        ensure!(
            crate::config::secret(&self.key_file)?.len() >= 32,
            "Remote key requires at least 32 characters"
        );
        Ok(())
    }
}
pub struct Request {
    pub instance: String,
    pub command: Value,
}
pratique::data_decode!(Request, deny_unknown=true, { instance, command });

pub fn permission(action: &str) -> Option<&'static str> {
    Some(match action {
        "status" | "rules" | "ingress" | "messages" | "message-detail" | "digests"
        | "digest-review" | "jobs" => "security.read",
        "setup"
        | "configure"
        | "connection-test"
        | "identities"
        | "identity-set"
        | "recipient-discover"
        | "recipient-discovery"
        | "recipient-apply"
        | "delivery-discover"
        | "delivery-test"
        | "delivery-status"
        | "delivery-save" => "security.configure",
        "draft" => "security.rules.write",
        "learn" | "learning-reset" => "security.learn",
        "learning" => "security.read",
        "test" | "reevaluate" => "security.rules.test",
        "activate" | "rollback" => "security.rules.activate",
        "content" => "security.content",
        "release" => "security.release",
        "discard" => "security.discard",
        "digest-action" => "security.read", // Receiver authorizes the specific release/discard operation.
        "hold" => "security.retention",
        "digest-create" | "job-retry" | "job-cancel" => "security.jobs",
        "audit" => "security.audit",
        "cluster-drain" | "cluster-handoff" | "cluster-rejoin" | "cluster-resync" => {
            "security.cluster.operate"
        }
        "cluster-takeover" => "security.cluster.takeover",
        "remediation-preview" | "remediation-review" => "security.remediation.preview",
        "remediation-start" => "security.remediation.execute",
        _ => return None,
    })
}
fn instance(access: &Access, id: &str) -> bool {
    access
        .security_instances
        .iter()
        .any(|x| x == "*" || x == id)
}
pub fn list(app: &App, access: &Access) -> Result<Value> {
    access.require("security.read")?;
    Ok(json!(
        app.config
            .security_remotes
            .iter()
            .filter(|r| instance(access, &r.id))
            .map(|r| json!({"id":r.id,"label":r.label}))
            .collect::<Vec<_>>()
    ))
}
pub fn execute(app: &App, access: &Access, r: Request) -> Result<Value> {
    let action = r.command["action"].as_str().ok_or(crate::rbac::Denied)?;
    access.require(permission(action).ok_or(crate::rbac::Denied)?)?;
    ensure!(
        instance(access, &r.instance),
        "Security instance scope denied"
    );
    let remote = app
        .config
        .security_remotes
        .iter()
        .find(|x| x.id == r.instance)
        .ok_or_else(|| crate::error!("Security instance is not registered"))?;
    let permissions = access
        .permissions()
        .into_iter()
        .filter_map(|p| p.strip_prefix("security."))
        .collect::<Vec<_>>();
    let envelope = json!({"version":1,"workspace":app.config.replication.cluster_id,"audience":remote.id,"at":crate::datetime::Utc::now().timestamp(),"nonce":crate::store::random_id(),
        "actor":{"id":format!("central:{}",access.username),"permissions":permissions,"domains":access.security_domains,"mailboxes":access.security_mailboxes},"command":r.command});
    let bytes = pratique::json_value::to_vec(&envelope)?;
    let key = crate::config::secret(&remote.key_file)?;
    let signature = Hmac::<Sha256>::mac(key.as_bytes(), &bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let client = if let Some(path) = &remote.ca_file {
        pratique::Client::with_tls_config(pratique::tls::ClientConfig::new(
            pratique::sys::trust_store_from_pem_file(path)?,
        ))
    } else {
        pratique::Client::new()?
    }
    .follow_redirects(false)
    .max_redirects(0)
    .connect_timeout(Duration::from_secs(5))
    .timeout(Duration::from_secs(30))
    .total_timeout(Duration::from_secs(60))
    .max_body_bytes(4 * 1024 * 1024)
    .max_decoded_bytes(4 * 1024 * 1024);
    let response=client.request("POST",&format!("{}/control",remote.origin))
        .header("Content-Type","application/json").header("X-Workglen-Signature",&signature).body(bytes).send()
        .map_err(|_|crate::error!("Security instance unavailable or response uncertain. Refresh the remote record before repeating a change."))?;
    let value: Value = pratique::json_value::from_slice(&response.body)?;
    ensure!(
        response.status == 200,
        "{}",
        value["error"].as_str().unwrap_or("Remote operation failed")
    );
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_and_removal_permissions_are_separate() {
        assert_eq!(permission("new-future-command"), None);
        assert_eq!(
            permission("remediation-preview"),
            Some("security.remediation.preview")
        );
        assert_eq!(
            permission("remediation-start"),
            Some("security.remediation.execute")
        );
        assert_ne!(permission("draft"), permission("activate"));
    }
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    pratique::data_encode!(Remote {
        id,
        label,
        origin,
        key_file,
        ca_file
    });
    #[test]
    fn record_contract_remote() {
        crate::data_contracts::check::<Remote>(
            "src_security_remote_Remote",
            &[
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",null]"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"unexpected_field":1}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null}"###,
                r###"{"id":false,"label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":false,"origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"label":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":false,"key_file":"sample-\u00e9\ud83d\ude00","ca_file":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"origin":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","ca_file":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":false,"ca_file":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"key_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":"wrong"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":null,"ca_file":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","label":"sample-\u00e9\ud83d\ude00","origin":"sample-\u00e9\ud83d\ude00","key_file":"sample-\u00e9\ud83d\ude00","ca_file":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    pratique::data_encode!(Request { instance, command });
    #[test]
    fn record_contract_request() {
        crate::data_contracts::check::<Request>(
            "src_security_remote_Request",
            &[
                r###"{"instance":"sample-\u00e9\ud83d\ude00","command":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",{"z":[1,true,null],"a":"sample"}]"###,
                r###"{"instance":"sample-\u00e9\ud83d\ude00","command":{"z":[1,true,null],"a":"sample"},"unexpected_field":1}"###,
                r###"{"command":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"instance":false,"command":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"instance":"sample-\u00e9\ud83d\ude00","command":{"z":[1,true,null],"a":"sample"},"instance":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"instance":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"instance":"sample-\u00e9\ud83d\ude00","command":"wrong"}"###,
                r###"{"instance":"sample-\u00e9\ud83d\ude00","command":{"z":[1,true,null],"a":"sample"},"command":{"z":[1,true,null],"a":"sample"}}"###,
            ],
        );
    }
}
