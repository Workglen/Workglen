//! Optional, read-only Microsoft 365 discovery. Network I/O never holds the store lock.
//! A complete bounded snapshot is reviewed before additive recipient changes.
use super::{
    db::*,
    model::*,
    service::{Service, event},
};
use crate::error::{Result, ensure};
use pratique::json_value::{Value, json};
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};

const CURRENT: &str = "directory/current";
const GRAPH: &str = "https://graph.microsoft.com";
const TTL: i64 = 900;

#[derive(Clone, Debug)]
pub struct Microsoft365 {
    pub tenant: String,
    pub client_id: String,
    pub secret_file: String,
}
pratique::data_decode!(Microsoft365, deny_unknown=true, { tenant, client_id, secret_file });

fn guid(v: &str) -> bool {
    v.len() == 36
        && v.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
impl Microsoft365 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            guid(&self.tenant) && guid(&self.client_id),
            "Microsoft 365 tenant and client IDs must be GUIDs"
        );
        ensure!(
            Path::new(&self.secret_file).is_absolute(),
            "Use an absolute Microsoft 365 secret file path"
        );
        crate::config::secret(&self.secret_file).map_err(|_| {
            crate::error!("Microsoft 365 secret file must be readable, private and nonempty")
        })?;
        Ok(())
    }
}
pub fn admin_origin(origin: &str) -> Result<()> {
    let u = crate::url::Url::parse(origin)?;
    ensure!(
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.path() == "/"
            && u.query().is_none()
            && u.fragment().is_none()
            && u.origin().ascii_serialization() == origin,
        "Admin address must be a canonical HTTPS origin"
    );
    Ok(())
}
fn domains(v: &Value) -> Result<Vec<String>> {
    let ds: Vec<String> = pratique::json_value::from_value(v.clone())?;
    ensure!(
        (1..=100).contains(&ds.len())
            && ds
                .iter()
                .all(|d| crate::config::domain(d) && d.to_lowercase() == *d)
            && ds.iter().collect::<BTreeSet<_>>().len() == ds.len(),
        "Choose 1–100 distinct accepted domains in Mail flow first"
    );
    Ok(ds)
}
fn continuation(next: &str, path: &str) -> Result<String> {
    ensure!(next.len() <= 16384, "Directory continuation too long");
    let u = crate::url::Url::parse(next)?;
    ensure!(
        u.scheme() == "https"
            && u.host_str() == Some("graph.microsoft.com")
            && u.port_or_known_default() == Some(443)
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
            && u.path() == path,
        "Directory continuation rejected; accepted recipients are unchanged"
    );
    Ok(next.into())
}

// Injectable transport for synthetic tests; the deployed transport has fixed Microsoft endpoints.
fn collect(ds: &[String], mut fetch: impl FnMut(&str) -> Result<Value>) -> Result<Value> {
    let start = Instant::now();
    let mut addresses = BTreeSet::new();
    let mut pages = 0;
    let mut objects = 0;
    let mut bytes = 0;
    for (kind, select) in [
        ("users", "id,mail,proxyAddresses,userType"),
        ("groups", "id,mail,proxyAddresses,mailEnabled"),
        ("contacts", "id,mail,proxyAddresses"),
    ] {
        let path = format!("/v1.0/{kind}");
        let mut next = Some(format!("{GRAPH}{path}?$select={select}&$top=999"));
        let mut seen = BTreeSet::new();
        while let Some(url) = next {
            ensure!(
                pages < 200
                    && start.elapsed() < Duration::from_secs(300)
                    && seen.insert(url.clone()),
                "Directory discovery limit reached; no partial list can be applied"
            );
            let page = fetch(&url)?;
            pages += 1;
            bytes += pratique::json_value::to_vec(&page)?.len();
            ensure!(
                bytes <= 64 * 1024 * 1024,
                "Directory response budget exceeded"
            );
            let rows = arr(&page, "value")?;
            objects += rows.len();
            ensure!(objects <= 100000, "Directory object limit exceeded");
            for row in rows {
                ensure!(row.is_object(), "Malformed directory object");
                if (kind == "groups" && row["mailEnabled"] != true)
                    || (kind == "users" && row["userType"] == "Guest")
                {
                    continue;
                }
                let mut candidates = Vec::new();
                if let Some(mail) = row["mail"].as_str() {
                    candidates.push(mail);
                }
                if let Some(proxies) = row.get("proxyAddresses").filter(|v| !v.is_null()) {
                    for proxy in proxies
                        .as_array()
                        .ok_or_else(|| crate::error!("Malformed directory aliases"))?
                    {
                        let proxy = proxy
                            .as_str()
                            .ok_or_else(|| crate::error!("Malformed directory alias"))?;
                        if let Some((prefix, value)) = proxy.split_once(':')
                            && prefix.eq_ignore_ascii_case("smtp")
                        {
                            candidates.push(value);
                        }
                    }
                }
                for value in candidates {
                    if let Ok(a) = address(value)
                        && ds
                            .iter()
                            .any(|d| a.rsplit_once('@').is_some_and(|(_, domain)| domain == d))
                    {
                        addresses.insert(a);
                        ensure!(
                            addresses.len() <= 10000,
                            "Directory recipient limit exceeded"
                        );
                    }
                }
            }
            next = match page.get("@odata.nextLink").filter(|v| !v.is_null()) {
                Some(v) => Some(continuation(
                    v.as_str()
                        .ok_or_else(|| crate::error!("Malformed directory continuation"))?,
                    &path,
                )?),
                None => None,
            };
        }
    }
    Ok(json!({"addresses":addresses,"pages":pages,"objects":objects}))
}
fn http(
    client: &pratique::Client,
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Vec<u8>,
    limit: usize,
) -> Result<Value> {
    let mut request = client.request(method, url).body(body);
    if let Some(token) = token {
        request = request.header("Authorization", &format!("Bearer {token}"));
    } else {
        request = request.header("Content-Type", "application/x-www-form-urlencoded");
    }
    let response = request.send().map_err(|_| {
        crate::error!(
            "Microsoft 365 connection failed; check outbound HTTPS, DNS and certificate trust"
        )
    })?;
    ensure!(
        response.status == 200,
        "Microsoft 365 returned HTTP {}; check application consent and credentials (429: retry later). Accepted recipients are unchanged",
        response.status
    );
    ensure!(
        response.body.len() <= limit,
        "Microsoft 365 response limit exceeded"
    );
    pratique::json_value::from_slice(&response.body)
        .map_err(|_| crate::error!("Invalid Microsoft 365 JSON response"))
}
fn discover(config: &Microsoft365, ds: &[String]) -> Result<Value> {
    let client = pratique::Client::new()?
        .follow_redirects(false)
        .max_redirects(0)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .total_timeout(Duration::from_secs(20))
        .max_body_bytes(4 * 1024 * 1024)
        .max_decoded_bytes(4 * 1024 * 1024);
    let secret = crate::config::secret(&config.secret_file)
        .map_err(|_| crate::error!("Microsoft 365 secret file unavailable"))?;
    let body = crate::url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &config.client_id)
        .append_pair("client_secret", &secret)
        .append_pair("scope", "https://graph.microsoft.com/.default")
        .append_pair("grant_type", "client_credentials")
        .finish();
    let token = http(
        &client,
        "POST",
        &format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            config.tenant
        ),
        None,
        body.into_bytes(),
        65536,
    )?;
    let token = s(&token, "access_token")?;
    ensure!(
        !token.is_empty() && token.len() <= 16384 && token.bytes().all(|b| b.is_ascii_graphic()),
        "Invalid Microsoft 365 access token"
    );
    collect(ds, |url| {
        http(
            &client,
            "GET",
            url,
            Some(token),
            Vec::new(),
            4 * 1024 * 1024,
        )
    })
}

impl Service {
    pub fn directory_start(&self, t: &mut Table, a: &Actor, d: &Value, rid: &str) -> Result<Value> {
        ensure!(
            self.config.recipient_directory.is_some(),
            "Provision a Microsoft 365 recipient_directory profile first"
        );
        let settings = must(t, "settings")?;
        a.global(&settings)?;
        ensure!(
            d["expected_revision"] == settings["revision"],
            "Configuration changed; reload"
        );
        let ds = domains(&d["domains"])?;
        a.global(&json!({"domains":ds}))?;
        if let Some(old) = get(t, CURRENT)? {
            ensure!(
                old["state"] != "queued" && old["state"] != "running",
                "Recipient discovery is already in progress"
            );
            ensure!(
                now() - old["started"].as_i64().unwrap_or(0) >= 30,
                "Wait 30 seconds between discovery requests"
            );
        }
        let task = json!({"id":rid,"state":"queued","actor":a.id,"domains":ds,
            "revision":settings["revision"],"started":now(),"source":"microsoft365"});
        put(t, CURRENT, &task)?;
        event(
            t,
            a,
            "recipient-discover",
            rid,
            "",
            json!({"domains":ds,"source":"microsoft365"}),
        )?;
        Ok(task)
    }
    pub fn directory_status(&self, t: &Table, a: &Actor) -> Result<Value> {
        a.global(&must(t, "settings")?)?;
        let task = get(t, CURRENT)?.unwrap_or(json!({"state":"none"}));
        if task["state"] != "none" {
            ensure!(
                task["actor"] == a.id,
                "Discovery belongs to another administrator; start your own review"
            );
            a.global(&json!({"domains":task["domains"]}))?;
        }
        Ok(task)
    }
    pub fn directory_changes(&self, t: &Table, a: &Actor, d: &Value) -> Result<(Value, Value)> {
        ensure!(
            d["confirm"] == true,
            "Review and confirm recipient additions"
        );
        let task = self.directory_status(t, a)?;
        ensure!(
            task["state"] == "ready" && task["id"] == d["id"],
            "Complete recipient discovery required"
        );
        ensure!(
            now() - task["completed"].as_i64().unwrap_or(0) < TTL,
            "Discovery expired; discover again"
        );
        let settings = must(t, "settings")?;
        ensure!(
            settings["revision"] == task["revision"]
                && settings["revision"] == d["expected_revision"],
            "Configuration changed since discovery; discover again"
        );
        ensure!(
            settings["enabled"] != true,
            "Pause new acceptance before applying recipients, then retest before resuming"
        );
        let ds = domains(&d["domains"])?;
        ensure!(
            json!(ds) == task["domains"],
            "Accepted domains changed; discover again"
        );
        let mut mailboxes = settings["mailboxes"].clone();
        let boxes = mailboxes
            .as_object_mut()
            .ok_or_else(|| crate::error!("Invalid recipients"))?;
        for value in arr(&task, "addresses")? {
            let value = value
                .as_str()
                .ok_or_else(|| crate::error!("Invalid discovery address"))?;
            a.require("configure", Some(value))?;
            boxes
                .entry(value.to_owned())
                .or_insert(json!({"enabled":true}));
        }
        Ok((
            task,
            json!({"domains":ds,"routes":d["routes"],"mailboxes":mailboxes}),
        ))
    }
    pub fn directory_once(&self) -> Result<bool> {
        self.directory_once_with(discover)
    }
    pub(super) fn directory_once_with(
        &self,
        fetch: impl FnOnce(&Microsoft365, &[String]) -> Result<Value>,
    ) -> Result<bool> {
        let task = self.db.write(|t| {
            let Some(mut task) = get(t, CURRENT)? else {
                return Ok(None);
            };
            if task["state"] != "queued" {
                return Ok(None);
            }
            task["state"] = json!("running");
            put(t, CURRENT, &task)?;
            Ok(Some(task))
        })?;
        let Some(mut task) = task else {
            return Ok(false);
        };
        let result = crate::resilience::boundary("directory discovery", || -> Result<Value> {
            let config =
                self.config.recipient_directory.as_ref().ok_or_else(|| {
                    crate::error!("Microsoft 365 discovery is no longer configured")
                })?;
            fetch(config, &domains(&task["domains"])?)
        });
        self.db.write(|t| {
            match result {
                Ok(result) => {
                    task["state"] = json!("ready");
                    task["addresses"] = result["addresses"].clone();
                    task["pages"] = result["pages"].clone();
                    task["objects"] = result["objects"].clone();
                }
                Err(e) => { task["state"] = json!("failed"); task["error"] = json!(e.to_string()); }
            }
            task["completed"] = json!(now());
            put(t, CURRENT, &task)?;
            audit(t, s(&task,"actor")?, "recipient-discovery-result", "", json!({
                "id":task["id"], "state":task["state"], "count":task["addresses"].as_array().map(Vec::len),
                "error":task["error"]}))?;
            Ok(())
        })?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_users_aliases_groups_contacts_and_domain_filter() {
        let result = collect(&["example.test".into()], |url| Ok(if url.contains("/users?") {
            json!({"value":[{"mail":"Shared@example.test","userType":"Member","accountEnabled":false,"proxyAddresses":["SMTP:Shared@example.test","smtp:alias@example.test","SIP:no@example.test","smtp:away@outside.test"]},{"mail":"guest@example.test","userType":"Guest"},{"userPrincipalName":"login@example.test"}]})
        } else if url.contains("/groups?") {
            json!({"value":[{"mail":"group@example.test","mailEnabled":true},{"mail":"nomail@example.test","mailEnabled":false}]})
        } else { json!({"value":[{"proxyAddresses":["smtp:contact@example.test"]}]}) })).unwrap();
        assert_eq!(
            result["addresses"],
            json!([
                "alias@example.test",
                "contact@example.test",
                "group@example.test",
                "shared@example.test"
            ])
        );
    }
    #[test]
    fn hostile_pagination_and_partial_failure_refused() {
        for url in [
            "http://graph.microsoft.com/v1.0/users?x=1",
            "https://evil.test/v1.0/users",
            "https://graph.microsoft.com/v1.0/groups",
            "https://graph.microsoft.com:444/v1.0/users",
            "https://x@graph.microsoft.com/v1.0/users",
            "https://graph.microsoft.com/v1.0/users#x",
        ] {
            assert!(continuation(url, "/v1.0/users").is_err(), "{url}");
        }
        let mut calls = 0;
        let result = collect(&["example.test".into()], |url| {
            calls += 1;
            if calls == 1 {
                Ok(
                    json!({"value":[{"mail":"first@example.test"}],"@odata.nextLink":format!("{}&page=2",url)}),
                )
            } else {
                crate::bail!("synthetic provider failure")
            }
        });
        assert!(result.is_err());
        assert_eq!(calls, 2);
        assert!(
            collect(&["example.test".into()], |url| Ok(
                json!({"value":[],"@odata.nextLink":url})
            ))
            .is_err()
        );
        assert!(collect(&["example.test".into()], |_| Ok(json!({"error":"denied"}))).is_err());
    }
    #[test]
    fn pagination_complete_and_empty_result() {
        let mut calls = 0;
        let result = collect(&["example.test".into()], |url| {
            calls += 1;
            Ok(if calls == 1 {
                json!({"value":[],"@odata.nextLink":format!("{url}&page=2")})
            } else {
                json!({"value":[]})
            })
        })
        .unwrap();
        assert_eq!(result["pages"], 4);
        assert_eq!(result["addresses"], json!([]));
    }
    #[test]
    fn origins_and_profile_ids_reject_redirects_or_paths() {
        assert!(admin_origin("https://localhost:8444").is_ok());
        for v in [
            "javascript:alert(1)",
            "https://user@admin.test",
            "https://admin.test/?next=bad",
            "https://admin.test/#x",
            "https://admin.test/path",
            "http://admin.test",
        ] {
            assert!(admin_origin(v).is_err());
        }
        assert!(guid("11111111-2222-3333-4444-555555555555"));
        assert!(!guid("common/../../evil"));
    }
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    pratique::data_encode!(Microsoft365 {
        tenant,
        client_id,
        secret_file
    });
    #[test]
    fn record_contract_microsoft365() {
        crate::data_contracts::check::<Microsoft365>(
            "src_security_directory_Microsoft365",
            &[
                r###"{"tenant":"sample-\u00e9\ud83d\ude00","client_id":"sample-\u00e9\ud83d\ude00","secret_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00"]"###,
                r###"{"tenant":"sample-\u00e9\ud83d\ude00","client_id":"sample-\u00e9\ud83d\ude00","secret_file":"sample-\u00e9\ud83d\ude00","unexpected_field":1}"###,
                r###"{"client_id":"sample-\u00e9\ud83d\ude00","secret_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"tenant":false,"client_id":"sample-\u00e9\ud83d\ude00","secret_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"tenant":"sample-\u00e9\ud83d\ude00","client_id":"sample-\u00e9\ud83d\ude00","secret_file":"sample-\u00e9\ud83d\ude00","tenant":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"tenant":"sample-\u00e9\ud83d\ude00","secret_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"tenant":"sample-\u00e9\ud83d\ude00","client_id":false,"secret_file":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"tenant":"sample-\u00e9\ud83d\ude00","client_id":"sample-\u00e9\ud83d\ude00","secret_file":"sample-\u00e9\ud83d\ude00","client_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"tenant":"sample-\u00e9\ud83d\ude00","client_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"tenant":"sample-\u00e9\ud83d\ude00","client_id":"sample-\u00e9\ud83d\ude00","secret_file":false}"###,
                r###"{"tenant":"sample-\u00e9\ud83d\ude00","client_id":"sample-\u00e9\ud83d\ude00","secret_file":"sample-\u00e9\ud83d\ude00","secret_file":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
}
