//! Guided destination setup. New destinations are immutable and stored with
//! encrypted settings. A short-lived, scoped SMTP/TLS test precedes each save.
use super::{
    db::*,
    model::*,
    service::{Service, event},
    transport,
};
use crate::error::{Result, ensure};
use pratique::json_value::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
const CURRENT: &str = "destination/current";

#[derive(Clone, Debug)]
pub(super) struct Candidate {
    pub label: String,
    pub provider: String,
    pub host: String,
    pub port: u16,
    pub implicit_tls: bool,
}
pratique::data_encode!(Candidate {
    label,
    provider,
    host,
    port,
    implicit_tls
});
pratique::data_decode!(Candidate, deny_unknown=true, { label, provider, host, port, implicit_tls });

fn microsoft_host(host: &str) -> bool {
    host.ends_with(".mail.protection.outlook.com") && crate::config::domain(host)
}
impl Candidate {
    fn route(&self) -> Result<Route> {
        ensure!(
            !self.label.trim().is_empty()
                && self.label.len() <= 80
                && !self.label.chars().any(char::is_control),
            "Enter a destination name (up to 80 characters)"
        );
        ensure!(
            crate::config::domain(&self.host)
                && self.host.contains('.')
                && self.host == self.host.to_ascii_lowercase()
                && self.host.parse::<std::net::IpAddr>().is_err(),
            "Enter a DNS hostname only, without https://, a path or a port"
        );
        ensure!(
            self.host != "localhost"
                && ![".localhost", ".local", ".internal"]
                    .iter()
                    .any(|s| self.host.ends_with(s)),
            "Use a public delivery hostname; private-network routes must be provisioned on the installation"
        );
        ensure!(
            matches!(self.provider.as_str(), "microsoft365" | "smtp"),
            "Choose Microsoft 365 or another SMTP mail system"
        );
        ensure!(
            (self.port == 25 && !self.implicit_tls) || (self.port == 465 && self.implicit_tls),
            "Use port 25 with STARTTLS or port 465 with TLS from connection start"
        );
        if self.provider == "microsoft365" {
            ensure!(
                microsoft_host(&self.host) && self.port == 25 && !self.implicit_tls,
                "Use your Microsoft 365 MX hostname ending in .mail.protection.outlook.com, on port 25 with STARTTLS"
            );
        }
        Ok(Route {
            host: self.host.clone(),
            port: self.port,
            implicit_tls: self.implicit_tls,
            public_only: true,
            ca_file: None,
            username: None,
            password_file: None,
        })
    }
}
fn domains(v: &Value) -> Result<Vec<String>> {
    let ds: Vec<String> = pratique::json_value::from_value(v.clone())?;
    ensure!(
        (1..=100).contains(&ds.len())
            && ds.iter().all(|d| crate::config::domain(d)
                && d.contains('.')
                && d == &d.to_ascii_lowercase())
            && ds.iter().collect::<BTreeSet<_>>().len() == ds.len(),
        "Enter your accepted email domain in Mail flow first"
    );
    Ok(ds)
}
fn saved(v: &Value) -> Result<BTreeMap<String, Candidate>> {
    Ok(pratique::json_value::from_value(
        v.get("delivery_destinations").cloned().unwrap_or(json!({})),
    )?)
}
impl Service {
    pub fn delivery_routes(&self, settings: &Value) -> Result<BTreeMap<String, Route>> {
        let mut routes = self.config.routes.clone();
        let managed = saved(settings)?;
        ensure!(managed.len() <= 100, "Delivery destination limit reached");
        for (name, candidate) in managed {
            key(&name)?;
            ensure!(
                !routes.contains_key(&name),
                "Duplicate delivery destination ID; resolve the installation configuration conflict"
            );
            ensure!(
                candidate.host != self.config.hostname,
                "Delivery destination must not point to this gateway"
            );
            routes.insert(name, candidate.route()?);
        }
        Ok(routes)
    }
    pub fn destination_summaries(&self, settings: &Value) -> Result<Value> {
        let managed = saved(settings)?;
        let mut out = json!({});
        for (name, route) in self.delivery_routes(settings)? {
            out[&name] = json!({"label":managed.get(&name).map(|c| c.label.as_str()).unwrap_or(&name),
                "host":route.host,"port":route.port,"tls":true,"implicit_tls":route.implicit_tls,
                "source":if managed.contains_key(&name) {"wizard"} else {"installation"}});
        }
        Ok(out)
    }
    pub fn destination_start(
        &self,
        t: &mut Table,
        a: &Actor,
        action: &str,
        d: &Value,
        rid: &str,
    ) -> Result<Value> {
        let settings = must(t, "settings")?;
        a.global(&settings)?;
        ensure!(
            d["expected_revision"] == settings["revision"],
            "Configuration changed; reload Mail flow"
        );
        let ds = domains(&d["domains"])?;
        a.global(&json!({"domains":ds}))?;
        if let Some(task) = get(t, CURRENT)? {
            ensure!(
                !["queued", "running"].contains(&task["state"].as_str().unwrap_or("")),
                "A delivery check is already in progress"
            );
        }
        let mut task = json!({"id":rid,"kind":action,"actor":a.id,"domains":ds,
            "revision":settings["revision"],"state":"queued","started":now()?});
        if action == "delivery-discover" {
            let domain = s(d, "domain")?;
            ensure!(
                ds.iter().any(|x| x == domain),
                "Choose one of your accepted domains"
            );
            task["domain"] = json!(domain);
        } else {
            ensure!(action == "delivery-test", "Unknown delivery check");
            let candidate: Candidate = pratique::json_value::from_value(d["candidate"].clone())?;
            candidate.route()?;
            ensure!(
                candidate.host != self.config.hostname,
                "Delivery destination must not point to this gateway"
            );
            task["candidate"] = pratique::json_value::to_value(candidate)?;
        }
        put(t, CURRENT, &task)?;
        event(
            t,
            a,
            action,
            rid,
            "",
            json!({"domains":ds,"candidate":task["candidate"],"domain":task["domain"]}),
        )?;
        Ok(task)
    }
    pub fn destination_status(&self, t: &Table, a: &Actor) -> Result<Value> {
        a.global(&must(t, "settings")?)?;
        let task = get(t, CURRENT)?.unwrap_or(json!({"state":"none"}));
        if task["state"] != "none" {
            ensure!(
                task["actor"] == a.id,
                "This check belongs to another administrator; run your own test before saving"
            );
            a.global(&json!({"domains":task["domains"]}))?;
        }
        Ok(task)
    }
    pub fn destination_save(
        &self,
        t: &mut Table,
        a: &Actor,
        d: &Value,
        rid: &str,
    ) -> Result<Value> {
        ensure!(
            d["confirm"] == true,
            "Confirm Save destination after reviewing the test"
        );
        let mut task = self.destination_status(t, a)?;
        ensure!(
            task["id"] == d["id"]
                && task["kind"] == "delivery-test"
                && task["state"] == "ready"
                && task["result"]["ok"] == true,
            "Run a successful connection test before saving this destination"
        );
        ensure!(
            now()?.saturating_sub(task["completed"].as_i64().unwrap_or(0)) < 900,
            "Connection test expired; test again"
        );
        let mut settings = must(t, "settings")?;
        ensure!(
            d["expected_revision"] == settings["revision"]
                && task["revision"] == settings["revision"],
            "Configuration changed after the test; reload and test again"
        );
        let candidate: Candidate = pratique::json_value::from_value(task["candidate"].clone())?;
        candidate.route()?;
        let mut managed = saved(&settings)?;
        ensure!(managed.len() < 100, "Delivery destination limit reached");
        let name = format!("wizard-{}", s(&task, "id")?);
        ensure!(
            !managed.contains_key(&name) && !self.config.routes.contains_key(&name),
            "Destination already exists"
        );
        managed.insert(name.clone(), candidate.clone());
        settings["delivery_destinations"] = pratique::json_value::to_value(managed)?;
        self.delivery_routes(&settings)?;
        settings["revision"] = json!(n(&settings, "revision")? + 1);
        put(t, "settings", &settings)?;
        task["state"] = json!("saved");
        task["destination"] = json!(name);
        put(t, CURRENT, &task)?;
        event(
            t,
            a,
            "delivery-save",
            rid,
            "",
            json!({"id":name,"candidate":candidate,"test":task["id"],"revision":settings["revision"]}),
        )?;
        Ok(
            json!({"id":name,"route":self.destination_summaries(&settings)?[&name],"revision":settings["revision"]}),
        )
    }
    pub fn destination_once(&self) -> Result<bool> {
        self.destination_once_with(|task| {
            if task["kind"] == "delivery-discover" {
                use workglen_dns::{RecordType,RData};
                let lookup = self.checker.lookup(s(task,"domain")?,RecordType::MX)
                    .map_err(|_| crate::error!("Could not read MX records. Retry, or copy the MX destination from Microsoft 365 Admin → Settings → Domains → DNS records"))?;
                let mut hosts = Vec::new();
                for record in lookup.answers().iter().take(100) {
                    if let RData::MX(value) = &record.data {
                        let host = value.exchange.to_ascii().trim_end_matches('.').to_ascii_lowercase();
                        if microsoft_host(&host) && host != self.config.hostname {
                            hosts.push((value.preference,host));
                        }
                    }
                }
                hosts.sort();hosts.dedup();hosts.truncate(20);
                Ok(json!({"hosts":hosts.into_iter().map(|(_,h)|h).collect::<Vec<_>>()}))
            } else {
                let candidate: Candidate = pratique::json_value::from_value(task["candidate"].clone())?;
                transport::probe(&candidate.route()?)?;
                Ok(json!({"ok":true,"detail":"SMTP greeting, verified TLS and NOOP succeeded. No email was sent; recipient acceptance and Microsoft 365 connector policy still need an end-to-end mail test."}))
            }
        })
    }
    pub(super) fn destination_once_with(
        &self,
        check: impl FnOnce(&Value) -> Result<Value>,
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
        let result = crate::resilience::boundary("delivery check", || check(&task));
        self.db.write(|t| {
            match result {
                Ok(v) => {
                    task["state"] = json!("ready");
                    task["result"] = v;
                }
                Err(e) => {
                    task["state"] = json!("failed");
                    task["error"] = json!(e.to_string());
                }
            }
            task["completed"] = json!(now()?);
            put(t, CURRENT, &task)?;
            audit(
                t,
                s(&task, "actor")?,
                "delivery-check-result",
                "",
                json!({"id":task["id"],"state":task["state"],"error":task["error"]}),
            )?;
            Ok(())
        })?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destination_input_and_public_network_boundary() {
        let mut c = Candidate {
            label: "Microsoft 365".into(),
            provider: "microsoft365".into(),
            host: "example-com.mail.protection.outlook.com".into(),
            port: 25,
            implicit_tls: false,
        };
        assert!(c.route().unwrap().public_only);
        for host in [
            "https://example.com",
            "example.com:25",
            "localhost",
            "127.0.0.1",
            "host.local",
            "bad.mail.protection.outlook.com.evil.test",
        ] {
            c.host = host.into();
            assert!(c.route().is_err());
        }
        c.provider = "smtp".into();
        c.host = "mail.example.test".into();
        assert!(c.route().is_ok());
        c.port = 80;
        assert!(c.route().is_err());
        c.port = 465;
        c.implicit_tls = true;
        assert!(c.route().is_ok());
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "2002:a00:1::1",
            "64:ff9b::a00:1",
        ] {
            assert!(!transport::public_destination(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "2603:1020:201:10::1"] {
            assert!(transport::public_destination(ip.parse().unwrap()), "{ip}");
        }
    }
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    #[test]
    fn record_contract_candidate() {
        crate::data_contracts::check::<Candidate>(
            "src_security_destinations_Candidate",
            &[
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",65535,true]"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"unexpected_field":1}"###,
                r###"{"provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true}"###,
                r###"{"label":false,"provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"label":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":false,"host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"provider":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":false,"port":65535,"implicit_tls":true}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"host":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","implicit_tls":true}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":"wrong","implicit_tls":true}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"port":65535}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":"wrong"}"###,
                r###"{"label":"sample-\u00e9\ud83d\ude00","provider":"sample-\u00e9\ud83d\ude00","host":"sample-\u00e9\ud83d\ude00","port":65535,"implicit_tls":true,"implicit_tls":true}"###,
            ],
        );
    }
}
