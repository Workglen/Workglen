//! Provisioned endpoints only. Preserve verified original MIME before any provider removal.
use super::{
    db::*,
    model::*,
    service::{Service, event},
    transport::{self, RetryAfter, Uncertain},
    xml,
};
use crate::encoding::STANDARD;
use crate::error::{Result, bail, ensure};
use pratique::json_value::{Value, json};
use std::time::{Duration, Instant};
const M: &str = "http://schemas.microsoft.com/exchange/services/2006/messages";
const T: &str = "http://schemas.microsoft.com/exchange/services/2006/types";
fn segment(s: &str) -> String {
    crate::url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}
fn field<'a>(v: &'a Option<String>, name: &str) -> Result<&'a str> {
    v.as_deref()
        .ok_or_else(|| crate::error!("Missing connector field: {name}"))
}
struct Client<'a> {
    c: &'a Connector,
    token: Option<String>,
}
fn http(
    c: &Connector,
    url: &str,
    method: &str,
    headers: &[(&str, String)],
    body: Vec<u8>,
    limit: usize,
) -> Result<(u16, Vec<u8>)> {
    let u = crate::url::Url::parse(url)?;
    ensure!(
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none(),
        "Canonical HTTPS endpoint required"
    );
    let client = if let Some(ca) = &c.ca_file {
        pratique::Client::with_tls_config(transport::tls(Some(ca))?)
    } else {
        pratique::Client::new()?
    }
    .follow_redirects(false)
    .max_redirects(0)
    .connect_timeout(Duration::from_secs(5))
    .timeout(Duration::from_secs(20))
    .total_timeout(Duration::from_secs(30))
    .max_body_bytes(limit as u64)
    .max_decoded_bytes(limit as u64);
    let mut req = client.request(method, url).body(body);
    for (key, value) in headers {
        req = req.header(key, value);
    }
    let r = req
        .send()
        .map_err(|_| crate::error!("Mailbox provider connection unavailable"))?;
    if r.status == 429 || r.status == 503 {
        let value = r.header("retry-after").unwrap_or("60");
        let seconds = value
            .parse::<i64>()
            .ok()
            .or_else(|| {
                crate::datetime::DateTime::parse_from_rfc2822(value)
                    .ok()
                    .map(|t| t.timestamp() - now())
            })
            .unwrap_or(60);
        return Err(RetryAfter(seconds.clamp(30, 86400)).into());
    }
    ensure!(
        (200..300).contains(&r.status) || r.status == 404,
        "Mailbox provider rejected operation ({})",
        r.status
    );
    Ok((r.status, r.body))
}
impl<'a> Client<'a> {
    fn new(svc: &'a Service, name: &str) -> Result<Self> {
        Ok(Self {
            c: svc
                .config
                .connectors
                .get(name)
                .ok_or_else(|| crate::error!("Unknown connector"))?,
            token: None,
        })
    }
    fn scope(&self, mailbox: &str) -> Result<()> {
        ensure!(
            self.c.mailboxes.iter().any(|m| m == mailbox),
            "Connector mailbox scope denied"
        );
        Ok(())
    }
    fn graph(&mut self, path: &str, method: &str) -> Result<(u16, Vec<u8>)> {
        ensure!(path.starts_with("/v1.0/"), "Invalid Graph path");
        if self.token.is_none() {
            self.token = Some(if let Some(file) = &self.c.token_file {
                crate::config::secret(file)?
            } else {
                let tenant = field(&self.c.tenant, "tenant")?;
                ensure!(
                    !tenant.is_empty()
                        && tenant
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c)),
                    "Invalid tenant"
                );
                let body = crate::url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("client_id", field(&self.c.client_id, "client_id")?)
                    .append_pair(
                        "client_secret",
                        &crate::config::secret(field(&self.c.secret_file, "secret_file")?)?,
                    )
                    .append_pair("scope", "https://graph.microsoft.com/.default")
                    .append_pair("grant_type", "client_credentials")
                    .finish();
                let (code, raw) = http(
                    self.c,
                    &format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
                    "POST",
                    &[("Content-Type", "application/x-www-form-urlencoded".into())],
                    body.into_bytes(),
                    65536,
                )?;
                ensure!(code == 200, "Token request failed");
                s(
                    &pratique::json_value::from_slice::<Value>(&raw)?,
                    "access_token",
                )?
                .to_string()
            });
        }
        http(
            self.c,
            &format!("https://graph.microsoft.com{path}"),
            method,
            &[
                (
                    "Authorization",
                    format!("Bearer {}", self.token.as_deref().unwrap_or("")),
                ),
                ("Prefer", "IdType=\"ImmutableId\"".into()),
            ],
            Vec::new(),
            MAX_MESSAGE,
        )
    }
    fn ews(&self, mailbox: &str, body: &str) -> Result<Vec<xml::Node>> {
        self.scope(mailbox)?;
        let envelope = format!(
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:m=\"{M}\" xmlns:t=\"{T}\"><s:Header><t:RequestServerVersion Version=\"Exchange2013_SP1\"/><t:ExchangeImpersonation><t:ConnectingSID><t:PrimarySmtpAddress>{}</t:PrimarySmtpAddress></t:ConnectingSID></t:ExchangeImpersonation></s:Header><s:Body>{body}</s:Body></s:Envelope>",
            xml::escape(mailbox)
        );
        let auth = if let Some(file) = &self.c.token_file {
            format!("Bearer {}", crate::config::secret(file)?)
        } else {
            format!(
                "Basic {}",
                STANDARD.encode(format!(
                    "{}:{}",
                    field(&self.c.username, "username")?,
                    crate::config::secret(field(&self.c.password_file, "password_file")?)?
                ))
            )
        };
        let (code, raw) = http(
            self.c,
            field(&self.c.endpoint, "endpoint")?,
            "POST",
            &[
                ("Authorization", auth),
                ("Content-Type", "text/xml; charset=utf-8".into()),
                ("X-AnchorMailbox", mailbox.into()),
            ],
            envelope.into_bytes(),
            MAX_BODY,
        )?;
        ensure!(code == 200, "Exchange endpoint unavailable");
        let nodes = xml::parse(&raw)?;
        let codes: Vec<_> = nodes
            .iter()
            .filter(|n| n.namespace == M && n.name == "ResponseCode")
            .collect();
        ensure!(
            !codes.is_empty() && codes.iter().all(|n| n.text == "NoError"),
            "Exchange rejected operation"
        );
        Ok(nodes)
    }
    fn list(
        &mut self,
        mailbox: &str,
        start: &str,
        end: &str,
        limit: usize,
    ) -> Result<(Vec<Value>, bool)> {
        self.scope(mailbox)?;
        match self.c.r#type.as_str() {
            "graph" => {
                let base = format!(
                    "/v1.0/users/{}/mailFolders/inbox/messages",
                    segment(mailbox)
                );
                let query=crate::url::form_urlencoded::Serializer::new(String::new()).append_pair("$select","id,receivedDateTime,parentFolderId").append_pair("$filter",&format!("receivedDateTime ge {start}T00:00:00Z and receivedDateTime lt {end}T00:00:00Z")).append_pair("$top",&limit.min(100).to_string()).finish();
                let mut path = format!("{base}?{query}");
                let mut rows = Vec::new();
                let mut more = false;
                for _ in 0..10 {
                    let (code, raw) = self.graph(&path, "GET")?;
                    ensure!(code == 200, "Mailbox unavailable");
                    let v: Value = pratique::json_value::from_slice(&raw)?;
                    for x in arr(&v, "value")? {
                        rows.push(json!({"id":s(x,"id")?,"location":x["parentFolderId"]}));
                    }
                    more = v["@odata.nextLink"].is_string();
                    if !more || rows.len() >= limit {
                        break;
                    }
                    let u = crate::url::Url::parse(s(&v, "@odata.nextLink")?)?;
                    ensure!(
                        u.scheme() == "https"
                            && u.host_str() == Some("graph.microsoft.com")
                            && u.port().is_none()
                            && u.username().is_empty()
                            && u.password().is_none()
                            && u.fragment().is_none()
                            && u.path() == base,
                        "Unexpected Graph continuation scope"
                    );
                    path = format!("{}?{}", u.path(), u.query().unwrap_or(""));
                }
                let truncated = more || rows.len() > limit;
                rows.truncate(limit);
                Ok((rows, truncated))
            }
            "ews" => {
                let body = format!(
                    "<m:FindItem Traversal=\"Shallow\"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape><m:IndexedPageItemView MaxEntriesReturned=\"{limit}\" Offset=\"0\" BasePoint=\"Beginning\"/><m:Restriction><t:And><t:IsGreaterThanOrEqualTo><t:FieldURI FieldURI=\"item:DateTimeReceived\"/><t:FieldURIOrConstant><t:Constant Value=\"{start}T00:00:00Z\"/></t:FieldURIOrConstant></t:IsGreaterThanOrEqualTo><t:IsLessThan><t:FieldURI FieldURI=\"item:DateTimeReceived\"/><t:FieldURIOrConstant><t:Constant Value=\"{end}T00:00:00Z\"/></t:FieldURIOrConstant></t:IsLessThan></t:And></m:Restriction><m:ParentFolderIds><t:DistinguishedFolderId Id=\"inbox\"/></m:ParentFolderIds></m:FindItem>"
                );
                let nodes = self.ews(mailbox, &body)?;
                let more = !nodes.iter().any(|n| {
                    n.namespace == M
                        && n.name == "RootFolder"
                        && n.attrs
                            .get("IncludesLastItemInRange")
                            .is_some_and(|s| s == "true")
                });
                let mut rows = Vec::new();
                for n in nodes
                    .iter()
                    .filter(|n| n.namespace == T && n.name == "ItemId")
                {
                    rows.push(json!({"id":n.attrs.get("Id").ok_or_else(||crate::error!("Missing item ID"))?,"change_key":n.attrs.get("ChangeKey"),"location":"inbox"}));
                }
                ensure!(rows.len() <= limit, "Provider exceeded item limit");
                Ok((rows, more))
            }
            "workglen" => {
                let mut imap = Imap::new(self.c, mailbox, false)?;
                let start = crate::datetime::NaiveDate::parse_from_str(start, "%Y-%m-%d")?
                    .format("%d-%b-%Y");
                let end =
                    crate::datetime::NaiveDate::parse_from_str(end, "%Y-%m-%d")?.format("%d-%b-%Y");
                let (lines, _) = imap.command(&format!("UID SEARCH SINCE {start} BEFORE {end}"))?;
                let mut ids = Vec::new();
                for line in lines {
                    if let Some(s) = line.strip_prefix("* SEARCH") {
                        for uid in s.split_whitespace() {
                            uid.parse::<u32>()?;
                            ids.push(json!({"id":uid,"validity":imap.validity,"location":"INBOX"}));
                        }
                    }
                }
                let more = ids.len() > limit;
                ids.truncate(limit);
                Ok((ids, more))
            }
            _ => bail!("Unsupported connector"),
        }
    }
    fn get(&mut self, mailbox: &str, item: &Value) -> Result<Vec<u8>> {
        self.scope(mailbox)?;
        let raw = match self.c.r#type.as_str() {
            "graph" => {
                let (code, raw) = self.graph(
                    &format!(
                        "/v1.0/users/{}/messages/{}/$value",
                        segment(mailbox),
                        segment(s(item, "id")?)
                    ),
                    "GET",
                )?;
                ensure!(code == 200, "Message unavailable");
                raw
            }
            "ews" => {
                let nodes=self.ews(mailbox,&format!("<m:GetItem><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:IncludeMimeContent>true</t:IncludeMimeContent></m:ItemShape><m:ItemIds><t:ItemId Id=\"{}\"/></m:ItemIds></m:GetItem>",xml::escape(s(item,"id")?)))?;
                let content: Vec<_> = nodes
                    .iter()
                    .filter(|n| n.namespace == T && n.name == "MimeContent")
                    .collect();
                ensure!(
                    content.len() == 1,
                    "Exchange MIME content missing or ambiguous"
                );
                STANDARD.decode(content[0].text.split_whitespace().collect::<String>())?
            }
            "workglen" => Imap::new(self.c, mailbox, false)?.fetch(item)?,
            _ => bail!("Unknown connector"),
        };
        ensure!(raw.len() <= MAX_MESSAGE, "Exported message too large");
        Ok(raw)
    }
    fn remove(&mut self, mailbox: &str, item: &Value) -> Result<String> {
        self.scope(mailbox)?;
        ensure!(self.c.allow_hard_delete, "Connector removal disabled");
        let result = (|| -> Result<String> {
            match self.c.r#type.as_str() {
                "graph" => {
                    let (code, _) = self.graph(
                        &format!(
                            "/v1.0/users/{}/messages/{}/permanentDelete",
                            segment(mailbox),
                            segment(s(item, "id")?)
                        ),
                        "POST",
                    )?;
                    Ok(if code == 404 {
                        "already-absent"
                    } else {
                        "removed"
                    }
                    .into())
                }
                "ews" => {
                    let change = item["change_key"]
                        .as_str()
                        .map(|s| format!(" ChangeKey=\"{}\"", xml::escape(s)))
                        .unwrap_or_default();
                    self.ews(mailbox,&format!("<m:DeleteItem DeleteType=\"HardDelete\" SendMeetingCancellations=\"SendToNone\" AffectedTaskOccurrences=\"AllOccurrences\"><m:ItemIds><t:ItemId Id=\"{}\"{change}/></m:ItemIds></m:DeleteItem>",xml::escape(s(item,"id")?)))?;
                    Ok("removed".into())
                }
                "workglen" => {
                    let mut c = Imap::new(self.c, mailbox, true)?;
                    ensure!(
                        hash(&c.fetch(item)?) == s(item, "hash")?,
                        "Message changed since preview"
                    );
                    let uid = s(item, "id")?;
                    c.command(&format!("UID STORE {uid} +FLAGS.SILENT (\\Deleted)"))?;
                    c.command(&format!("UID EXPUNGE {uid}"))?;
                    Ok("removed".into())
                }
                _ => bail!("Unknown connector"),
            }
        })();
        result.map_err(|e| {
            if e.downcast_ref::<RetryAfter>().is_some() {
                e
            } else {
                Uncertain.into()
            }
        })
    }
}
struct Imap {
    wire: crate::net::Wire,
    tag: u32,
    validity: String,
}
fn quoted(s: &str) -> Result<String> {
    ensure!(!s.chars().any(char::is_control), "Invalid IMAP credential");
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
impl Imap {
    fn new(c: &Connector, mailbox: &str, write: bool) -> Result<Self> {
        ensure!(
            c.mailboxes.iter().any(|s| s == mailbox),
            "Connector scope denied"
        );
        let mut wire = transport::connect(
            field(&c.host, "host")?,
            c.port.unwrap_or(993),
            c.ca_file.as_deref(),
            true,
        )?;
        ensure!(
            wire.text(8192)?.starts_with("* OK"),
            "Invalid IMAP greeting"
        );
        let mut x = Self {
            wire,
            tag: 0,
            validity: String::new(),
        };
        let password = crate::config::secret(
            c.password_files
                .get(mailbox)
                .ok_or_else(|| crate::error!("Missing mailbox credential"))?,
        )?;
        x.command(&format!(
            "LOGIN {} {}",
            quoted(mailbox)?,
            quoted(&password)?
        ))?;
        let (lines, _) = x.command("CAPABILITY")?;
        ensure!(
            lines
                .iter()
                .any(|l| l.split_whitespace().any(|v| v == "UIDPLUS")),
            "UIDPLUS required for scoped removal"
        );
        let (lines, _) = x.command(if write {
            "SELECT INBOX"
        } else {
            "EXAMINE INBOX"
        })?;
        for line in lines {
            if let Some((_, tail)) = line.split_once("[UIDVALIDITY ") {
                let v = tail.split(']').next().unwrap_or("");
                v.parse::<u32>()?;
                x.validity = v.into();
            }
        }
        ensure!(!x.validity.is_empty(), "Missing UIDVALIDITY");
        Ok(x)
    }
    fn command(&mut self, cmd: &str) -> Result<(Vec<String>, Vec<Vec<u8>>)> {
        self.tag += 1;
        let tag = format!("W{}", self.tag);
        self.wire.deadline.set(Duration::from_secs(30));
        self.wire.send(&format!("{tag} {cmd}\r\n"))?;
        let mut lines = Vec::new();
        let mut bodies = Vec::new();
        let mut total = 0;
        for _ in 0..10000 {
            let line = self.wire.text(65536)?;
            total += line.len();
            ensure!(total <= MAX_BODY, "IMAP response budget");
            if line.starts_with(&format!("{tag} ")) {
                ensure!(
                    line.starts_with(&format!("{tag} OK")),
                    "IMAP command failed"
                );
                return Ok((lines, bodies));
            }
            if line.ends_with('}') {
                let (_, len) = line
                    .rsplit_once('{')
                    .ok_or_else(|| crate::error!("Invalid IMAP literal"))?;
                let size: usize = len[..len.len() - 1].parse()?;
                ensure!(
                    size <= MAX_MESSAGE && bodies.is_empty(),
                    "IMAP literal limit"
                );
                let mut b = vec![0; size];
                self.wire.exact(&mut b)?;
                total += size;
                bodies.push(b);
            }
            lines.push(line);
        }
        bail!("IMAP response line limit")
    }
    fn fetch(&mut self, item: &Value) -> Result<Vec<u8>> {
        ensure!(
            self.validity == s(item, "validity")?,
            "UIDVALIDITY changed; create a new preview"
        );
        let uid = s(item, "id")?;
        ensure!(uid.parse::<u32>()? > 0, "Invalid UID");
        let (lines, mut bodies) = self.command(&format!("UID FETCH {uid} (UID BODY.PEEK[])"))?;
        ensure!(
            bodies.len() == 1
                && lines
                    .iter()
                    .any(|l| l.contains(&format!("UID {uid} "))
                        || l.contains(&format!("UID {uid})"))),
            "Message missing or wrong UID"
        );
        Ok(bodies.remove(0))
    }
}
pub fn probe(svc: &Service, name: &str) -> Result<()> {
    let mut c = Client::new(svc, name)?;
    let mailbox =
        c.c.mailboxes
            .first()
            .ok_or_else(|| crate::error!("No connector mailbox"))?
            .clone();
    c.list(&mailbox, "2000-01-01", "2000-01-02", 1)?;
    Ok(())
}
pub fn command(
    svc: &Service,
    t: &mut Table,
    a: &Actor,
    action: &str,
    d: &Value,
    rid: &str,
) -> Result<Value> {
    let settings = must(t, "settings")?;
    if action == "remediation-review" {
        key(s(d, "id")?)?;
        let p = must(t, &format!("plan/{}", s(d, "id")?))?;
        a.require("remediation.preview", Some(s(&p, "recipient")?))?;
        return Ok(p);
    }
    if action == "remediation-preview" {
        let recipient = address(s(d, "recipient")?)?;
        a.require("remediation.preview", Some(&recipient))?;
        let name = s(d, "connector")?;
        ensure!(
            settings["mailboxes"].get(&recipient).is_some() && settings["connectors"][name] == true,
            "Mailbox or connector disabled"
        );
        let start = crate::datetime::NaiveDate::parse_from_str(s(d, "start")?, "%Y-%m-%d")?;
        let end = crate::datetime::NaiveDate::parse_from_str(s(d, "end")?, "%Y-%m-%d")?;
        ensure!(
            (1..=90).contains(&(end - start).num_days()),
            "Choose 1–90 calendar days"
        );
        let v = must(t, &format!("rule/{}", n(d, "version")?))?;
        ensure!(
            v["state"] == "test" || v["state"] == "active",
            "Choose a tested version"
        );
        let mut c = Client::new(svc, name)?;
        let limit = d["limit"].as_u64().unwrap_or(100).clamp(1, 200) as usize;
        let (items, more) = c.list(&recipient, &start.to_string(), &end.to_string(), limit)?;
        let mut plan = json!({"id":id(),"recipient":recipient,"connector":name,"version":v["id"],"start":start.to_string(),"end":end.to_string(),"created":now(),"expires":now()+3600,"complete":!more,"state":"preview","items":[],"location":"Inbox only; end date exclusive; IMAP uses server calendar days"});
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut results = Vec::new();
        for mut item in items {
            let result = (|| -> Result<(String, Value)> {
                ensure!(Instant::now() < deadline, "Preview time budget");
                let raw = c.get(&recipient, &item)?;
                let verdict = svc.evaluate(t, &raw, &v["rules"], &settings, &json!({}))?;
                Ok((hash(&raw), verdict))
            })();
            if let Ok((hash, verdict)) = result {
                item["hash"] = json!(hash);
                item["matched"] = json!(verdict["action"] == "quarantine");
                item["verdict"] = verdict;
                item["status"] = json!("identified");
            } else {
                item["status"] = json!("scan-failed");
                item["matched"] = json!(false);
                plan["complete"] = json!(false);
            }
            results.push(item);
        }
        plan["items"] = json!(results);
        ensure!(
            list(t, "plan/")?.len() < 10000,
            "Preview history capacity reached"
        );
        put(t, &format!("plan/{}", s(&plan, "id")?), &plan)?;
        event(
            t,
            a,
            action,
            rid,
            &recipient,
            json!({"plan":plan["id"],"count":results.len(),"complete":plan["complete"]}),
        )?;
        return Ok(plan);
    }
    ensure!(action == "remediation-start", "Unknown remediation action");
    key(s(d, "id")?)?;
    let k = format!("plan/{}", s(d, "id")?);
    let mut p = must(t, &k)?;
    a.require("remediation.execute", Some(s(&p, "recipient")?))?;
    ensure!(
        p["state"] == "preview" && p["expires"].as_i64().unwrap_or(0) > now(),
        "Preview started or expired"
    );
    ensure!(
        d["confirm"] == true && (p["complete"] == true || d["acknowledge_partial"] == true),
        "Confirm scope and partial results"
    );
    let name = s(&p, "connector")?;
    ensure!(
        settings["connectors"][name] == true && Client::new(svc, name)?.c.allow_hard_delete,
        "Connector removal disabled"
    );
    let mut jobs = Vec::new();
    for (i, item) in arr(&p, "items")?.iter().enumerate() {
        if item["matched"] == true {
            svc.capacity(t, &settings, 0, 0, 1)?;
            let j = format!("remediate-{}-{i}", s(&p, "id")?);
            job(
                t,
                "remediation",
                json!({"recipient":p["recipient"],"plan":p["id"],"index":i}),
                &j,
            )?;
            jobs.push(j);
        }
    }
    p["state"] = json!(if jobs.is_empty() {
        "completed"
    } else {
        "queued"
    });
    p["jobs"] = json!(jobs);
    put(t, &k, &p)?;
    event(
        t,
        a,
        action,
        rid,
        s(&p, "recipient")?,
        json!({"plan":p["id"],"jobs":jobs}),
    )?;
    Ok(json!({"plan":p["id"],"jobs":jobs}))
}
pub fn execute(svc: &Service, data: &Value) -> Result<()> {
    let (p, item, settings, v) = svc.db.write(|t| {
        let p = must(t, &format!("plan/{}", s(data, "plan")?))?;
        let item = p["items"]
            .get(n(data, "index")? as usize)
            .ok_or_else(|| crate::error!("Invalid plan item"))?
            .clone();
        let settings = must(t, "settings")?;
        let v = must(t, &format!("rule/{}", n(&p, "version")?))?;
        Ok((p, item, settings, v))
    })?;
    if item["status"] == "removed" {
        return Ok(());
    }
    let name = s(&p, "connector")?;
    ensure!(settings["connectors"][name] == true, "Connector disabled");
    let recipient = s(&p, "recipient")?;
    let mut c = Client::new(svc, name)?;
    let raw = c.get(recipient, &item)?;
    ensure!(
        hash(&raw) == s(&item, "hash")?,
        "Message changed; create another preview"
    );
    let id = format!("remediation-{}-{}", s(&p, "id")?, n(data, "index")?);
    svc.db.write(|t|{let settings=must(t,"settings")?;ensure!(settings["connectors"][name]==true,"Connector disabled");let verdict=svc.evaluate(t,&raw,&v["rules"],&settings,&json!({}))?;ensure!(verdict["action"]=="quarantine","Message no longer matches");if get(t,&format!("message/{id}"))?.is_none(){svc.capacity(t,&settings,raw.len(),1,0)?;blob(t,&raw)?;let m=json!({"id":id,"recipient":recipient,"arrived":now(),"state":"quarantined","revision":1,"hash":item["hash"],"subject":verdict["subject"],"sender":verdict["sender"],"envelope_from":"","releasable":false,"verdict":verdict,"engines":{},"rule_version":p["version"],"expires":now()+n(&settings,"retention_days")? as i64*86400,"hold":true,"route":settings["routes"][recipient.rsplit('@').next().unwrap_or("")],"source":{"item":item,"connector":name}});save_message(t,&m)?;audit(t,"worker","remediation-content-preserved",recipient,json!({"id":id,"hash":item["hash"],"plan":p["id"]}))?;}Ok(())})?;
    let result = c.remove(recipient, &item)?;
    svc.db.write(|t| {
        let k = format!("plan/{}", s(&p, "id")?);
        let mut current = must(t, &k)?;
        let i = n(data, "index")? as usize;
        current["items"][i]["status"] = json!("removed");
        current["items"][i]["quarantine_id"] = json!(id);
        current["items"][i]["provider_result"] = json!(result);
        put(t, &k, &current)?;
        audit(
            t,
            "worker",
            "remediation-removed",
            recipient,
            json!({"plan":p["id"],"id":id,"provider_result":result}),
        )
    })
}
