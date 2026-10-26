//! SimpleFIN v2 adapter. Financial data is staged, never posted by a feed.
use super::bank_files::Entry;
use super::*;
use crate::encoding::STANDARD;
use pratique::crypto::gcm::AesGcm;
use std::{collections::BTreeSet, sync::Arc, time::Duration};

fn endpoint(raw: &str, claim: bool) -> Result<crate::url::Url> {
    ensure!(
        raw.len() <= 4096 && !raw.chars().any(char::is_control),
        "Invalid SimpleFIN URL"
    );
    let u = crate::url::Url::parse(raw).map_err(|_| crate::error!("Invalid SimpleFIN URL"))?;
    ensure!(
        u.scheme() == "https"
            && matches!(
                u.host_str(),
                Some("bridge.simplefin.org" | "beta-bridge.simplefin.org")
            )
            && u.port_or_known_default() == Some(443)
            && u.query().is_none()
            && u.fragment().is_none(),
        "Only HTTPS SimpleFIN Bridge endpoints on port 443 are supported"
    );
    if claim {
        ensure!(
            u.username().is_empty()
                && u.password().is_none()
                && u.path().starts_with("/simplefin/claim/")
                && u.path().len() > 17,
            "Invalid SimpleFIN setup token"
        );
    } else {
        ensure!(
            !u.username().is_empty()
                && u.password().is_some_and(|s| !s.is_empty())
                && u.path().trim_end_matches('/') == "/simplefin",
            "Invalid SimpleFIN access URL"
        );
    }
    Ok(u)
}
fn key_bytes(db: &Db) -> Result<Vec<u8>> {
    let path=db.config.feed_key_file.as_ref().ok_or_else(||crate::error!("Set accounting.feed_key_file to a 0600 file holding a base64-encoded 32-byte encryption key"))?;
    let k = STANDARD
        .decode(crate::config::secret(path)?)
        .map_err(|_| crate::error!("Invalid feed encryption key"))?;
    ensure!(
        k.len() == 32,
        "Feed encryption key must contain 32 random bytes"
    );
    Ok(k)
}
fn seal(key: &[u8], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; 12];
    pratique::crypto::rand::fill(&mut iv)
        .map_err(|_| crate::error!("Random source unavailable"))?;
    ensure!(key.len() == 32, "Invalid feed encryption key");
    let sealed = AesGcm::new(key).seal(&iv, aad, plain);
    let split = sealed.len() - 16;
    Ok([iv.as_slice(), &sealed[split..], &sealed[..split]].concat())
}
fn unseal(key: &[u8], aad: &[u8], data: &[u8]) -> Result<String> {
    ensure!(
        data.len() >= 28 && key.len() == 32,
        "Invalid encrypted connection"
    );
    let sealed = [&data[28..], &data[12..28]].concat();
    let p = AesGcm::new(key)
        .open(data[..12].try_into().unwrap(), aad, &sealed)
        .ok_or_else(|| {
            crate::error!("Cannot decrypt bank connection; restore the correct feed encryption key")
        })?;
    String::from_utf8(p).map_err(Into::into)
}

fn aad(db: &Db, book: &str, id: &str) -> Result<Vec<u8>> {
    Ok(pratique::json_value::to_vec(&(&db.workspace, book, id))?)
}
fn client() -> Result<pratique::Client> {
    Ok(pratique::Client::new()?
        .follow_redirects(false)
        .max_redirects(0)
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(5))
        .total_timeout(Duration::from_secs(12))
        .max_body_bytes(4 * 1024 * 1024)
        .max_decoded_bytes(4 * 1024 * 1024)
        .user_agent("Workglen/0.4"))
}
fn credential(s: &str) -> Result<String> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            ensure!(i + 2 < b.len(), "Invalid access credentials");
            out.push(
                u8::from_str_radix(&s[i + 1..i + 3], 16)
                    .map_err(|_| crate::error!("Invalid access credentials"))?,
            );
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    let s = String::from_utf8(out)?;
    ensure!(
        !s.chars().any(char::is_control),
        "Invalid access credentials"
    );
    Ok(s)
}
pub fn connect(app: &crate::app::App, book: &str, v: &Value, actor: &str) -> Result<Value> {
    let db = app.accounting.as_ref().unwrap();
    let id = field(v, "id")?;
    key(id)?;
    let name = field(v, "name")?;
    text(name, 200, "connection name")?;
    let key = key_bytes(db)?;
    let claim_lease = crate::store::random_id();
    let token = field(v, "setup_token")?;
    ensure!(token.len() <= 6000, "Setup token too long");
    let bytes = STANDARD
        .decode(token.trim())
        .map_err(|_| crate::error!("Invalid setup token"))?;
    let claim = endpoint(
        std::str::from_utf8(&bytes).map_err(|_| crate::error!("Invalid setup token"))?,
        true,
    )?;
    {
        let mut c = db.connect()?;
        let mut t = c.transaction()?;
        installation(&mut t, &db.workspace, true)?;
        t.query_one(
            "SELECT id FROM workglen_accounting.books WHERE id=$1 FOR UPDATE",
            &[&book],
        )?;
        if let Some(r) = t.query_opt(
            "SELECT active FROM workglen_accounting.feed_connections WHERE book_id=$1 AND id=$2",
            &[&book, &id],
        )? {
            ensure!(
                r.get::<_, bool>(0),
                "Connection ID already exists; use a new ID for a replacement token"
            );
            return Ok(json!({"id":id,"replayed":true}));
        }
        ensure!(
            t.query_one(
                "SELECT count(*) FROM workglen_accounting.feed_connections WHERE active",
                &[]
            )?
            .get::<_, i64>(0)
                < 25,
            "At most 25 active feed connections per installation"
        );
        t.execute("INSERT INTO workglen_accounting.feed_connections(book_id,id,name,provider,active,lease) VALUES($1,$2,$3,'simplefin',false,$4)",&[&book,&id,&name,&claim_lease])?;
        t.commit()?;
    }
    let result = (|| -> Result<Vec<u8>> {
        let r=client()?.request("POST",claim.as_str()).body(Vec::<u8>::new()).max_body_bytes(8192).send().map_err(|_|crate::error!("SimpleFIN setup failed; disable the token in SimpleFIN and generate a new one before retrying"))?;
        ensure!(
            r.status == 200,
            "SimpleFIN setup rejected (HTTP {}). The token may already be used or compromised; disable it in SimpleFIN and generate a new one.",
            r.status
        );
        let raw = std::str::from_utf8(&r.body)?.trim();
        endpoint(raw, false)?;
        seal(&key, &aad(db, book, id)?, raw.as_bytes())
    })();
    let mut c = db.connect()?;
    let mut t = c.transaction()?;
    installation(&mut t, &db.workspace, true)?;
    app.require_primary()?;
    match result {
        Ok(secret) => {
            ensure!(t.execute("UPDATE workglen_accounting.feed_connections SET secret=$3,active=true,lease=NULL WHERE book_id=$1 AND id=$2 AND lease=$4",&[&book,&id,&secret,&claim_lease])?==1,"Connection was cancelled during setup; revoke the token in SimpleFIN");
            audit(
                &mut t,
                Some(book),
                actor,
                "feed-connect",
                id,
                json!({"provider":"simplefin"}),
            )?;
            t.commit()?;
            Ok(
                json!({"id":id,"message":"Connected. Sync to discover accounts, then map each account to its ledger account."}),
            )
        }
        Err(e) => {
            t.execute("UPDATE workglen_accounting.feed_connections SET errors=$3,lease=NULL WHERE book_id=$1 AND id=$2 AND lease=$4",&[&book,&id,&json!([e.to_string()]),&claim_lease])?;
            t.commit()?;
            Err(e)
        }
    }
}
#[derive(Debug)]
struct FeedAccount {
    key: String,
    name: String,
    currency: String,
    balance: String,
    balance_at: i64,
    entries: Vec<Entry>,
}
fn parse_payload(v: &Value, scale: i16, currency: &str) -> Result<(Vec<FeedAccount>, Value)> {
    let errors = v
        .get("errlist")
        .and_then(Value::as_array)
        .ok_or_else(|| crate::error!("SimpleFIN v2 errlist missing"))?;
    ensure!(errors.len() <= 100, "Too many provider errors");
    let mut messages = Vec::new();
    for e in errors {
        let msg = field(e, "msg")?;
        text(msg, 1000, "provider message")?;
        messages.push(json!({"code":e["code"],"message":msg,"connection":e["conn_id"],"account":e["account_id"]}));
    }
    // Preserve errors and do not advance a cursor on a partial/incomplete result.
    if !messages.is_empty() {
        return Ok((vec![], json!(messages)));
    }
    let a = v["accounts"]
        .as_array()
        .ok_or_else(|| crate::error!("Missing feed accounts"))?;
    ensure!(a.len() <= 200, "Feed exceeds 200 accounts");
    let mut keys = BTreeSet::new();
    let mut count = 0;
    let mut out = Vec::new();
    for a in a {
        let conn = field(a, "conn_id")?;
        let id = field(a, "id")?;
        text(conn, 200, "provider connection ID")?;
        text(id, 200, "provider account ID")?;
        let key = hash(&(conn, id))?;
        ensure!(keys.insert(key.clone()), "Duplicate feed account");
        let name = field(a, "name")?;
        text(name, 200, "feed account name")?;
        let cur = field(a, "currency")?;
        text(cur, 100, "currency")?;
        let balance = field(a, "balance")?;
        text(balance, 30, "balance")?;
        if cur == currency {
            bank_files::signed(balance, scale)?;
        }
        let balance_at = a["balance-date"]
            .as_i64()
            .ok_or_else(|| crate::error!("Missing balance date"))?;
        let tx = a.get("transactions").and_then(Value::as_array);
        let mut entries = Vec::new();
        let mut ids = BTreeSet::new();
        if cur == currency {
            for x in tx.into_iter().flatten() {
                count += 1;
                ensure!(
                    count <= 10000,
                    "Feed exceeds 10000 transactions; use smaller accounts or file imports"
                );
                if x["pending"].as_bool() == Some(true) {
                    continue;
                }
                let ts = x["posted"]
                    .as_i64()
                    .ok_or_else(|| crate::error!("Invalid posted timestamp"))?;
                if ts == 0 {
                    continue;
                }
                let d = crate::datetime::DateTime::from_timestamp(ts, 0)
                    .ok_or_else(|| crate::error!("Invalid posted timestamp"))?
                    .format("%Y-%m-%d")
                    .to_string();
                let id = field(x, "id")?;
                text(id, 200, "provider transaction ID")?;
                ensure!(
                    ids.insert(id.to_string()),
                    "Duplicate provider transaction ID"
                );
                let description = field(x, "description")?;
                text(description, 500, "transaction description")?;
                let amount = bank_files::signed(field(x, "amount")?, scale)?;
                if amount == 0 {
                    continue;
                }
                entries.push(Entry {
                    id: id.into(),
                    date: d,
                    amount,
                    description: description.into(),
                });
            }
        }
        out.push(FeedAccount {
            key,
            name: name.into(),
            currency: cur.into(),
            balance: balance.into(),
            balance_at,
            entries,
        });
    }
    Ok((out, json!([])))
}
pub fn sync(app: &crate::app::App, book: &str, id: &str) -> Result<Value> {
    let db = app.accounting.as_ref().unwrap();
    let key = key_bytes(db)?;
    let lease = crate::store::random_id();
    let now = crate::datetime::Utc::now().timestamp();
    let (secret, start, end, scale, currency) = {
        let mut c = db.connect()?;
        let mut t = c.transaction()?;
        installation(&mut t, &db.workspace, true)?;
        let b = t.query_one(
            "SELECT scale,currency FROM workglen_accounting.books WHERE id=$1",
            &[&book],
        )?;
        let r=t.query_one("SELECT secret,cursor_at,active,next_sync<=now() FROM workglen_accounting.feed_connections WHERE book_id=$1 AND id=$2 FOR UPDATE",&[&book,&id])?;
        ensure!(r.get::<_, bool>(2), "Feed connection is disconnected");
        ensure!(
            r.get::<_, bool>(3),
            "Feed is not due yet; refreshes are limited to once per hour, including retries"
        );
        let cursor = r.get::<_, Option<i64>>(1).unwrap_or(now - 84 * 86400);
        let start = (cursor - 5 * 86400).max(0);
        let end = (start + 89 * 86400).min(now);
        ensure!(start < end, "Feed cursor is in the future");
        t.execute("UPDATE workglen_accounting.feed_connections SET next_sync=now()+interval '1 hour',lease=$3 WHERE book_id=$1 AND id=$2",&[&book,&id,&lease])?;
        let data = (
            r.get::<_, Vec<u8>>(0),
            start,
            end,
            b.get::<_, i16>(0),
            b.get::<_, String>(1),
        );
        t.commit()?;
        data
    };
    let result = (|| -> Result<(Vec<FeedAccount>, Value)> {
        let raw = unseal(&key, &aad(db, book, id)?, &secret)?;
        let mut u = endpoint(&raw, false)?;
        let user = credential(u.username())?;
        ensure!(!user.contains(':'), "Invalid access username");
        let pass = credential(u.password().unwrap())?;
        let auth = format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")));
        u.set_username("")
            .map_err(|_| crate::error!("Invalid feed URL"))?;
        u.set_password(None)
            .map_err(|_| crate::error!("Invalid feed URL"))?;
        u.set_path("/simplefin/accounts");
        u.append_query_pair("version", "2")
            .append_query_pair("start-date", &start.to_string())
            .append_query_pair("end-date", &end.to_string());
        let r = client()?
            .request("GET", u.as_str())
            .header("Authorization", &auth)
            .send()
            .map_err(|_| {
                crate::error!("Cannot refresh SimpleFIN; connection or verified TLS failed")
            })?;
        ensure!(r.status != 402, "SimpleFIN subscription needs attention");
        ensure!(
            r.status != 403,
            "SimpleFIN access was revoked or expired; reconnect with a new setup token"
        );
        ensure!(r.status == 200, "SimpleFIN returned HTTP {}", r.status);
        let v: Value = pratique::json_value::from_slice(&r.body)
            .map_err(|_| crate::error!("Invalid SimpleFIN response"))?;
        parse_payload(&v, scale, &currency)
    })();
    let mut c = db.connect()?;
    let mut t = c.transaction()?;
    installation(&mut t, &db.workspace, true)?;
    app.require_primary()?;
    t.query_one(
        "SELECT id FROM workglen_accounting.books WHERE id=$1 FOR UPDATE",
        &[&book],
    )?;
    let r=t.query_one("SELECT active,lease FROM workglen_accounting.feed_connections WHERE book_id=$1 AND id=$2 FOR UPDATE",&[&book,&id])?;
    ensure!(
        r.get::<_, bool>(0) && r.get::<_, Option<String>>(1).as_deref() == Some(&lease),
        "Connection changed while sync was running; result discarded"
    );
    let (accounts, errors) = match result {
        Ok(x) => x,
        Err(e) => (vec![], json!([{"message":e.to_string()}])),
    };
    let has_errors = errors.as_array().is_some_and(|a| !a.is_empty());
    let mut inserted = 0;
    if !has_errors {
        for a in accounts {
            t.execute("INSERT INTO workglen_accounting.feed_accounts(book_id,connection_id,source_key,name,currency,balance,balance_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(book_id,connection_id,source_key) DO UPDATE SET name=excluded.name,currency=excluded.currency,balance=excluded.balance,balance_at=excluded.balance_at",&[&book,&id,&a.key,&a.name,&a.currency,&a.balance,&a.balance_at])?;
            if let Some(r)=t.query_opt("SELECT b.id,b.import_from::text FROM workglen_accounting.feed_accounts f JOIN workglen_accounting.bank_accounts b ON(b.book_id=f.book_id AND b.id=f.bank_id) WHERE f.book_id=$1 AND f.connection_id=$2 AND f.source_key=$3",&[&book,&id,&a.key])?{
   ensure!(a.currency==currency,"Mapped feed account currency changed; reconnect after resolving");let bank:String=r.get(0);let from:String=r.get(1);
   for e in a.entries.into_iter().filter(|e|e.date>=from){inserted+=banking::stage(&mut t,book,&bank,&format!("simplefin:{id}:{}",a.key),&e,true)? as usize;}
  }
        }
    }
    t.execute("UPDATE workglen_accounting.feed_connections SET lease=NULL,errors=$3,last_sync=CASE WHEN $4 THEN last_sync ELSE now() END,cursor_at=CASE WHEN $4 THEN cursor_at ELSE $5 END,next_sync=now()+CASE WHEN $4 OR $5<$6 THEN interval '1 hour' ELSE interval '6 hours' END WHERE book_id=$1 AND id=$2",&[&book,&id,&errors,&has_errors,&end,&now])?;
    audit(
        &mut t,
        Some(book),
        "feed",
        "feed-sync",
        id,
        json!({"new_transactions":inserted,"errors":errors,"start":start,"end":end}),
    )?;
    t.commit()?;
    Ok(json!({"new_transactions":inserted,"errors":errors,"complete":!has_errors}))
}
pub fn start(app: Arc<crate::app::App>) {
    if app.accounting.is_none() {
        return;
    }
    std::thread::spawn(move || {
        loop {
            let _ = crate::resilience::boundary("accounting feed worker", || {
                if app.primary() {
                    let db = app.accounting.as_ref().unwrap();
                    let due = (|| -> Result<Vec<(String, String)>> {
                        let mut c = db.connect()?;
                        let rows=c.query("SELECT f.book_id,f.id FROM workglen_accounting.feed_connections f CROSS JOIN workglen_accounting.installation i WHERE i.enabled AND f.active AND f.next_sync<=now() ORDER BY f.next_sync LIMIT 25",&[])?;
                        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
                    })();
                    if let Ok(due) = due {
                        for (book, id) in due {
                            if !app.primary() {
                                break;
                            }
                            let _ = crate::resilience::boundary("accounting feed sync", || {
                                sync(&app, &book, &id)
                            });
                        }
                    }
                }
                Ok(())
            });
            std::thread::sleep(Duration::from_secs(60));
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restrict_destinations() {
        for s in [
            "http://bridge.simplefin.org/simplefin/claim/x",
            "https://127.0.0.1/simplefin/claim/x",
            "https://bridge.simplefin.org.evil.test/simplefin/claim/x",
            "https://bridge.simplefin.org:444/simplefin/claim/x",
            "https://u:p@bridge.simplefin.org/simplefin/claim/x",
        ] {
            assert!(endpoint(s, true).is_err());
        }
        assert!(endpoint("https://bridge.simplefin.org/simplefin/claim/test", true).is_ok());
    }
    #[test]
    fn encrypted_scoped_tokens() {
        let k = [7u8; 32];
        let c = seal(&k, b"book-a", b"secret").unwrap();
        assert_eq!(unseal(&k, b"book-a", &c).unwrap(), "secret");
        assert!(unseal(&k, b"book-b", &c).is_err());
        let mut bad = c;
        bad[28] ^= 1;
        assert!(unseal(&k, b"book-a", &bad).is_err());
    }
    #[test]
    fn v2_scopes_pending_and_partial_errors() {
        let v = json!({"errlist":[],"accounts":[{"id":"a","conn_id":"login1","name":"Checking","currency":"USD","balance":"40.00","balance-date":1,"transactions":[{"id":"1","posted":1700000000,"amount":"-1.23","description":"Coffee"},{"id":"pending","posted":0,"amount":"1.00","description":"Pending","pending":true}]},{"id":"a","conn_id":"login2","name":"Other checking","currency":"USD","balance":"50.00","balance-date":1}]});
        let (a, e) = parse_payload(&v, 2, "USD").unwrap();
        assert_ne!(a[0].key, a[1].key);
        assert_eq!(a[0].entries.len(), 1);
        assert_eq!(a[0].entries[0].amount, -123);
        assert_eq!(e, json!([]));
        let mut v = v;
        v["errlist"] = json!([{"code":"act.missingdata","msg":"Incomplete feed"}]);
        let (a, e) = parse_payload(&v, 2, "USD").unwrap();
        assert!(a.is_empty());
        assert_eq!(e.as_array().unwrap().len(), 1);
    }
}
