//! Optional accounting service. PostgreSQL is the sole source of accounting state.
pub mod bank_files;
pub mod banking;
mod corrections;
pub mod db;
pub mod feeds;
pub mod model;
pub mod xero;
use crate::error::{Result, bail, ensure};
pub use db::{Config, Db};
use lazaret_pg::{IsolationLevel, Transaction};
use model::*;
use pratique::json_value::{Value, json};
pub const MAX_BODY: usize = 4 * 1024 * 1024;

pub fn status(app: &crate::app::App) -> Value {
    match &app.accounting {None=>json!({"configured":false,"ready":false,"enabled":false,"revision":0,"message":"Add [accounting] with a PostgreSQL connection file, then run accounting-init."}),Some(db)=>db.status().unwrap_or_else(|e|json!({"configured":true,"ready":false,"enabled":false,"revision":0,"message":e.to_string()}))}
}
pub fn execute(app: &crate::app::App, c: Command, actor: &str) -> Result<Value> {
    if c.action == "status" {
        return Ok(status(app));
    }
    let db = app
        .accounting
        .as_ref()
        .ok_or_else(|| crate::error!("Configure a BYO PostgreSQL database first"))?;
    if is_write(&c.action) {
        app.require_primary()?;
    }
    if c.action == "feed-connect" || c.action == "feed-sync" {
        let book = c
            .book_id
            .as_deref()
            .ok_or_else(|| crate::error!("book_id required"))?;
        key(book)?;
        return if c.action == "feed-connect" {
            feeds::connect(app, book, &c.data, actor)
        } else {
            feeds::sync(app, book, field(&c.data, "id")?)
        };
    }
    db.run(c, actor)
}
fn is_write(a: &str) -> bool {
    !matches!(
        a,
        "status"
            | "books"
            | "chart"
            | "contacts"
            | "trial-balance"
            | "ledger"
            | "journals"
            | "journal"
            | "documents"
            | "imports"
            | "audit"
            | "bank-accounts"
            | "bank-transactions"
            | "feed-connections"
            | "feed-accounts"
    )
}
fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| crate::error!("Missing text field: {k}"))
}
fn audit(
    t: &mut Transaction,
    book: Option<&str>,
    actor: &str,
    action: &str,
    id: &str,
    details: Value,
) -> Result<()> {
    t.execute("INSERT INTO workglen_accounting.audit(book_id,actor,action,record_id,details) VALUES($1,$2,$3,$4,$5)",&[&book,&actor,&action,&id,&details])?;
    Ok(())
}
fn installation(t: &mut Transaction, workspace: &str, enabled: bool) -> Result<()> {
    let r=t.query_one("SELECT workspace_id,enabled,version FROM workglen_accounting.installation WHERE singleton FOR SHARE",&[])?;
    ensure!(
        r.get::<_, String>(0) == workspace && r.get::<_, i32>(2) == 2,
        "Database workspace or schema mismatch. Run accounting-init with the current binary"
    );
    ensure!(
        !enabled || r.get::<_, bool>(1),
        "Accounting is disabled. Enable it in Modules."
    );
    Ok(())
}
impl Db {
    pub fn set_enabled(&self, enabled: bool, expected: Option<u64>, actor: &str) -> Result<Value> {
        let mut c = self.connect()?;
        let mut t = c.transaction()?;
        let r=t.query_one("SELECT workspace_id,enabled,revision FROM workglen_accounting.installation WHERE singleton FOR UPDATE",&[])?;
        ensure!(
            r.get::<_, String>(0) == self.workspace,
            "Database workspace mismatch"
        );
        let rev: i64 = r.get(2);
        ensure!(
            expected.is_none_or(|x| x == rev as u64),
            "Module settings changed. Refresh and try again."
        );
        if r.get::<_, bool>(1) != enabled {
            t.execute("UPDATE workglen_accounting.installation SET enabled=$1,revision=revision+1 WHERE singleton",&[&enabled])?;
            audit(
                &mut t,
                None,
                actor,
                "module-setting",
                "accounts",
                json!({"enabled":enabled}),
            )?;
        }
        t.commit()?;
        drop(c);
        self.status()
    }
    pub fn run(&self, c: Command, actor: &str) -> Result<Value> {
        text(actor, 200, "actor")?;
        if c.action == "status" {
            return self.status();
        }
        let mut connection = self.connect()?;
        let mut t = connection
            .build_transaction()
            .isolation_level(if is_write(&c.action) {
                IsolationLevel::ReadCommitted
            } else {
                IsolationLevel::RepeatableRead
            })
            .start()?;
        installation(&mut t, &self.workspace, true)?;
        if c.action == "books" {
            let rows=t.query("SELECT id,name,currency,scale,lock_date::text,cutover_date::text FROM workglen_accounting.books ORDER BY id LIMIT 201",&[])?;
            ensure!(rows.len() <= 200, "Book listing limit exceeded");
            let out=rows.iter().map(|r|json!({"id":r.get::<_,String>(0),"name":r.get::<_,String>(1),"currency":r.get::<_,String>(2),"scale":r.get::<_,i16>(3),"lock_date":r.get::<_,Option<String>>(4),"cutover_date":r.get::<_,Option<String>>(5)})).collect::<Vec<_>>();
            t.commit()?;
            return Ok(json!(out));
        }
        if c.action == "create-book" {
            let id = field(&c.data, "id")?;
            key(id)?;
            let name = field(&c.data, "name")?;
            text(name, 200, "book name")?;
            let currency = field(&c.data, "currency")?;
            ensure!(
                currency.len() == 3 && currency.bytes().all(|b| b.is_ascii_uppercase()),
                "Use a three-letter uppercase currency"
            );
            let scale = c.data["scale"]
                .as_i64()
                .filter(|s| (0..=3).contains(s))
                .ok_or_else(|| crate::error!("Set currency scale 0..3"))?
                as i16;
            t.execute(
                "INSERT INTO workglen_accounting.books(id,name,currency,scale) VALUES($1,$2,$3,$4)",
                &[&id, &name, &currency, &scale],
            )?;
            audit(
                &mut t,
                Some(id),
                actor,
                "create-book",
                id,
                json!({"currency":currency,"scale":scale}),
            )?;
            t.commit()?;
            return Ok(json!({"id":id}));
        }
        let book = c
            .book_id
            .as_deref()
            .ok_or_else(|| crate::error!("book_id is required"))?;
        key(book)?;
        let sql = if is_write(&c.action) {
            "SELECT currency,scale,lock_date::text,cutover_date::text FROM workglen_accounting.books WHERE id=$1 FOR UPDATE"
        } else {
            "SELECT currency,scale,lock_date::text,cutover_date::text FROM workglen_accounting.books WHERE id=$1"
        };
        let r = t
            .query_opt(sql, &[&book])?
            .ok_or_else(|| crate::error!("Book not found"))?;
        let currency: String = r.get(0);
        let scale: i16 = r.get(1);
        let lock: Option<String> = r.get(2);
        let out = match c.action.as_str() {
            "chart" => json_rows(
                &mut t,
                "SELECT to_jsonb(a) FROM workglen_accounting.accounts a WHERE book_id=$1 ORDER BY code LIMIT 5001",
                book,
            )?,
            "contacts" => page_rows(
                &mut t,
                "SELECT to_jsonb(a) FROM workglen_accounting.contacts a WHERE book_id=$1 ORDER BY id LIMIT 200 OFFSET $2",
                book,
                &c.data,
            )?,
            "audit" => page_rows(
                &mut t,
                "SELECT to_jsonb(a) FROM workglen_accounting.audit a WHERE book_id=$1 ORDER BY id DESC LIMIT 200 OFFSET $2",
                book,
                &c.data,
            )?,
            "imports" => json_rows(
                &mut t,
                "SELECT jsonb_build_object('id',id,'hash',payload_hash,'summary',summary,'state',state,'created_at',created_at) FROM workglen_accounting.imports WHERE book_id=$1 ORDER BY created_at DESC LIMIT 100",
                book,
            )?,
            "add-account" => {
                let a: Account = pratique::json_value::from_value(c.data)?;
                a.validate()?;
                ensure!(a.source_id.is_none(), "source_id is reserved for imports");
                insert_accounts(&mut t, book, std::slice::from_ref(&a))?;
                audit(&mut t, Some(book), actor, "add-account", &a.code, json!(a))?;
                json!({"code":a.code})
            }
            "add-contact" => {
                let a: Contact = pratique::json_value::from_value(c.data)?;
                validate_contact(&a)?;
                ensure!(a.source_id.is_none(), "source_id is reserved for imports");
                insert_contacts(&mut t, book, std::slice::from_ref(&a))?;
                audit(
                    &mut t,
                    Some(book),
                    actor,
                    "add-contact",
                    &a.id,
                    json!({"name":a.name}),
                )?;
                json!({"id":a.id})
            }
            "lock-date" | "reopen-period" => {
                corrections::lock_date(&mut t, book, &c.action, &c.data, lock.as_deref(), actor)?
            }
            "journals" => corrections::list(&mut t, book, &c.data)?,
            "journal" => corrections::get(&mut t, book, field(&c.data, "journal_id")?, scale)?,
            "edit-journal" | "void-journal" | "delete-journal" | "edit-document"
            | "void-document" | "delete-document" | "edit-payment" | "void-payment"
            | "delete-payment" => corrections::change(
                &mut t,
                book,
                &c.action,
                &c.data,
                scale,
                lock.as_deref(),
                actor,
            )?,
            "post-journal" => {
                let j: Journal = pratique::json_value::from_value(c.data)?;
                key(&j.request_id)?;
                text(&j.description, 500, "description")?;
                let hash = hash(&j)?;
                if let Some(id) = existing(&mut t, book, &j.request_id, &hash)? {
                    json!({"journal_id":id,"replayed":true})
                } else {
                    posting_date(&j.date, lock.as_deref())?;
                    let ls = lines(&j.lines, scale)?;
                    check_accounts(&mut t, book, &ls, true)?;
                    let id = post(
                        &mut t,
                        book,
                        &j.request_id,
                        &hash,
                        &j.date,
                        &j.description,
                        "manual",
                        &ls,
                        actor,
                    )?;
                    json!({"journal_id":id})
                }
            }
            "reverse-journal" => {
                let id = field(&c.data, "journal_id")?;
                let request = field(&c.data, "request_id")?;
                key(request)?;
                let hash = hash(&c.data)?;
                if let Some(id) = existing(&mut t, book, request, &hash)? {
                    json!({"journal_id":id,"replayed":true})
                } else {
                    let d = field(&c.data, "date")?;
                    posting_date(d, lock.as_deref())?;
                    ensure!(t.query_opt("SELECT 1 FROM workglen_accounting.bank_transactions WHERE book_id=$1 AND journal_id=$2",&[&book,&id])?.is_none(),"Unmatch bank transactions before reversing this journal");
                    let old=t.query_one("SELECT kind,entry_date::text FROM workglen_accounting.active_journals WHERE book_id=$1 AND id=$2",&[&book,&id])?;
                    ensure!(
                        old.get::<_, String>(0) == "manual",
                        "Only manual journals can be reversed directly"
                    );
                    ensure!(
                        d >= old.get::<_, String>(1).as_str(),
                        "Reversal cannot predate the original"
                    );
                    let rows=t.query("SELECT account_code,credit,debit FROM workglen_accounting.lines WHERE book_id=$1 AND journal_id=$2 ORDER BY line_no",&[&book,&id])?;
                    let ls = rows
                        .iter()
                        .map(|r| Line {
                            account: r.get(0),
                            debit: r.get(1),
                            credit: r.get(2),
                        })
                        .collect::<Vec<_>>();
                    let reversal = post(
                        &mut t,
                        book,
                        request,
                        &hash,
                        d,
                        &format!("Reversal of {id}"),
                        "reversal",
                        &ls,
                        actor,
                    )?;
                    t.execute("INSERT INTO workglen_accounting.reversals(book_id,original_id,reversal_id) VALUES($1,$2,$3)",&[&book,&id,&reversal])?;
                    audit(
                        &mut t,
                        Some(book),
                        actor,
                        "reverse-journal",
                        id,
                        json!({"request_id":request,"reason":c.data.get("reason"),"before":{"journal_id":id},"after":{"journal_id":id,"reversal_id":reversal,"reversal_date":d}}),
                    )?;
                    json!({"journal_id":reversal})
                }
            }
            "trial-balance" => trial_balance(&mut t, book, &c.data, scale, &currency)?,
            "ledger" => {
                let offset = offset(&c.data)?;
                let rows=t.query("SELECT j.id,j.entry_date::text,j.description,j.kind,l.account_code,l.debit,l.credit FROM workglen_accounting.active_journals j JOIN workglen_accounting.lines l ON (j.book_id=l.book_id AND j.id=l.journal_id) WHERE j.book_id=$1 ORDER BY j.entry_date,j.id,l.line_no LIMIT 200 OFFSET $2",&[&book,&offset])?;
                json!({"rows":rows.iter().map(|r|json!({"journal_id":r.get::<_,String>(0),"date":r.get::<_,String>(1),"description":r.get::<_,String>(2),"kind":r.get::<_,String>(3),"account":r.get::<_,String>(4),"debit":display(r.get::<_,i64>(5) as i128,scale),"credit":display(r.get::<_,i64>(6) as i128,scale)})).collect::<Vec<_>>(),"offset":offset,"page_size":200})
            }
            "documents" => {
                let offset = offset(&c.data)?;
                let rows=t.query("SELECT d.id,d.kind,d.number,c.name,d.due::text,d.original_amount,(d.opening_due-coalesce((SELECT sum(p.amount) FROM workglen_accounting.active_payments p WHERE p.book_id=d.book_id AND p.document_id=d.id),0))::text FROM workglen_accounting.active_documents d JOIN workglen_accounting.contacts c ON(c.book_id=d.book_id AND c.id=d.contact_id) WHERE d.book_id=$1 ORDER BY d.due,d.id LIMIT 200 OFFSET $2",&[&book,&offset])?;
                json!({"rows":rows.iter().map(|r|Ok(json!({"id":r.get::<_,String>(0),"kind":r.get::<_,String>(1),"number":r.get::<_,String>(2),"contact":r.get::<_,String>(3),"due":r.get::<_,String>(4),"total":display(r.get::<_,i64>(5) as i128,scale),"outstanding":display(r.get::<_,String>(6).parse()?,scale)}))).collect::<Result<Vec<_>>>()?,"offset":offset,"page_size":200})
            }
            "create-document" => {
                create_document(&mut t, book, &c.data, scale, lock.as_deref(), actor)?
            }
            "record-payment" => payment(&mut t, book, &c.data, scale, lock.as_deref(), actor)?,
            "xero-preview" => xero::preview(&mut t, book, &currency, scale, c.data, actor)?,
            "xero-commit" => xero::commit(&mut t, book, &c.data, lock.as_deref(), actor)?,
            a if a.starts_with("bank-") || a.starts_with("feed-") => banking::run(
                &mut t,
                book,
                a,
                &c.data,
                &currency,
                scale,
                lock.as_deref(),
                actor,
            )?,
            _ => bail!("Unknown accounting action"),
        };
        t.commit()?;
        Ok(out)
    }
}
fn offset(v: &Value) -> Result<i64> {
    let n = v
        .get("offset")
        .map(|v| v.as_i64().ok_or_else(|| crate::error!("Invalid offset")))
        .transpose()?
        .unwrap_or(0);
    ensure!((0..=10_000_000).contains(&n), "Invalid offset");
    Ok(n)
}
fn json_rows(t: &mut Transaction, sql: &str, book: &str) -> Result<Value> {
    let r = t.query(sql, &[&book])?;
    ensure!(r.len() <= 5000, "Listing too large");
    Ok(json!(
        r.iter().map(|r| r.get::<_, Value>(0)).collect::<Vec<_>>()
    ))
}
fn page_rows(t: &mut Transaction, sql: &str, book: &str, data: &Value) -> Result<Value> {
    let off = offset(data)?;
    let r = t.query(sql, &[&book, &off])?;
    Ok(
        json!({"rows":r.iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>(),"offset":off,"page_size":200}),
    )
}
fn posting_date(d: &str, lock: Option<&str>) -> Result<()> {
    date(d)?;
    ensure!(lock.is_none_or(|l| d > l), "Date is within a locked period");
    Ok(())
}
fn validate_contact(c: &Contact) -> Result<()> {
    key(&c.id)?;
    text(&c.name, 200, "contact name")?;
    ensure!(
        c.email.len() <= 254 && !c.email.chars().any(char::is_control),
        "Invalid contact email"
    );
    Ok(())
}
fn insert_accounts(t: &mut Transaction, book: &str, a: &[Account]) -> Result<()> {
    t.execute("INSERT INTO workglen_accounting.accounts(book_id,code,name,kind,bank,control,source_id) SELECT $1,x.* FROM jsonb_to_recordset($2) AS x(code text,name text,kind text,bank boolean,control text,source_id text)",&[&book,&json!(a)])?;
    Ok(())
}
fn insert_contacts(t: &mut Transaction, book: &str, a: &[Contact]) -> Result<()> {
    t.execute("INSERT INTO workglen_accounting.contacts(book_id,id,name,email,source_id) SELECT $1,x.* FROM jsonb_to_recordset($2) AS x(id text,name text,email text,source_id text)",&[&book,&json!(a)])?;
    Ok(())
}
fn existing(t: &mut Transaction, book: &str, request: &str, hash: &str) -> Result<Option<String>> {
    let r=t.query_opt("SELECT id,payload_hash FROM workglen_accounting.journals WHERE book_id=$1 AND request_id=$2",&[&book,&request])?;
    if let Some(r) = r {
        ensure!(
            r.get::<_, String>(1) == hash,
            "Request ID already used with different content"
        );
        Ok(Some(r.get(0)))
    } else {
        Ok(None)
    }
}
fn check_accounts(t: &mut Transaction, book: &str, ls: &[Line], no_control: bool) -> Result<()> {
    let codes = ls
        .iter()
        .map(|l| l.account.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let r = t.query(
        "SELECT code,control FROM workglen_accounting.accounts WHERE book_id=$1 AND code=ANY($2)",
        &[&book, &codes],
    )?;
    ensure!(r.len() == codes.len(), "Unknown account code");
    ensure!(
        !no_control || r.iter().all(|r| r.get::<_, Option<String>>(1).is_none()),
        "Use invoices, bills and payments for control accounts"
    );
    Ok(())
}
#[allow(clippy::too_many_arguments)] // Explicit posting context stays together at the transaction boundary.
fn post(
    t: &mut Transaction,
    book: &str,
    request: &str,
    hash: &str,
    d: &str,
    description: &str,
    kind: &str,
    ls: &[Line],
    actor: &str,
) -> Result<String> {
    let id = crate::store::random_id();
    t.execute("INSERT INTO workglen_accounting.journals(book_id,id,entry_date,description,kind,request_id,payload_hash,actor) VALUES($1,$2,$3::text::date,$4,$5,$6,$7,$8)",&[&book,&id,&d,&description,&kind,&request,&hash,&actor])?;
    t.execute("INSERT INTO workglen_accounting.lines(book_id,journal_id,line_no,account_code,debit,credit) SELECT $1,$2,(row_number() OVER())::integer,x.account,x.debit,x.credit FROM jsonb_to_recordset($3) AS x(account text,debit bigint,credit bigint)",&[&book,&id,&json!(ls)])?;
    audit(
        t,
        Some(book),
        actor,
        "post-journal",
        &id,
        json!({"kind":kind,"request_id":request,"hash":hash,"before":null,"after":{"journal_id":id,"date":d,"description":description,"kind":kind,"lines":ls,"amount_units":"minor"}}),
    )?;
    Ok(id)
}
fn insert_documents(
    t: &mut Transaction,
    book: &str,
    docs: &[OpenDocument],
    journal: &str,
) -> Result<()> {
    t.execute("INSERT INTO workglen_accounting.documents(book_id,id,kind,contact_id,number,issued,due,control_account,original_amount,opening_due,source_id,journal_id) SELECT $1,x.id,x.kind,x.contact_id,x.number,x.issued::date,x.due::date,x.control_account,x.original_amount,x.opening_due,x.source_id,$3 FROM jsonb_to_recordset($2) AS x(id text,kind text,contact_id text,number text,issued text,due text,control_account text,original_amount bigint,opening_due bigint,source_id text)",&[&book,&json!(docs),&journal])?;
    Ok(())
}
fn trial_balance(
    t: &mut Transaction,
    book: &str,
    v: &Value,
    scale: i16,
    currency: &str,
) -> Result<Value> {
    let d = field(v, "as_of")?;
    date(d)?;
    let rows=t.query("SELECT a.code,a.name,a.kind,coalesce(sum(l.debit),0)::text,coalesce(sum(l.credit),0)::text FROM workglen_accounting.accounts a LEFT JOIN (workglen_accounting.lines l JOIN workglen_accounting.active_journals j ON (l.book_id=j.book_id AND l.journal_id=j.id AND j.entry_date<=$2::text::date)) ON(a.book_id=l.book_id AND a.code=l.account_code) WHERE a.book_id=$1 GROUP BY a.code,a.name,a.kind ORDER BY a.code LIMIT 5001",&[&book,&d])?;
    ensure!(rows.len() <= 5000, "Too many accounts");
    let mut debit = 0i128;
    let mut credit = 0i128;
    let mut net = 0i128;
    let mut out = Vec::new();
    for r in rows {
        let balance =
            r.get::<_, String>(3).parse::<i128>()? - r.get::<_, String>(4).parse::<i128>()?;
        debit += balance.max(0);
        credit += (-balance).max(0);
        let kind: String = r.get(2);
        if kind == "income" || kind == "expense" {
            net -= balance;
        }
        out.push(json!({"code":r.get::<_,String>(0),"name":r.get::<_,String>(1),"kind":kind,"debit":display(balance.max(0),scale),"credit":display((-balance).max(0),scale)}));
    }
    Ok(
        json!({"as_of":d,"currency":currency,"rows":out,"debit":display(debit,scale),"credit":display(credit,scale),"balanced":debit==credit,"net_income_since_opening":display(net,scale)}),
    )
}
fn create_document(
    t: &mut Transaction,
    book: &str,
    v: &Value,
    scale: i16,
    lock: Option<&str>,
    actor: &str,
) -> Result<Value> {
    let request = field(v, "request_id")?;
    key(request)?;
    let hash = hash(v)?;
    if let Some(id) = existing(t, book, request, &hash)? {
        return Ok(json!({"journal_id":id,"document_id":request,"replayed":true}));
    }
    let kind = field(v, "kind")?;
    ensure!(
        ["receivable", "payable"].contains(&kind),
        "kind must be receivable or payable"
    );
    let d = field(v, "date")?;
    posting_date(d, lock)?;
    let due = field(v, "due")?;
    date(due)?;
    ensure!(due >= d, "Due date cannot precede issue date");
    let contact = field(v, "contact_id")?;
    let number = field(v, "number")?;
    text(number, 100, "document number")?;
    let control = t
        .query_opt(
            "SELECT code FROM workglen_accounting.accounts WHERE book_id=$1 AND control=$2",
            &[&book, &kind],
        )?
        .ok_or_else(|| crate::error!("Create a matching control account first"))?
        .get::<_, String>(0);
    let input = v["lines"]
        .as_array()
        .ok_or_else(|| crate::error!("lines required"))?;
    ensure!(
        (1..=100).contains(&input.len()),
        "Use 1..100 document lines"
    );
    let mut total = 0i64;
    let mut ls = Vec::new();
    for l in input {
        let code = field(l, "account")?;
        let n = money(field(l, "amount")?, scale)?;
        ensure!(n > 0, "Line amount must be positive");
        total = total
            .checked_add(n)
            .filter(|n| *n <= MAX_AMOUNT)
            .ok_or_else(|| crate::error!("Total exceeds limit"))?;
        ls.push(Line {
            account: code.into(),
            debit: if kind == "payable" { n } else { 0 },
            credit: if kind == "receivable" { n } else { 0 },
        });
    }
    check_accounts(t, book, &ls, true)?;
    ls.push(Line {
        account: control.clone(),
        debit: if kind == "receivable" { total } else { 0 },
        credit: if kind == "payable" { total } else { 0 },
    });
    let id = post(
        t,
        book,
        request,
        &hash,
        d,
        number,
        if kind == "receivable" {
            "invoice"
        } else {
            "bill"
        },
        &ls,
        actor,
    )?;
    insert_documents(
        t,
        book,
        &[OpenDocument {
            id: request.into(),
            kind: kind.into(),
            contact_id: contact.into(),
            number: number.into(),
            issued: d.into(),
            due: due.into(),
            control_account: control,
            original_amount: total,
            opening_due: total,
            source_id: None,
        }],
        &id,
    )?;
    audit(
        t,
        Some(book),
        actor,
        "create-document",
        &id,
        json!({"before":null,"after":{"document_id":request,"kind":kind,"number":number,"contact_id":contact,"date":d,"due":due,"total":display(total as i128,scale)}}),
    )?;
    Ok(json!({"journal_id":id,"document_id":request}))
}
fn payment(
    t: &mut Transaction,
    book: &str,
    v: &Value,
    scale: i16,
    lock: Option<&str>,
    actor: &str,
) -> Result<Value> {
    let request = field(v, "request_id")?;
    key(request)?;
    let hash = hash(v)?;
    if let Some(id) = existing(t, book, request, &hash)? {
        return Ok(json!({"journal_id":id,"replayed":true}));
    }
    let document = field(v, "document_id")?;
    let bank = field(v, "bank_account")?;
    let d = field(v, "date")?;
    posting_date(d, lock)?;
    let amount = money(field(v, "amount")?, scale)?;
    ensure!(amount > 0, "Payment must be positive");
    let r=t.query_one("SELECT kind,control_account,issued::text,opening_due-coalesce((SELECT sum(amount) FROM workglen_accounting.active_payments p WHERE p.book_id=d.book_id AND p.document_id=d.id),0)::bigint FROM workglen_accounting.active_documents d WHERE book_id=$1 AND id=$2",&[&book,&document])?;
    ensure!(
        d >= r.get::<_, String>(2).as_str(),
        "Payment cannot predate document"
    );
    ensure!(
        amount <= r.get::<_, i64>(3),
        "Payment exceeds outstanding amount"
    );
    ensure!(t.query_opt("SELECT code FROM workglen_accounting.accounts WHERE book_id=$1 AND code=$2 AND bank AND control IS NULL",&[&book,&bank])?.is_some(),"Select a bank account");
    let receivable = r.get::<_, String>(0) == "receivable";
    let control: String = r.get(1);
    let ls = [
        Line {
            account: bank.into(),
            debit: if receivable { amount } else { 0 },
            credit: if receivable { 0 } else { amount },
        },
        Line {
            account: control,
            debit: if receivable { 0 } else { amount },
            credit: if receivable { amount } else { 0 },
        },
    ];
    let id = post(
        t,
        book,
        request,
        &hash,
        d,
        &format!("Payment for {document}"),
        "payment",
        &ls,
        actor,
    )?;
    t.execute("INSERT INTO workglen_accounting.payments(book_id,id,document_id,journal_id,amount,payment_date) VALUES($1,$2,$3,$4,$5,$6::text::date)",&[&book,&request,&document,&id,&amount,&d])?;
    audit(
        t,
        Some(book),
        actor,
        "record-payment",
        &id,
        json!({"before":{"document_id":document,"outstanding":display(r.get::<_,i64>(3) as i128,scale)},"after":{"payment_id":request,"document_id":document,"date":d,"amount":display(amount as i128,scale),"outstanding":display((r.get::<_,i64>(3)-amount) as i128,scale)}}),
    )?;
    Ok(json!({"journal_id":id,"remaining":display((r.get::<_,i64>(3)-amount) as i128,scale)}))
}
