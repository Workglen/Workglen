use super::bank_files::{Entry, Statement};
use super::*;

#[allow(clippy::too_many_arguments)] // Shared transaction/book context for bank commands.
pub fn run(
    t: &mut Transaction,
    book: &str,
    action: &str,
    v: &Value,
    currency: &str,
    scale: i16,
    lock: Option<&str>,
    actor: &str,
) -> Result<Value> {
    match action {
        "bank-accounts" => json_rows(
            t,
            "SELECT jsonb_build_object('id',b.id,'name',b.name,'ledger_account',b.ledger_account,'import_from',b.import_from,'statement_account_id',b.statement_account_id,'unmatched',(SELECT count(*) FROM workglen_accounting.bank_transactions x WHERE x.book_id=b.book_id AND x.bank_id=b.id AND x.state IN ('unmatched','conflict')),'feed_balance',f.balance,'balance_at',f.balance_at,'connection_id',f.connection_id) FROM workglen_accounting.bank_accounts b LEFT JOIN workglen_accounting.feed_accounts f ON(f.book_id=b.book_id AND f.bank_id=b.id) WHERE b.book_id=$1 ORDER BY b.name LIMIT 201",
            book,
        ),
        "feed-connections" => json_rows(
            t,
            "SELECT jsonb_build_object('id',id,'name',name,'provider',provider,'active',active,'last_sync',last_sync,'next_sync',next_sync,'cursor_at',cursor_at,'errors',errors) FROM workglen_accounting.feed_connections WHERE book_id=$1 ORDER BY name LIMIT 201",
            book,
        ),
        "feed-accounts" => json_rows(
            t,
            "SELECT to_jsonb(f) FROM workglen_accounting.feed_accounts f WHERE book_id=$1 ORDER BY name LIMIT 201",
            book,
        ),
        "bank-create" => {
            let id = field(v, "id")?;
            key(id)?;
            let name = field(v, "name")?;
            text(name, 200, "bank name")?;
            let code = field(v, "ledger_account")?;
            let from = field(v, "import_from")?;
            posting_date(from, lock)?;
            ensure!(t.query_opt("SELECT code FROM workglen_accounting.accounts WHERE book_id=$1 AND code=$2 AND bank AND control IS NULL",&[&book,&code])?.is_some(),"Choose a bank/credit-card ledger account without a control role");
            let statement_id = v
                .get("statement_account_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
            if let Some(s) = statement_id {
                text(s, 200, "statement account ID")?;
            }
            t.execute("INSERT INTO workglen_accounting.bank_accounts(book_id,id,name,ledger_account,import_from,statement_account_id) VALUES($1,$2,$3,$4,$5::text::date,$6)",&[&book,&id,&name,&code,&from,&statement_id])?;
            audit(
                t,
                Some(book),
                actor,
                action,
                id,
                json!({"ledger_account":code,"import_from":from}),
            )?;
            Ok(json!({"id":id}))
        }
        "feed-map" => {
            let connection = field(v, "connection_id")?;
            let source = field(v, "source_key")?;
            let bank = field(v, "bank_id")?;
            let a=t.query_one("SELECT currency,bank_id FROM workglen_accounting.feed_accounts WHERE book_id=$1 AND connection_id=$2 AND source_key=$3",&[&book,&connection,&source])?;
            ensure!(
                a.get::<_, String>(0) == currency,
                "Feed currency does not match book currency"
            );
            ensure!(
                a.get::<_, Option<String>>(1).is_none_or(|b| b == bank),
                "A mapped feed cannot be reassigned to a different bank account"
            );
            if a.get::<_, Option<String>>(1).as_deref() == Some(bank) {
                return Ok(json!({"mapped":true,"replayed":true}));
            }
            ensure!(t.query_opt("SELECT 1 FROM workglen_accounting.feed_accounts f JOIN workglen_accounting.feed_connections c ON(c.book_id=f.book_id AND c.id=f.connection_id) WHERE f.book_id=$1 AND f.bank_id=$2 AND c.active",&[&book,&bank])?.is_none(),"Disconnect the old feed before replacing its bank mapping");
            t.execute("UPDATE workglen_accounting.feed_accounts SET bank_id=NULL WHERE book_id=$1 AND bank_id=$2",&[&book,&bank])?;
            let start:String=t.query_one("SELECT import_from::text FROM workglen_accounting.bank_accounts WHERE book_id=$1 AND id=$2",&[&book,&bank])?.get(0);
            let start = date(&start)?
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .timestamp();
            t.execute("UPDATE workglen_accounting.feed_accounts SET bank_id=$4 WHERE book_id=$1 AND connection_id=$2 AND source_key=$3",&[&book,&connection,&source,&bank])?;
            t.execute("UPDATE workglen_accounting.feed_connections SET cursor_at=least(coalesce(cursor_at,$3),$3),lease=NULL WHERE book_id=$1 AND id=$2",&[&book,&connection,&start])?;
            audit(
                t,
                Some(book),
                actor,
                action,
                bank,
                json!({"connection_id":connection,"source_key":source}),
            )?;
            Ok(json!({"mapped":true}))
        }
        "feed-disconnect" => {
            let id = field(v, "id")?;
            ensure!(t.execute("UPDATE workglen_accounting.feed_connections SET active=false,secret=NULL,lease=NULL WHERE book_id=$1 AND id=$2",&[&book,&id])?==1,"Connection not found");
            audit(t, Some(book), actor, action, id, json!({}))?;
            Ok(
                json!({"disconnected":true,"message":"Local polling stopped. Revoke this app in SimpleFIN too. Existing transactions are retained."}),
            )
        }
        "bank-preview" => {
            let bank = field(v, "bank_id")?;
            let format = field(v, "format")?;
            let content = field(v, "content")?;
            let s = bank_files::parse(format, content, scale)?;
            let b=t.query_one("SELECT import_from::text,statement_account_id FROM workglen_accounting.bank_accounts WHERE book_id=$1 AND id=$2",&[&book,&bank])?;
            if let Some(c) = &s.currency {
                ensure!(c == currency, "Statement currency differs from book");
            }
            if let Some(id) = &s.account_id {
                ensure!(
                    b.get::<_, Option<String>>(1).as_ref() == Some(id),
                    "Statement account ID does not match. Set the bank account's exact statement_account_id when creating it."
                );
            }
            let from: String = b.get(0);
            ensure!(
                s.entries.iter().all(|e| e.date >= from),
                "Statement includes transactions before this bank account's import-from date"
            );
            let h = hash(&s)?;
            let id = crate::store::random_id();
            t.execute("INSERT INTO workglen_accounting.bank_imports(book_id,id,bank_id,payload_hash,plan) VALUES($1,$2,$3,$4,$5) ON CONFLICT(book_id,bank_id,payload_hash) DO NOTHING",&[&book,&id,&bank,&h,&json!(s)])?;
            let r=t.query_one("SELECT id,state FROM workglen_accounting.bank_imports WHERE book_id=$1 AND bank_id=$2 AND payload_hash=$3",&[&book,&bank,&h])?;
            let preview=s.entries.iter().take(50).map(|e|json!({"date":e.date,"amount":display(e.amount as i128,scale),"description":e.description})).collect::<Vec<_>>();
            Ok(
                json!({"id":r.get::<_,String>(0),"hash":h,"state":r.get::<_,String>(1),"bank_id":bank,"count":s.entries.len(),"warnings":s.warnings,"preview":preview,"message":"Commit adds to bank review only; no ledger entries are posted."}),
            )
        }
        "bank-commit" => {
            let id = field(v, "id")?;
            let expected = field(v, "hash")?;
            let r=t.query_one("SELECT bank_id,payload_hash,plan,state FROM workglen_accounting.bank_imports WHERE book_id=$1 AND id=$2 FOR UPDATE",&[&book,&id])?;
            ensure!(
                r.get::<_, String>(1) == expected,
                "Statement preview changed; review again"
            );
            if r.get::<_, String>(3) == "committed" {
                return Ok(json!({"replayed":true,"id":id}));
            }
            let s: Statement = pratique::json_value::from_value(r.get(2))?;
            ensure!(
                hash(&s)? == expected,
                "Statement preview integrity check failed"
            );
            let bank: String = r.get(0);
            let mut count = 0;
            for e in &s.entries {
                count += stage(t, book, &bank, &s.source, e, false)? as usize;
            }
            t.execute("UPDATE workglen_accounting.bank_imports SET state='committed' WHERE book_id=$1 AND id=$2",&[&book,&id])?;
            audit(
                t,
                Some(book),
                actor,
                action,
                id,
                json!({"hash":expected,"new_transactions":count}),
            )?;
            Ok(json!({"id":id,"new_transactions":count}))
        }
        "bank-transactions" => {
            let bank = field(v, "bank_id")?;
            let off = offset(v)?;
            let rows=t.query("SELECT x.id,x.posted::text,x.amount,x.description,x.state,x.journal_id,x.note,x.source,EXISTS(SELECT 1 FROM workglen_accounting.bank_transactions d WHERE d.book_id=x.book_id AND d.bank_id=x.bank_id AND d.id<>x.id AND d.posted=x.posted AND d.amount=x.amount) FROM workglen_accounting.bank_transactions x WHERE book_id=$1 AND bank_id=$2 ORDER BY posted DESC,id LIMIT 200 OFFSET $3",&[&book,&bank,&off])?;
            Ok(
                json!({"rows":rows.iter().map(|r|json!({"id":r.get::<_,String>(0),"date":r.get::<_,String>(1),"amount":display(r.get::<_,i64>(2) as i128,scale),"description":r.get::<_,String>(3),"state":r.get::<_,String>(4),"journal_id":r.get::<_,Option<String>>(5),"note":r.get::<_,String>(6),"source":r.get::<_,String>(7),"possible_duplicate":r.get::<_,bool>(8)})).collect::<Vec<_>>(),"offset":off,"page_size":200}),
            )
        }
        "bank-match" | "bank-post" | "bank-payment" | "bank-exclude" | "bank-unmatch" => {
            reconcile(t, book, action, v, scale, lock, actor)
        }
        _ => bail!("Unknown banking action"),
    }
}

pub fn stage(
    t: &mut Transaction,
    book: &str,
    bank: &str,
    source: &str,
    e: &Entry,
    feed: bool,
) -> Result<bool> {
    if let Some(r)=t.query_opt("SELECT id,posted::text,amount,description,state FROM workglen_accounting.bank_transactions WHERE book_id=$1 AND bank_id=$2 AND source=$3 AND source_id=$4",&[&book,&bank,&source,&e.id])?{
  let changed=r.get::<_,String>(1)!=e.date||r.get::<_,i64>(2)!=e.amount||r.get::<_,String>(3)!=e.description;
  if changed {
   ensure!(feed,"Statement reuses an existing transaction ID with different data; resolve manually");let id:String=r.get(0);let state:String=r.get(4);
   t.execute("UPDATE workglen_accounting.bank_transactions SET posted=$3::text::date,amount=$4,description=$5,state=CASE WHEN state IN ('matched','excluded') THEN 'conflict' ELSE state END,note='Provider changed this transaction; review against the bank statement.' WHERE book_id=$1 AND id=$2",&[&book,&id,&e.date,&e.amount,&e.description])?;
   audit(t,Some(book),"feed","transaction-correction",&id,json!({"previous_date":r.get::<_,String>(1),"previous_amount":r.get::<_,i64>(2),"previous_description":r.get::<_,String>(3),"previous_state":state}))?;
  }
  return Ok(false);
 }
    let id = crate::store::random_id();
    t.execute("INSERT INTO workglen_accounting.bank_transactions(book_id,bank_id,id,source,source_id,posted,amount,description) VALUES($1,$2,$3,$4,$5,$6::text::date,$7,$8)",&[&book,&bank,&id,&source,&e.id,&e.date,&e.amount,&e.description])?;
    Ok(true)
}
fn reconcile(
    t: &mut Transaction,
    book: &str,
    action: &str,
    v: &Value,
    scale: i16,
    lock: Option<&str>,
    actor: &str,
) -> Result<Value> {
    let id = field(v, "id")?;
    let r=t.query_one("SELECT x.bank_id,x.posted::text,x.amount,x.description,x.state,x.journal_id,b.ledger_account,x.posting_generation FROM workglen_accounting.bank_transactions x JOIN workglen_accounting.bank_accounts b ON(b.book_id=x.book_id AND b.id=x.bank_id) WHERE x.book_id=$1 AND x.id=$2 FOR UPDATE OF x",&[&book,&id])?;
    let d: String = r.get(1);
    let amount: i64 = r.get(2);
    let state: String = r.get(4);
    let bank: String = r.get(6);
    let old: Option<String> = r.get(5);
    let mut generation: i64 = r.get(7);
    let mut request = if generation == 0 {
        format!("bank:{id}")
    } else {
        format!("bank:{id}:{generation}")
    };
    if state=="unmatched" && matches!(action,"bank-post"|"bank-payment") && t.query_opt("SELECT 1 FROM workglen_accounting.journals WHERE book_id=$1 AND request_id=$2 AND status<>'posted'", &[&book,&request])?.is_some() {
        generation=generation.checked_add(1).ok_or_else(||crate::error!("Posting generation exhausted"))?;
        request=format!("bank:{id}:{generation}");
        t.execute("UPDATE workglen_accounting.bank_transactions SET posting_generation=$3 WHERE book_id=$1 AND id=$2", &[&book,&id,&generation])?;
    }
    if action == "bank-unmatch" {
        posting_date(&d, lock)?;
        let note = field(v, "note")?;
        text(note, 500, "reason")?;
        ensure!(
            state == "matched" || state == "conflict" || state == "excluded",
            "Transaction is already unmatched"
        );
        t.execute("UPDATE workglen_accounting.bank_transactions SET state='unmatched',journal_id=NULL,note=$3 WHERE book_id=$1 AND id=$2",&[&book,&id,&note])?;
        audit(
            t,
            Some(book),
            actor,
            action,
            id,
            json!({"reason":note,"previous_journal":old}),
        )?;
        return Ok(
            json!({"state":"unmatched","message":"Ledger entries are unchanged; correct them before matching again."}),
        );
    }
    if state == "matched" {
        let expected = match action {
            "bank-match" => Some(field(v, "journal_id")?.to_string()),
            "bank-post" => existing(
                t,
                book,
                &request,
                &hash(&(id, &d, amount, field(v, "account")?))?,
            )?,
            "bank-payment" => existing(
                t,
                book,
                &request,
                &hash(
                    &json!({"request_id":request,"document_id":field(v,"document_id")?,"bank_account":bank,"date":d,"amount":display(amount.abs() as i128,scale)}),
                )?,
            )?,
            _ => bail!("Unmatch before changing or excluding this transaction"),
        };
        ensure!(
            expected.is_some() && expected == old,
            "Transaction is already matched differently; unmatch before changing it"
        );
        return Ok(json!({"state":state,"journal_id":old,"replayed":true}));
    }
    ensure!(
        state == "unmatched",
        "Unmatch or resolve the conflict first"
    );
    if action == "bank-exclude" {
        let note = field(v, "note")?;
        text(note, 500, "reason")?;
        t.execute("UPDATE workglen_accounting.bank_transactions SET state='excluded',note=$3 WHERE book_id=$1 AND id=$2",&[&book,&id,&note])?;
        audit(t, Some(book), actor, action, id, json!({"reason":note}))?;
        return Ok(json!({"state":"excluded"}));
    }
    let journal = if action == "bank-match" {
        field(v, "journal_id")?.to_string()
    } else if action == "bank-payment" {
        let document = field(v, "document_id")?;
        let kind: String = t
            .query_one(
                "SELECT kind FROM workglen_accounting.active_documents WHERE book_id=$1 AND id=$2",
                &[&book, &document],
            )?
            .get(0);
        ensure!(
            (kind == "receivable" && amount > 0) || (kind == "payable" && amount < 0),
            "Transaction direction does not match document"
        );
        let p = payment(
            t,
            book,
            &json!({"request_id":request,"document_id":document,"bank_account":bank,"date":d,"amount":display(amount.abs() as i128,scale)}),
            scale,
            lock,
            actor,
        )?;
        field(&p, "journal_id")?.to_string()
    } else {
        posting_date(&d, lock)?;
        let contra = field(v, "account")?;
        ensure!(contra != bank, "Choose a different counter-account");
        let ls = vec![
            Line {
                account: bank.clone(),
                debit: amount.max(0),
                credit: (-amount).max(0),
            },
            Line {
                account: contra.into(),
                debit: (-amount).max(0),
                credit: amount.max(0),
            },
        ];
        check_accounts(t, book, &ls, true)?;
        let h = hash(&(id, &d, amount, contra))?;
        if let Some(j) = existing(t, book, &request, &h)? {
            j
        } else {
            post(
                t,
                book,
                &request,
                &h,
                &d,
                &r.get::<_, String>(3),
                "manual",
                &ls,
                actor,
            )?
        }
    };
    ensure!(
        t.query_opt(
            "SELECT 1 FROM workglen_accounting.active_journals WHERE book_id=$1 AND id=$2",
            &[&book, &journal]
        )?
        .is_some(),
        "Posting is void or deleted. Create a replacement and match it."
    );
    let total=t.query_one("SELECT coalesce(sum(debit-credit),0)::text FROM workglen_accounting.lines WHERE book_id=$1 AND journal_id=$2 AND account_code=$3",&[&book,&journal,&bank])?.get::<_,String>(0).parse::<i128>()?;
    ensure!(
        total == amount as i128,
        "Journal amount on this bank account must exactly equal the statement transaction"
    );
    ensure!(t.query_opt("SELECT 1 FROM workglen_accounting.reversals r JOIN workglen_accounting.active_journals a ON(a.book_id=r.book_id AND a.id=r.original_id) JOIN workglen_accounting.active_journals b ON(b.book_id=r.book_id AND b.id=r.reversal_id) WHERE r.book_id=$1 AND (r.original_id=$2 OR r.reversal_id=$2)",&[&book,&journal])?.is_none(),"Cannot match a reversed journal or its reversal");
    t.execute("UPDATE workglen_accounting.bank_transactions SET state='matched',journal_id=$3,note='' WHERE book_id=$1 AND id=$2",&[&book,&id,&journal])?;
    audit(
        t,
        Some(book),
        actor,
        action,
        id,
        json!({"journal_id":journal}),
    )?;
    Ok(json!({"state":"matched","journal_id":journal}))
}
