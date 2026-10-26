//! Corrections retain immutable before/after audit history while updating the current books.
use super::*;

pub(super) fn lock_date(
    t: &mut Transaction,
    book: &str,
    action: &str,
    v: &Value,
    old: Option<&str>,
    actor: &str,
) -> Result<Value> {
    let new = match v.get("date") {
        Some(Value::Null) => None,
        Some(Value::String(d)) => {
            date(d)?;
            Some(d.as_str())
        }
        _ => bail!("Provide a date, or null to remove the lock"),
    };
    if action == "reopen-period" {
        ensure!(
            v.get("expected_lock_date").is_some(),
            "Refresh the current lock date before reopening"
        );
        ensure!(
            v["expected_lock_date"] == json!(old),
            "Lock date changed. Refresh before saving."
        );
        text(field(v, "reason")?, 500, "reason")?;
    } else {
        ensure!(
            new.is_some() && old.is_none_or(|d| new.is_some_and(|n| n >= d)),
            "Use Reopen period to move or remove an existing lock"
        );
    }
    t.execute(
        "UPDATE workglen_accounting.books SET lock_date=$2::text::date WHERE id=$1",
        &[&book, &new],
    )?;
    audit(
        t,
        Some(book),
        actor,
        action,
        book,
        json!({"before":{"lock_date":old},"after":{"lock_date":new},"reason":v.get("reason")}),
    )?;
    Ok(json!({"lock_date":new}))
}
pub(super) fn list(t: &mut Transaction, book: &str, v: &Value) -> Result<Value> {
    let o = offset(v)?;
    let deleted = v["include_deleted"].as_bool().unwrap_or(false);
    let rows=t.query("SELECT jsonb_build_object('id',id,'date',entry_date::text,'description',description,'kind',kind,'status',status,'revision',revision) FROM workglen_accounting.journals WHERE book_id=$1 AND ($3 OR status<>'deleted') ORDER BY entry_date DESC,created_at DESC,id LIMIT 200 OFFSET $2", &[&book,&o,&deleted])?;
    Ok(
        json!({"rows":rows.iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>(),"offset":o,"page_size":200}),
    )
}
fn snapshot(t: &mut Transaction, book: &str, id: &str) -> Result<Value> {
    let j=t.query_opt("SELECT to_jsonb(j)-'created_xid'-'updated_xid' FROM workglen_accounting.journals j WHERE book_id=$1 AND id=$2", &[&book,&id])?.ok_or_else(||crate::error!("Journal not found"))?.get::<_,Value>(0);
    let ls=t.query("SELECT jsonb_build_object('account',account_code,'debit',debit,'credit',credit) FROM workglen_accounting.lines WHERE book_id=$1 AND journal_id=$2 ORDER BY line_no", &[&book,&id])?.iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
    let doc=t.query_opt("SELECT to_jsonb(d) FROM workglen_accounting.documents d WHERE book_id=$1 AND journal_id=$2 ORDER BY id LIMIT 1", &[&book,&id])?.map(|r|r.get::<_,Value>(0));
    let pay=t.query_opt("SELECT to_jsonb(p) FROM workglen_accounting.payments p WHERE book_id=$1 AND journal_id=$2", &[&book,&id])?.map(|r|r.get::<_,Value>(0));
    Ok(json!({"journal":j,"lines":ls,"document":doc,"payment":pay,"amount_units":"minor"}))
}
pub(super) fn get(t: &mut Transaction, book: &str, id: &str, scale: i16) -> Result<Value> {
    let mut v = snapshot(t, book, id)?;
    for l in v["lines"].as_array_mut().unwrap() {
        for k in ["debit", "credit"] {
            l[k] = json!(display(l[k].as_i64().unwrap() as i128, scale));
        }
    }
    v["amount_units"] = json!("decimal");
    if let Some(d) = v["document"].as_object_mut() {
        for k in ["original_amount", "opening_due"] {
            d.insert(
                k.into(),
                json!(display(d[k].as_i64().unwrap() as i128, scale)),
            );
        }
    }
    if let Some(p) = v["payment"].as_object_mut() {
        p.insert(
            "amount".into(),
            json!(display(p["amount"].as_i64().unwrap() as i128, scale)),
        );
    }
    v["bank_matches"]=json!(t.query("SELECT id FROM workglen_accounting.bank_transactions WHERE book_id=$1 AND journal_id=$2 ORDER BY id", &[&book,&id])?.iter().map(|r|r.get::<_,String>(0)).collect::<Vec<_>>());
    v["related_reversals"] = json!(related(t, book, id)?);
    v["history"]=json!(t.query("SELECT to_jsonb(a) FROM workglen_accounting.audit a WHERE book_id=$1 AND record_id=$2 ORDER BY id DESC LIMIT 200", &[&book,&id])?.iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>());
    Ok(v)
}
fn related(t: &mut Transaction, book: &str, id: &str) -> Result<Vec<String>> {
    Ok(t.query("SELECT j.id FROM workglen_accounting.reversals r JOIN workglen_accounting.active_journals j ON(j.book_id=r.book_id AND j.id=CASE WHEN r.original_id=$2 THEN r.reversal_id ELSE r.original_id END) WHERE r.book_id=$1 AND (r.original_id=$2 OR r.reversal_id=$2)", &[&book,&id])?.iter().map(|r|r.get(0)).collect())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn change(
    t: &mut Transaction,
    book: &str,
    action: &str,
    v: &Value,
    scale: i16,
    lock: Option<&str>,
    actor: &str,
) -> Result<Value> {
    let id = field(v, "journal_id")?;
    let request = field(v, "request_id")?;
    key(request)?;
    let h = hash(&(action, v))?;
    if let Some(r)=t.query_opt("SELECT journal_id,revision,payload_hash FROM workglen_accounting.journal_changes WHERE book_id=$1 AND request_id=$2", &[&book,&request])? {
        ensure!(r.get::<_,String>(2)==h,"Request ID already used with different content");
        return Ok(json!({"journal_id":r.get::<_,String>(0),"revision":r.get::<_,i64>(1),"replayed":true}));
    }
    let before = snapshot(t, book, id)?;
    let j = &before["journal"];
    let revision = v["expected_revision"]
        .as_i64()
        .ok_or_else(|| crate::error!("expected_revision required"))?;
    ensure!(
        j["revision"].as_i64() == Some(revision),
        "Posting changed. Refresh before saving."
    );
    ensure!(
        j["status"] == "posted" || (j["status"] == "void" && action.starts_with("delete-")),
        "This posting is already void or deleted"
    );
    let kind = field(j, "kind")?;
    let editing = action.starts_with("edit-");
    let source = action.split_once('-').unwrap().1;
    ensure!(
        match source {
            "journal" => matches!(kind, "manual" | "reversal"),
            "document" => matches!(kind, "invoice" | "bill"),
            "payment" => kind == "payment",
            _ => false,
        },
        "Use the originating invoice, bill or payment to correct this posting. Imported opening balances require a cutover adjustment."
    );
    let reason = v
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or(if editing { "Correction" } else { "" });
    text(reason, 500, "reason")?;
    let old_date = field(j, "entry_date")?;
    posting_date(old_date, lock)?;
    let mut d = old_date.to_string();
    let mut description = field(j, "description")?.to_string();
    let mut ls: Vec<Line> = pratique::json_value::from_value(before["lines"].clone())?;
    let mut doc = before["document"].clone();
    let mut pay = before["payment"].clone();
    if editing {
        d = field(v, "date")?.into();
        posting_date(&d, lock)?;
        match source {
            "journal" => {
                description = field(v, "description")?.into();
                text(&description, 500, "description")?;
                ls = lines(
                    &pratique::json_value::from_value::<Vec<InputLine>>(v["lines"].clone())?,
                    scale,
                )?;
                check_accounts(t, book, &ls, true)?;
            }
            "document" => {
                let due = field(v, "due")?;
                date(due)?;
                ensure!(due >= d.as_str(), "Due date cannot precede issue date");
                let number = field(v, "number")?;
                text(number, 100, "document number")?;
                let contact = field(v, "contact_id")?;
                let input = v["lines"]
                    .as_array()
                    .ok_or_else(|| crate::error!("lines required"))?;
                ensure!(
                    (1..=100).contains(&input.len()),
                    "Use 1..100 document lines"
                );
                ls.clear();
                let mut total = 0i64;
                let receivable = kind == "invoice";
                for l in input {
                    let n = money(field(l, "amount")?, scale)?;
                    ensure!(n > 0, "Line amount must be positive");
                    total = total
                        .checked_add(n)
                        .filter(|x| *x <= MAX_AMOUNT)
                        .ok_or_else(|| crate::error!("Total exceeds limit"))?;
                    ls.push(Line {
                        account: field(l, "account")?.into(),
                        debit: if receivable { 0 } else { n },
                        credit: if receivable { n } else { 0 },
                    });
                }
                check_accounts(t, book, &ls, true)?;
                let paid=t.query_one("SELECT coalesce(sum(amount),0)::bigint,min(payment_date)::text FROM workglen_accounting.active_payments WHERE book_id=$1 AND document_id=$2", &[&book,&field(&doc,"id")?])?;
                ensure!(
                    total >= paid.get::<_, i64>(0),
                    "Remove or correct allocated payments before reducing the total below the paid amount"
                );
                ensure!(
                    paid.get::<_, Option<String>>(1)
                        .is_none_or(|first| d <= first),
                    "Issue date cannot follow an allocated payment"
                );
                ls.push(Line {
                    account: field(&doc, "control_account")?.into(),
                    debit: if receivable { total } else { 0 },
                    credit: if receivable { 0 } else { total },
                });
                description = number.into();
                doc["number"] = json!(number);
                doc["contact_id"] = json!(contact);
                doc["issued"] = json!(d);
                doc["due"] = json!(due);
                doc["original_amount"] = json!(total);
                doc["opening_due"] = json!(total);
            }
            "payment" => {
                let amount = money(field(v, "amount")?, scale)?;
                ensure!(amount > 0, "Payment must be positive");
                let bank = field(v, "bank_account")?;
                let document = field(v, "document_id")?;
                let r=t.query_opt("SELECT kind,control_account,issued::text,(opening_due-coalesce((SELECT sum(amount) FROM workglen_accounting.active_payments p WHERE p.book_id=d.book_id AND p.document_id=d.id AND p.journal_id<>$3),0))::bigint FROM workglen_accounting.active_documents d WHERE book_id=$1 AND id=$2", &[&book,&document,&id])?.ok_or_else(||crate::error!("Active document not found"))?;
                ensure!(
                    d >= r.get::<_, String>(2),
                    "Payment cannot predate document"
                );
                ensure!(
                    amount <= r.get::<_, i64>(3),
                    "Payment exceeds outstanding amount"
                );
                ensure!(t.query_opt("SELECT 1 FROM workglen_accounting.accounts WHERE book_id=$1 AND code=$2 AND bank AND control IS NULL", &[&book,&bank])?.is_some(),"Select a bank account");
                let receivable = r.get::<_, String>(0) == "receivable";
                ls = vec![
                    Line {
                        account: bank.into(),
                        debit: if receivable { amount } else { 0 },
                        credit: if receivable { 0 } else { amount },
                    },
                    Line {
                        account: r.get(1),
                        debit: if receivable { 0 } else { amount },
                        credit: if receivable { amount } else { 0 },
                    },
                ];
                description = format!("Payment for {document}");
                pay["document_id"] = json!(document);
                pay["amount"] = json!(amount);
                pay["payment_date"] = json!(d);
            }
            _ => unreachable!(),
        }
    } else if source == "document" {
        ensure!(t.query_opt("SELECT 1 FROM workglen_accounting.active_payments WHERE book_id=$1 AND document_id=$2 LIMIT 1", &[&book,&field(&doc,"id")?])?.is_none(),"Remove or reallocate payments before voiding or deleting this document");
    }
    let related = related(t, book, id)?;
    ensure!(
        related.is_empty() || v["acknowledge_reversal"].as_bool() == Some(true),
        "A related reversal will remain unchanged. Review it and acknowledge before correcting this posting."
    );
    let matches=t.query("SELECT id,posted::text,to_jsonb(b) FROM workglen_accounting.bank_transactions b WHERE book_id=$1 AND journal_id=$2", &[&book,&id])?;
    ensure!(
        matches.is_empty() || v["unmatch"].as_bool() == Some(true),
        "This posting is bank matched. Confirm returning its bank transactions to review, or unmatch them first."
    );
    for r in matches {
        posting_date(&r.get::<_, String>(1), lock)?;
        let bank_id: String = r.get(0);
        t.execute("UPDATE workglen_accounting.bank_transactions SET journal_id=NULL,state='unmatched',note=$3 WHERE book_id=$1 AND id=$2", &[&book,&bank_id,&reason])?;
        audit(
            t,
            Some(book),
            actor,
            "bank-unmatch",
            &bank_id,
            json!({"reason":reason,"before":r.get::<_,Value>(2),"after":{"state":"unmatched","journal_id":null},"correction_request":request}),
        )?;
    }
    let next = revision
        .checked_add(1)
        .ok_or_else(|| crate::error!("Revision limit reached"))?;
    t.execute("INSERT INTO workglen_accounting.journal_changes(book_id,journal_id,revision,request_id,payload_hash,action,actor,reason,before_value,request_value) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", &[&book,&id,&next,&request,&h,&action,&actor,&reason,&before,&v])?;
    let status = if editing {
        "posted"
    } else if action.starts_with("void-") {
        "void"
    } else {
        "deleted"
    };
    t.execute("UPDATE workglen_accounting.journals SET entry_date=$3::text::date,description=$4,status=$5,revision=$6,updated_xid=txid_current() WHERE book_id=$1 AND id=$2", &[&book,&id,&d,&description,&status,&next])?;
    if editing {
        t.execute(
            "DELETE FROM workglen_accounting.lines WHERE book_id=$1 AND journal_id=$2",
            &[&book, &id],
        )?;
        t.execute("INSERT INTO workglen_accounting.lines(book_id,journal_id,line_no,account_code,debit,credit) SELECT $1,$2,(row_number() OVER())::integer,x.account,x.debit,x.credit FROM jsonb_to_recordset($3) AS x(account text,debit bigint,credit bigint)", &[&book,&id,&json!(ls)])?;
        if source == "document" {
            t.execute("UPDATE workglen_accounting.documents SET contact_id=$3,number=$4,issued=$5::text::date,due=$6::text::date,original_amount=$7,opening_due=$7 WHERE book_id=$1 AND journal_id=$2", &[&book,&id,&field(&doc,"contact_id")?,&field(&doc,"number")?,&d,&field(&doc,"due")?,&doc["original_amount"].as_i64().unwrap()])?;
        }
        if source == "payment" {
            t.execute("UPDATE workglen_accounting.payments SET document_id=$3,amount=$4,payment_date=$5::text::date WHERE book_id=$1 AND journal_id=$2", &[&book,&id,&field(&pay,"document_id")?,&pay["amount"].as_i64().unwrap(),&d])?;
        }
    }
    let after = snapshot(t, book, id)?;
    audit(
        t,
        Some(book),
        actor,
        action,
        id,
        json!({"request_id":request,"reason":reason,"before":before,"after":after,"related_reversals":related}),
    )?;
    Ok(json!({"journal_id":id,"revision":next,"status":status}))
}
