//! Xero cutover: import reconciled balances once; open documents are subledger only.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
pub struct Bundle {
    pub source_org: String,
    pub as_of: String,
    pub currency: String,
    pub receivable_account: String,
    pub payable_account: String,
    pub trial_balance_csv: String,
    pub accounts: Vec<Value>,
    pub contacts: Vec<Value>,
    pub invoices: Vec<Value>,
    pub credit_notes: Vec<Value>,
    pub prepayments: Vec<Value>,
    pub overpayments: Vec<Value>,
    pub source_frozen: bool,
}
pratique::data_encode!(Bundle {
    source_org,
    as_of,
    currency,
    receivable_account,
    payable_account,
    trial_balance_csv,
    accounts,
    contacts,
    invoices,
    credit_notes,
    prepayments,
    overpayments,
    source_frozen
});
pratique::data_decode!(Bundle, deny_unknown=true, { source_org, as_of, currency, receivable_account, payable_account, trial_balance_csv, accounts, contacts, invoices, credit_notes, prepayments, overpayments, source_frozen });

#[derive(Debug)]
struct Plan {
    source_org: String,
    as_of: String,
    accounts: Vec<Account>,
    contacts: Vec<Contact>,
    lines: Vec<Line>,
    documents: Vec<OpenDocument>,
    summary: Value,
}
pratique::data_encode!(Plan {
    source_org,
    as_of,
    accounts,
    contacts,
    lines,
    documents,
    summary
});
pratique::data_decode!(Plan, deny_unknown=false, { source_org, as_of, accounts, contacts, lines, documents, summary });

fn amount(v: &Value, scale: i16) -> Result<i64> {
    let s = if let Some(s) = v.as_str() {
        s.to_string()
    } else if v.is_number() {
        v.to_string()
    } else {
        bail!("Missing Xero monetary amount")
    };
    money(&s, scale)
}
fn source_date(v: &Value, key: &str) -> Result<String> {
    if let Some(s) = v.get(format!("{key}String")).and_then(Value::as_str) {
        let d = s
            .get(..10)
            .ok_or_else(|| crate::error!("Invalid Xero date"))?;
        date(d)?;
        return Ok(d.into());
    }
    let s = field(v, key)?;
    if s.starts_with("/Date(") {
        let raw = s.trim_start_matches("/Date(");
        let stop = raw
            .char_indices()
            .skip(1)
            .find(|(_, c)| !c.is_ascii_digit())
            .map(|(i, _)| i)
            .unwrap_or(raw.len());
        let millis: i64 = raw[..stop].parse()?;
        let d = crate::datetime::DateTime::from_timestamp_millis(millis)
            .ok_or_else(|| crate::error!("Invalid Xero date"))?;
        Ok(d.format("%Y-%m-%d").to_string())
    } else {
        let d = s
            .get(..10)
            .ok_or_else(|| crate::error!("Invalid Xero date"))?;
        date(d)?;
        Ok(d.into())
    }
}
fn empty(t: &mut Transaction, book: &str) -> Result<()> {
    let r=t.query_one("SELECT (SELECT count(*) FROM workglen_accounting.accounts WHERE book_id=$1)+(SELECT count(*) FROM workglen_accounting.contacts WHERE book_id=$1)+(SELECT count(*) FROM workglen_accounting.journals WHERE book_id=$1)",&[&book])?;
    ensure!(
        r.get::<_, i64>(0) == 0,
        "Xero cutover requires an empty book. Create a new book; do not delete a posted ledger."
    );
    Ok(())
}
fn plan(b: Bundle, currency: &str, scale: i16) -> Result<Plan> {
    text(&b.source_org, 200, "source organization")?;
    date(&b.as_of)?;
    ensure!(
        b.source_frozen,
        "Freeze source changes and confirm source_frozen before preparing a cutover"
    );
    ensure!(
        b.currency == currency,
        "Source and destination base currencies differ"
    );
    ensure!(
        b.accounts.len() <= 5000 && b.contacts.len() <= 10000 && b.invoices.len() <= 10000,
        "Import exceeds small-book limits"
    );
    ensure!(
        b.receivable_account != b.payable_account,
        "Receivable and payable accounts must differ"
    );
    for (name, entries) in [
        ("credit notes", &b.credit_notes),
        ("prepayments", &b.prepayments),
        ("overpayments", &b.overpayments),
    ] {
        for v in entries {
            let status = field(v, "Status")?;
            if status == "VOIDED" || status == "DELETED" {
                continue;
            }
            let remaining = v
                .get("RemainingCredit")
                .ok_or_else(|| crate::error!("Missing RemainingCredit on {name}"))?;
            ensure!(
                amount(remaining, scale)? == 0,
                "Unallocated {name} need settlement in Xero before this cutover format can be used"
            );
        }
    }
    let mut accounts = Vec::new();
    let mut codes = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for v in b.accounts {
        let code = field(&v, "Code")?.to_string();
        let id = field(&v, "AccountID")?.to_string();
        key(&id)?;
        ensure!(ids.insert(id.clone()), "Duplicate Xero account ID");
        let typ = field(&v, "Type")?;
        let kind = match typ {
            "BANK"
                if v["Class"].as_str() == Some("LIABILITY")
                    || v["BankAccountType"].as_str() == Some("CREDITCARD") =>
            {
                "liability"
            }
            "BANK" | "CURRENT" | "FIXED" | "INVENTORY" | "NONCURRENT" | "PREPAYMENT" => "asset",
            "CURRLIAB" | "LIABILITY" | "TERMLIAB" => "liability",
            "EQUITY" => "equity",
            "REVENUE" | "SALES" | "OTHERINCOME" => "income",
            "DIRECTCOSTS" | "EXPENSE" | "OVERHEADS" | "DEPRECIATN" => "expense",
            _ => bail!("Unsupported Xero account type: {typ}"),
        };
        ensure!(
            typ != "BANK"
                || v.get("CurrencyCode")
                    .and_then(Value::as_str)
                    .is_none_or(|c| c == currency),
            "Foreign-currency bank accounts require an FX migration path"
        );
        let control = if code == b.receivable_account {
            Some("receivable".into())
        } else if code == b.payable_account {
            Some("payable".into())
        } else {
            None
        };
        let a = Account {
            code: code.clone(),
            name: field(&v, "Name")?.into(),
            kind: kind.into(),
            bank: typ == "BANK",
            control,
            source_id: Some(id),
        };
        a.validate()?;
        ensure!(
            codes.insert(code, kind.to_string()).is_none(),
            "Duplicate account code"
        );
        accounts.push(a);
    }
    ensure!(
        codes
            .get(&b.receivable_account)
            .is_some_and(|v| v == "asset")
            && codes
                .get(&b.payable_account)
                .is_some_and(|v| v == "liability"),
        "Set valid receivable asset and payable liability control accounts"
    );
    let mut contacts = Vec::new();
    let mut contact_ids = BTreeSet::new();
    for v in b.contacts {
        let id = field(&v, "ContactID")?.to_string();
        let c = Contact {
            id: id.clone(),
            name: field(&v, "Name")?.into(),
            email: v["EmailAddress"].as_str().unwrap_or("").into(),
            source_id: Some(id.clone()),
        };
        validate_contact(&c)?;
        ensure!(contact_ids.insert(id), "Duplicate contact ID");
        contacts.push(c);
    }
    let reader = crate::csv_reader::Reader::new(&b.trial_balance_csv, 8 * 1024 * 1024, 5000)?;
    ensure!(
        reader.headers() == ["AccountCode", "Debit", "Credit"],
        "Trial balance columns must be AccountCode,Debit,Credit"
    );
    let mut input = Vec::new();
    let mut seen = BTreeSet::new();
    let mut ar = 0i128;
    let mut ap = 0i128;
    for row in reader {
        let row = row?;
        let account_code = &row[0];
        let debit_text = &row[1];
        let credit_text = &row[2];
        ensure!(
            codes.contains_key(account_code),
            "Trial balance contains unknown account {}",
            account_code
        );
        ensure!(
            seen.insert(account_code.clone()),
            "Duplicate trial balance account"
        );
        let debit = money(debit_text, scale)?;
        let credit = money(credit_text, scale)?;
        ensure!(
            debit == 0 || credit == 0,
            "Use net closing balances, not turnover columns"
        );
        if account_code == &b.receivable_account {
            ar = debit as i128 - credit as i128;
        }
        if account_code == &b.payable_account {
            ap = credit as i128 - debit as i128;
        }
        if debit > 0 || credit > 0 {
            input.push(InputLine {
                account: account_code.clone(),
                debit: debit_text.clone(),
                credit: credit_text.clone(),
            });
        }
    }
    let ls = lines(&input, scale)?;
    let mut documents = Vec::new();
    let mut doc_ids = BTreeSet::new();
    let mut doc_numbers = BTreeSet::new();
    let mut ar_due = 0i128;
    let mut ap_due = 0i128;
    for v in b.invoices {
        let status = field(&v, "Status")?;
        if ["DELETED", "VOIDED", "DRAFT", "SUBMITTED"].contains(&status) {
            continue;
        }
        let due_amount = amount(&v["AmountDue"], scale)?;
        if due_amount == 0 {
            continue;
        }
        ensure!(
            status == "AUTHORISED",
            "Unexpected invoice status with outstanding balance"
        );
        ensure!(
            field(&v, "CurrencyCode")? == currency,
            "Foreign-currency open documents require an FX migration path; this release refuses them"
        );
        let kind = match field(&v, "Type")? {
            "ACCREC" => "receivable",
            "ACCPAY" => "payable",
            _ => bail!("Unsupported invoice type"),
        };
        let id = field(&v, "InvoiceID")?.to_string();
        key(&id)?;
        ensure!(doc_ids.insert(id.clone()), "Duplicate invoice ID");
        let contact = field(&v["Contact"], "ContactID")?.to_string();
        ensure!(contact_ids.contains(&contact), "Invoice contact missing");
        let number = field(&v, "InvoiceNumber")?.to_string();
        text(&number, 100, "invoice number")?;
        ensure!(
            doc_numbers.insert((
                kind.to_string(),
                if kind == "receivable" {
                    String::new()
                } else {
                    contact.clone()
                },
                number.clone()
            )),
            "Duplicate document number"
        );
        let issued = source_date(&v, "Date")?;
        let due = source_date(&v, "DueDate")?;
        ensure!(issued <= b.as_of, "Invoice issued after cutover");
        ensure!(due >= issued, "Invoice due date precedes issue date");
        let total = amount(&v["Total"], scale)?;
        ensure!(
            due_amount <= total && total > 0,
            "Outstanding exceeds document total"
        );
        if kind == "receivable" {
            ar_due += due_amount as i128;
        } else {
            ap_due += due_amount as i128;
        }
        documents.push(OpenDocument {
            id: id.clone(),
            kind: kind.into(),
            contact_id: contact,
            number,
            issued,
            due,
            control_account: if kind == "receivable" {
                b.receivable_account.clone()
            } else {
                b.payable_account.clone()
            },
            original_amount: total,
            opening_due: due_amount,
            source_id: Some(id),
        });
    }
    ensure!(
        ar == ar_due,
        "Receivables mismatch: trial balance {}, open invoices {}",
        display(ar, scale),
        display(ar_due, scale)
    );
    ensure!(
        ap == ap_due,
        "Payables mismatch: trial balance {}, open bills {}",
        display(ap, scale),
        display(ap_due, scale)
    );
    let total = ls.iter().map(|l| l.debit as i128).sum::<i128>();
    let summary = json!({"source_org":b.source_org,"as_of":b.as_of,"currency":currency,"accounts":accounts.len(),"contacts":contacts.len(),"open_documents":documents.len(),"opening_debits":display(total,scale),"opening_credits":display(total,scale),"receivables":display(ar,scale),"payables":display(ap,scale),"warnings":["Cutover only: archive source history and statutory reports separately.","No tax returns, payroll, attachments, bank-feed credentials or historical payment records are migrated.","Open documents reference the opening journal and do not post a second receivable/payable balance."]});
    Ok(Plan {
        source_org: b.source_org,
        as_of: b.as_of,
        accounts,
        contacts,
        lines: ls,
        documents,
        summary,
    })
}
pub fn preview(
    t: &mut Transaction,
    book: &str,
    currency: &str,
    scale: i16,
    v: Value,
    actor: &str,
) -> Result<Value> {
    let b: Bundle = pratique::json_value::from_value(v)?;
    let p = plan(b, currency, scale)?;
    let hash = hash(&p)?;
    if let Some(r)=t.query_opt("SELECT id,state,summary FROM workglen_accounting.imports WHERE book_id=$1 AND payload_hash=$2",&[&book,&hash])?{return Ok(json!({"id":r.get::<_,String>(0),"hash":hash,"state":r.get::<_,String>(1),"summary":r.get::<_,Value>(2)}));}
    empty(t, book)?;
    let id = crate::store::random_id();
    t.execute("INSERT INTO workglen_accounting.imports(book_id,id,payload_hash,source_org,as_of,plan,summary,state) VALUES($1,$2,$3,$4,$5::text::date,$6,$7,'preview')",&[&book,&id,&hash,&p.source_org,&p.as_of,&json!(p),&p.summary])?;
    audit(
        t,
        Some(book),
        actor,
        "xero-preview",
        &id,
        json!({"hash":hash}),
    )?;
    Ok(json!({"id":id,"hash":hash,"state":"preview","summary":p.summary}))
}
pub fn commit(
    t: &mut Transaction,
    book: &str,
    v: &Value,
    lock: Option<&str>,
    actor: &str,
) -> Result<Value> {
    let id = field(v, "id")?;
    let expected = field(v, "hash")?;
    let r=t.query_one("SELECT payload_hash,state,plan,journal_id FROM workglen_accounting.imports WHERE book_id=$1 AND id=$2 FOR UPDATE",&[&book,&id])?;
    ensure!(
        r.get::<_, String>(0) == expected,
        "Preview hash differs; review again"
    );
    if r.get::<_, String>(1) == "committed" {
        return Ok(json!({"id":id,"journal_id":r.get::<_,String>(3),"replayed":true}));
    }
    empty(t, book)?;
    let p: Plan = pratique::json_value::from_value(r.get(2))?;
    ensure!(
        hash(&p)? == expected,
        "Stored preview integrity check failed"
    );
    posting_date(&p.as_of, lock)?;
    insert_accounts(t, book, &p.accounts)?;
    insert_contacts(t, book, &p.contacts)?;
    let journal = post(
        t,
        book,
        &format!("xero:{id}"),
        expected,
        &p.as_of,
        "Xero cutover opening balances",
        "opening",
        &p.lines,
        actor,
    )?;
    insert_documents(t, book, &p.documents, &journal)?;
    t.execute("UPDATE workglen_accounting.books SET cutover_date=$2::text::date,lock_date=$2::text::date WHERE id=$1",&[&book,&p.as_of])?;
    t.execute("UPDATE workglen_accounting.imports SET state='committed',journal_id=$3 WHERE book_id=$1 AND id=$2",&[&book,&id,&journal])?;
    audit(
        t,
        Some(book),
        actor,
        "xero-commit",
        id,
        json!({"hash":expected,"journal_id":journal}),
    )?;
    Ok(json!({"id":id,"journal_id":journal,"summary":p.summary}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_money() {
        assert_eq!(money("123.45", 2).unwrap(), 12345);
        for s in ["1.001", "-1.00", "1e2", "1,000", "NaN", "1."] {
            assert!(money(s, 2).is_err());
        }
        assert_eq!(display(-12345, 2), "-123.45");
    }
    #[test]
    fn fixture_reconciles() {
        let b: Bundle = pratique::json_value::from_str(include_str!(
            "../../examples/accounting/xero-cutover.json"
        ))
        .unwrap();
        let p = plan(b, "USD", 2).unwrap();
        assert_eq!(p.documents.len(), 2);
        assert_eq!(p.summary["receivables"], "120.00");
    }
    #[test]
    fn credit_card_and_foreign_bank_migration() {
        let mut b: Bundle = pratique::json_value::from_str(include_str!(
            "../../examples/accounting/xero-cutover.json"
        ))
        .unwrap();
        b.accounts.push(json!({"AccountID":"card","Code":"2200","Name":"Card","Type":"BANK","BankAccountType":"CREDITCARD","CurrencyCode":"USD"}));
        let p = plan(b, "USD", 2).unwrap();
        assert_eq!(
            p.accounts.iter().find(|a| a.code == "2200").unwrap().kind,
            "liability"
        );
        let mut b: Bundle = pratique::json_value::from_str(include_str!(
            "../../examples/accounting/xero-cutover.json"
        ))
        .unwrap();
        b.accounts[0]["CurrencyCode"] = json!("EUR");
        assert!(plan(b, "USD", 2).is_err());
    }
    #[test]
    fn mismatch_blocks() {
        let mut b: Bundle = pratique::json_value::from_str(include_str!(
            "../../examples/accounting/xero-cutover.json"
        ))
        .unwrap();
        b.invoices[0]["AmountDue"] = json!(119);
        assert!(
            plan(b, "USD", 2)
                .unwrap_err()
                .to_string()
                .contains("Receivables mismatch")
        );
    }
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    #[test]
    fn record_contract_bundle() {
        crate::data_contracts::check::<Bundle>(
            "src_accounting_xero_Bundle",
            &[
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",[{"z":[1,true,null],"a":"sample"}],[{"z":[1,true,null],"a":"sample"}],[{"z":[1,true,null],"a":"sample"}],[{"z":[1,true,null],"a":"sample"}],[{"z":[1,true,null],"a":"sample"}],[{"z":[1,true,null],"a":"sample"}],true]"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"unexpected_field":1}"###,
                r###"{"as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":false,"as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"source_org":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":false,"currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"as_of":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":false,"receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"currency":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":false,"payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"receivable_account":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":false,"trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"payable_account":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":false,"accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"trial_balance_csv":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":"wrong","contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"accounts":[{"z":[1,true,null],"a":"sample"}]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":"wrong","invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"contacts":[{"z":[1,true,null],"a":"sample"}]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":"wrong","credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"invoices":[{"z":[1,true,null],"a":"sample"}]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":"wrong","prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"credit_notes":[{"z":[1,true,null],"a":"sample"}]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":"wrong","overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"prepayments":[{"z":[1,true,null],"a":"sample"}]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":"wrong","source_frozen":true}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"overpayments":[{"z":[1,true,null],"a":"sample"}]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":"wrong"}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","currency":"sample-\u00e9\ud83d\ude00","receivable_account":"sample-\u00e9\ud83d\ude00","payable_account":"sample-\u00e9\ud83d\ude00","trial_balance_csv":"sample-\u00e9\ud83d\ude00","accounts":[{"z":[1,true,null],"a":"sample"}],"contacts":[{"z":[1,true,null],"a":"sample"}],"invoices":[{"z":[1,true,null],"a":"sample"}],"credit_notes":[{"z":[1,true,null],"a":"sample"}],"prepayments":[{"z":[1,true,null],"a":"sample"}],"overpayments":[{"z":[1,true,null],"a":"sample"}],"source_frozen":true,"source_frozen":true}"###,
            ],
        );
    }
    #[test]
    fn record_contract_plan() {
        crate::data_contracts::check::<Plan>(
            "src_accounting_xero_Plan",
            &[
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",[],[],[],[],{"z":[1,true,null],"a":"sample"}]"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"},"unexpected_field":1}"###,
                r###"{"as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":false,"as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"},"source_org":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":false,"accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"},"as_of":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":"wrong","contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"},"accounts":[]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":"wrong","lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"},"contacts":[]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":"wrong","documents":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"},"lines":[]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":"wrong","summary":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"},"documents":[]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[]}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":"wrong"}"###,
                r###"{"source_org":"sample-\u00e9\ud83d\ude00","as_of":"sample-\u00e9\ud83d\ude00","accounts":[],"contacts":[],"lines":[],"documents":[],"summary":{"z":[1,true,null],"a":"sample"},"summary":{"z":[1,true,null],"a":"sample"}}"###,
            ],
        );
    }
}
