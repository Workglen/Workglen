//! Bounded statement readers. All amounts use exact integer minor units.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: String,
    pub date: String,
    pub amount: i64,
    pub description: String,
}
pratique::data_encode!(Entry {
    id,
    date,
    amount,
    description
});
pratique::data_decode!(Entry, deny_unknown=false, { id, date, amount, description });

#[derive(Debug)]
pub struct Statement {
    pub source: String,
    pub account_id: Option<String>,
    pub currency: Option<String>,
    pub entries: Vec<Entry>,
    pub warnings: Vec<String>,
}
pratique::data_encode!(Statement {
    source,
    account_id,
    currency,
    entries,
    warnings
});
pratique::data_decode!(Statement, deny_unknown=false, { source, account_id, currency, entries, warnings });

pub fn signed(s: &str, scale: i16) -> Result<i64> {
    let s = s.trim();
    let (sign, s) = if let Some(s) = s.strip_prefix('-') {
        (-1, s)
    } else {
        (1, s.strip_prefix('+').unwrap_or(s))
    };
    Ok(sign * money(s, scale)?)
}
fn clean_date(s: &str) -> Result<String> {
    let d = if s.contains('/') {
        crate::datetime::NaiveDate::parse_from_str(s, "%m/%d/%Y")?
    } else {
        date(s)?
    };
    Ok(d.format("%Y-%m-%d").to_string())
}
pub fn parse(format: &str, content: &str, scale: i16) -> Result<Statement> {
    ensure!(content.len() <= 2 * 1024 * 1024, "Statement exceeds 2 MiB");
    let mut s = match format {
        "csv" => csv(content, scale)?,
        "ofx" | "qfx" | "qbo" => ofx(content, scale)?,
        _ => bail!("Use CSV, OFX, QFX or QBO"),
    };
    ensure!(
        !s.entries.is_empty() && s.entries.len() <= 5000,
        "Statement must contain 1..5000 posted transactions"
    );
    let mut ids = BTreeSet::new();
    for e in &mut s.entries {
        date(&e.date)?;
        text(&e.id, 200, "transaction ID")?;
        text(&e.description, 500, "description")?;
        ensure!(e.amount != 0, "Zero-value transactions are not supported");
        ensure!(
            ids.insert(e.id.clone()),
            "Duplicate transaction ID in statement"
        );
    }
    Ok(s)
}
fn csv(content: &str, scale: i16) -> Result<Statement> {
    let reader = crate::csv_reader::Reader::new(
        content.trim_start_matches('\u{feff}'),
        2 * 1024 * 1024,
        5000,
    )?;
    let headers = reader.headers().to_vec();
    let col = |names: &[&str]| -> Option<usize> {
        headers
            .iter()
            .position(|h| names.iter().any(|n| h.eq_ignore_ascii_case(n)))
    };
    let d = col(&["Date", "Posting Date", "Post Date"])
        .ok_or_else(|| crate::error!("CSV requires Date, Posting Date, or Post Date"))?;
    let desc = col(&["Description"]).ok_or_else(|| crate::error!("CSV requires Description"))?;
    let amt = col(&["Amount"]).ok_or_else(|| {
        crate::error!("CSV requires signed Amount: deposits positive, withdrawals/charges negative")
    })?;
    let id = col(&["ID", "Transaction ID", "FITID"]);
    let mut occurrence = BTreeMap::<String, u32>::new();
    let mut entries = Vec::new();
    for r in reader {
        let r = r?;
        ensure!(entries.len() < 5000, "Statement exceeds 5000 rows");
        let date = clean_date(&r[d])?;
        let description = r[desc].to_string();
        let amount = signed(&r[amt], scale)?;
        let eid = if let Some(i) = id {
            r[i].to_string()
        } else {
            let h = hash(&(date.clone(), amount, &description))?;
            let n = occurrence.entry(h.clone()).or_default();
            *n += 1;
            format!("{h}:{n}")
        };
        entries.push(Entry {
            id: eid,
            date,
            amount,
            description,
        });
    }
    Ok(Statement {
        source: if id.is_some() {
            "csv-id"
        } else {
            "csv-derived"
        }
        .into(),
        account_id: None,
        currency: None,
        entries,
        warnings: if id.is_none() {
            vec!["CSV has no stable transaction IDs. Identical rows use occurrence numbers; review overlap and same-day repeated purchases against your bank statement.".into()]
        } else {
            vec![]
        },
    })
}
// OFX 1.x SGML and OFX 2.x XML share the scalar tags below. No DTD, entity
// expansion, arbitrary XML, or external resource resolution is performed.
fn scalar(s: &str, name: &str) -> Result<String> {
    let tag = format!("<{name}>");
    let upper = s.to_ascii_uppercase();
    let p = upper
        .find(&tag)
        .ok_or_else(|| crate::error!("Missing statement field {name}"))?
        + tag.len();
    let end = s[p..].find('<').map(|i| p + i).unwrap_or(s.len());
    let raw = s[p..end].trim();
    let mut out = String::new();
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let n = rest[i..]
            .find(';')
            .ok_or_else(|| crate::error!("Invalid entity"))?
            + i;
        out.push_str(match &rest[i..=n] {
            "&amp;" => "&",
            "&lt;" => "<",
            "&gt;" => ">",
            "&quot;" => "\"",
            "&apos;" => "'",
            _ => bail!("Unsupported entity in statement"),
        });
        rest = &rest[n + 1..];
    }
    out.push_str(rest);
    Ok(out)
}
fn ofx(content: &str, scale: i16) -> Result<Statement> {
    let up = content.to_ascii_uppercase();
    ensure!(
        !up.contains("<!DOCTYPE") && !up.contains("<!ENTITY"),
        "DTD and entities are forbidden"
    );
    ensure!(
        up.matches("<STMTRS>").count() + up.matches("<CCSTMTRS>").count() == 1,
        "Import one bank or credit-card statement at a time"
    );
    if up.contains("<CODE>") {
        ensure!(
            scalar(content, "CODE")? == "0",
            "Statement reports an OFX error"
        );
    }
    let account_id = Some(scalar(content, "ACCTID")?);
    let currency = Some(scalar(content, "CURDEF")?);
    let mut entries = Vec::new();
    let mut start = 0;
    while let Some(i) = up[start..].find("<STMTTRN>") {
        let i = start + i + 9;
        let end = up[i..]
            .find("</STMTTRN>")
            .map(|n| i + n)
            .ok_or_else(|| crate::error!("Unclosed STMTTRN"))?;
        let tr = &content[i..end];
        ensure!(
            !tr.to_ascii_uppercase().contains("<CORRECTFITID>"),
            "OFX corrections require manual review before import"
        );
        let d = scalar(tr, "DTPOSTED")?;
        ensure!(
            d.get(..8)
                .is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit())),
            "Invalid OFX date"
        );
        let date = crate::datetime::NaiveDate::parse_from_str(&d[..8], "%Y%m%d")?
            .format("%Y-%m-%d")
            .to_string();
        let name = scalar(tr, "NAME").unwrap_or_default();
        let memo = scalar(tr, "MEMO").unwrap_or_default();
        entries.push(Entry {
            id: scalar(tr, "FITID")?,
            date,
            amount: signed(&scalar(tr, "TRNAMT")?, scale)?,
            description: format!("{name} {memo}").trim().to_string(),
        });
        ensure!(entries.len() <= 5000, "Statement exceeds 5000 rows");
        start = end + 10;
    }
    Ok(Statement {
        source: "ofx".into(),
        account_id,
        currency,
        entries,
        warnings: vec![],
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chase_csv_exact_and_duplicates() {
        let s=parse("csv","Details,Posting Date,Description,Amount,Type,Balance,Check or Slip #\nDEBIT,10/22/2026,Coffee,-4.50,DEBIT,100,\nDEBIT,10/22/2026,Coffee,-4.50,DEBIT,95.50,\n",2).unwrap();
        assert_eq!(s.entries[0].amount, -450);
        assert_ne!(s.entries[0].id, s.entries[1].id);
        assert_eq!(s.warnings.len(), 1);
    }
    #[test]
    fn ofx_sgml() {
        let s=parse("qbo","<OFX><STMTRS><CURDEF>USD<BANKACCTFROM><ACCTID>1234</BANKACCTFROM><BANKTRANLIST><STMTTRN><TRNTYPE>DEBIT<DTPOSTED>20261022<TRNAMT>-4.50<FITID>A<NAME>Coffee &amp; cake</STMTTRN></BANKTRANLIST></STMTRS></OFX>",2).unwrap();
        assert_eq!(s.entries[0].description, "Coffee & cake");
        assert_eq!(s.entries[0].amount, -450);
    }
    #[test]
    fn hostile_and_precision() {
        assert!(parse("ofx", "<!DOCTYPE x><OFX>", 2).is_err());
        assert!(signed("1.001", 2).is_err());
        assert!(signed("1e6", 2).is_err());
        assert!(
            parse(
                "csv",
                "Date,Description,Amount,ID\n2026-10-01,A,1.00,same\n2026-10-02,B,2.00,same",
                2
            )
            .is_err()
        );
    }
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    #[test]
    fn record_contract_entry() {
        crate::data_contracts::check::<Entry>(
            "src_accounting_bank_files_Entry",
            &[
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808,"description":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",-9223372036854775808,"sample-\u00e9\ud83d\ude00"]"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808,"description":"sample-\u00e9\ud83d\ude00","unexpected_field":1}"###,
                r###"{"date":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808,"description":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":false,"date":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808,"description":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808,"description":"sample-\u00e9\ud83d\ude00","id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808,"description":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":false,"amount":-9223372036854775808,"description":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808,"description":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","amount":"wrong","description":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808,"description":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808,"description":false}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","amount":-9223372036854775808,"description":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    #[test]
    fn record_contract_statement() {
        crate::data_contracts::check::<Statement>(
            "src_accounting_bank_files_Statement",
            &[
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",null,null,[],["sample-\u00e9\ud83d\ude00"]]"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"],"unexpected_field":1}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","entries":[],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"account_id":null,"currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"source":false,"account_id":null,"currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"],"source":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":"wrong","currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"],"account_id":null}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":"sample-\u00e9\ud83d\ude00","currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":"wrong","entries":[],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"],"currency":null}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":"sample-\u00e9\ud83d\ude00","entries":[],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"entries":"wrong","warnings":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"],"entries":[]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"entries":[]}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"entries":[],"warnings":"wrong"}"###,
                r###"{"source":"sample-\u00e9\ud83d\ude00","account_id":null,"currency":null,"entries":[],"warnings":["sample-\u00e9\ud83d\ude00"],"warnings":["sample-\u00e9\ud83d\ude00"]}"###,
            ],
        );
    }
}
