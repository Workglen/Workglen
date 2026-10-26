use crate::error::{Result, ensure};
use pratique::crypto::sha2::{Hash, Sha256};
pub const MAX_AMOUNT: i64 = 9_000_000_000_000_000;
pub fn money(s: &str, scale: i16) -> Result<i64> {
    ensure!((0..=3).contains(&scale), "Currency scale must be 0..3");
    ensure!(
        !s.is_empty() && s.len() <= 24 && s.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "Amounts must be nonnegative decimal strings without separators or exponents"
    );
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    ensure!(
        !whole.is_empty()
            && !frac.contains('.')
            && frac.len() <= scale as usize
            && (!s.contains('.') || !frac.is_empty()),
        "Amount exceeds currency precision"
    );
    let whole: i64 = whole.parse()?;
    let f: i64 = if frac.is_empty() { 0 } else { frac.parse()? };
    let value = whole
        .checked_mul(10i64.pow(scale as u32))
        .and_then(|v| v.checked_add(f * 10i64.pow(scale as u32 - frac.len() as u32)))
        .ok_or_else(|| crate::error!("Amount overflow"))?;
    ensure!(value <= MAX_AMOUNT, "Amount exceeds supported limit");
    Ok(value)
}
pub fn display(v: i128, scale: i16) -> String {
    let sign = if v < 0 { "-" } else { "" };
    let v = v.abs();
    let m = 10i128.pow(scale as u32);
    if scale == 0 {
        format!("{sign}{v}")
    } else {
        format!("{sign}{}.{:0width$}", v / m, v % m, width = scale as usize)
    }
}
pub fn text(s: &str, max: usize, name: &str) -> Result<()> {
    ensure!(
        !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control),
        "Invalid {name}"
    );
    Ok(())
}
pub fn key(s: &str) -> Result<()> {
    ensure!(
        !s.is_empty()
            && s.len() <= 80
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b)),
        "Invalid identifier"
    );
    Ok(())
}
pub fn date(s: &str) -> Result<crate::datetime::NaiveDate> {
    let d = crate::datetime::NaiveDate::parse_from_str(s, "%Y-%m-%d")?;
    ensure!(
        d.format("%Y-%m-%d").to_string() == s,
        "Use ISO YYYY-MM-DD dates"
    );
    Ok(d)
}
pub fn hash(v: &impl pratique::data::Encode) -> Result<String> {
    Ok(pratique::util::hex(&Sha256::digest(
        &pratique::json_value::to_vec(v)?,
    )))
}
#[derive(Debug, Clone)]
pub struct Account {
    pub code: String,
    pub name: String,
    pub kind: String,
    pub bank: bool,
    pub control: Option<String>,
    pub source_id: Option<String>,
}
pratique::data_encode!(Account {
    code,
    name,
    kind,
    bank,
    control,
    source_id
});
pratique::data_decode!(Account, deny_unknown=true, { code, name, kind, bank = Default::default(), control, source_id });

impl Account {
    pub fn validate(&self) -> Result<()> {
        key(&self.code)?;
        text(&self.name, 200, "account name")?;
        ensure!(
            ["asset", "liability", "equity", "income", "expense"].contains(&self.kind.as_str()),
            "Unknown account kind"
        );
        ensure!(
            !self.bank || ["asset", "liability"].contains(&self.kind.as_str()),
            "Bank or credit card must be an asset or liability"
        );
        if let Some(c) = &self.control {
            ensure!(
                (c == "receivable" && self.kind == "asset")
                    || (c == "payable" && self.kind == "liability"),
                "Invalid control account kind"
            );
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct Contact {
    pub id: String,
    pub name: String,
    pub email: String,
    pub source_id: Option<String>,
}
pratique::data_encode!(Contact {
    id,
    name,
    email,
    source_id
});
pratique::data_decode!(Contact, deny_unknown=true, { id, name, email = Default::default(), source_id });

#[derive(Debug, Clone)]
pub struct InputLine {
    pub account: String,
    pub debit: String,
    pub credit: String,
}
pratique::data_encode!(InputLine {
    account,
    debit,
    credit
});
pratique::data_decode!(InputLine, deny_unknown=true, { account, debit, credit });

#[derive(Debug, Clone)]
pub struct Line {
    pub account: String,
    pub debit: i64,
    pub credit: i64,
}
pratique::data_encode!(Line {
    account,
    debit,
    credit
});
pratique::data_decode!(Line, deny_unknown=false, { account, debit, credit });

pub fn lines(input: &[InputLine], scale: i16) -> Result<Vec<Line>> {
    ensure!(
        (2..=5000).contains(&input.len()),
        "A journal requires 2..5000 lines"
    );
    let mut d = 0i128;
    let mut c = 0i128;
    let mut out = Vec::new();
    for l in input {
        key(&l.account)?;
        let debit = money(&l.debit, scale)?;
        let credit = money(&l.credit, scale)?;
        ensure!(
            (debit > 0 && credit == 0) || (credit > 0 && debit == 0),
            "Each line needs exactly one positive debit or credit"
        );
        d += debit as i128;
        c += credit as i128;
        out.push(Line {
            account: l.account.clone(),
            debit,
            credit,
        });
    }
    ensure!(
        d == c && d > 0 && d <= MAX_AMOUNT as i128,
        "Debits and credits must balance within the amount limit"
    );
    Ok(out)
}
#[derive(Debug, Clone)]
pub struct Journal {
    pub request_id: String,
    pub date: String,
    pub description: String,
    pub lines: Vec<InputLine>,
}
pratique::data_encode!(Journal {
    request_id,
    date,
    description,
    lines
});
pratique::data_decode!(Journal, deny_unknown=true, { request_id, date, description, lines });

#[derive(Debug, Clone)]
pub struct Command {
    pub action: String,
    pub book_id: Option<String>,
    pub data: pratique::json_value::Value,
}
pratique::data_encode!(Command {
    action,
    book_id,
    data
});
pratique::data_decode!(Command, deny_unknown=true, { action, book_id, data = Default::default() });

#[derive(Debug, Clone)]
pub struct OpenDocument {
    pub id: String,
    pub kind: String,
    pub contact_id: String,
    pub number: String,
    pub issued: String,
    pub due: String,
    pub control_account: String,
    pub original_amount: i64,
    pub opening_due: i64,
    pub source_id: Option<String>,
}
pratique::data_encode!(OpenDocument {
    id,
    kind,
    contact_id,
    number,
    issued,
    due,
    control_account,
    original_amount,
    opening_due,
    source_id
});
pratique::data_decode!(OpenDocument, deny_unknown=false, { id, kind, contact_id, number, issued, due, control_account, original_amount, opening_due, source_id });
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    #[test]
    fn record_contract_account() {
        crate::data_contracts::check::<Account>(
            "src_accounting_model_Account",
            &[
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",true,null,null]"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null,"unexpected_field":1}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null}"###,
                r###"{"code":false,"name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null,"code":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":false,"kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null,"name":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":false,"bank":true,"control":null,"source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null,"kind":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","control":null,"source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":"wrong","control":null,"source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null,"bank":true}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":"wrong","source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null,"control":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":"sample-\u00e9\ud83d\ude00","source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":"wrong"}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":null,"source_id":null}"###,
                r###"{"code":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","bank":true,"control":null,"source_id":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    #[test]
    fn record_contract_contact() {
        crate::data_contracts::check::<Contact>(
            "src_accounting_model_Contact",
            &[
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",null]"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":null,"unexpected_field":1}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":null}"###,
                r###"{"id":false,"name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":null,"id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":false,"email":"sample-\u00e9\ud83d\ude00","source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":null,"name":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","email":false,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":null,"email":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":"wrong"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":null,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","name":"sample-\u00e9\ud83d\ude00","email":"sample-\u00e9\ud83d\ude00","source_id":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    #[test]
    fn record_contract_inputline() {
        crate::data_contracts::check::<InputLine>(
            "src_accounting_model_InputLine",
            &[
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":"sample-\u00e9\ud83d\ude00","credit":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00"]"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":"sample-\u00e9\ud83d\ude00","credit":"sample-\u00e9\ud83d\ude00","unexpected_field":1}"###,
                r###"{"debit":"sample-\u00e9\ud83d\ude00","credit":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"account":false,"debit":"sample-\u00e9\ud83d\ude00","credit":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":"sample-\u00e9\ud83d\ude00","credit":"sample-\u00e9\ud83d\ude00","account":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","credit":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":false,"credit":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":"sample-\u00e9\ud83d\ude00","credit":"sample-\u00e9\ud83d\ude00","debit":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":"sample-\u00e9\ud83d\ude00","credit":false}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":"sample-\u00e9\ud83d\ude00","credit":"sample-\u00e9\ud83d\ude00","credit":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
    #[test]
    fn record_contract_line() {
        crate::data_contracts::check::<Line>(
            "src_accounting_model_Line",
            &[
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":-9223372036854775808,"credit":-9223372036854775808}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",-9223372036854775808,-9223372036854775808]"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":-9223372036854775808,"credit":-9223372036854775808,"unexpected_field":1}"###,
                r###"{"debit":-9223372036854775808,"credit":-9223372036854775808}"###,
                r###"{"account":false,"debit":-9223372036854775808,"credit":-9223372036854775808}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":-9223372036854775808,"credit":-9223372036854775808,"account":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","credit":-9223372036854775808}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":"wrong","credit":-9223372036854775808}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":-9223372036854775808,"credit":-9223372036854775808,"debit":-9223372036854775808}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":-9223372036854775808}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":-9223372036854775808,"credit":"wrong"}"###,
                r###"{"account":"sample-\u00e9\ud83d\ude00","debit":-9223372036854775808,"credit":-9223372036854775808,"credit":-9223372036854775808}"###,
            ],
        );
    }
    #[test]
    fn record_contract_journal() {
        crate::data_contracts::check::<Journal>(
            "src_accounting_model_Journal",
            &[
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00","lines":[]}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",[]]"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00","lines":[],"unexpected_field":1}"###,
                r###"{"date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00","lines":[]}"###,
                r###"{"request_id":false,"date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00","lines":[]}"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00","lines":[],"request_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00","lines":[]}"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":false,"description":"sample-\u00e9\ud83d\ude00","lines":[]}"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00","lines":[],"date":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","lines":[]}"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","description":false,"lines":[]}"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00","lines":[],"description":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00","lines":"wrong"}"###,
                r###"{"request_id":"sample-\u00e9\ud83d\ude00","date":"sample-\u00e9\ud83d\ude00","description":"sample-\u00e9\ud83d\ude00","lines":[],"lines":[]}"###,
            ],
        );
    }
    #[test]
    fn record_contract_command() {
        crate::data_contracts::check::<Command>(
            "src_accounting_model_Command",
            &[
                r###"{"action":"sample-\u00e9\ud83d\ude00","book_id":null,"data":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",null,{"z":[1,true,null],"a":"sample"}]"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","book_id":null,"data":{"z":[1,true,null],"a":"sample"},"unexpected_field":1}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"book_id":null,"data":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"action":false,"book_id":null,"data":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","book_id":null,"data":{"z":[1,true,null],"a":"sample"},"action":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","data":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","book_id":"wrong","data":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","book_id":null,"data":{"z":[1,true,null],"a":"sample"},"book_id":null}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","book_id":"sample-\u00e9\ud83d\ude00","data":{"z":[1,true,null],"a":"sample"}}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","book_id":null}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","book_id":null,"data":"wrong"}"###,
                r###"{"action":"sample-\u00e9\ud83d\ude00","book_id":null,"data":{"z":[1,true,null],"a":"sample"},"data":{"z":[1,true,null],"a":"sample"}}"###,
            ],
        );
    }
    #[test]
    fn record_contract_opendocument() {
        crate::data_contracts::check::<OpenDocument>(
            "src_accounting_model_OpenDocument",
            &[
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",-9223372036854775808,-9223372036854775808,null]"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"unexpected_field":1}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808}"###,
                r###"{"kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":false,"kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":false,"contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"kind":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":false,"number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"contact_id":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":false,"issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"number":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":false,"due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"issued":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":false,"control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"due":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":false,"original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"control_account":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":"wrong","opening_due":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"original_amount":-9223372036854775808}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":"wrong","source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"opening_due":-9223372036854775808}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":"wrong"}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":null,"source_id":null}"###,
                r###"{"id":"sample-\u00e9\ud83d\ude00","kind":"sample-\u00e9\ud83d\ude00","contact_id":"sample-\u00e9\ud83d\ude00","number":"sample-\u00e9\ud83d\ude00","issued":"sample-\u00e9\ud83d\ude00","due":"sample-\u00e9\ud83d\ude00","control_account":"sample-\u00e9\ud83d\ude00","original_amount":-9223372036854775808,"opening_due":-9223372036854775808,"source_id":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
}
