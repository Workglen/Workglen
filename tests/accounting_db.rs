//! Opt-in database checks. Use a disposable PostgreSQL database only.
use pratique::json_value::{Value, json};
use workglen_mail::accounting::{Config, Db, model::Command};
fn cmd(db: &Db, a: &str, b: Option<&str>, v: Value) -> workglen_mail::error::Result<Value> {
    db.run(
        Command {
            action: a.into(),
            book_id: b.map(str::to_string),
            data: v,
        },
        "test-admin",
    )
}
#[test]
#[ignore = "requires WORKGLEN_TEST_DSN_FILE and WORKGLEN_TEST_CA_FILE; disposable DB"]
fn accounting_transactions_and_banking() {
    let db = Db::new(
        Config {
            dsn_file: std::env::var("WORKGLEN_TEST_DSN_FILE").unwrap(),
            ca_file: Some(std::env::var("WORKGLEN_TEST_CA_FILE").unwrap()),
            feed_key_file: None,
            pool_size: 1,
            transport: Default::default(),
        },
        "test-accounting".into(),
    )
    .unwrap();
    let database_id = db.initialize().unwrap();
    assert_eq!(db.initialize().unwrap(), database_id);
    assert!(!db.status().unwrap()["enabled"].as_bool().unwrap());
    assert!(cmd(&db, "books", None, json!({})).is_err());
    db.set_enabled(true, Some(0), "test").unwrap();
    assert!(db.set_enabled(false, Some(0), "test").is_err());
    cmd(
        &db,
        "create-book",
        None,
        json!({"id":"main","name":"Test company","currency":"USD","scale":2}),
    )
    .unwrap();
    let bundle: Value =
        pratique::json_value::from_str(include_str!("../examples/accounting/xero-cutover.json"))
            .unwrap();
    let mut wrong = bundle.clone();
    wrong["invoices"][0]["AmountDue"] = json!(119);
    assert!(cmd(&db, "xero-preview", Some("main"), wrong).is_err());
    let p = cmd(&db, "xero-preview", Some("main"), bundle.clone()).unwrap();
    let p2 = cmd(&db, "xero-preview", Some("main"), bundle).unwrap();
    assert_eq!(p["id"], p2["id"]);
    assert!(
        cmd(
            &db,
            "xero-commit",
            Some("main"),
            json!({"id":p["id"],"hash":"wrong"})
        )
        .is_err()
    );
    let commit = json!({"id":p["id"],"hash":p["hash"]});
    cmd(&db, "xero-commit", Some("main"), commit.clone()).unwrap();
    assert_eq!(
        cmd(&db, "xero-commit", Some("main"), commit).unwrap()["replayed"],
        true
    );
    let tb = cmd(
        &db,
        "trial-balance",
        Some("main"),
        json!({"as_of":"2026-10-23"}),
    )
    .unwrap();
    assert_eq!(tb["debit"], "1120.00");
    assert_eq!(tb["credit"], "1120.00");
    assert_eq!(
        cmd(&db, "documents", Some("main"), json!({})).unwrap()["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let journal = json!({"request_id":"journal1","date":"2026-10-01","description":"opening work","lines":[{"account":"1000","debit":"10.00","credit":"0.00"},{"account":"4000","debit":"0.00","credit":"10.00"}]});
    let mut bad = journal.clone();
    bad["date"] = json!("2026-09-30");
    assert!(cmd(&db, "post-journal", Some("main"), bad).is_err());
    let j = cmd(&db, "post-journal", Some("main"), journal.clone()).unwrap();
    assert_eq!(
        cmd(&db, "post-journal", Some("main"), journal.clone()).unwrap()["replayed"],
        true
    );
    let mut bad = journal.clone();
    bad["description"] = json!("different");
    assert!(cmd(&db, "post-journal", Some("main"), bad).is_err());
    let mut bad = journal.clone();
    bad["request_id"] = json!("unbalanced");
    bad["lines"][0]["debit"] = json!("11.00");
    assert!(cmd(&db, "post-journal", Some("main"), bad).is_err());
    cmd(&db,"bank-create",Some("main"),json!({"id":"checking","name":"Chase checking","ledger_account":"1000","import_from":"2026-10-01","statement_account_id":"1234"})).unwrap();
    let csv = "Date,Description,Amount,ID\n2026-10-01,Sale,10.00,a\n2026-10-02,Office,-4.50,b\n2026-10-03,Customer,120.00,c\n2026-10-04,Supplier,-50.00,d\n2026-10-05,Duplicate candidate,10.00,e\n2026-10-05,Duplicate candidate,10.00,f\n";
    let p = cmd(
        &db,
        "bank-preview",
        Some("main"),
        json!({"bank_id":"checking","format":"csv","content":csv}),
    )
    .unwrap();
    assert_eq!(p["count"], 6);
    assert_eq!(
        cmd(
            &db,
            "bank-transactions",
            Some("main"),
            json!({"bank_id":"checking"})
        )
        .unwrap()["rows"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let c = json!({"id":p["id"],"hash":p["hash"]});
    assert_eq!(
        cmd(&db, "bank-commit", Some("main"), c.clone()).unwrap()["new_transactions"],
        6
    );
    assert_eq!(
        cmd(&db, "bank-commit", Some("main"), c).unwrap()["replayed"],
        true
    );
    let tx = cmd(
        &db,
        "bank-transactions",
        Some("main"),
        json!({"bank_id":"checking"}),
    )
    .unwrap();
    let rows = tx["rows"].as_array().unwrap();
    let id = |desc: &str| {
        rows.iter().find(|r| r["description"] == desc).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(
        rows.iter()
            .filter(|r| r["possible_duplicate"] == true)
            .count(),
        2
    );
    assert!(
        cmd(
            &db,
            "bank-match",
            Some("main"),
            json!({"id":id("Office"),"journal_id":j["journal_id"]})
        )
        .is_err()
    );
    cmd(
        &db,
        "bank-match",
        Some("main"),
        json!({"id":id("Sale"),"journal_id":j["journal_id"]}),
    )
    .unwrap();
    assert!(
        cmd(
            &db,
            "reverse-journal",
            Some("main"),
            json!({"journal_id":j["journal_id"],"request_id":"reverse","date":"2026-10-08"})
        )
        .is_err()
    );
    let post = cmd(
        &db,
        "bank-post",
        Some("main"),
        json!({"id":id("Office"),"account":"5000"}),
    )
    .unwrap();
    assert_eq!(post["state"], "matched");
    assert_eq!(
        cmd(
            &db,
            "bank-post",
            Some("main"),
            json!({"id":id("Office"),"account":"5000"})
        )
        .unwrap()["replayed"],
        true
    );
    assert!(
        cmd(
            &db,
            "bank-payment",
            Some("main"),
            json!({"id":id("Customer"),"document_id":"bill-1"})
        )
        .is_err()
    );
    cmd(
        &db,
        "bank-payment",
        Some("main"),
        json!({"id":id("Customer"),"document_id":"invoice-1"}),
    )
    .unwrap();
    cmd(
        &db,
        "bank-payment",
        Some("main"),
        json!({"id":id("Supplier"),"document_id":"bill-1"}),
    )
    .unwrap();
    let docs = cmd(&db, "documents", Some("main"), json!({})).unwrap();
    assert!(
        docs["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["outstanding"] == "0.00")
    );
    let duplicate = id("Duplicate candidate");
    assert!(
        cmd(
            &db,
            "bank-exclude",
            Some("main"),
            json!({"id":duplicate,"note":""})
        )
        .is_err()
    );
    cmd(
        &db,
        "bank-exclude",
        Some("main"),
        json!({"id":duplicate,"note":"Duplicate verified against statement"}),
    )
    .unwrap();
    cmd(
        &db,
        "bank-unmatch",
        Some("main"),
        json!({"id":id("Sale"),"note":"Correcting classification"}),
    )
    .unwrap();
    cmd(
        &db,
        "reverse-journal",
        Some("main"),
        json!({"journal_id":j["journal_id"],"request_id":"reverse","date":"2026-10-08"}),
    )
    .unwrap();
    assert!(
        cmd(
            &db,
            "bank-match",
            Some("main"),
            json!({"id":id("Sale"),"journal_id":j["journal_id"]})
        )
        .is_err()
    );
    let p=cmd(&db,"bank-preview",Some("main"),json!({"bank_id":"checking","format":"csv","content":"Date,Description,Amount,ID\n2026-10-02,Changed,-5.50,b\n"})).unwrap();
    assert!(
        cmd(
            &db,
            "bank-commit",
            Some("main"),
            json!({"id":p["id"],"hash":p["hash"]})
        )
        .is_err()
    );
    // Bank accounts stay isolated, even with equal source transaction IDs.
    cmd(
        &db,
        "add-account",
        Some("main"),
        json!({"code":"2000","name":"Credit card","kind":"liability","bank":true}),
    )
    .unwrap();
    cmd(&db,"bank-create",Some("main"),json!({"id":"card","name":"Chase card","ledger_account":"2000","import_from":"2026-10-01","statement_account_id":"5678"})).unwrap();
    let ofx = "<OFX><CCSTMTRS><CURDEF>USD<CCACCTFROM><ACCTID>5678</CCACCTFROM><BANKTRANLIST><STMTTRN><DTPOSTED>20261002<TRNAMT>-4.50<FITID>b<NAME>Office</STMTTRN></BANKTRANLIST></CCSTMTRS></OFX>";
    assert!(
        cmd(
            &db,
            "bank-preview",
            Some("main"),
            json!({"bank_id":"checking","format":"ofx","content":ofx})
        )
        .is_err()
    );
    let p = cmd(
        &db,
        "bank-preview",
        Some("main"),
        json!({"bank_id":"card","format":"qfx","content":ofx}),
    )
    .unwrap();
    cmd(
        &db,
        "bank-commit",
        Some("main"),
        json!({"id":p["id"],"hash":p["hash"]}),
    )
    .unwrap();
    let c = cmd(
        &db,
        "bank-transactions",
        Some("main"),
        json!({"bank_id":"card"}),
    )
    .unwrap();
    cmd(
        &db,
        "bank-post",
        Some("main"),
        json!({"id":c["rows"][0]["id"],"account":"5000"}),
    )
    .unwrap();
    let tb = cmd(
        &db,
        "trial-balance",
        Some("main"),
        json!({"as_of":"2026-10-23"}),
    )
    .unwrap();
    assert_eq!(tb["balanced"], true);
    assert_eq!(
        tb["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["code"] == "2000")
            .unwrap()["credit"],
        "4.50"
    );
    // Database-enforced ledger balance and immutability, independent of handlers.
    {
        let mut c = db.connect().unwrap();
        assert!(
            c.execute(
                "UPDATE workglen_accounting.lines SET debit=debit+1 WHERE book_id='main'",
                &[]
            )
            .is_err()
        );
        let mut t = c.transaction().unwrap();
        t.execute("INSERT INTO workglen_accounting.journals(book_id,id,entry_date,description,kind,request_id,payload_hash,actor) VALUES('main','bad','2026-10-01','bad','manual','bad','bad','test')",&[]).unwrap();
        assert!(t.commit().is_err());
    }
    // Replacement feed mapping and provider corrections preserve posted journals.
    {
        let mut c = db.connect().unwrap();
        c.execute("INSERT INTO workglen_accounting.feed_connections(book_id,id,name,provider,active) VALUES('main','f1','First','simplefin',true),('main','f2','Replacement','simplefin',true)",&[]).unwrap();
        c.execute("INSERT INTO workglen_accounting.feed_accounts(book_id,connection_id,source_key,name,currency,balance,balance_at) VALUES('main','f1','k1','Bank','USD','0',0),('main','f2','k2','Bank','USD','0',0)",&[]).unwrap();
    }
    cmd(
        &db,
        "feed-map",
        Some("main"),
        json!({"connection_id":"f1","source_key":"k1","bank_id":"checking"}),
    )
    .unwrap();
    assert!(
        cmd(
            &db,
            "feed-map",
            Some("main"),
            json!({"connection_id":"f2","source_key":"k2","bank_id":"checking"})
        )
        .is_err()
    );
    cmd(&db, "feed-disconnect", Some("main"), json!({"id":"f1"})).unwrap();
    cmd(
        &db,
        "feed-map",
        Some("main"),
        json!({"connection_id":"f2","source_key":"k2","bank_id":"checking"}),
    )
    .unwrap();
    let mut e = workglen_mail::accounting::bank_files::Entry {
        id: "provider-1".into(),
        date: "2026-10-22".into(),
        amount: 2000,
        description: "Provider deposit".into(),
    };
    {
        let mut c = db.connect().unwrap();
        let mut t = c.transaction().unwrap();
        assert!(
            workglen_mail::accounting::banking::stage(
                &mut t,
                "main",
                "checking",
                "simplefin:test",
                &e,
                true
            )
            .unwrap()
        );
        t.commit().unwrap();
    }
    let ts = cmd(
        &db,
        "bank-transactions",
        Some("main"),
        json!({"bank_id":"checking"}),
    )
    .unwrap();
    let tid = ts["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["description"] == "Provider deposit")
        .unwrap()["id"]
        .clone();
    let posted = cmd(
        &db,
        "bank-post",
        Some("main"),
        json!({"id":tid,"account":"4000"}),
    )
    .unwrap();
    assert!(
        cmd(
            &db,
            "bank-post",
            Some("main"),
            json!({"id":tid,"account":"5000"})
        )
        .is_err()
    );
    e.amount = 2100;
    {
        let mut c = db.connect().unwrap();
        let mut t = c.transaction().unwrap();
        assert!(
            !workglen_mail::accounting::banking::stage(
                &mut t,
                "main",
                "checking",
                "simplefin:test",
                &e,
                true
            )
            .unwrap()
        );
        t.commit().unwrap();
    }
    let ts = cmd(
        &db,
        "bank-transactions",
        Some("main"),
        json!({"bank_id":"checking"}),
    )
    .unwrap();
    let changed = ts["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == tid)
        .unwrap();
    assert_eq!(changed["state"], "conflict");
    assert_eq!(changed["journal_id"], posted["journal_id"]);
    {
        let mut c = db.connect().unwrap();
        let amount:i64=c.query_one("SELECT debit FROM workglen_accounting.lines WHERE book_id='main' AND journal_id=$1 AND account_code='1000'",&[&posted["journal_id"].as_str().unwrap()]).unwrap().get(0);
        assert_eq!(amount, 2000);
    }
    assert!(
        !cmd(&db, "feed-connections", Some("main"), json!({}))
            .unwrap()
            .to_string()
            .contains("secret")
    );
    db.set_enabled(false, Some(1), "test").unwrap();
    assert!(cmd(&db, "bank-accounts", Some("main"), json!({})).is_err());
    db.set_enabled(true, Some(2), "test").unwrap();
    assert_eq!(
        cmd(&db, "bank-accounts", Some("main"), json!({}))
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let before_reinitialize = cmd(
        &db,
        "trial-balance",
        Some("main"),
        json!({"as_of":"2026-10-23"}),
    )
    .unwrap();
    let before_audit: i64 = db
        .connect()
        .unwrap()
        .query_one("SELECT count(*) FROM workglen_accounting.audit", &[])
        .unwrap()
        .get(0);
    assert_eq!(db.initialize().unwrap(), database_id);
    assert_eq!(
        cmd(
            &db,
            "trial-balance",
            Some("main"),
            json!({"as_of":"2026-10-23"})
        )
        .unwrap(),
        before_reinitialize
    );
    assert_eq!(
        db.connect()
            .unwrap()
            .query_one("SELECT count(*) FROM workglen_accounting.audit", &[])
            .unwrap()
            .get::<_, i64>(0),
        before_audit
    );
    assert_eq!(db.status().unwrap()["enabled"], true);
    println!(
        "Accounting scenario passed: cutover, exact ledger, replay guards, statement preview/commit, multiple banks, card signs, matching, payments, exclusion, locking, immutability and module lifecycle."
    );
}
