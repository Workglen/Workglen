//! Run only against a disposable, TLS-enabled PostgreSQL database.
use pratique::json_value::{Value, json};
use workglen_mail::accounting::{Config, Db, model::Command};
#[test]
#[ignore = "requires disposable WORKGLEN_TEST_DSN_FILE and WORKGLEN_TEST_CA_FILE"]
fn posting_corrections_locks_sources_and_audit() {
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
    db.initialize().unwrap();
    db.initialize().unwrap();
    db.set_enabled(true, None, "test").unwrap();
    let book = format!("corrections-{}", workglen_mail::store::random_id());
    let run = |a: &str, v: Value| {
        db.run(
            Command {
                action: a.into(),
                book_id: Some(book.clone()),
                data: v,
            },
            "external-accountant",
        )
    };
    run(
        "create-book",
        json!({"id":book,"name":"Corrections","currency":"USD","scale":2}),
    )
    .unwrap();
    for (code, kind, bank, control) in [
        ("1000", "asset", true, None),
        ("1100", "asset", false, Some("receivable")),
        ("2000", "liability", false, Some("payable")),
        ("4000", "income", false, None),
        ("5000", "expense", false, None),
    ] {
        run(
            "add-account",
            json!({"code":code,"name":code,"kind":kind,"bank":bank,"control":control}),
        )
        .unwrap();
    }
    run("add-contact", json!({"id":"customer","name":"Customer"})).unwrap();
    let lines = |n: &str| json!([{"account":"1000","debit":n,"credit":"0"},{"account":"4000","debit":"0","credit":n}]);
    let post = json!({"request_id":"original","date":"2026-10-10","description":"Original","lines":lines("10")});
    let id = run("post-journal", post.clone()).unwrap()["journal_id"]
        .as_str()
        .unwrap()
        .to_string();
    let edit = json!({"journal_id":id,"request_id":"edit1","expected_revision":0,"date":"2026-10-11","description":"Corrected","lines":lines("20"),"reason":"Correct amount"});
    assert_eq!(run("edit-journal", edit.clone()).unwrap()["revision"], 1);
    assert_eq!(run("edit-journal", edit.clone()).unwrap()["replayed"], true);
    let mut stale = edit.clone();
    stale["request_id"] = json!("stale");
    assert!(run("edit-journal", stale).is_err());
    let mut bad = edit.clone();
    bad["request_id"] = json!("bad");
    bad["expected_revision"] = json!(1);
    bad["lines"][0]["debit"] = json!("21");
    assert!(run("edit-journal", bad).is_err());
    assert_eq!(run("post-journal", post).unwrap()["replayed"], true);
    assert_eq!(
        run("trial-balance", json!({"as_of":"2026-10-11"})).unwrap()["debit"],
        "20.00"
    );
    assert_eq!(
        run("trial-balance", json!({"as_of":"2026-10-10"})).unwrap()["debit"],
        "0.00"
    );
    run("lock-date", json!({"date":"2026-10-31"})).unwrap();
    let void =
        json!({"journal_id":id,"request_id":"void1","expected_revision":1,"reason":"Duplicate"});
    assert!(run("void-journal", void.clone()).is_err());
    assert!(run("lock-date", json!({"date":"2026-09-30"})).is_err());
    assert!(
        run(
            "reopen-period",
            json!({"date":null,"expected_lock_date":"2026-10-30","reason":"Correction"})
        )
        .is_err()
    );
    assert!(
        run(
            "reopen-period",
            json!({"date":null,"expected_lock_date":"2026-10-31","reason":""})
        )
        .is_err()
    );
    run(
        "reopen-period",
        json!({"date":"2026-09-30","expected_lock_date":"2026-10-31","reason":"Correct October"}),
    )
    .unwrap();
    let mut bad = edit.clone();
    bad["request_id"] = json!("locked-new-date");
    bad["expected_revision"] = json!(1);
    bad["date"] = json!("2026-09-30");
    assert!(run("edit-journal", bad).is_err());
    run("void-journal", void).unwrap();
    assert_eq!(
        run("trial-balance", json!({"as_of":"2026-10-31"})).unwrap()["debit"],
        "0.00"
    );
    let history = run("journal", json!({"journal_id":id})).unwrap();
    assert_eq!(history["journal"]["status"], "void");
    assert_eq!(history["lines"][0]["debit"], "20.00");
    assert!(
        history["history"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action"] == "edit-journal"
                && a["details"]["before"]["lines"][0]["debit"] == 1000
                && a["details"]["after"]["lines"][0]["debit"] == 2000
                && a["actor"] == "external-accountant")
    );
    {
        let mut c = db.connect().unwrap();
        assert!(c.execute("UPDATE workglen_accounting.journals SET description='bypass' WHERE book_id=$1 AND id=$2", &[&book,&id]).is_err());
        assert!(
            c.execute(
                "DELETE FROM workglen_accounting.lines WHERE book_id=$1 AND journal_id=$2",
                &[&book, &id]
            )
            .is_err()
        );
        assert!(
            c.execute(
                "DELETE FROM workglen_accounting.audit WHERE book_id=$1",
                &[&book]
            )
            .is_err()
        );
        assert!(
            c.execute(
                "DELETE FROM workglen_accounting.journal_changes WHERE book_id=$1",
                &[&book]
            )
            .is_err()
        );
    }
    let doc=run("create-document",json!({"request_id":"invoice","kind":"receivable","number":"INV1","contact_id":"customer","date":"2026-10-01","due":"2026-10-31","lines":[{"account":"4000","amount":"100"}]})).unwrap();
    let pay=run("record-payment",json!({"request_id":"payment","document_id":"invoice","bank_account":"1000","date":"2026-10-12","amount":"40"})).unwrap();
    let dedit = json!({"journal_id":doc["journal_id"],"request_id":"invoice-edit","expected_revision":0,"date":"2026-10-01","due":"2026-11-01","number":"INV1","contact_id":"customer","lines":[{"account":"4000","amount":"80"}]});
    let mut bad = dedit.clone();
    bad["lines"][0]["amount"] = json!("30");
    assert!(run("edit-document", bad).is_err());
    run("edit-document", dedit).unwrap();
    assert_eq!(
        run("documents", json!({})).unwrap()["rows"][0]["outstanding"],
        "40.00"
    );
    let delete_doc = json!({"journal_id":doc["journal_id"],"request_id":"invoice-delete","expected_revision":1,"reason":"Duplicate"});
    assert!(run("delete-document", delete_doc.clone()).is_err());
    assert!(run("delete-journal",json!({"journal_id":doc["journal_id"],"request_id":"wrong-source","expected_revision":1,"reason":"wrong"})).is_err());
    run("edit-payment",json!({"journal_id":pay["journal_id"],"request_id":"payment-edit","expected_revision":0,"date":"2026-10-12","document_id":"invoice","bank_account":"1000","amount":"20"})).unwrap();
    assert_eq!(
        run("documents", json!({})).unwrap()["rows"][0]["outstanding"],
        "60.00"
    );
    run("void-payment",json!({"journal_id":pay["journal_id"],"request_id":"payment-void","expected_revision":1,"reason":"Not received"})).unwrap();
    assert_eq!(
        run("documents", json!({})).unwrap()["rows"][0]["outstanding"],
        "80.00"
    );
    run("delete-document", delete_doc).unwrap();
    assert_eq!(
        run("documents", json!({})).unwrap()["rows"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert!(
        !run("journals", json!({})).unwrap()["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == doc["journal_id"])
    );
    assert!(
        run("journals", json!({"include_deleted":true})).unwrap()["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == doc["journal_id"] && r["status"] == "deleted")
    );
    run("bank-create",json!({"id":"bank","name":"Bank","ledger_account":"1000","import_from":"2026-10-01","statement_account_id":"123"})).unwrap();
    let preview=run("bank-preview",json!({"bank_id":"bank","format":"csv","content":"Date,Description,Amount,ID\n2026-10-20,Sale,50.00,1\n"})).unwrap();
    run(
        "bank-commit",
        json!({"id":preview["id"],"hash":preview["hash"]}),
    )
    .unwrap();
    let bid = run("bank-transactions", json!({"bank_id":"bank"})).unwrap()["rows"][0]["id"].clone();
    let bankpost = run("bank-post", json!({"id":bid,"account":"4000"})).unwrap();
    let mut delete = json!({"journal_id":bankpost["journal_id"],"request_id":"bank-delete","expected_revision":0,"reason":"Reclassify"});
    assert!(run("delete-journal", delete.clone()).is_err());
    delete["unmatch"] = json!(true);
    run("delete-journal", delete).unwrap();
    assert_eq!(
        run("bank-transactions", json!({"bank_id":"bank"})).unwrap()["rows"][0]["state"],
        "unmatched"
    );
    assert!(
        run(
            "bank-match",
            json!({"id":bid,"journal_id":bankpost["journal_id"]})
        )
        .is_err()
    );
    let replacement = run("bank-post", json!({"id":bid,"account":"4000"})).unwrap();
    assert_ne!(replacement["journal_id"], bankpost["journal_id"]);
    assert_eq!(
        run("bank-post", json!({"id":bid,"account":"4000"})).unwrap()["replayed"],
        true
    );
    assert_eq!(
        run("trial-balance", json!({"as_of":"2026-10-31"})).unwrap()["debit"],
        "50.00"
    );
    run(
        "reopen-period",
        json!({"date":null,"expected_lock_date":"2026-09-30","reason":"Open all periods"}),
    )
    .unwrap();
    println!(
        "PASS: edits, idempotency, stale revisions, date boundaries, reopen controls, audit guards, source integrity, payment balances, bank unmatch/repost, deleted visibility"
    );
}
