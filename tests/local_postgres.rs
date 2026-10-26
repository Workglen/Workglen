//! Opt-in loopback PostgreSQL regression; use only a disposable database.
use workglen_mail::accounting::{Config, Db, db::Transport};
#[test]
#[ignore = "requires disposable WORKGLEN_LOCAL_TEST_DSN_FILE"]
fn accounting_initializes_and_reopens_over_explicit_local_transport() {
    let db = Db::new(
        Config {
            dsn_file: std::env::var("WORKGLEN_LOCAL_TEST_DSN_FILE").unwrap(),
            ca_file: None,
            feed_key_file: None,
            pool_size: 1,
            transport: Transport::Local,
        },
        "local-postgres-fixture".into(),
    )
    .unwrap();
    let id = db.initialize().unwrap();
    assert_eq!(db.initialize().unwrap(), id);
    assert_eq!(db.status().unwrap()["enabled"], false);
    db.set_enabled(true, Some(0), "fixture-admin").unwrap();
    assert_eq!(db.status().unwrap()["enabled"], true);
}
