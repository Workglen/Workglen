//! Opt-in, disposable database only. Never points at a user installation.
use lazaret_pg::{Config, IsolationLevel, types::Text};
#[test]
#[ignore = "requires LAZARET_PG_TEST_DSN for a disposable PostgreSQL database"]
fn postgres_sql_types_transactions_streaming_and_errors() {
    let mut cfg: Config = std::env::var("LAZARET_PG_TEST_DSN")
        .unwrap()
        .parse()
        .unwrap();
    if let Ok(ca) = std::env::var("LAZARET_PG_TEST_CA") {
        cfg.ca_file(ca);
    }
    let mut c = cfg.connect().unwrap();
    c.batch_execute("CREATE TEMP TABLE driver_test(id bigint PRIMARY KEY, value text, bytes bytea, n numeric(30,8)); CREATE TEMP TABLE parent(id int PRIMARY KEY); CREATE TEMP TABLE child(id int REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)").unwrap();
    let text = "Lazaret \u{1f331} '; DROP TABLE driver_test; --";
    let bytes = vec![0, 1, 255, 39, 92];
    let exact = Text("1234567890123456789012.12345678".into());
    assert_eq!(
        c.execute(
            "INSERT INTO driver_test VALUES($1,$2,$3,$4::numeric)",
            &[&1i64, &text, &bytes, &exact]
        )
        .unwrap(),
        1
    );
    let row=c.query_one("SELECT id,value,bytes,n::text,NULL::text,true::bool,12::smallint,13::int FROM driver_test",&[]).unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, String>("value"), text);
    assert_eq!(row.get::<_, Vec<u8>>(2), bytes);
    assert_eq!(row.get::<_, String>(3), exact.0);
    assert_eq!(row.get::<_, Option<String>>(4), None);
    assert!(row.get::<_, bool>(5));
    assert_eq!(row.get::<_, i16>(6), 12);
    assert_eq!(row.get::<_, i32>(7), 13);
    assert!(row.try_get::<_, i32>(0).is_err());
    assert!(row.try_get::<_, String>(99).is_err());
    {
        let mut tx = c
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .unwrap();
        tx.execute("INSERT INTO driver_test(id) VALUES($1)", &[&2i64])
            .unwrap();
        {
            let mut nested = tx.transaction().unwrap();
            nested
                .execute("INSERT INTO driver_test(id) VALUES(3)", &[])
                .unwrap();
            nested.rollback().unwrap();
        }
        tx.commit().unwrap();
    }
    {
        let mut tx = c.transaction().unwrap();
        tx.execute("INSERT INTO driver_test(id) VALUES(4)", &[])
            .unwrap();
    }
    assert_eq!(
        c.query_one("SELECT count(*) FROM driver_test", &[])
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    assert_eq!(
        c.execute("INSERT INTO driver_test(id) VALUES(1)", &[])
            .unwrap_err()
            .code(),
        Some("23505")
    );
    assert!(!c.is_closed());
    {
        let mut tx = c.transaction().unwrap();
        assert!(
            tx.execute("INSERT INTO driver_test(id) VALUES(1)", &[])
                .is_err()
        );
        assert!(tx.commit().is_err());
    }
    assert_eq!(c.transaction_status(), b'I');
    {
        let mut tx = c.transaction().unwrap();
        tx.execute("INSERT INTO child VALUES(42)", &[]).unwrap();
        assert_eq!(tx.commit().unwrap_err().code(), Some("23503"));
    }
    assert_eq!(c.transaction_status(), b'I');
    let mut stream = c
        .query_stream("SELECT generate_series(1,1001)::bigint AS n", &[], 37)
        .unwrap();
    let mut sum = 0;
    for row in stream.by_ref() {
        sum += row.unwrap().get::<_, i64>(0);
    }
    assert_eq!(sum, 501501);
    assert_eq!(stream.command().unwrap().rows_affected, 1001);
    drop(stream);
    let a: &[&(dyn lazaret_pg::ToSql + Sync)] = &[&10i64];
    let b: &[&(dyn lazaret_pg::ToSql + Sync)] = &[&11i64];
    assert_eq!(
        c.execute_many("INSERT INTO driver_test(id) VALUES($1)", &[a, b])
            .unwrap(),
        2
    );
    assert!(
        c.execute_many("INSERT INTO driver_test(id) VALUES($1)", &[&[&12i64], a])
            .is_err()
    );
    assert_eq!(
        c.query_one("SELECT count(*) FROM driver_test WHERE id=12", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(
        c.query_opt("SELECT id FROM driver_test WHERE id=999", &[])
            .unwrap()
            .is_none()
    );
    assert!(c.query_one("SELECT id FROM driver_test", &[]).is_err());
    assert!(c.query("SELECT $1::int; SELECT 2", &[&1i32]).is_err());
    assert!(!c.is_closed());
    #[cfg(feature = "with-json")]
    {
        let json = pratique::json_value::json!({"a":[null,true,123],"quote":"'"});
        assert_eq!(
            c.query_one("SELECT $1::jsonb", &[&json])
                .unwrap()
                .get::<_, pratique::json_value::Value>(0),
            json
        );
    }
    c.close().unwrap();
}
