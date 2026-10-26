mod support;
use std::time::{Duration, Instant};
use workglen_mail::{
    config::{self, Limits, Message},
    imap,
    store::{self, Op, Store},
    witness::State,
};
#[test]
fn journal_replay_is_atomic_and_rejects_gaps() {
    let a = support::tempdir().unwrap();
    let b = support::tempdir().unwrap();
    let leader = Store::open(&a.path().join("db"), "test-cluster-0001").unwrap();
    let replica = Store::open(&b.path().join("db"), "test-cluster-0001").unwrap();
    let (seq, _) = leader
        .write(|_| {
            Ok((
                vec![
                    Op::json("key/a".into(), &42u64)?,
                    Op::json("key/b".into(), &43u64)?,
                ],
                (),
            ))
        })
        .unwrap();
    let frame = leader.log(seq).unwrap().unwrap();
    assert!(replica.replay(seq + 1, &frame).is_err());
    assert_eq!(replica.seq().unwrap(), 0);
    replica.replay(seq, &frame).unwrap();
    assert_eq!(replica.get::<u64>("key/a").unwrap(), Some(42));
    assert_eq!(replica.get::<u64>("key/b").unwrap(), Some(43));
    assert!(replica.replay(seq, &frame).is_err());
    drop(replica);
    let reopened = Store::open(&b.path().join("db"), "test-cluster-0001").unwrap();
    assert_eq!(reopened.seq().unwrap(), 1);
    assert_eq!(reopened.get::<u64>("key/a").unwrap(), Some(42));
}
#[test]
fn quota_failure_does_not_commit_body_or_sequence() {
    let d = support::tempdir().unwrap();
    let s = Store::open(&d.path().join("db"), "test-cluster-0001").unwrap();
    s.add_user("a@example.test", "dummy", 10).unwrap();
    let before = s.seq().unwrap();
    let result = s.write(|t| {
        let (ops, _, _) = store::append_ops(
            t,
            "a@example.test",
            "INBOX",
            "too-big",
            11,
            vec![],
            0,
            &Limits::default(),
        )?;
        Ok((ops, ()))
    });
    assert!(result.is_err());
    assert_eq!(s.seq().unwrap(), before);
    assert!(s.messages("a@example.test", "INBOX").unwrap().is_empty());
}
#[test]
fn uid_state_survives_restart_and_changes_on_promotion() {
    let d = support::tempdir().unwrap();
    let path = d.path().join("db");
    let s = Store::open(&path, "test-cluster-0001").unwrap();
    s.add_user("a@example.test", "dummy", 1000).unwrap();
    let old = s
        .get::<config::Folder>(&store::folder_key("a@example.test", "INBOX"))
        .unwrap()
        .unwrap();
    s.write(|t| {
        let (ops, _, uid) = store::append_ops(
            t,
            "a@example.test",
            "INBOX",
            "b",
            5,
            vec![],
            0,
            &Limits::default(),
        )?;
        assert_eq!(uid, 1);
        Ok((ops, ()))
    })
    .unwrap();
    drop(s);
    let s = Store::open(&path, "test-cluster-0001").unwrap();
    s.begin_term(1).unwrap();
    let new = s
        .get::<config::Folder>(&store::folder_key("a@example.test", "INBOX"))
        .unwrap()
        .unwrap();
    assert_ne!(old.validity, new.validity);
    assert_eq!(new.next_uid, 2);
    assert_eq!(s.messages("a@example.test", "INBOX").unwrap()[0].uid, 1);
}
#[test]
fn witness_never_overlaps_leases_and_waits_after_restart() {
    let now = Instant::now();
    let ttl = Duration::from_secs(15);
    let mut s = State {
        holder: String::new(),
        term: 9,
        until: now,
        startup_until: now + ttl,
    };
    assert!(s.acquire("a", true, now, ttl).is_none());
    assert_eq!(s.acquire("a", true, now + ttl, ttl), Some(10));
    assert!(
        s.acquire("b", true, now + ttl + Duration::from_secs(14), ttl)
            .is_none()
    );
    assert_eq!(s.acquire("b", true, now + ttl + ttl, ttl), Some(11));
    assert!(
        s.acquire("replacement", false, now + ttl * 4, ttl)
            .is_none()
    );
}
#[test]
fn imap_quoted_and_section_grammar_and_reversed_uid_sets() {
    assert_eq!(
        imap::tokens("a LOGIN \"user name\" \"p\\\"ass\"").unwrap(),
        ["a", "LOGIN", "user name", "p\"ass"]
    );
    assert_eq!(
        imap::tokens("BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)] UID")
            .unwrap()
            .len(),
        2
    );
    assert!(imap::tokens("(FLAGS UID").is_err());
    assert!(imap::in_set("*:3", 4, 8).unwrap());
    assert!(imap::in_set("0", 1, 8).is_err());
    assert!(imap::in_set("1:4294967295", 5, 8).unwrap());
    assert!(imap::flags("(\\Recent)").is_err());
}
#[test]
fn address_and_header_injection_are_rejected() {
    assert!(config::address("evil\r\nRCPT TO:<x@y>@a.test").is_err());
    assert!(config::address("x..y@example.test").is_err());
    assert!(config::folder("../other").is_err());
    assert!(
        workglen_mail::auth::validate(b"From: a@b.test\r\nFrom: b@c.test\r\n\r\nx\r\n").is_err()
    );
    assert!(workglen_mail::auth::validate(b"From: a@b.test\r\nSubject: test\r\n\r\nx\r\n").is_ok());
}
#[test]
fn gc_preserves_shared_message_body() {
    let d = support::tempdir().unwrap();
    let s = Store::open(&d.path().join("db"), "test-cluster-0001").unwrap();
    let m = Message {
        blob: "shared".into(),
        uid: 1,
        flags: vec![],
        size: 5,
        date: 0,
    };
    s.write(|_| {
        Ok((
            vec![
                Op {
                    key: "blob/shared".into(),
                    value: Some(b"hello".to_vec()),
                },
                Op::json("mail/a/INBOX/1".into(), &m)?,
                Op::json("mail/b/INBOX/1".into(), &m)?,
            ],
            (),
        ))
    })
    .unwrap();
    s.write(|t| {
        let deleted = vec!["mail/a/INBOX/1".to_string()];
        let mut ops = store::gc_ops(t, &deleted)?;
        ops.push(Op::del(deleted[0].clone()));
        Ok((ops, ()))
    })
    .unwrap();
    assert_eq!(s.blob("shared").unwrap(), b"hello");
}

#[test]
fn smtp_ehlo_accepts_address_literals_without_injection() {
    assert!(config::greeting("[127.0.0.1]"));
    assert!(config::greeting("[IPv6:::1]"));
    assert!(!config::greeting("[127.0.0.1]\r\nMAIL FROM:<a@b>"));
    assert!(!config::greeting("[999.2.3.4]"));
}
#[test]
fn backup_has_consistent_metadata_and_read_only_export() {
    let d = support::tempdir().unwrap();
    let s = Store::open(&d.path().join("db"), "test-cluster-0001").unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    s.write(|_| {
        Ok((
            vec![Op {
                key: format!("blob/{id}"),
                value: Some(b"From: a@b.test\r\n\r\nbody\r\n".to_vec()),
            }],
            (),
        ))
    })
    .unwrap();
    let path = d.path().join("backup");
    workglen_mail::backup::create(&s, "test-cluster-0001", &path).unwrap();
    let out = d.path().join("export");
    assert_eq!(workglen_mail::backup::export(&path, &out).unwrap(), 1);
    assert!(out.join(format!("{id}.eml")).exists());
    let b = Store::open(&path, "test-cluster-0001").unwrap();
    assert_eq!(b.seq().unwrap(), s.seq().unwrap());
}

#[test]
fn deployment_transitions_require_seeded_data_and_explicit_demotion() {
    use config::Mode;
    let d = support::tempdir().unwrap();
    let s = Store::open(&d.path().join("db"), "test-cluster-0001").unwrap();
    assert!(s.enter_mode(Mode::Single).is_err());
    s.set_meta("ready", 1).unwrap();
    s.enter_mode(Mode::Single).unwrap();
    s.begin_term(1).unwrap();
    s.add_user("a@example.test", "dummy", 1000).unwrap();
    s.enter_mode(Mode::Single).unwrap();
    s.enter_mode(Mode::Dual).unwrap();
    assert!(s.enter_mode(Mode::Single).is_err());
    s.demote_single().unwrap();
    s.enter_mode(Mode::Single).unwrap();
    assert!(
        s.get::<config::User>("user/a@example.test")
            .unwrap()
            .is_some()
    );
    assert_eq!(s.meta("term").unwrap(), 1);
    s.enter_mode(Mode::Dual).unwrap();
    s.set_meta("ready", 0).unwrap();
    assert!(s.demote_single().is_err());
}
#[test]
fn missing_deployment_marker_cannot_allow_an_unfenced_writer() {
    let d = support::tempdir().unwrap();
    let s = Store::open(&d.path().join("db"), "test-cluster-0001").unwrap();
    s.set_meta("ready", 1).unwrap();
    s.begin_term(1).unwrap();
    assert!(s.enter_mode(config::Mode::Single).is_err());
}

#[test]
fn acceptance_rejects_mime_floods_and_shapes_that_imap_cannot_render() {
    use workglen_mail::auth;
    let mut flood =
        b"From: sender@example.test\r\nContent-Type: multipart/mixed; boundary=X\r\n\r\n".to_vec();
    for _ in 0..1100 {
        flood.extend_from_slice(b"--X\r\nContent-Type: text/plain\r\n\r\nx\r\n");
    }
    flood.extend_from_slice(b"--X--\r\n");
    assert!(
        auth::validate(&flood)
            .unwrap_err()
            .to_string()
            .contains("MIME boundaries")
    );
    let nested = |depth| {
        let mut raw = b"From: sender@example.test\r\n".to_vec();
        for n in 0..depth {
            raw.extend_from_slice(
                format!("Content-Type: multipart/mixed; boundary=b{n}\r\n\r\n--b{n}\r\n")
                    .as_bytes(),
            );
        }
        raw.extend_from_slice(b"Content-Type: text/plain\r\n\r\nhello\r\n");
        for n in (0..depth).rev() {
            raw.extend_from_slice(format!("--b{n}--\r\n").as_bytes());
        }
        raw
    };
    assert!(auth::validate(&nested(3)).is_ok());
    assert!(
        auth::validate(&nested(auth::MAX_MIME_DEPTH))
            .unwrap_err()
            .to_string()
            .contains("MIME nesting")
    );
}
