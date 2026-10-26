mod support;
use workglen_mail::{
    replication_codec::{self as codec, Error, MAX_ENCODED_BYTES},
    store::{Op, Store},
};

// Independently specified legacy little-endian frame: put "a"=[0,255], delete "z".
const GOLDEN: &[u8] = &[
    2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, b'a', 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 255, 1, 0,
    0, 0, 0, 0, 0, 0, b'z', 0,
];
fn operations() -> Vec<Op> {
    vec![
        Op {
            key: "a".into(),
            value: Some(vec![0, 255]),
        },
        Op::del("z".into()),
    ]
}

#[test]
fn persisted_format_is_exact_and_preserves_empty_unicode_and_binary_values() {
    assert_eq!(codec::encode(&operations()).unwrap(), GOLDEN);
    assert_eq!(codec::decode(GOLDEN).unwrap(), operations());
    assert_eq!(codec::encode(&[]).unwrap(), [0; 8]);
    assert!(codec::decode(&[0; 8]).unwrap().is_empty());
    let ops = vec![
        Op {
            key: "café/日本語\0".into(),
            value: Some((0..=255).collect()),
        },
        Op {
            key: String::new(),
            value: Some(vec![]),
        },
        Op::del(String::new()),
    ];
    assert_eq!(codec::decode(&codec::encode(&ops).unwrap()).unwrap(), ops);
}

#[test]
fn malformed_frames_are_rejected_before_any_database_change() {
    let dir = support::tempdir().unwrap();
    let db = Store::open(&dir.path().join("db"), "test-cluster-0001").unwrap();
    db.write(|_| Ok((vec![Op::json("existing".into(), &42)?], ())))
        .unwrap();
    let seq = db.seq().unwrap();
    let mut bad = Vec::new();
    for n in 0..GOLDEN.len() {
        bad.push(GOLDEN[..n].to_vec());
    }
    let mut trailing = GOLDEN.to_vec();
    trailing.push(0);
    bad.push(trailing);
    let mut tag = GOLDEN.to_vec();
    tag[17] = 2;
    bad.push(tag);
    let mut utf8 = GOLDEN.to_vec();
    utf8[16] = 0xff;
    bad.push(utf8);
    for start in [0, 8, 18] {
        let mut length = GOLDEN.to_vec();
        length[start..start + 8].fill(255);
        bad.push(length);
    }
    for frame in bad {
        assert!(codec::decode(&frame).is_err());
        assert!(db.replay(seq + 1, &frame).is_err());
        assert_eq!(db.seq().unwrap(), seq);
        assert_eq!(db.get::<i64>("existing").unwrap(), Some(42));
        assert!(
            db.get::<pratique::json_value::Value>("a")
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn exact_transaction_limit_and_oversize_refusal() {
    // count + key length + one-byte key + option + value length = 26 bytes.
    let mut ops = vec![Op {
        key: "a".into(),
        value: Some(vec![7; MAX_ENCODED_BYTES - 26]),
    }];
    let bytes = codec::encode(&ops).unwrap();
    assert_eq!(bytes.len(), MAX_ENCODED_BYTES);
    assert_eq!(codec::decode(&bytes).unwrap(), ops);
    ops[0].value.as_mut().unwrap().push(7);
    assert_eq!(codec::encode(&ops), Err(Error::TooLarge));
    let mut oversized = bytes;
    oversized.push(0);
    assert_eq!(codec::decode(&oversized), Err(Error::TooLarge));
    let dir = support::tempdir().unwrap();
    let db = Store::open(&dir.path().join("db"), "test-cluster-0001").unwrap();
    let before = db.seq().unwrap();
    assert!(db.write(|_| Ok((ops, ()))).is_err());
    assert_eq!(db.seq().unwrap(), before);
    assert!(db.log(before + 1).unwrap().is_none());
}

#[test]
fn legacy_frame_replays_and_log_bytes_survive_reopen() {
    let dir = support::tempdir().unwrap();
    let path = dir.path().join("db");
    let db = Store::open(&path, "test-cluster-0001").unwrap();
    let (seq, ()) = db.write(|_| Ok((operations(), ()))).unwrap();
    assert_eq!(db.log(seq).unwrap().unwrap(), GOLDEN);
    drop(db);
    let db = Store::open(&path, "test-cluster-0001").unwrap();
    assert_eq!(db.log(seq).unwrap().unwrap(), GOLDEN);
    let other = support::tempdir().unwrap();
    let replica = Store::open(&other.path().join("db"), "test-cluster-0001").unwrap();
    replica.replay(1, GOLDEN).unwrap();
    assert_eq!(replica.seq().unwrap(), 1);
    assert!(replica.replay(1, GOLDEN).is_err());
}
