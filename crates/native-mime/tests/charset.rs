//! Former-engine output/error fingerprints for 2,883,056 deterministic cases.
#![allow(dead_code)]
#[path = "../src/charset.rs"]
mod charset;
mod charset_corpus;
#[path = "../src/transfer.rs"]
mod transfer;
use pratique::crypto::sha2::{Hash, Sha256};
#[test]
fn pinned_charset_contracts() {
    let mut hashes = std::collections::BTreeMap::<String, (u64, Sha256)>::new();
    charset_corpus::cases(|label, bytes| {
        let (text, bad) = charset::decode(bytes, Some(label));
        let (n, h) = hashes
            .entry(label.into())
            .or_insert_with(|| (0, Sha256::new()));
        *n += 1;
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(bytes);
        h.update(&(text.len() as u64).to_le_bytes());
        h.update(text.as_bytes());
        h.update(&[u8::from(bad)]);
    });
    let mut actual = String::new();
    let mut total = 0;
    for (label, (n, h)) in hashes {
        total += n;
        let digest: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        actual += &format!("{label} {n} {digest}\n");
    }
    assert_eq!(actual, include_str!("charset-golden.txt"));
    assert_eq!(total, 2_883_056);
}
#[test]
fn malformed_sequences_preserve_ascii_delimiters() {
    for label in ["shift_jis", "big5", "gb18030", "euc-kr"] {
        assert_eq!(
            charset::decode(&[0x81, b'"'], Some(label)),
            ("\u{fffd}\"".into(), true)
        );
    }
    assert_eq!(
        charset::decode(&[0xff, 0xfe, b'a'], Some("windows-1252")),
        ("\u{fffd}".into(), true)
    );
    assert!(charset::decode(b"valid ASCII", Some("unknown-charset")).1);
}
