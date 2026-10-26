//! Development-only oracle against bincode 1.3.3. In a disposable copy of the
//! preceding checkpoint, copy this file and src/replication_codec.rs, then add:
//! [[test]] name = "replication_codec_compat"
//! path = "tools/replication-codec-compat.rs"
//! Run cargo test --offline --locked --release --jobs 1
//! --test replication_codec_compat -- --nocapture.
//! bincode is not a dependency of the current build or normal test suite.
mod store {
    pub use workglen_mail::store::Op;
}
#[path = "../src/replication_codec.rs"]
mod replication_codec;
use bincode::Options;
use replication_codec::{MAX_ENCODED_BYTES, decode, encode};
use store::Op;

fn old_decode(bytes: &[u8]) -> Option<Vec<Op>> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_ENCODED_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .ok()
}
fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
fn operations(seed: &mut u64) -> Vec<Op> {
    let keys = ["", "a", "café/日本語\0", "repeated", "😀", "a/b\r\n"];
    (0..next(seed) % 12)
        .map(|_| {
            let key = keys[next(seed) as usize % keys.len()].to_owned();
            let value = if next(seed) % 3 == 0 {
                None
            } else {
                Some((0..next(seed) % 128).map(|_| next(seed) as u8).collect())
            };
            Op { key, value }
        })
        .collect()
}
#[test]
fn valid_frames_match_the_previous_serializer_and_decoder() {
    let mut seed = 0x123456789abcdef;
    for _ in 0..10_000 {
        let ops = operations(&mut seed);
        let old = bincode::serialize(&ops).unwrap();
        let new = encode(&ops).unwrap();
        assert_eq!(old, new);
        assert_eq!(decode(&old).unwrap(), ops);
        assert_eq!(old_decode(&new).unwrap(), ops);
    }
    let ops = vec![Op {
        key: "a".into(),
        value: Some(vec![7; MAX_ENCODED_BYTES - 26]),
    }];
    let old = bincode::serialize(&ops).unwrap();
    assert_eq!(old.len(), MAX_ENCODED_BYTES);
    assert_eq!(encode(&ops).unwrap(), old);
    assert_eq!(decode(&old).unwrap(), ops);
    assert_eq!(old_decode(&old).unwrap(), ops);
    println!(
        "10,000 generated operation lists and exact 24 MiB boundary: byte identity and bidirectional decode passed"
    );
}
#[test]
fn malformed_and_mutated_frames_have_the_same_acceptance() {
    let mut seed = 0xfedcba987654321;
    let mut checks = 0;
    let mut check = |bytes: &[u8]| {
        assert_eq!(decode(bytes).ok(), old_decode(bytes));
        checks += 1;
    };
    for _ in 0..300 {
        let ops = operations(&mut seed);
        let bytes = bincode::serialize(&ops).unwrap();
        for n in 0..bytes.len() {
            check(&bytes[..n]);
        }
        for _ in 0..40 {
            let mut changed = bytes.clone();
            let i = next(&mut seed) as usize % changed.len();
            changed[i] ^= (next(&mut seed) as u8) | 1;
            check(&changed);
        }
        let mut trailing = bytes;
        trailing.push(0);
        check(&trailing);
    }
    for size in 0..512 {
        let bytes: Vec<u8> = (0..size).map(|_| next(&mut seed) as u8).collect();
        check(&bytes);
    }
    println!(
        "{checks} truncation, mutation, trailing and random-frame acceptance comparisons passed"
    );
}
