// SPDX-FileCopyrightText: 2026 Workglen contributors
// SPDX-License-Identifier: Apache-2.0
// Development oracle only: link former and current mail-auth rlibs under
// old_mail_auth and mail_auth. No dependency is added to the application.
extern crate old_mail_auth;
use mail_auth::{AuthenticatedMessage, common::crypto::HashAlgorithm, dkim2::Recipe};

fn hashes(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let msg = AuthenticatedMessage::parse(raw).unwrap();
    (
        HashAlgorithm::Sha256
            .headers_hash(msg.headers.iter().copied())
            .as_ref()
            .to_vec(),
        HashAlgorithm::Sha256
            .body_hash(msg.raw_body())
            .as_ref()
            .to_vec(),
    )
}

#[test]
fn generated_recipes_interoperate_with_previous_implementation() {
    let mut seed = 0xeabc_103a_4455_903du64;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed as usize
    };
    let words = [
        "",
        "a",
        "b",
        "repeated",
        "café",
        "日本語",
        "\0value",
        " spaced ",
    ];
    let mut same = 0;
    let mut different = 0;
    for case in 0..5000 {
        let mut a = String::from("From: origin@example.test\r\nTo: reader@example.test\r\n");
        let mut b = a.clone();
        for raw in [&mut a, &mut b] {
            for _ in 0..rng() % 8 {
                raw.push_str(&format!("X-Tag: {}\r\n", words[rng() % words.len()]));
            }
            raw.push_str("Subject: test\r\n folded\r\n\r\n");
            for _ in 0..rng() % 40 {
                raw.push_str(words[rng() % words.len()]);
                raw.push_str("\r\n");
            }
        }
        let orig = AuthenticatedMessage::parse(a.as_bytes()).unwrap();
        let changed = AuthenticatedMessage::parse(b.as_bytes()).unwrap();
        let old_orig = old_mail_auth::AuthenticatedMessage::parse(a.as_bytes()).unwrap();
        let old_changed = old_mail_auth::AuthenticatedMessage::parse(b.as_bytes()).unwrap();
        let current = Recipe::diff(&orig, &changed);
        let previous = old_mail_auth::dkim2::Recipe::diff(&old_orig, &old_changed);
        let mut current_json = Vec::new();
        current.to_json(&mut current_json).unwrap();
        let mut previous_json = Vec::new();
        previous.to_json(&mut previous_json).unwrap();
        if current_json == previous_json {
            same += 1;
        } else {
            different += 1;
        }
        // Generated scripts can differ where multiple shortest scripts exist.
        // Verify canonical reconstruction by both versions in both directions.
        let expected = hashes(a.as_bytes());
        for json in [&current_json, &previous_json] {
            let new_recipe = Recipe::from_json(json).unwrap();
            let old_recipe = old_mail_auth::dkim2::Recipe::from_json(json).unwrap();
            let new_raw = new_recipe
                .apply(&changed.headers, changed.raw_body())
                .unwrap();
            let old_raw = old_recipe
                .apply(&old_changed.headers, old_changed.raw_body())
                .unwrap();
            assert_eq!(hashes(&new_raw), expected, "new receiver case {case}");
            assert_eq!(hashes(&old_raw), expected, "old receiver case {case}");
            assert_eq!(new_raw, old_raw, "receiver byte mismatch case {case}");
        }
    }
    println!(
        "5000 message pairs; 20000 canonical reconstruction checks; bidirectional JSON compatibility passed"
    );
    println!("Generated recipe JSON: {same} byte-identical, {different} different valid scripts");
}
