//! Synthetic DKIM2 recipes: exact sequence oracle, canonical reconstruction,
//! JSON compatibility and resource limits. No DNS, provider or live mail access.
#[path = "../src/mailauth/dkim2/native_diff.rs"]
mod native_diff;
use native_diff::{Budget, Edit};
use workglen_mail::mailauth::dkim2::{self, BodyRecipe, Message as AuthenticatedMessage, Recipe};

fn check_sequence(old: &[&[u8]], new: &[&[u8]]) {
    let edits = native_diff::diff(old, new, &mut Budget::default()).unwrap();
    let mut result = Vec::new();
    let mut copied = 0;
    for edit in edits {
        match edit {
            Edit::Copy { start, len } => {
                result.extend_from_slice(&old[start..start + len]);
                copied += len;
            }
            Edit::Insert { start, len } => result.extend_from_slice(&new[start..start + len]),
        }
    }
    assert_eq!(result, new, "old={old:?} new={new:?}");
    // Independent dynamic-programming LCS oracle, only for small test inputs.
    let mut lcs = vec![vec![0; new.len() + 1]; old.len() + 1];
    for (i, a) in old.iter().enumerate() {
        for (j, b) in new.iter().enumerate() {
            lcs[i + 1][j + 1] = if a == b {
                lcs[i][j] + 1
            } else {
                lcs[i][j + 1].max(lcs[i + 1][j])
            };
        }
    }
    assert_eq!(copied, lcs[old.len()][new.len()], "nonminimal script");
}

#[test]
fn exhaustive_short_sequences_match_independent_lcs_oracle() {
    let alphabet = [b"".as_slice(), b"repeat", "é\0".as_bytes()];
    let mut sequences = vec![Vec::new()];
    for len in 1..=4 {
        for mut value in 0..3usize.pow(len) {
            let mut seq = Vec::new();
            for _ in 0..len {
                seq.push(alphabet[value % 3]);
                value /= 3;
            }
            sequences.push(seq);
        }
    }
    for old in &sequences {
        for new in &sequences {
            check_sequence(old, new);
        }
    }
}

#[test]
fn seeded_sequences_cover_repetitions_binary_and_reordering() {
    let words = [
        b"".as_slice(),
        b"a",
        b"b",
        b"c",
        b"\xff\0",
        b"\r\n",
        "日本語".as_bytes(),
    ];
    let mut seed = 0x3344_aaee_eeff_7711u64;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed as usize
    };
    for _ in 0..2000 {
        let old: Vec<_> = (0..rng() % 70)
            .map(|_| words[rng() % words.len()])
            .collect();
        let new: Vec<_> = (0..rng() % 70)
            .map(|_| words[rng() % words.len()])
            .collect();
        check_sequence(&old, &new);
    }
}

fn message(body: &[u8], headers: &[u8]) -> Vec<u8> {
    let mut raw = b"From: sender@example.test\r\nTo: reader@example.test\r\n".to_vec();
    raw.extend_from_slice(headers);
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(body);
    raw
}
fn hashes(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    dkim2::hashes(&AuthenticatedMessage::parse(raw).unwrap())
}
fn reconstruct(original: &[u8], modified: &[u8]) -> Recipe {
    let old = AuthenticatedMessage::parse(original).unwrap();
    let new = AuthenticatedMessage::parse(modified).unwrap();
    let recipe = Recipe::diff(&old, &new);
    let mut json = Vec::new();
    recipe.to_json(&mut json).unwrap();
    let parsed = Recipe::from_json(&json).unwrap();
    assert_eq!(parsed, recipe);
    let restored = parsed.apply(&new.headers, new.raw_body()).unwrap();
    assert_eq!(hashes(original), hashes(&restored));
    recipe
}

#[test]
fn recipes_reconstruct_folded_repeated_unicode_and_empty_inputs() {
    for body in [
        b"".as_slice(),
        b"\r\n",
        b"a\r\na\r\nb\r\n",
        "é\r\n日本語\r\n".as_bytes(),
        b"a\0b\r\n",
    ] {
        for changed in [b"".as_slice(), b"a\r\nb\r\na\r\n", b"banner\r\n"] {
            let old = message(
                body,
                b"Subject: original\r\nX-Tag: first\r\nX-Tag: folded\r\n value\r\n",
            );
            let new = message(
                changed,
                b"Subject: changed\r\nX-Tag: added\r\nX-Tag: first\r\n",
            );
            reconstruct(&old, &new);
        }
    }
}

#[test]
fn unchanged_binary_is_copied_and_lossy_literal_is_unreconstructable() {
    let original = message(b"\xff\xfe\r\na\r\n", b"Subject: original\r\n");
    let modified = message(b"banner\r\n\xff\xfe\r\na\r\n", b"Subject: original\r\n");
    reconstruct(&original, &modified);
    let modified = message(b"replacement\r\n", b"Subject: original\r\n");
    let a = AuthenticatedMessage::parse(&original).unwrap();
    let b = AuthenticatedMessage::parse(&modified).unwrap();
    let r = Recipe::diff(&a, &b);
    assert_eq!(r.body, BodyRecipe::Unreconstructable);
    assert!(r.apply(&b.headers, b.raw_body()).is_err());
}

#[test]
fn large_changes_use_lossless_linear_fallback() {
    let old_body = "original é\r\n".repeat(3000);
    let new_body = "different\r\n".repeat(3000);
    let old = message(old_body.as_bytes(), b"Subject: unchanged\r\n");
    let new = message(new_body.as_bytes(), b"Subject: unchanged\r\n");
    let recipe = reconstruct(&old, &new);
    assert!(matches!(recipe.body, BodyRecipe::Steps(ref s) if s.len()==1));
}

#[test]
fn generation_caps_mark_unreconstructable_without_affecting_recipe_reader() {
    let old = message(b"old\r\n", b"");
    let huge = message(&vec![b'\n'; native_diff::MAX_ITEMS], b"");
    let a = AuthenticatedMessage::parse(&old).unwrap();
    let b = AuthenticatedMessage::parse(&huge).unwrap();
    assert_eq!(Recipe::diff(&a, &b).body, BodyRecipe::Unreconstructable);
    // The raw-size cap is checked before any line collection or diff search.
    let huge = message(&vec![b'x'; 64 * 1024 * 1024], b"");
    let b = AuthenticatedMessage::parse(&huge).unwrap();
    assert_eq!(Recipe::diff(&a, &b).body, BodyRecipe::Unreconstructable);
    let null = Recipe::from_json(br#"{"b":null}"#).unwrap();
    assert_eq!(null.body, BodyRecipe::Unreconstructable);
    assert!(null.apply(&a.headers, a.raw_body()).is_err());
}

#[test]
fn malformed_recipes_are_rejected_and_ranges_stay_bounded() {
    for input in [
        b"".as_slice(),
        b"{",
        br#"{"b":[{"c":[-1,2]}]}"#,
        br#"{"b":[{"c":[1,4294967296]}]}"#,
        br#"{"b":true}"#,
        br#"{"b":[{"c":[1]}]}"#,
    ] {
        assert!(Recipe::from_json(input).is_err(), "accepted {input:?}");
    }
    // Upstream deliberately ignores unknown/scalar steps for forward compatibility.
    assert_eq!(
        Recipe::from_json(br#"{"b":[{},-1,true,null]}"#)
            .unwrap()
            .body,
        BodyRecipe::Steps(Vec::new())
    );
    // Exercise the existing in-memory application API's clamping semantics.
    use workglen_mail::mailauth::dkim2::Step;
    let r = Recipe {
        headers: Vec::new(),
        body: BodyRecipe::Steps(vec![Step::Copy {
            start: 0,
            end: u32::MAX,
        }]),
    };
    assert_eq!(
        r.apply(&[], b"one\r\ntwo\r\n").unwrap(),
        b"\r\none\r\ntwo\r\n"
    );
}

#[test]
fn signed_two_hop_chain_verifies_reconstruction_and_rejects_tampering() {
    use dkim2::{Envelope, Hop, Signer, Status};
    use workglen_mail::mailauth::{Dns, crypto::SigningKey};
    struct Zone;
    impl Dns for Zone {
        async fn lookup(
            &self,
            name: &str,
            _: workglen_dns::RecordType,
        ) -> workglen_dns::Result<Vec<workglen_dns::RData>> {
            let seed = if name.contains("origin.example.test") {
                7
            } else if name.contains("gateway.example.test") {
                9
            } else {
                panic!("unexpected DNS query")
            };
            Ok(vec![workglen_dns::RData::TXT(workglen_dns::TXT {
                txt_data: vec![SigningKey::ed25519(&[seed; 32]).dns_record().into_bytes()],
            })])
        }
    }
    let a = Signer::new("origin.example.test", "s", SigningKey::ed25519(&[7; 32]));
    let b = Signer::new("gateway.example.test", "s", SigningKey::ed25519(&[9; 32]));
    pratique::asyncio::block_on(async {
        for repeat in [3, 3000] {
            let raw = String::from_utf8(message(
                "original é\r\n".repeat(repeat).as_bytes(),
                b"Subject: original\r\n",
            ))
            .unwrap();
            let first = a
                .sign(raw.as_bytes(), Hop::imaginary("gateway.example.test"))
                .unwrap();
            let original = format!("{}{raw}", first.to_header());
            let modified = original
                .replace("Subject: original", "Subject: revised")
                .replace("original é\r\n", "revised text\r\n");
            let env = Envelope::new("<bounce@gateway.example.test>", ["<reader@example.test>"]);
            let second = b
                .sign_revised(
                    original.as_bytes(),
                    modified.as_bytes(),
                    Hop::Real(env.clone()),
                )
                .unwrap();
            assert!(second.message_instance.is_some());
            let signed = format!("{}{modified}", second.to_header());
            let result = dkim2::verify(
                signed.as_bytes(),
                &Zone,
                &env,
                workglen_mail::mailauth::now(),
            )
            .await;
            assert_eq!(result.status, Status::Pass, "{}", result.detail);
            assert_eq!(result.chain.len(), 2);
            assert_ne!(
                dkim2::verify(
                    format!("{signed}tampered\r\n").as_bytes(),
                    &Zone,
                    &env,
                    workglen_mail::mailauth::now()
                )
                .await
                .status,
                Status::Pass
            );
        }
    });
}
