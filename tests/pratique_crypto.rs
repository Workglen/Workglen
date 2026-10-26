//! Independent published vectors at Workglen's integration boundary.
use pratique::crypto::{
    gcm::AesGcm,
    hmac::Hmac,
    sha2::{Hash, Sha256},
};
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn aes256_gcm_known_answer_and_authentication_failure() {
    let cipher = AesGcm::new(&[0; 32]);
    let nonce = [0; 12];
    let expected = hex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
    assert_eq!(cipher.seal(&nonce, &[], &[0; 16]), expected);
    assert_eq!(cipher.open(&nonce, &[], &expected).unwrap(), [0; 16]);
    for i in 0..expected.len() {
        let mut bad = expected.clone();
        bad[i] ^= 1;
        assert!(cipher.open(&nonce, &[], &bad).is_none());
    }
    assert!(
        cipher
            .open(&nonce, b"changed associated data", &expected)
            .is_none()
    );
}
#[test]
fn hmac_sha256_rfc4231_case_one() {
    assert_eq!(
        Hmac::<Sha256>::mac(&[0x0b; 20], b"Hi There"),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}

#[test]
fn sha256_known_answers_and_streaming_boundaries() {
    // Published SHA-256 vectors, including padding across a 64-byte block.
    for (input, expected) in [
        (
            b"".as_slice(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".as_slice(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_slice(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ] {
        assert_eq!(Sha256::digest(input), hex(expected));
        assert_eq!(workglen_mail::security::model::hash(input), expected);
        for width in [1, 7, 55, 56, 63, 64, 65] {
            let mut state = Sha256::new();
            for chunk in input.chunks(width) {
                state.update(chunk);
            }
            assert_eq!(state.finalize(), hex(expected));
        }
    }
    let mut state = Sha256::new();
    for _ in 0..1000 {
        state.update(&[b'a'; 1000]);
    }
    assert_eq!(
        state.finalize(),
        hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    );
}

#[test]
fn os_entropy_fills_slices_and_preserves_boundaries() {
    // Smoke-check the actual OS interface, not a statistical RNG certification.
    pratique::crypto::rand::fill(&mut []).unwrap();
    let mut first = [0u8; 1026];
    first[0] = 0x5a;
    first[1025] = 0xa5;
    pratique::crypto::rand::fill(&mut first[1..1025]).unwrap();
    let mut second = [0u8; 1024];
    pratique::crypto::rand::fill(&mut second).unwrap();
    assert_eq!(first[0], 0x5a);
    assert_eq!(first[1025], 0xa5);
    assert_ne!(first[1..1025], [0; 1024]);
    assert_ne!(first[1..1025], second);
}

#[test]
fn persisted_accounting_hash_encoding_is_unchanged() {
    // Fixed digest independently computed from the exact canonical JSON bytes.
    let value = pratique::json_value::json!({"z":"existing audit", "a":1});
    assert_eq!(
        workglen_mail::accounting::model::hash(&value).unwrap(),
        "435c49768e9d328a83e38562b0077bd7ab4ef7a0c35f6b1b8a054281b37df48d"
    );
}
