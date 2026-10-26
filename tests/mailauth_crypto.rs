//! Synthetic fixtures made by Python cryptography; no network or installed keys.
use pratique::crypto::sha2::{Hash, Sha256};
use pratique::crypto::{ed25519, legacy};
use pratique::json_value::Value;
use workglen_mail::encoding::STANDARD;
use workglen_mail::mailauth::{
    crypto::{Algorithm, SigningKey},
    verify_dkim::{public_key_bits, verify_bytes},
};

fn fixtures() -> Value {
    pratique::json_value::from_str(include_str!("fixtures/mailauth-crypto.json")).unwrap()
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}
fn field<'a>(v: &'a Value, name: &str) -> &'a str {
    v[name].as_str().unwrap()
}

#[test]
fn independent_rsa_and_ed25519_vectors_and_rejections() {
    for v in fixtures()["vectors"].as_array().unwrap() {
        let record = field(v, "record");
        let algorithm = Algorithm::parse(field(v, "algorithm")).unwrap();
        let input = unhex(field(v, "message"));
        let signature = unhex(field(v, "signature"));
        assert!(
            verify_bytes(record, algorithm, &input, &signature).is_ok(),
            "{}",
            v["label"]
        );
        let mut changed = input.clone();
        changed.push(0);
        assert!(verify_bytes(record, algorithm, &changed, &signature).is_err());
        let mut changed = signature.clone();
        changed[0] ^= 1;
        assert!(verify_bytes(record, algorithm, &input, &changed).is_err());
        assert!(
            verify_bytes(record, algorithm, &input, &signature[..signature.len() - 1]).is_err()
        );
        let mut long = signature.clone();
        long.push(0);
        assert!(verify_bytes(record, algorithm, &input, &long).is_err());
        let wrong = if algorithm == Algorithm::Ed25519Sha256 {
            Algorithm::RsaSha256
        } else {
            Algorithm::Ed25519Sha256
        };
        assert!(verify_bytes(record, wrong, &input, &signature).is_err());
        if field(v, "kind") == "rsa" {
            assert_eq!(
                public_key_bits(record).unwrap(),
                v["bits"].as_u64().unwrap() as usize
            );
        }
    }
}

#[test]
fn hash_known_answers_and_streaming_boundaries() {
    for v in fixtures()["hashes"].as_array().unwrap() {
        let input = vec![b'a'; v["length"].as_u64().unwrap() as usize];
        assert_eq!(
            pratique::util::hex(&Sha256::digest(&input)),
            field(v, "sha256")
        );
        for chunk in [1, 7, 55, 64, 65, 127, 4096] {
            let mut sha1 = legacy::Sha1::new();
            let mut sha256 = Sha256::new();
            for part in input.chunks(chunk) {
                sha1.update(part);
                sha256.update(part);
                sha1.update(&[]);
            }
            assert_eq!(pratique::util::hex(&sha1.finalize()), field(v, "sha1"));
            assert_eq!(pratique::util::hex(&sha256.finalize()), field(v, "sha256"));
        }
        let mut h = legacy::Sha1::new();
        h.update(&input);
        assert_eq!(pratique::util::hex(&h.clone().finalize()), field(v, "sha1"));
    }
}

#[test]
fn strict_ed25519_rejects_small_order_without_changing_general_verifier() {
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&identity);
    assert!(ed25519::verify(&identity, b"synthetic", &signature));
    assert!(!ed25519::verify_strict(&identity, b"synthetic", &signature));
    let record = format!("v=DKIM1;k=ed25519;p={}", STANDARD.encode(identity));
    assert!(verify_bytes(&record, Algorithm::Ed25519Sha256, b"synthetic", &signature).is_err());
    for n in [0, 1, 31, 33, 64] {
        assert!(!ed25519::public_key_is_valid(&vec![0; n]));
    }
}

#[test]
fn revoked_malformed_oversized_and_weak_keys_are_refused() {
    for record in [
        "v=DKIM1;k=rsa;p=",
        "v=DKIM1;k=ed25519;p=",
        "v=DKIM1;k=rsa;p=AQID",
        "v=DKIM1;k=ed25519;p=AQID",
    ] {
        assert!(public_key_bits(record).is_err());
    }
    use pratique::asn1::write::{integer, sequence};
    for bits in [512usize, 1023, 1024, 2048, 8192, 8193] {
        let mut modulus = vec![0; bits.div_ceil(8)];
        modulus[0] = 1 << ((bits - 1) % 8);
        *modulus.last_mut().unwrap() |= 1;
        let der = sequence(&[&integer(&modulus), &integer(&[1, 0, 1])]);
        let record = format!("v=DKIM1;k=rsa;p={}", STANDARD.encode(der));
        let parsed = public_key_bits(&record);
        assert_eq!(parsed.is_ok(), (1024..=8192).contains(&bits), "{bits}");
    }
    let v = &fixtures()["vectors"][0];
    let encoded = field(v, "record").split("p=").nth(1).unwrap();
    let mut der = STANDARD.decode(encoded).unwrap();
    der.push(0);
    assert!(public_key_bits(&format!("v=DKIM1;k=rsa;p={}", STANDARD.encode(der))).is_err());
}

#[test]
fn native_ed25519_signing_hashes_once_and_validates_key_identity() {
    use pratique::crypto::ed25519_sign::Ed25519SigningKey;
    let seed = [7; 32];
    let native = Ed25519SigningKey::from_seed(&seed);
    let key = SigningKey::ed25519_checked(&seed, native.public_key()).unwrap();
    assert!(SigningKey::ed25519_checked(&seed, &[0; 32]).is_err());
    let input = b"synthetic DKIM input";
    let expected = native.sign(&Sha256::digest(input));
    assert_eq!(key.sign(input.as_slice()).unwrap(), expected);
    let der = SigningKey::generate_ed25519_pkcs8().unwrap();
    let restored = SigningKey::ed25519_pkcs8(&der).unwrap();
    let record = restored.dns_record();
    assert!(
        verify_bytes(
            &record,
            Algorithm::Ed25519Sha256,
            input,
            &restored.sign(input).unwrap()
        )
        .is_ok()
    );
    let mut invalid = der;
    invalid.push(0);
    assert!(SigningKey::ed25519_pkcs8(&invalid).is_err());
}
