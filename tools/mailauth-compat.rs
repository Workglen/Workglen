//! Development-only differential oracle. Link the cached pre-change mail-auth,
//! ed25519-dalek, curve25519-dalek and SHA-2 rlibs under the aliases below.
//! These are not dependencies of Workglen or its normal test suite.
use old_mail_auth as old;
use mail_auth as native;
use serde_json::Value;
use pratique::crypto::{ed25519, sha2::{Hash, Sha512}};
use old_curve::{constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION}, scalar::Scalar};

fn hex(s: &str) -> Vec<u8> { s.as_bytes().chunks_exact(2).map(|v|u8::from_str_radix(std::str::from_utf8(v).unwrap(),16).unwrap()).collect() }
fn text<'a>(v:&'a Value,k:&str)->&'a str {v[k].as_str().unwrap()}
macro_rules! check {
    ($lib:ident, $record:expr, $message:expr, $signature:expr, $alg:expr) => {{
        use $lib::common::{parse::TxtRecordParser, verify::DomainKey, crypto::Algorithm};
        DomainKey::parse($record).map(|k|k.p.verify_bytes($message,$signature,Algorithm::parse($alg).unwrap()).is_ok()).ok()
    }};
}

#[test]
fn same_signatures_hashes_and_malformed_inputs_as_previous_provider() {
    let f:Value=serde_json::from_str(include_str!("../tests/fixtures/mailauth-crypto.json")).unwrap();
    let mut checks=0;
    for v in f["vectors"].as_array().unwrap() {
        let record=text(v,"record").as_bytes();let msg=hex(text(v,"message"));let sig=hex(text(v,"signature"));let a=text(v,"algorithm").as_bytes();
        assert_eq!(check!(old,record,&msg,&sig,a),Some(true));
        assert_eq!(check!(native,record,&msg,&sig,a),Some(true)); checks+=1;
        for i in 0..sig.len() {
            let mut changed=sig.clone();changed[i]^=1;
            assert_eq!(check!(old,record,&msg,&changed,a),check!(native,record,&msg,&changed,a),"{} byte {i}",v["label"]);checks+=1;
        }
    }
    let mut state=0x5678_abcdef01u64;
    let mut byte=|| {state^=state<<13;state^=state>>7;state^=state<<17;state as u8};
    for size in 0..2048 {
        let bytes=(0..size).map(|_|byte()).collect::<Vec<_>>();
        for (o,n) in [(old::common::crypto::HashAlgorithm::Sha1,native::common::crypto::HashAlgorithm::Sha1),(old::common::crypto::HashAlgorithm::Sha256,native::common::crypto::HashAlgorithm::Sha256)] {
            assert_eq!(o.hash(bytes.as_slice()).as_ref(),n.hash(bytes.as_slice()).as_ref());checks+=1;
        }
    }
    for _ in 0..2000 {
        let key:[u8;32]=std::array::from_fn(|_|byte());let sig:[u8;64]=std::array::from_fn(|_|byte());let message=[byte();16];
        let record=format!("v=DKIM1;k=ed25519;p={}",pratique::pem::base64_encode(&key));
        assert_eq!(check!(old,record.as_bytes(),&message,&sig,b"ed25519-sha256"),check!(native,record.as_bytes(),&message,&sig,b"ed25519-sha256"));checks+=1;
    }
    println!("{checks} old/new provider comparisons passed");
}

#[test]
fn strict_ed25519_matches_previous_dalek_on_mixed_and_small_order_points() {
    // Construct mixed-order points with the independent former curve library.
    // Vary torsion and nonce: some cofactorless equations balance, some do not.
    let mut accepted=0;let mut checked=0;
    for t in 0..8 {for u in 0..8 {for nonce in 1..12u64 {
        let a=Scalar::from(42u64);let r=Scalar::from(nonce);
        let public=(ED25519_BASEPOINT_POINT*a+EIGHT_TORSION[t]).compress().to_bytes();
        let big_r=(ED25519_BASEPOINT_POINT*r+EIGHT_TORSION[u]).compress().to_bytes();
        let message=b"synthetic mixed-order differential fixture";
        let mut h=Sha512::new();h.update(&big_r);h.update(&public);h.update(message);
        let digest:[u8;64]=h.finalize().try_into().unwrap();
        let k=Scalar::from_bytes_mod_order_wide(&digest);
        let mut sig=[0;64];sig[..32].copy_from_slice(&big_r);sig[32..].copy_from_slice(&(r+k*a).to_bytes());
        let key=old_ed25519::VerifyingKey::from_bytes(&public).unwrap();
        let expected=key.verify_strict(message,&old_ed25519::Signature::from_bytes(&sig)).is_ok();
        assert_eq!(ed25519::verify_strict(&public,message,&sig),expected,"{t} {u} {nonce}");
        accepted+=usize::from(expected);checked+=1;
        let mut malleable=sig;
        // S + L must be rejected even when the ordinary signature is valid.
        let l=hex("edd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000010");
        let mut carry=0u16;for i in 0..32 {let n=malleable[32+i] as u16+l[i] as u16+carry;malleable[32+i]=n as u8;carry=n>>8;}
        assert!(!ed25519::verify_strict(&public,message,&malleable));
    }}}
    for p in EIGHT_TORSION {
        let public=p.compress().to_bytes();let mut sig=[0;64];sig[0]=1;
        let key=old_ed25519::VerifyingKey::from_bytes(&public).unwrap();
        assert!(key.verify_strict(b"fixture",&old_ed25519::Signature::from_bytes(&sig)).is_err());
        assert!(!ed25519::verify_strict(&public,b"fixture",&sig));checked+=1;
    }
    assert!(accepted>11);
    println!("{checked} mixed/small-order comparisons, {accepted} valid mixed-order signatures");
}

#[test]
fn signing_adapters_match_the_previous_provider_and_independent_signature() {
    use native::common::crypto::SigningKey as _;
    use old::common::crypto::SigningKey as _;
    let f:Value=serde_json::from_str(include_str!("../tests/fixtures/mailauth-crypto.json")).unwrap();
    let bytes=hex(text(&f,"private_test_key"));
    let o=old::common::crypto::RsaKey::<old::common::crypto::Sha256>::from_key_der(
        rustls_pki_types::PrivateKeyDer::Pkcs8(bytes.clone().into())).unwrap();
    let n=native::common::crypto::RsaKey::<native::common::crypto::Sha256>::from_key_der(
        rustls_pki_types::PrivateKeyDer::Pkcs8(bytes.into())).unwrap();
    assert_eq!(o.public_key(),n.public_key());
    let fixture=f["vectors"].as_array().unwrap().iter().find(|v|text(v,"label")=="rsa-2048-spki-rsa-sha256").unwrap();
    let message=hex(text(fixture,"message"));let signature=hex(text(fixture,"signature"));
    assert_eq!(o.sign(message.as_slice()).unwrap(),signature);
    assert_eq!(n.sign(message.as_slice()).unwrap(),signature);
    for seed in [[0u8;32],[1;32],[255;32]] {
        let key=old_ed25519::SigningKey::from_bytes(&seed);
        let public=key.verifying_key().to_bytes();
        let o=old::common::crypto::Ed25519Key::from_seed_and_public_key(&seed,&public).unwrap();
        let n=native::common::crypto::Ed25519Key::from_seed_and_public_key(&seed,&public).unwrap();
        assert_eq!(o.sign(message.as_slice()).unwrap(),n.sign(message.as_slice()).unwrap());
        assert_eq!(o.public_key(),n.public_key());
    }
}
