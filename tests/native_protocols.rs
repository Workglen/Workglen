//! Synthetic independent wire fixtures produced by the prior attributed engine.
use std::collections::HashMap;
use workglen_dns::{Error, RData, RecordType, ResponseCode, TXT};
use workglen_mail::mailauth::{
    self, Dns,
    crypto::SigningKey,
    dkim2::{self, Envelope, Hop, Signer, Status},
};
struct Zone(HashMap<String, String>);
impl Dns for Zone {
    async fn lookup(&self, n: &str, k: RecordType) -> Result<Vec<RData>, Error> {
        assert_eq!(k, RecordType::TXT);
        self.0
            .get(n.trim_end_matches('.'))
            .map(|v| {
                vec![RData::TXT(TXT {
                    txt_data: vec![v.as_bytes().to_vec()],
                })]
            })
            .ok_or(Error::NoRecords(ResponseCode::NXDomain))
    }
}
fn fixtures() -> pratique::json_value::Value {
    pratique::json_value::from_str(include_str!("fixtures/mailauth-protocol-reference.json"))
        .unwrap()
}
fn zone(v: &pratique::json_value::Value) -> Zone {
    Zone(
        v["records"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
            .collect(),
    )
}

#[test]
fn independent_dkim2_chains_and_refusals() {
    let f = fixtures();
    let zone = zone(&f);
    pratique::asyncio::block_on(async {
        for v in f["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["kind"] == "dkim2")
        {
            let raw = v["raw"].as_str().unwrap();
            let env = Envelope::new("<bounce@gateway.example.test>", ["<r@example.test>"]);
            let now = f["time"].as_u64().unwrap();
            let result = dkim2::verify(raw.as_bytes(), &zone, &env, now).await;
            assert_eq!(result.status, Status::Pass, "{}", result.detail);
            assert_eq!(result.chain.len(), 2);
            for broken in [
                format!("{raw}tamper\r\n"),
                raw.replace("From: Sender", "From: Forged"),
                raw.replace("i=2;", "i=3;"),
                raw.replace("m=1;", "m=9;"),
            ] {
                assert_ne!(
                    dkim2::verify(broken.as_bytes(), &zone, &env, now)
                        .await
                        .status,
                    Status::Pass
                );
            }
            assert_ne!(
                dkim2::verify(raw.as_bytes(), &zone, &env, now + 15 * 86400)
                    .await
                    .status,
                Status::Pass
            );
            assert_ne!(
                dkim2::verify(
                    raw.as_bytes(),
                    &zone,
                    &Envelope::new("<bounce@gateway.example.test>", ["<wrong@example.test>"]),
                    now
                )
                .await
                .status,
                Status::Pass
            );
        }
    });
}
#[cfg(feature = "arc")]
#[test]
fn independent_arc_sets_and_refusals() {
    let f = fixtures();
    let zone = zone(&f);
    pratique::asyncio::block_on(async {
        for v in f["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["kind"] == "arc")
        {
            let raw = v["raw"].as_str().unwrap();
            let now = f["time"].as_u64().unwrap();
            let result = mailauth::arc::verify(raw.as_bytes(), &zone, now).await;
            assert_eq!(
                result.status,
                mailauth::arc::Status::Pass,
                "{}",
                result.detail
            );
            for broken in [
                format!("{raw}tamper\r\n"),
                raw.replace("From: Sender", "From: Forged"),
                raw.replace("i=1;", "i=4;"),
                raw.replace("cv=none", "cv=pass"),
            ] {
                assert_ne!(
                    mailauth::arc::verify(broken.as_bytes(), &zone, now)
                        .await
                        .status,
                    mailauth::arc::Status::Pass
                );
            }
        }
    });
}
#[test]
fn native_dkim2_signing_reconstruction_flags_and_envelope() {
    pratique::asyncio::block_on(async {
        let f = fixtures();
        let zone = zone(&f);
        let a = Signer::new("origin.example.test", "s", SigningKey::ed25519(&[7; 32]));
        let mut b = Signer::new("gateway.example.test", "s", SigningKey::ed25519(&[9; 32]));
        let raw = "From: a@origin.example.test\r\nSubject: First\r\nSubject: Repeated\r\n\r\nFirst café\r\n";
        let first = format!(
            "{}{raw}",
            a.sign(raw.as_bytes(), Hop::imaginary("gateway.example.test"))
                .unwrap()
                .to_header()
        );
        let modified = first.replace("First", "Revised");
        let env = Envelope::new("bounce@gateway.example.test", ["r@example.test"]);
        b.flags = vec!["feedback".into(), "feedhere".into()];
        let second = b
            .sign_revised(
                first.as_bytes(),
                modified.as_bytes(),
                Hop::Real(env.clone()),
            )
            .unwrap();
        assert!(second.message_instance.is_some());
        let signed = format!("{}{modified}", second.to_header());
        let result = dkim2::verify(signed.as_bytes(), &zone, &env, mailauth::now()).await;
        assert_eq!(result.status, Status::Pass, "{}", result.detail);
        assert_eq!(result.feedback_domains(), vec!["gateway.example.test"]);
        assert_eq!(result.feedback_relay(), Some("gateway.example.test"));
        assert_eq!(result.return_path(), Some("<bounce@gateway.example.test>"));
        let mut all = vec![
            pratique::json_value::json!({"kind":"dkim2","raw":signed,"mail_from":env.mail_from,"rcpt_to":env.rcpt_to}),
        ];
        #[cfg(feature = "arc")]
        {
            let key = SigningKey::ed25519(&[7; 32]);
            let first = format!(
                "{}{raw}",
                mailauth::arc::seal(
                    raw.as_bytes(),
                    &zone,
                    "origin.example.test",
                    "s",
                    &key,
                    "origin.example.test; dkim=pass",
                    mailauth::now()
                )
                .await
                .unwrap()
            );
            let result = mailauth::arc::verify(first.as_bytes(), &zone, mailauth::now()).await;
            assert_eq!(
                result.status,
                mailauth::arc::Status::Pass,
                "{}",
                result.detail
            );
            let key = SigningKey::ed25519(&[9; 32]);
            let second = format!(
                "{}{first}",
                mailauth::arc::seal(
                    first.as_bytes(),
                    &zone,
                    "gateway.example.test",
                    "s",
                    &key,
                    "gateway.example.test; arc=pass",
                    mailauth::now()
                )
                .await
                .unwrap()
            );
            let result = mailauth::arc::verify(second.as_bytes(), &zone, mailauth::now()).await;
            assert_eq!(
                result.status,
                mailauth::arc::Status::Pass,
                "{}",
                result.detail
            );
            all.push(pratique::json_value::json!({"kind":"arc","raw":second}));
        }
        if let Ok(path) = std::env::var("WORKGLEN_EXPORT_PROTOCOL_FIXTURES") {
            std::fs::write(
                path,
                pratique::json_value::to_vec_pretty(
                    &pratique::json_value::json!({"records":f["records"],"fixtures":all}),
                )
                .unwrap(),
            )
            .unwrap();
        }
    });
}
