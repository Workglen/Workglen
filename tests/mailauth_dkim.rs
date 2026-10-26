//! Full-message verification against independent Python-signed fixtures.
use std::collections::HashMap;
use workglen_dns::{Error, RData, RecordType, ResponseCode, TXT};
use workglen_mail::mailauth::{Dns, dkim, dmarc, spf};
struct Zone(HashMap<String, Result<Vec<RData>, Error>>);
impl Zone {
    fn new(record: &str) -> Self {
        let mut z = Self(HashMap::new());
        z.txt("test._domainkey.dkim.test", record);
        z.txt("_dmarc.dkim.test", "v=DMARC1;p=reject;adkim=s;aspf=s;psd=n");
        z
    }
    fn txt(&mut self, n: &str, v: &str) {
        self.0.insert(
            n.into(),
            Ok(vec![RData::TXT(TXT {
                txt_data: vec![v.as_bytes().to_vec()],
            })]),
        );
    }
}
impl Dns for Zone {
    async fn lookup(&self, n: &str, k: RecordType) -> Result<Vec<RData>, Error> {
        assert_eq!(k, RecordType::TXT);
        self.0
            .get(n.trim_end_matches('.'))
            .cloned()
            .unwrap_or(Err(Error::NoRecords(ResponseCode::NXDomain)))
    }
}

fn fixtures() -> pratique::json_value::Value {
    pratique::json_value::from_str(include_str!("fixtures/mailauth-crypto.json")).unwrap()
}
#[test]
fn all_canonicalizations_and_algorithms_preserve_dkim_and_dmarc_results() {
    pratique::asyncio::block_on(async {
        for f in fixtures()["messages"].as_array().unwrap() {
            let raw = f["raw"].as_str().unwrap();
            let zone = Zone::new(f["record"].as_str().unwrap());
            let result = dkim::verify(raw.as_bytes(), &zone, 0).await.unwrap();
            assert_eq!(result.len(), 1);
            assert_eq!(
                result[0].status,
                dkim::Status::Pass,
                "{} {}",
                f["label"],
                result[0].detail
            );
            assert_eq!(
                dmarc::verify(
                    &zone,
                    "dkim.test",
                    "bounces.test",
                    spf::Status::Fail,
                    &result
                )
                .await
                .status,
                dmarc::Status::Pass
            );
            for damaged in [
                raw.replace("First", "Wrong"),
                raw.replace("Sender <", "Forged <"),
            ] {
                let dkim = dkim::verify(damaged.as_bytes(), &zone, 0).await.unwrap();
                assert_ne!(dkim[0].status, dkim::Status::Pass);
                assert_eq!(
                    dmarc::verify(&zone, "dkim.test", "bounces.test", spf::Status::Fail, &dkim)
                        .await
                        .status,
                    dmarc::Status::Fail
                );
            }
        }
    });
}
#[test]
fn revoked_keys_and_dns_errors_never_become_authentication_passes() {
    pratique::asyncio::block_on(async {
        for f in fixtures()["messages"].as_array().unwrap() {
            let raw = f["raw"].as_str().unwrap();
            let mut zone = Zone::new("v=DKIM1;p=");
            assert_eq!(
                dkim::verify(raw.as_bytes(), &zone, 0).await.unwrap()[0].status,
                dkim::Status::Fail
            );
            zone.0
                .insert("test._domainkey.dkim.test".into(), Err(Error::Timeout));
            assert_eq!(
                dkim::verify(raw.as_bytes(), &zone, 0).await.unwrap()[0].status,
                dkim::Status::Temporary
            );
            zone.0.insert(
                "test._domainkey.dkim.test".into(),
                Err(Error::NoRecords(ResponseCode::NXDomain)),
            );
            assert_eq!(
                dkim::verify(raw.as_bytes(), &zone, 0).await.unwrap()[0].status,
                dkim::Status::Fail
            );
        }
    });
}
#[test]
fn native_outbound_signatures_verify_and_protect_repeated_headers() {
    let f = fixtures();
    let hex = f["private_test_key"].as_str().unwrap();
    let der: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    let key = pratique::sign::SigningKey::from_der(&der).unwrap();
    let record = format!(
        "v=DKIM1;p={}",
        workglen_mail::encoding::STANDARD.encode(key.public_key_spki())
    );
    let zone = Zone::new(&record);
    pratique::asyncio::block_on(async {
        for body in [
            "",
            "\r\n",
            "Message",
            "Message\r\n\r\n",
            " \t Message \t end \t\r\n",
            "Unicode café\r\n",
            " \t\r\n",
        ] {
            let raw = format!(
                "From: Sender <a@dkim.test>\r\nSubject: First\r\nSubject: Second\r\nSubject: Third\r\n\r\n{body}"
            );
            let signed = dkim::sign(raw.as_bytes(), "dkim.test", "test", &key).unwrap();
            let result = dkim::verify(&signed, &zone, 0).await.unwrap();
            assert_eq!(result[0].status, dkim::Status::Pass, "{}", result[0].detail);
            let signed = String::from_utf8(signed).unwrap();
            for damaged in [
                signed.replace("Subject: Third", "Subject: Altered"),
                signed.replace("From: Sender", "Subject: Injected\r\nFrom: Sender"),
                format!("{signed}tampered\r\n"),
            ] {
                assert_ne!(
                    dkim::verify(damaged.as_bytes(), &zone, 0).await.unwrap()[0].status,
                    dkim::Status::Pass
                );
            }
        }
    });
}
