//! Offline protocol fixtures. Unknown DNS names fail immediately; no external traffic.
use std::collections::HashMap;
use workglen_dns::{Error, RData, RecordType, ResponseCode, TXT};
use workglen_mail::mailauth::{Dns, dkim, dmarc, spf};
#[derive(Default)]
struct Zone(HashMap<(String, RecordType), Result<Vec<RData>, Error>>);
impl Zone {
    fn txt(&mut self, name: &str, value: &str) {
        self.0
            .entry((name.into(), RecordType::TXT))
            .or_insert(Ok(Vec::new()))
            .as_mut()
            .unwrap()
            .push(RData::TXT(TXT {
                txt_data: vec![value.as_bytes().to_vec()],
            }));
    }
    fn absent(&mut self, name: &str) {
        self.0.insert(
            (name.into(), RecordType::TXT),
            Err(Error::NoRecords(ResponseCode::NXDomain)),
        );
    }
}
impl Dns for Zone {
    async fn lookup(&self, name: &str, kind: RecordType) -> Result<Vec<RData>, Error> {
        self.0
            .get(&(name.trim_end_matches('.').to_ascii_lowercase(), kind))
            .unwrap_or_else(|| panic!("unprovisioned DNS fixture: {name} {kind:?}"))
            .clone()
    }
}

#[test]
fn independent_dkim_messages_and_mutations() {
    let fixtures: pratique::json_value::Value =
        pratique::json_value::from_str(include_str!("fixtures/mailauth-crypto.json")).unwrap();
    pratique::asyncio::block_on(async {
        for fixture in fixtures["messages"].as_array().unwrap() {
            let raw = fixture["raw"].as_str().unwrap();
            let mut zone = Zone::default();
            zone.txt(
                "test._domainkey.dkim.test",
                fixture["record"].as_str().unwrap(),
            );
            let outcome = dkim::verify(raw.as_bytes(), &zone, 0).await.unwrap();
            assert_eq!(outcome.len(), 1);
            assert_eq!(
                outcome[0].status,
                dkim::Status::Pass,
                "{}: {}",
                fixture["label"],
                outcome[0].detail
            );
            for damaged in [
                raw.replace("First", "Wrong"),
                raw.replace("Sender <", "Forged <"),
            ] {
                assert_ne!(
                    dkim::verify(damaged.as_bytes(), &zone, 0).await.unwrap()[0].status,
                    dkim::Status::Pass
                );
            }
        }
    });
}
#[test]
fn native_signing_verifies_repeated_headers() {
    let fixtures: pratique::json_value::Value =
        pratique::json_value::from_str(include_str!("fixtures/mailauth-crypto.json")).unwrap();
    let hex = fixtures["private_test_key"].as_str().unwrap();
    let der: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    let key = pratique::sign::SigningKey::from_der(&der).unwrap();
    let raw=b"From: a@example.test\r\nSubject: Native\r\nSubject: Second\r\nSubject: Third\r\n\r\nMessage\r\n\r\n\r\n";
    let signed = dkim::sign(raw, "example.test", "test", &key).unwrap();
    let record = format!(
        "v=DKIM1; p={}",
        workglen_mail::encoding::STANDARD.encode(key.public_key_spki())
    );
    let mut zone = Zone::default();
    zone.txt("test._domainkey.example.test", &record);
    pratique::asyncio::block_on(async {
        let outcome = dkim::verify(&signed, &zone, u64::MAX / 2).await.unwrap();
        assert_eq!(
            outcome[0].status,
            dkim::Status::Pass,
            "{}",
            outcome[0].detail
        );
    });
}
#[test]
fn spf_recursive_limits_qualifiers_and_null_sender() {
    let mut zone = Zone::default();
    zone.txt("example.test", "v=spf1 include:other.test -all");
    zone.txt("other.test", "v=spf1 ip4:192.0.2.0/24 ~all");
    pratique::asyncio::block_on(async {
        for (ip, want) in [
            ("192.0.2.10", spf::Status::Pass),
            ("198.51.100.2", spf::Status::Fail),
        ] {
            assert_eq!(
                spf::verify(
                    &zone,
                    spf::Parameters {
                        ip: ip.parse().unwrap(),
                        helo: "example.test",
                        sender: ""
                    }
                )
                .await,
                want
            );
        }
        let mut cycle = Zone::default();
        cycle.txt("example.test", "v=spf1 include:example.test -all");
        assert_eq!(
            spf::verify(
                &cycle,
                spf::Parameters {
                    ip: "192.0.2.1".parse().unwrap(),
                    helo: "example.test",
                    sender: "a@example.test"
                }
            )
            .await,
            spf::Status::Permanent
        );
        let mut duplicates = Zone::default();
        duplicates.txt("example.test", "v=spf1 +all");
        duplicates.txt("example.test", "v=spf1 -all");
        assert_eq!(
            spf::verify(
                &duplicates,
                spf::Parameters {
                    ip: "192.0.2.1".parse().unwrap(),
                    helo: "example.test",
                    sender: ""
                }
            )
            .await,
            spf::Status::Permanent
        );
    });
}
#[test]
fn dmarc_alignment_tree_and_policy() {
    let mut zone = Zone::default();
    zone.txt("_dmarc.example.test", "v=DMARC1;p=reject;psd=n");
    zone.absent("_dmarc.sub.example.test");
    zone.absent("_dmarc.bounce.example.test");
    pratique::asyncio::block_on(async {
        assert_eq!(
            dmarc::verify(
                &zone,
                "sub.example.test",
                "bounce.example.test",
                spf::Status::Pass,
                &[]
            )
            .await
            .status,
            dmarc::Status::Pass
        );
        let failed = dmarc::verify(
            &zone,
            "sub.example.test",
            "unrelated.test",
            spf::Status::Pass,
            &[],
        )
        .await;
        assert_eq!(failed.status, dmarc::Status::Fail);
        assert_eq!(failed.policy, dmarc::Policy::Reject);
        let pending = dmarc::verify(
            &zone,
            "sub.example.test",
            "sub.example.test",
            spf::Status::Temporary,
            &[],
        )
        .await;
        assert_eq!(pending.status, dmarc::Status::Temporary);
    });
}

#[test]
fn spf_text_mechanisms_match_recorded_reference() {
    let fixtures: pratique::json_value::Value =
        pratique::json_value::from_str(include_str!("fixtures/spf-reference.json")).unwrap();
    pratique::asyncio::block_on(async {
        for f in fixtures.as_array().unwrap() {
            let mut zone = Zone::default();
            zone.txt("example.test", f["record"].as_str().unwrap());
            zone.txt("other.test", "v=spf1 ip4:192.0.2.1 ip6:2001:db8::1 ~all");
            let status = spf::verify(
                &zone,
                spf::Parameters {
                    ip: f["ip"].as_str().unwrap().parse().unwrap(),
                    helo: "example.test",
                    sender: "a@example.test",
                },
            )
            .await;
            assert_eq!(
                format!("{status:?}"),
                f["expected"].as_str().unwrap(),
                "{f}"
            );
        }
    });
}

#[test]
fn spf_candidate_rejects_malformed_policies() {
    let mut zone = Zone::default();
    zone.txt("example.test", "v=spf1 ip4:192.0.2.1/33 -all");
    assert_eq!(
        pratique::asyncio::block_on(spf::verify(
            &zone,
            spf::Parameters {
                ip: "192.0.2.1".parse().unwrap(),
                helo: "example.test",
                sender: ""
            }
        )),
        spf::Status::Permanent
    );
}
