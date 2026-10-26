//! Closed DNS fixtures for evaluation limits and failure propagation.
use std::{collections::HashMap, sync::Mutex};
use workglen_dns::{A, AAAA, Error, MX, Name, RData, RecordType, ResponseCode, TXT};
use workglen_mail::mailauth::{
    Dns,
    crypto::SigningKey,
    dkim2::{self, Envelope, Hop, Signer},
    dmarc, spf,
};
#[derive(Default)]
struct Zone {
    records: HashMap<(String, RecordType), Result<Vec<RData>, Error>>,
    queries: Mutex<Vec<String>>,
}
impl Zone {
    fn set(&mut self, n: &str, k: RecordType, v: Vec<RData>) {
        self.records.insert((n.into(), k), Ok(v));
    }
    fn txt(&mut self, n: &str, v: &str) {
        self.set(
            n,
            RecordType::TXT,
            vec![RData::TXT(TXT {
                txt_data: vec![v.as_bytes().to_vec()],
            })],
        );
    }
    fn a(&mut self, n: &str, v: &str) {
        self.set(n, RecordType::A, vec![RData::A(A(v.parse().unwrap()))]);
    }
}
impl Dns for Zone {
    async fn lookup(&self, n: &str, k: RecordType) -> Result<Vec<RData>, Error> {
        let n = n.trim_end_matches('.').to_ascii_lowercase();
        self.queries.lock().unwrap().push(n.clone());
        self.records
            .get(&(n, k))
            .cloned()
            .unwrap_or(Err(Error::NoRecords(ResponseCode::NXDomain)))
    }
}

#[test]
fn independent_dkim_extensions_and_key_policies() {
    pratique::asyncio::block_on(async {
        let f: pratique::json_value::Value =
            pratique::json_value::from_str(include_str!("fixtures/native-auth-extensions.json"))
                .unwrap();
        for c in f["cases"].as_array().unwrap() {
            let mut z = Zone::default();
            z.txt("test._domainkey.dkim.test", c["record"].as_str().unwrap());
            for (n, v) in c["dns"].as_object().unwrap() {
                if v == "TIMEOUT" {
                    z.records
                        .insert((n.clone(), RecordType::TXT), Err(Error::Timeout));
                } else {
                    z.txt(n, v.as_str().unwrap());
                }
            }
            let o = workglen_mail::mailauth::dkim::verify(
                c["raw"].as_str().unwrap().as_bytes(),
                &z,
                c["now"].as_u64().unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(
                format!("{:?}", o[0].status),
                c["expected"].as_str().unwrap(),
                "{}: {}",
                c["label"],
                o[0].detail
            );
        }
    });
}
async fn spf(z: &Zone, ip: &str) -> spf::Status {
    spf::verify(
        z,
        spf::Parameters {
            ip: ip.parse().unwrap(),
            helo: "example.test",
            sender: "strong-bad@example.test",
        },
    )
    .await
}
#[test]
fn spf_dns_mechanisms_macros_and_explanations() {
    pratique::asyncio::block_on(async {
        let mut z = Zone::default();
        z.a("host.test", "192.0.2.9");
        z.set(
            "host.test",
            RecordType::AAAA,
            vec![RData::AAAA(AAAA("2001:db8::9".parse().unwrap()))],
        );
        z.set(
            "example.test",
            RecordType::MX,
            vec![RData::MX(MX {
                preference: 10,
                exchange: Name::parse("host.test").unwrap(),
            })],
        );
        z.set(
            "9.2.0.192.in-addr.arpa",
            RecordType::PTR,
            vec![RData::PTR(Name::parse("host.test").unwrap())],
        );
        for (record, ip) in [
            ("v=spf1 a:host.test -all", "192.0.2.9"),
            ("v=spf1 a:host.test -all", "2001:db8::9"),
            ("v=spf1 mx -all", "192.0.2.9"),
            ("v=spf1 ptr:test -all", "192.0.2.9"),
            ("v=spf1 exists:%{i}.%{d} -all", "192.0.2.9"),
        ] {
            z.txt("example.test", record);
            z.a("192.0.2.9.example.test", "127.0.0.2");
            assert_eq!(spf(&z, ip).await, spf::Status::Pass, "{record}");
        }
        z.txt("example.test", "v=spf1 exists:%{l1r-}.%{d2r} -all");
        z.a("strong.test.example", "127.0.0.2");
        assert_eq!(spf(&z, "192.0.2.9").await, spf::Status::Pass);
        z.txt("example.test", "v=spf1 -all exp=why.example.test");
        z.txt("why.example.test", "Denied %{s} from %{c} at %{r}");
        let o = spf::verify_detailed(
            &z,
            spf::Parameters {
                ip: "192.0.2.9".parse().unwrap(),
                helo: "example.test",
                sender: "a@example.test",
            },
            "receiver.test",
        )
        .await;
        assert_eq!(o.status, spf::Status::Fail);
        assert_eq!(
            o.explanation.as_deref(),
            Some("Denied a@example.test from 192.0.2.9 at receiver.test")
        );
        z.txt("why.example.test", "%{invalid}");
        let o = spf::verify_detailed(
            &z,
            spf::Parameters {
                ip: "192.0.2.9".parse().unwrap(),
                helo: "example.test",
                sender: "",
            },
            "receiver.test",
        )
        .await;
        assert_eq!(o.status, spf::Status::Fail);
        assert_eq!(o.explanation, None);
    });
}
#[test]
fn spf_shared_budgets_and_dns_errors() {
    pratique::asyncio::block_on(async {
        let mut z = Zone::default();
        z.txt(
            "example.test",
            "v=spf1 exists:a.test exists:b.test exists:c.test +all",
        );
        assert_eq!(spf(&z, "192.0.2.9").await, spf::Status::Permanent);
        z.a("host.test", "198.51.100.1");
        for n in [10, 11] {
            z.txt(
                "example.test",
                &format!("v=spf1 {} +all", vec!["a:host.test"; n].join(" ")),
            );
            assert_eq!(
                spf(&z, "192.0.2.9").await,
                if n == 10 {
                    spf::Status::Pass
                } else {
                    spf::Status::Permanent
                }
            );
        }
        z.txt("example.test", "v=spf1 mx -all");
        z.set(
            "example.test",
            RecordType::MX,
            (0..11)
                .map(|i| {
                    RData::MX(MX {
                        preference: i,
                        exchange: Name::parse("host.test").unwrap(),
                    })
                })
                .collect(),
        );
        assert_eq!(spf(&z, "192.0.2.9").await, spf::Status::Permanent);
        z.txt("example.test", "v=spf1 include:down.test -all");
        z.records
            .insert(("down.test".into(), RecordType::TXT), Err(Error::Timeout));
        assert_eq!(spf(&z, "192.0.2.9").await, spf::Status::Temporary);
        z.txt("example.test", "v=spf1 +all redirect=missing.test");
        assert_eq!(spf(&z, "192.0.2.9").await, spf::Status::Pass);
        z.txt("example.test", "v=spf1 redirect=missing.test");
        assert_eq!(spf(&z, "192.0.2.9").await, spf::Status::Permanent);
        for value in [
            "v=spf1 +all exp=%{x}",
            "v=spf1 -all +redirect=example.test",
            "v=spf1 a//129 -all",
            "v=spf1 exists:%{d0} +all",
        ] {
            z.txt("example.test", value);
            assert_eq!(
                spf(&z, "192.0.2.9").await,
                spf::Status::Permanent,
                "{value}"
            );
        }
    });
}
#[test]
fn dmarc_tree_invalid_records_and_policy_modes() {
    pratique::asyncio::block_on(async {
        let mut z = Zone::default();
        z.txt(
            "_dmarc.example.test",
            "v=DMARC1;p=reject;sp=quarantine;np=reject;psd=n",
        );
        z.set(
            "_dmarc.sub.example.test",
            RecordType::TXT,
            vec![
                RData::TXT(TXT {
                    txt_data: vec![b"v=DMARC1;p=none".to_vec()],
                }),
                RData::TXT(TXT {
                    txt_data: vec![b"v=DMARC1;p=none".to_vec()],
                }),
            ],
        );
        let o = dmarc::verify(&z, "sub.example.test", "other.test", spf::Status::Fail, &[]).await;
        assert_eq!(
            (o.status, o.policy),
            (dmarc::Status::Fail, dmarc::Policy::Reject)
        );
        z.a("sub.example.test", "192.0.2.2");
        assert_eq!(
            dmarc::verify(&z, "sub.example.test", "other.test", spf::Status::Fail, &[])
                .await
                .policy,
            dmarc::Policy::Quarantine
        );
        for (record, status, policy) in [
            (
                "v=DMARC1;p=bad;rua=mailto:r@example.test;psd=n",
                dmarc::Status::Fail,
                dmarc::Policy::None,
            ),
            (
                "v=DMARC1;p=bad;psd=n",
                dmarc::Status::None,
                dmarc::Policy::None,
            ),
            (
                "v=DMARC1;p=reject;sp=bad;rua=mailto:r@example.test;psd=n",
                dmarc::Status::Fail,
                dmarc::Policy::None,
            ),
            (
                "v=DMARC1;p=reject;t=y;psd=n",
                dmarc::Status::Fail,
                dmarc::Policy::Quarantine,
            ),
        ] {
            z.txt("_dmarc.example.test", record);
            let o = dmarc::verify(&z, "example.test", "other.test", spf::Status::Fail, &[]).await;
            assert_eq!((o.status, o.policy), (status, policy), "{record}");
        }
        let z = Zone::default();
        assert_eq!(
            dmarc::verify(
                &z,
                "a.b.c.d.e.f.g.h.i.example.test",
                "other.test",
                spf::Status::Fail,
                &[]
            )
            .await
            .status,
            dmarc::Status::None
        );
        assert_eq!(z.queries.lock().unwrap().len(), 8);
    });
}
#[test]
fn dkim2_signed_restrictions_and_dsn() {
    pratique::asyncio::block_on(async {
        let mut z = Zone::default();
        let key = SigningKey::ed25519(&[7; 32]);
        z.txt("s._domainkey.origin.test", &key.dns_record());
        let mut a = Signer::new("origin.test", "s", key);
        let key = SigningKey::ed25519(&[9; 32]);
        z.txt("s._domainkey.gateway.test", &key.dns_record());
        let mut b = Signer::new("gateway.test", "s", key);
        let raw = "From: a@origin.test\r\nSubject: Original\r\n\r\nOriginal\r\n";
        let env = Envelope::new("b@gateway.test", ["r@receiver.test"]);
        for flag in ["donotmodify", "donotexplode"] {
            a.flags = vec![flag.into()];
            let first = format!(
                "{}{raw}",
                a.sign(raw.as_bytes(), Hop::imaginary("gateway.test"))
                    .unwrap()
                    .to_header()
            );
            let changed = if flag == "donotmodify" {
                first.replace("Original", "Changed")
            } else {
                first.clone()
            };
            b.flags = if flag == "donotexplode" {
                vec!["exploded".into()]
            } else {
                vec![]
            };
            let signed = format!(
                "{}{changed}",
                b.sign_revised(first.as_bytes(), changed.as_bytes(), Hop::Real(env.clone()))
                    .unwrap()
                    .to_header()
            );
            assert_eq!(
                dkim2::verify(signed.as_bytes(), &z, &env, workglen_mail::mailauth::now())
                    .await
                    .status,
                dkim2::Status::Fail
            );
        }
        a.flags.clear();
        b.flags.clear();
        let inner = format!(
            "{}{raw}",
            a.sign(
                raw.as_bytes(),
                Hop::real("a@origin.test", ["r@gateway.test"])
            )
            .unwrap()
            .to_header()
        );
        for full in [true, false] {
            let returned = if full {
                inner.clone()
            } else {
                format!("{}\r\n", inner.split_once("\r\n\r\n").unwrap().0)
            };
            let typ = if full {
                "message/rfc822"
            } else {
                "text/rfc822-headers"
            };
            let body = format!(
                "From: mailer-daemon@gateway.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; boundary=dsn; report-type=delivery-status\r\n\r\n--dsn\r\nContent-Type: text/plain\r\n\r\nDelivery failed\r\n--dsn\r\nContent-Type: {typ}\r\n\r\n{returned}\r\n--dsn--\r\n"
            );
            let env = Envelope::new("", ["a@origin.test"]);
            let signed = format!(
                "{}{body}",
                b.sign(body.as_bytes(), Hop::Real(env.clone()))
                    .unwrap()
                    .to_header()
            );
            let (o, i) =
                dkim2::verify_dsn(signed.as_bytes(), &z, &env, workglen_mail::mailauth::now())
                    .await
                    .unwrap();
            assert_eq!(
                (o.status, i.status),
                (dkim2::Status::Pass, dkim2::Status::Pass)
            );
        }
    });
}
