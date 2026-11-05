use super::*;
use crate::encoding::{STANDARD, URL_SAFE_NO_PAD};
use pratique::{
    crypto::ecdsa::Curve,
    http::Client,
    tls::{
        ClientConfig, TlsStream,
        pki::{CertSpec, KeyPair, issue, issue_for_spki},
    },
    x509::TrustStore,
};
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    time::Instant,
};

fn settings(path: &Path) -> AcmeSettings {
    AcmeSettings {
        domains: vec!["mail.example.test".into()],
        email: "admin@example.test".into(),
        state_dir: path.to_str().unwrap().into(),
        http_listen: "127.0.0.1:0".parse().unwrap(),
        staging: true,
        agree_to_terms: true,
    }
}

#[test]
fn configuration_is_explicit_and_covers_every_service_name() {
    let dir = crate::test_support::tempdir().unwrap();
    let mut s = settings(&dir.path().join("state"));
    assert!(validate("", "", Some(&s), &[]).is_err()); // zero port
    s.http_listen.set_port(80);
    assert!(validate("", "", Some(&s), &["mail.example.test"]).is_ok());
    assert!(validate("", "", Some(&s), &["admin.example.test"]).is_err());
    assert!(validate("cert", "key", Some(&s), &[]).is_err());
    assert!(validate("", "", None, &[]).is_err());
    assert!(validate("cert", "key", None, &[]).is_ok());
    for domain in [
        "*.example.test",
        "127.0.0.1",
        "Mail.example.test",
        "mail.example.test.",
        "localhost",
    ] {
        s.domains = vec![domain.into()];
        assert!(validate("", "", Some(&s), &[]).is_err());
    }
    s.domains = vec!["mail.example.test".into()];
    s.agree_to_terms = false;
    assert!(validate("", "", Some(&s), &[]).is_err());
    assert!(!Path::new(&s.state_dir).exists()); // offline validation creates nothing
}

#[test]
fn state_is_private_exclusive_and_rejects_links() {
    let dir = crate::test_support::tempdir().unwrap();
    let path = dir.path().join("state");
    let lock = private_state(&path).unwrap();
    assert!(private_state(&path).is_err());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    drop(lock);
    assert!(private_state(&path).is_ok());
    fs::write(path.join("account.key"), b"dummy").unwrap();
    fs::set_permissions(path.join("account.key"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(private_state(&path).is_err());
    fs::remove_file(path.join("account.key")).unwrap();
    std::os::unix::fs::symlink(dir.path(), path.join("link")).unwrap();
    assert!(private_state(&path).is_err());
}

#[test]
fn fallback_tracks_certificate_lifetime_including_short_certificates() {
    let key = KeyPair::generate_ecdsa(Curve::P256).unwrap();
    let now = crate::datetime::Utc::now().unwrap().timestamp();
    for days in [90, 64, 45, 6] {
        let mut spec = CertSpec::server(&["mail.example.test"]);
        spec.not_before = now;
        spec.not_after = now + days * 86400;
        let der = issue(&spec, &key, None);
        let cert = pratique::tls::certs::CertifiedKey::from_pem(
            &pem(&der),
            std::str::from_utf8(&key.signing_key().to_pkcs8_pem().unwrap()).unwrap(),
        )
        .unwrap();
        let expected = now
            + if days < 10 {
                days * 86400 / 2
            } else {
                days * 86400 * 2 / 3
            };
        assert_eq!(acme::default_renewal_time(&cert), expected);
    }
}

fn client() -> Client {
    Client::with_tls_config(ClientConfig::new(TrustStore::empty()))
        .allow_insecure_http(true)
        .timeout(Duration::from_secs(5))
}
fn pem(der: &[u8]) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(der)
    )
}
fn until(mut test: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !test() {
        assert!(Instant::now() < deadline, "local ACME condition timed out");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Deliberately tiny local CA for integration wiring. The vendored protocol suite
/// separately checks signatures, nonce rejection, ARI replacement and CA errors.
struct Ca {
    base: Mutex<String>,
    key: KeyPair,
    root: Vec<u8>,
    port: AtomicU16,
    valid: AtomicBool,
    finalized: AtomicBool,
    reject: AtomicBool,
    orders: AtomicUsize,
    certs: Mutex<Vec<String>>,
    replaced: AtomicBool,
}
impl Ca {
    fn reply(&self, value: Value) -> Response {
        Response::bytes(
            200,
            "application/json",
            pratique::json_value::to_vec(&value).unwrap(),
        )
        .with_header("replay-nonce", "bG9jYWwtdGVzdC1ub25jZQ")
    }
    fn handle(&self, mut r: Request) -> Response {
        let base = self.base.lock().unwrap().clone();
        let path = r.path().to_owned();
        let data = if r.method() == "POST" {
            let j: Value = pratique::json_value::from_slice(&r.read_body(16384).unwrap()).unwrap();
            let bytes = URL_SAFE_NO_PAD
                .decode(j["payload"].as_str().unwrap())
                .unwrap();
            if bytes.is_empty() {
                Value::Null
            } else {
                pratique::json_value::from_slice(&bytes).unwrap()
            }
        } else {
            Value::Null
        };
        match path.as_str() {
            "/dir" => self.reply(json!({"newNonce":format!("{base}/nonce"),"newAccount":format!("{base}/account"),"newOrder":format!("{base}/new-order"),"renewalInfo":format!("{base}/renew")})),
            "/nonce" => self.reply(json!({})),
            "/account" => self.reply(json!({"status":"valid"})).with_header("location", &format!("{base}/account/1")),
            "/new-order" => {
                self.orders.fetch_add(1, Ordering::SeqCst);
                if self.reject.load(Ordering::SeqCst) {
                    return Response::bytes(503, "application/problem+json", br#"{"type":"urn:ietf:params:acme:error:serverInternal","detail":"synthetic outage"}"#.to_vec()).with_header("replay-nonce", "bG9jYWwtdGVzdC1ub25jZQ");
                }
                if data["replaces"].is_string() { self.replaced.store(true, Ordering::SeqCst); }
                self.valid.store(false, Ordering::SeqCst);
                self.finalized.store(false, Ordering::SeqCst);
                self.reply(json!({"status":"pending","authorizations":[format!("{base}/auth")],"finalize":format!("{base}/finalize")})).with_header("location", &format!("{base}/order"))
            }
            "/auth" => self.reply(json!({"status":if self.valid.load(Ordering::SeqCst){"valid"}else{"pending"},"identifier":{"type":"dns","value":"mail.example.test"},"challenges":[{"type":"http-01","token":"YWJjZGVmZ2hpamtsbW5vcA","url":format!("{base}/challenge")}]})),
            "/challenge" => {
                until(|| self.port.load(Ordering::SeqCst) != 0);
                let response = client().get(&format!("http://127.0.0.1:{}/.well-known/acme-challenge/YWJjZGVmZ2hpamtsbW5vcA", self.port.load(Ordering::SeqCst))).unwrap();
                assert_eq!(response.status, 200);
                assert!(String::from_utf8_lossy(&response.body).starts_with("YWJjZGVmZ2hpamtsbW5vcA."));
                self.valid.store(true, Ordering::SeqCst);
                self.reply(json!({"status":"valid"}))
            }
            "/order" => self.reply(json!({"status":if self.finalized.load(Ordering::SeqCst){"valid"}else{"ready"},"finalize":format!("{base}/finalize"),"certificate":format!("{base}/cert")})),
            "/finalize" => {
                let bytes = URL_SAFE_NO_PAD.decode(data["csr"].as_str().unwrap()).unwrap();
                let mut outer = pratique::asn1::Der::new(&bytes);
                let mut seq = outer.sequence().unwrap(); outer.finish().unwrap();
                let request = seq.expect(pratique::asn1::TAG_SEQUENCE).unwrap();
                let algorithm = seq.expect(pratique::asn1::TAG_SEQUENCE).unwrap();
                assert_eq!(algorithm.raw, pratique::asn1::write::sequence(&[&pratique::asn1::write::oid_str("1.2.840.10045.4.3.2")]));
                let sig_tlv = seq.expect(pratique::asn1::TAG_BIT_STRING).unwrap();
                let sig = pratique::asn1::bit_string_bytes(&sig_tlv).unwrap(); seq.finish().unwrap();
                let mut info = pratique::asn1::Der::new(request.content);
                info.expect(pratique::asn1::TAG_INTEGER).unwrap();
                info.expect(pratique::asn1::TAG_SEQUENCE).unwrap();
                let spki = info.expect(pratique::asn1::TAG_SEQUENCE).unwrap();
                let pratique::x509::PublicKey::Ec {curve, point} = pratique::x509::parse_spki(spki.raw).unwrap() else { panic!("expected EC CSR"); };
                assert!(pratique::crypto::ecdsa::verify(curve, &point, pratique::crypto::sha2::HashAlg::Sha256, request.raw, sig));
                let mut certs = self.certs.lock().unwrap();
                let mut spec = CertSpec::server(&["mail.example.test"]);
                spec.serial = certs.len() as u64 + 1;
                let leaf = issue_for_spki(&spec, spki.raw, "Workglen local test CA", &self.key);
                self.finalized.store(true, Ordering::SeqCst);
                certs.push(format!("{}{}", pem(&leaf), pem(&self.root)));
                self.reply(json!({"status":"valid","certificate":format!("{base}/cert")}))
            }
            "/cert" => Response::bytes(200, "application/pem-certificate-chain", self.certs.lock().unwrap().last().unwrap().as_bytes().to_vec()).with_header("replay-nonce", "bG9jYWwtdGVzdC1ub25jZQ"),
            _ if path.starts_with("/renew/") => {
                let offset = if self.certs.lock().unwrap().len() == 1 { -60 } else { 15*86400 };
                let date = |seconds| crate::datetime::DateTime::from_timestamp(crate::datetime::Utc::now().unwrap().timestamp()+seconds,0).unwrap().to_rfc3339();
                self.reply(json!({"suggestedWindow":{"start":date(offset),"end":date(offset+30)}})).with_header("retry-after", "3600")
            }
            _ => Response::new(404),
        }
    }
}

#[test]
fn native_issuance_retry_live_reload_and_cached_restart() {
    let root = crate::test_support::tempdir().unwrap();
    let mut settings = settings(&root.path().join("acme"));
    let key = KeyPair::generate_ecdsa(Curve::P256).unwrap();
    let cert = issue(&CertSpec::ca("Workglen local test CA"), &key, None);
    let ca = Arc::new(Ca {
        base: Mutex::new(String::new()),
        key,
        root: cert,
        port: AtomicU16::new(0),
        valid: AtomicBool::new(false),
        finalized: AtomicBool::new(false),
        reject: AtomicBool::new(false),
        orders: AtomicUsize::new(0),
        certs: Mutex::new(vec![]),
        replaced: AtomicBool::new(false),
    });
    let handler = ca.clone();
    let _ca_server = ServerBuilder::new(move |r| handler.handle(r))
        .plain("127.0.0.1:0")
        .start()
        .unwrap();
    let base = format!("http://{}", _ca_server.local_addrs()[0]);
    *ca.base.lock().unwrap() = base.clone();
    let state_dir = settings.state_dir.clone();
    let config = || {
        let mut c = AcmeConfig::new(&format!("{base}/dir"), &state_dir)
            .client(client())
            .agree_to_terms()
            .validation_timeout(Duration::from_secs(5));
        c.retry_after_failure = Duration::from_secs(2);
        c
    };
    let manager = ManagedTls::start_acme(&settings, config(), |_| {}).unwrap();
    ca.port.store(
        manager._challenge.as_ref().unwrap().local_addrs()[0].port(),
        Ordering::SeqCst,
    );
    let tls = Arc::new((*manager.tls).clone().with_alpn(&["http/1.1"]));
    let web = ServerBuilder::new(|_| Response::text(200, "secured"))
        .tls("127.0.0.1:0", tls)
        .start()
        .unwrap();
    let handshake = || {
        let mut trust = TrustStore::empty();
        trust.add_der(&ca.root).unwrap();
        let tcp = TcpStream::connect(web.local_addrs()[0]).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut tls =
            TlsStream::connect(tcp, "mail.example.test", &ClientConfig::new(trust)).unwrap();
        let peer = tls.peer_certificate().unwrap().to_vec();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: mail.example.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut body = Vec::new();
        tls.read_to_end(&mut body).unwrap();
        assert!(String::from_utf8_lossy(&body).contains("secured"));
        peer
    };
    until(|| manager.status().unwrap()["ready"] == true);
    ca.reject.store(true, Ordering::SeqCst);
    let first = manager.tls.store.as_ref().unwrap().certificates()[0].chain()[0].clone();
    assert_eq!(handshake(), first);
    until(|| manager.status().unwrap()["last_error"] == "issuance-or-renewal-failed");
    assert_eq!(
        manager.tls.store.as_ref().unwrap().certificates()[0].chain()[0],
        first
    );
    assert_eq!(handshake(), first); // valid certificate remains available during the outage
    ca.reject.store(false, Ordering::SeqCst);
    until(|| manager.tls.store.as_ref().unwrap().certificates()[0].chain()[0] != first);
    assert_ne!(handshake(), first); // same listener and configuration use the renewed key
    assert!(ca.replaced.load(Ordering::SeqCst));
    assert!(manager.status().unwrap()["last_error"].is_null());
    let port = ca.port.load(Ordering::SeqCst);
    assert_eq!(
        client()
            .get(&format!("http://127.0.0.1:{port}/api/session"))
            .unwrap()
            .status,
        404
    );
    assert_eq!(
        client()
            .get(&format!(
                "http://127.0.0.1:{port}/.well-known/acme-challenge/YWJjZGVmZ2hpamtsbW5vcA"
            ))
            .unwrap()
            .status,
        404
    );
    let current = manager.tls.store.as_ref().unwrap().certificates()[0].chain()[0].clone();
    web.shutdown(Duration::from_secs(1));
    drop(manager);
    settings.http_listen.set_port(port);
    let restarted = ManagedTls::start_acme(&settings, config(), |_| {}).unwrap();
    assert_eq!(
        restarted.tls.store.as_ref().unwrap().certificates()[0].chain()[0],
        current
    );
    assert_eq!(restarted.status().unwrap()["ready"], true);
    assert_eq!(ca.certs.lock().unwrap().len(), 2);
    drop(restarted);
    _ca_server.shutdown(Duration::from_secs(1));
}
