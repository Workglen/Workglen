use super::*;
use pratique::{
    crypto::{ecdsa::Curve, sha2::HashAlg},
    tls::{
        pki::{CertSpec, KeyPair, issue},
        server::{ServerConfig, ServerStream},
    },
};
use std::{net::TcpListener, sync::Arc};
struct FixtureDir(std::path::PathBuf);
impl FixtureDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "lazaret-pg-tls-{}",
            pratique::util::hex(&pratique::crypto::rand::bytes::<16>().unwrap())
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("ca.pem"));
        let _ = std::fs::remove_dir(&self.0);
    }
}
fn exchange(host: &str, trusted: bool, expired: bool) -> bool {
    let ca = KeyPair::generate_ecdsa(Curve::P256).unwrap();
    let root = issue(&CertSpec::ca("test CA"), &ca, None);
    let key = KeyPair::generate_ecdsa(Curve::P256).unwrap();
    let mut spec = CertSpec::server(&["localhost"]);
    if expired {
        spec.not_after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 1;
    }
    let leaf = issue(&spec, &key, Some(("test CA", &ca)));
    let expected = HashAlg::Sha256.digest(&leaf);
    let server = Arc::new(ServerConfig::new(vec![leaf, root.clone()], key));
    let directory = FixtureDir::new();
    let ca_file = directory.path().join("ca.pem");
    let trusted_root = if trusted {
        root
    } else {
        let ca = KeyPair::generate_ecdsa(Curve::P256).unwrap();
        issue(&CertSpec::ca("other CA"), &ca, None)
    };
    std::fs::write(
        &ca_file,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            pratique::pem::base64_encode(&trusted_root)
        ),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = [0; 8];
        tcp.read_exact(&mut request).unwrap();
        assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
        tcp.write_all(b"S").unwrap();
        if let Ok(mut tls) = ServerStream::accept(tcp, &server) {
            let mut data = vec![0; 131072];
            if tls.read_exact(&mut data).is_ok() {
                assert!(data.iter().all(|b| *b == 73));
                for part in data.chunks(701) {
                    tls.write_all(part).unwrap();
                }
                tls.flush().unwrap();
            }
        }
    });
    let mut config = Config::new();
    config
        .host(host)
        .hostaddr("127.0.0.1".parse().unwrap())
        .port(port)
        .ca_file(ca_file);
    let success = if let Ok(mut stream) = Transport::connect(&config) {
        assert_eq!(stream.binding.take().unwrap(), expected);
        stream.binding = None;
        let data = vec![73; 131072];
        stream.write_all(&data).unwrap();
        stream.flush().unwrap();
        let mut received = vec![0; data.len()];
        stream.read_exact(&mut received).unwrap();
        assert_eq!(received, data);
        true
    } else {
        false
    };
    worker.join().unwrap();
    success
}
#[test]
fn postgres_transport_verifies_chain_hostname_expiry_and_moves_records() {
    assert!(exchange("localhost", true, false));
    assert!(!exchange("wrong.example", true, false));
    assert!(!exchange("localhost", false, false));
    assert!(!exchange("localhost", true, true));
}
#[test]
fn channel_binding_uses_the_certificate_hash_and_refuses_undefined_algorithms() {
    let key = KeyPair::generate_ecdsa(Curve::P384).unwrap();
    let cert = issue(&CertSpec::server(&["localhost"]), &key, None);
    assert_eq!(endpoint_hash(&cert).unwrap(), HashAlg::Sha384.digest(&cert));
    let key = KeyPair::generate().unwrap();
    let cert = issue(&CertSpec::server(&["localhost"]), &key, None);
    assert!(endpoint_hash(&cert).is_none());
    assert!(endpoint_hash(b"invalid").is_none());
}
#[test]
fn postgres_scram_plus_authenticates_with_required_channel_binding() {
    use pratique::crypto::{
        hmac::Hmac,
        sha2::{Hash, Sha256},
    };
    fn send(tls: &mut impl Write, code: u32, data: &[u8]) {
        tls.write_all(b"R").unwrap();
        tls.write_all(&((data.len() + 8) as u32).to_be_bytes())
            .unwrap();
        tls.write_all(&code.to_be_bytes()).unwrap();
        tls.write_all(data).unwrap();
        tls.flush().unwrap();
    }
    fn password(tls: &mut impl Read) -> Vec<u8> {
        let mut header = [0u8; 5];
        tls.read_exact(&mut header).unwrap();
        assert_eq!(header[0], b'p');
        let n = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
        assert!((4..4096).contains(&n));
        let mut body = vec![0; n - 4];
        tls.read_exact(&mut body).unwrap();
        body
    }
    let ca = KeyPair::generate_ecdsa(Curve::P256).unwrap();
    let root = issue(&CertSpec::ca("SCRAM fixture CA"), &ca, None);
    let key = KeyPair::generate_ecdsa(Curve::P256).unwrap();
    let leaf = issue(
        &CertSpec::server(&["localhost", "127.0.0.1"]),
        &key,
        Some(("SCRAM fixture CA", &ca)),
    );
    let binding = HashAlg::Sha256.digest(&leaf);
    let mut server = ServerConfig::new(vec![leaf, root.clone()], key);
    server.alpn_protocols = vec![b"postgresql".to_vec()];
    let server = Arc::new(server);
    let directory = FixtureDir::new();
    let ca_file = directory.path().join("ca.pem");
    std::fs::write(
        &ca_file,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            pratique::pem::base64_encode(&root)
        ),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = [0u8; 8];
        tcp.read_exact(&mut request).unwrap();
        assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
        tcp.write_all(b"S").unwrap();
        let mut tls = ServerStream::accept(tcp, &server).unwrap();
        let mut size = [0u8; 4];
        tls.read_exact(&mut size).unwrap();
        let n = u32::from_be_bytes(size) as usize;
        assert!((8..4096).contains(&n));
        let mut startup = vec![0; n - 4];
        tls.read_exact(&mut startup).unwrap();
        send(&mut tls, 10, b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0");
        let initial = password(&mut tls);
        let end = initial.iter().position(|b| *b == 0).unwrap();
        assert_eq!(&initial[..end], b"SCRAM-SHA-256-PLUS");
        let initial = std::str::from_utf8(&initial[end + 5..]).unwrap();
        let bare = initial.strip_prefix("p=tls-server-end-point,,").unwrap();
        let client_nonce = bare.split(',').find_map(|x| x.strip_prefix("r=")).unwrap();
        let nonce = format!("{client_nonce}server-fixture");
        let salt = b"synthetic-salt-2026";
        let first = format!("r={nonce},s={},i=4096", pratique::pem::base64_encode(salt));
        send(&mut tls, 11, first.as_bytes());
        let final_message = String::from_utf8(password(&mut tls)).unwrap();
        let (without, proof) = final_message.rsplit_once(",p=").unwrap();
        let bound = without
            .split(',')
            .find_map(|x| x.strip_prefix("c="))
            .unwrap();
        assert_eq!(
            pratique::pem::base64_decode_strict(bound).unwrap(),
            [b"p=tls-server-end-point,,".as_slice(), &binding].concat()
        );
        assert!(without.ends_with(&format!("r={nonce}")));
        let auth = format!("{bare},{first},{without}");
        let mut u = Hmac::<Sha256>::mac(
            b"fixture-password",
            &[salt.as_slice(), &1u32.to_be_bytes()].concat(),
        );
        let mut salted = u.clone();
        for _ in 1..4096 {
            u = Hmac::<Sha256>::mac(b"fixture-password", &u);
            for (a, b) in salted.iter_mut().zip(&u) {
                *a ^= *b;
            }
        }
        let client_key = Hmac::<Sha256>::mac(&salted, b"Client Key");
        let stored = Sha256::digest(&client_key);
        let signature = Hmac::<Sha256>::mac(&stored, auth.as_bytes());
        let expected: Vec<u8> = client_key
            .iter()
            .zip(signature)
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(
            pratique::pem::base64_decode_strict(proof).unwrap(),
            expected
        );
        let server_key = Hmac::<Sha256>::mac(&salted, b"Server Key");
        let signature = Hmac::<Sha256>::mac(&server_key, auth.as_bytes());
        send(
            &mut tls,
            12,
            format!("v={}", pratique::pem::base64_encode(&signature)).as_bytes(),
        );
        send(&mut tls, 0, &[]);
        tls.write_all(b"Z\0\0\0\x05I").unwrap();
        tls.flush().unwrap();
        let mut termination = [0u8; 5];
        tls.read_exact(&mut termination).unwrap();
        assert_eq!(&termination, b"X\0\0\0\x04");
    });
    let mut config = crate::Config::new();
    config
        .host("127.0.0.1")
        .port(port)
        .user("fixture")
        .password("fixture-password")
        .dbname("fixture")
        .ssl_mode(crate::SslMode::Require)
        .channel_binding(crate::ChannelBinding::Require);
    let client = config.ca_file(&ca_file).connect().unwrap();
    drop(client);
    worker.join().unwrap();
}
