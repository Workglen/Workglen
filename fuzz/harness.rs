//! Shared replay/libFuzzer entry points. Memory-only; no sockets, DNS or system
//! trust. The fixed test date and trust anchor make inputs reproducible.
pub const TARGETS: [&str; 4] = ["tls_client", "tls_server", "h2", "x509"];
pub const MAX_INPUT: usize = 65536;

pub fn exercise(target: &str, data: &[u8]) {
    if data.len() > MAX_INPUT { return; }
    match target {
        "tls_client" => {
            let Some((&mode, bytes)) = data.split_first() else { return; };
            match mode % 4 {
                0 => pratique::tls::fuzz_hooks::server_bytes(bytes),
                1 => pratique::tls::fuzz_hooks::server_flight(bytes),
                2 => pratique::tls::fuzz_hooks::peer_records(bytes),
                _ => { pratique::tls::fuzz_hooks::server_flight12(bytes); }
            }
        }
        "tls_server" => pratique::tls::server_fuzz::server_exchange(data),
        "h2" => {
            let Some((&mode, bytes)) = data.split_first() else { return; };
            match mode % 4 {
                0 => pratique::http::fuzz_hooks::h2_hpack(bytes),
                1 => { pratique::http::fuzz_hooks::h2_frames(bytes); }
                2 => pratique::http::fuzz_hooks::h2_client(bytes),
                _ => pratique::http::fuzz_hooks_server::h2_server(bytes),
            }
        }
        "x509" => {
            if let Ok(cert) = pratique::x509::Certificate::from_der(data) {
                let _ = cert.matches_hostname("example.test");
                let _ = cert.subject_summary();
                let _ = cert.verify_signed_by(&cert);
            }
            let mut trust = pratique::x509::TrustStore::empty();
            trust.add_pem(include_str!("../vendor/pratique/tests/data/root_rsa.pem"));
            let chain = pratique::tls::fuzz_hooks::example_chain();
            let _ = trust.verify_server_chain(&[data.to_vec(), chain[1].clone()], "example.test", 1789430400);
        }
        _ => panic!("unknown target"),
    }
}

pub fn seeds(target: &str) -> Vec<Vec<u8>> {
    let prefix = |tag, mut bytes: Vec<u8>| { bytes.insert(0,tag); bytes };
    let mut out = vec![vec![], vec![0], vec![255; 32]];
    match target {
        "tls_client" => {
            for i in 0..3 {
                out.push(prefix(0, prefix(0, pratique::tls::fuzz_hooks::example_server_hello(i))));
                out.push(prefix(0, prefix(1, pratique::tls::fuzz_hooks::example_hello_retry(i))));
                out.push(prefix(3, prefix(0, prefix(i, pratique::tls::fuzz_hooks::example_tls12_flight(i, 0)))));
            }
        }
        "tls_server" => out.extend(pratique::tls::server_fuzz::server_exchange_seeds()),
        "h2" => {
            out.extend(pratique::http::fuzz_hooks::h2_example_header_blocks().into_iter().map(|s| prefix(0,s)));
            out.extend(pratique::http::fuzz_hooks::h2_example_server_flights().into_iter().map(|s| prefix(2,s)));
            out.extend(pratique::http::fuzz_hooks::h2_example_client_flights().into_iter().map(|s| prefix(3,s)));
        }
        "x509" => {
            out.extend(pratique::tls::fuzz_hooks::example_chain());
            out.extend(pratique::pem::parse(include_str!("../vendor/pratique/tests/data/root_rsa.pem")).into_iter().map(|p|p.data));
        }
        _ => panic!("unknown target"),
    }
    out
}
