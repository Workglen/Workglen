use std::{
    net::UdpSocket,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use workglen_mail::{
    auth::{AuthContext, Checker, Verdict},
    config::Policy,
};

#[test]
fn authentication_uses_one_deadline_across_dns_protocol_stages() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = server.local_addr().unwrap();
    server
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let seen = Arc::new(AtomicUsize::new(0));
    let requests = seen.clone();
    let peer = std::thread::spawn(move || {
        let mut bytes = [0; 1024];
        while !done.load(Ordering::Acquire) {
            let (n, peer) = match server.recv_from(&mut bytes) {
                Ok(v) => v,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            let index = requests.fetch_add(1, Ordering::AcqRel);
            if index == 0 {
                // Spend part of the outer budget on SPF, then leave DMARC unanswered.
                std::thread::sleep(Duration::from_millis(100));
                let mut reply = bytes[..n].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                reply[6..8].copy_from_slice(&1u16.to_be_bytes());
                let text = b"v=spf1 +all";
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0]);
                reply.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
                reply.push(text.len() as u8);
                reply.extend_from_slice(text);
                server.send_to(&reply, peer).unwrap();
            }
        }
    });
    let checker = Checker::new(Some(address)).unwrap();
    let policy = Policy::default();
    let start = Instant::now();
    let verdict = checker
        .check_context(
            b"From: sender@example.test\r\nSubject: deadline\r\n\r\nbody\r\n",
            AuthContext {
                ip: "192.0.2.1".parse().unwrap(),
                helo: "mail.example.test",
                from: "sender@example.test",
                hostname: "receiver.test",
                policy: &policy,
                seconds: 1,
            },
        )
        .unwrap();
    let elapsed = start.elapsed();
    stop.store(true, Ordering::Release);
    peer.join().unwrap();
    assert_eq!(verdict, Verdict::Temporary);
    assert!(seen.load(Ordering::Acquire) >= 2);
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(2),
        "{elapsed:?}"
    );
}
