use lazaret_pg::{ChannelBinding, Config, ErrorKind, SslMode};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};
fn startup(s: &mut TcpStream) {
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut n = [0; 4];
    s.read_exact(&mut n).unwrap();
    let len = u32::from_be_bytes(n) as usize;
    assert!((8..4096).contains(&len));
    let mut b = vec![0; len - 4];
    s.read_exact(&mut b).unwrap();
    assert_eq!(&b[..4], &196608u32.to_be_bytes());
}
fn frame(s: &mut impl Write, kind: u8, b: &[u8]) {
    s.write_all(&[kind]).unwrap();
    s.write_all(&((b.len() + 4) as u32).to_be_bytes()).unwrap();
    s.write_all(b).unwrap();
    s.flush().unwrap();
}
fn read_frame(s: &mut impl Read) -> (u8, Vec<u8>) {
    let mut h = [0; 5];
    s.read_exact(&mut h).unwrap();
    let n = u32::from_be_bytes(h[1..].try_into().unwrap()) as usize;
    assert!((4..20_000_000).contains(&n));
    let mut b = vec![0; n - 4];
    s.read_exact(&mut b).unwrap();
    (h[0], b)
}
fn serve(f: impl FnOnce(TcpStream) + Send + 'static) -> (Config, thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut c = Config::new();
    c.host("127.0.0.1")
        .port(l.local_addr().unwrap().port())
        .user("fixture")
        .dbname("fixture")
        .password("fixture-password")
        .ssl_mode(SslMode::Disable)
        .operation_timeout(Duration::from_secs(2));
    let handle = thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        startup(&mut s);
        f(s)
    });
    (c, handle)
}
fn auth(s: &mut TcpStream) {
    frame(s, b'R', &0u32.to_be_bytes());
    frame(s, b'Z', b"I");
}
fn query(s: &mut TcpStream) {
    for tag in b"PBDEH" {
        assert_eq!(read_frame(s).0, *tag);
    }
}
fn desc() -> Vec<u8> {
    let mut b = vec![0, 1, b'v', 0];
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&23u32.to_be_bytes());
    b.extend_from_slice(&4u16.to_be_bytes());
    b.extend_from_slice(&(-1i32).to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b
}
fn begin_rows(s: &mut TcpStream) {
    frame(s, b'1', b"");
    frame(s, b'2', b"");
    frame(s, b'T', &desc());
}
#[test]
fn trust_is_refused_when_binding_required() {
    let (mut c, h) = serve(|mut s| {
        frame(&mut s, b'R', &0u32.to_be_bytes());
    });
    c.channel_binding(ChannelBinding::Require);
    assert_eq!(c.connect().unwrap_err().kind, ErrorKind::Authentication);
    h.join().unwrap();
}
#[test]
fn cleartext_password_is_not_sent_without_opt_in() {
    let (c, h) = serve(|mut s| {
        frame(&mut s, b'R', &3u32.to_be_bytes());
        let mut b = [0];
        let n = s.read(&mut b).unwrap_or(0);
        assert!(n == 0 || b[0] == b'X');
    });
    assert!(c.connect().is_err());
    h.join().unwrap();
}
#[test]
fn unexpected_auth_steps_are_rejected() {
    for code in [11u32, 12, 8] {
        let (c, h) = serve(move |mut s| {
            frame(&mut s, b'R', &code.to_be_bytes());
        });
        assert!(c.connect().is_err());
        h.join().unwrap();
    }
}
#[test]
fn invalid_frame_length_and_startup_state_are_rejected() {
    for bytes in [
        b"R\0\0\0\x03".as_slice(),
        b"R\x7f\xff\xff\xff",
        b"Z\0\0\0\x05I",
    ] {
        let bytes = bytes.to_vec();
        let (c, h) = serve(move |mut s| {
            s.write_all(&bytes).unwrap();
        });
        assert!(c.connect().is_err());
        h.join().unwrap();
    }
}
#[test]
fn malformed_rows_close_connection() {
    for body in [
        vec![0, 2],
        vec![0, 1, 255, 255, 255, 254],
        vec![0, 1, 0, 0, 0, 3, b'x', b'y', b'z'],
    ] {
        let (c, h) = serve(move |mut s| {
            auth(&mut s);
            query(&mut s);
            begin_rows(&mut s);
            frame(&mut s, b'D', &body);
        });
        let mut client = c.connect().unwrap();
        assert!(client.query("SELECT 1", &[]).is_err());
        assert!(client.is_closed());
        h.join().unwrap();
    }
}
#[test]
fn recoverable_sql_error_drains_and_reuses_connection() {
    let (c, h) = serve(|mut s| {
        auth(&mut s);
        query(&mut s);
        frame(&mut s, b'E', b"SERROR\0C23505\0Mduplicate fixture\0\0");
        assert_eq!(read_frame(&mut s).0, b'S');
        frame(&mut s, b'Z', b"I");
        query(&mut s);
        begin_rows(&mut s);
        frame(&mut s, b'D', b"\0\x01\0\0\0\x01\x37");
        frame(&mut s, b'C', b"SELECT 1\0");
        assert_eq!(read_frame(&mut s).0, b'S');
        frame(&mut s, b'Z', b"I");
        assert_eq!(read_frame(&mut s).0, b'X');
    });
    let mut client = c.connect().unwrap();
    assert_eq!(client.query("bad", &[]).unwrap_err().code(), Some("23505"));
    assert!(!client.is_closed());
    assert_eq!(
        client.query_one("SELECT 7", &[]).unwrap().get::<_, i32>(0),
        7
    );
    drop(client);
    h.join().unwrap();
}
#[test]
fn deferred_commit_error_is_not_reported_as_success() {
    let (c, h) = serve(|mut s| {
        auth(&mut s);
        query(&mut s);
        begin_rows(&mut s);
        frame(&mut s, b'D', b"\0\x01\0\0\0\x01\x37");
        frame(&mut s, b'C', b"SELECT 1\0");
        assert_eq!(read_frame(&mut s).0, b'S');
        frame(&mut s, b'E', b"SERROR\0C23503\0Mdeferred failure\0\0");
        frame(&mut s, b'Z', b"I");
    });
    let mut client = c.connect().unwrap();
    assert_eq!(
        client.query("fixture", &[]).unwrap_err().code(),
        Some("23503")
    );
    assert!(!client.is_closed());
    h.join().unwrap();
}
#[test]
fn dropping_unfinished_stream_closes_connection() {
    let (c, h) = serve(|mut s| {
        auth(&mut s);
        query(&mut s);
        begin_rows(&mut s);
        frame(&mut s, b'D', b"\0\x01\0\0\0\x01\x37");
        let mut b = [0];
        assert_eq!(s.read(&mut b).unwrap(), 0);
    });
    let mut client = c.connect().unwrap();
    let mut stream = client.query_stream("SELECT 7", &[], 1).unwrap();
    assert_eq!(stream.next().unwrap().unwrap().get::<_, i32>(0), 7);
    drop(stream);
    assert!(client.is_closed());
    h.join().unwrap();
}
#[test]
fn notification_and_server_parameter_bounds() {
    let (c, h) = serve(|mut s| {
        frame(&mut s, b'R', &0u32.to_be_bytes());
        frame(&mut s, b'S', b"client_encoding\0LATIN1\0");
    });
    assert!(c.connect().is_err());
    h.join().unwrap();
}
#[test]
fn operation_timeout_closes_connection() {
    let (mut c, h) = serve(|mut s| {
        auth(&mut s);
        query(&mut s);
        thread::sleep(Duration::from_millis(100));
    });
    c.operation_timeout(Duration::from_millis(30));
    let mut client = c.connect().unwrap();
    assert!(client.query("SELECT 1", &[]).is_err());
    assert!(client.is_closed());
    h.join().unwrap();
}

#[test]
fn legacy_md5_matches_independent_python_hashlib_vector() {
    let (c, h) = serve(|mut s| {
        frame(&mut s, b'R', b"\0\0\0\x05abcd");
        assert_eq!(
            read_frame(&mut s),
            (b'p', b"md50806ab8fda2708da7a28c62ae931003a\0".to_vec())
        );
        auth(&mut s);
        assert_eq!(read_frame(&mut s).0, b'X');
    });
    drop(c.connect().unwrap());
    h.join().unwrap();
}
#[test]
fn cancel_token_uses_original_peer_and_backend_key() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        startup(&mut s);
        frame(&mut s, b'R', &0u32.to_be_bytes());
        frame(
            &mut s,
            b'K',
            &[123u32.to_be_bytes(), 456u32.to_be_bytes()].concat(),
        );
        frame(&mut s, b'Z', b"I");
        let (mut cancel, _) = listener.accept().unwrap();
        cancel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut packet = [0; 16];
        cancel.read_exact(&mut packet).unwrap();
        assert_eq!(
            packet,
            [
                16u32.to_be_bytes(),
                80877102u32.to_be_bytes(),
                123u32.to_be_bytes(),
                456u32.to_be_bytes()
            ]
            .concat()
            .as_slice()
        );
        assert_eq!(read_frame(&mut s).0, b'X');
    });
    let mut cfg = Config::new();
    cfg.host("127.0.0.1")
        .port(port)
        .user("fixture")
        .dbname("fixture")
        .ssl_mode(SslMode::Disable);
    let client = cfg.connect().unwrap();
    let token = client.cancel_token().unwrap();
    assert!(!format!("{token:?}").contains("456"));
    token.cancel_query().unwrap();
    drop(client);
    worker.join().unwrap();
}

#[test]
fn connection_strings_keep_secrets_private_and_reject_unsupported_options() {
    for raw in [
        "host=127.0.0.1 user=u dbname=d password='secret with \\' quote'",
        "postgresql://u:p%40ss@127.0.0.1:5432/d?sslmode=disable",
        "postgres://u:p+ss@[::1]/d",
    ] {
        let c: Config = raw.parse().unwrap();
        assert!(!format!("{c:?}").contains("secret"));
        assert_eq!(c.get_user(), Some("u"));
    }
    for raw in [
        "password='unterminated",
        "host=a,b",
        "sslmode=verify-ca",
        "require_auth=!!md5",
        "require_auth=md5,!password",
        "password=%00 bogus=x",
        "postgres://u:p@x/d?password=%00",
    ] {
        let parsed = raw.parse::<Config>();
        if raw == "host=a,b" {
            assert!(parsed.unwrap().connect().is_err());
        } else {
            assert!(parsed.is_err(), "{raw}");
        }
    }
}
