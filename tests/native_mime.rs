//! Independent former-parser snapshots plus focused protocol/security invariants.
extern crate workglen_mime as mail_parser;
#[allow(dead_code)]
#[path = "../tools/mime-reference-native.rs"]
mod reference;
use workglen_mime::{Limits, Message, MessageParser, MimeHeaders, PartType};
#[test]
fn reference_corpus_and_reviewed_differences() {
    let rows: pratique::json_value::Value =
        pratique::json_value::from_str(include_str!("fixtures/native-mime.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let hex = row["hex"].as_str().unwrap().as_bytes();
        let raw: Vec<u8> = hex
            .as_chunks::<2>()
            .0
            .iter()
            .map(|h| u8::from_str_radix(std::str::from_utf8(h).unwrap(), 16).unwrap())
            .collect();
        let parsed = MessageParser::default()
            .parse(&raw)
            .map_or(pratique::json_value::Value::Null, |m| {
                reference::message(&m, 0)
            });
        let expected = row.get("native").unwrap_or(&row["expected"]);
        assert_eq!(&parsed, expected, "{}", row["label"]);
        if row.get("native").is_some() {
            assert!(row["reason"].as_str().is_some_and(|s| !s.is_empty()));
            assert_ne!(&row["expected"], expected);
        }
    }
    println!(
        "{} independent MIME snapshots, with explicit reviewed differences",
        rows.as_array().unwrap().len()
    );
}
fn parse(s: &str) -> Message<'_> {
    MessageParser::default().parse(s.as_bytes()).unwrap()
}
#[test]
fn bad_decoding_and_ambiguous_headers_never_look_complete() {
    for raw in [
        "Content-Transfer-Encoding: base64\r\n\r\n!!!!",
        "Content-Transfer-Encoding: base64\r\n\r\nZh==",
        "Content-Transfer-Encoding: quoted-printable\r\n\r\n=GG",
        "Content-Transfer-Encoding: unknown\r\n\r\nbody",
        "Content-Type: text/plain; charset=unknown\r\n\r\nbody",
        "Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\nbody",
        "Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\nbody",
        "Content-Type: multipart/mixed\r\n\r\nhidden bytes",
        "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*0*=utf-8''part; filename*2*=tail\r\n\r\nx",
        "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=a; filename=b\r\n\r\nx",
    ] {
        let m = parse(raw);
        assert!(m.parts.iter().any(|p| p.is_encoding_problem), "{raw}");
    }
}
#[test]
fn shared_budgets_bound_headers_parts_depth_and_expansion() {
    let p = MessageParser::with_limits(Limits {
        input_bytes: 100,
        ..Limits::default()
    });
    assert!(p.parse(&[b'a'; 101]).is_none());
    let p = MessageParser::with_limits(Limits {
        header_bytes: 10,
        ..Limits::default()
    });
    assert!(p.parse(b"Subject: too long\r\n\r\nx").is_none());
    let p = MessageParser::with_limits(Limits {
        header_fields: 1,
        ..Limits::default()
    });
    assert!(p.parse(b"A: a\r\nB: b\r\n\r\nx").is_none());
    let p = MessageParser::with_limits(Limits {
        parts: 2,
        ..Limits::default()
    });
    assert!(p.parse(b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\none\r\n--x\r\n\r\ntwo\r\n--x--\r\n").is_none());
    let p = MessageParser::with_limits(Limits {
        depth: 2,
        ..Limits::default()
    });
    let mut s = "Subject: end\r\n\r\nx".to_owned();
    for _ in 0..3 {
        s = format!("Content-Type: message/rfc822\r\n\r\n{s}");
    }
    assert!(p.parse(s.as_bytes()).is_none());
    let p = MessageParser::with_limits(Limits {
        decoded_bytes: 100,
        ..Limits::default()
    });
    assert!(
        p.parse(format!("\r\n{}", "x".repeat(60)).as_bytes())
            .is_none()
    );
}
#[test]
fn mime_boundaries_offsets_and_nested_content_are_exact() {
    let raw = "Content-Type: multipart/mixed; boundary=x\r\n\r\npreamble\r\n--xNOT\r\n--x\r\nContent-Type: message/rfc822\r\n\r\nSubject: nested\r\n\r\ninside\r\n--x--\r\nepilogue";
    let m = parse(raw);
    assert_eq!(m.parts.len(), 2);
    let p = &m.parts[1];
    assert_eq!(
        &raw[p.offset_header as usize..p.offset_body as usize],
        "Content-Type: message/rfc822\r\n\r\n"
    );
    let PartType::Message(n) = &p.body else {
        panic!("nested message")
    };
    let root = n.root_part();
    assert_eq!(
        &n.raw_message[root.offset_body as usize..root.offset_end as usize],
        b"inside"
    );
    assert_eq!(p.contents(), b"Subject: nested\r\n\r\ninside");
}
#[test]
fn encoded_display_name_cannot_inject_an_author() {
    let m = parse("From: =?UTF-8?Q?fake=3Cevil=40test=3E?= <real@example.test>\r\n\r\nx");
    let a = m.from().unwrap();
    assert_eq!(a.iter().count(), 1);
    assert_eq!(
        a.first().unwrap().address.as_deref(),
        Some("real@example.test")
    );
    for s in [
        "Good <good@example.test> evil@example.test",
        "Good <good@example.test",
        "\"unclosed <good@example.test>",
        "bad@example.test:good@example.test",
    ] {
        let raw = format!("From: {s}\r\n\r\nx");
        assert!(parse(&raw).from().is_none(), "{s}");
    }
}
#[test]
fn international_parameters_transfer_and_html_projection() {
    let m = parse(
        "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=old.txt; filename*0*=utf-8''caf%C3; filename*1*=%A9.txt\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAw==",
    );
    let a = m.attachment(0).unwrap();
    assert_eq!(a.attachment_name(), Some("café.txt"));
    assert_eq!(a.contents(), [0, 1, 2, 3]);
    assert!(!a.is_encoding_problem);
    let m = parse(
        "Content-Type: text/html\r\n\r\n<script>ignore()</script><style>hide</style><p>&NotEqualTilde; &#x1f600; &amp;</p>",
    );
    assert_eq!(m.body_text(0).unwrap(), "≂̸ 😀 &\n");
    let m = parse("Content-Type: text/plain; charset=utf-7\r\n\r\nHello +- +ThZ1TA-");
    assert_eq!(m.body_text(0).unwrap(), "Hello + 世界");
}
#[test]
fn deterministic_mutations_never_panic_or_escape_offsets() {
    fn check(m: &Message<'_>) {
        for p in &m.parts {
            assert!(
                p.offset_header <= p.offset_body
                    && p.offset_body <= p.offset_end
                    && p.offset_end as usize <= m.raw_message.len()
            );
            match &p.body {
                PartType::Multipart(ids) => {
                    for id in ids {
                        assert!((*id as usize) < m.parts.len());
                    }
                }
                PartType::Message(n) => check(n),
                _ => {}
            }
        }
    }
    let seeds=[b"From: a@example.test\r\nSubject: =?utf-8?Q?text?=\r\n\r\nx".as_slice(),b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Transfer-Encoding: base64\r\n\r\nAA==\r\n--x--\r\n".as_slice()];
    let mut rng = 0xa9122384u64;
    for seed in seeds {
        for _ in 0..10_000 {
            let mut b = seed.to_vec();
            for _ in 0..4 {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let pos = rng as usize % b.len();
                b[pos] = (rng >> 32) as u8;
            }
            if let Some(m) = MessageParser::default().parse(&b) {
                check(&m);
            }
        }
    }
}
