#[path = "../src/mailauth/encoding.rs"]
mod encoding;

#[test]
fn rfc_vectors_and_output_bounds() {
    for (input, expected) in [
        (&b""[..], ""),
        (&b"f"[..], "Zg=="),
        (&b"fo"[..], "Zm8="),
        (&b"foo"[..], "Zm9v"),
        (&b"foob"[..], "Zm9vYg=="),
        (&b"fooba"[..], "Zm9vYmE="),
        (&b"foobar"[..], "Zm9vYmFy"),
        (&[251, 255][..], "+/8="),
    ] {
        for capacity in 0..=expected.len() + 5 {
            let mut output = vec![0xa5; capacity + 7];
            let written = encoding::base64_encode_slice(input, &mut output[..capacity]);
            let length = expected.len().min(capacity / 4 * 4);
            assert_eq!(written, length);
            assert_eq!(&output[..written], &expected.as_bytes()[..length]);
            assert!(output[written..].iter().all(|b| *b == 0xa5));
        }
    }
}

#[test]
fn streamed_chunks_do_not_add_padding_or_newlines_between_blocks() {
    // 0xff groups encode to '/', with independently specified final padding.
    for (length, tail) in [
        (191, "//8="),
        (192, ""),
        (193, "/w=="),
        (194, "//8="),
        (384, ""),
        (385, "/w=="),
    ] {
        let input = vec![255; length];
        let expected = "/".repeat(length / 3 * 4) + tail;
        let mut output = vec![0xa5; expected.len() + 3];
        let written = encoding::base64_encode_slice(&input, &mut output);
        assert_eq!(&output[..written], expected.as_bytes());
        assert_eq!(&output[written..], &[0xa5; 3]);
    }
}
