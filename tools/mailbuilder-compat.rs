//! Development-only oracle. Compile with rustc --test, aliasing the cached
//! pre-removal mail-builder rlib as old_mail_builder and linking Pratique.
//! Neither mail-builder nor this oracle is in the current Cargo graph.
#[path = "../src/mailauth/encoding.rs"]
mod encoding;

#[test]
fn encoding_and_truncation_match_previous_mail_builder() {
    let mut seed = 0x8c34f01298abcdu64;
    let mut checks = 0;
    for length in 0usize..=4096 {
        let input: Vec<u8> = (0..length)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        let full = length.div_ceil(3) * 4;
        for capacity in [
            0,
            1,
            3,
            4,
            7,
            8,
            9,
            255,
            256,
            257,
            full.saturating_sub(1),
            full,
            full + 3,
        ] {
            let mut old = vec![0xa5; capacity + 8];
            let mut native = old.clone();
            let a = old_mail_builder::encoders::base64::base64_encode_slice(
                &input,
                &mut old[..capacity],
            );
            let b = encoding::base64_encode_slice(&input, &mut native[..capacity]);
            assert_eq!(
                (a, old),
                (b, native),
                "length={length}, capacity={capacity}"
            );
            checks += 1;
        }
    }
    println!("{checks} old/new Base64 and buffer-sentinel comparisons passed");
}
