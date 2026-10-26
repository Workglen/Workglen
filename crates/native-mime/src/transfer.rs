//! RFC 2045 transfer encodings. Errors preserve recoverable bytes and are
//! reported to the scanner; damaged input never becomes a silent clean decode.
pub fn base64(input: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut bits = 0u32;
    let mut count = 0u8;
    let mut digits = 0usize;
    let mut padding = 0usize;
    let mut bad = false;
    for &b in input {
        let value = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => {
                bad = true;
                continue;
            }
        };
        if padding > 0 {
            bad = true;
        }
        digits += 1;
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    let remainder = digits % 4;
    bad |= remainder == 1
        || padding > 2
        || (padding > 0
            && (!(digits + padding).is_multiple_of(4)
                || padding
                    != if remainder == 2 {
                        2
                    } else if remainder == 3 {
                        1
                    } else {
                        0
                    }));
    if count > 0 {
        bad |= bits & ((1 << count) - 1) != 0;
    }
    // Missing final padding is common in stored MIME; complete octets are retained.
    (out, bad)
}
pub fn quoted_printable(input: &[u8], word: bool) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len());
    let mut bad = false;
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'_' if word => out.push(b' '),
            b'=' => {
                if !word && input.get(i + 1) == Some(&b'\r') && input.get(i + 2) == Some(&b'\n') {
                    i += 3;
                    continue;
                }
                if !word && input.get(i + 1) == Some(&b'\n') {
                    i += 2;
                    continue;
                }
                if let (Some(a), Some(b)) = (
                    input.get(i + 1).and_then(|v| (*v as char).to_digit(16)),
                    input.get(i + 2).and_then(|v| (*v as char).to_digit(16)),
                ) {
                    out.push((a * 16 + b) as u8);
                    i += 3;
                    continue;
                }
                bad = true;
                out.push(b'=');
            }
            b => out.push(b),
        }
        i += 1;
    }
    (out, bad)
}
pub fn decode(input: &[u8], encoding: Option<&str>) -> (Vec<u8>, bool) {
    match encoding.unwrap_or("7bit").to_ascii_lowercase().as_str() {
        "base64" => base64(input),
        "quoted-printable" => quoted_printable(input, false),
        "7bit" | "8bit" | "binary" => (input.to_vec(), false),
        _ => (input.to_vec(), true),
    }
}
