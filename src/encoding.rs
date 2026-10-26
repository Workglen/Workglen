//! First-party Base64 facade. Pratique supplies the codec; these policies preserve
//! standard padded and URL-safe unpadded canonical forms at application boundaries.
use std::fmt;

#[derive(Clone, Copy)]
pub struct Base64 { url_safe: bool }
pub const STANDARD: Base64 = Base64 { url_safe: false };
pub const URL_SAFE_NO_PAD: Base64 = Base64 { url_safe: true };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("Invalid Base64 encoding") }
}
impl std::error::Error for DecodeError {}

impl Base64 {
    pub fn encode(self, input: impl AsRef<[u8]>) -> String {
        let text = pratique::pem::base64_encode(input.as_ref());
        if self.url_safe { text.trim_end_matches('=').replace('+', "-").replace('/', "_") } else { text }
    }
    pub fn decode(self, input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
        let text = std::str::from_utf8(input.as_ref()).map_err(|_| DecodeError)?;
        let normalized;
        let standard = if self.url_safe {
            if text.len() % 4 == 1 || text.bytes().any(|b| !b.is_ascii_alphanumeric() && b != b'-' && b != b'_') { return Err(DecodeError); }
            let mut value = text.replace('-', "+").replace('_', "/");
            value.extend(std::iter::repeat_n('=', (4 - value.len() % 4) % 4));
            normalized = value; normalized.as_str()
        } else { text };
        let decoded = pratique::pem::base64_decode_strict(standard).ok_or(DecodeError)?;
        // Also protects against any future relaxation of Pratique's PEM decoding.
        if self.encode(&decoded) != text { return Err(DecodeError); }
        Ok(decoded)
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn rfc4648_vectors_and_binary_alphabets() {
        for (raw, encoded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(STANDARD.encode(raw), encoded);
            assert_eq!(STANDARD.decode(encoded).unwrap(), raw.as_bytes());
            assert_eq!(URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('=')).unwrap(), raw.as_bytes());
        }
        assert_eq!(STANDARD.encode([251,255]), "+/8=");
        assert_eq!(URL_SAFE_NO_PAD.encode([251,255]), "-_8");
        assert_eq!(URL_SAFE_NO_PAD.decode("-_8").unwrap(), [251,255]);
    }
    #[test] fn refuses_noncanonical_and_mixed_forms() {
        for bad in ["Zg", "Zg=", "Zg===", "Zh==", "Zm9=", "Zg==\n", " Zg==", "AA=A", "A===", "====", "-_8="] { assert!(STANDARD.decode(bad).is_err(), "{bad:?}"); }
        for bad in ["Zg=", "Zg==", "Zh", "Zm9", "A", "Zm9v\n", "+/8", "-_8="] { assert!(URL_SAFE_NO_PAD.decode(bad).is_err(), "{bad:?}"); }
        assert!(STANDARD.decode([255]).is_err());
    }
}
