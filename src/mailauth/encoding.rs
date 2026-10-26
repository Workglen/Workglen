// SPDX-FileCopyrightText: 2026 Workglen contributors
// SPDX-License-Identifier: Apache-2.0
//! First-party adapter for the two active mail-auth Base64 slice call sites.
//! Header folding remains in headers.rs; Pratique supplies padded RFC 4648 bytes.

pub(crate) fn base64_encode_slice(input: &[u8], output: &mut [u8]) -> usize {
    // Preserve the former encoder's complete-four-byte-group truncation policy.
    let input = &input[..input.len().min((output.len() / 4).saturating_mul(3))];
    let mut written = 0;
    // Every non-final chunk is a multiple of three. Temporary encoding storage
    // is at most 256 bytes, independently of the caller's total input size.
    for chunk in input.chunks(192) {
        let encoded = pratique::pem::base64_encode(chunk);
        output[written..written + encoded.len()].copy_from_slice(encoded.as_bytes());
        written += encoded.len();
    }
    written
}
