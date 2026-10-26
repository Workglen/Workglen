# Native email and MIME

First-party, bounded parsing for Workglen's existing consumers. No mail-parser
implementation source is copied. The crate has no external dependencies. Native charset conversion includes
multibyte Japanese, Chinese, Korean and stateful encodings; see ../../NATIVE-CHARSETS.md.

Supported application APIs cover raw headers, unfolded/encoded-word subjects,
mailboxes/groups, dates and message IDs, content headers, multipart trees,
nested message/rfc822 and message/global, body selection, attachments, MIME
Base64/quoted-printable and HTML-to-text projection. Parameters support quoted
strings, RFC 2231 extended values and contiguous continuations. Invalid or
ambiguous decoding sets `is_encoding_problem`; hard limits return `None`.

Default bounds: 64 MiB input; 64 KiB and 256 fields per header block; 128 MIME
parameters per content header; 32 nested levels; 1024 total parts and 256 MiB
cumulative work/decoded-byte accounting across nested messages. Workglen's
scanner additionally retains its smaller inspection budgets. `parse_headers`
reads the root header only. Buffers and offsets for nested messages are local to
each `Message::raw_message`; multipart offsets address their containing message.

This is the subset used by the application, not a drop-in public implementation
of every API from mail-parser. HTML projection is not sanitization; existing
Webmail escaping remains necessary. A recognized charset is not a promise that
all byte sequences are valid. Unknown charsets and invalid sequences are marked
incomplete rather than silently clean.

Run `python3 tools/generate.py --check` in this crate to verify generated data.
The generator uses bundled files only and does not rely on Python's Unicode
version. Protocol tests and the independent corpus live in the workspace's
`tests/native_mime.rs`; see ../../NATIVE-MIME.md and ../../PORTABLE-CHECKS.md.

## Data provenance

- `data/cp850.txt`: https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP850.TXT
- `data/iso8859-16.txt`: https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-16.TXT
- Unicode files: retain `data/LICENSE-UNICODE` (Unicode License v3).
- `data/entities.json`: https://html.spec.whatwg.org/entities.json
- WHATWG data: retain `data/LICENSE-HTML`; its BSD-3-Clause option applies to
  portions incorporated into code, while the specification uses CC BY 4.0.
- `data/indexes.json` and `encodings.json`: https://encoding.spec.whatwg.org/
- Encoding data: retain `data/LICENSE-WHATWG`; source URLs and retrieval hashes
  are recorded in `data/encoding-provenance.json`.
- Exact input hashes: `data/SHA256.json`.

Protocol references: RFC 5322, RFC 2045, RFC 2046, RFC 2047, RFC 2231,
RFC 2387 (related root selection), RFC 2152 (UTF-7), and the WHATWG Encoding
and HTML specifications. Our Rust protocol code uses the workspace Apache-2.0
license; embedded generated Unicode/HTML data keeps the notices above.
