# Native MIME charsets and reusable-library dependency boundary

At the DEPS-19 checkpoint, all six then-present reusable libraries—Pratique,
Lazaret PostgreSQL, native DNS, IDNA, MIME and TOML—required only std and reviewed
first-party libraries. The automatic
boundary check inspects their resolved dependency closure and every manifest
section, including disabled optional, development, build and platform dependencies.
The current source adds two first-party Lazaret archive packages and enforces the
same boundary across all eight. The root Workglen application retains its
database/password dependencies separately.

First-party MIME decoders replace encoding_rs without reducing supported legacy
charsets. The removed package versions are encoding_rs 0.8.42, cfg-if 1.0.5,
core_detect 1.0.0, multiversion_no_op 1.0.0, rustversion 1.0.23, scopeguard 1.2.0
and simdutf8 0.1.5: 22 to 15 external versions. The complete update also removes
11 Serde/JSON packages, taking the prior source from 33 to 15. Retained registry
versions and checksums are unchanged.

The earlier catalog's Android description for simdutf8 was incorrect. It was
encoding_rs's SIMD UTF-8 validation helper on supported CPUs, including Linux
and macOS. Workglen's main UTF-8 MIME path already used std. The new graph removes
that helper through charset replacement, not by excluding Android.

## Implementation and provenance

`crates/native-mime/src/charset_whatwg.rs` contains first-party decoding logic
for single-byte encodings, GBK/GB18030, Big5, EUC-JP, Shift_JIS, ISO-2022-JP,
EUC-KR, replacement and x-user-defined. Existing MIME label aliases, UTF-7,
UTF-8/UTF-16 handling, CP850 and ISO-8859-16 behavior remain in `charset.rs`.
BOM overrides and malformed-input error flags preserve the former adapter's
behavior, including its distinct legacy UTF-16 label handling.

Official WHATWG indexes and labels were retrieved on October 26, 2026. Their
verbatim inputs, URLs, SHA-256 hashes, notices and offline generator ship in
`crates/native-mime/data/` and `tools/generate.py`. Generated arrays are mapping
data. No encoding_rs decoder code or generated implementation tables were copied.
The existing Unicode mappings keep their Unicode notice. WHATWG data keeps
`LICENSE-WHATWG` (CC-BY-4.0; BSD-3-Clause for portions incorporated into code).

Decoding has linear work in input length with bounded table lookup; output is
at most three UTF-8 bytes per input byte. Existing MIME input, part, nesting and
decoded-size limits still apply. Invalid encodings remain visible to incomplete
scan/quarantine logic. Byte-sequence failures preserve ASCII delimiters according
to each codec's rules; ISO-2022-JP's stateful rules are tested separately. No
platform conversion service, dynamic library, subprocess or network lookup is used.

## Reproducible evidence

The independent comparison has **2,883,056 cases with zero mismatches**, comparing
both decoded text and error flags through the old and new MIME adapters. It covers:

- Accepted WHATWG labels and additional MIME aliases, empty/single-byte sweeps.
- Every two-byte sequence for eight common multibyte/UTF-8 encodings.
- Every syntactically shaped GB18030 four-byte sequence, including invalid ranges.
- Every EUC-JP JIS0212 trailing pair and ISO-2022-JP pairs in five initial states.
- BOM overrides, truncated/surrogate cases, seeded arbitrary inputs, consecutive
  and malformed state transitions.

The standard Rust tests rerun the exact inputs and compare per-label SHA-256
fingerprints of framed input, decoded output and error flags against the former
engine. Focused assertions also check delimiter preservation and unknown labels.
The native charset test requires only the first-party Pratique hash in development.
All 344 existing MIME snapshots and the application suites are retained.
This is synthetic compatibility evidence, not universal conformance or an audit.

```sh
python3 tools/check-first-party-dependencies.py
python3 crates/native-mime/tools/generate.py --check
cargo test --offline --locked -p workglen-mime
python3 tools/check-charset-reference.py --baseline-zip /path/to/native-tokio-source.zip --output /tmp/charset-reference
```

The last command is optional independent verification. It requires the exact v33
source ZIP (hash in NATIVE-DATA.md) and cached encoding_rs 0.8.42 dependencies.
Its frozen oracle lock is outside the application graph. It refuses unexpected
differences and never refreshes expectations automatically. Full portable checks
and executed logs are documented in PORTABLE-CHECKS.md and VALIDATION.md.
