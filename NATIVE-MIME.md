# Native email/MIME parsing — DEPS-15

Current update: the legacy charset layer described as retained in this earlier
MIME checkpoint has now been replaced. See NATIVE-CHARSETS.md for the native
decoders, zero-external-dependency rule and independent comparisons.

The cumulative source now contains **51 external registry package versions**,
from 54 at the IDNA checkpoint and 96 before native authentication: **45 removed**.
This stage removes `mail-parser 0.11.9`, `hashify 0.2.9` and the exclusive
`syn 2.0.119`. The retained `syn 3.0.9` remains needed by Serde. There are 57
lockfile entries including six first-party packages and seven direct external
crates. No registry addition, upgrade or retained checksum change is made.

`workglen-mime` now serves all former mail-parser consumers: From parsing for
SMTP authentication, security inspection, IMAP envelope/sections/bodystructure,
Webmail previews and attachments, and DKIM2 returned-message parsing. Structure,
headers, address delimiters, transfer decoding, international filenames and HTML
text projection are native Rust. Existing `encoding_rs 0.8.42` stays in the graph
for legacy charset decoding. UTF-7, UTF-16, CP850 and ISO-8859-16 support is also
preserved. This stage does not claim to remove all charset dependencies.

The parser enforces input/header/part/depth/decoded-work limits shared across
nested messages. Corrupt transfer data, unknown or damaged charset decoding,
ambiguous content headers, broken parameter continuations and truncated MIME
boundaries set an incomplete flag consumed by mandatory security quarantine.
Hard resource limits return a parse failure. Encoded display names are decoded
after address delimiters, so they cannot introduce a second mailbox.

## Reproducible evidence

`tests/native_mime.rs` includes former-parser snapshots and focused limits,
malformed-input, nested-offset, transfer, filename, encoded-address and HTML
checks. A deterministic 20,000-input mutation test checks panic/offset safety.
`tools/generate-mime-fixtures.py` creates synthetic inputs, including Python's
standard email writer; no network or real mail is involved. The fixture corpus
also records all 252 former charset labels and 33 all-byte charset cases.

The corpus contains 344 snapshots: 312 exact matches and 32 reviewed differences.

The checked snapshot file retains both old expectations and explicit corrected
expectations, each with a review reason. Deliberate differences include quoted
local parts, obsolete address routes, RFC 2231 filename precedence, related
Content-ID root selection, UTF-7 plus escaping, complete HTML entities and strict
boundary-line matching. Nested offsets consistently address nested raw buffers.
Modern official/retained charset mappings correct a few old mappings; undefined
or invalid bytes now flag incomplete inspection. Full details are in
`tests/fixtures/native-mime.json`. No claim of universal parser equivalence is
made from this finite corpus.

The old parser exists only in the optional isolated development reference
harness. It is absent from the application manifest, lockfile and source tree.
The ordinary portable runner executes MIME tests and exact data regeneration
alongside all prior authentication, Unicode, URL, storage and delivery checks.
See [PORTABLE-CHECKS.md](PORTABLE-CHECKS.md) for commands and recorded results.

Official Unicode mapping data and the WHATWG HTML entity data remain bundled
with hashes, licenses and an offline generator. Removing parser crates does not
remove their data attribution requirements. No installed configuration, data,
keys or deployment is changed.

The IDNA security capability assessment is in [NATIVE-IDNA.md](NATIVE-IDNA.md).
UTS #46 validation, full IDNA2008 eligibility, impersonation detection and domain
reputation are explicitly distinguished; the latter policies are not silently
introduced by the MIME work.

Validation passed: 218 Rust tests (four optional PostgreSQL fixtures ignored),
release Clippy/build, 54 outbound/DKIM, 119 mail/IMAP and 34 Webmail checks.
