# Lazaret archive integration

Workglen Mail Security uses the first-party `lazaret-archive` 0.1.9 snapshot
from Lazaret commit `a08bc1684abd29d13e726c014b9dee4d4eacfc20`. The existing
Workglen ZIP reader remains separate because the Lazaret crate deliberately
does not include ZIP.

## Supported subset

| Container | Mail Security coverage |
| --- | --- |
| TAR | Regular files/directories in USTAR, supported PAX metadata and GNU long-name forms |
| GZIP / TAR.GZ | Strict bounded inflation, filename recovery and recursive inspection; TAR.GZ parsed as TAR |
| RAR4 / RAR5 | Stored members only, with header and member CRC checks |
| 7-Zip | Copy, DEFLATE, LZMA1 and LZMA2; supported encoded headers and multiple files per folder |
| BZIP2 | Multi-block and concatenated streams |
| XZ | Single-filter LZMA2 blocks with None, CRC32 or CRC64 checks |
| LZMA-alone | Known-size and end-marker streams |

Compressed/encrypted/solid/split or multi-volume RAR, encrypted 7-Zip,
unsupported coder/filter chains, links and special entries, ambiguous extractor
readings, path collisions, corruption, truncation and limit failures are
mandatory administrator-only quarantine. No partial extraction is accepted.

## Workglen boundary

The Lazaret crate handles one in-memory container. Workglen supplies the mail
policy around it:

- content and filename detection, with a mismatch becoming mandatory quarantine;
- one aggregate configured decoded/expanded-byte ceiling across MIME and nested archives;
- at most 256 archive members and eight nested attachment/message levels;
- a 200x output/input expansion guard once output exceeds 1 MiB;
- recursive inspection of returned files, including executable and serialized-payload magic;
- mandatory quarantine for extractor/filesystem path ambiguity; and
- current-policy re-evaluation before any release.

The five-second scanner deadline is checked before and after each archive call
and between members. The Lazaret API is synchronous and currently exposes no
cooperative mid-decoder work budget; input/output/structure limits and scan
concurrency are the in-call controls. The upstream request is tracked in
`LAZARET-ARCHIVE-BACKLOG.md`.

## Validation

Run offline and locked:

```text
cargo test --offline --locked -p lazaret-archive
cargo test --offline --locked security::tests::lazaret_
cargo test --offline --locked security::tests::gzip_crc_and_expansion_limits
cargo test --offline --locked security::tests::independent_deflated_zip_and_ustar_fixtures
cargo test --offline --locked security::tests::mandatory_attachment_release_prevented_even_for_owner
cargo clippy --offline --locked --all-targets -- -D warnings
```

These are synthetic and fixture-based checks, not a detection-efficacy claim or
live-provider validation.
