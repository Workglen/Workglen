# Workglen native IDNA

First-party domain processing implements Unicode 18 UTS #46 mapping, NFC,
validation, ContextJ and RFC 5893 bidi rules, with Pratique Punycode. The default
API matches the prior nontransitional `idna::domain_to_ascii` settings. URL and
DNS callers retain their separate forbidden-character and wire-length policies.
No registry dependency, network access, runtime data file or external process is
required. Tables are compiled into the executable.

Unicode data and conformance inputs are third-party data under Unicode License
v3, preserved verbatim with `LICENSE-UNICODE` and `data/SHA256.json`. The Rust
logic and generator are Workglen code; no IDNA/ICU implementation is copied.

`domain_to_ascii` returns an error for invalid input. `to_unicode` also returns
an error instead of producing a best-effort display string. `Options` permits
the standard switches for conformance tests; application defaults check joiners
and bidi. Strict DNS conversion allows a final root dot by default; the pure
UTS #46 conformance tests disable that allowance explicitly.

Bounds: 64 KiB input domains, 256 KiB mapping/normalization buffers (counted as
bytes or scalars at the appropriate stage), and the former implementation's
1000-scalar encoding / 2000-byte decoding Punycode label bounds. The added domain
cap exceeds legal DNS names and prevents unbounded URL-host allocation. Canonical
combining runs use stable sorting instead of quadratic insertion.

## Offline verification

```sh
python3 crates/native-idna/tools/generate.py --check
cargo test --offline --locked -p workglen-idna -- --nocapture
```

The generator consumes pinned data directly; it never uses Python's Unicode
database. Without `--check` it regenerates `src/tables.rs` and the hash inventory.
The conformance suite tests successful output and valid/invalid decisions;
error strings and best-effort invalid-display strings are not a public API.
Two rows with isolated UTF-16 surrogates cannot be represented by Rust `str`
and are explicitly counted as skipped.

Sources, all version 18.0.0:

- https://www.unicode.org/Public/18.0.0/idna/IdnaMappingTable.txt
- https://www.unicode.org/Public/18.0.0/idna/IdnaTestV2.txt
- https://www.unicode.org/Public/18.0.0/ucd/UnicodeData.txt
- https://www.unicode.org/Public/18.0.0/ucd/DerivedNormalizationProps.txt
- https://www.unicode.org/Public/18.0.0/ucd/extracted/DerivedJoiningType.txt
- https://www.unicode.org/Public/18.0.0/ucd/extracted/DerivedBidiClass.txt
- https://www.unicode.org/Public/18.0.0/ucd/NormalizationTest.txt

Specifications: https://www.unicode.org/reports/tr46/tr46-36.html,
https://www.unicode.org/reports/tr15/tr15-58.html,
https://www.rfc-editor.org/rfc/rfc5892 and
https://www.rfc-editor.org/rfc/rfc5893.
