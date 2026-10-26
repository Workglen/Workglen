# Unused mail-auth reporting/compression cleanup

The Workglen mail-auth deployment already disables the upstream report module
and does not expose its `report` feature. Its unconditional flate2 dependency
was still compiled solely because of an unconditional public re-export. The
deployment manifest now removes that dependency, and the re-export is gated by
the same disabled report configuration as the module.

This is removal of unused code from the build, not a new compressor. No supported
Workglen reporting function, mail authentication check or quarantine/digest
feature is removed. Original disabled report sources remain in the attributed
third-party package for provenance. Re-enabling upstream report generation or
parsing would require an explicit feature and dependency review.

## Exact dependency result

The lockfile removes six package versions:

| Package | Version |
|---|---|
| flate2 | 1.1.10 |
| crc32fast | 1.5.3 |
| miniz_oxide | 0.9.1 |
| adler2 | 2.0.1 |
| simd-adler32 | 0.3.10 |
| zlib-rs | 0.6.8 |

External package versions decrease from **188 to 182**: 181 registry entries
and the one attributed mail-auth path package. There are 185 total lockfile
entries including Workglen, Pratique and lazaret-pg. No retained version/checksum
changes and no new registry packages occur. Together with the preceding bincode
checkpoint, this removes **seven** external package versions (189 to 182).
Counts include all platforms/build/test; they are not memory or executable-size
measurements. See `validation/0.8-native-mailauth-reports-inventory.json`.

## Preserved behavior and provenance

Mail-builder remains necessary for DKIM header/signature encoding. Similar,
serde_json and memchr still serve active DKIM2 code; their dependencies are not
removed under the label of unused reporting utilities. MIME/charset support,
DNS, SPF/DKIM/DMARC handling and Pratique cryptography retain their existing
configuration. RSA-SHA1 acceptance is unchanged by this cleanup; its separately
discussed policy change is not part of this checkpoint.

Security archive inspection already uses the native Pratique inflater and
Workglen archive reader. Those files are unchanged, including mandatory
quarantine for unsupported or incompletely scanned archives. The dependency
allowlist pins the revised third-party deployment manifest and complete graph.

Upstream notices, license texts and identity remain in `vendor/mail-auth/`.
`WORKGLEN-PATCHES.json` records the current file hashes and
`workglen-pratique.patch` reproduces the complete changes against the published
source. Verification reconstructed and checked 66 upstream files, reapplied
the patch and compared all modified files exactly. See
`validation/0.8-native-mailauth-reports-provenance.json`.

## Executed validation

On Linux x86-64, Rust 1.99.1: **152 offline locked Rust tests**, release Clippy
with warnings denied, the release build and **54 direct-delivery/DKIM loopback
checks** passed. The Rust suite includes native archive inspection/quarantine,
mail-auth signature and tampering fixtures, and replication codec persistence
and malformed-frame cases. Four opt-in disposable PostgreSQL/accounting tests
remain skipped; those components were not changed. Results are in
`validation/0.8-native-mailauth-reports-*`.

The preceding bincode checkpoint's 119 mail/replication checks and independent
format comparisons are retained under `validation/0.8-native-bincode-*`.
Neither stage tested a live Microsoft 365 tenant, deployed to either host, or
claimed a Mac build. All mail/DNS peers used here were synthetic local fixtures.

This cumulative source ZIP also contains the native replication codec. Rebuild
with `bash install.sh build` as the normal build account, then use the existing
Mac/Lightsail stop, binary replacement and restart instructions. Preserve current
configuration, keys and databases; no conversion or automatic deployment occurs.
