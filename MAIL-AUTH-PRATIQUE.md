# Mail authentication cryptography through Pratique

This document records the cryptography checkpoint. The later cumulative
dependency count and unused compression cleanup are documented in
[MAIL-AUTH-REPORT-TRIM.md](MAIL-AUTH-REPORT-TRIM.md); the provider behavior below
is unchanged by that cleanup.

Workglen now uses its existing first-party Pratique implementation for mail-auth
RSA/Ed25519 verification and SHA-256/legacy SHA-1 hashing. Outbound Workglen DKIM
continues to use Pratique RSA-SHA256 signing. SPF, DKIM and DMARC protocol handling
remain with the attributed, pinned mail-auth 0.13.3 source.

## Dependency result

The locked graph decreases from **224 to 189 external package versions**:
188 registry packages plus one patched third-party mail-auth package. The 35
removed package versions are listed in `validation/0.8-native-mailauth-inventory.json`.
Moving mail-auth from the registry into `vendor/mail-auth` is explicitly excluded
from the saving. There are 192 total package entries, including Workglen, Pratique
and lazaret-pg. No new registry package or retained-version/checksum change is
introduced. These are all-platform/build/test counts, not runtime memory figures.

The earlier estimate was 33. Cargo additionally dropped `const-oid` 0.9 and
`libm` after dependency feature unification was recalculated. Other versions of
digest/block-buffer/crypto-common and randomness remain for retained libraries.
No reporting, MIME, DNS, storage or password functionality is removed for the count.

## Behavior and boundaries

- The upstream protocol source is preserved; the adapter replaces cryptography.
  Its complete patch/provenance record and licenses are in `vendor/mail-auth/`.
- Strict Ed25519 verification is a separate Pratique entry point. It preserves
  the former provider's small-order, mixed-order and scalar acceptance behavior.
  Other Pratique consumers retain the existing general verifier.
- SHA-256 and legacy SHA-1 hashing stream without buffering entire message bodies.
  Pratique's existing SHA-1 compression code is reused for a streaming context.
  TLS, certificates, password hashing and on-disk encryption policies do not change.
- Inbound RSA keys below 1024 bits are now rejected, including the weak keys the
  former DKIM1 provider could accept. RSA SPKI/PKCS#1 parsing is bounded and rejects
  malformed encodings; exponents retain the former provider's upper bound.
  Outbound Workglen DKIM still requires 2048..4096-bit keys.
- Existing legacy RSA-SHA1 verification is preserved for this provider swap; this
  is not a recommendation to use it. RFC 8301 deprecates SHA-1 for DKIM. Changing
  its acceptance policy remains separate. New Workglen signatures use RSA-SHA256.

References: [RFC 8463](https://www.rfc-editor.org/rfc/rfc8463.html) and
[RFC 8301](https://www.rfc-editor.org/rfc/rfc8301.html).

## Validation

The normal offline Rust suite includes independently generated RSA 1024/2048/4096
and Ed25519 signatures, corrupted/truncated/extended signatures, key-type mismatch,
revocation, malformed/oversized/weak keys, streaming hash boundary vectors and
native key identity checks. Synthetic fixtures are checked into
`tests/fixtures/mailauth-crypto.json`; their deliberately public private test key
must never be deployed. `tools/mailauth-fixtures.py` uses Python cryptography only
when explicitly regenerating development fixtures, never during normal builds.

Full-message fixtures independently sign all four simple/relaxed header/body
canonicalization combinations for RSA-SHA256, Ed25519-SHA256 and retained legacy
RSA-SHA1. A closed DNS cache exercises DKIM/DMARC success, header/body tampering,
revocation, NXDOMAIN and temporary DNS failure without querying real DNS.

`tools/mailauth-compat.rs` is an additional development-only differential oracle.
It links previously cached RustCrypto/mail-auth rlibs, without adding them to the
Cargo graph. It compares signatures, hashes and malformed inputs, and constructs
mixed-order Ed25519 cases using the former independent curve implementation.
Those removed crates are not required by `cargo test` or a source build.

**Executed:** 148 offline locked Rust tests; release Clippy with warnings denied;
release build; 11,772 former-provider comparisons; 712 mixed/small-order Ed25519
cases (88 accepted mixed-order cases); old/new/Python signing agreement; 119
full mail/replication checks; 54 direct-delivery/DKIM checks. Rust 1.99.1 on
Linux x86-64 was used.

Executed results are in `validation/0.8-native-mailauth-*`. These are synthetic
local regression/interoperability checks, not a complete independent cryptographic
audit or live Microsoft 365 deployment validation. The complete upstream Pratique
and mail-auth test harnesses are not claimed as executed.

## Install the checkpoint in a test environment

Extract the cumulative source ZIP into a source directory and run `bash install.sh build` with the normal build account. For a disposable test installation, follow the M5 Mac/Ubuntu test-server stop,
binary replacement and restart instructions. Keep that test configuration, DKIM
keys, storage keys and databases. There is no schema, configuration or key conversion.
This checkpoint changes source only; it does not deploy to either test host or update any current installation.
