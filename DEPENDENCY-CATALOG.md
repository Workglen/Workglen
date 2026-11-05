# Full crate catalog — October 26, 2026

The main application/workspace has **15 external package versions**, **3 direct external crates**
and **24 total Cargo.lock entries**, including nine first-party packages.
All eight reusable first-party libraries have zero external dependencies, including
optional, development, build and platform edges. The root application retains
its separately reviewed database/password dependencies.

| Completed checkpoint | Removed | Remaining external versions |
| --- | ---: | ---: |
| mail-auth | 17 | 79 |
| IDNA / ICU | 25 | 54 |
| Email / MIME | 3 | 51 |
| TOML | 10 | 41 |
| Tokio | 8 | 33 |
| Serde / serde_json | 11 | 22 |
| Native MIME charsets | 7 | 15 |

This removes 81 package versions from the 96-package baseline. No registry
package was added or upgraded in the application/workspace; retained checksums are unchanged. JSON remains
the interchange/storage format; its implementation and explicit typed schemas
are now first-party. Legacy charset support remains through native decoders.
F5's opt-in mixed-script heuristic is implemented without new dependencies; full IDNA2008 and UTS #39 confusable policy remain deferred under SEC-IDNA-04.
See NATIVE-DATA.md, NATIVE-CHARSETS.md, PRATIQUE-UPSTREAM.md and PORTABLE-CHECKS.md.

The former simdutf8 entry incorrectly described an Android-only purpose. It was
encoding_rs's CPU SIMD UTF-8 helper on x86/ARM64, including Linux and macOS.
Both crates are now removed from the application and workspace test graph.

The main-workspace counts cover all target/build/test dependencies; they are not runtime size
measurements or a vulnerability audit.

## First-party crates

| Crate | Version | Purpose |
| --- | --- | --- |
| `lazaret-archive` | 0.1.9 | Bounded first-party TAR/GZIP, RAR, 7z, BZIP2, XZ and LZMA archive extraction for Mail Security |
| `lazaret-pg` | 0.1.0 | Native PostgreSQL wire client translated from Lazaret, using Pratique TLS |
| `pratique` | 0.1.0 | A from-scratch HTTPS client for Rust with zero dependencies: TLS 1.3 (and 1.2), X.509 validation and HTTP/1.1, std only |
| `workglen-dns` | 0.1.0 | Bounded first-party recursive DNS client |
| `workglen-idna` | 0.1.0 | First-party UTS 46 domain processing using attributed Unicode 18 data |
| `workglen-lazaret-verify` | 0.1.0 | Narrow compatibility facade exposing Workglen's existing Pratique inflater to the unmodified Lazaret archive source |
| `workglen-mail` | 0.8.0 | Modular Linux mail and accounting server using Pratique, redb and BYO PostgreSQL |
| `workglen-mime` | 0.1.0 | Bounded first-party email and MIME parsing for Workglen |
| `workglen-toml` | 0.1.0 | Bounded first-party TOML configuration parser with first-party typed decoding |

## Direct external crates

| Crate | Pinned version | Purpose |
| --- | --- | --- |
| `argon2` | 0.5.3 | Memory-hard password hashing and password verification. |
| `redb` | 3.1.3 | Transactional embedded database; Workglen adds its own Mail Security encryption layer. |
| `subtle` | 2.6.1 | Constant-time comparisons/selection for secrets and password primitives. |

## All transitive crates

Shared packages remain until every consumer releases them. Exact parents,
features and target conditions are in `validation/0.8-dependency-catalog.json`.

| Crate | Pinned version | Purpose | Included through |
| --- | --- | --- | --- |
| `base64ct` | 1.8.3 | Constant-time Base64 for password-hash/PHC encoding; distinct from the removed mail codec. | `argon2` |
| `blake2` | 0.10.6 | BLAKE2 hashing used inside Argon2 password hashing. | `argon2` |
| `block-buffer` | 0.10.4 | Fixed-block buffering for the password-hash cryptography stack. | `argon2` |
| `cpufeatures` | 0.2.17 | Runtime CPU-instruction detection for optimized cryptographic operations. | `argon2` |
| `crypto-common` | 0.1.7 | Shared hash/cryptographic traits for the Argon2 dependency chain. | `argon2` |
| `digest` | 0.10.7 | Hash-function traits for BLAKE2/Argon2. | `argon2` |
| `generic-array` | 0.14.7 | Fixed-size array abstractions for the password-hash stack. | `argon2` |
| `libc` | 0.2.191 | Platform C/OS interfaces for sockets, files, entropy and memory operations. | `argon2`, `redb` |
| `password-hash` | 0.5.0 | Password-hash/PHC string parsing, formatting and verification interfaces. | `argon2` |
| `rand_core` | 0.6.4 | Random-number-generator traits used by the remaining entropy/password/DNS graph. | `argon2` |
| `typenum` | 1.20.1 | Compile-time numeric types for fixed-size cryptographic buffers. | `argon2` |
| `version_check` | 0.9.5 | Build-time Rust version/feature checks. | `argon2` |

## Optional, isolated fuzz tooling

The offensive-review checkpoint includes a separate `fuzz/` workspace. It does
not enter the application or reusable-library dependency graphs. Its lockfile
contains 10 registry versions: `arbitrary` 1.5.0, `cc` 1.10.0, `cfg-if` 1.0.5,
`find-msvc-tools` 0.1.15, `getrandom` 0.4.3, `jobserver` 0.1.35, `libc` 0.2.191,
`libfuzzer-sys` 0.4.12, `r-efi` 6.0.0 and `shlex` 2.0.1. These support the
optional libFuzzer harness and its build/entropy helpers. There are 24 distinct
external package versions across the main and new fuzz lockfiles combined;
libc is shared. The standalone seed/replay workspace adds no external package.
This is an explicit development-tool exception, not a claim that the entire
source ZIP has no external dependencies. See OFFENSIVE-REVIEW-REMEDIATION.md.
