# Dependency minimization

The current source has **15 external package versions**, down from 96; three
direct external application crates and nine first-party packages remain.
Serde/serde_json removal accounts for 11 removals (33 to 22), and native MIME
charsets account for seven more (22 to 15). No retained registry version or
checksum changed. JSON, configuration, storage and wire formats remain in use
through first-party implementations. See NATIVE-DATA.md, NATIVE-CHARSETS.md,
DEPENDENCY-CATALOG.md and PORTABLE-CHECKS.md. Earlier tables are historical.

The eight reusable first-party libraries must have **no external dependencies**.
They may depend on std and approved first-party paths. This requirement covers
normal, optional, development, build and platform dependencies; the portable
runner checks both manifests and transitive closure. A local path does not
justify relabeling third-party implementation code. Official mapping data
retains its actual provenance and notices. The root application's existing
database/password dependencies remain separately reviewed and counted.

Changes to the dependency allowlists require an explicit documented review.
DEPS-18/19/20 record these user-authorized changes in security/DEPENDENCY-POLICY.md.
F5's opt-in mixed-script heuristic adds no dependency; full IDNA2008 and UTS #39 confusable policy remain deferred under SEC-IDNA-04.

DEPS-20 adds the exact first-party Lazaret archive snapshot and a narrow
Workglen compatibility facade that re-exports the already-vendored Pratique
inflater. Cargo.lock grows from 22 to 24 entries, both first-party; the 15
registry packages, their versions and checksums are unchanged. The archive
crate's Unicode path-folding data retains its Unicode-3.0 notice.

## Implemented reductions — October 24–25, 2026

| Measure | Original | Lazaret port checkpoint |
|---|---:|---:|
| Direct third-party application dependencies | 20 | 16 |
| First-party application dependencies | 1 | 2 |
| Direct development-only registry dependency (tempfile) | 1 | 1 |
| Registry package versions in Cargo.lock, all platforms/build/test | 271 | 230 |
| Total Cargo.lock entries, including first-party code | 273 | 233 |
| Linux x86-64 application/build registry packages | 202 | 176 |
| Mac ARM64 application/build registry packages | 206 | 177 |

The first cleanup removed 13 registry package versions (271 to 258); the native
Lazaret PostgreSQL port removes another 28 (258 to 230). No registry package was
added or upgraded. The first cleanup's historical target graph counts remain in
`validation/0.8-dependencies-inventory.json`; the port's inventory is in
`validation/0.8-lazaret-pg-inventory.json`.

Package/version pairs are counted separately. The complete lockfile includes
platform-specific and development packages that are not built into a Linux or
Mac runtime. These counts are not executable size or memory measurements.
Retained versions and registry checksums are unchanged; nothing was added,
downloaded or replaced with another third-party package for this reduction.

| Change | Preserved behavior |
|---|---|
| Remove direct `sha2` 0.10 | Existing Pratique SHA-256 handles audit/content/session hashes and streaming replication checksums; bytes and lowercase hex encoding remain identical |
| Remove direct `getrandom` 0.3 | Pratique calls the OS cryptographic entropy source for salts, keys, nonces and IDs; errors remain fatal to the operation |
| Remove `fs2` | Rust's `File::try_lock` provides nonblocking exclusive locks, retained for the same file-handle lifetime |
| Chrono `clock` → `now` | Keep UTC timestamps, formatting and accounting/IMAP date parsing; stop compiling unused local-timezone lookup support |
| TOML parse/Serde/std features only | Read the same configuration format without enabling display/serialization support |
| Argon2 allocation/password-hash features only | Keep existing Argon2id parameters and PHC strings; salts already come from Workglen's OS entropy source |

The 13 removed lockfile entries are `fs2`, `getrandom` 0.3.4, `sha2` 0.10.9,
`iana-time-zone`, `iana-time-zone-haiku`, `android_system_properties`, `r-efi`
5.3.0, `winapi`, `winapi-i686-pc-windows-gnu`, `winapi-x86_64-pc-windows-gnu`,
`windows-core` 0.62.2, `windows-implement`, and `windows-interface`.
Other versions of SHA-2 and getrandom remain necessary transitive dependencies.
Feature reduction does not necessarily remove a crate if another dependency
still enables the same feature.

The Linux entropy fallback was also tightened: if the `getrandom` system call
is unavailable or blocked, `/dev/urandom` is used only after `/dev/random`
positively reports readiness. Failed opening/polling, timeout and error/hangup
events fail closed. Linux normally uses the blocking `getrandom` system call;
macOS uses `getentropy` in bounded chunks. That first cleanup added no new cryptographic algorithm. Existing constant-time comparison remains with `subtle`.

No test configuration, key, database schema, replication encoding or audit format changes.
When updating a disposable test installation, rebuild and replace its binary using
the instructions in [MICROSOFT-365-RECIPIENTS.md](MICROSOFT-365-RECIPIENTS.md).
Do not recreate test databases or keys. Cargo can reuse unaffected cached builds.
No current installation exists.

## Remaining priorities

### Completed package-removal checkpoints — 2026-10-25

All three authorized checkpoints are complete.
The DEPS-09 checkpoint finished with **175 external package versions**. Each completed
checkpoint has its own cumulative ZIP, compatibility evidence and reviewed graph.
External Ubuntu test relay sign-off remains separate; see GATEWAY-RELAY-SECURITY.md.

| Order / ID | Change | Removal | Remaining | Status |
|---|---|---:|---:|---|
| 1 / DEPS-07 | Disable unused hostname lookup | 4 | 178 | Complete |
| 2 / DEPS-08 | Pratique Base64 replaces mail-builder | 1 | 177 | Complete |
| 3 / DEPS-09 | Bounded native DKIM2 diff replaces similar | 2 | 175 | Complete |

The removals are verified against the pinned graph with no added packages,
retained upgrades or checksum changes. The five mail-builder-related removals
are counted only once. The Base64 checkpoint preserves encoding/buffer behavior
and passed delivery/DKIM checks. The native DKIM2 diff preserves valid recipe
formats and canonical reconstruction with explicit work/memory limits. Generated
recipes may differ where multiple scripts are valid; out-of-range copy indices
now reject. See MAIL-AUTH-UTILITIES.md for exact compatibility results and limits.
DKIM2 remains enabled, and third-party identity/notices remain intact.

### DEPS-10 — Native application errors replace anyhow

Completed: 175 → **174 external package versions**. 168 Rust tests,
release Clippy/build, 54 delivery/DKIM checks and 119 broader mail/IMAP checks
passed. Four optional database tests skipped. See NATIVE-ERRORS-AND-DATES.md.

### DEPS-11 — Native Gregorian dates and timestamps replace Chrono

Completed: 174 → **173 external package versions**. 174 Rust tests,
release Clippy/build, 54 delivery/DKIM checks and 119 broader mail/IMAP checks
passed. Four optional database tests skipped. See NATIVE-ERRORS-AND-DATES.md.

### Remaining architectural work

1. **Separate build profiles for module hosts.** Mail Security still shares the
   full executable with Accounting. Make the native PostgreSQL client and CSV
   import code optional at compile time while preserving the full suite by
   default. The external PostgreSQL client has already been removed; its former
   transitive dependency savings must not be counted again for module profiles.
   Native/remote RBAC and existing host behavior need coverage.
2. **Review the remaining root dependencies individually.** Argon2, redb and
   subtle remain the three direct external crates. JSON, DKIM2 recipes, DNS,
   URLs, IDNA, MIME, TOML and charsets now use first-party implementations.
   See DEPENDENCY-CATALOG.md for every remaining crate and purpose; further
   reduction requires a separate security/storage review and must not weaken
   required protocol, password or transactional behavior.

### PostgreSQL and Lazaret: current boundary

The operator's PostgreSQL server remains unchanged. Workglen now uses the separate
first-party `vendor/lazaret-pg` Rust port of Lazaret's Python wire driver with
Pratique TLS, SHA-256, HMAC and OS entropy. There is no Python runtime and no
external postgres/tokio-postgres/protocol/types crate. The optional JSON feature
uses Pratique JSON values; generated Unicode tables retain their Unicode notice.

The port retains parameterized SQL, NULLs and exact accounting values,
transactions/savepoints, error recovery, bounded streaming, cancellation, SCRAM,
required channel binding, certificate refusal and local endpoint restrictions.
See [LAZARET-POSTGRESQL.md](LAZARET-POSTGRESQL.md) and the crate README for the
explicitly unsupported Python/libpq conveniences and eventual upstream handoff.
No database/schema conversion or Workglen importer is involved.

Keep redb, Argon2 and subtle unless a separately reviewed replacement preserves
their transactional, password and constant-time behavior. Retain the native JSON,
MIME, replication byte format and CSV accounting semantics, whose replacements
are checked against their former implementations. Do not trade these guarantees
for a lower count. Module-specific builds remain unimplemented. The PostgreSQL
client port, Pratique mail-auth crypto/Base64 adapters, native replication codec,
bounded DKIM2 diff and unused reporting/compression cleanup are implemented. The
complete remaining-crate purpose catalog is in DEPENDENCY-CATALOG.md.

## Enforcement and evidence

`security/dependency-policy.json` records both the direct feature choices and
every external package/version/source in Cargo.lock. The native test
`inherited_dependencies_do_not_expand` rejects unreviewed changes, including
transitive additions and OpenSSL. Review dependency feature unification as well
as counts; version/security updates remain allowed after explicit review.

Use `cargo tree --locked --offline -d` to see duplicate versions and
`cargo tree --locked --offline --target TARGET --edges normal,build` to inspect
the application build for a specific host. All-platform and target-specific
measurements are in `validation/0.8-dependencies-inventory.json`; current license
declarations are in `validation/0.8-license-inventory.json`.

See [VALIDATION.md](VALIDATION.md) for executed checks and their limits. The
compatibility fixture uses pre/post-change executables only as regression
oracles for the same schema; it is not an importer or deployed-version converter.

## DEPS-12: Native DNS, HTTP URLs and outbound DKIM

First-party workglen-dns replaces hickory-resolver throughout routing,
authentication and destination checks. `src/url.rs` replaces HTTP(S) parsing
and form encoding. Native outbound DKIM retains Pratique cryptography and the
existing protected key lifecycle. The graph removes 77 external package
versions with no additions, upgrades or retained-checksum changes. IDNA 1.1.0
remains explicitly pinned to preserve full Unicode hostname validation.

At the historical DEPS-12 checkpoint, inbound candidates were development-only
and mail-auth remained external. DEPS-13 below completes that removal. See the
DEPS-12 validation files for evidence specific to that earlier state.

## DEPS-13: Complete mail-auth removal

The native protocol implementation removes mail-auth and 16 exclusive registry
package versions, 96 to 79. See NATIVE-MAILAUTH.md for independent fixtures,
wire interoperability, bounded processing and the preserved deployment boundary.

## DEPS-14: Native Unicode IDNA

workglen-idna removes 25 registry package versions, 79 to 54. Official Unicode
18 data, full mapping/NFC/context/bidi behavior and portable conformance tests
remain. All retained registry versions and checksums are unchanged.


## Native email/MIME checkpoint — DEPS-15

First-party workglen-mime replaces mail-parser throughout the application. This
removes mail-parser 0.11.9, hashify 0.2.9 and syn 2.0.119, taking 54 external
versions to 51 (57 total entries including six first-party packages). Remaining
versions/checksums do not change. encoding_rs stays pinned for legacy character
sets. Headers, addresses, multipart/nested structure, transfer decoding,
international filenames and HTML text projection are native. See NATIVE-MIME.md
for bounds, independent snapshots, corrected behavior and portable checks.

## DEPS-16 — Native TOML, October 26, 2026

Completed: 51 → **41 external package versions**. The first-party reader serves
node and witness configuration plus dependency-policy tests. Serde schemas and
configuration formats remain; no installed files are rewritten. All ten TOML-only
versions are gone with no registry additions/upgrades/checksum changes. See
NATIVE-TOML.md, the current catalog and validation/0.8-native-toml-inventory.json.

## DEPS-17 — Pratique DNS transport, October 26, 2026

Completed: 41 → **33 external package versions**. Pratique adds bounded,
cancellable nonblocking UDP/TCP and cooperative yielding; existing executor,
timer/timeout and async I/O APIs are reused. Native DNS and authentication no
longer use Tokio. The eight removals are tokio, bytes, mio, pin-project-lite,
socket2, wasi, windows-link and windows-sys; retained versions/checksums are
unchanged. All earlier/new Pratique changes have a verified upstream patch
series and file-hash ledger. See NATIVE-ASYNC-DNS.md and PRATIQUE-UPSTREAM.md.
