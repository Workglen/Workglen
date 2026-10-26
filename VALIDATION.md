# Validation — Workglen 0.8.0

Latest validation: October 26, 2026 (UTC), Linux x86-64, Rust 1.99.1.
Builds and tests used `--offline --locked` after preparing the pinned dependencies
and updating the lockfile offline. Native DNS, HTTP(S) URLs, mail authentication, Unicode IDNA, email/MIME parsing, TOML configuration parsing Pratique DNS transport, first-party typed data/JSON and native charset decoding are active.
No registry package was added/upgraded in the main workspace and retained checksums are unchanged. Optional isolated fuzz tooling has its own lockfile.
This source validation did not deploy a live service or exercise real providers.

## Latest offensive-review checkpoint

See [OFFENSIVE-REVIEW-REMEDIATION.md](OFFENSIVE-REVIEW-REMEDIATION.md) and
`validation/0.8-resilience-review/` for the latest tests and retained failure logs.
Panic isolation, state-specific poison handling, resolver health failover and
Base64 differential regressions are implemented. MIME budget configuration and
fallible clock conversion remain open; IDNA security additions remain deferred.

## Current and historical checks


- **Microsoft 365 gateway setup (October 26, 2026):** **308 workspace tests
  passed**, four optional PostgreSQL fixtures ignored. Warnings-denied workspace
  Clippy and offline locked release build passed. Six plan checks, **37 browser
  checks** (9 new Microsoft setup, 8 destination, 6 directory, 14 native UI) and
  **19 local network checks** passed. Forwarding prepends a trusted SMTP peer
  trace while the preserved original hash stays unchanged. The wizard prepares
  a disabled Partner connector, exact public IPv4 restrictions, Enhanced
  Filtering, staged activation, rollback and positive/negative deployment tests.
  All Cargo manifests and lockfile bytes match the previous source package;
  **15 external registry versions** remain and all six reusable libraries retain
  zero external dependencies. No schema conversion or Pratique change.
  Live Microsoft tenant enforcement is **not verified** by these local tests.
  Reproduce with `python3 tools/check-microsoft365-setup.py --browser`; details
  and machine-readable evidence are in MICROSOFT-365-GATEWAY.md and
  `validation/0.8-microsoft365-setup/`. Development browser tools are not runtime
  requirements. New validation evidence includes only summaries/logs; generated fixture keys
  and screenshots are excluded.

- **DEPS-18/19 / typed data, JSON and native charsets (October 26, 2026):**
  **305 workspace tests passed**, ARC enabled; four optional PostgreSQL tests
  remain ignored. Warnings-denied release Clippy and the release build passed,
  as did 54 outbound/DKIM, 119 mail/IMAP, 34 Webmail and 10 installer checks.
  Six pre/post executable checks preserve encrypted-store/audit/password/key
  behavior in disposable fixtures. All six reusable libraries have zero external
  dependencies, including optional/build/dev/platform manifest entries.
  External package versions: **15** (18 fewer than v33, 81 fewer than 96).
  Registry versions/checksums, installer and shipped configs remain unchanged.
  The JSON corpus has 73,260 cases: 72,844 exact matches and 416 explicitly
  reviewed, independently checked corrections (NATIVE-DATA.md). All 1,148
  contracts across 51 actual record types match. TOML retains 712 official cases
  and 5,748 matching snapshots; all 344 MIME snapshots remain satisfied. Native
  charset decoding matches text and error flags in 2,883,056 cases. Portable
  tests reproduce per-label SHA-256 fingerprints without the retired engine.
  Pratique's standalone pure-feature, 13 existing signed-JSON, nine new data,
  ten socket and new-module lint checks passed. All three patches apply exactly;
  all 199 vendor file hashes match. Linux x86-64 was tested; macOS native
  validation remains outstanding. See `validation/0.8-native-libraries-*`,
  `0.8-pratique-data-*`, NATIVE-DATA.md and NATIVE-CHARSETS.md.

- **DEPS-17 / native Tokio removal (October 26, 2026):** 241 workspace tests
  passed with ARC enabled; four optional PostgreSQL fixtures remain ignored.
  Exact Unicode/MIME/TOML fixture regeneration, warnings-denied release Clippy
  and release build passed. Local suites passed 54 outbound/DKIM, 119 mail/IMAP,
  34 Webmail and 10 installer/generated-configuration checks. Ten reusable
  Pratique socket tests cover cancellation, IPv4/IPv6, capacity, peer filtering,
  partial I/O, backpressure and trickling; DNS/real authentication tests cover
  shared deadlines and wrong-ID flooding. The standalone Pratique pure-feature,
  zero-registry-dependency, socket test and new-module Clippy checks passed.
  Both upstream patches applied exactly against the pinned baseline; all 195
  vendored file hashes match their ledger. External versions: **33**, eight
  fewer than TOML and 63 fewer than 96. Retained versions/checksums, installer
  and shipped configurations are unchanged. macOS native validation remains
  outstanding. Early validation setup failures and one cluster-startup timeout
  are retained with the successful reruns in the validation notes; no failure
  has been reclassified as a pass. See NATIVE-ASYNC-DNS.md, PRATIQUE-UPSTREAM.md,
  `validation/0.8-native-tokio-*` and `validation/0.8-pratique-*`.

- **DEPS-16 / native-toml (October 26, 2026):** 227 workspace tests passed
  with ARC enabled; four optional PostgreSQL fixtures remain ignored. Exact
  Unicode/MIME data and TOML input regeneration, warnings-denied release Clippy
  and release build passed. TOML tests cover 712 official 1.1 cases and 5,748
  pinned former-parser snapshots with zero mismatches, plus schema/resource
  limits and 20,000 mutation attempts. Local suites passed 54 outbound/DKIM,
  119 mail/IMAP, 34 Webmail and 10 installer/generated-configuration checks.
  External versions: **41**, ten fewer than the MIME stage and 55 fewer than 96.
  No registry additions/upgrades/checksum changes; installer and shipped config
  files match the prior ZIP byte-for-byte. All checks and fixtures are shipped.
  See NATIVE-TOML.md and `validation/0.8-native-toml-*`.

- **DEPS-15 / native-mime (October 25, 2026):** 218 workspace tests passed with
  ARC enabled; four optional PostgreSQL fixtures remain ignored. Exact Unicode
  and MIME data regeneration, warnings-denied release Clippy and release build
  passed. Loopback checks passed: 54 outbound/DKIM, 119 mail/IMAP and 34 Webmail
  API/MIME/attachment checks. The isolated old/new MIME wrapper passed 344
  snapshots: 312 exact matches and 32 explicitly reviewed differences, including
  all 252 former charset labels and 33 all-byte charset cases. A deterministic
  20,000-input mutation test checks parser/offset safety. IDNA security-boundary
  tests and the optional Python 3.19 comparison record the policy gaps discussed
  in NATIVE-IDNA.md. External versions: **51**, three fewer than the IDNA stage,
  or 45 removed from 96. No registry additions/upgrades/checksum changes.
  See NATIVE-MIME.md and `validation/0.8-native-mime-*`.


- **DEPS-14 / native-idna (October 25, 2026):** The shipped runner passed exact
  Unicode-data regeneration, 208 workspace tests (including ARC), warnings-denied
  release Clippy, release build, 54 outbound/DKIM and 119 mail/IMAP loopback checks.
  Four PostgreSQL fixture tests remain ignored. The tests include 19,182 official
  IDNA checks and 100,855 NFC assertions; two ill-formed UTF-16 source rows cannot
  be represented by Rust str. Both shipped oracle wrappers passed: 3,456,617
  pinned-IDNA comparisons and 106,600 URL comparisons with zero mismatches.
  External versions: **54**, down from 79 after mail-auth, or 42 removed from 96.
  See NATIVE-IDNA.md, PORTABLE-CHECKS.md and `validation/0.8-native-idna-*`.

- **DEPS-13 / native-mailauth (October 25, 2026):** The shipped portable runner
  passed 205 workspace tests with ARC enabled; four PostgreSQL fixture tests
  remain ignored. Release Clippy passed with warnings denied, release build
  passed, and loopback suites passed 54 outbound/DKIM plus 119 mail/IMAP checks.
  The portable prior-engine wrapper regenerated the SPF/protocol fixtures and
  verified native two-hop DKIM2/ARC signatures. External versions: **79**, down
  from 96; no registry additions, upgrades or retained checksum changes. See
  NATIVE-MAILAUTH.md, PORTABLE-CHECKS.md and `validation/0.8-native-mailauth-*`.

- **DEPS-12 / native-dns-url (October 25, 2026):** 189 default workspace tests
  passed; four optional PostgreSQL tests skipped. Six development-only native
  authentication tests passed. Release Clippy for all workspace targets including
  the candidate feature passed with warnings denied; the default release build
  and optional ARC compilation passed. The final binary passed 54 outbound/DKIM
  and 119 broader mail/IMAP loopback checks. The URL oracle compared 106,600 parser
  cases, all 256 byte values for form encoding and six setter cases with no
  mismatches. External package versions: 96 (95 registry plus attributed
  mail-auth). Full mail-auth removal is unfinished. See NATIVE-DNS-URL-AUTH.md,
  `validation/0.8-native-dns-url-*`, `0.8-native-url-comparison.txt`,
  `0.8-native-auth-candidate-tests.txt`, `0.8-native-dns-arc-check.txt` and
  `0.8-native-dns-provenance.json`.

- **DEPS-11 / chrono (October 25, 2026):** 174 offline locked Rust tests,
  release Clippy with warnings denied, release build, 54 delivery/DKIM checks and
  119 broader mail/IMAP checks passed. Four optional PostgreSQL tests skipped.
  External package versions: 173. See NATIVE-ERRORS-AND-DATES.md and
  `validation/0.8-native-chrono-*`.

- **DEPS-10 / anyhow (October 25, 2026):** 168 offline locked Rust tests,
  release Clippy with warnings denied, release build, 54 delivery/DKIM checks and
  119 broader mail/IMAP checks passed. Four optional PostgreSQL tests skipped.
  External package versions: 174. See NATIVE-ERRORS-AND-DATES.md and
  `validation/0.8-native-anyhow-*`.

- **DEPS-09 / native-diff (October 25, 2026):** 164 offline locked Rust
  tests, release Clippy with warnings denied, release build and 54 direct-delivery/
  DKIM checks passed. Four opt-in database tests skipped. External versions: 175.
  See MAIL-AUTH-UTILITIES.md and `validation/0.8-native-native-diff-*`.

- **DEPS-08 / mailbuilder (October 25, 2026):** 154 offline locked Rust
  tests, release Clippy with warnings denied, release build and 54 direct-delivery/
  DKIM checks passed. Four opt-in database tests skipped. External versions: 177.
  See MAIL-AUTH-UTILITIES.md and `validation/0.8-native-mailbuilder-*`.

- **DEPS-07 / hostname (October 25, 2026):** 152 offline locked Rust
  tests, release Clippy with warnings denied, release build and 54 direct-delivery/
  DKIM checks passed. Four opt-in database tests skipped. External versions: 178.
  See MAIL-AUTH-UTILITIES.md and `validation/0.8-native-hostname-*`.

- **Relay verification/backlog checkpoint (October 25, 2026 UTC):** 18 native
  Security loopback checks passed, including 12 envelope/TLS assertions from
  `tools/check-gateway-relay.py`, with no message submission by the diagnostic.
  The current release binary was reused; production Rust and dependencies are
  unchanged. The full Rust suite was not rerun for these documentation/operator
  tool changes. Live Lightsail verification remains pending. See
  [GATEWAY-RELAY-SECURITY.md](GATEWAY-RELAY-SECURITY.md).

- **Unused mail-auth report/compression checkpoint (October 25, 2026 UTC):**
  152 offline locked Rust tests, release Clippy with warnings denied, release
  build and 54 direct-delivery/DKIM loopback checks passed. Six packages were
  removed (188 to 182 external versions). Upstream patch reconstruction and
  reapplication verified all changed files. See
  [MAIL-AUTH-REPORT-TRIM.md](MAIL-AUTH-REPORT-TRIM.md) and
  `validation/0.8-native-mailauth-reports-*`. Four opt-in disposable database
  tests were skipped in both this and the bincode checkpoint; no live provider,
  Mac build or host deployment is claimed.

- **Native bincode checkpoint (October 25, 2026 UTC):** 152 offline locked Rust
  tests, release Clippy with warnings denied, release build and 119 loopback
  mail/replication checks passed. The independent bincode 1.3.3 oracle passed
  10,000 generated operation lists, the exact 24 MiB boundary and 123,184 damaged
  frame acceptance comparisons. External versions decrease from 189 to 188.
  See [REPLICATION-CODEC.md](REPLICATION-CODEC.md) and
  `validation/0.8-native-bincode-*`. No live deployment or Mac build is claimed.

- **Pratique mail-auth checkpoint:** 148 offline locked Rust tests, release
  Clippy with warnings denied, release build, 119 Mail/replication checks and
  54 direct-delivery/DKIM checks passed. The differential oracle passed 11,772
  provider comparisons and 712 mixed/small-order Ed25519 cases, plus signing
  agreement. External packages decrease from 224 to 189, counting the vendored
  third-party mail-auth package. See [MAIL-AUTH-PRATIQUE.md](MAIL-AUTH-PRATIQUE.md)
  and `validation/0.8-native-mailauth-*`.

- **Native testdirs checkpoint:** 141 offline locked Rust tests, release
  Clippy with warnings denied, and release build passed. See
  `validation/0.8-native-testdirs-*` and [CRATE-REPLACEMENTS.md](CRATE-REPLACEMENTS.md).

- **Native csv checkpoint:** 138 offline locked Rust tests, release
  Clippy with warnings denied, and release build passed. See
  `validation/0.8-native-csv-*` and [CRATE-REPLACEMENTS.md](CRATE-REPLACEMENTS.md).

- **Native base64 checkpoint:** 135 offline locked Rust tests, release
  Clippy with warnings denied, and release build passed. See
  `validation/0.8-native-base64-*` and [CRATE-REPLACEMENTS.md](CRATE-REPLACEMENTS.md).

- **Native Lazaret PostgreSQL port (October 25 UTC):** 133 offline locked Rust
  tests passed (94 Workglen library, 12 core, 5 cryptography, 9 driver unit and
  13 protocol tests). Release Clippy passed with all targets and warnings denied,
  rustfmt checks passed, and the release executable built successfully. The
  ordinary suite explicitly ignores four database tests; all four were then
  executed against fresh disposable databases in five scenarios: native driver
  over plain loopback and verified TLS, accounting/banking, posting corrections/
  locks/audit, and local Accounting initialization/reopen. All passed. The
  independent SQL engine was PGlite PostgreSQL WASM with a Node TLS frontend;
  this is not native PostgreSQL 18/macOS or a user database validation.
  Driver authentication tests include RFC 7677, 20 PostgreSQL 16 password
  verifier fixtures, every Unicode scalar compared with the pinned Lazaret
  Python reference, required SCRAM-PLUS, wrong/untrusted/expired certificates,
  malformed frames/rows, cancellation, interrupted streams, SQLSTATE recovery
  and deferred commit errors. Failed exchanges are not replayed automatically.
  The port removes 28 more registry package versions (258 to 230), with no
  additions/upgrades and unchanged retained checksums. Direct third-party
  application dependencies are now 16, down from the original 20. Application/
  build graph resolution counts are 176 for Linux x86-64 and 177 for Mac ARM64;
  the Mac figure is not a Mac compile. See `validation/0.8-lazaret-pg-*` and
  [LAZARET-POSTGRESQL.md](LAZARET-POSTGRESQL.md) for the first port's scope and
  unsupported Python/libpq conveniences. No live deployment or schema/key
  conversion was performed. An additional 119 full Mail/witness/replication
  checks passed against the rebuilt executable after dependency pruning;
  this covers DNS mail authentication, TLS delivery, DKIM, IMAP and replication.

- **Dependency minimization (October 24 Chicago):** direct third-party
  application dependencies fell from 20 to 17; all-platform registry package
  versions in Cargo.lock fell from 271 to 258. Thirteen packages were removed,
  none added, and retained versions/checksums are unchanged. Linux x86-64 normal/
  build dependencies fell from 202 to 197; Mac ARM64 from 206 to 200. The Mac
  figure is Cargo graph resolution, not a Mac compile. Direct and transitive
  policy checks enforce the reviewed reduced baseline. License declarations
  were rechecked for the 260 retained total lockfile entries.
- **114 offline locked Rust tests passed** (97 library, 12 core, 5 cryptography);
  three PostgreSQL integration tests remained explicitly ignored in that earlier pass.
  Release Clippy passed with all targets and warnings denied; the release build
  passed. Nine separately compiled Pratique OS-randomness tests passed, including
  the new refusal of ambiguous/error readiness events in the Linux fallback.
  SHA-256 vectors cover empty/short/multi-block/million-byte and chunked input;
  a fixed accounting hash checks persisted JSON/hex compatibility.
- **244 local integration/browser/compatibility checks passed:** 119 full Mail/
  witness/replication checks, 54 direct-delivery/DKIM checks, 34 Webmail checks,
  17 native Security checks, 14 Security browser checks and six pre/post-change
  compatibility checks. These exercised real loopback TLS, independently checked
  DKIM signatures, replication snapshots/checksums, encrypted storage recovery,
  existing/new password hashes and audit chains, and independent `flock` holders
  against both the former fs2 and new standard-library locks. Configuration and
  original storage keys stayed unchanged. No importer/converter was introduced.
  Existing PostgreSQL TLS/channel-binding loopback tests also passed in the Rust
  suite; no real accounting database or user installation was contacted.
  See `validation/0.8-dependencies-*`, `tests/pratique_crypto.rs`, and
  `tools/dependency-compat-test.py`. All fixtures were synthetic/local, no public
  CA or real mailbox was used, and no dependencies were downloaded. The entire
  upstream Pratique test suite was not run; its standalone RNG module was.
  [DEPENDENCIES.md](DEPENDENCIES.md) separates completed removals from remaining
  module-profile and mail-auth work. No executable-size,
  build-time or peak-memory improvement is claimed from package counts alone.

- **Guided delivery destination setup (October 25 UTC):** 111 offline locked
  Rust tests passed (97 library, 12 core, 2 crypto); the same three PostgreSQL
  integration tests remained explicitly ignored. Release Clippy passed with
  warnings denied, and the embedded UI/native release binary rebuilt successfully.
  New security tests cover destination creation from an empty installation,
  authorization, failed/expired/stale tests, idempotent saves, protected settings,
  encrypted persistence and reopen, interrupted-check recovery, and public-address
  enforcement at the actual transport boundary. Browser-created destinations use
  checked public addresses on every subsequent connection and cannot supply
  arbitrary ports, credential paths or custom trust paths.
- **45 local integration/browser checks passed** for that update: 17 native
  gateway checks, 14 native-browser checks, 8 destination-wizard checks and 6
  recipient-discovery UI regressions. The exact empty-route failure is exercised:
  the wizard blocks premature advance, finds a synthetic Microsoft MX hostname,
  preserves fields after a failed test, saves/selects a tested destination, keeps
  the recipient draft across Back, and advances successfully to Detection. Narrow
  viewport checks and browser script-error checks passed. See
  `validation/0.8-destination-*` and `security/tests/destinations-ui.cjs`.
  New Microsoft MX and SMTP test outcomes were synthetic; existing SMTP/TLS,
  IMAPS/EWS, signed control, encryption and restart checks ran on loopback. No
  live Microsoft tenant, public DNS/SMTP destination, user host or public CA was
  used. Build dependencies and lockfile are unchanged. This update requires
  replacing the binary on both Admin and gateway, then refreshing the browser;
  route creation itself subsequently needs no file edit or restart.
- **Microsoft 365 discovery and module navigation:** 106 offline locked Rust
  tests passed (92 library, 12 core, 2 crypto); three PostgreSQL integration
  tests remained explicitly ignored because no disposable PostgreSQL endpoint
  was provided for this change. Release Clippy passed with warnings denied and
  the native release binary built successfully. Six directory-focused Rust
  tests cover shared/disabled accounts, SMTP aliases, groups/contacts, domain
  filtering, pagination refusal, partial failure, RBAC, additive/idempotent
  apply, preserved disabled/manual recipients, stale/expired previews and live
  acceptance refusal. Network fetches execute outside the database transaction.
- **37 synthetic integration/browser checks passed:** 17 native loopback
  gateway checks, 14 native-browser checks and 6 directory-UI checks. These
  verify existing SMTP/quarantine/digest/connector behavior, encrypted forced
  restart, signed central administration, visible Back to Admin navigation at
  390px, return to the Admin module overview, mailbox-holder link exclusion,
  directory review/apply and failed-fetch UI behavior. The Webmail UI uses its
  configured Admin origin without forwarding credentials. JavaScript syntax
  and installer Bash syntax checks passed.
  Records: `validation/0.8-directory-*`; fixtures:
  `security/tests/native-network.cjs`, `security/tests/browser.cjs`, and
  `security/tests/directory-ui.cjs`. Microsoft responses and credentials were
  synthetic; no live Microsoft tenant, admin consent, real mailbox discovery,
  public CA issuance or user host was accessed. Microsoft OAuth/API behavior
  still requires deployment validation against the intended tenant. Directory
  discovery is on demand and additive; automatic synchronization/removal is
  not implemented. **This update requires rebuilding and replacing the
  installed binary on both Admin and gateway**, because the UI is embedded.
- **12 installer password-flow tests passed** against the existing native
  release executable in private temporary Linux installations. Interactive
  confirmation mismatches, invalid lengths/single-line checks and equal Admin/
  gateway passwords recover without losing setup answers. Mixed file/prompt
  inputs keep supplied files unchanged; invalid or identical file-only inputs
  and missing noninteractive inputs fail promptly. Pseudo-terminal checks verify
  hidden password input and successful retry; EOF and interruption before
  password acceptance leave no installation or bundle. All initialization was
  offline, with no services, public certificates or real database connections.
  Bash syntax and the existing 37 isolated build-flow tests also passed. See
  `tools/install-password-test.py` and `validation/0.8-installer-password.txt`.
  That earlier password-prompt-only fix did not change Rust or dependencies;
  the newer directory/navigation update above does require a rebuild.
- **The revised release build passed** on Linux x86-64 with Rust 1.99.1,
  `opt-level = 1`, `lto = "off"`, 16 codegen units and one Cargo job. Pratique
  compiled in 36.66 seconds; the remaining application build took 155.42 seconds.
  The largest child-process RSS reported during these stages was 728,760 KiB
  (about 712 MiB) for Pratique and 761,860 KiB (about 744 MiB) over the complete
  build. These are process high-water measurements, not total machine memory,
  minimum requirements, or a comparison against the old profile's peak.
  Validation used an isolated source copy in a larger Linux environment, not
  the user's 1 GiB Lightsail VM. No swap or live host configuration was changed.
  The executor exposes only UID 0, so the direct Cargo validation used that UID;
  the installer was not invoked and its user-host root refusal remains tested.
- **14 release-profile tests passed**: 12 core and two published cryptography
  vector/authentication checks. A repeat build using the same target cache took
  0.111 seconds and compiled zero crates. See `validation/0.8-memory-release.json`
  and the corresponding build/test/repeat logs. Cached retry does not resume
  inside a rustc process that was killed; that crate must compile again.
- Installer build-flow update: **37 isolated regression tests passed** with fake
  package managers, sudo, Apple setup and Rust/Cargo tools, with no network or compilation.
  They cover missing/all-present APT and DNF prerequisites, reuse of minimal curl,
  package-manager/sudo failures, checks after installation, repeated-build reuse,
  privilege separation, read-only checks and offline refusal, simulated Apple
  tool installation/resumption and headless/failure paths, automatic locked
  dependency fetch, explicit offline mode with no online fallback, missing/wrong
  toolchains, official-source Rust/Cargo setup, existing tools outside PATH,
  disabled implicit Rustup installation, partial-download/installer/toolchain
  failures, temporary-file cleanup, compiler prerequisites, root setup refusal,
  download/compile failures, preserved failure exit status, conditional OOM
  diagnostics without automatic retry/privilege escalation, conflicting flags
  and read-only `check`.
  All package/download/toolchain tools are simulated and cannot reach the real executables;
  no real OS-package or fresh Rustup installation was performed. Bash syntax and a real installed-Rust
  `check` also passed on Linux. See `tools/install-build-test.py` and
  `validation/0.8-installer-build.txt`. This update does not establish a Mac build.
- The initial OpenSSL-removal license review covered **all 273 then-current Cargo.lock entries**; the first dependency reduction retained 260 entries; the native driver port retains 233 entries with unchanged registry declarations,
  together with vendored Pratique notices. No declared package requires choosing
  a GPL-family license; the source ZIP retains the separately licensed Mozilla
  trust-store file. See `THIRD-PARTY.md` and `validation/0.8-license-inventory.json`
  for scope, qualifications and redistribution obligations.

Pratique now supplies database TLS, AES-GCM storage/feed encryption, HMAC management authentication, DKIM RSA signing/key generation and native setup certificates/secrets. The application, build and installer require no OpenSSL. The dependency graph and dynamic executable linkage were checked; independent test peers still use OpenSSL/Python/Node. See [PRATIQUE-INTEGRATION.md](PRATIQUE-INTEGRATION.md).

The CLI installer now targets local Admin/Accounting with existing local PostgreSQL and a separately hosted Linux gateway. Its native Admin profile does not start mail listeners/workers. PostgreSQL local mode is explicit and constrained to loopback IPs/Unix sockets; remote TLS verification remains the default.

Installer validation uses Linux and synthetic fixtures. **No macOS build, Keychain enrollment, live Lightsail systemd installation or public CA issuance was performed.** macOS Bash-compatible syntax and portable paths are implemented, and Darwin's no-follow file flag is selected separately from Linux, but an actual Mac build/startup remains an operator validation step. `install.sh gateway --destdir` verifies deployment layout without changing host accounts, services or firewalls.

Development installations now exist on Mac and Lightsail. Preserve their configuration, keys and current-schema data; this release adds no Workglen version converter. Removed the Security importer/exporter and legacy password/audit paths, Accounting version-upgrade scripts, old outbound queue conversion, and persisted-record compatibility defaults. Accounting creates one complete current schema; external Xero/statement imports, backups and replication remain supported.

- **100 Rust unit/core/cryptography tests passed**, including **41 native Security tests**. Coverage includes local detection, immutable rule lifecycle, activation confirmation, scopes, receipts/replay, digest snapshots, mandatory release guards, retained-content holds, audit integrity, explicit spam learning, in-flight restart handling and dependency-policy enforcement.
- **4 TLS/ACME tests passed**: explicit configuration/SAN coverage, private and exclusively locked state, lifetime-based scheduling for 90/64/45/6-day certificates, and local HTTP-01 issuance with simulated CA outage/retry, ARI replacement, live TLS handshakes using the renewed leaf, challenge cleanup and cached restart on the same port. No public CA account or certificate was created. The vendored crate’s separate protocol test target could not compile because its upstream test fixture files are not included in this source distribution; no pass is claimed for that target.
- **10 encrypted-storage tests passed**: key generation/BYOK and permissions, whole-database confidentiality, wrong-key/corruption rejection, random-access/resize behavior, uncommitted/crash-tail recovery, nonce freshness after recovery, cross-file ciphertext substitution rejection, compaction and exclusive locking.
- Encrypted offline backup recovery passed with the original key and the same 41-event audit chain. Missing and incorrect keys were rejected without changing the backed-up database.
- Archive tests include independently generated Deflate ZIP, GZIP and USTAR fixtures; nested executable inspection; corrupt checksums/headers; path traversal; encrypted/unsupported/truncated archives; nesting/expansion limits; links; and a deterministic ZIP byte-mutation corpus. This is not a long-running fuzz campaign.
- **17 loopback network checks passed**: real native HTTPS and SMTP STARTTLS, verified TLS forwarding with exact original MIME, native quarantine, recipient refusal, mandatory release refusal, digest delivery/CSRF/recipient isolation, central signed control of two native instances, independent RBAC scopes, native Workglen IMAPS and synthetic EWS remediation, acceptance with central Admin offline, generated/supplied storage keys, ciphertext inspection and forced-termination recovery.
- **11 browser checks passed**: standalone sign-in, seven-step setup/rationale, AI-rule defaults, draft/testing, evidence review, recipient-scoped bulk discard, central remote selection, encryption/key-custody guidance, TLS availability/expiry, guided TLS setup and no script errors. Screenshots were inspected locally and are not included in the source package.
- **54 direct-delivery/DKIM loopback checks passed** with native Pratique key generation and signing, independently verified signatures, exact retry bytes, TLS refusals and ordinary queue retries. The generated RSA key also passed independent private-key consistency/primality checks.
- **3 Accounting database scenarios passed** against independent disposable PGlite fixtures (two over verified TLS and one explicit loopback connection): fresh schema creation, repeat initialization preserving balances/audit, Xero cutover, banking, posting corrections/locks/audit and local-transport schema initialization/reopening. Prior Accounting browser results below are historical, not represented as rerun here.
- **11 installer checks passed**: protected generated bundles and local-secret separation; existing-install refusal; loopback/Admin-profile guards; explicit ACME agreement with offline preparation; BYOK; injection/linked-password refusal; Linux staging; native Admin HTTPS/CLI without binding occupied mail ports; verified signed gateway control; browser checks, gateway continuity after Admin shutdown, and completion with the OpenSSL command explicitly blocked. The grouped final browser/continuity scenarios are recorded in `validation/0.8-installer.json`.
- **3 PostgreSQL TLS adapter tests passed** (included in the Rust total): multi-record asynchronous exchange; rejection of untrusted, wrong-name and expired certificates; certificate-hash selection; and a full required SCRAM-SHA-256-PLUS authentication exchange with independently checked proof and channel-binding bytes.
- Published AES-256-GCM/HMAC-SHA256 known-answer tests passed; modified ciphertext/tag/AAD is refused. Native local certificates passed independent chain and hostname validation.
- Clippy with all targets and warnings denied passed. Changed Rust formatting and current Security JavaScript syntax checks passed. The earlier full functional suites used the debug executable; some fixtures used that executable with debug symbols stripped to limit disk use. The revised release build and its selected tests are recorded separately above; the full network/browser suites were not repeated for the profile change.

Current logs use the `0.8-` prefix. Prior logs are historical. All tests used synthetic recipients and loopback services. No customer mail was sent or removed. Graph was ported but has not been tested against a live tenant in this release; EWS uses a synthetic TLS protocol fixture. Native policy/heuristic scanning is not a maintained malware-signature feed or a measured efficacy benchmark. Production load, provider consent/authentication, DNS/MX routing, sender reputation and independent security review remain outstanding. PGlite does not establish native PostgreSQL concurrency or production durability.

The earlier development source snapshot was the baseline, not a prior deployed version. 189 of the 191 baseline Pratique files remain byte-identical, including root-certificate notices. Two files expose the new native RSA generator and the existing constant-time PEM encoder; one generator source file is added. Independent cryptographic review of these additions remains outstanding. The old security runtime and its service-specific tests were replaced by native code and fixtures. The archive-reader integration is first-party and uses the already-present first-party bounded inflater. See [security/README.md](security/README.md) and [the dependency rule](security/DEPENDENCY-POLICY.md).

---

# Validation — Workglen 0.6.0

Validated October 24, 2026 (America/Chicago), Linux x86-64, Rust 1.99.1
(58cf8f9c3 2026-10-13). New code builds/tests use `--offline --locked`.
The unchanged vendored Pratique files were compared with the authoritative 0.5
source archive. No new Rust dependency was added.

## Current checks

- **Guided delivery destination setup (October 25 UTC):** 111 offline locked
  Rust tests passed (97 library, 12 core, 2 crypto); the same three PostgreSQL
  integration tests remained explicitly ignored. Release Clippy passed with
  warnings denied, and the embedded UI/native release binary rebuilt successfully.
  New security tests cover destination creation from an empty installation,
  authorization, failed/expired/stale tests, idempotent saves, protected settings,
  encrypted persistence and reopen, interrupted-check recovery, and public-address
  enforcement at the actual transport boundary. Browser-created destinations use
  checked public addresses on every subsequent connection and cannot supply
  arbitrary ports, credential paths or custom trust paths.
- **45 local integration/browser checks passed** for that update: 17 native
  gateway checks, 14 native-browser checks, 8 destination-wizard checks and 6
  recipient-discovery UI regressions. The exact empty-route failure is exercised:
  the wizard blocks premature advance, finds a synthetic Microsoft MX hostname,
  preserves fields after a failed test, saves/selects a tested destination, keeps
  the recipient draft across Back, and advances successfully to Detection. Narrow
  viewport checks and browser script-error checks passed. See
  `validation/0.8-destination-*` and `security/tests/destinations-ui.cjs`.
  New Microsoft MX and SMTP test outcomes were synthetic; existing SMTP/TLS,
  IMAPS/EWS, signed control, encryption and restart checks ran on loopback. No
  live Microsoft tenant, public DNS/SMTP destination, user host or public CA was
  used. Build dependencies and lockfile are unchanged. This update requires
  replacing the binary on both Admin and gateway, then refreshing the browser;
  route creation itself subsequently needs no file edit or restart.
- **Microsoft 365 discovery and module navigation:** 106 offline locked Rust
  tests passed (92 library, 12 core, 2 crypto); three PostgreSQL integration
  tests remained explicitly ignored because no disposable PostgreSQL endpoint
  was provided for this change. Release Clippy passed with warnings denied and
  the native release binary built successfully. Six directory-focused Rust
  tests cover shared/disabled accounts, SMTP aliases, groups/contacts, domain
  filtering, pagination refusal, partial failure, RBAC, additive/idempotent
  apply, preserved disabled/manual recipients, stale/expired previews and live
  acceptance refusal. Network fetches execute outside the database transaction.
- **37 synthetic integration/browser checks passed:** 17 native loopback
  gateway checks, 14 native-browser checks and 6 directory-UI checks. These
  verify existing SMTP/quarantine/digest/connector behavior, encrypted forced
  restart, signed central administration, visible Back to Admin navigation at
  390px, return to the Admin module overview, mailbox-holder link exclusion,
  directory review/apply and failed-fetch UI behavior. The Webmail UI uses its
  configured Admin origin without forwarding credentials. JavaScript syntax
  and installer Bash syntax checks passed.
  Records: `validation/0.8-directory-*`; fixtures:
  `security/tests/native-network.cjs`, `security/tests/browser.cjs`, and
  `security/tests/directory-ui.cjs`. Microsoft responses and credentials were
  synthetic; no live Microsoft tenant, admin consent, real mailbox discovery,
  public CA issuance or user host was accessed. Microsoft OAuth/API behavior
  still requires deployment validation against the intended tenant. Directory
  discovery is on demand and additive; automatic synchronization/removal is
  not implemented. **This update requires rebuilding and replacing the
  installed binary on both Admin and gateway**, because the UI is embedded.
- Rust unit/core tests: **37 passed**; database tests run separately.
- Accounting SQL/application scenarios: **2 passed** over verified loopback TLS,
  including the original cutover/banking scenario and the new correction scenario.
- Browser: **18 Accounting scenarios passed**, plus **1 scoped-role browser scenario**
  covering accountant/viewer access and switching back to the owner.
- API/CLI: **12 checks passed**, including CSRF, read-only denial, cross-book denial,
  assigned accountant corrections, separate period authority, and named audit actors.
- Clippy: all targets, no dependencies, warnings denied, passed.
- Changed Rust formatting and JavaScript/Python syntax checks passed.

Correction checks cover balanced edits, original/new date boundaries, revision
conflicts, replay conflicts, void/delete effects, deleted visibility, immutable
before/after history, direct SQL mutation rejection, invoice/payment consistency,
restored outstanding balances, explicit bank unmatching, and fresh posting after a
removed generated bank journal. Browser checks exercise the actual HTTPS service.

SQL checks use PGlite 0.5.11 with pglite-socket 0.2.14, a disposable TLS proxy, and a
single database connection. This validates SQL and application behavior; **native
PostgreSQL concurrency, managed-service failover, and production durability remain
unvalidated**. PGlite, Playwright, certificates, passwords, and test mailbox content
are test-only and are not included as runtime dependencies or package secrets.

Current results are prefixed `0.6-` in `validation/`. Default Rust tests skip the two
opt-in database scenarios; their separate passing run is included. The
`tools/accounting-web-test.py` fixture runs Accounting and RBAC browser checks using
a disposable database and the supplied TLS CA; existing instructions below apply.

This source release was built in the dev/test profile. A new optimized release
build and the complete Mail/Webmail/direct-delivery integration suites were not
rerun for 0.6. Their prior evidence is retained below as historical baseline only.

Remote module hosting, standalone Mail Security, spam engines, quarantine digests,
rule lifecycle enforcement, and Exchange mailbox remediation are **requirements
recorded in MODULE-HOSTING-AND-MAIL-SECURITY.md, not implemented/tested features**.
No public SMTP traffic or real external mailbox operation was performed.

---

## Historical 0.5 validation (not a new 0.6 execution)

# Validation — Workglen 0.5.0

Validated October 24, 2026 (UTC) on Linux x86-64 with Rust 1.99.1
(58cf8f9c3 2026-10-13). Pratique remains pinned to
`9efaab9c010a2ca7f5ffaaf46b3b82eb50e20be4`; its vendored files match the
0.4 source package byte for byte (191 files).

## Build and code checks

- Release build: passed with `--offline --locked`.
- Rust tests: **34 passed** (12 core and 22 protocol, DKIM, Webmail, web/accounting unit tests).
- Accounting database scenario: **1 passed**, run separately with opt-in credentials.
- Clippy: all targets, `-D warnings`, passed.
- Browser/test JavaScript and Python syntax: passed.
- No SQLite or rusqlite dependencies. Runtime executable: `workglen`.

Captured build, test and lint output is in `validation/`. The default test command
intentionally skips the database scenario; its separate result is included.

## Accounting database and browser checks

The database scenario exercised schema initialization/replay, module enable state,
exact minor-unit arithmetic, balanced immutable journals, reversals, period locks,
Xero cutover and replay, multiple banks and credit-card signs, statement preview and
commit, stable-ID deduplication, payment bounds, explicit posting and matching,
changed replay rejection, exclusion/reopening, and source corrections that flag
matched transactions without rewriting the ledger. It also checks disconnected
feed mapping replacement and correction handling for excluded rows.

Database statements ran through the production Rust PostgreSQL client over
certificate-verified loopback TLS against **PGlite 0.5.11** (the PostgreSQL WASM
engine), exposed by **pglite-socket 0.2.14** and a disposable TLS proxy. This fixture
has a single connection, and Workglen used a pool size of one. It validates SQL and
application behavior, but **does not validate native PostgreSQL concurrency,
managed-service failover, or production durability**. PGlite is only a test fixture;
it is not bundled or used as Workglen's runtime database. Native PostgreSQL and
provider-specific deployment validation remain required.

Chromium exercised the actual Workglen HTTPS server with synthetic books and files.
**12 Accounting browser scenarios and 5 API/CLI checks passed**, covering:

- Module enable/disable/re-enable with data retained; CSRF enforcement.
- Book and account creation, bank mapping and balanced reporting.
- Statement preview without ledger posting, commit and duplicate warnings.
- Explicit transaction posting and Xero preview/commit.
- Mobile Banking layout and no browser JavaScript errors.
- Unsafe SimpleFIN destinations rejected before any outbound connection.
- CLI access to browser-created books.

Desktop and mobile Banking screenshots were visually inspected. Tables scroll
inside their containers on narrow screens. Screenshots were used for internal
review and are not part of this source package.

SimpleFIN protocol parsing, scoped account IDs, pending rows, partial errors,
destination restrictions, and authenticated token encryption have unit coverage.
Synthetic provider rows are exercised in the database scenario. **No real SimpleFIN
account, Chase login, OAuth/authorization flow, live transaction feed, or paid
provider request was used.** Provider availability and actual account coverage are
unverified. Xero uses prepared synthetic cutover data; no live Xero organization
was migrated. Plaid integration is not implemented or required.

### Reproducing accounting checks

Use a fresh, empty disposable database for each scenario. These commands initialize
and write synthetic accounting data; they must never target live books. DSN files
must be mode 0600, and the CA must validate the database endpoint's certificate.

```sh
WORKGLEN_TEST_DSN_FILE=/private/test-postgres.dsn \
WORKGLEN_TEST_CA_FILE=/private/test-ca.pem \
cargo test --locked --test accounting_db -- --ignored --nocapture
```

For the browser/API scenario, use another empty disposable database, an installed
Playwright/Chromium, and the release executable. `NODE_PATH` can identify externally
installed Playwright; `WORKGLEN_CHROMIUM` can select a Chromium executable.

```sh
python3 tools/accounting-web-test.py \
  --binary target/release/workglen \
  --pg-dsn-file /private/empty-browser-postgres.dsn \
  --pg-ca /private/test-ca.pem \
  --work /tmp/workglen-accounting-test
```

The optional `--pg-server` argument starts a user-provided JavaScript database
fixture instead; it must print a readiness line and expose a fresh database on
localhost:55431. No bank-provider calls are made by the test harness.

## Mail integration and browser regression

**120 checks passed**, using two Workglen processes, a witness, local DNS fixtures
and a loopback TLS SMTP relay. Python smtplib/imaplib, OpenSSL and Chromium acted as
independent clients. No mail was sent to an external recipient.

Scenarios include SPF/DKIM/DMARC, SMTP STARTTLS, open-relay refusal, authenticated
submission and relay delivery, IMAP folders/messages/flags/IDLE, backup/export,
replication, primary loss and witnessed promotion, old-primary rejoin, replacement
seeding, single-node startup and expansion, witness loss, and fenced dual-to-single
conversion with retained data. Module tests cover durable disable state, in-flight
work boundaries, disabled APIs/protocols, stale revisions, re-enable, and propagation
to standby/promoted/replacement nodes. Independent Webmail enable state is also
verified through replication, promotion and replacement snapshots. Relay-mode DKIM
signing remains enabled alongside the shared queue.

Security regressions cover MIME part/depth limits, rejected APPEND/SMTP storage,
subsequent BODYSTRUCTURE/SEARCH, rate-limit isolation and actual-peer attribution,
malformed login recovery, oversized command closure, Host/Origin/CSRF restrictions,
cookies/CSP, standby read-only controls and logout. The prior reviewer's separate
full offensive harness was not available and was not rerun.

**18 Mail browser scenarios passed** with Chromium Headless Shell 141.0.7390.37
via Playwright, including branding, Capacity, module state/navigation, account
creation/reset, queue/policy/backups, standby behavior, mobile overflow and logout.
The standard Chromium executable could not create its singleton socket in this
environment; headless shell completed the checks with the restricted-runtime flag.
Node.js and Chromium are test dependencies, not Workglen runtime dependencies.

## Direct delivery and DKIM

**54 retained loopback checks passed in the earlier development snapshot** using synthetic DNS, Python SMTP peers, generated
certificates and independent OpenSSL DKIM verification. Scenarios include MX
priority, implicit A/AAAA routing, multiple addresses, IPv6 despite A lookup
failure, own-MX cutoff, Null MX, mixed Null MX, NXDOMAIN and private-address refusal;
STARTTLS and certificate failures; no plaintext downgrade after failed STARTTLS;
post-TLS capability reset; HELO compatibility; SIZE and 8BITMIME; RCPT/DATA failures;
retries; lost final acknowledgments; local failure notices; and relay hostname
resolution with authenticated TLS. No provider endpoint or public recipient was
contacted.

Signature checks cover Unicode-compatible MIME transport, empty bodies, header/body
tampering, added-From oversigning, relaxed whitespace, recipient retry byte identity,
published TXT verification and aligned receiving DMARC. Obsolete cross-version
queue tests were removed; private test keys are not included in this archive.

```sh
python3 tools/outbound-integration.py --binary target/release/workglen \
  --work /tmp/workglen-outbound-test
```

The test port/private address overrides apply only to synthetic loopback peers. Default Internet-routing
guards are also exercised by the harness.

## Webmail API and browser

**34 API/IMAP checks and 17 browser scenarios passed** against the actual HTTPS
listener, using synthetic Alice/Bob/small-quota mailboxes. Coverage includes default
disablement, independent enable state, admin-cookie separation, Host/Origin/CSRF,
account-scoped APIs, stale UIDVALIDITY and traversal rejection, Unicode MIME and
attachments, inert binary downloads, shared DKIM-signed messages visible in IMAP,
atomic local/Sent copies, idempotent send retry and changed-replay refusal, unknown
recipients, unsupported outbound routing, header injection, aggregate self-delivery
quota rollback, flags, Trash/restore, bounded pagination, module pause/resume,
password-reset revocation and logout.

Chromium checked inbox/reader/compose, attachments, reply and Sent reply recipients,
Sent folders, stars, Trash, mobile list/reader navigation, and logout. Hostile HTML
was displayed as text, with no image/script elements inserted into the reader,
no remote requests and no browser script errors. Desktop reader and mobile reader
screenshots were visually inspected; screenshots are not in the source archive.
This is functional smoke coverage, not a complete accessibility/security audit.

```sh
python3 tools/webmail-test.py --binary target/release/workglen \
  --work /tmp/workglen-webmail-test --browser
```

The scripts use Python's standard library/OpenSSL plus external Playwright/Chromium
for optional browser checks. There is no runtime browser/Node dependency. Webmail
uses the existing Rust binary, mail database and delivery worker.

## Memory measurement

| Process | Maximum sampled peak RSS |
|---|---:|
| Node 1, including replacement restarts | 62,808 KiB / 61.34 MiB |
| Node 2, promoted primary | **326,740 KiB / 319.08 MiB** |

The Mail workload used 12 accounts, 10 idle authenticated sessions, two concurrent
large IMAP fetches with BODYSTRUCTURE, and a message with 9,000,000 body bytes plus
headers. Replication and HTTPS administration remained active, with Webmail listeners configured. RSS is the process
high-water mark exposed by the authenticated status API.

This meets the under-512-MiB goal for this specific Mail workload. It does not
measure concurrent Webmail workloads, Accounting workloads or the cloud PostgreSQL service, and is not a
whole-machine or universal bound. The OS, witness, browser and optional gateway
are excluded. The 480-MiB service limit is an operating guard, not proof that every
workload fits.

## Remaining scope

Mail, Webmail and the documented Accounting development module are implemented. Remaining
suite modules, fine-grained accounting roles, complete Xero history, tax/payroll,
multicurrency, payment initiation, automatic reconciliation and formal bank
statement-close workflows are not implemented. See ACCOUNTING.md for limits.

No actual Outlook installation, complete IMAP conformance suite, public SMTP
interoperability matrix, prolonged soak, hardware power-loss test, production
cloud database failover test, or independent financial/security audit was performed.
No PlanetScale database, public MX deliverability test or IP-reputation warmup was used.
The mail nodes were separate processes on one host. Pratique's pinned TLS
implementation remains experimental and unaudited; Workglen inherits that limit.
