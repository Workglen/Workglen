# Staged first-party crate replacements

Each checkpoint is a full, cumulative Workglen source ZIP. Extract a checkpoint
into a fresh source directory and rebuild; preserve deployed configuration,
keys and databases. No binary is deployed automatically. The main version remains
0.8.0; the descriptive ZIP suffix identifies the dependency checkpoint.

## 1. Native Base64

`src/encoding.rs` uses Pratique for the byte codec, with standard padded and
URL-safe unpadded canonical forms. All application imports and test fixtures
now use it. Whitespace, mixed alphabets, extra/missing padding and nonzero tail
bits remain rejected where the former strict codec rejected them. MIME callers
retain their existing explicit whitespace handling and line wrapping.

The former base64 0.22.1 package is removed; registry package versions decrease
from 230 to 229. No package is added or upgraded. Existing Base64 strings,
credentials, feed encryption keys, message encodings and signed content retain
the same bytes. Development-only `tools/encoding-compat.rs` compares the new
implementation against the former cached crate over binary data, randomized
hostile strings and all two-byte inputs. It does not reintroduce the crate into
Cargo.toml or the deployed build.

Validation results are recorded alongside each checkpoint under `validation/`.

Base64 interoperability: 119 full Mail/replication checks and 34 Webmail checks
passed with the rebuilt binary; the former-codec differential suite passed.

Checkpoint `base64`: **135 offline locked Rust tests passed**, release
Clippy passed with warnings denied, and the release build passed.
Registry package versions: **229**.

## 2. Native accounting CSV

`src/csv_reader.rs` implements the CSV subset used by bank statements and Xero
opening balances. Commas, quoted fields, doubled quotes, embedded CR/LF,
empty fields, BOMs, Unicode whitespace trimming and equal-width records retain
the former reader's behavior. Its permissive handling of an open quote at EOF
is intentional compatibility, not a newly introduced repair of financial data.
Bank amounts and Xero balances still use the existing exact integer parsers;
no floating-point conversion or derived transaction-ID change is introduced.

Records are streamed from the existing bounded string input. Bank statements
retain their 2 MiB/5,000-record limits. Trial balances allow 8 MiB/5,000 records,
consistent with the 5,000-account cutover bound. Each record has a 4,096-column
limit. The reader is not a drop-in implementation of every CSV/Serde API.

`csv` 1.4.0, `csv-core` and `ryu` are removed (229 to 226 registry versions).
The former cached CSV crate is used only as an independent development oracle
in `tools/csv-compat.rs`; its source is not incorporated into the native reader.
The differential suite compares 80,000 generated inputs plus targeted cases.

CSV database validation passed against fresh disposable PostgreSQL fixtures:
banking/Xero cutover and posting corrections/locks/audit. The 80,000-input
former-reader comparison and three native parser tests also passed.

Checkpoint `csv`: **138 offline locked Rust tests passed**, release
Clippy passed with warnings denied, and the release build passed.
Registry package versions: **226**.

## 3. Native test directories

`tests/support/mod.rs` replaces the test-only tempfile dependency. It uses
Pratique OS randomness and exclusive directory creation, with mode 0700 on
Linux/macOS. Drop removes the directory's contents through the standard library;
it refuses a root whose directory identity changed and does not follow child
symlinks. Collision retries are bounded. No production filesystem/storage API
uses this helper, and cleanup never targets installed configuration or data.

The helper is included only by the library test build and the core integration
test target. Tests cover permissions, uniqueness, nested cleanup, child links,
a replaced root and cleanup during unwinding. `tempfile` and `fastrand` are
removed (226 to 224 registry versions). The deployed runtime gains no new module
or dependency; the two-package saving is development-only.

All three snapshots are cumulative. The `native-testdirs` ZIP contains Base64,
CSV and the test-directory replacement. At this third checkpoint, mail-auth cryptography
was still a separate next step; none of the first three checkpoints changes
SPF/DKIM/DMARC verification engines or replaces Argon2, redb, URL or TOML.

Checkpoint `testdirs`: **141 offline locked Rust tests passed**, release
Clippy passed with warnings denied, and the release build passed.
Registry package versions: **224**.

## 4. Mail-auth cryptography through Pratique

The full `native-mailauth` source ZIP includes all earlier checkpoints and the
Pratique provider. **35 external package versions are removed (224 to 189).**
The remaining count includes the attributed vendored mail-auth crate; its move
is not counted as a removal. No retained registry version/checksum changes.
See [MAIL-AUTH-PRATIQUE.md](MAIL-AUTH-PRATIQUE.md) for compatibility boundaries,
weak-key enforcement, synthetic tests, provenance and rebuild instructions.

Checkpoint `mailauth`: **148 offline locked Rust tests passed**, release Clippy
with warnings denied, release build, 119 mail/replication and 54 direct-delivery
checks passed. Former-provider comparisons and strict Ed25519 cases passed.
External package versions: **189** (188 registry + 1 vendored third-party).

## 5. Native replication codec

The `native-bincode` source ZIP replaces both bincode call sites with the small
first-party `Vec<Op>` codec. Persisted and transmitted bytes remain identical;
the existing 24 MiB frame bound is enforced before allocation and malformed
frames cannot commit database changes. See [REPLICATION-CODEC.md](REPLICATION-CODEC.md).

Checkpoint `bincode`: **152 offline locked Rust tests passed**, release Clippy
with warnings denied, release build and **119 mail/replication checks** passed.
The independent former-codec oracle passed 10,000 generated operation lists,
123,184 malformed/mutated acceptance comparisons and the exact 24 MiB boundary.
Only bincode 1.3.3 is removed: **188 external versions** (187 registry plus one
vendored third-party), with no added/upgraded package or retained checksum change.

## 6. Unused mail-auth reporting/compression

The `mailauth-report-trim` source ZIP contains all earlier checkpoints. It
removes flate2 and its five exclusive transitive packages from the existing
report-disabled deployment. Active mail-builder, similar, MIME/charset and
authentication functionality remain. Native attachment decompression and
mandatory quarantine are unchanged. See
[MAIL-AUTH-REPORT-TRIM.md](MAIL-AUTH-REPORT-TRIM.md).

Checkpoint `mailauth-reports`: **152 offline locked Rust tests passed**, release
Clippy with warnings denied, release build and **54 direct-delivery/DKIM checks**
passed. Four opt-in database tests were skipped in both new checkpoints.
The complete attributed patch was reconstructed and reapplied exactly.
External versions: **182** (181 registry plus one vendored third-party), down six
from the bincode checkpoint and seven across these last two stages. No added or
upgraded package, or retained checksum change.

## 7. Disable unused hostname lookup

Checkpoint `hostname`: **152 offline locked Rust tests**, release Clippy,
release build and **54 direct-delivery/DKIM checks** passed. Four opt-in database
tests skipped. External versions decrease from 182 to **178**;
no new package, upgrade or retained checksum change. The full attributed patch
reapplies exactly. See [MAIL-AUTH-UTILITIES.md](MAIL-AUTH-UTILITIES.md).

## 8. Pratique Base64 replaces mail-builder

Checkpoint `mailbuilder`: **154 offline locked Rust tests**, release Clippy,
release build and **54 direct-delivery/DKIM checks** passed. Four opt-in database
tests skipped. External versions decrease from 178 to **177**;
no new package, upgrade or retained checksum change. The full attributed patch
reapplies exactly. See [MAIL-AUTH-UTILITIES.md](MAIL-AUTH-UTILITIES.md).

## 9. Bounded native DKIM2 diff replaces similar

Checkpoint `native-diff`: **164 offline locked Rust tests**, release Clippy,
release build and **54 direct-delivery/DKIM checks** passed. Four opt-in database
tests skipped. External versions decrease from 177 to **175**;
no new package, upgrade or retained checksum change. The full attributed patch
reapplies exactly. See [MAIL-AUTH-UTILITIES.md](MAIL-AUTH-UTILITIES.md).

## 10. Native application errors replace anyhow

External versions: 175 → **174**. 168 offline locked Rust tests,
release Clippy/build, 54 delivery/DKIM checks and 119 broader mail/IMAP checks
passed. Four optional PostgreSQL tests skipped. No added package, retained
version or checksum change. See NATIVE-ERRORS-AND-DATES.md for oracle evidence.

## 11. Native Gregorian dates and timestamps replace Chrono

External versions: 174 → **173**. 174 offline locked Rust tests,
release Clippy/build, 54 delivery/DKIM checks and 119 broader mail/IMAP checks
passed. Four optional PostgreSQL tests skipped. No added package, retained
version or checksum change. See NATIVE-ERRORS-AND-DATES.md for oracle evidence.

## 12. Native DNS, HTTP URLs and outbound DKIM

Checkpoint `native-dns-url` replaces active hickory-resolver and url usage with
first-party code and moves outbound DKIM signing to native canonicalization
with Pratique RSA. External package versions decrease from 173 to **96**
(95 registry plus attributed mail-auth). No retained registry version or
checksum changes. The lockfile has 100 total entries including four first-party
packages. Full mail-auth replacement remains unfinished: inbound authentication,
DKIM2 and optional ARC remain in the retained attributed engine. Development
SPF/DKIM/DMARC candidates are disabled by default and never selected by SMTP.

The full source ZIP includes updated policy, catalogs, upstream patch evidence,
packet fixtures, URL comparisons and synthetic integration logs. See
NATIVE-DNS-URL-AUTH.md and VALIDATION.md for results and outstanding work.
