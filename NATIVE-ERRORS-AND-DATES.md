# Native errors and date/time utilities

These are two user-authorized, cumulative source checkpoints after DEPS-09.
No configuration, key, database schema, audit timestamp or queue format is
changed. When applying a checkpoint to a disposable test installation, rebuild
and replace the binary using the M5 Mac/Ubuntu test-server instructions;
preserve that test configuration, keys and data. No current installation exists.

## DEPS-10 — application errors replace anyhow

`src/error.rs` uses standard-library error trait objects and first-party context
wrappers. Call sites now use the explicit Workglen error module and macros.
Typed causes survive context, `?` propagation and `bail!`, preserving permission
403 responses, timeouts, permanent delivery failures and uncertain-delivery
handling. Formatting keeps the outer message for ordinary Display and the full
cause chain for alternate Display (`{error:#}`), as used by CLI and queue logs.
Ordinary Debug retains cause indentation, including multiline/trailing-newline
messages. It does not automatically capture backtraces or implement every
unused anyhow API; alternate Debug exposes the native wrapper structure.

The replacement removes **anyhow 1.0.104 only**, taking **175 to 174 external
package versions** (173 registry plus attributed mail-auth). No package is added,
and retained versions/checksums stay unchanged. The policy and license inventory
are updated for this explicit removal. This is first-party code, not vendored
anyhow source.

A development-only oracle checks 150 former/native cases for messages, normal
and alternate Display, ordinary Debug, typed classification and source chains.
The normal tests cover context propagation, lazy evaluation, Send/Sync and the
permission/timeout/permanent-delivery markers. Delivery testing caught and fixed
a typed-expression macro regression before packaging; the regression now has a
specific unit assertion. The oracle source is `tools/error-compat.rs`, and its
output is `validation/0.8-native-anyhow-compat.txt`. The former rlib is used only
as a development oracle, never as an application/build dependency.

## DEPS-11 — native dates replace Chrono

`src/datetime.rs` replaces the exact date/time operations used by Workglen.
It uses standard-library SystemTime, fixed numeric offsets and Gregorian
arithmetic already present in first-party Pratique (with its calendar-algorithm
credit retained). No Chrono source is copied or vendored. It is an application
utility, not a complete substitute for Chrono's public API, locales or timezone
database. The old dependency enabled only UTC `now`, not local-time services.

The supported operations preserve:

- UTC Unix seconds and milliseconds, including floor division before 1970 and
  subsecond SystemTime conversion; no silent clamp to epoch zero.
- Valid Gregorian dates from year -262143 through +262142, century/leap-year
  rules, date ordering and calendar-day differences used by remediation windows.
- Canonical accounting ISO dates, US statement dates, OFX compact dates and
  Xero millisecond dates. The application's existing canonical-date checks remain.
- IMAP search/internal dates and fixed offsets, outbound RFC2822 Date headers,
  Retry-After RFC2822 parsing, RFC3339 strings and ASN.1 certificate formatting.
- Existing leap-second representation and accepted legacy RFC2822 zones, optional
  seconds, nested comments and weekday consistency checks. Invalid/overflowing
  dates and trailing input continue to reject; comment scanning is iterative.

This removes **Chrono 0.4.45 only**, taking **174 to 173 external package versions**
(172 registry plus mail-auth). `num-traits` and `autocfg` remain required by the
DNS prefix-trie dependency. There are **11 direct external crates** and **176
packages total** including Workglen, Pratique and lazaret-pg. Retained versions
and checksums do not change.

`tools/date-compat.rs` is a development oracle against the former pinned Chrono
build. It passed **433,652 comparisons**: 313,698 Gregorian date/day conversions,
90,148 timestamp/format cases, 19,134 date/IMAP parse cases and 10,672 RFC2822 parse
cases. These include supported-range endpoints, negative timestamps, fractions,
leap seconds, offsets, centuries, Unicode/malformed inputs and deterministic
single-edit mutations. The old rlib is not an application/build dependency.
The normal suite also tests fixed known answers and application accounting/date
boundaries. See `validation/0.8-native-chrono-compat.txt`.

## Full crate catalog

`DEPENDENCY-CATALOG.md` includes first-party crates, every remaining direct and
transitive external package/version, its purpose and which direct dependencies
bring it into Workglen. The companion JSON records precise immediate parents,
features, dependency kinds and target conditions. The all-platform lockfile
includes build tools and target-specific libraries, not just deployed code.

## Validation boundary

Checks use Rust 1.99.1 on Linux x86-64, offline locked Cargo builds and synthetic
loopback peers. Optional disposable-PostgreSQL tests remain opt-in. No live
Mac/Lightsail service, real mailbox, customer database or public CA is modified.
These checks are not an independent security audit or production-load benchmark.

**Executed `anyhow` checkpoint:** 168 Rust tests, Clippy with warnings denied,
release build, 54 delivery/DKIM checks and 119 broader mail/IMAP checks passed
on Linux x86-64 with Rust 1.99.1. Cargo operations used `--offline --locked`.
Four optional PostgreSQL tests skipped. See `validation/0.8-native-anyhow-*`.

**Executed `chrono` checkpoint:** 174 Rust tests, Clippy with warnings denied,
release build, 54 delivery/DKIM checks and 119 broader mail/IMAP checks passed
on Linux x86-64 with Rust 1.99.1. Cargo operations used `--offline --locked`.
Four optional PostgreSQL tests skipped. See `validation/0.8-native-chrono-*`.
