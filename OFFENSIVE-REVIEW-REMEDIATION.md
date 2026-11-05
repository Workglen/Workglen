# Offensive review remediation — October 26, 2026

This checkpoint addresses the supplied review using synthetic offline and
loopback tests. It does not establish production readiness or detection efficacy.
No live deployment, tenant, DNS service, mailbox or host swap configuration changed.

| Finding | Current status |
| --- | --- |
| F1 — panic isolation and poisoned locks | Implemented session/operation panic boundaries and reviewed lock recovery. Critical database replacement and authority state fail closed; caches are revoked/reset. Tests cover a subsequent connection after a panic, permit release, rollback and witness lease recovery. |
| F2 — Pratique fuzz coverage | Four optional cargo-fuzz targets and reproducible seed/replay tooling are included. One-hour macOS ASan campaigns passed for `tls_client` (7,566,582 inputs) and the corrected `tls_server` harness (7,506,825 inputs), with no artifacts. PRA-WG-04 fragments generated handshake streams and adds a regression seed without changing production TLS; exact-artifact and all seed replays passed. HTTP/2 and X.509 extended campaigns remain pending, as does supported leak detection. |
| F3 — DNS failover | Implemented passive health tracking and bounded cooldown across configured resolvers. Deployment still needs independent resolver endpoints or a per-node recursor. A single load-balancer address cannot expose its individual backends. |
| F4 — memory budget | Implemented operator-configurable SMTP/scanner input, MIME decoded/expanded-byte, part and concurrency bounds with synthetic limit and permit-release regressions. Focused and full-workspace tests, both Clippy configurations and release build passed on the M5 Mac. The bounded concurrent-scan probe peaked at 41.0 MiB RSS. Parser budgets are not peak-process RSS limits; no host swap configuration changed. |
| F5 — additional IDNA security | Implemented an opt-in mixed-script domain risk signal over validated Unicode and A-label forms, default off, with single-script, mixed-script and bounded-input regressions. Focused and full-workspace tests passed on the M5 Mac. This is not UTS #39 confusable detection or a malicious-domain verdict; full SEC-IDNA-04 work remains on the backlog. |
| F6 — Base64 differences | Added differential tests for the shared DKIM/MIME language and malformed-input quarantine. Protocol-specific acceptance remains intentional; merely having two decoders does not establish a bypass. |
| F8 — fallible clock | Implemented fallible UTC acquisition and propagated failures through security-sensitive callers without an epoch fallback or altered lease/token validity semantics. The synthetic out-of-range-clock regression and full workspace tests passed on the M5 Mac. |

## F2 macOS fuzzer-memory triage — October 26, 2026

An attempted one-hour-per-target campaign stopped in `tls_client` after
2,584,055 inputs when RSS reached 516 MiB against libFuzzer's configured 512 MiB
cap; the other targets did not run. Its 5,708-byte saved OOM artifact replayed
against the preserved binary with the same cap in 8 ms without a failure. The
largest reported allocation contexts were libFuzzer bookkeeping, not Pratique.

Fresh same-seed runs of that preserved binary then produced these bounded
results, with ASan enabled, leak inspection disabled and no saved artifacts:

| Target and diagnostic setting | Inputs | Peak RSS | Result |
| --- | ---: | ---: | --- |
| `tls_client`, 240 seconds, default ASan quarantine | 573,191 | 415 MiB | Completed normally |
| `tls_client`, 240 seconds, 64 MiB ASan quarantine | 629,150 | 178 MiB | Completed normally |
| `tls_server`, 60 seconds, 64 MiB ASan quarantine | 380,321 | 199 MiB | Completed normally |
| `h2`, 60 seconds, 64 MiB ASan quarantine | 698,854 | 226 MiB | Completed normally |
| `x509`, 60 seconds, 64 MiB ASan quarantine | 539,644 | 167 MiB | Completed normally |

Reducing only ASan quarantine therefore identified sanitizer retention as the
dominant measured contributor to the earlier RSS growth; it does not prove the
absence of a cumulative product defect. The reduced quarantine shortens
use-after-free retention and is diagnostic, not equivalent full-strength fuzz
evidence. Leak checking remains unvalidated and no extended-campaign assurance
is claimed. Logs and corpora are retained under `target/fuzz-mac-extended/`,
`target/fuzz-mac-rss-retest/` and `target/fuzz-mac-quarantine64/`.

## F2 extended macOS campaign and harness correction — October 26, 2026

A subsequent campaign retained ASan, used a 64 MiB ASan quarantine, disabled leak
checking and requested 3,600 seconds per target. Seed replay and the fuzz build
passed. `tls_client` completed 7,566,582 inputs in 3,602.42 seconds with 273 MiB
peak RSS, exit 0 and no saved artifact. `tls_server` stopped after 2,657,534
inputs in 800.33 seconds with 256 MiB peak RSS. HTTP/2 and X.509 did not start
because the runner stops after a failed target.

The server artifact is 16,604 bytes with SHA-256
`fbfba540fc8d781ee94c86e23c2dc0303c6cc5b49212ab8614b12e062c428785`.
The preserved pre-fix binary reproduced exit 77 and the assertion
`content.len() <= MAX_PLAINTEXT` at `vendor/pratique/src/tls/suite.rs:239`.
The input reached `server_exchange` with more than `MAX_PLAINTEXT` bytes in its
arbitrary handshake-message field; the harness passed that entire byte stream to
one `RecordCipher::encrypt_into` call. This establishes a harness contract
violation, not a production TLS remotely reachable panic.

PRA-WG-04 changes only `src/tls/server_fuzz.rs`: it fragments that field across
records of at most `MAX_PLAINTEXT` while preserving the transcript, and adds an
oversized handshake-stream seed. The production cipher and assertion are
unchanged. Exact patch application/postimage verification, all 222 vendored-file
hashes and `git diff --check` passed. The M5 Mac then rebuilt the release replay
with `--cfg pratique_fuzzing`: the exact 16,604-byte artifact returned
`PASS replay tls_server`, and all four targets returned `PASS seed replay`,
including the new oversized server seed. A fresh server campaign then completed
7,506,825 inputs in 3,602.37 seconds with 329 MiB peak RSS, exit 0 and no saved
artifact; its seed replay and fuzz build also passed. Logs, the original artifact
and pre-fix replay evidence are under `target/fuzz-mac-extended-q64/`; generated
seeds are under `target/fuzz-mac-tls-server-fragmentation-seeds/`; the passing
server campaign is under `target/fuzz-mac-tls-server-fragmentation/`; patch
provenance is under `upstream/pratique/`. Reduced quarantine and disabled leak
checking remain explicit evidence limits.

## F4/F5/F8 macOS validation — October 26, 2026

The developer's Apple Silicon M5 Mac (macOS Darwin 25.5.0, arm64) ran
`tools/validate-f4-f5-f8.sh` with the pinned Rust 1.99.1 toolchain. IDNA table
verification, all focused F4/F5/F8 regressions, the complete offline locked
workspace suite, and the offline locked release build passed. Warnings-denied
Clippy passed both with default features and with `--features arc`. The earlier
F4 test used unconfigured default settings; its final version proves the
configured baseline valid before mutating each scanner field. Test-only
canonicalization of the macOS temporary root also allowed both ACME tests to
exercise the unchanged production real-directory checks.

`tools/measure-f4-memory.sh` then passed its explicit release-mode probe: two
overlapping scans, three iterations each, with a 4 MiB binary attachment per
message. `/usr/bin/time -l` reported 43,024,384 bytes maximum RSS (41.0 MiB)
and zero swaps. This is synthetic test-process evidence only, not gateway/service
peak RSS, production capacity, leak detection, detection efficacy or a swap
recommendation. Ubuntu test-host execution remains pending.

The combined validator still exits nonzero because `cargo fmt --check` reports
vendored Pratique example formatting and a missing example `report.rs` module.
That separate vendored issue remains open; the formatting check did not modify
source. Logs are retained in `validation/f4-f5-f8-local/`.

## Panic and delivery behavior

Unwinding panics inside the new boundaries terminate the affected session or
operation. They are not automatically replayed. A panicked cache is cleared;
poisoned database replacement is fenced; witness recovery reloads durable term
state and waits out a possible prior lease. Reusing every poisoned guard without
review would not preserve these invariants. Pratique already contained an HTTP
handler panic boundary before this update.

Relay delivery persists a `sending` state before contacting a destination.
Interrupted sends remain parked for operator reconciliation. Security delivery
panics are recorded as uncertain. Review remote acceptance before retrying:
these changes do not provide exactly-once SMTP delivery or a new reconciliation UI.
A bare Rust thread panic does not necessarily kill the whole process. These
boundaries do not contain process aborts, OOM kills or stack overflow.

## Evidence and portable checks

Run `python3 tools/check-resilience.py` from the extracted `workglen` directory.
Prepare the pinned Rust 1.99.1 toolchain, Clippy and locked dependencies first;
see PORTABLE-CHECKS.md for existing prerequisites. Add `--browser` only after
preparing the documented local Playwright/Chromium fixtures. The runner does not
install software, deploy services or send real mail. All Cargo checks are offline.
The source integrity check expects an unmodified extraction.

Validation ran on Linux x86-64 with Rust 1.99.1: 320 workspace tests passed,
4 optional PostgreSQL fixtures were ignored; warnings-denied Clippy, release
build, 217 outbound/mail/webmail/installer checks, 6 Microsoft 365 plan checks,
37 browser checks and 19 local network checks passed. macOS execution has not
been performed here. Logs and machine-readable summaries accompany this report
under `validation/0.8-resilience-review/`.

The optional fuzz smoke run used cargo-fuzz 0.13.2 and Rust
1.101.0-nightly (76456a688 2026-10-25). TLS client/server, HTTP/2 and X.509
executed 306,315 inputs in total. AddressSanitizer remained enabled.
The first attempt failed at LeakSanitizer shutdown because this environment
cannot inspect processes through `/proc`/ptrace. That failure is retained;
the successful repeat explicitly disabled leak detection. Leak checking is
therefore not validated. No long campaign or Apple Silicon result is claimed.

## Dependencies and Pratique tracking

The main workspace remains at 15 external package versions. Later Lazaret
archive integration added two first-party lock entries without adding or
upgrading a registry package; the current lock has 24 entries, including nine
first-party packages. All eight reusable libraries have zero external
dependencies. Optional fuzz tooling is a separate workspace with 10 registry
versions (9 distinct additions because libc overlaps). See DEPENDENCY-CATALOG.md.

Pratique runtime code did not change in this checkpoint. Twenty-three exact
upstream development fixture/target files were restored to make its existing
fuzz hooks buildable. The 222-file vendor inventory is tracked and verified in
`upstream/pratique/changes.json`; the four-patch series includes PRA-WG-04's
development-only server harness correction. No GitLab push or merge was performed.
