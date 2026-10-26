# Offensive review remediation — October 26, 2026

This checkpoint addresses the supplied review using synthetic offline and
loopback tests. It does not establish production readiness or detection efficacy.
No live deployment, tenant, DNS service, mailbox or host swap configuration changed.

| Finding | Current status |
| --- | --- |
| F1 — panic isolation and poisoned locks | Implemented session/operation panic boundaries and reviewed lock recovery. Critical database replacement and authority state fail closed; caches are revoked/reset. Tests cover a subsequent connection after a panic, permit release, rollback and witness lease recovery. |
| F2 — Pratique fuzz coverage | Four optional cargo-fuzz targets and reproducible seed/replay tooling are included. A 30-second ASan run per target completed without a finding. This is only a short smoke campaign; extended fuzzing remains open. No further fuzzer work was performed after the user's request to package. |
| F3 — DNS failover | Implemented passive health tracking and bounded cooldown across configured resolvers. Deployment still needs independent resolver endpoints or a per-node recursor. A single load-balancer address cannot expose its individual backends. |
| F4 — memory budget | Open: expose gateway MIME budgets to operators and measure peak memory under concurrency. Parser budgets are not peak-process RSS limits; swap alone does not fix this. |
| F5 — additional IDNA security | Deferred by explicit user direction; SEC-IDNA-04 remains on the backlog. |
| F6 — Base64 differences | Added differential tests for the shared DKIM/MIME language and malformed-input quarantine. Protocol-specific acceptance remains intentional; merely having two decoders does not establish a bypass. |
| F8 — fallible clock | Open: propagate clock conversion failure safely. Do not substitute an epoch time that could alter lease/token validity. |

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

The main workspace remains at 15 external package versions. Its Cargo manifest
and lockfile are unchanged. All six reusable libraries retain zero external
dependencies. Optional fuzz tooling is a separate workspace with 10 registry
versions (9 distinct additions because libc overlaps). See DEPENDENCY-CATALOG.md.

Pratique runtime code did not change in this checkpoint. Twenty-three exact
upstream development fixture/target files were restored to make its existing
fuzz hooks buildable. The 222-file vendor inventory is tracked and verified in
`upstream/pratique/changes.json`; the existing three upstream patches remain
unchanged. No GitLab push or merge was performed.
