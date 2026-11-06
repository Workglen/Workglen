# Mail Security backlog

Updated: 2026-11-05 for the TBD 0.1.1 development/test release.

This backlog records future work. An item here is not a claim that the saved release implements it. There is no current installation.

## SEC-INGRESS-01 — Durable acceptance during scanner upgrades

**Priority:** P0 availability and loss-prevention boundary.
**Status:** Implemented in source. A guarded target-host campaign runner and runbook now cover Ubuntu/systemd preflight, 10k/25k/50k SMTP injection, scanner replacement, optional actual package-upgrade execution, evidence capture and backlog drain; external execution, soak, physical disk-full and power-loss validation remain required before production readiness.

- SMTP now performs bounded protocol, enabled-recipient and configured-capacity checks, then commits exact original MIME, envelope, observed peer, active immutable rule version and a versioned analysis-settings snapshot as `pending-scan` before returning `250`.
- `security-serve` remains the sole encrypted-store owner. The same native executable provides a separately restartable `security-scan-worker` role using an owner-only bounded Unix socket, version handshake and renewable token-bound claims. The worker renews active leases every 30 seconds; stale tokens are refused, cancellation is checked at bounded analysis phase boundaries, and a control-service restart immediately invalidates and requeues its orphaned leases. No external scanner/runtime/database was added.
- Authentication, MIME/archive inspection and rule evaluation occur after acceptance. Temporary authentication lookup failures retry; inspection errors become non-releasable incomplete quarantine. An incomplete report cannot produce delivery.
- Finalization binds the result to the receive hash, source evidence, lease token, rule pack and API/profile/coverage versions, bounds/redacts returned evidence, creates message/delivery records atomically and removes the receive record in the same commit.
- Pending receive records reserve message and potential delivery-job quota and keep their encrypted blobs live during retention maintenance. Status exposes scoped `pending-scan` counts, receive-record depth/state, oldest-pending age, scanner-contact freshness, scan retries, SMTP accepts/temporary deferrals since process start and owner-only message/job/content quota use.
- Release is fail-closed while scanner and control-process engine/profile versions differ. Delivery uncertainty remains separate and is not described as exactly once.

Synthetic local evidence recorded 2026-11-04 (not production sizing):

- An explicit ignored stress test accepted 500 one-recipient messages through 20 concurrent writers while scanning was unavailable, rejected an incompatible worker before claim, refused the 501st message at configured capacity without an orphan blob, reclaimed leases across 11 simulated scanner-replacement boundaries, rejected every stale token/result, and atomically drained all 500 records. A post-hardening unoptimized macOS run observed 6.35 seconds for acceptance and 12.14 seconds for drain/finalization.
- A focused release-binary loopback test used verified STARTTLS, killed the actual scanner child with `SIGKILL` four times, accepted 175 messages during the outages, returned the expected transient SMTP refusal at the configured 100-message backlog limit, started replacement scanner processes and delivered all 176 messages including its baseline. A post-hardening repeat also asserted live receive depth/state, oldest-pending age, logical quota use, SMTP accept/deferral counts and replacement-scanner freshness; it completed the outage/replacement phase in 7.69 seconds on macOS.
- A release-mode resource probe completed two overlapping 4 MiB attachment scans, three iterations per worker, at 43,188,224 bytes maximum RSS (about 41.2 MiB) and zero swaps on the test Mac.
- Encrypted-store interruption simulations passed for transaction panic rollback and restart after unsynced/partially written tail data.
- Focused regressions verify heartbeat framing and renewal, cooperative cancellation before and after bounded inspection, incomplete-quarantine finalization, stale-token refusal, immediate orphaned-lease requeue after control-service restart, scanner freshness, oldest-pending/depth telemetry and quota-use telemetry.

Remaining hardening/operations work:

- Execute [the guarded Ubuntu campaign](MAIL-SECURITY-UBUNTU-CAMPAIGN.md) on the intended disposable systemd host, including its optional reviewed package-upgrade driver, then add longer outage/soak periods, real filesystem-full behavior, host power-loss fault injection and startup rebuild/retention measurements. The runner is source capability, not completed external evidence. The local macOS simulations cover actual scanner `SIGKILL`, state-machine lease replacement, logical quota exhaustion and encrypted-store interrupted-write recovery, not those host-specific behaviors.
- Versioned status now derives critical/warning alerts for scanner unavailability, old receive work, uncertain/failed delivery, replication debt, stale/failed bidirectional peer contact and host free-space reserve, and Central Admin renders them as a high-contrast cluster-wide action panel. External alert delivery, acknowledgement/deduplication policy and Ubuntu delivery validation remain required. SMTP admission reserves a configurable host-filesystem floor and fails closed.
- Worker and peer-replication protocol 2 now negotiate an explicit version 1–2 window. Current workers begin with a version-1-compatible hello and pin the highest mutually supported version for the connection; current services accept real legacy version-1 frames, while disjoint windows fail before work is claimed or state is applied. Focused current/legacy pair regressions pass; a packaged rolling two-host campaign remains an activation gate.
- A restart of `security-serve` itself still relies on ordinary SMTP sender retry. Listener-FD handoff or independently spooling dual ingress nodes remains a later availability increment; no shared multi-gateway spool is claimed.

## SEC-SCALE-01 — High-backlog gateway scaling

**Priority:** P0 capacity validation for large gateway deployments.
**Status:** Indexed/constant-time source paths are implemented and locally exercised through 25,000 queued messages per store and 50,000 aggregate across two independent stores; Ubuntu, representative-content, replication and larger network sign-off remain required.

- Admission uses a transactionally maintained durable capacity ledger rather than enumerating every message, receive record, job and blob. Scanner claims use ordered due and active-lease indexes. Global status uses durable state counters and an oldest-arrival index. Authoritative records and their derived updates commit in the same redb transaction.
- Service startup rebuilds the ledger, counters and indexes from authoritative encrypted records, so missing or damaged derived data cannot silently change capacity or queue order. Startup rebuild and retention garbage collection remain linear maintenance operations; scoped status also remains linear because it enforces arbitrary mailbox/domain visibility.
- The release scaling harness parameterizes backlog, writer concurrency, exact MIME size and optional drain, then reports acceptance latency/throughput, status latency, disk growth, peak RSS and CPU. A separate process test exercises verified STARTTLS, scanner kills/replacements, capacity refusal and delivery.
- Local bounded group commit raised 4 KiB direct-ingress throughput from 201.5/s with one caller to 2,550.4/s with 16 callers while reducing 2,000 messages to 125 encrypted durable commits; p95 was 7.3 ms. Thirty-two callers added no throughput and doubled p95, confirming the deliberate 16-message/session ceiling. Status exposes commits, messages, largest batch and messages per commit. The wrapper accepts comma-separated concurrency points plus host-calibrated throughput/latency ceilings and exits unsuccessfully on regression. This is development-Mac storage-path evidence, not production capacity or malware-analysis throughput.
- Delivery selection now uses a durable partition/term/owner/due index and a configurable bounded 1–16 worker pool (default four), replacing the single O(n) list-and-sort loop. Rebuild and eight-worker concurrent-claim tests prove 100 indexed jobs are claimed exactly once. The 5k loopback run exercised the pool through downstream delivery.
- A scanner matrix over 500 benign 64 KiB messages measured 71.0/s at one worker, 75.6/s at two, 76.2/s at four and 75.7/s at eight. Two remains the default because higher concurrency added negligible throughput and sharply increased p95. Archive-heavy Ubuntu sizing remains required.
- The scanner reserves exactly one indexed latency worker for small, clearly single-part mail; all additional workers increase resource-capped heavy capacity for multipart, attachments, encoded bodies, large or ambiguous input. Light workers never take heavy work; an idle heavy worker may assist the light queue. Classification changes scheduling only—both lanes run the same pinned analysis profile and fail-closed coverage rules. Status and the receive queue expose the actual lane depth and allocation. The default remains two workers pending target-host resource evidence.
- The original two-worker, three-run benchmark reduced light-message p95 completion from 2.854 s to 0.915 s (3.12x), but its strict one-light/one-heavy reservation reduced total throughput from 69.4/s to 58.6/s (15.5%). With the corrected scalable allocation, three workers (one light/two heavy) restored total throughput to 67.8/s versus 67.4/s shared while retaining a 1.76x light-p95 advantage (1.667 s versus 2.941 s). Four workers (one light/three heavy) reached 68.7/s versus 67.5/s shared but narrowed the light-p95 advantage to 1.36x. Three workers are therefore the target-host candidate, not yet the production default or an Ubuntu SLO.
- A same-host two-store baseline accepted 50,000 messages at an exact 25k/25k split with 40 writers: 229.0 aggregate accepts/s, 350 ms p95, 339 ms last-quarter p95, 8 ms combined status, 74.3 MiB peak RSS and 1,025.2 MiB aggregate disk growth. It intentionally excludes peer replication and is the ceiling against which SEC-HA-02 overhead will be measured.
- The actual-process test queued 1,000 messages over separate verified-STARTTLS connections with 16 concurrent clients while the scanner was unavailable, killed/replaced the scanner four times, observed the deliberate capacity refusal and delivered all 1,076 accepted messages.
- A persistent-session real-process campaign accepted 5,000 messages while the scanner was offline through 16 verified-STARTTLS clients and 48 total connections (up to 150 messages each). Acceptance sustained 1,877.6/s; four scanner `SIGKILL`/replacement cycles, one deliberate refusal and delivery of all 5,076 accepted messages completed in 145.864 seconds.

Detailed results, repeatable commands, conservative initial resource envelopes, disk sizing and remaining gates are in [MAIL-SECURITY-SCALING.md](MAIL-SECURITY-SCALING.md).

Remaining before production sizing:

- Validate the three-worker one-light/two-heavy candidate against two and four workers on the intended Ubuntu host. Pin host-calibrated light-p95, total-throughput and peak-memory regression guards before changing the default.
- Execute the guarded 10k/25k/50k scanner-replacement and reviewed package-upgrade campaign on the intended Ubuntu filesystem and systemd units; measure restart rebuild and retention collection time.
- Run the campaign's deterministic mixed profile at 64 KiB, 1 MiB and near-limit sizes. It now cycles plain, benign attachment, compression-heavy GZIP, nested message and malformed-transfer-encoding inputs and records exact accepted variant counts; contained/local validation is not target-host evidence.
- Repeat the completed 5k persistent-session SMTP campaign across a real network on the target Ubuntu host and disposable downstream service.
- Run real disk-full/power-loss injection on Ubuntu. Native host-free-space admission now reserves a configurable floor and fails closed, but the local macOS probe is not a disk-exhaustion campaign.
- Use the independent two-store results only as a distribution baseline. Implement and fault-test SEC-HA-02 before making any synchronized-HA claim; no shared multi-owner spool is currently claimed.

## SEC-HA-02 — Synchronized dual-node acceptance with fenced delivery ownership

**Priority:** P0 availability and accepted-mail durability.
**Status:** Implemented in source as a pre-production two-node availability slice: authenticated verified-TLS/HMAC peer transport, durable peer acknowledgement before SMTP `250`, bounded explicit degraded acceptance, ordered acceptance and later-state logs, immutable replay receipts with gap/conflict checks, version-1/2 rolling compatibility, full retained-log or checkpoint-tail resync, bounded checksummed compaction, fenced planned handoff with exact-state cancellation and automatic scan-generation reassignment, guarded exclusion/takeover and Admin controls. A strict-mode message returned with SMTP `451` stays non-runnable and is automatically tombstoned on every replica if a peer acknowledgement arrives late. A complete native two-node loopback fixture passes acceptance, state catch-up, delivery, scanner upgrade, central outage and encrypted restart. Production synchronized HA is still not claimed: Ubuntu multi-host fault/scale work, interrupted handoff/takeover/cancellation/compaction campaigns, real disk-full/power-loss tests and packaged rolling-upgrade evidence remain open. Recovery before a compaction frontier requires the retained encrypted database snapshot; fresh-node snapshot streaming is not implemented.

- Publish two MX receivers. Both durably accept, spool, scan and deliver the messages they own. Every message/ownership partition has exactly one fenced delivery owner, normally its accepting node; placement peers hold non-delivering replicas.
- Healthy acceptance requires local plus peer durable commit before `250`. Explicit maintenance-only degraded acceptance may use one durable copy with bounded, visible replication debt.
- The accepting/delivery owner retains its authoritative item until placement peers durably acknowledge replicas. All failover-relevant state changes use a transactionally committed, ordered, idempotent replication outbox.
- Takeover is never automatic from peer timeout. Planned ownership handoff is initiated by the current owner; operator takeover requires that owner to be fenced and explicitly acknowledges incomplete replication or uncertain-delivery risk.
- Durable per-partition terms fence downstream delivery/remediation. Scans use separate cluster-wide owner/lease generations and synchronized policy/model revisions, allowing all scanner pools to work without creating duplicate authoritative results. A returning stale node can accept new work but cannot deliver a partition transferred under a higher term.

The complete protocol, state, security, observability, handoff and fault-test requirements are in [MAIL-SECURITY-REPLICATION.md](MAIL-SECURITY-REPLICATION.md). The staged source slice is implemented; continue the remaining activation gates in the order defined there and do not describe the current same-host pre-production evidence as production synchronized HA.

The guarded [two-host activation campaign](MAIL-SECURITY-HA-ACTIVATION.md) now
defines the physical-host preflight, balanced/skew traffic, strict peer-loss,
drain/cancel/handoff, fenced takeover, resync, rolling-upgrade and destructive
fault order. The Ubuntu runner can authenticate to both nodes and refuses an
execute run unless identities, protocol windows, reciprocal membership, fresh
bidirectional contact and both debt counters are healthy. This is executable
source and a runbook, not completed multi-host evidence.

The protocol must remain extensible beyond two nodes: versioned rendezvous placement, bounded replication factors, per-origin ordered logs and placement generations instead of full-mesh replication. Delivery ownership is partitioned initially by accepting/origin node and may later use tenant/domain/route partitions; every partition retains exactly one fenced owner term.

Central Admin must provide an authenticated cluster view with stable node identity, version compatibility, acceptance/scanner/delivery eligibility, ownership terms, replication lag/debt/gaps, queue age, capacity and degraded/fenced health. Separate audited permissions cover read-only health, normal drain/exclude/rejoin/resync/handoff operations, and high-risk operator takeover. See the Admin section of [MAIL-SECURITY-REPLICATION.md](MAIL-SECURITY-REPLICATION.md).

## SEC-OPS-04 — Cluster mail operations console

**Priority:** P0 operator safety and queue visibility.
**Status:** Implemented in source for cluster aggregation, per-message/job actions, native host-free-space state, derived high-contrast operational alerts, content-hash reconciliation, bounded compaction, safe exclusion/rejoin, planned drain/handoff/cancellation, log resync and separately permissioned forced takeover. Browser-source parsing and interactive browser-surface review pass; the dependency-free synthetic Playwright fixture remains for the established browser-test lane because Playwright is not installed locally.

- Operations aggregates reachable registered gateways and exposes receive depth/oldest age, scanner and delivery utilization, quarantine, delivery review, protected-storage utilization, node health and replication debt. Unavailable and stale nodes remain visible rather than disappearing from totals.
- Receive Queue exposes bounded, cursor-based, mailbox/domain-scoped ingress summaries without message content. Quarantine defaults to only active quarantines, separates release-queued and history records, and filters by reason, release eligibility, hold, search and gateway. Delivery Jobs defaults to failed/uncertain work and separates active, queued/retrying and history records.
- List responses are compact summaries. Full verdict/evidence and the bounded matching audit/job journey are fetched only for an explicitly selected message, keeping ordinary central responses below the existing remote response boundary. Original content retains its separate permission and inert-text rendering.
- Central queue reads can fan out across registered gateways. Every row retains gateway identity, and release, discard, hold, re-evaluation, training and job retry/cancel commands are sent explicitly to that gateway with the existing revision, permission, confirmation, duplicate-risk and audit controls.
- Saved browser-local filters, optional 15-second live refresh, explicit loading/empty/partial-error states, node-aware high-contrast badges, responsive queue cards and a maximum-20 client-side bulk release/discard workflow are included. Bulk work invokes the existing audited command separately for each item and reports partial failures instead of implying atomic completion.
- Rust regressions cover compact summaries, separate detail/journey evidence, job filters, ingress ownership, reconciliation, safe exclusion and hiding out-of-scope recipients. The synthetic Playwright fixture now uses a two-node 10k/15k receive profile and bounded 100-row pages, and covers cluster aggregation, reconciliation/compaction controls, receive/quarantine/job views, message journey, node-routed bulk/retry actions, control/dialog labelling, duplicate IDs, critical-alert contrast, keyboard activation and narrow-width layout. Source parsing passes; the current developer environment and contained ARM64 runner do not include the supported Playwright/Chromium lane, so execution remains required there.

Remaining operations work:

- Deliver the new versioned alert state to explicitly approved configured external destinations with bounded retries and deduplication/acknowledgement; peer-contact alerts and the Admin action panel are implemented, but they are not external paging. No operational metadata egress is enabled by the current source.
- Add a bounded fresh-node encrypted snapshot/bootstrap stream. Current compaction checkpoints are checksummed, prune no more than 10,000 fully acknowledged operations per log per transaction and safely replay retained tails for an intact replica, but recovery before the frontier requires a retained encrypted database snapshot.
- Run the expanded synthetic fixture in the supported Playwright/Chromium lane. Its 25k aggregate queue, accessibility, keyboard and responsive checks are implemented and source-checked but have not been browser-executed in this environment.

## SEC-RELAY-03 — Ubuntu test deployment sign-off

**Priority:** Operational P0 before treating any future gateway as production-ready.
**Status:** Source controls reviewed and synthetic checks passed; external Ubuntu
test-host verification pending. See [GATEWAY-RELAY-SECURITY.md](GATEWAY-RELAY-SECURITY.md).

- Confirm the disposable test binary/service, accepted test domains, enabled
  synthetic recipient list, test route and management access; verify both
  IP-family firewalls.
- Run the supplied no-message external relay diagnostic with a synthetic enabled
  test recipient as a positive control. A stopped/paused/unreachable server is
  not a pass.
- Confirm actual monitoring ownership, DNS/PTR and the AWS port 25 approval.
- Evaluate optional SMTP egress restrictions and per-source/recipient abuse
  quotas separately. Neither is claimed as implemented by the current limits.

The three package-removal checkpoints in [DEPENDENCIES.md](DEPENDENCIES.md)
are complete: DEPS-07 hostname feature (4), DEPS-08 mail-builder adapter (1
additional), DEPS-09 native diff (2). External package versions decrease from
182 to 175. See MAIL-AUTH-UTILITIES.md for evidence and DEPENDENCY-CATALOG.md for
the purpose of every remaining crate. External test relay sign-off above remains pending.

## SEC-ARCHIVE-01 — Native archive inspection

**Status:** Partial — the first-party Lazaret archive crate is integrated for the validated subset; unsupported cases remain fail-closed.
**Priority:** Validate the integrated subset through the full product gates, then expand only from observed attachment demand and the separate Lazaret upstream backlog.
**Goal:** Inspect common compressed email attachments using our own code, without installing an external extractor, scanner service, or additional runtime.

Lazaret and Pratique are first-party code and may be incorporated directly. Preserve applicable notices for any actual third-party material. Build the format readers and decompressors in Rust and reuse the existing first-party bounded decompression interfaces where suitable.

### Delivery order

1. **Integrated now:** RAR4/RAR5 stored members; 7z Copy, DEFLATE, LZMA1 and LZMA2; TAR/USTAR plus the documented PAX/GNU subset; GZIP/TAR.GZ; BZIP2; single-filter XZ; and LZMA-alone. Existing Workglen ZIP/ZIP64 stored/Deflate inspection remains separate.
2. **Fail-closed now:** compressed/encrypted/solid/split or multi-volume RAR; encrypted or unsupported 7z coder/filter chains; unsupported XZ filters/checks/stream shapes; links, devices, sparse/special entries; corrupted, truncated, ambiguous, path-colliding and over-budget content.
3. **Next:** finish portable product validation and use [the Lazaret archive upstream backlog](LAZARET-ARCHIVE-BACKLOG.md) for changes that belong in Lazaret rather than patching Workglen's vendored copy.

Do not postpone the current native security work while these additional formats are developed. A format or compression method becomes supported only when the complete contents can be inspected within the configured resource limits.

### Mandatory security behavior

- Identify formats from content as well as filenames; inspect nested archives and every member, including misleading extensions and embedded executables.
- Use bounded readers with per-message aggregate limits on nesting, member count, input/output bytes, compression expansion, memory and processing time. Share budgets across nested containers.
- Never execute content or invoke a shell, installed archive utility, external scanner or cloud unpacking service. Do not extract into user-controlled filesystem paths. Reject traversal, links, device entries, conflicting headers and other ambiguous member types.
- Treat encrypted, unsupported, malformed, truncated, incomplete multi-volume and over-budget archives as suspicious. Retain the original message in administrator-only quarantine with a specific reason; a partial scan is never a clean result.
- Block executables, scripts, macro payloads and other prohibited active content found anywhere inside an archive. Mailbox-holder spam release and bulk cleanup cannot bypass these checks.
- Follow the existing Development / Test / Active rules lifecycle. Identification tests must have no delivery or mailbox side effects. Recheck mandatory archive policy before any release.
- Show the supported formats and limitations in guided setup. Record detector version, coverage, reason, rule version and disposition in the audit trail without copying attachment contents into logs.

### Acceptance criteria

- Benign fixtures for every supported format, compression method and boundary condition; independently produced fixtures with known member hashes.
- Adversarial fixtures for nested executables, renamed archives, malformed sizes, checksum failures, duplicate/overlapping records, encrypted entries, missing volumes, traversal and decompression bombs.
- Fuzz container parsing and decompression; demonstrate bounded memory and termination on corrupt inputs. Measure maximum-size and concurrent-message behavior.
- Prove incomplete inspection cannot produce a clean verdict or a mailbox-holder-releasable quarantine.
- Exercise rule testing, live quarantine, re-evaluation, digest visibility, release checks and audit events through the service.
- Review format specifications and applicable rights before implementation; carry forward any required third-party notices. No additional deployed dependency or silently downloaded decoder.

**Completion:** Ship only the validated subset, publish the coverage matrix and keep unsupported cases quarantined. Expand support in later increments.


## SEC-STORAGE-02 — Key lifecycle and wider storage coverage

**Status:** Backlog. Mail Security now has mandatory encrypted redb storage with supplied or generated keys; see [encrypted storage](security/ENCRYPTED-STORAGE.md).

- Add an audited, recoverable key-rotation procedure and validate restoration of backups associated with each retained key.
- Integrate the shared encryption backend with fresh Mail/Core stores, including encrypted replication snapshots and backup/recovery. Webmail uses Mail storage.
- Consider optional remote key custody and controlled unlock without introducing a mandatory external service.
- Complete independent security review, crash/power-failure fault injection, fuzzing and realistic storage/compaction performance tests.

These are operational security features. They do not reinstate the removed Workglen-to-Workglen upgrade/import paths.

## SEC-IDNA-04 — Additional international-domain security

**Status:** Partial — the user authorized F5 on October 26, 2026. An opt-in
mixed-script domain risk signal is now implemented alongside the existing UTS
#46 normalization, prohibited-character, bidi and ContextJ safeguards. It is
not UTS #39 confusable detection or a malicious-domain verdict. Full IDNA2008
and confusable policy remain backlog items. See [NATIVE-IDNA.md](NATIVE-IDNA.md).

- Add an explicit IDNA2008 PVALID/ContextO policy for provisioned domains,
  preserving the separate browser-compatible profile needed to inspect URLs.
- Add UTS #39 confusable and script-risk analysis against configured protected
  domains. Keep Unicode display, canonical ASCII identity and risk evidence
  distinct; never use a confusable skeleton as an authorization or DNS identity.
- Evaluate domain-reputation feeds separately if requested, including provenance,
  freshness, audit evidence and failure behavior. Current configured blocking
  does not imply an active reputation feed.

Acceptance must include independent fixtures, legitimate multilingual names,
lookalike examples, malformed inputs and bounded-resource tests. Preserve
existing authentication alignment and mandatory incomplete-scan behavior.
No implementation or detection-effectiveness claim is made by this backlog entry.

## Offensive-review follow-up — October 26, 2026

See [remediation status](OFFENSIVE-REVIEW-REMEDIATION.md) for implemented changes
and exact evidence. Remaining work:

- F2: complete extended HTTP/2 and X.509 campaigns and obtain supported leak
  detection. One-hour Apple Silicon ASan campaigns completed without artifacts
  for `tls_client` (7,566,582 inputs) and the corrected PRA-WG-04 `tls_server`
  harness (7,506,825 inputs); exact-artifact and all seed replays also passed.
  Reduced-quarantine memory triage is not equivalent full-strength evidence.
  The original server finding was a harness contract violation, not an
  established production TLS defect.
- SEC-DNS-02 / F3: configure and validate independent recursors or a per-node
  recursor in the actual deployment. Passive endpoint health failover is now
  implemented; a single resolver VIP still hides backend health.
- F4 follow-up: measure peak RSS and load behavior with representative
  concurrent messages and selected budgets on the Ubuntu test host. The M5 Mac
  synthetic probe passed at 41.0 MiB maximum RSS for two overlapping 4 MiB
  attachment scans, three iterations each; this is not service or production
  capacity evidence. Parser budgets are not process RSS limits. Any host swap
  decision is operational; consider mail privacy and encrypted swap, not swap
  as the sole OOM control.
- SEC-IDNA-04 follow-up: full IDNA2008 eligibility/ContextO and UTS #39
  confusable analysis remain unimplemented. The F5 mixed-script signal is only
  an opt-in heuristic and needs deployment-specific false-positive review.

F4, F5 and F8 are implemented with synthetic regressions. F4 adds operator
scanner budgets and concurrency admission; F5 adds the mixed-script signal;
F8 propagates UTC clock failures without an epoch fallback or altered token/lease
validity semantics. On October 26, 2026, the M5 Mac passed the focused and full
workspace tests, both Clippy configurations and release build. Ubuntu execution
and the separate vendored Pratique formatting issue remain open.

Persisted relay `sending` items still need operator reconciliation. Security
`uncertain` delivery jobs now have a high-contrast needs-review view and retain
the existing explicit duplicate/removal-risk acknowledgement before retry or
cancel; this does not make SMTP delivery exactly once.
