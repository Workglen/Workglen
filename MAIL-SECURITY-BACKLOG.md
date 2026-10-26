# Mail Security backlog

Updated: 2026-10-25

This backlog records future work. An item here is not a claim that the saved release implements it.

## SEC-RELAY-03 — Lightsail deployment sign-off

**Priority:** Operational P0 before treating the gateway as production-ready.
**Status:** Source controls reviewed and synthetic checks passed; live host
verification pending. See [GATEWAY-RELAY-SECURITY.md](GATEWAY-RELAY-SECURITY.md).

- Confirm the deployed binary/service, accepted domains, enabled recipient list,
  Microsoft 365 route and management access; verify both IP-family firewalls.
- Run the supplied no-message external relay diagnostic with a known configured
  recipient as a positive control. A stopped/paused/unreachable server is not a pass.
- Confirm actual monitoring ownership, DNS/PTR and the AWS port 25 approval.
- Evaluate optional SMTP egress restrictions and per-source/recipient abuse
  quotas separately. Neither is claimed as implemented by the current limits.

The three package-removal checkpoints in [DEPENDENCIES.md](DEPENDENCIES.md)
are complete: DEPS-07 hostname feature (4), DEPS-08 mail-builder adapter (1
additional), DEPS-09 native diff (2). External package versions decrease from
182 to 175. See MAIL-AUTH-UTILITIES.md for evidence and DEPENDENCY-CATALOG.md for
the purpose of every remaining crate. Live relay sign-off above remains pending.

## SEC-ARCHIVE-01 — Native archive inspection

**Status:** Backlog — requested; implementation deferred.  
**Priority:** Next archive expansion after the delivered 0.8 native Mail Security baseline.  
**Goal:** Inspect common compressed email attachments using our own code, without installing an external extractor, scanner service, or additional runtime.

Lazaret and Pratique are first-party code and may be incorporated directly. Preserve applicable notices for any actual third-party material. Build the format readers and decompressors in Rust and reuse the existing first-party bounded decompression interfaces where suitable.

### Delivery order

1. **RAR:** implement RAR 5 and RAR 4 readers and the decompression methods required for the supported subset. Document solid archive, split/multi-volume, encrypted entry, and header support explicitly. Never advertise blanket RAR support when only a subset is inspectable.
2. **7z:** implement container parsing and required native compression/filter support in separately testable increments.
3. **Other archive coverage:** expand the validated ZIP/ZIP64, GZIP and TAR subsets; assess BZIP2, XZ and compressed TAR variants next. Rank further formats using observed attachment demand, implementation effort and scan coverage.

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

**Status:** Backlog — explicitly deferred by the user on October 25, 2026.
These capabilities are not part of the next crate-reduction implementation.
The existing UTS #46 normalization, prohibited-character, bidi and ContextJ
safeguards remain implemented. See [NATIVE-IDNA.md](NATIVE-IDNA.md).

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

- F2: extended coverage-guided TLS client/server, HTTP/2 and X.509 campaigns,
  native Apple Silicon execution and supported leak detection. Short ASan smoke
  runs are complete; no long-campaign assurance is claimed.
- SEC-DNS-02 / F3: configure and validate independent recursors or a per-node
  recursor in the actual deployment. Passive endpoint health failover is now
  implemented; a single resolver VIP still hides backend health.
- F4: operator-configurable MIME input/decoded/part/concurrency budgets and
  measured peak-memory/load behavior. Any host swap decision is operational;
  consider mail privacy and encrypted swap, not swap as the sole OOM control.
- F8: fallible UTC clock conversion propagated through security-sensitive
  call paths without an epoch fallback or altered token/lease validity.
- F5 remains deferred under SEC-IDNA-04 above.

Persisted relay `sending` items and security `uncertain` deliveries need operator
reconciliation before retry; no new recovery UI is included in this checkpoint.
