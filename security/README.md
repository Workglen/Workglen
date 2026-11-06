# Workglen 0.1.1 (TBD) · native Mail Security

This is a development/test target. There are no current installations, live or otherwise.

Mail Security now runs as two process roles of the **same Rust `workglen` executable**. `security-serve` owns encrypted storage, SMTP/HTTPS, authenticated peer replication and delivery; `security-scan-worker` is independently restartable and performs sender authentication plus bounded inspection over an owner-only local socket. It can front Workglen Mail, a configured cloud mail system or an on-premises server without running Workglen mailbox storage on the gateway. Central Admin reaches independently hosted instances through verified TLS and a shared installation pairing key. The default pairing ceiling is intentionally limited to read/status, rule drafting and rule testing; it is not per-operator gateway authentication.

The detector, archive reader, local spam model, encrypted quarantine database, queues, rule lifecycle, HTTPS UI and mailbox connectors are native. There is no external scanner service, interpreter or additional database to install. Pinned compiled Rust libraries remain; TLS, encryption and authentication use Pratique, with no OpenSSL prerequisite. See [the dependency rule](DEPENDENCY-POLICY.md). New inspection code reuses our first-party bounded decompressor and archive-reader technology. Mutating command receipts use a durable time index, bounded pruning and a rebuilt counter; the default seven-day TTL prevents the 100,000-receipt safety valve from becoming a permanent administration lockout.

This is a development release. Native attachment policy and spam heuristics do **not** provide a maintained malware-signature feed or measured commercial-product detection parity. The UI reports coverage; OCR, full document rendering, dynamic sandbox execution and comprehensive binary malware analysis are not implemented. Live Microsoft provider validation and an independent security review remain outstanding.

## Installation

Mail Security starts with a fresh, encrypted `security.redb` database. There are no prior deployed stores to migrate; initialization creates the administrator, default development rules and audit chain. Subsequent starts reopen that same native store.

Build the normal Workglen executable using the repository instructions and pinned Cargo.lock. Native archive expansion adds only reviewed first-party Lazaret path crates; it adds no registry dependency, extractor process or runtime service.

1. Provision a dedicated service account and a private data directory. For the current private-test-CA procedure, copy `security/example.json` (manual TLS) to `/etc/workglen-security/config.json` and replace workspace, instance ID, hostname and origin. Use `security/letsencrypt.example.json` only for a separately and explicitly authorized ACME test; see TLS-CERTIFICATES.md. The workspace must match the central Admin cluster ID; instance IDs must be unique and stable.
2. Provision a random 256-bit storage key at `storage_key_file`, outside `data_dir`: either supply your own or run `workglen security-generate-key /etc/workglen-security/storage.key` as the service account. Keep a separate protected key backup. Missing or incorrect keys prevent startup. See [encrypted storage](ENCRYPTED-STORAGE.md) for BYOK formats, recovery and limits. For current tests, install a private-test-CA certificate matching the configured HTTPS origin and an owner-only private key. Native [Let’s Encrypt issuance and renewal](../TLS-CERTIFICATES.md) is a separately tested capability, not part of the current private-test-CA procedure. Install a random management key of at least 32 characters, owner-only. Share that key only with the matching central registration. A replicated test pair also needs one random peer-authentication secret of at least 32 characters in an owner-only file on both nodes; it is independent of both storage keys and is never replicated. Credentials belong in protected files, never browser-entered endpoint definitions.
3. Provision SMTP routes in the installation config. Use a verified STARTTLS destination, or implicit TLS when the target provides it. Optional route authentication uses `username` and `password_file`. Provision only the mailbox connectors needed; see `connectors.example.json`. Removal defaults off.
4. Create an administrator hash and initialize the native redb store:

   ```sh
   umask 077
   systemd-ask-password 'Security administrator password' | workglen hash-password > /etc/workglen-security/admin.hash
   workglen security-check /etc/workglen-security/config.json
   workglen security-init /etc/workglen-security/config.json admin /etc/workglen-security/admin.hash
   workglen security-serve /etc/workglen-security/config.json
   workglen security-scan-worker /etc/workglen-security/config.json
   ```

5. Open the configured HTTPS origin. Complete the eight-step wizard: mail flow, recipients, native detection/protected identities, test rules, digests/retention, optional mailbox connectors, Microsoft 365 protection, and go-live. In the current development phase, go-live means enabling only the disposable synthetic test scenario; do not change public MX or a live delivery configuration. Setup starts disabled. Typical defaults: spam score 6, AI-instruction score 3 with quarantine, daily digest and 30-day retention. Test representative legitimate and hostile samples before activating. A successful readiness check is required before enabling acceptance.
6. Register each test instance in central Admin using `[[security_remotes]]` with `id`, `label`, `origin`, `key_file` and optional `ca_file`. Grant explicit security roles and instance/domain/mailbox scopes. Ordinary cluster operations require `security.cluster.operate`; forced takeover separately requires `security.cluster.takeover`. The gateway's `trusted_admin.permissions` ceiling must include the corresponding `cluster.operate` and/or `cluster.takeover` names. Open `/mail-security` in the central UI.
7. Validate synthetic end-to-end mail and the downstream test receive connector. Check receive-spool depth, queues, recipient coverage, loop prevention and original sender authentication handling. Deploy both `deploy/workglen-security.service` and `deploy/workglen-security-scanner.service` with the paths and account adjusted to the disposable test installation.

The readiness test connects to provisioned destinations without sending email or removing mailbox content. A healthy detector self-check is not a measurement of detection efficacy. Once SMTP returns `250`, the exact original MIME and envelope are already committed in encrypted storage as `pending-scan`; when replication is configured in strict mode, the configured durable-copy count has also acknowledged it. Scanner outages and temporary sender-authentication DNS failures retain that work for retry while ingress continues accepting within configured capacity. Authentication policy failures and high-risk or incomplete content are retained in quarantine. Unknown recipients are refused. TLS is mandatory on delivery, management and peer transport; requiring inbound STARTTLS is a separate deployment choice.

## Replicated test pair

Each node lists the other node under the optional immutable installation-level `replication` block. Origins must be canonical HTTPS and certificates must validate against the configured CA. This example requires both local and peer durable commit before SMTP success and does not allow degraded acceptance:

```json
"replication": {
  "peers": [{
    "node_id": "gateway-b",
    "origin": "https://security-b.example.com:8445",
    "ca_file": "/etc/workglen-security/cluster-ca.pem",
    "key_file": "/etc/workglen-security/replication.key"
  }],
  "durable_copies": 2,
  "acknowledgement_timeout_seconds": 10,
  "degraded_acceptance": false,
  "max_degraded_operations": 0,
  "max_degraded_bytes": 0
}
```

Reverse the peer identity/origin on gateway B and use its own `instance`, storage key and data directory. The peer secret may authenticate this one pair; do not reuse it across unrelated clusters. Installation refuses silent replication removal or topology changes after initialization. Strict-mode messages that return SMTP `451` remain non-runnable; a late peer acknowledgement triggers a replicated tombstone, while an immutable receipt makes subsequent log replay safe. Resynchronization deliberately pauses acceptance, resets one peer's acknowledgement positions and replays the complete retained acceptance and state logs. Rejoin is refused until both debts are zero. There is no compact snapshot or log pruning yet, so retained logs also retain their referenced content bytes.

The Admin Operations page shows node mode, acceptance/scanner/delivery eligibility, ownership terms, both replication debts, last peer health and the host free-space reserve. Planned drain/handoff never automatically takes over after a timeout. Forced takeover is recovery-only: stop or network-fence the old owner first, review ambiguous downstream delivery, and use the separate high-risk permission and confirmation workflow.

## Detection and archive coverage

| Content | Native behavior |
| --- | --- |
| Spam | Explainable local heuristics; optional administrator-trained statistical score. Only spam-only quarantine is mailbox-holder releasable. |
| AI instructions | Weighted instruction override, role delimiter, secret extraction, tool-use and concealment signals in decoded text; quarantine by default. Common fullwidth/zero-width obfuscation is normalized. Quoted educational examples can match. |
| Impersonation | Combined protected display-name, bounded domain-lookalike, differing Reply-To and payment/credential signals. An optional mixed-script domain signal is off by default; it is not full confusable detection and legitimate multilingual names can match. Authentication success alone does not establish safety. |
| ZIP | Stored and Deflate members; bounds, checksum, names, local/central agreement and complete directory/layout checks. Unsupported ZIP variants are quarantined. ZIP64 coverage is limited; do not assume all ZIP64 archives are inspectable. |
| GZIP / TAR.GZ | Bounded first-party inflation with trailer/checksum checks, original filename recovery and nested-content inspection. TAR.GZ is parsed as TAR. |
| TAR | Regular files/directories in USTAR, supported PAX metadata and GNU long-name forms. Links, sparse/special entries, ambiguous metadata and unsupported extensions are quarantined. |
| RAR4 / RAR5 | Stored members only, with header/member CRC validation. Compressed, encrypted, solid, split/multi-volume, link and special entries are administrator-only. |
| 7-Zip | Copy, DEFLATE, LZMA1 and LZMA2, including supported encoded headers and multiple files per folder. Encrypted archives, unsupported coder/filter chains, external/additional streams and special entries are administrator-only. |
| BZIP2 / XZ / LZMA-alone | BZIP2 includes concatenated streams; XZ supports single-filter LZMA2 blocks with supported checks; LZMA-alone supports known-size and end-marker streams. Extracted content is recursively inspected. Unsupported filters/checks/stream shapes are administrator-only. |
| Other archives | Unsupported, encrypted, corrupted, ambiguous, missing-volume, path-colliding or over-budget content is suspicious and administrator-only. |
| Prohibited content | Executable signatures and dangerous extensions, scripts, macro/embedded-object package members, legacy compound documents, disk images and selected active-document indicators are blocked, including inside inspected archives. |
| Other binaries | No claim of full antivirus coverage; benign unknown binaries are not automatically declared malware. Coverage is recorded. |

Default bounds: 10 MiB raw message, 200 MIME parts, eight attachment/nested-message levels, 256 inspected archive members, 32 MiB aggregate parser-decoded and archive-expanded bytes, 200× expansion after the first MiB, two concurrent scans, four concurrent downstream deliveries, a 24-hour sender-authentication retry ceiling, and bounded per-stream output. Operators can configure input (1 KiB–10 MiB), decoded/expanded bytes (1–256 MiB), MIME parts (1–1000), concurrent scans (1–16), authentication retry time (1–72 hours) and concurrent deliveries (1–16) in Detection setup. Scanner concurrency takes effect when its process starts; delivery concurrency takes effect when the gateway service starts. SMTP advertises the selected input limit. These are work budgets, not peak-process RSS guarantees; host memory sizing, downstream connection allowances and any encrypted-swap decision remain operational. Inspection checks a five-second budget before and after an archive call and between members; the current Lazaret API does not provide cooperative mid-decoder cancellation, so input/output/structure limits and concurrency are the in-call controls. The worker renews its token-bound lease every 30 seconds, cannot extend one lease beyond ten minutes, and observes cooperative cancellation between sender-authentication and inspection phases. Two consecutive renewal failures stop work fail-closed; a stale worker cannot finalize under a replacement token. Three expired worker leases terminate in administrator-only incomplete quarantine. Nothing is extracted to disk or executed. The receive spool retains exact original MIME, not a rewritten version.

Mandatory attachment/archive checks cannot be disabled by an editable spam rule or overridden by mailbox-holder release. Re-evaluation and release use current native checks; queued releases are checked again before delivery. Rule tests remain identification-only. Changing an active rule creates an immutable new version, and activation never initiates retrospective removal automatically.

Local training is explicit: an administrator needs `learn`, content access and all configured scopes. Training begins contributing after 20 spam and 20 legitimate examples, is bounded and deduplicates content. Received mail, releases and digest clicks never silently train the model. Training/reset actions are audited; training cannot bypass mandatory attachment checks. The `learning` and `learning-reset` commands expose model status/reset; reset requires the current model revision and confirmation.

## Quarantine, digests, jobs and audit

Quarantine metadata and content permissions are separate. Each mailbox-holder digest contains a frozen list of at most 200 messages; truncation is shown. **Release selected**, **Discard selected** and **Discard all listed spam** require authenticated same-origin CSRF-protected POSTs. GET/link previews do not mutate anything. The mailbox identity comes from administered access, not message headers. Current high-risk decisions, status and holds are checked again.

The administrator Operations workspace follows the durable pipeline rather than exposing unfiltered storage collections. It aggregates reachable registered gateways, then separates the Receive Queue, active Quarantine and Delivery Jobs. Receive, message and job APIs return bounded cursor pages and compact scoped summaries; detection evidence and a bounded message/job/audit journey are fetched separately. Central actions retain the row's gateway identity and execute only against that gateway. Quarantine defaults to active items, Delivery Jobs defaults to failed/uncertain work, and high-risk uncertainty is shown with text and an icon as well as color. Saved filters and optional queue live refresh are browser-local. Bulk release/discard is limited to 20 visible selections and issues the existing revision-checked, authorized, audited command for each item; partial failures are reported and are not represented as an atomic transaction.

Receive-spool entries, jobs and original MIME persist in encrypted redb. SMTP acceptance reserves logical message/job capacity and a native host-filesystem floor (256 MiB by default) before returning `250`; exhausted capacity or an unavailable capacity probe returns a transient SMTP failure. A bounded single writer can group at most 16 concurrent accepts into one encrypted durable transaction, but each SMTP session receives success only after that transaction commits. Its 32-request queue and the 16-session SMTP gate provide explicit backpressure. When peer replication is configured, the exact MIME acceptance and later processing/ownership state use separate ordered, authenticated, idempotent logs; strict mode waits for the configured durable-copy count. Scan leases are renewable, expire safely after worker interruption, and are immediately invalidated/requeued when the storage-owning service restarts; service restart and planned ownership handoff do not count as worker lease failures. Temporary sender-authentication retries begin at 60 seconds, double to a 15-minute cap and end in administrator-only incomplete quarantine at the configured maximum age. Operators with discard authority can stop queued work immediately into quarantine or cooperatively cancel an active scan; the original message is never dropped. Retry, cancellation and terminal state changes are replicated and audited. Completion atomically creates quarantine/delivery records while removing the receive record. Delivery work is claimed through a durable ordered index scoped to the current partition owner and fencing term; bounded workers may deliver concurrently without claiming one job twice, and a replicated delivery state must be durable before downstream contact. Status also exposes configured/running/active delivery workers, process-lifetime delivery results, scanner freshness, receive depth/state, oldest-pending age, scan-retry and SMTP accept/deferral counters, logical quota, host free space, peer contact and both replication debts. Reports pin immutable rule, API, profile and coverage versions; several incompleteness reasons may coexist, and no incomplete report can deliver. Ambiguous external delivery acknowledgments remain `uncertain`, including jobs that were running at restart. They require destination review and explicit risk acknowledgment before retry/cancel. SMTP does not provide exactly-once delivery. Pausing acceptance does not erase queued work. Holds override content expiry; audit survives expiry. Every node still needs encrypted offline backups, a separate protected key backup and deployment alerts; peer replication is not a backup and no shared database file is used.

Admission, scanner claim and owner-global status use durable ledgers/counters and ordered indexes so normal work does not grow linearly with receive depth. Startup reconstructs that derived state from authoritative records. Local development tests cover up to 25,000 queued messages, but are not production sizing evidence; see [scaling results and initial resource envelopes](../MAIL-SECURITY-SCALING.md).

The audit API is append-only and chains event hashes. `workglen security-audit-verify CONFIG` verifies the native audit history. Keep independent trusted chain checkpoints: a host administrator able to rewrite the database can also rewrite an unanchored chain. Content and credentials do not enter general audit events. Local offline CLI operations use the `local-console` identity and require exclusive access to the data directory.

## Optional mailbox remediation

Workglen IMAPS uses UIDVALIDITY, content hashes and targeted UIDPLUS removal. Graph uses provisioned Microsoft endpoints and immutable message IDs. EWS uses verified HTTPS and scoped impersonation with token or Basic credentials; NTLM is not implemented. Deployment-specific provider authorization remains necessary.

Preview an explicit recipient, tested version and 1–90-day date range. Scope is Inbox only, with an exclusive end date; IMAP follows server calendar days. Search/export limits and failures mark the preview incomplete. Execution requires separate permission, confirmation, any partial-result acknowledgment and installation-enabled removal. Native Workglen quarantine stores the verified original MIME under a hold **before** provider removal. It cannot recall already downloaded, forwarded or exported copies. Recovery is MIME redelivery through SMTP, not reconstruction of all provider properties.

Microsoft Graph has been ported but has not been validated against a live tenant in this release. EWS has a synthetic verified-TLS protocol fixture; this does not establish compatibility with every Exchange configuration.

## Validation

Run `cargo test --offline --locked` and `cargo clippy --offline --locked --all-targets -- -D warnings`. Native tests cover rules, mandatory checks, archive corruption/bounds, scopes, digest snapshots, replay protection, retention, learning and audit. The loopback fixture runs real native gateways and central Admin, TLS delivery, IMAPS/EWS remediation and optional browser tests:

```sh
node security/tests/native-network.cjs /absolute/path/to/workglen /new/fixture/directory --browser
```

The browser option needs development-only Playwright/Chromium. No customer credentials, actual recipients or live providers are used. See [VALIDATION.md](../VALIDATION.md) for exact results and remaining limits.

## Microsoft 365 recipients and Admin navigation

Optional native directory discovery is available in Setup → Recipients. Read [MICROSOFT-365-RECIPIENTS.md](../MICROSOFT-365-RECIPIENTS.md) for Entra consent, protected credentials, additive review/apply, coverage limits and updating existing installs. Discovery is on demand; scheduled synchronization and automatic recipient removal are not implemented. Central module screens now expose an explicit Back to Admin link; standalone gateways may provision an `admin_origin` for administrator sessions.

## Guided delivery destinations

Setup → Mail flow can now discover a Microsoft 365 MX host, test verified SMTP/TLS, and save a destination directly in encrypted settings. Empty route lists have guided recovery and cannot advance prematurely. See [DELIVERY-DESTINATIONS.md](../DELIVERY-DESTINATIONS.md) for scope, advanced installation-managed routes and existing-host update instructions.

## Microsoft 365 gateway enforcement

Setup → Microsoft 365 protection walks through a disabled Partner connector, dedicated outbound IPv4 restrictions, Enhanced Filtering, activation and positive/negative delivery tests. MX routing alone does not block direct delivery. See [MICROSOFT-365-GATEWAY.md](../MICROSOFT-365-GATEWAY.md). The guide does not configure or certify a live tenant.
