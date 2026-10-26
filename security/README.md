# Workglen 0.8 · native Mail Security

Mail Security now runs as a process profile of the **same Rust `workglen` executable**. It can front Workglen Mail, a configured cloud mail system or an on-premises server without running Workglen mailbox storage on the gateway. Central Admin manages independently hosted instances through the existing authenticated remote protocol.

The detector, archive reader, local spam model, encrypted quarantine database, queues, rule lifecycle, HTTPS UI and mailbox connectors are native. There is no external scanner service, interpreter or additional database to install. Pinned compiled Rust libraries remain; TLS, encryption and authentication use Pratique, with no OpenSSL prerequisite. See [the dependency rule](DEPENDENCY-POLICY.md). New inspection code reuses our first-party bounded decompressor and archive-reader technology.

This is a development release. Native attachment policy and spam heuristics do **not** provide a maintained malware-signature feed or measured commercial-product detection parity. The UI reports coverage; OCR, full document rendering, dynamic sandbox execution and comprehensive binary malware analysis are not implemented. Live Microsoft provider validation and an independent security review remain outstanding.

## Installation

Mail Security starts with a fresh, encrypted `security.redb` database. There are no prior deployed stores to migrate; initialization creates the administrator, default development rules and audit chain. Subsequent starts reopen that same native store.

Build the normal Workglen executable using the repository instructions and pinned Cargo.lock. The native implementation adds no additional Cargo dependency.

1. Provision a dedicated service account and a private data directory. Copy `security/letsencrypt.example.json` (automatic TLS; see TLS-CERTIFICATES.md) or `security/example.json` (manual TLS) to `/etc/workglen-security/config.json` and replace workspace, instance ID, hostname and origin. The workspace must match the central Admin cluster ID; instance IDs must be unique and stable.
2. Provision a random 256-bit storage key at `storage_key_file`, outside `data_dir`: either supply your own or run `workglen security-generate-key /etc/workglen-security/storage.key` as the service account. Keep a separate protected key backup. Missing or incorrect keys prevent startup. See [encrypted storage](ENCRYPTED-STORAGE.md) for BYOK formats, recovery and limits. Configure native [Let’s Encrypt issuance and renewal](../TLS-CERTIFICATES.md), or install a certificate matching the configured HTTPS origin and an owner-only private key. Install a random management key of at least 32 characters, owner-only. Share that key only with the matching central registration. Credentials belong in protected files, never browser-entered endpoint definitions.
3. Provision SMTP routes in the installation config. Use a verified STARTTLS destination, or implicit TLS when the target provides it. Optional route authentication uses `username` and `password_file`. Provision only the mailbox connectors needed; see `connectors.example.json`. Removal defaults off.
4. Create an administrator hash and initialize the native redb store:

   ```sh
   umask 077
   systemd-ask-password 'Security administrator password' | workglen hash-password > /etc/workglen-security/admin.hash
   workglen security-check /etc/workglen-security/config.json
   workglen security-init /etc/workglen-security/config.json admin /etc/workglen-security/admin.hash
   workglen security-serve /etc/workglen-security/config.json
   ```

5. Open the configured HTTPS origin. Complete the eight-step wizard: mail flow, recipients, native detection/protected identities, test rules, digests/retention, optional mailbox connectors, Microsoft 365 protection, and go-live. Setup starts disabled. Typical defaults: spam score 6, AI-instruction score 3 with quarantine, daily digest and 30-day retention. Test representative legitimate and hostile samples before activating. A successful readiness check is required before enabling acceptance or changing the live delivery configuration.
6. Register each instance in central Admin using `[[security_remotes]]` with `id`, `label`, `origin`, `key_file` and optional `ca_file`. Grant explicit security roles and instance/domain/mailbox scopes. Open `/mail-security` in the central UI.
7. Validate synthetic end-to-end mail and the downstream receive connector before changing MX records. Check queues, recipient coverage, loop prevention and original sender authentication handling. Deploy `deploy/workglen-security.service` with the paths and account adjusted to the installation.

The readiness test connects to provisioned destinations without sending email or removing mailbox content. A healthy detector self-check is not a measurement of detection efficacy. DNS failures during sender authentication defer SMTP acceptance; authentication policy failures and high-risk content are retained in quarantine. Unknown recipients are refused. TLS is mandatory on delivery and management; requiring inbound STARTTLS is a separate deployment choice.

## Detection and archive coverage

| Content | Native behavior |
| --- | --- |
| Spam | Explainable local heuristics; optional administrator-trained statistical score. Only spam-only quarantine is mailbox-holder releasable. |
| AI instructions | Weighted instruction override, role delimiter, secret extraction, tool-use and concealment signals in decoded text; quarantine by default. Common fullwidth/zero-width obfuscation is normalized. Quoted educational examples can match. |
| Impersonation | Combined protected display-name, bounded domain-lookalike, differing Reply-To and payment/credential signals. Authentication success alone does not establish safety. |
| ZIP | Stored and Deflate members; bounds, checksum, names, local/central agreement and complete directory/layout checks. Unsupported ZIP variants are quarantined. ZIP64 coverage is limited; do not assume all ZIP64 archives are inspectable. |
| GZIP | Bounded first-party inflation with trailer/checksum checks, original filename and nested-content inspection. |
| TAR | Basic USTAR regular files/directories, checksum and size checks. Links, special entries and unsupported extensions are quarantined. |
| Other archives | Unsupported, encrypted, corrupted, missing-volume or over-budget content is suspicious and administrator-only. RAR/7z and further native formats remain in the backlog. |
| Prohibited content | Executable signatures and dangerous extensions, scripts, macro/embedded-object package members, legacy compound documents, disk images and selected active-document indicators are blocked, including inside inspected archives. |
| Other binaries | No claim of full antivirus coverage; benign unknown binaries are not automatically declared malware. Coverage is recorded. |

Current bounds: 10 MiB raw message, 200 MIME parts, eight attachment/nested-message levels, 256 inspected members, 32 MiB aggregate expanded bytes, and bounded per-stream expansion. Inspection checks a five-second budget between members; byte/structure limits bound individual decoder work. Nothing is extracted to disk or executed. The queue retains original MIME, not a rewritten version.

Mandatory attachment/archive checks cannot be disabled by an editable spam rule or overridden by mailbox-holder release. Re-evaluation and release use current native checks; queued releases are checked again before delivery. Rule tests remain identification-only. Changing an active rule creates an immutable new version, and activation never initiates retrospective removal automatically.

Local training is explicit: an administrator needs `learn`, content access and all configured scopes. Training begins contributing after 20 spam and 20 legitimate examples, is bounded and deduplicates content. Received mail, releases and digest clicks never silently train the model. Training/reset actions are audited; training cannot bypass mandatory attachment checks. The `learning` and `learning-reset` commands expose model status/reset; reset requires the current model revision and confirmation.

## Quarantine, digests, jobs and audit

Quarantine metadata and content permissions are separate. Each mailbox-holder digest contains a frozen list of at most 200 messages; truncation is shown. **Release selected**, **Discard selected** and **Discard all listed spam** require authenticated same-origin CSRF-protected POSTs. GET/link previews do not mutate anything. The mailbox identity comes from administered access, not message headers. Current high-risk decisions, status and holds are checked again.

Jobs and original MIME persist in encrypted redb. Ambiguous external acknowledgments remain `uncertain`, including jobs that were running at restart. They require destination review and explicit risk acknowledgment before retry/cancel. SMTP does not provide exactly-once delivery. Pausing acceptance does not erase queued work. Holds override content expiry; audit survives expiry. Single-host storage needs encrypted offline backups, a separate protected key backup and capacity monitoring; no multi-gateway shared-store replication is claimed.

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
