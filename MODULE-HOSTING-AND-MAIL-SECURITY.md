# Remote modules and standalone Mail Security

For delivered topology and the Mac/local-PostgreSQL deployment, use [ARCHITECTURE.md](ARCHITECTURE.md) and [MAC-ADMIN-LIGHTSAIL.md](MAC-ADMIN-LIGHTSAIL.md). The older design requirements below are retained for context, not a statement that every target is implemented.

The current [Mail Security backlog](MAIL-SECURITY-BACKLOG.md) includes native RAR and other archive-format inspection using first-party code, with unsupported content quarantined until support is validated.

Historical 0.6 architecture requirements, October 24, 2026. Mail Security is implemented as a separate native Rust process profile in 0.8 with central remote management. See [security/README.md](security/README.md) for the delivered capability map and specific operational limits. The descriptions below retain the original target; independent Accounting and Webmail hosting remain outside this Mail Security release.

## Historical 0.6 boundary (superseded)

Modules are currently linked into one Rust process and share `App`. The HTTPS administration handler invokes local module functions. Accounting owns its PostgreSQL data and can already use a remote database, but there is no remote module registry or authenticated inter-host management API. Mail Security is currently part of the SMTP/Mail processing path. Cluster replication and failover are not independent module hosting.

## Target deployment

The same distribution should support local modules and independently hosted services through explicit process profiles:

- Admin: central UI, identity/RBAC management, module registry, health and job status, and audit search.
- Accounting: ledger and source-transaction API with its own PostgreSQL database.
- Mail: SMTP submission/delivery, mailbox storage, IMAP, and mailbox operations.
- Mail Security: SMTP gateway, rule evaluation, quarantine, release delivery, and optional mailbox remediation. It must not require Workglen mailbox storage or a local Mail module.
- Webmail: client of a Mail API; its current direct-storage dependencies need extraction before remote hosting.

Each deployment has a stable workspace, module type, instance ID, permitted domains/books, API version, endpoint, health, and advertised capabilities. Multiple gateway instances can protect different domains under one Admin console. A remote instance need not accept arbitrary endpoints provided by a browser.

Admin routes commands through a local/remote module interface. Remote communication uses verified TLS and authenticated instance identities, scoped authorization, audience checks, replay protection, and credential rotation/revocation. Forward the verified originating user, book/domain scopes, request ID, and correlation ID; never trust a client-supplied actor string. The receiving module independently authorizes every command.

Financial commands retain their transaction boundaries, optimistic revisions, and idempotency. Do not automatically replay an uncertain remote financial result with a new request ID. Configuration changes use expected revisions and explicit activation acknowledgments. Show offline/stale/failed status instead of pretending the last reported state is current. Module-local audit is durable before acknowledging a change; central audit aggregation may catch up later and must display gaps.

An Admin outage must not stop established mail delivery or gateway evaluation under the last acknowledged active rule version. Cached authorization for operations needs a bounded expiry and explicit revocation behavior; an unreachable authorization service must not silently expand privileges.

## Gateway placement

Support inbound SMTP forwarding to Workglen Mail, Microsoft 365/Exchange Online, and on-premises Exchange or another configured SMTP system. Outlook is the client; Exchange Online or Exchange Server is the integration target.

Domain-specific next hops, validated recipient handling, and authenticated connectors must prevent open relay, routing loops, and bypass of the gateway. Preserve the original message and authentication evidence. Configure the downstream system to recognize the gateway and evaluate the original sending source appropriately; a gateway connection alone does not prove sender authenticity. Public SMTP and real mailbox connectors require deployment-specific validation.

SMTP acceptance, delivery retry, and security quarantine are different states and queues. A block during the envelope/connection phase cannot retain a body that was never received. Content rules requiring retention must spool the accepted message durably before acknowledging it. If capacity is exhausted, defer acceptance rather than silently losing accepted mail.

## Rule lifecycle

| State | Allowed work | Effect on live messages |
| --- | --- | --- |
| Development | Author/edit a draft, validate syntax and limits, select samples, inspect matches | Identification only; no delivery or mailbox changes |
| Test | Freeze a rule version, replay retained samples or observe live traffic in shadow mode, compare with the active version, inspect proposed actions | Identification only; existing active rules continue enforcing |
| Active | Explicitly promote a tested version with activation permission, record its scope and rollout result | Enforce the configured actions for the selected domains/instances |

Editing an active ruleset creates a new Development version; it must not alter the active version in place. Retain immutable version contents, author, test results, approval/activation actor, timestamps, scopes, and the previous active version. Rollback selects a previously published version and creates an audit event. Rollback must not automatically release earlier quarantines.

Tests report matched message counts, message identity, reasons/rule IDs, proposed action, change from the current active version, unscannable content, time range, corpus completeness, and rule evaluation errors. Rules need bounded execution time, message/attachment expansion limits, and explicit error behavior. Do not describe a partial scan as comprehensive.

**Default: identify matches only.** Rule creation and testing must never implicitly quarantine, delete, release, or move messages.

## Quarantine and delivery

Retain blocked content in a dedicated access-controlled quarantine store with stable IDs, original MIME bytes, content hash, envelope recipients, original routing, source instance, applied rule version, match explanation, timestamps, and retention deadline. Avoid putting bodies, attachments, credentials, or full sensitive content into general audit logs.

Provide search, safe text inspection, individual/bulk review, release, re-evaluate, and retention management. Quarantine is not a normal user's mail folder. Review, content access, release, retention changes, and deletion are separately permissioned. Retention holds override expiry. Deduplicate stored blobs without conflating distinct recipients or delivery states.

Release uses a durable delivery queue with attempts, backoff, next retry, last error, cancellation, and explicit uncertain-acknowledgment states. It must prevent release loops and duplicate release jobs. Do not claim exactly-once SMTP delivery after an ambiguous acknowledgment. Preserve audit history after a message body reaches its retention deadline.

## Retrospective mailbox remediation

At activation, offer **Quarantine existing matching messages**, disabled by default. This is separate from prospective enforcement. Require a supported mailbox connector and remediation permission, a bounded mailbox/domain/time scope, an identification preview, and an explicit job initiation. Bind the job to the tested ruleset version and scan scope.

Connectors advertise supported read/search/export/move/delete/restore capabilities and authorization scope. Workglen Mail can implement these through its own mailbox API; Exchange Online should use supported Microsoft Graph operations; on-premises Exchange needs a supported version-specific connector. A SMTP gateway by itself cannot retrieve or remove delivered messages.

A remediation job records provider message IDs (and updated IDs after moves), mailbox identity, a verified content fingerprint, original location, rule version, intended action, status, attempts, and recovery information. Recheck that the target still matches before acting; missing, moved, edited, or inaccessible messages are explicit outcomes. Retries must be idempotent and handle provider rate limits and partial failures. Preserve required content/recovery evidence before a destructive provider operation; surface uncertainty rather than claiming removal succeeded.

A normal mailbox folder is not necessarily an access-restricted security quarantine. The connector must prove the supported isolation behavior or use the secured Workglen quarantine with an explicit supported mailbox removal/restore flow. Rule activation must not promise recall of copies already forwarded, exported, or downloaded to a client.

## Spam detection and mailbox-holder digests

Add spam detection to Mail Security, with explainable rule/score results and a
separate high-risk classification. Spam threshold changes follow the same
Development/Test/Active lifecycle. Do not use a spam score as a substitute for
malware, phishing, or mandatory policy checks. Detection provider/engine selection,
licensing, resource budgets, and effectiveness testing remain implementation work.

Send a configurable quarantine digest **to the affected mailbox holder**. Daily
is a proposed default, with timezone, frequency, and empty-digest preferences.
Only include that mailbox's quarantined recipients and permitted metadata. Resolve
the destination from the administered mailbox identity, not untrusted message
headers. Shared mailbox recipients and delegates require explicit configuration.

Show sender, subject, arrival time, reason/category, retention deadline, and action
availability. Escape untrusted subjects/senders, omit active message content and
remote images, and avoid reproducing harmful attachments or links. Classifications:

- **Spam — release available**: the mailbox holder may request release or discard.
- **Blocked — administrator review required**: visible identification where policy
  permits, with no user release or bulk-discard action.
- **Expired / already released / already discarded**: display current status when
  an older digest is opened; do not silently repeat its action.

Use **Release selected**, **Discard selected**, and **Discard all listed spam**.
The last action affects only the releasable spam IDs in that digest's frozen list,
not all messages in the mailbox, newly arrived quarantines, other recipients, or
administrator-only items. A confirmation page must state the count and scope.
Discard follows retention/hold policy; audit and identification can outlive bodies.

Digest links open an authenticated, recipient-scoped review page. Token scope and
expiry, current permissions, current quarantine status, and current active security
rules are checked again on action. GET requests have no release/discard effects:
mail security scanners and link previews must never trigger them. State changes use
CSRF-protected POST operations, optimistic revisions, and idempotent job IDs. A
forwarded digest must not grant another person mailbox authority.

User release only overrides the releasable spam decision; current high-risk and
mandatory policy checks still apply. An administrator override is separate and
audited. Release routes through the durable delivery queue without creating a
quarantine-release loop. Digest generation and sending also use durable jobs with
recipient isolation and retry controls; templates and tests use synthetic mailboxes
until a real deployment is explicitly configured.

## Roles and audit

Define independent permissions for rule authoring, testing, activation, quarantine metadata, quarantine content, release, remediation preview, remediation execution, connector administration, and retention management. A rule author does not automatically gain mailbox-removal rights. Scope by workspace, module instance, domain, and mailbox group. Accountants' ledger rights imply none of these permissions.

Record actor, action, old/new rule versions, scope, request/job ID, time, reason, and result for configuration, lifecycle transitions, quarantine/release, connector changes, and remediation. Keep module-origin audit events append-only and correlate centrally without rewriting the original event.

## Simple but secure: detection priorities

The product mantra is **simple but secure**. Keep one recommended protection
profile, readable match explanations, a protected-people/supplier list, and a small
number of meaningful actions. Advanced tuning belongs behind an advanced panel.
Never label authentication success as proof that a message is safe.

The highest-value additional feature beyond the requested lifecycle/quarantine
workflow is **impersonation and payment-fraud protection**. Protect selected people
and supplier domains; combine display-name/domain lookalikes, Unicode confusables,
unusual Reply-To identities, first-time relationships, and suspicious payment or
credential requests. Context and multiple signals should determine a verdict; a
payment-related keyword or unfamiliar sender alone must not cause a hard block.
A legitimate compromised supplier account can pass domain authentication. Behavioral
signals are useful but must not be represented as guaranteed account-takeover detection.

This is a prioritization judgment, not a measured efficacy claim. First ship tested
baseline spam, malware, and malicious-link controls; add impersonation detection
using the same Development/Test/Active lifecycle. Do not make malware self-releasable
or let a spam allowlist bypass mandatory checks. No claim of leading-vendor detection
parity is justified without a representative corpus, false-positive evaluation,
miss-rate analysis, resource measurements, and live deployment validation.

Leading-product reference points, reviewed October 24, 2026:

| Product | Relevant documented capability | Workglen implication |
| --- | --- | --- |
| Microsoft Defender for Office 365 | User/domain/sender impersonation settings and phishing thresholds | A protected-identity list and understandable detection evidence |
| Proofpoint | Detection across messages, identities, and compromised trusted accounts | Domain authentication alone is insufficient; preserve post-delivery remediation |
| Mimecast | Impersonation, relationship analysis, URL and attachment protection | Combine identity/fraud signals with basic content threat detection |

References: [Microsoft anti-phishing policies](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about),
[Proofpoint threat protection](https://www.proofpoint.com/us/blog/threat-protection/email-threat-protection-across-messages-identities-and-accounts),
[Mimecast BEC protection](https://www.mimecast.com/use-cases/advanced-bec-protection/).

## Delivery sequence and acceptance checks

1. Extract a module interface and remote registry; authenticate and authorize central administration against two independently hosted instances. Test cross-workspace denial, revocation, version mismatch, uncertain retries, and Admin outages.
2. Separate SMTP gateway routing and security policy from mailbox storage. Demonstrate delivery to a loopback external SMTP server without a Mail module, including recipient validation, deferred delivery, and loop prevention.
3. Add durable quarantine and release queues, quotas, retention, content-access permissions, and crash/retry tests.
4. Implement versioned Development/Test/Active rules and comparison reports. Prove Development/Test have no mail side effects, activation is atomic per instance, and partial rollout is visible.
5. Add Workglen retrospective remediation first, then separately validated Exchange Online and on-premises connectors. Test preview-only defaults, content preservation, scoped permissions, rate limits, partial failure, and recovery.

## Primary integration references checked

- [Microsoft Graph: move message](https://learn.microsoft.com/en-us/graph/api/message-move?view=graph-rest-1.0): moves a message within a mailbox; this is not by itself a security quarantine.
- [Microsoft Graph permissions](https://learn.microsoft.com/en-us/graph/permissions-reference): mailbox read/write capabilities require appropriate permissions and scoping.
- [EWS: move and copy messages](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-move-and-copy-email-messages-by-using-ews-in-exchange): a possible Exchange Server adapter building block; verify support for the installed server version before implementation.
- [Exchange Online enhanced filtering for connectors](https://learn.microsoft.com/en-us/Exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors): relevant when inbound mail passes through a third-party gateway.
