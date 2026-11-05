# Module implementation and architecture

Current documentation targets the TBD 0.1.1 development/test release. There are no current installations.

Webmail is now a separate optional module depending on Mail. It provides mailbox
login, reading, composing, replies, attachments and Sent copies on the shared mail
store. See WEBMAIL.md. Mail also supports direct delivery and DKIM; see DIRECT-MAIL.md.

Accounting is an optional implemented module, with books, ledger, Xero cutover
and banking on BYO PostgreSQL. See ACCOUNTING.md. It has independent enable state
and preserves data when disabled. Remaining suite modules below are still planned.
Shared permissions, workflow and record linking remain roadmap work.

# Workglen module architecture

Workglen is the suite. Mail, Webmail and Accounting are its implemented applications.
The administrator uses **Workglen Administration**, regardless of which
applications are enabled. The CLI is `workglen`. This release establishes the
admin shell, replicated Mail/Webmail enable controls, and independently enabled
PostgreSQL-backed Accounting; the remaining suite modules are planned.

## Navigation and ownership

| Admin area | Contents | Current development state |
|---|---|---|
| Workspace | Overview, module catalog and lifecycle controls | Yes |
| Foundation | Core services, capacity, deployment and replication status, backups | Yes; future shared services are labeled planned |
| Workglen Mail | Mailboxes, delivery queue, mail protection | Yes, shown only while Mail is enabled |
| Workglen Webmail | Separate mailbox HTTPS client with mailbox credentials | Yes; independently enabled; requires Mail |
| Contacts | Contact and organization directory | Planned |
| Calendar | Calendars, availability, bookings | Planned |
| Sites | CMS, publishing, forms | Planned |
| Sales | Leads, pipeline, opportunities, quotes | Planned |
| Projects | Projects, tasks, milestones, time | Planned |
| People | HR, employee records, leave, onboarding | Planned |
| Workglen Accounting | Books, ledger, invoices/bills, trial balance, Xero cutover, bank feeds/imports | Yes; requires BYO PostgreSQL; see ACCOUNTING.md |
| Files | Document library, versions, knowledge | Planned |
| Support | Cases, service requests, shared inbox integrations | Planned |
| Messages | Light messaging, record discussions, mentions | Planned |
| Workflows | Process library, designer, runs and approval administration | Planned |

“Mailboxes” avoids confusing email accounts with the Accounts accounting
module. Each enabled application will own its navigation and settings, with
permissions determining which entries each user sees. Planned modules have no
activation controls or running workers. They are shown only in the catalog,
not as empty application destinations in the sidebar.

As the suite grows, keep the global navigation short: workspace overview,
module switcher, shared inbox/search, and administration. The module switcher
lists only enabled modules the user may access, with pinned and recent choices.
Selecting a module opens its own contextual navigation. Do not expand every
module's pages into one long sidebar. Module administration is permissioned
separately from using a module: a salesperson should not gain cluster controls.
Shared inbox/search and unified user permissions remain planned.

## Foundation versus optional modules

Core cannot be disabled. Today it consists of the administrative credentials
and sessions, web/CLI administration, module registry, redb persistence,
replication, witnessed leadership and backup/recovery. Administrator credentials
remain node-local; mailbox logins are separate. Core is an implementation
boundary within one Rust process, not an extra microservice.

Before adding other business applications, extend Core with these services:

| Shared service | Why it belongs in the foundation |
|---|---|
| Organization, identity and permissions | One user may use Sales without a mailbox; HR and finance need narrower access than general contacts. A module being enabled never grants a person access. |
| Stable record directory and minimal party identifiers | References survive renames. Sales or Accounts can own customer records even without the optional Contacts management screens. |
| Record links, attachments and permission checks | Each module can reference permitted data and store attachments without depending on Messages or the Files management UI. |
| Activity, indexed search and notifications | Search, recent-record suggestions and approval notifications keep working with Messages disabled. Disabled-module records are omitted from ordinary search/pickers. |
| Audit events | Identity, configuration, approvals and sensitive record access need a consistent audit history. The current module revision/timestamp is not a full audit trail. |
| Durable events, jobs and workflow runtime | Modules need timers, approvals and retries without depending on the optional Workflows designer. Keep executors dormant when no eligible work exists. |
| Versioned module manifests and schema definitions | Declare required Core capabilities, schema versions, routes, jobs, permissions and lifecycle hooks. Reject unsupported or missing dependencies before activation. |

These additional shared services are **design requirements**, not implemented
features. In particular, the current implementation has no general user directory,
record ACL system, message service, workflow engine or general audit log.

## Independence and optional integrations

The target is that **any subset of the business modules can run**, including
none. Modules depend on Core capabilities, with optional links to one another:

- Sales can keep a pipeline without Mail, Calendar or Messages. Enabling Mail
  adds email actions and associations; disabling it removes those actions.
- Sites publishes content without Sales. A form-to-lead integration becomes
  available only when Sales is enabled.
- People can handle employee records and leave without Accounts. Payroll or
  posting integrations must be explicitly configured; accounting is not an HR
  dependency, and payroll itself is not included in this roadmap implementation.
- Accounts owns invoices and ledger records without Sales or Projects. Those
  modules may offer invoice creation when Accounts is enabled.
- Support can accept web/manual cases without Mail; an email ingestion adapter
  is optional.
- Messages owns conversations and record threads. It uses the Core record picker
  and must not become the record store for other applications.
- Workflows provides configurable processes and a designer. Core owns durable
  execution so built-in approvals are not removed with the designer.

Most modules declare `requires: ["core"]`; Webmail additionally requires Mail. Future releases
must version individual Core capabilities before treating it as an installable
plugin contract. This is not yet a third-party plugin loader.

A future manifest should contain an immutable ID, display name, implementation
version, schema version, required Core capabilities, optional integrations,
permission definitions, owned record types, routes, scheduled jobs, memory
budget and explicit enable/quiesce/resume hooks. Dependency validation belongs
on the server and applies to CLI and UI alike.

## Workflow and intelligent record tagging

Use `@person` and a record picker such as `#record`. Rank permitted matches by
text match, current record, recent edits/comments, related conversation records,
assignments, then recent views. Show an explanation such as “Edited today”.
Use indexed activity and bounded queries; this does not require a local AI model.
An explicit user selection creates a typed stable record link.

Check permissions during suggestions, previews and every later access. A link
never grants access. Recipients without permission see no record title, snippet,
HR/financial detail or attachment. Private messages remain private even when
linked to a shared record. Use a restricted or unavailable reference when a
record's module is disabled; retain its ID without copying sensitive content
into another module's search index.

Workflow state, conversation content, links, job progress and module settings
belong in the replicated database. Only the current primary may execute jobs.
Persist operation identifiers, retries and deduplication state. External side
effects need provider idempotency where possible: replication alone cannot
promise exactly-once email sending, payment or webhook delivery.

Disable design for future modules: show affected integrations and outstanding
approvals, quiesce work, suspend jobs targeted at the module, retain records and
links, and resume explicitly. Unrelated applications keep operating. Do not
silently approve pending work, publish drafts, drop queued jobs, or delete data.
Uninstall and permanent deletion must be separate, explicit operations.

## Implemented Mail lifecycle

In **Modules**, Mail can be enabled or disabled on the primary. The same
operations are available through the authenticated local CLI:

```bash
workglen modules /etc/workglen/node.toml
workglen module-disable /etc/workglen/node.toml mail
workglen module-enable /etc/workglen/node.toml mail
```

- State is a versioned JSON record at `core/modules/v1` in redb. It travels
  through the existing journal and snapshots, including to a replacement node,
  and is included in backups. Mail is enabled by default until an administrator changes the setting.
  Webmail is disabled by default.
  Its separate preference is retained while Mail is paused.
- Web mutations require the existing session, exact Origin and CSRF token,
  primary ownership, and an expected revision. Stale browser changes fail.
  Core, unknown IDs and planned modules cannot be toggled.
- Disabled Mail refuses SMTP/submission with temporary unavailability and IMAP
  with BYE. The listening sockets stay reserved so re-enabling needs no process
  restart. This is an application disable, not a firewall change or code unload.
- Mail account changes and mailbox commits are checked under the serialized
  write transaction, closing the disable/write race. Existing commands may
  finish; sessions stop at the next command or I/O timeout. In-flight data
  reads are not a revocation mechanism. Mail metadata inspection APIs are also
  unavailable while disabled; Core overview still reports retained counts.
- The outbound worker sleeps without starting new deliveries when disabled.
  A toggle is refused during an in-flight outbound delivery; retry after that
  bounded attempt and its queue update finish. This avoids disabling between
  an external delivery result and its durable bookkeeping. Normal SMTP crash
  retry/duplicate caveats still apply.
- Disabling does not delete accounts, passwords, messages, folders or queued
  deliveries. Re-enabling resumes eligible deliveries and mailbox access.
- Core status, module controls, backups and replication continue even with all
  optional modules disabled. No planned module consumes worker resources.

Replication remains **asynchronous**. A change made while the peer is offline
is local until catch-up; failure before replication may lose that change along
with other unreplicated writes. Check the peer's applied term/sequence before
relying on a module setting during failover. The new primary uses its replicated
state; the witness still prevents simultaneous writers. Module controls do not
change the single/dual topology or replace the explicit fenced demotion process.

## Resource budget

Keep one process, shared storage/cache, bounded worker concurrency and lazy
module initialization. Add per-module memory, queue and job metrics when those
modules exist. The 512 MiB target must be tested for a specified set of enabled
modules and workload; Mail's benchmark is not a promise for the entire future
suite. This release adds no frontend runtime or server-side JavaScript service.

## Growing beyond the compact profile

See [SCALING.md](SCALING.md) for the implementation sequence, storage decision,
worker roles, resource isolation, data ownership, blob durability and the future
admin controls. Module activation, placement and capacity are separate concerns.
The current replicated pair provides availability; it does not add write
throughput. The Capacity page shows real current configuration limits and labels
future placement and worker controls as planned.
