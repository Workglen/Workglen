# Implementation update — 0.5

Accounting now uses a shared BYO PostgreSQL endpoint. Each node has a bounded
connection pool (default 2, maximum 8). Its state is not replicated through redb.
Book writes serialize on the book row; horizontal write scaling and worker pools
remain future work. Current feed, statement and Xero batch limits are in ACCOUNTING.md.

# Workglen growth architecture

## Decision and current boundary

Keep a modular application that can start in one process, with explicit module
ownership, transactional storage boundaries, and durable work queues. Separate
**feature activation**, **runtime placement**, and **capacity**. An organization
should not have to enable a second copy of Sales just to run more Sales workers.

Workglen 0.5 implements compact Mail with one/two-node availability, an optional
slim Webmail client, and Accounting using shared BYO PostgreSQL. Larger deployments
below are a design, not a claim that the
current binary is a distributed business suite. The two-node mode has one active
writer and a standby: it improves availability, not write throughput. A standby
is not an extra independent database writer.

Establish these boundaries before implementing the next business modules.
Future data-format changes require explicit schema/version handling.

## Deployment stages

| Stage | Placement | Capacity and availability | Status |
|---|---|---|---|
| Compact | One Rust process with enabled modules and embedded redb | Start small; bounded connections, caches and background work; one durable copy | Mail implemented |
| Resilient | Two data nodes plus an independent witness | One active writer; asynchronous replica and automatic failover; same database workload budget | Mail implemented |
| Growing | Multiple web/API instances and dedicated worker pools; database service and shared blob storage | Scale requests and expensive jobs separately; replicate the canonical database and blobs | Planned |
| Large | Multiple data groups, each with its own ownership and HA; separate search/reporting workers | Partition by organization first, then measured hot domains such as mailboxes if needed | Planned |

Do not assign invented account-count thresholds to these stages. Mail volume,
attachments, indexing, workflows, reports and concurrent sessions can dominate
user count. Promote a deployment when measured latency, queue age, storage I/O,
memory or recovery-time objectives exceed the tested budget.

## Module boundaries to establish now

1. Give each module an immutable ID and owned record types, permission names,
   jobs, routes, data namespace/schema, and a versioned manifest.
2. Use module/domain repository interfaces rather than exposing raw redb tables
   to business logic. Keep explicit transaction operations such as
   `post_invoice_and_lines` or `accept_message_and_enqueue`, including their
   consistency requirements. A generic get/set interface is not sufficient for
   relational queries, indexes or transactional business rules.
3. Prohibit one module from directly editing another module's storage. Use a
   typed internal command for immediate work and a durable event for deferred
   integration. Start these calls in-process; preserve a boundary that can later
   move across a service connection without changing record identity.
4. Include organization scope in business keys and permission decisions from
   the first suite schema, even if the first UI manages only one organization.
   Do not claim multi-tenant isolation until it is tested end to end.
5. Keep invoice/ledger invariants inside Accounts transactions, mailbox/UID
   invariants inside the Mail owner, and approval transitions inside their
   authoritative workflow transactions. Cross-module flows use explicit
   pending/completed/failed states and idempotency, not assumed distributed ACID.
6. Introduce a module supervisor with lifecycle hooks, bounded worker pools,
   health, readiness and resource budgets. Register jobs centrally so turning
   off a module stops scheduling its work across every eligible node.

Current Mail handlers still reach the shared Store directly, and App serializes
commits with a global write mutex. Refactoring these is required before claiming
independent module scaling. The new module catalog is a first administrative
boundary; it is not this complete runtime framework.

## Storage recommendation

Retain **redb for compact Mail**. It meets the embedded/no-SQLite requirement and
keeps a small install operationally simple. Do not put its database file on a
shared filesystem and let multiple application nodes open it for writing. Its
current logical replication should continue to have one authoritative writer
per data group.

Accounting now uses **BYO PostgreSQL**. For the broader suite, evaluate it for the
canonical business data: customer relationships, invoices, accounting entries,
HR records and reporting benefit from explicit relational schemas and
transactions. Accounting is implemented; the other business modules and their
capacity characteristics still require implementation and benchmarking.
SQLite remains excluded.

Extend the Accounting storage contract before implementing People. Avoid
promising that every module will support both redb and PostgreSQL: two backends
mean two query/index implementations, schema definitions, and invariant test suites.
A reasonable product boundary is a compact embedded Mail deployment and a
larger suite deployment with PostgreSQL. Evaluate a compact whole-suite backend
separately against an explicit feature set and memory budget.

With PostgreSQL, multiple application instances can issue transactions to the
same database primary; Workglen's current global single-primary application gate
must not accidentally serialize all of those instances. Leadership remains
necessary for singleton scheduling and data ownership, while jobs can be leased
by multiple workers. PostgreSQL standbys can serve suitable read-only work, but
replication lag makes them unsuitable for unchecked permission decisions,
immediate read-after-write views or duplicate-job arbitration. Streaming
replication is asynchronous by default; stronger acknowledgment policies trade
availability/latency for durability. [1][2]

Increasing application replicas does not scale database writes without limit.
Add indexes and eliminate scans, then tune/size the primary, isolate reporting,
and only partition data when measurements justify the operational complexity.
Use one canonical transaction store per data group, not unrelated authoritative
databases for every module plus a web of ad hoc cross-database joins.

## Background execution and noisy-neighbor control

Start with durable queues in the transaction store. Commit each business change
and its outbox event in the **same transaction**. Job handlers claim bounded
batches using atomic leases, record lease generation and expiry, checkpoint
progress, and require the current generation when committing results. Retried
jobs use stable operation IDs. A crash between an external side effect and a
commit still requires idempotency/reconciliation; do not promise exactly-once
external actions.

PostgreSQL's row locking with `SKIP LOCKED` is a possible queue-claim primitive,
not a general consistent read mechanism. Keep the claim transaction short and
persist a recoverable lease rather than holding a database transaction open
through a long network call. [3]

Separate resource classes even when they initially share a process:

- Interactive requests and mail protocol sessions.
- Mail delivery/authentication and other latency-sensitive work.
- Workflow timers, webhooks and integration jobs.
- Indexing, imports, report generation and document processing.

Apply global and per-module concurrency, memory/cache budgets, maximum queue
size/age, request deadlines, per-organization quotas and fair scheduling. Pause
or reject excess work explicitly; never create an unbounded thread, task, cache
or in-memory queue per record. Large imports must not consume the slots needed
to accept mail or open the admin console.

Move the heavy classes into separate worker processes when needed. In-process
budgets cannot provide hard isolation against a module bug or allocation spike;
process/cgroup limits are the next boundary. Do not require containers,
Kubernetes, an external broker, or a search cluster for the compact profile.

## Large bodies, files and search

The current mail implementation commits bodies and metadata together in redb.
A future blob store must preserve equivalent durability at acceptance time:
write an immutable object with verified checksum, receive the configured
replicated durability acknowledgment, then commit its metadata/reference.
A crash may leave an unreferenced object; garbage collection must tolerate that
and never delete an object referenced by a live transaction or retained backup.
Do not acknowledge SMTP acceptance with a reference to a blob stored only on a
failed or inaccessible node.

Replicate blobs and metadata under a coordinated backup/restore policy. A
replicated metadata database does not make an external attachment store durable.
Support bounded streaming uploads/downloads and separate storage quotas.

Indexing is asynchronous and rebuildable. Primary records and ACLs remain
authoritative. Search suggestions and snippets must respect current permissions
before disclosure, including after access revocation or module disable; do not
trust a stale search index alone. Export/report jobs need bounded snapshots and
consistent authorization too.

## Administration as deployments grow

Keep a single Workglen Administration experience, with these future controls:

| Area | What an administrator needs |
|---|---|
| Modules | Enabled state per organization; implementation/schema version; dependencies; affected integrations; disable/drain progress |
| Capacity | Per-module activity, latency, queues, oldest job, failures, retries, storage and estimated resource usage |
| Placement | Eligible node roles and worker pools; desired versus running worker counts; per-module concurrency and limits |
| Nodes & data | Readiness, ownership/leadership, applied config revision, replication delay, blob availability, recovery status |
| Operations | Drain a worker, pause a job class, restart a failed job, review audit history, run a restore verification |

Use a module switcher and contextual module navigation as the catalog grows,
with global search/inbox and administrative settings kept in a stable location.
Display only enabled, authorized modules; keep record links stable across UI
reorganization. Scope organization-level module choices separately from
operator-only node placement, replication and capacity controls.

Module enablement is not a per-node checkbox. Desired state is persisted in the
canonical database; healthy nodes reconcile to a versioned configuration.
Disabling stops new scheduling, handles in-flight work according to declared
lifecycle rules, then reports when all participating workers have observed the
change. Offline nodes must reconcile before taking work. Drain and purge are
separate operations.

Distributed web sessions must use a deliberately chosen shared or verifiable
session scheme with revocation support; current node-local in-memory sessions
are sufficient only for the present node admin UI. Keep a local recovery CLI
available when the shared control interface is unreachable, with the same
ownership and fencing checks for writes.

The 0.5 Capacity page exposes existing read-only limits and the growth direction;
it does not offer worker placement or automatic scaling controls yet.

## First bottlenecks in the current code

- Dashboard/account inspection scans mailbox metadata; add transaction-maintained
  counters, indexes, cursor pagination and server-side filters before large
  account or record counts. Do not simply poll the full dataset more slowly.
- Mail sessions use a thread per connection and small hard caps. Introduce
  bounded multiplexed I/O and isolate blocking password/storage work before
  increasing connection limits substantially.
- A global commit mutex and one Store couple module write throughput. Introduce
  repository boundaries and measure transaction latency before splitting data.
- Snapshots, backups, imports and search rebuilds need resource budgets, resumable
  progress and throttling so they do not starve interactive traffic.
- The current pair replicates one database to one peer. Adding a third writable
  node, a consensus group, or shard placement is new implementation work, not a
  config-only extension of the witness protocol.

## Implementation order and evidence

1. Establish organization/record/permission contracts, domain repositories and
   indexed/paginated access before building the next module.
2. Implement the durable job/outbox service and module supervisor; exercise
   duplicate delivery, crashes, disable/drain and revocation behavior.
3. Prototype suite storage with representative Sales/Accounts invariants and
   large datasets. Choose the backend/profile before those modules depend on it.
4. Add worker roles, placement and capacity telemetry. Verify useful throughput
   gains from extra workers without degrading interactive latency.
5. Add blob/search separation when storage and indexing measurements justify it.
6. Introduce organization/data-group partitioning only after the previous stages
   reach measured limits; give every group independent recovery and HA tests.

Define benchmark profiles by enabled modules, active sessions, records, message
sizes, jobs per second, and I/O. Measure p95/p99 interactive latency, queue age,
throughput, process and whole-node memory, replication gap, failover time and
restore time. Test one noisy module beside Mail, slow storage, stale leases,
worker crashes, a disconnected peer and cold recovery. The current ~512 MiB
objective applies to the tested small Mail workload, not a future full suite or
an unlimited number of accounts.

## Primary references

The backend recommendation and the architecture above are design judgments.
The PostgreSQL behaviors cited above were checked against its official docs:

1. [Streaming and synchronous replication](https://www.postgresql.org/docs/current/warm-standby.html)
2. [Hot standby and its read-only/eventual-consistency behavior](https://www.postgresql.org/docs/current/hot-standby.html)
3. [SELECT locking and SKIP LOCKED](https://www.postgresql.org/docs/current/sql-select.html)
