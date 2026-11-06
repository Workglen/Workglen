# Mail Security synchronized acceptance and delivery ownership

Updated: 2026-11-04. This is the accepted implementation contract and current pre-production state for the next Mail Security availability increment. The source implements a two-node synchronized slice, but production HA is not yet claimed.

## Implemented pre-production slice

The source now persists stable cluster/node identity, a delivery partition and term, separate scan-owner generation, and ownership metadata on accepted ingress, finalized messages and delivery jobs. Scanner claims are restricted to their scan owner, and delivery claims recheck the current durable partition owner and term so a stale owner is fenced.

Acceptance can commit an ordered outbox operation in the same encrypted transaction as the exact MIME and ingress record. The replica apply path validates cluster/protocol, origin sequence, API/profile/coverage and rule versions, ID, content hash/length, capacity and initial ownership. It rejects gaps, corruption and conflicts; an identical replay is idempotent. Replicas are stored but remain non-scanning and non-delivering. Focused tests cover these properties and a release profile has applied 20,000 originals as 40,000 durable copies across three in-process encrypted stores.

The transport-neutral protocol engine exports only contiguous bounded batches, reports the receiver's exact next sequence, and records monotonic cumulative acknowledgements only for configured peers. Per-operation cumulative byte positions make lag available in operations and bytes without walking the backlog. Missing derived outbox-tail state is rebuilt and sequence/cumulative-byte continuity is validated on restart. Status exposes outbound acknowledgement/lag, inbound applied sequences and oldest outstanding debt; Central Admin renders this debt per registered node. The 5,000-message three-node regression completed with exact placement and zero residual debt after final acknowledgements.

The source now adds authenticated peer exchange on the existing verified HTTPS listener. TLS authenticates the receiving endpoint and a configured per-peer HMAC authenticates the exact bounded envelope; cluster/source/target identity, timestamp, 128-bit nonce, replay, protocol window and operation order are validated. Healthy SMTP acceptance waits for the configured durable-copy count before `250`. Optional degraded acceptance is explicit and bounded by operation/byte debt. A background retry loop catches up both the immutable acceptance log and a separate ordered state log covering ingress transitions, message/job state, tombstones and ownership records. Replicas remain non-scanning and non-delivering unless ownership is explicitly transferred.

Planned drain/handoff/cancellation, retained-log or checkpoint-tail resynchronization/rejoin, safe exclusion and guarded operator takeover are durable and audited. Cancellation revalidates the exact current owner/term and pending owner/term before retaining ownership and resuming acceptance. A handoff or takeover automatically advances pending scan generations and rejects stale results. Delivery is fenced by partition term, and a queued/running delivery state must reach the configured durable-copy threshold before any downstream attempt. Native host-free-space admission reserves a configurable floor before SMTP commit. Central Admin exposes node mode, eligibility, partitions/terms, both debt counters, peer health, content reconciliation, bounded compaction, high-contrast storage reserve and derived operational alerts, with separate ordinary-operation and forced-takeover permissions.

The missing production boundary remains material: the only network campaign so far is a same-host two-node native loopback fixture. Checksummed inventory checkpoints now prune bounded, fully acknowledged log prefixes and current protocol 2 has real version-1 worker and replication-service pair tests. This is not a fresh-node snapshot stream: recovery before a checkpoint requires a retained encrypted database snapshot. Multi-host Ubuntu failure-domain and packaged rolling-upgrade tests, peer loss at every SMTP/commit/ack boundary, interrupted handoff/takeover/compaction, real disk-full/power-loss, representative-content scale, Playwright execution and explicitly approved external alert delivery remain required.

## Topology and guarantee

Two Mail Security nodes publish equal-priority MX records. Both nodes accept SMTP, durably spool exact original MIME, scan assigned messages and deliver the messages they own. Every message or stable ownership partition has exactly one **delivery owner**, normally the node that accepted it. Only that owner may commit downstream delivery/remediation jobs or send the message to Exchange, Google Workspace, Workglen Mail, or another configured route. Other placement nodes hold non-delivering replicas.

Another node can take delivery ownership only through:

1. an authenticated, completed handoff initiated by the current owner; or
2. an explicit operator takeover that confirms the old owner has been fenced.

There is no automatic takeover based only on a timeout. A two-node network partition cannot distinguish a failed peer from an isolated peer safely; automatic takeover would risk two delivery owners for the same partition and duplicate downstream delivery.

## Acceptance and synchronization

Every accepted message has a globally unique ID containing its accepting node identity, an immutable content hash, an origin sequence, the exact envelope/peer metadata, the pinned rule/API/profile/coverage versions, an ownership partition and a delivery-owner term.

The SMTP path is:

1. Validate protocol, recipients, message size and logical/host capacity.
2. Commit the exact MIME and an immutable local acceptance record before any peer call.
3. When the peer is healthy, send the acceptance operation and MIME by verified TLS using bounded frames and an authenticated cluster identity.
4. The peer verifies identity, cluster, term, ID, hash, length, versions and capacity; it commits idempotently and acknowledges only after durable commit.
5. The accepting node returns `250` after the configured durability condition is met.

Normal healthy mode requires both durable copies before `250`. A deliberately enabled degraded-acceptance mode may return `250` after the local durable commit while the peer is unavailable during maintenance. Degraded mode must be visible, audited, capacity-bounded and alerting; it creates replication debt and temporarily loses peer-failure tolerance. It never silently becomes the default.

The accepting node is initially the delivery owner and retains the local authoritative copy. Placement peers durably acknowledge replicas before the healthy-mode `250`. Replays are idempotent by origin node, sequence, message ID and content hash; an ID/hash disagreement is corruption and fails closed.

## Replicated state

Replication is an ordered, transactionally committed outbox—not ad hoc database-file copying while a writer is active. Each authoritative transaction that affects failover behavior commits its replication operation in the same encrypted transaction:

- accepted MIME/envelope and import ownership;
- scan/quarantine disposition and completeness evidence;
- queued/running/succeeded/failed/uncertain delivery state;
- holds, releases, discards and retention tombstones;
- active immutable rule/config/profile versions needed to process queued content;
- placement, owner term, handoff and reconciliation records.

Strict-mode acceptances that miss the acknowledgement deadline are marked non-runnable before SMTP returns `451`. If the peer acknowledgement arrives later, a durable cleanup queue removes the local reservation and replicates an ingress tombstone; immutable acceptance receipts keep later full-log replay idempotent without resurrecting the message.

The peer applies operations in origin-sequence order, durably records its applied sequence, and returns cumulative acknowledgements. Missing ranges are requested explicitly. Snapshot/bootstrap is separately bounded and checksummed, then followed by log catch-up. Tombstones remain until every configured peer has acknowledged them and the retention window has elapsed.

Replica application must not create a second runnable delivery copy. Each message has one durable scan owner and lease generation, normally assigned to its accepting node. Either node may scan work it owns; an expired lease may be reassigned explicitly. A scan result is accepted only when its MIME hash, immutable rule pack, API/profile/coverage versions, cancellation context, policy/model revision and current lease generation all match. Duplicate, stale or conflicting results fail closed. Only the current delivery owner term may turn the accepted result into a downstream job, and it rechecks mandatory delivery policy immediately before sending.

## Planned ownership handoff

A normal upgrade transfers the upgrading node's owned partition explicitly:

1. Verify peer identity, protocol/schema compatibility, configuration/rule coverage, capacity and zero unrecoverable replication gaps.
2. Keep both SMTP listeners and scanner pools running; stop creating new downstream delivery/remediation claims for the partition being transferred.
3. Let bounded in-flight delivery work finish. Scans with synchronized policy/model revisions may continue across the handoff. Mark ambiguous external delivery attempts `uncertain`; never replay them automatically.
4. Flush the current owner's replication outbox until applied sequences and content hashes agree.
5. Persist a partition handoff for `term + 1`. The receiving replica prepares but does not deliver that partition yet.
6. The old owner durably disables downstream delivery/remediation claims for that partition and sends the authenticated activation record. Its eligible scanners remain available.
7. The new owner durably activates the new term, starts delivery claims for the partition and acknowledges. The old owner remains an accepting node, scanner and replica.

This permits a brief scan/delivery pause while SMTP acceptance continues. The transition must be restart-safe at every step; recovery resumes or safely aborts the handoff based on durable phase records.

## Operator takeover

Operator takeover is intentionally stronger than an ordinary UI action. It requires the partition, current expected owner term, a stable request ID, the target node identity, explicit confirmation that the former owner service is stopped or network-fenced, and a duplicate-delivery risk acknowledgement when any delivery is `running` or replication is incomplete.

Takeover creates a higher durable owner term and audits replication gaps. Items whose last external delivery outcome is ambiguous remain `uncertain`. When the old node returns, observing a higher term prevents it from delivering the transferred partition. It may rejoin the scanner pool only after policy/model reconciliation and fresh scan leases. A stale term can accept new locally owned messages under the defined policy, but it cannot deliver, discard, release or mutate a partition transferred under a higher term.

## Capacity and observability

Each node is sized for its own MX/delivery share plus configured skew and takeover headroom. Capacity includes local authoritative records, replicas, unacknowledged outbound items, inbound staging, tombstones and snapshot workspace. A 50/50 DNS intention is not a capacity guarantee.

Status and alerts must expose:

- node ID, owned partitions, per-partition durable term and handoff phase;
- peer identity and last authenticated contact;
- local/outbound/applied sequence and replication lag in operations/bytes/time;
- local-only accepted count and oldest replication debt;
- inbound staging depth and oldest unimported item;
- content/hash reconciliation failures;
- delivery-owner fencing and per-node scanner eligibility/lease state;
- degraded-acceptance state and duration;
- per-node receive rate, backlog, disk reserve and downstream queue age.

The gateway refuses new mail transiently when accepting it would exceed local capacity, peer-negotiated limits in required-replication mode, or configured degraded-debt limits.

## Security and compatibility

- Use verified TLS with pinned cluster/node identities plus an owner-only rotating authentication secret; never expose replication on the public SMTP listener.
- Bound connections, frames, operations, snapshots, outstanding bytes, retries and processing deadlines.
- Replicated bytes remain encrypted at rest under each node's own storage key. Keys are not copied through the replication stream.
- Redact credentials and unrestricted evidence. Replication logs contain hashes/metadata, not duplicate audit plaintext beyond what the receiving encrypted store requires.
- Pin a versioned replication API/schema. Rolling upgrades require an explicit N/N-1 compatibility window; incompatible nodes continue SMTP only under the reviewed degraded policy and cannot receive delivery ownership.
- Configuration/rules that affect queued processing are immutable and content-addressed. A node cannot receive an ownership partition without every referenced version.

## Central Admin cluster operations

Central Admin identifies a Mail Security cluster and its explicitly provisioned members. Discovery is authenticated configuration/registration, never unauthenticated network broadcast. Node identity is stable across restarts and includes cluster ID, node ID, expected certificate identity and configured failure-domain labels.

The cluster overview exposes:

- node identity, hostname, endpoint, software build and replication/API/schema versions;
- authenticated last contact and high-contrast healthy, degraded, draining, stale, incompatible or fenced state;
- SMTP acceptance, scanner eligibility and delivery-ownership eligibility separately;
- owned delivery partitions/terms and pending handoffs;
- peer/replica reachability, local/outbound/applied sequence, lag in operations/bytes/time, missing ranges and oldest replication debt;
- receive, scan, quarantine and delivery depths/ages plus uncertain external operations;
- logical capacity, host free space once implemented, snapshot/rebalance workspace and tested sizing tier;
- active immutable rule, profile, coverage, policy/model and configuration revisions.

Basic cluster operations are explicit, asynchronous, idempotent and audited:

- run health/readiness and content-hash reconciliation checks;
- drain/resume SMTP acceptance independently from delivery ownership;
- drain a node's delivery claims while leaving its scanner pool eligible;
- exclude/rejoin a node from new placement after replication safety checks;
- request bounded resynchronization, gap repair or snapshot/bootstrap;
- initiate/cancel a planned partition ownership handoff;
- perform guarded operator takeover only after fencing confirmation and risk acknowledgement.

Read-only cluster health, ordinary node operations and high-risk takeover use separate permissions. Every mutation requires an expected cluster/config revision and stable request ID. The UI never exposes replication secrets or unrestricted message content. A stale Admin view cannot authorize takeover; the target node revalidates term, fencing confirmation, replication state and permissions at execution time. Local recovery CLI remains available if Central Admin is unavailable, with the same durable checks and audit events.

The current Admin implementation enumerates every registered gateway remote and shows stable node identity, mode, acceptance/scanner/delivery eligibility, host free-space reserve, owned partitions/terms, peer contact, acceptance/state replication debt and derived warning/critical conditions. Authorized administrators can pause/resume SMTP, start or cancel a planned drain, complete a replicated handoff, reset one peer for retained-log or checkpoint-tail resync, rejoin only after both debts reach zero, reconcile referenced content hashes, exclude a safely drained node and compact fully acknowledged log prefixes in bounded transactions. Forced takeover remains a separate high-risk permission and dialog requiring exact current owner/term, confirmation that the old owner is stopped or network-fenced, an incomplete-replication/duplicate-delivery acknowledgement and a typed phrase.

## Required tests before activation

- Balanced and 60/40 acceptance, 25k/50k aggregate backlogs, representative MIME sizes and concurrent drain.
- Acceptance crash before/after local commit, peer send, peer commit, acknowledgement and SMTP `250`.
- Duplicate/reordered/missing/corrupt operations and ID/hash conflicts.
- Owner and replica restarts, peer outage, bounded replication debt, reconnection and full reconciliation.
- Planned ownership handoff interruption at every durable phase; prove never more than one delivery owner per message/partition while both scanner pools remain usable.
- Scan assignment, lease expiry/reassignment, stale/conflicting results and policy/model revision mismatch across nodes.
- Operator takeover with the old owner fenced; old-node return with a stale term.
- Deliberate partition without fencing; prove a replica never starts delivery for another owner's partition automatically.
- Downstream acknowledgement loss before state replication; preserve `uncertain` and require explicit reconciliation.
- Disk-full, storage corruption, snapshot interruption, power-loss simulation and retention/tombstone safety.
- Measure healthy replicated acceptance, degraded local acceptance, catch-up, handoff time, peak RSS/CPU/disk/network and status latency on the intended Debian hosts.

## Delivery order

1. **Foundation implemented:** durable delivery partition/owner terms, scan-assignment metadata, automatic planned-handoff/takeover scan-generation reassignment and worker/delivery fencing with restart and stale-result tests.
2. **Acceptance path implemented:** immutable acceptance staging, transactionally committed outbox, authenticated network transport, idempotent peer apply and peer durability before healthy-mode SMTP success.
3. **State replication implemented:** a separate ordered log covers processing/message/job/tombstone/ownership state; delivery waits for durable state replication before contacting the downstream system.
4. **Ownership operations implemented:** planned drain/handoff, term fencing, explicit resync/rejoin and separately guarded operator takeover, with Admin permissions and audit.
5. **Bootstrap/compatibility foundation implemented:** retained-log and checkpoint-tail replay are bounded and idempotent, acceptance pauses during resync, protocol min/max fields negotiate real current/legacy pairs, and checksummed content-inventory frontiers prune only fully acknowledged prefixes in bounded transactions. A fresh-node encrypted snapshot stream and packaged multi-host rolling pair remain.
6. **Hardening partially complete:** native free-space admission and a full same-host two-node network fixture pass. Multi-host Ubuntu fault/scale, disk-full/power-loss, interrupted transition and alert campaigns remain.

Do not expose a production-looking enable switch until all six increments are integrated and the failover tests pass. Independent dual-MX acceptance testing remains useful as the performance baseline against which replication overhead is measured.

## Growth beyond two nodes

The two-node protocol must not assume that every item is copied to every future node. The scalable form separates the control plane from data placement:

- Every receiver may accept SMTP and scan assigned work.
- A versioned rendezvous-hash placement function maps each message ID to a small replica set. Start with replication factor two; a larger deployment may choose three copies with a two-copy durable acknowledgement policy.
- Placement includes failure-domain labels so replicas do not intentionally land on the same host, disk or availability zone.
- Each origin keeps an ordered sequence. Replica acknowledgements and gaps are tracked per origin and placement generation, avoiding a single global write lock.
- Adding/removing a node creates a new placement generation. Existing messages retain their old placement until a bounded, checksummed rebalance copies and acknowledges them; new messages use the new generation. Garbage collection waits for both placement generations to be safe.
- Each delivery owner consumes authoritative, replicated dispositions for its partitions. It does not need every message body locally before scan, but the body must be retrievable from the durable replica set before downstream delivery.
- Scan ownership is assigned within the replica set with a lease generation. Another eligible replica can rescan after lease expiry; stale or conflicting results cannot become authoritative.

Do not build an all-to-all mesh: connection count, duplicate storage and resynchronization traffic would grow poorly. Nodes should maintain bounded peer pools and transfer only the partitions they own.

Delivery ownership is partitioned from the start, initially by accepting/origin node. Every node can therefore accept, scan and deliver its own messages. For rebalancing or larger deployments, use a stable boundary such as origin, tenant, domain or route; each partition has one fenced delivery-owner term, and no message can belong to two active owners.

Two nodes can use the explicit ownership-handoff/operator-fencing model above. Reliable automatic takeover should use an odd control quorum (for example three small voters) rather than inferring ownership from peer timeouts. Data replicas and control voters are separate roles; a voter need not store MIME.

Additional N-node tests must cover placement determinism, weighted/skewed ingress, node addition/removal, rebalance interruption, replica-factor loss, quorum loss, stale placement generations, simultaneous scan-node loss and partition ownership handoff while rebalancing.
