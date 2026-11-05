# Mail Security two-host HA activation campaign

This is the controlled activation sequence for the pre-production synchronized
two-node source slice. It is not authorization to publish production MX records.
Use two disposable Ubuntu hosts in separate failure domains, a reserved test
mail domain, a private management/replication network and a disposable verified
TLS downstream sink.

## Preconditions

- Both nodes run the exact reviewed build unless the phase is the explicit
  N/N-1 experiment. Each has its own durable node ID, storage key, private data
  directory and host free-space reserve; both use the same cluster/workspace ID.
- Each node configures the other node's canonical HTTPS origin, expected node
  ID, CA trust and owner-only replication key. Use verified TLS/HMAC transport;
  never expose replication through the public SMTP listener.
- Healthy mode uses two durable copies, degraded acceptance is disabled, and
  each host has capacity for its intended MX share, replicas, measured skew and
  takeover headroom. Equal MX preference is not a 50/50 guarantee.
- Both admin origins are private and reachable by the campaign operator. Store
  each test administrator password in a separate root-owned mode-0600 file.
- The target downstream system is a test sink. Do not point this campaign at
  Exchange, Google Workspace or production Workglen Mail.

## Read-only gate

Run [the Ubuntu campaign](MAIL-SECURITY-UBUNTU-CAMPAIGN.md) on node A with the
peer admin options:

```sh
python3 tools/gateway-ubuntu-campaign.py \
  --binary /usr/local/bin/workglen \
  --config /etc/workglen-security/security.json \
  --ca-file /etc/workglen-security/test-ca.pem \
  --admin-url https://node-a.test:8445 \
  --admin-password-file /root/node-a-admin-password \
  --peer-admin-url https://node-b.test:8445 \
  --peer-admin-password-file /root/node-b-admin-password \
  --recipient owner@example.test \
  --smtp-host node-a.test --smtp-port 25 \
  --output /var/tmp/workglen-ha-plan-a
```

`ha_readiness.passed` requires distinct durable node IDs, one cluster ID,
overlapping protocol windows, reciprocal peer membership, authenticated peer-log
topology, fresh successful contact in both directions and zero acceptance/state
replication debt on both nodes. A plan records violations without changing a
service. Execute mode refuses to start while any violation remains.

Repeat the plan from node B with B as the SMTP target. Preserve both preflight
files and systemd unit properties with the campaign evidence.

## Fault and transition order

Use synthetic unique message IDs and reconcile accepted, replica, scan,
quarantine, job and sink counts after every phase. Stop at the first unexplained
count, content hash, ownership term or alert difference.

1. Send balanced and 60/40 traffic to both SMTP listeners. Prove every `250`
   has two durable copies, exactly one scan owner/generation and exactly one
   stable delivery owner/term. Prove only the origin owner delivers.
2. Stop the scanner on A while both receivers remain enabled. Send to A and B,
   replace A's scanner, and prove both queues drain with zero replication debt.
   Repeat on B. The guarded runner automates the 10k/25k/50k form of this phase.
3. Interrupt peer transport at local commit, peer send, peer commit and
   acknowledgement boundaries. In strict mode, unacknowledged mail must receive
   a transient SMTP response and remain non-runnable; late acknowledgement must
   converge through the durable tombstone path.
4. Start a planned drain on A, cancel it, and prove the exact owner/current term
   and pending owner/term are revalidated before A resumes acceptance. Repeat a
   completed A-to-B handoff and verify the higher term fences A from delivery.
   Interrupt both cancellation and completion before/after every durable state.
5. Stop or network-fence A's gateway. MX traffic to B must continue. B must not
   automatically deliver A's partition. Perform an operator takeover only after
   the former owner is demonstrably fenced; keep ambiguous external attempts
   `uncertain`. Restart A and prove the higher term fences it until resync/rejoin.
6. Reset each peer for complete retained-log resynchronization. Acceptance on the
   resynchronizing node stays paused until both debts reach zero and explicit
   rejoin succeeds. Measure catch-up time, network bytes, peak memory and disk.
7. Rehearse the actual package upgrade on one node while the other accepts and
   remains synchronized. Current protocol 1 has no real N/N-1 implementation;
   an N/N-1 activation remains a blocker rather than an inferred pass.
8. On disposable volume snapshots, separately test physical filesystem
   exhaustion, abrupt host power loss, restart index/capacity rebuild, retention
   collection and encrypted-store recovery. The normal campaign does not perform
   destructive fault injection.

## Activation exit criteria

Do not publish production MX records until both directions pass the full matrix
with representative small, 1 MiB, near-limit, malformed, nested and
compression-heavy MIME; no duplicate or missing sink delivery; no unexplained
`uncertain` work; zero final acceptance/state debt; fresh bidirectional peer
health; bounded p95/p99/status latency; and retained evidence for systemd,
resource, restart and alert behavior.

Compact snapshots/log pruning, real N/N-1 compatibility, automatic scan-lease
reassignment, content-hash reconciliation, external alert delivery and the
physical fault campaign remain explicit production blockers. Cancellation and
live synchronization health improve safe operations but do not remove them.
