# Mail Security scaling and initial sizing

Updated: 2026-11-05. These are local development measurements, not production capacity claims.

## What changed

SMTP acceptance no longer enumerates all messages, receive records, jobs and blobs before each commit. Capacity is held in a transactionally maintained durable ledger. Concurrent accepts now enter one bounded writer that combines at most 16 messages arriving within 500 microseconds into one encrypted transaction and durable commit. Every caller receives success only after that shared commit; a failed commit fails the whole batch without an ambiguous automatic retry. The queue is bounded at 32 requests, and the existing SMTP session gate remains 16. The scanner claims the first eligible item through durable due/lease indexes rather than listing and sorting the receive spool. Global status uses durable state counters and an oldest-arrival index rather than walking the backlog.

Delivery jobs now use a transactionally maintained due index keyed by delivery partition, fencing term, owner, due time and job ID. Selection examines the head of each locally owned stable partition rather than listing and sorting the job backlog. Four delivery workers run by default; operators can select 1–16, bounded independently from the scanner. Status distinguishes configured/running workers and reports active work plus process-lifetime attempt, success and deferral counts.

The source records remain authoritative. Startup rebuilds all derived ledgers, counters and indexes in the same encrypted database, so a missing or damaged derived record does not silently change capacity or queue order. Every normal source-record mutation and its derived update commit in one redb transaction.

This changes the important operations from backlog-wide work to bounded/indexed work:

- admission and capacity accounting: O(1) ledger reads/updates;
- durable acceptance commits: amortized across at most 16 concurrent messages, with bounded wait, memory and backpressure;
- next eligible scanner claim: ordered-index lookup plus at most the configured active leases;
- next eligible delivery claim: ordered-index head lookup per locally owned stable partition;
- global status/state counts and oldest arrival: bounded counters/index lookup;
- scoped status: still scans records to enforce arbitrary mailbox/domain visibility;
- startup derived-state rebuild and retention garbage collection: still O(n).

## Repeatable test

The ignored Rust profile verifies durable counts and dispositions while collecting latency, throughput, storage growth and optional drain measurements. The Node wrapper runs the exact optimized release test executable under the platform resource timer, excluding Cargo compilation from peak RSS.

```sh
# counts, comma-separated aggregate thread counts, MIME bytes, drain (0/1), nodes, weights, replicas
node security/tests/ingress-scale.cjs 2000 1,2,4,8,16,32 4096 0 1 1 0
node security/tests/ingress-scale.cjs 1000,5000,10000 20 4096 0 1 1 0
node security/tests/ingress-scale.cjs 1000,5000 20 4096 1 1 1 0
node security/tests/ingress-scale.cjs 1000 20 65536 0 1 1 0
node security/tests/scanner-scale.cjs 500 1,2,4,8 65536
# Three alternating shared-versus-lane runs: 160 archive-heavy plus 40 light
cargo test --release scanner_lane_mixed_workload_profile -- --ignored --nocapture
node security/tests/ingress-scale.cjs 50000 40 4096 0 2 1,1 0
# Deliberate 60/40 MX/distributor-skew simulation
node security/tests/ingress-scale.cjs 25000 40 4096 0 2 3,2 0
# Three nodes, one non-delivering replica per accepted message
node security/tests/ingress-scale.cjs 20000 60 4096 0 3 1,1,1 1

# Host-calibrated regression guard (example floors/ceilings for this test Mac)
WORKGLEN_INGRESS_SCALE_MIN_ACCEPTS_PER_SECOND=150 \
WORKGLEN_INGRESS_SCALE_MAX_ACCEPT_P95_MS=250 \
WORKGLEN_INGRESS_SCALE_MAX_TAIL_P95_MS=250 \
WORKGLEN_INGRESS_SCALE_MAX_STATUS_MS=25 \
node security/tests/ingress-scale.cjs 10000,25000 20 4096 0 1 1 0
```

The optional thresholds make the wrapper exit unsuccessfully and report every violation. Calibrate and pin them per CI/test-host class; portable defaults would produce false confidence or false failures across filesystems and machines.

With `nodes` above one and `replicas=0`, the profile creates independent services and encrypted stores, distributes messages with smooth weighted routing, verifies aggregate capacity and the requested per-node distribution, and optionally drains the nodes concurrently. Equal weights model an even distributor; unequal weights model realistic MX/DNS/connection skew.

With `replicas=1` or `2`, every accepting node also exports its transactionally committed acceptance operation and exact MIME to the requested number of in-process encrypted replica stores. The profile preserves per-origin sequence order, verifies hash/length/version/capacity checks and proves replicas remain non-scanning and non-delivering under the origin owner's term. This exercises the storage/outbox/apply boundary only. It does not use authenticated peer networking, coordinate the SMTP `250`, replicate later state, acknowledge/catch up gaps, migrate ownership or prove failover. Replicated drain is therefore refused.

The loopback process test exercises real verified STARTTLS, SMTP protocol handling, the encrypted store, scanner process kills/replacements and downstream delivery:

```sh
node security/tests/ingress-upgrade-stress.cjs \
  target/release/workglen /private/tmp/workglen-smtp-scale 5000 16 150
```

Use a unique private test directory. The test generates its own private CA and loopback services and must not target a live domain or provider.

## Local release results

Host: local `darwin-arm64` development machine. Acceptance rows use direct callers and exact one-recipient MIME sizes. They include encrypted durable MIME, ingress and audit commits, but exclude network/TLS. All accepted IDs, capacity values and receive depth were verified.

The bounded group-commit thread sweep used 2,000 messages of 4 KiB each. The durable-commit counts come from the live status telemetry, not an estimate:

| Callers | Accept/s | p95 | Durable commits | Largest batch |
|---:|---:|---:|---:|---:|
| 1 | 201.5/s | 5.4 ms | 2,000 | 1 |
| 2 | 385.7/s | 5.4 ms | 1,000 | 2 |
| 4 | 719.7/s | 6.3 ms | 500 | 4 |
| 8 | 1,393.3/s | 6.3 ms | 250 | 8 |
| 16 | 2,550.4/s | 7.3 ms | 125 | 16 |
| 32 | 2,540.5/s | 14.4 ms | 125 | 16 |

Sixteen callers are the useful local ceiling: they produced a 12.7x gain over one caller while retaining a small p95. Thirty-two did not add throughput and doubled p95 because the batch and SMTP-session bounds are deliberately 16. Raising thread count alone is therefore not a scaling recommendation.

A 10,000-message soak at 16 callers sustained 2,160.7 accepts/s with 7.5 ms p95, 625 durable commits, 3 ms global status and 41.0 MiB peak RSS. It verified every receive record and capacity counter. This is the stronger sustained storage-path point; the 2k sweep remains useful for selecting concurrency.

The scanner concurrency matrix used 500 benign 64 KiB messages and included native MIME/policy inspection, learning lookup and encrypted queue finalization. It excluded sender-authentication DNS and downstream SMTP:

| Scanner workers | Messages/s | p95 per message | Peak active | Peak RSS |
|---:|---:|---:|---:|---:|
| 1 | 71.0/s | 10.6 ms | 1 | 46.8 MiB |
| 2 | 75.6/s | 21.0 ms | 2 | 50.0 MiB |
| 4 | 76.2/s | 38.1 ms | 4 | 49.9 MiB |
| 8 | 75.7/s | 75.9 ms | 8 | 47.0 MiB |

Two scanner workers remain the default. Four added less than one percent throughput over two, while eight slightly regressed throughput and increased p95 3.6x. This profile is dominated by serialized durable finalization; archive-heavy target-host profiles may have a different CPU/RSS curve and must be measured before raising concurrency.

The explicit mixed-lane benchmark used 160 archive-heavy messages (351,991 raw MIME bytes each, containing a 256 KiB tar/gzip payload) already queued ahead of 40 simple 4 KiB messages. It ran each configuration three times in alternating order and reports medians:

| Two-worker scheduling | Total messages/s | Light first completion | Light p50 completion | Light p95 completion | Light service p95 |
|---|---:|---:|---:|---:|---:|
| Shared oldest-first workers | 69.4/s | 2.319 s | 2.599 s | 2.854 s | 23.1 ms |
| One heavy + one light lane | 58.6/s | 19 ms | 488 ms | 915 ms | 18.9 ms |

The lane split produced a clear 3.12x light-p95 improvement and moved the first simple message ahead by about 2.30 seconds. It also reduced total mixed-workload throughput by 15.5% and increased total completion time from a 2.881-second median to 3.411 seconds. That cost is expected from the strict reservation: after the 40 light messages drain, the light worker does not take the remaining heavy work. The current result supports a latency-reserve decision, not a claim of free throughput. The next optimization should measure configurable heavy/light splits and bounded weighted assistance while proving that a newly arriving light message cannot become trapped behind an unbounded archive inspection and that heavy work cannot starve.

The following older backlog rows predate bounded group commit and remain useful as conservative backlog/RSS/storage evidence, not current peak-throughput results:

| Backlog | MIME bytes | Accept/s | p95 | Last-quarter p95 | Global status | Peak RSS | Durable disk growth |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 10,000 | 4 KiB | 203.3/s | 105 ms | 103 ms | 3 ms | 40.0 MiB | 212.0 MiB |
| 25,000 | 4 KiB | 219.3/s | 97 ms | 93 ms | 3 ms | 46.6 MiB | 486.9 MiB |
| 1,000 | 64 KiB | 183.4/s | 121 ms | 125 ms | 4 ms | 52.8 MiB | 186.5 MiB |

Independent two-node baselines on the same physical Mac use separate encrypted stores and aggregate writer counts. They do not yet include peer replication:

| Aggregate backlog | Distribution | Writers | Accept/s | p95 | Tail p95 | Combined status | Peak RSS | Aggregate disk growth |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 500 / 500 | 20 | 236.5/s | 99 ms | 141 ms | 6 ms | 22.9 MiB | 15.1 MiB |
| 1,000 | 600 / 400 | 20 | 237.2/s | 154 ms | 169 ms | 8 ms | 22.9 MiB | 26.5 MiB |
| 25,000 | 15,000 / 10,000 | 40 | 248.8/s | 283 ms | 281 ms | 9 ms | 68.2 MiB | 603.3 MiB |
| 50,000 | 25,000 / 25,000 | 40 | 229.0/s | 350 ms | 339 ms | 8 ms | 74.3 MiB | 1,025.2 MiB |
| 40,000 | 10k / 10k / 10k / 10k | 80 | 248.0/s | 1,189 ms | 1,230 ms | 17 ms | 115.4 MiB | 834.3 MiB |

The 50k run verifies exact balance and constant-time status at a doubled aggregate backlog. The four-store run verifies deterministic N-node placement but shows that 80 writers on one filesystem sharply increase tail latency without materially increasing throughput. These tests do not double throughput on one host because every store contends for the same CPU, filesystem and encrypted-storage path; separate-host results must be measured. They are pre-replication baselines for [synchronized multi-node acceptance](MAIL-SECURITY-REPLICATION.md), not HA evidence.

The current acceptance-replication slice was also exercised across three encrypted stores with one non-delivering replica per message (replication factor two). Latency includes both durable transactions:

| Original messages | Origin distribution | Stored-copy distribution | Writers | Original accepts/s | p95 | Tail p95 | Combined status | Combined peak RSS | Aggregate disk growth |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 300 | 100 / 100 / 100 | 200 / 200 / 200 | 30 | 87.9/s | 1,013 ms | 723 ms | 12 ms | 21.3 MiB | 42.1 MiB |
| 5,000 | 1,667 / 1,667 / 1,666 | 3,333 / 3,334 / 3,333 | 60 | 74.7/s | 2,433 ms | 2,405 ms | 14 ms | 80.4 MiB | 328.2 MiB |
| 20,000 | 6,667 / 6,667 / 6,666 | 13,333 / 13,334 / 13,333 | 60 | 75.6/s | 2,363 ms | 1,757 ms | 13 ms | 92.7 MiB | 1.034 GiB |

The 20k run created 40,000 durable copies. Per-node disk growth was 288.7, 388.4 and 381.3 MiB; a 1.5x measured-workload reserve is therefore 434, 583 and 572 MiB respectively (1,588 MiB aggregate). The imbalance is encrypted-store journal/compaction timing, not a record-count imbalance. Physical growth was about 54.2 KiB per original message or 27.1 KiB per stored copy at this test point. The combined RSS is from one process hosting all three test services and cannot be divided into a per-node production memory claim.

The 5k regression includes the newer cumulative acknowledgement/debt accounting. Each origin finished with its final peer acknowledgement durably recorded; all three nodes reported zero operation/byte debt, one expected outbound peer and one expected inbound origin. Per-node measured-workload reserves at 1.5x were 154, 171 and 169 MiB.

This is a conservative storage-path baseline, not synchronized-HA evidence. Synchronous per-origin application kept ordering simple but materially reduced throughput and increased p95 latency. The implemented authenticated peer batching preserves commit/order in focused and native loopback tests; its throughput, tail latency and catch-up behavior still require measurement on separate Ubuntu hosts.

Before the ledger/index change, the 5,000 × 4 KiB point managed 34.5 accepts/s with 1.21-second p95 and a 105 ms status query. After the acceptance/index change, the same point managed 205.8 accepts/s with 134 ms p95; the subsequent status-counter change reduced 10k/25k global status to 3–4 ms while keeping acceptance above 200/s. The 25k row is the final post-hardening rerun after malformed-derived-record recovery was added.

Synthetic sequential scan/finalization was also flat across tested depths: 73.2 messages/s at 1,000 and 72.1 messages/s at 5,000. This bypasses sender-authentication DNS and uses small benign text, so it is a queue/index measurement, not a malware-analysis throughput claim.

The real-process test now supports bounded connection reuse. A 5,000-message run used 16 concurrent verified-STARTTLS clients, at most 150 messages per connection and 48 total connections. With the scanner offline, durable acceptance completed in 2.663 seconds (1,877.6 messages/s). The run then killed/replaced the scanner four times, observed one deliberate capacity refusal and delivered all 5,076 accepted messages in 145.864 seconds. This is synthetic loopback evidence with small text messages, not an Internet/provider capacity claim.

## Initial resource envelope

Use these as test-host starting points, then rerun the matrix on the intended Ubuntu instance with representative MIME distributions.

The target-host acceptance/upgrade campaign is now scripted in
[MAIL-SECURITY-UBUNTU-CAMPAIGN.md](MAIL-SECURITY-UBUNTU-CAMPAIGN.md). Its default
mode is a read-only systemd/host/capacity plan; its explicitly acknowledged
execute mode measures 10k/25k/50k verified-STARTTLS acceptance while the scanner
is replaced, records systemd memory properties and waits for the queue to drain.
An optional reviewed executable makes the same run an actual package-upgrade
campaign. The source runner is not Ubuntu evidence until its generated report is
retained and reviewed from the intended disposable host.

| Intended envelope | `security-serve` | `security-scan-worker` | Host RAM | Notes |
|---|---|---|---|---|
| Up to 10k small queued messages, scan concurrency 2 | 2 vCPU / 512 MiB | 2 vCPU / 512 MiB | 2 GiB | Suitable next Ubuntu validation tier. |
| Up to 25k small queued messages, scan concurrency 2–4 | 4 vCPU / 1 GiB | 4 vCPU / 1 GiB | 4 GiB | Validate large/hostile MIME and recovery soak before use. |
| More than 25k or scan concurrency above 4 | Not yet prescribed | Not yet prescribed | Not yet prescribed | Run 50k plus representative scanner matrix first. |

The observed service RSS is far below these floors. The extra margin is deliberate: the backlog tests use small benign messages, while each scanner slot may consume configured raw/decoded/archive budgets and TLS/DNS/delivery work adds transient memory. The earlier release probe measured about 41.2 MiB total RSS for two overlapping benign 4 MiB scans; it was not a worst-case decoder measurement.

### Disk sizing

Logical MIME bytes and physical encrypted-store growth are different. The 64 KiB calibration consumed about 196 KiB of durable space per message after ingress metadata, indexes, audit and storage allocation. Until Ubuntu measurements provide a better workload-specific factor, use:

```text
receive-spool reserve >= 1.5 × backlog × (3 × p95 raw MIME bytes + 16 KiB)
```

Examples:

- 10k backlog at 64 KiB p95: about 3.0 GiB receive-spool reserve;
- 25k backlog at 64 KiB p95: about 7.4 GiB receive-spool reserve;
- add operating-system, binary, logs, backup staging and filesystem reserve separately.

The current configured logical content ceiling is at most 1 GiB. Tens of thousands of messages are therefore possible only when their aggregate unique raw MIME remains below that limit. Do not raise the ceiling until proactive native filesystem-free-space admission, disk-full testing and a larger encrypted-store campaign are complete.

### Planning rates and alerts

Do not provision to the observed peak. The loopback slim-acceptance path sustained 1,877.6 small messages/s while scanning was offline; use at most 900/s as a synthetic burst-planning ceiling on this host class. Sustainable no-growth traffic is governed by the slower scanner/delivery path: use at most 35 small messages/s per node until representative archive, DNS-authentication and target-Ubuntu results supersede the 75–76/s scanner measurements. For the current synchronous three-node acceptance-replication slice, use at most 37 original messages/s aggregate until a separate-host network test supersedes it.

Initial alerts:

- warning at 70% and critical at 85% of message, job or logical-byte capacity;
- scanner contact stale after the exposed 45-second threshold;
- warning when oldest pending exceeds 5 minutes, critical at 15 minutes;
- warning when receive depth exceeds the deployment's tested tier;
- host free-space warning/critical thresholds must be added before production readiness.

## Remaining gates

- Recover more of the 15.5% heavy-dominated mixed-workload throughput cost while retaining the measured light p95 improvement; test configurable four-plus-worker lane splits and only bounded assistance that cannot weaken the latency reserve, durable leases or heavy-lane progress.
- Repeat 10k/25k on the intended Ubuntu filesystem and service units, including restart during the backlog and derived-state rebuild timing.
- Run representative 64 KiB, 1 MiB and near-limit MIME mixes with benign, nested, malformed and compression-heavy attachments.
- Repeat the 5k persistent-session SMTP test across a real network on the target Ubuntu host and a disposable downstream service; current evidence is loopback only.
- Extend scanner concurrency testing to benign, nested, malformed and compression-heavy attachment mixes; the completed 1/2/4/8 matrix uses benign 64 KiB text.
- Add native host free-space admission and real filesystem-full/power-loss injection.
- Profile startup rebuild and retention garbage collection at 25k/50k; they remain linear maintenance operations.
- Measure the implemented authenticated peer transport, SMTP durability acknowledgement, full-log catch-up, later-state replication and ownership operations under 10k/25k/50k multi-host campaigns. The same-host native two-node fixture proves the network path and upgrade continuity, while the three-store harness proves ordered placement mechanics; neither is production failover or sizing evidence.
