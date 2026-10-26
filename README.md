# Workglen 0.8 · native Mail Security

**Start here:** [CLI installer](START-HERE.md), [Mac Admin + local PostgreSQL + Lightsail gateway](MAC-ADMIN-LIGHTSAIL.md), [current architecture](ARCHITECTURE.md), and [all included documentation](DOCUMENTATION.md).

Mail Security now runs inside the Workglen Rust executable with encrypted embedded redb storage, supplied or generated storage keys, local attachment/archive inspection and spam detection. It retains independently hosted gateways, central administration, scoped access, rule testing/activation, quarantine, digests and mailbox remediation. Start with [security/README.md](security/README.md) for installation, native redb storage and coverage limits, and [the dependency rule](security/DEPENDENCY-POLICY.md) for the self-contained service contract.

All modules target fresh installations: there are no active installs to upgrade. Workglen-to-Workglen conversion paths are omitted; backup/restore, replication and external accounting import/export remain in scope.

No additional third-party Cargo dependency was added. This is a development release; native policy scanning is not a claim of comprehensive malware detection or live Microsoft-provider certification. RAR and 7z remain [backlog work](MAIL-SECURITY-BACKLOG.md).

The earlier 0.6 posting-correction behavior remains included. The following application overview describes the included modules.

# Workglen 0.6 — posting corrections

This update adds ordinary posting edits/voids/deletes, controlled period reopening,
named administration roles, and retained correction history. See [ACCOUNTING.md](ACCOUNTING.md)
for external-system imports and operation details. [MODULE-HOSTING-AND-MAIL-SECURITY.md](MODULE-HOSTING-AND-MAIL-SECURITY.md)
records the next-phase remote hosting, standalone gateway, quarantine, rule lifecycle,
and mailbox remediation requirements; the Mail Security implementation now supports those remote capabilities.

The remaining material below describes the existing Mail/Webmail baseline and its limitations.

# Workglen 0.5.0 — Mail, Webmail and Accounting

Current builds use Pratique for TLS and application cryptography; OpenSSL headers, libraries and CLI are not required. See [INSTALL.md](INSTALL.md).

This release adds direct MX email delivery, local DKIM signing and an optional slim
Webmail module. Start with [DIRECT-MAIL.md](DIRECT-MAIL.md) for outbound DNS, keys
and network setup, and [WEBMAIL.md](WEBMAIL.md) for mailbox access in a browser.
Existing implicit-TLS relay configurations remain supported.

Optional PostgreSQL-backed Accounting, Xero cutover, SimpleFIN bank feeds and
statement imports remain available. See [ACCOUNTING.md](ACCOUNTING.md) for scope,
setup and the optional PlanetScale Postgres deployment notes. Plaid is not required.
Mail backups cover redb; Accounting backups belong with your PostgreSQL provider.

## Workglen Mail — Linux mail server in Rust

Workglen Mail is an experimental implementation for a small domain: Pratique TLS,
SPF/DKIM/DMARC filtering, IMAP mailboxes, authenticated SMTP submission, an
outbound delivery queue, separate Webmail and administration UIs, and redb storage.
Start with one mail node, scale to two replicated mail nodes, or explicitly
convert back to a single node.
**SQLite and POP3 are not used.**

This is a runnable development release, not a production-certified mail service.
Pratique's pinned upstream revision explicitly calls its server TLS and
cryptography unaudited and not ready for production. The IMAP implementation
covers common mailbox operations but has not been tested with a real Outlook
installation or passed a complete IMAP conformance suite. See
[limitations](#limitations) and [VALIDATION.md](VALIDATION.md) before deployment.

## What is implemented

| Area | Behavior |
|---|---|
| Inbound SMTP | Port 25, EHLO/HELO, STARTTLS, MAIL/RCPT/DATA, SIZE, 8BITMIME, dot unstuffing, recipient validation, relay refusal, message and connection limits |
| Mail security | SPF and DKIM verification, aligned DMARC policy evaluation, reject/quarantine, temporary DNS failures deferred with 451, configurable sender/domain/IP deny rules, optional independent strict SPF/DKIM policies |
| Mailbox access | TLS IMAP, LOGIN/AUTHENTICATE PLAIN, folder listing/subscriptions, CREATE/DELETE/RENAME, SELECT/EXAMINE/STATUS, UID FETCH/STORE/SEARCH, APPEND, COPY/MOVE, EXPUNGE, IDLE, UIDPLUS |
| Message data | Message previews, MIME body structure, attachments by part, partial fetches, standard message flags, per-user quotas |
| Submission | Implicit TLS on 465, AUTH PLAIN/LOGIN, authenticated account must match envelope sender and From header |
| Delivery | Persistent per-recipient queue; direct MX routing with verified STARTTLS or implicit-TLS relay; RSA-SHA256 DKIM signing; retries, failed queue retention and local failure notices |
| Webmail | Optional mailbox HTTPS client; compose/reply, Unicode MIME, attachments, Sent copies, folders, read/unread, stars and reversible Trash; no frontend runtime service |
| Storage | redb ACID transactions; one durable commit for message bodies, mailbox metadata and replication journal |
| Replication | Ordered logical transactions; snapshot and catch-up for a replacement; all accounts, folders, flags, messages, queue and module state included |
| Availability | Standalone primary without a witness; optional two-node mode with automatic witness-based failover and local acceptance while the peer is down |
| Administration | Embedded HTTPS web UI and TLS/token-protected loopback CLI; accounts, password resets, status, replication telemetry, policy inspection, queue inspection and consistent backups; offline CLI for topology changes and recovery export |

## Workglen branding and modules

Workglen is the suite. Mail, Webmail and Accounting are implemented optional
modules, managed from **Workglen Administration**. Webmail depends on Mail;
Accounting uses its own PostgreSQL database and can run with Mail disabled.
Contacts, Calendar, Sites, Sales, Projects, People, Files, Support, Messages and
Workflows remain planned. See the module catalog for actual enable state.

Mail's enabled state is stored in redb and replicated with the rest of the
database. Disabling it preserves data, pauses delivery and mailbox access,
and leaves Core administration, backups and replication running. Web and CLI
controls both enforce primary ownership. The web control also rejects stale
settings revisions. An active outbound delivery must finish before toggling.

```bash
workglen modules /etc/workglen/node.toml
workglen module-disable /etc/workglen/node.toml mail
workglen module-enable /etc/workglen/node.toml mail
```

See [MODULES.md](MODULES.md) for the admin structure, the foundation/module
boundary, workflows and permission-aware record tagging, and exact disable
semantics. [SCALING.md](SCALING.md) defines growth beyond the compact Mail
profile, including storage choices, worker roles and resource isolation. The
Capacity page shows current limits and the planned scaling direction. New deployments use the `workglen` executable and configuration
examples under `config/`.

## Build

Rust **1.99.1** on Linux was used for validation. The pinned toolchain is in
`rust-toolchain.toml`. A C compiler may still be required by transitive build
scripts on some targets, while native mail authentication uses Pratique cryptography.

For guided prerequisite setup and the build, run:

```bash
bash install.sh build
```

The release defaults use basic optimisation, no LTO and 16 codegen units;
the helper uses one build job to reduce memory pressure on small hosts.
See [INSTALL.md](INSTALL.md) for offline builds and out-of-memory recovery.
For development checks after setup:

```bash
cargo test --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
```

The executable is `target/release/workglen`. Pratique's exact source revision is
vendored under `vendor/pratique`; other dependency versions/checksums are in
`Cargo.lock`. See [THIRD-PARTY.md](THIRD-PARTY.md). No external Git repository was
created or changed for this project.

## Start with one node, then change deployment size

`mode = "single"` runs one writable mail node without a witness or peer. Use
`config/single.toml`, choose a unique permanent `replication.cluster_id`, and set
`node_id` and `role = "primary"`. Networking fields in `[replication]` may be
omitted; omit `[witness]` entirely. Single mode does not start replication or
lease threads and opens no replication listener. All mail data is still in redb.
Initialize a **fresh** database once with `init CONFIG --bootstrap`, then run
`serve CONFIG`. Online CLI and web administration both work in single mode.
Single-node operation has no automatic failover or second durable copy.

`mode = "dual"` enables witnessed leadership and replication. Omitting `mode`
defaults to dual-node operation. A dual-mode primary can also run
while its configured peer is offline, but it must still reach the witness.

### Scale from one mail node to two

1. Keep the existing node's **data directory and cluster ID**. Create a consistent
   backup. Provision the independent witness and a new mail host; install TLS
   certificates and the matching replication/witness tokens.
2. Prepare dual-mode configurations from `config/node-a.toml` and
   `config/node-b.toml`. Set unique `[witness].node_id` values and reciprocal peer
   addresses. The witness must use the same cluster ID. Configure the same mail
   domain, filtering rules, limits and outbound delivery policy on both nodes.
3. Start the witness. Stop the existing mail service, change its configuration
   to `mode = "dual"`, and restart it against the **same database**. This is a
   brief maintenance restart, not a live configuration toggle. Do not run
   `init --bootstrap` again on it. It acquires the witness lease.
4. On the new host, run `workglen init CONFIG` **without `--bootstrap`**, then
   start the service. The primary transfers a consistent snapshot, then catches
   up subsequent journal entries. The new node cannot promote before seeding.
5. Compare `workglen status CONFIG` on both nodes: `ready=true`, matching terms,
   and matching sequences once writes are quiescent. The UI also shows the last
   contact and acknowledged sequence. Only then rely on the replica for failover.
6. Add the second MX address and update the client gateway's backends. IMAP
   clients need the stable endpoint described below to follow a new primary.

### Reduce two mail nodes to one

This is an explicit **offline CLI operation**. A plain configuration edit is
refused for a database that has participated in dual mode. The dashboard includes
these instructions, but cannot fence machines or change deployment mode itself.

1. Retain the current primary. During a planned maintenance window, quiesce mail
   and mailbox writes, confirm both databases are caught up, and take a backup.
   If a node has been lost, retain the surviving seeded database and assess the
   asynchronous replication gap before accepting it as authoritative.
2. Stop both mail services. **Fence every other data node**: prevent its mail
   service from restarting and isolate or power off that host. For example,
   disable and mask its systemd mail unit in addition to your host/network
   fencing. A missed heartbeat is not proof that a peer is stopped. Do not rely
   solely on stopping the witness: it may later restart and grant a lease.
3. On the stopped retained node, set `mode = "single"`, `role = "primary"`, and
   top-level `node_id`; remove `[witness]`. Keep `data_dir`, `domain`, and
   `replication.cluster_id` unchanged. Remove unused peer networking fields.
4. Run on that retained node:

   ```bash
   sudo -u workglen workglen demote-single /etc/workglen/node.toml --peer-fenced
   ```

   The command takes an exclusive database lock, requires a seeded dual-mode
   database, creates and fsyncs a consistent backup, then persists the change to
   single mode. Accounts, password hashes, messages, folder/UID state and queue
   entries remain in place. It refuses to run while the local service is alive.
   **`--peer-fenced` is your assertion of completed fencing. The command does
   not verify remote power state or fence the peer for you.** If fencing cannot
   be established, keep the deployment in dual mode.
5. Start the retained node with the single-mode configuration. Point the client
   gateway and MX routing at it alone. It no longer needs the witness. Keep all
   retired peers fenced. Archive the pre-conversion backup securely.

To scale out again, repeat the expansion procedure. Reintroduce a former peer
with an **empty data directory** and `init` without `--bootstrap`; archive its old
state first. Never bring an old writable peer back independently. Retain the
witness epoch state if reusing the same witness/cluster; do not reset an active
cluster's witness state file. A crash after the conversion commit is safe to
restart in single mode; running `demote-single` twice is rejected.

## Embedded web administration

The UI is compiled into the Rust binary and served directly by Pratique over
HTTPS. It needs no Node.js, frontend build, CDN, or separate web service at
runtime. It manages the server; reading and composing mail remain in an IMAP
client such as Outlook. Keep the administration listener on a private management
network or behind an SSH tunnel.

Create a separate administrator password hash with the CLI. Keep the password
out of command-line arguments and shell history, and ensure the hash is owned
by the service account and mode `0600`. For example, as that account in a shell
with write access to `/etc/workglen`:

```bash
umask 077
systemd-ask-password 'Web administrator password (12+ characters)' | \
  workglen hash-password > /etc/workglen/web-admin.hash
```

Enable the optional section on each node:

```toml
[web]
listen = "127.0.0.1:8443"
origin = "https://mail.example.com:8443"
username = "admin"
password_hash_file = "/etc/workglen/web-admin.hash"
session_minutes = 30
```

The origin is the exact HTTPS URL used by the browser, **without a trailing
slash**, path, username, or query. Its hostname must be covered by the node's
TLS certificate; the UI uses the shared native ACME certificate manager or configured `tls_cert`/`tls_key`. Direct access
can bind to a private management IP. For loopback, forward port 8443 over SSH
and resolve the configured hostname to that local endpoint on the administrator's
computer. Keep origin, browser hostname/port and certificate consistent. CLI
administration still uses its separate loopback port and token, never the web
password. Omitting `[web]` disables the web listener entirely.

The UI provides:

- Overview: deployment mode, primary/standby/seed status, mailbox counts, queue
  totals, peak RSS, replication contact and last acknowledged sequence.
- Accounts: create a mailbox, inspect storage/quota counts and reset passwords.
  Account writes are rejected on a standby. No mailbox credentials are returned
  in the API; a reset does not force existing IMAP sessions to disconnect.
- Delivery queue: inspect recipients, attempts, retry times and errors.
- Security: view effective configured SPF/DKIM/DMARC handling and deny lists.
  Configuration changes require editing the node's TOML and a restart.
- Backups: create a consistent redb snapshot and list completed local backups.
  Transfer these using your secure file tools; the UI does not download or
  restore arbitrary database files.

Web authentication uses a separate Argon2 password hash. Sessions are random,
server-side, capped at 16 per process, expire absolutely after the configured
1–60 minutes, and are invalidated by logout/restart. Cookies are Secure,
HttpOnly and SameSite=Strict. POSTs require the exact origin, JSON content type,
and (after login) a per-session CSRF token. Login attempts are limited
to 20 per minute per actual client IP, with at most 1,024 active source buckets.
Malformed login bodies do not consume the password-attempt budget. Forwarding
headers are not trusted; clients behind one NAT or reverse proxy share its
bucket. At capacity, new sources wait for expiry while existing buckets remain
usable. Concurrent expensive password work returns a short retry response
instead of tying up every HTTP handler. A restrictive CSP and no-store headers apply to all
responses. No authentication tokens are stored in localStorage or URLs.
The listener allows four concurrent HTTP/1.1 connections and 8 KiB request bodies;
password verification/hashing shares the mailbox Argon2 concurrency lock.

Web credentials/sessions, TLS keys, node configuration and backup files are
**local to each node**. Provision administrator credentials on both nodes and
log in separately. Mailbox accounts and data are replicated; management secrets
are deliberately outside the replicated mail database. The dashboard on a
standby remains readable even when mail access is fenced. This remains an
experimental, unaudited management surface, as does Pratique's server runtime.

## Two mail nodes and a small independent witness

Both mail nodes run the same executable and each has its own complete redb
`mail.redb`. Only the node holding the witness lease serves mail. The witness
stores a lease epoch counter, not mail or account data. Run it in an independent
failure domain, for example on the network gateway or a small third host.

A two-node system cannot distinguish a failed machine from a network partition
without arbitration. This implementation uses the witness to avoid overlapping
primaries. It does **not** silently allow both nodes to write during a partition.
If the witness is unreachable, the current primary stops serving after its lease
expires, even if the other mail node is also unavailable.

Default lease duration in the example is 15 seconds. Nodes renew every 2 seconds
and stop using the lease 3 seconds before its advertised expiry. The witness
waits a complete lease plus 2 seconds after restarting before granting a new one.
A new primary changes mailbox UIDVALIDITY so clients refresh potentially stale
UID caches after failover.

### Write and recovery semantics

1. A mail or mailbox change commits locally together with its journal entry.
2. The client can receive success without waiting for the peer. This preserves
   availability when the peer is offline, as requested.
3. The primary streams transactions to its peer in sequence. The receiver
   acknowledges only after its redb transaction commits.
4. On reconnection, the peer catches up from the journal. If its term differs,
   history is unavailable, or it is an empty replacement, it receives a
   consistent snapshot followed by newer transactions.
5. The receiver verifies the current lease holder with the witness before
   applying changes. Snapshot installation atomically replaces the active file.

**Replication is asynchronous.** If the primary's only disk is lost before its
latest writes reach the peer, those writes cannot be recovered from the peer.
Healthy replication also has a small lag. Zero data loss during a peer outage
would require another durable copy or refusing writes; this design chooses local
availability. SMTP delivery is at least once: a crash after a destination accepts a
message but before the queue update is replicated can cause a duplicate.

A returning former primary may have an unreplicated tail. Before reseeding it,
Workglen Mail preserves its previous database as `recovery-<random>.redb`. It does not
automatically merge stale passwords, message deletions, or already-sent queue
entries. Inspect and recover missing messages using:

```bash
workglen export-recovery /etc/workglen/node.toml \
  /var/lib/workglen/recovery-EXACT-ID.redb /secure/new-recovery-directory
```

This opens the saved database read-only and exports raw `.eml` files plus a
`metadata.jsonl` mapping for folders and queue entries. It does not export
password hashes. Import only missing mail through IMAP APPEND; inspect outbound
queue records before resending. Recovery databases are not automatically deleted.
Monitor disk use and archive/remove reviewed copies explicitly.

## Install and configure

The files under `config/` and `deploy/` are examples, not credentials or live
addresses. Replace domain names, addresses and paths. The relay IP in the
example belongs to a documentation-only range.

1. Install the binary as `/usr/local/bin/workglen`; create a dedicated
   `workglen` service account.
2. Place a node configuration at `/etc/workglen/node.toml` on each mail node.
   Use one unique cluster ID on both nodes and the witness; use different node
   IDs. Configure each peer address to point to the other node's private IP.
3. Configure native [Let’s Encrypt issuance and renewal](TLS-CERTIFICATES.md), or install matching TLS certificate chains and private keys. Pratique's server
   accepts TLS 1.3. Keys and all secret files must be mode `0600` (or stricter)
   and readable by the service account. Data directories are mode `0700`.
4. Generate three independent high-entropy tokens, for example with
   `workglen setup-random hex 32`. Replication tokens must match between mail nodes;
   witness tokens must match between the witness and both nodes. Use a separate
   admin token on each node. Keep each in its own mode-0600 file.
5. Configure the relay's implicit-TLS endpoint, certificate hostname, login and
   password file if you choose relay delivery. For direct MX delivery, remove
   `[relay]`, configure `[direct]` and `[dkim]`, and follow DIRECT-MAIL.md. Local
   DKIM signing can also be used with a relay.
6. Configure the system resolver or `dns_server` with a trusted recursive DNS
   service. Authentication has a total time budget and a bounded resolver cache.
7. Provision the initial database and accounts before first startup:

```bash
sudo -u workglen workglen init /etc/workglen/node.toml --bootstrap
systemd-ask-password 'Initial mailbox password' | \
  sudo -u workglen workglen add-user-offline /etc/workglen/node.toml alice@example.com
```

Run the bootstrap command on **only the first fresh node**, whose example
`role` is `primary`. On the other node and every empty replacement use:

```bash
sudo -u workglen workglen init /etc/workglen/node.toml
```

An unseeded replacement is not eligible to become primary. Do not use
`--bootstrap` to recover an existing cluster.

8. Install and start the witness service first, then the two mail services.
   The provided systemd files limit memory and privileges. Adjust their paths
   only if you also adjust the configurations. A service restart closes client
   connections; clients reconnect. Persistent transactions survive restart.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now workglen-witness  # on witness host
sudo systemctl enable --now workglen          # on each mail node
```

9. Publish MX records pointing at both mail node hostnames. Keep inbound port 25 direct
   to each node so SPF receives the original sender IP. Configure domain SPF,
   DKIM and DMARC records for direct delivery or with the outbound relay provider.
   Use native Let’s Encrypt issuance and renewal; renewed certificates load automatically without restarting. Follow [TLS-CERTIFICATES.md](TLS-CERTIFICATES.md). Manual certificate files remain supported and require a restart after replacement.

## Outlook setup and a stable client endpoint

| Setting | Value |
|---|---|
| Account type | IMAP |
| Incoming server | Your stable mail hostname |
| Incoming port | 993, SSL/TLS |
| Outgoing server | Your stable mail hostname |
| Outgoing port | 465, SSL/TLS |
| Username | Full mailbox address |
| Outgoing authentication | Required, same account credentials |
| Default folders | INBOX, Sent, Drafts, Trash, Junk |

Direct clients must support TLS 1.3. Some Outlook/Windows combinations use TLS
1.2. The optional `deploy/haproxy.cfg` accepts TLS 1.2/1.3 and opens a verified TLS
1.3 connection to Workglen Mail. It also supplies a stable endpoint that selects the
current primary using its SMTP greeting: `220` on primary, `421` on standby.
Validate the HAProxy configuration against your installed version before use.
That configuration was not executed in this environment.

Place this gateway in the witness's independent failure domain or provide a
separate managed TCP endpoint. Point the client mail hostname to it. Two MX
records provide inbound SMTP fallback; they do not by themselves make Outlook
switch IMAP servers. Do not put inbound SMTP behind this proxy: Workglen Mail does not
implement the PROXY protocol and would otherwise evaluate SPF against the proxy
IP. The gateway is trusted with decrypted client sessions while bridging TLS.

Workglen Mail implements ordinary IMAP/SMTP accounts. Exchange/MAPI, OAuth2,
Autodiscover, contacts, calendars and shared Exchange mailboxes are not included.

## Operating commands

Run admin commands on the active node with access to its protected config and
token files. The admin listener is restricted to loopback and requires TLS and a
token. It is not a public management interface.

```bash
workglen status /etc/workglen/node.toml
workglen users /etc/workglen/node.toml
workglen policy /etc/workglen/node.toml
workglen backups /etc/workglen/node.toml
workglen queue /etc/workglen/node.toml
systemd-ask-password 'New mailbox password' | \
  workglen add-user /etc/workglen/node.toml bob@example.com
systemd-ask-password 'Replacement password' | \
  workglen set-password /etc/workglen/node.toml bob@example.com
workglen backup /etc/workglen/node.toml
```

`backup` creates a consistent logical redb backup in the data directory and
prints its path. Copy the completed backup to separate storage. Replication is
not a substitute for backups: accidental deletions and bad administrative changes
are replicated too. Never copy a live `mail.redb` file with ordinary `cp` as a
backup. A stopped database can be restored from a completed logical backup only
with the old primary fenced and cluster leadership/recovery planned.

`status` reports the node, primary status, term, transaction sequence, eligibility
deployment mode, last replication exchange, and Linux peak RSS. Compare both nodes' term and sequence to detect replication
lag. Logs report connection failures, replication failures and queue errors;
message bodies and passwords are not logged. Failed outbound messages remain in
the queue for inspection rather than being silently discarded. Automatic queue
expiry cleanup, retry administration and account deletion are not yet provided.

Keep replication (9443) and witness (9444) private and firewall-restricted to the
cluster. Allow public SMTP 25 and client 465/993 as appropriate. Do not expose the
admin port. Validate OS clock synchronization and certificate renewal; lease
intervals themselves use monotonic clocks.

## Memory and load

The supplied defaults use a 16 MiB redb cache, 16 client connections, two data
transfers, four optional HTTPS administration connections, one Argon2 operation at a time, 10 MiB messages, 64 KiB headers, at
most 256 header fields and 8 DKIM signatures. MIME boundaries are bounded before
full parsing. SMTP MX, authenticated submission and IMAP APPEND share acceptance
validation, including MIME part/nesting limits aligned with mailbox reads. The DNS runtime has two worker threads and a 256-entry cache.
Mail bodies and queues persist on disk; the whole mailbox is not loaded at once.

The systemd unit sets `MemoryHigh=384M`, `MemoryMax=480M`, and disables swap for
the service. These are operational ceilings, not proof that every workload fits.
A cgroup limit can kill the process under exhaustion. See VALIDATION.md for the
measured workload; repeat the load test with your expected messages and accounts
on the target machine, including kernel/cgroup memory if the entire VM has only
512 MB. The operating system and optional gateway need memory too.

## Validation

See [SECURITY-REVIEW.md](SECURITY-REVIEW.md) for the supplied offensive review
findings and their resolution in this release.

```bash
cargo test --offline --locked
python3 tools/integration.py --binary target/release/workglen \
  --work /tmp/workglen-test-NEW-DIRECTORY
```

Add `--browser-smoke` to exercise the real UI using an installed Playwright/Chromium
runtime. See VALIDATION.md for optional browser setup. Node.js is needed only for
this browser test, not for the mail server.

The integration test uses Python's standard library and OpenSSL, local TLS
certificates, local DNS records, and a fake local outbound relay. It never sends
mail to a real recipient. Use a new work directory on each run. It retains logs
and a JSON result report. The script kills its own test nodes to verify failover.

## Limitations

Webmail-specific bounds and draft behavior are in WEBMAIL.md. Direct-delivery
TLS policy, port 25 requirements, retry limits and key rotation are in DIRECT-MAIL.md.

- Experimental, unaudited server. Pratique's upstream production warning applies.
- Real Outlook, long-duration operation, adversarial fuzzing, complete MIME/IMAP
  conformance and hardware power-loss testing are not completed.
- Flat folder names (ASCII or caller-supplied modified UTF-7), no nested folder
  hierarchy, INBOX rename, arbitrary IMAP keywords, literal LOGIN arguments,
  CONDSTORE/QRESYNC or server-side sorting. `\\Recent` is always zero.
- Common MIME part fetches are implemented; nested message/rfc822 section paths
  such as `BODY[2.1.HEADER]` are not complete.
- ASCII dot-atom mailbox addresses only; SMTPUTF8, DSN extension, BDAT/CHUNKING,
  mailbox aliases, mailing lists and multi-domain hosting are not included.
- No antivirus, URL reputation, attachment sandbox, ARC trust policy, DMARC report
  generation, MTA-STS/DANE delivery policy or general spam scoring.
- Submission is implicit TLS on 465; there is no port-587 submission listener.
- Local acceptance is durable, asynchronous replication is not a zero-loss
  guarantee, and an ambiguous SMTP acknowledgment may cause duplicates.
- In dual mode, the independent witness is required for automatic leadership. Loss of that
  witness stops service after lease expiry. It is not a consensus cluster itself.
- Reconciliation preserves divergent databases for review; it does not silently
  merge conflicting account changes or resend ambiguous outbound messages.
- Backups, recovery databases and journal/disk usage need monitoring and retention
  management. The snapshot receiver limits a logical snapshot to 10 GiB.

Offline tests and validation tools ship with the source: [PORTABLE-CHECKS.md](PORTABLE-CHECKS.md).
