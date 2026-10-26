# Mail Security encrypted storage

Mail Security requires encryption for its entire native redb store. Original MIME,
attachments, recipient and identity records, rules, configuration, quarantine,
queues, learning data and audit events are encrypted before they reach the database
file. Database journals and compaction files contain ciphertext too. The service
does not create a plaintext working database or fall back to plaintext storage.

## Choose and protect a key

Set `storage_key_file` to an absolute path outside `data_dir`. Typical setup uses
a Workglen-generated key:

```sh
workglen security-generate-key /etc/workglen-security/storage.key
```

Run this as the service account, or provision ownership for that account before
initialization. The command generates 256 random bits, writes 64 hexadecimal digits
and a newline to a new mode-0600 file, syncs it, and refuses to replace an existing
file. It never prints the key. Startup never generates a replacement for a missing
key.

For BYOK, provision an independently generated random 256-bit key at the same path:
either 32 binary bytes or 64 hexadecimal digits with an optional final newline.
This is a cryptographic key, not a password. Use owner-only access (0600 or 0400),
a regular file, and a single hard link. Symlink key files are refused. Directories
containing keys and installation configuration must be administered by trusted
operators. A secret manager can provision a regular file before startup; this
release does not include a remote KMS or HSM integration.

Then run `security-check`, `security-init` and `security-serve` as described in
[README.md](README.md). The overview and guided setup report encryption status and
key-custody guidance. Keys cannot be uploaded, retrieved, changed or disabled
through the web UI or central management protocol. Missing keys, wrong keys,
insecure key permissions and unsupported plaintext stores prevent startup.

## Backup and recovery

Stop the service and copy `security.redb` for an encrypted offline backup. Retain
the installation configuration separately; it contains paths and endpoint settings,
not the storage key itself. Copying a live file during journal append or compaction
is not a supported backup procedure. Keep a separate protected backup of the key,
with recovery access limited to the authorized operators. Restore the encrypted
database with its original key and workspace/instance binding. Losing the key
makes the stored content unrecoverable; Workglen has no recovery backdoor.

Keeping the key outside the data directory prevents ordinary data-only backups
from bundling it. A persistent key on the same disk does **not** protect against
theft of a complete disk image containing both files. For that threat, provision
the key from a separately controlled secret mount at boot, or use an independently
unlocked encrypted system volume. A running process and a privileged host operator
can access decrypted content. The supplied service disables core dumps; protect
swap, crash reporting and host access as part of the deployment.

Generating a different key is not key rotation: an existing database will reject
it. This release has no operator-facing rekey/rotation command. Keep the current
key until a separately tested rotation facility is available. Backups made before
any future rotation will still need the corresponding original key.

## Storage implementation and limits

The reusable `encrypted_store` backend implements the pinned redb 3.1.3 storage
interface. It uses Pratique AES-256-GCM with
128-bit authentication tags. Each file has a random identifier and an HMAC-SHA256
derived file key. Each frame uses a fresh random 96-bit nonce; file identity,
sequence, payload length and the previous authentication tag are authenticated.
Recovery does not reuse a discarded frame's nonce. Compaction creates a new file
identifier and derived key. The container and journal are first-party code; no new
Cargo library, external encryption utility or service is required.

The virtual file is divided into 4 KiB blocks. Changed blocks and logical-length
operations append as encrypted frames. `sync_data` appends an authenticated commit
marker and syncs the file before returning to redb. This avoids in-place encrypted
sector updates damaging both redb commit slots. On reopening, authenticated changes
through the last complete commit are restored; an incomplete or uncommitted crash
tail is discarded. Complete frames with invalid authentication fail closed.

Journal compaction starts beyond the greater of 16 MiB or about three times the
current indexed block footprint. It writes and syncs a complete encrypted
replacement, atomically renames it, and syncs the parent directory while retaining
the exclusive lock. Reserve space for both the journal and its replacement.
This initial profile supports a 4 GiB logical database, up to 65,536 pending
storage operations between sync points, and at most 1 GiB of retained message
content. Metadata/audit history also consume database capacity. These are bounded
small-gateway limits, not a large-scale storage benchmark.

Authenticated encryption does not establish freshness against replacement with an
older valid whole-file backup or truncation to an earlier valid commit. Keep trusted
external audit-chain checkpoints where rollback detection is required. File sizes,
access timing and ciphertext framing remain observable. No physical power-loss
campaign, long-running fuzz campaign or independent cryptographic review has been
completed; synthetic corruption, recovery and compaction tests are implementation
checks.

## Other modules and follow-up work

Mail Security uses this backend now. Workglen Mail's separate redb store, mailbox
backups and replicated snapshots are not encrypted by this change. Webmail uses
that Mail store. Accounting remains in PostgreSQL; its storage encryption is a
database-provider/deployment responsibility.

Follow-up requirements:

- Apply the shared backend to fresh Mail/Core stores and validate encrypted
  replication snapshots, backups, failover and recovery together.
- Add audited key rotation and recovery checks without exposing key material in
  APIs, logs or audit records.
- Add optional external key custody/unlock integrations and production-scale
  durability, performance and independent security validation.

External Xero/QuickBooks/other accounting import/export remains separate from
these storage controls and from the removed Workglen version-upgrade tooling.
