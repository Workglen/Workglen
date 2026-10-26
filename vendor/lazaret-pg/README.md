# lazaret-pg

Native, synchronous PostgreSQL wire client translated from Lazaret's Python
`python/src/lazaret/pg` at `09ffce95d0913076bcfd18d7facf1e30ce818116`
(`engine-0.1.9`). This crate is separate from Workglen so the implementation,
protocol tests and fixtures can be returned to Lazaret without extracting
accounting application code. No publication or upstream push has been performed.

Pratique supplies TLS, certificate verification, SHA-256, HMAC, randomness and
secret-buffer clearing. Legacy MD5 challenge compatibility uses a small
RFC 1321 routine in this crate, tested against published vectors; it is not a
password-storage hash. There are no external crate dependencies, including optional features.
The optional `with-json` feature reuses Pratique JSON values for SQL JSON
values. PostgreSQL remains an external database server; this is its client,
not an embedded PostgreSQL engine. Rust 1.99 or later is required.

## Usage

```rust,no_run
use lazaret_pg::{Config, IsolationLevel};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Read a protected operator-managed connection file; do not log its contents.
let secret = std::fs::read_to_string("/private/path/postgres.dsn")?;
let config: Config = secret.parse()?;
let mut client = config.connect()?;
let mut tx = client.build_transaction()
    .isolation_level(IsolationLevel::Serializable).start()?;
tx.execute("UPDATE accounts SET name=$1 WHERE id=$2", &[&"Operations", &7i64])?;
tx.commit()?;
let mut rows = client.query_stream("SELECT id FROM accounts", &[], 128)?;
for row in rows.by_ref() { let id: i64 = row?.try_get(0)?; println!("{id}"); }
# Ok(()) }
```

The caller controls SQL structure. Parameters are encoded separately in
Parse/Bind/Execute messages; parameter strings are never interpolated into SQL.
Use `batch_execute` only with trusted SQL when multiple statements are needed.

## Supported boundary and intentional differences

| Lazaret capability | Rust implementation |
|---|---|
| PostgreSQL v3 startup and queries | Simple batches and extended parameterized queries; strict message ordering and bounded frames |
| DSNs | Quoted key/value and PostgreSQL URI forms, IPv4/IPv6/Unix socket paths; one endpoint per configuration |
| Environment and passfiles | Explicit `Config::from_env()` opt-in; private regular passfiles, escaped fields and first-match lookup. Normal parsing does not read environment/files |
| Authentication | Trust, SCRAM-SHA-256, SCRAM-SHA-256-PLUS, legacy MD5 challenge; cleartext passwords require verified TLS, a Unix socket or explicit opt-in |
| Authentication policy | `require_auth` allow/deny lists and `channel_binding=disable/prefer/require`; required binding also rejects trust/password/MD5 |
| Password normalization | RFC 4013 with PostgreSQL raw-byte fallback; Unicode 3.2 properties and corrected NFKC tables; invalid UTF-8 remains raw |
| TLS | Pratique verifies chain, hostname and validity; `require` and `verify-full` both verify; no silent plaintext fallback |
| SQL values | NULL, text, signed integers, booleans, floats, bytea, text-array parameters, optional JSON/JSONB; `types::Text` preserves exact numeric/date/time/UUID/array/custom text without lossy float conversion |
| Transactions | Isolation/read-only settings, nested savepoints, explicit commit/rollback, rollback on drop, SQLSTATE and deferred commit errors |
| Repeated execution | Atomic `execute_many`; currently sequential rather than Python's pipelined batching |
| Streaming | Incremental portal batches with backpressure; `finish()` consumes to ReadyForQuery and surfaces deferred errors |
| Cancellation | Separate request to the original resolved peer with original TLS verification policy; credentials are not retained in the token |
| Notices and notifications | Bounded queues collected while processing responses; `pop_notice` / `pop_notification` |
| Recovery | Ordinary SQL errors synchronize before reuse; protocol/authentication/I/O errors close the connection; no automatic query replay |

This is not an API-compatible replacement for every Python or libpq facility.
Multi-host failover, GSS/SSPI, client-certificate authentication, TLS modes that
skip verification, direct TLS negotiation, COPY, named prepared-statement caches,
an idle notification-wait API, automatic reconnect, and typed date/decimal/
multidimensional-array conversion are not implemented. Unknown connection options
are rejected rather than silently ignored. Exact values remain available through
`Text`; cast parameters in SQL where the server cannot infer their type.

Dropping a stream before it is exhausted closes its connection. That prevents
partially consumed writes from being silently committed or returned to a pool.
An error after a connection is lost can leave a write's outcome unknown; callers
must resolve that through application idempotency/audit checks, not blind replay.

## Bounds and transport

Frames are limited to 16 MiB. Materialized queries allow at most 100,000 rows
and 64 MiB of field data; use streaming for larger results. Rows permit 4,096
columns. SCRAM iterations are capped at 1,000,000 and passwords at 16 KiB.
Notices retain 64 entries; notification overflow closes the connection at 256.
Cancellation is best effort: PostgreSQL does not acknowledge a cancel request.

Connection/TLS negotiation defaults to five seconds and each operation/stream
batch to thirty seconds, with socket deadlines checked before I/O. Blocking DNS
and Unix connect calls run in at most eight bounded workers; timed-out OS calls
cannot create unlimited workers. Workglen sets a fifteen-second operation limit
plus server statement/lock/idle-transaction limits. No OS-specific keepalive or
TCP_USER_TIMEOUT tuning is silently emulated.

Plain TCP is an explicit `sslmode=disable` choice in this reusable library.
Workglen applies the additional requirement that its local transport use a
literal loopback IP or an absolute Unix socket path, without hostaddr overrides.
The driver cannot infer whether an arbitrary operator-specified plain endpoint
is trusted. Unix sockets also require explicit `sslmode=disable`.

## Tests and handoff

From the Workglen source root:

```sh
cargo test --locked --offline -p lazaret-pg --features with-json
cargo clippy --locked --offline -p lazaret-pg --all-targets -- -D warnings
```

`tests/database.rs` is opt-in and requires `LAZARET_PG_TEST_DSN` pointing only at
a disposable database, plus `LAZARET_PG_TEST_CA` for its local test CA if using TLS.
Run it with `-- --ignored`. Unit tests preserve RFC authentication vectors and
20 PostgreSQL 16 password verifiers from Lazaret. Protocol fixtures exercise
malformed servers, channel binding, TLS refusals, deferred failures, deadlines,
cancellation and cleanup. Root Workglen tests additionally cover accounting
transactions, posting corrections, locks and audit history.

The Unicode generator is development-only and pinned to Python Unicode 15.0.0.
Generated Unicode data retains `LICENSE-UNICODE`. The first-party crate is
Apache-2.0; Pratique's actual third-party notices remain applicable. For an
upstream handoff, copy this directory beside Pratique and adjust the path
dependency or workspace membership as needed. No Workglen storage/schema
dependency, Python interpreter, TLS subprocess or external scanner is required.
