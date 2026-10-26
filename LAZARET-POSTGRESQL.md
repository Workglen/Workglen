# Native Lazaret PostgreSQL client

Workglen Accounting now connects through `vendor/lazaret-pg`, a separate native
Rust port of Lazaret's Python SQL driver. It uses Pratique directly for verified
TLS and SCRAM cryptography. The external `postgres`, `tokio-postgres`,
`postgres-protocol` and `postgres-types` crates are removed.

This replaces the connection driver. Your existing PostgreSQL server, database,
accounting schema, journal history, credentials and storage keys remain in place.
Rebuild and replace the executable using the existing deployment instructions;
do not reinitialize the database or regenerate keys. Nothing in this source
release installs or updates your running Mac or Lightsail hosts automatically.

The source is organized for a later Lazaret handoff. Its public API, authentication,
wire protocol, types, transport and regression tests live in the crate rather
than in Workglen's accounting module. The baseline is Lazaret `engine-0.1.9` at
`09ffce95d0913076bcfd18d7facf1e30ce818116`. No upstream publication has occurred.

## Implemented behavior

- Separate SQL parameters, NULLs, text, integers, booleans, floats, bytea,
  text-array parameters and optional JSON. Exact decimal/date/custom values
  can use PostgreSQL text representations without floating-point conversion.
- Transactions, nested savepoints, isolation/read-only settings, rollback on
  drop, atomic repeated execution and deferred commit errors.
- Streaming portal batches, cancellation tokens, bounded notices/notifications,
  SQLSTATE errors and synchronization before reusing a failed query's connection.
- SCRAM-SHA-256 and required SCRAM-SHA-256-PLUS, PostgreSQL-compatible Unicode
  password normalization, legacy MD5 challenges and explicit authentication policy.
- Verified TLS by default, certificate refusal, deadlines and bounded protocol
  parsing. Local Workglen transport remains limited to literal loopback or an
  absolute Unix socket path, with no hostaddr override.

The reusable crate intentionally rejects unsupported options. It does not yet
offer every Python/libpq convenience: multi-host failover, GSS/SSPI, client
certificates, COPY, pipelined bulk execution, automatic reconnection, idle
notification waiting and typed multidimensional arrays/date/decimal values are
outside this first port. SQL text representations remain available. See the
[crate README](vendor/lazaret-pg/README.md) for the exact API and boundary.

## Dependency and test evidence

This port removes 28 more registry package versions, taking the lockfile from
258 to 230. Together with the preceding dependency cleanup, the total falls
from 271 to 230 and direct third-party application dependencies from 20 to 16.
No registry package was added or upgraded. The default driver runtime depends
only on first-party Pratique; its optional JSON support uses existing serde_json.
Generated Unicode data retains its actual license notice.

Tests cover the published SCRAM vector, Lazaret's 20 PostgreSQL password
verifiers, all Unicode scalar values against the Python reference, malformed
protocol responses, transaction failures, cancellation, TLS channel binding and
certificate refusals. Disposable database and Workglen accounting results are
recorded in [VALIDATION.md](VALIDATION.md). This is not a claim of production
load testing, live Mac/Lightsail deployment or independent security certification.
