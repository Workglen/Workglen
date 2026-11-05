# Pratique integration

Workglen builds, installs and runs without OpenSSL, postgres-openssl, an OpenSSL CLI, OpenSSL development headers or pkg-config. The original TLS consolidation removed nine packages; subsequent reductions are recorded in DEPENDENCIES.md. The application retains its other existing compiled Rust libraries; this is not a claim that the entire product has no dependencies.

## Implemented paths

| Function | Implementation |
|---|---|
| SMTP/IMAP/HTTPS/replication TLS and ACME | Existing Pratique transports and certificate manager |
| PostgreSQL TLS | `vendor/lazaret-pg/src/transport.rs`: native PostgreSQL transport using Pratique TLS |
| Mail Security encrypted redb | Pratique AES-256-GCM and HMAC-SHA256, retaining authenticated framing, key custody and crash/compaction behavior |
| Bank-feed token encryption | Pratique AES-256-GCM with existing workspace/book/connection binding |
| Signed central gateway commands | Pratique HMAC-SHA256; existing constant-time comparison, audience/time/nonce/RBAC checks remain |
| DKIM | First-party Workglen canonicalization with Pratique RSA-SHA256 signing, RSA/strict Ed25519 verification and streaming hashes |
| DKIM key generation | First-party Pratique RSA-2048 provisioning; exponent 65537; exclusive mode-0600 output |
| DNS transport and deadlines | New bounded nonblocking UDP/TCP and cooperative yield; existing executor, timer/timeout and async I/O traits |
| Local setup | Native `setup-random`, `setup-local-tls` and `setup-check-tls` commands |
| Application hashes and entropy | Pratique SHA-256 for content/audit/session/replication hashes and OS randomness for salts, IDs, keys and nonces |

## Database transport and Lazaret reuse

The native `lazaret-pg` crate now owns PostgreSQL wire messages, parameter encoding,
authentication, transactions and recovery. Its synchronous transport matches
Workglen's existing bounded pool and uses Pratique directly. TLS verifies the
certificate chain, hostname and dates. The connection/TLS deadline is five
seconds; Workglen operations use fifteen-second deadlines plus server-side SQL
limits. Explicit local transport remains restricted to literal loopback or an
absolute Unix socket path without hostaddr overrides.

`tls-server-end-point` uses the certificate signature hash for supported
RSA/ECDSA algorithms. Undefined algorithms provide no binding; required binding
then refuses the connection. Tests retain SCRAM-SHA-256-PLUS and certificate
chain/hostname/expiry refusal coverage. The Python Lazaret source at
`09ffce95d0913076bcfd18d7facf1e30ce818116` supplies the port's behavioral reference;
no Python interpreter or SSL subprocess is used by Workglen. See
[LAZARET-POSTGRESQL.md](LAZARET-POSTGRESQL.md) for the supported boundary and
intentional differences.

## First-party Pratique additions

The original vendored baseline is `9efaab9c010a2ca7f5ffaaf46b3b82eb50e20be4`. The initial integration changed three existing files: `src/crypto/mod.rs` exports the added `src/crypto/rsa_generate.rs`; `src/sign.rs` exposes its existing constant-time private-key PEM encoder; `src/crypto/rand.rs` now fails closed if Linux fallback entropy readiness cannot be established. That initial change preserved the other baseline files, licenses and root-certificate notices. See [DEPENDENCIES.md](DEPENDENCIES.md) for the additional 13-package reduction and compatibility evidence.

The mail-auth checkpoint additionally adds a strict Ed25519 verification entry
point in `src/crypto/ed25519.rs`, a streaming legacy SHA-1 context in
`src/crypto/sha1.rs`, an RSA public-exponent accessor in `src/crypto/rsa.rs`,
and the explicit legacy verification exports in `src/crypto/mod.rs`. The
general Ed25519 verifier and TLS/X.509 SHA-1 rejection are unchanged. See
[MAIL-AUTH-PRATIQUE.md](MAIL-AUTH-PRATIQUE.md) for the 35-package reduction.

The generator uses OS randomness and Pratique's existing constant-time Montgomery arithmetic. It generates independently sampled 1024-bit odd prime candidates with their two high bits set, trial-divides small primes, checks the public exponent, and applies 80 independent randomized Miller–Rabin rounds. Attempts and base sampling are bounded. It enforces prime separation, derives the private/CRT exponents, and imports the result through Pratique's RSA validation and blinded signing self-check before returning it. Secret buffers use Pratique's zeroizing containers. The private PKCS#8 PEM encoder avoids secret-indexed Base64 lookup tables.

Generation is an offline operator action. Candidate rejection and the number of attempts are variable-time; this is not an online key-generation service or a claim of independently audited/FIPS-certified cryptography. Independent key validation and DKIM signature interoperability are development checks, not a substitute for cryptographic review.

Local certificates use fresh P-256 keys, a five-year private CA constrained to no intermediate CAs, and a one-year localhost leaf with DNS/IPv4/IPv6 loopback names and server-auth usage. Native generation validates the resulting chain and key match before writing it. Existing paths are refused; files are mode 0600. Keychain enrollment and local certificate renewal remain operator steps. Public gateway certificates continue through the existing ACME lifecycle.

## Validation and remaining limits

See [VALIDATION.md](VALIDATION.md) for executed results. The suite covers published AES-GCM/HMAC vectors, authentication failures, encrypted-store recovery, native ACME, database operations, verified management requests, independent DKIM verification and installer execution with the OpenSSL command blocked. The executable's dynamic library list is checked separately for OpenSSL absence.

Development fixtures may use independent OpenSSL/Python/Node TLS implementations as interoperability oracles. They are not application, build or installation requirements. Tests remain synthetic and local; no customer database, mailbox or public CA is used. The developer laptop is an Apple Silicon M5 Mac and server test machines run Ubuntu. The packaged Linux evidence does not establish M5 macOS compilation/Keychain trust, Ubuntu test deployment, production load or independent cryptographic review. There is no current installation.

## Tracked upstream handoff

`PRATIQUE-UPSTREAM.md` and `upstream/pratique/README.md` track every divergence
from the pinned Pratique library baseline. PRA-WG-01 covers seven earlier crypto
files; PRA-WG-02 covers five new/modified networking and test files. The ordered
patches include exact source preimages/postimages, patch SHA-256 and the complete
vendored inventory. Verification applies patches in a temporary directory.

The networking addition removes Tokio and seven exclusive support versions.
Pratique remains dependency-free. See NATIVE-ASYNC-DNS.md for cancellation,
capacity, polling/deadline behavior and the outstanding native macOS validation.
Status is prepared for upstream review; no GitLab push or merge is claimed.

## Reusable typed data and JSON (PRA-WG-03)

Pratique now supplies std-only explicit record contracts, JSON values and bounded
parsing/writing. The existing signed JSON parser policy remains strict. The
new capability and reusable tests are tracked in patch 0003; see NATIVE-DATA.md
and PRATIQUE-UPSTREAM.md. Pure builds forbid unsafe code and exclude the I/O
writer seam. No external dependency was added to Pratique.
