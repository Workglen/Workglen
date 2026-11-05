# First-party code and dependency provenance

## Apache 2.0 compatibility inventory — updated 2026-11-03

Workglen's own code is already declared Apache-2.0 in Cargo.toml and LICENSE.
The current package inventory has 24 entries: nine first-party packages and
15 registry packages. mail-auth and its source are removed. Retained registry
versions, checksums and declared licenses are unchanged from the preceding
review. The preceding 22-package inventory is retained in
`validation/0.8-license-inventory.json`; the current first-party additions and
their licenses are recorded in Cargo.lock, DEPENDENCY-CATALOG.md and this file.

On this evidence, Workglen can remain Apache-2.0 overall, provided component
licenses and notices are respected. This does not relicense every third-party
file as Apache-2.0. License expressions joined with AND require both sets of
terms; OR permits the chosen alternative. In particular:

- MIT, BSD, ISC and Zlib components retain their notices and applicable terms.
- Unicode/ICU components retain their Unicode-3.0 notices. The generated
  lazaret-pg Unicode tables retain `vendor/lazaret-pg/LICENSE-UNICODE`. The
  native IDNA tables/data retain `crates/native-idna/LICENSE-UNICODE`. Lazaret
  archive path-folding data retains `vendor/lazaret-archive/LICENSE-UNICODE`.
- Native MIME bundles Unicode charset mappings and official WHATWG encoding indexes, labels and HTML entities.
  Preserve `crates/native-mime/data/LICENSE-UNICODE`, `LICENSE-WHATWG` and `LICENSE-HTML`; the latter two
  offer BSD-3-Clause for portions incorporated into code. See the crate README.
- TOML conformance fixtures retain the MIT notice in
  `tests/fixtures/toml-test/LICENSE`; no upstream parser implementation is bundled.
- Pratique's NOTICE includes BearSSL-derived MIT code. First-party ownership
  does not remove these third-party notice requirements.
- The bundled `vendor/pratique/roots/mozilla.pem` remains MPL-2.0. Its feature
  is disabled in this build, but the file is still distributed in the source
  ZIP with its MPL notice. Preserve its MPL terms and any covered modifications;
  it does not require Workglen's separate source files to adopt MPL.

The preceding 22-entry package/version/license-expression inventory and its
Cargo.lock hash are recorded in `validation/0.8-license-inventory.json`; it is
historical evidence, not a current 24-package lock snapshot. This review covers
declared package licenses and the bundled notices, not every source-file origin
or contributor's rights. Recheck after dependency changes. Before distributing
compiled binaries, assemble the complete notices for their included dependencies;
this summary is not a substitute for those license texts. The source ZIP does
not bundle those registry crate sources or a compiled binary.

Primary references: [Apache 2.0 section 4](https://www.apache.org/licenses/LICENSE-2.0),
[Mozilla's MPL FAQ, questions 11 and 13](https://www.mozilla.org/en-US/MPL/2.0/FAQ/),
and [Unicode License v3](https://www.unicode.org/license.txt).

## Provenance and components

Pratique and the incorporated Lazaret archive-reader technology are first-party code. Their use does not require additional product attribution. Preserve all actual third-party notices, including certificate-root and Unicode notices.

`vendor/lazaret-archive` is copied from Lazaret commit
`a08bc1684abd29d13e726c014b9dee4d4eacfc20` (2026-11-03). Its Rust source,
tests and fixtures are unchanged; only standalone Cargo metadata points its
single inflater dependency at Workglen's narrow compatibility facade. See
`vendor/lazaret-archive/WORKGLEN.md` and `LAZARET-ARCHIVE-INTEGRATION.md`.

Pratique is vendored from https://github.com/lazaret-dev/pratique,
commit `9efaab9c010a2ca7f5ffaaf46b3b82eb50e20be4` (retrieved 2026-10-23).
Workglen adds native RSA-2048 key generation, exposes the existing constant-time private-key PEM encoder, and makes the Linux entropy fallback fail closed when random-pool readiness cannot be established; see `PRATIQUE-INTEGRATION.md`. The remaining upstream library files and root notices are preserved. The bounded async sockets, cooperative yield and typed-data/JSON modules are tracked alongside all earlier changes in PRATIQUE-UPSTREAM.md and upstream/pratique/.
The vendored build subset contains upstream Cargo.toml, src/, roots/, README.md,
LICENSE and NOTICE, plus the new standalone async socket and typed-data/JSON tests. Upstream examples, test data, development tools and Git
history are omitted. Pratique is Apache-2.0; its optional bundled Mozilla trust
store has the notices in vendor/pratique/NOTICE. The Mozilla feature is disabled.

Workglen Mail uses Pratique ServerStream/TlsStream for SMTP TLS, IMAP TLS, outbound
SMTP relay/direct STARTTLS, replication, administration and witness communication. Linux TCP
listeners use std::net, as required by Pratique's blocking-stream interface.
The optional embedded web UI uses Pratique's HTTPS ServerBuilder and HTTP/1.1
handler runtime. No third-party frontend assets or runtime are bundled.
SPF/DKIM/DMARC DNS uses first-party workglen-dns. Authentication, DKIM2 and
optional ARC are first-party source with Pratique cryptography; see
NATIVE-MAILAUTH.md. The removed third-party mail-auth source is not relabeled.

Other direct dependencies are resolved in Cargo.lock:

- redb: embedded transactional database, MIT/Apache-2.0.
- Argon2 and subtle: password hashing and constant-time token comparison, under
  their upstream licenses. Workglen's own SHA-256 and OS randomness now use
  Pratique. Both former getrandom package versions are now removed.
- Serde, serde_json and encoding_rs are removed from the application graph. Their optional isolated reference harnesses remain development-only.

The source package does not vendor every crates.io dependency. Cargo.lock pins
versions and registry checksums. Fetch them once on a build host, then build and
test using `--offline --locked`. No SQLite dependency is used.

Accounting uses the first-party `lazaret-pg` client, native CSV reader and
native HTTP(S) URL/form encoding. PostgreSQL TLS uses Pratique directly. The native client port is
Apache-2.0 and retains its actual Unicode data notice. Feed tokens and the
encrypted redb store use Pratique AES-256-GCM; management requests use its HMAC.
The native DKIM signer uses Pratique RSA-SHA256; Pratique also handles key generation, inbound RSA/strict
Ed25519 verification, HTTPS and ACME. See MAIL-AUTH-PRATIQUE.md.
OpenSSL and postgres-openssl are absent from the build and runtime dependency graph.
No PostgreSQL server, provider SDK or browser framework is bundled. PGlite,
Playwright and independent OpenSSL/Python TLS peers are development test tools only.

Webmail uses first-party workglen-mime for MIME parsing and HTML-to-text conversion.
First-party decoders supply legacy charset conversion using attributed official mapping data.
No new third-party runtime dependencies were added for direct delivery or Webmail.

Native Mail Security reuses the existing first-party inflater, the existing ZIP reader and Lazaret's bounded archive crate. The two added path packages are first-party and add no registry package, extractor process or runtime service. Direct and transitive policy checks run in the regression suite. See `DEPENDENCIES.md` and `LAZARET-ARCHIVE-INTEGRATION.md`.

Native DNS, URL parsing and mail authentication are first-party. Unicode IDNA
logic is first-party; its official Unicode 18 data remains attributed under
Unicode License v3. No removed implementation is relabeled. See NATIVE-IDNA.md.
