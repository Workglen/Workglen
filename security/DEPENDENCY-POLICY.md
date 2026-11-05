# Mail Security dependency rule

Mail Security runs within the Workglen Rust executable, including its HTTPS interface, SMTP gateway, detector, encrypted embedded redb store, queues and mailbox connectors. It must not require an additional interpreter, installed extractor, scanner daemon, external database, paid scanning API or cloud inference service.

Use first-party source for new inspection and decompression functionality. Lazaret and Pratique are first-party projects. Existing compiled Workglen libraries remain pinned in Cargo.lock; the native implementation adds no third-party Cargo dependencies. The user-authorized 2026-10-24 cryptography change removes OpenSSL and postgres-openssl (and their now-unused dependencies). OpenSSL must not return as a direct/transitive application dependency or setup prerequisite. Use Pratique for TLS, AES-GCM, HMAC, RSA signing/key generation and certificate provisioning. Optional Accounting still requires its configured PostgreSQL server. “Self-contained” describes the security service, not an assertion that the entire suite has no libraries or operating-system dependencies.

Normal DNS, provisioned SMTP destinations and explicitly enabled mailbox connectors remain necessary network interfaces. Explicitly configured Let’s Encrypt certificate management uses native ACME over outbound HTTPS plus an inbound HTTP-01 challenge listener; it adds no daemon or library and never sends mail or attachment content to the CA. Do not download decoders or rules during inspection, execute message contents, invoke a shell/extraction utility, or transmit attachment content to an external analysis service.

The inherited dependency list is captured in dependency-policy.json and checked by the native regression suite. Changes to that list require an explicit architecture-policy change; do not silently update the baseline to accommodate a new dependency. Preserve real third-party notices in reused first-party code. Development-only test tools are not deployed runtime requirements.

The user-authorized October 24, 2026 dependency minimization replaces Workglen's
direct SHA-256 and OS-entropy calls with existing Pratique implementations and
file locking with `std::fs::File::try_lock`. Chrono enables only UTC `now`, TOML
only parsing/Serde/std, and Argon2 only allocation/password-hash support. This
removes three direct registry dependencies and 13 lockfile package versions;
retained versions and persisted formats do not change. The policy now also pins
the complete registry package/version/source allowlist, including development
and platform dependencies. Review both direct features and transitive changes.

Prefer standard-library or existing first-party capabilities before adding a
crate. Keep reviewed, necessary parsers, password hashing, transactional storage
and protocol implementations until a tested replacement preserves their behavior.
Do not count moving third-party code into `vendor/` as eliminating it. Do not
disable authentication, certificate validation, character-set support, parser
bounds or durable storage just to reduce the package count. See
[DEPENDENCIES.md](../DEPENDENCIES.md) for measurements and the remaining work.

New archive formats must follow [SEC-ARCHIVE-01](../MAIL-SECURITY-BACKLOG.md). Unsupported or incomplete inspection remains administrator-only quarantine. Never disable mandatory checks to make a missing decoder appear supported.

Delivery destinations may also be provisioned through the authenticated setup wizard, with instance/domain/configuration authorization, an audited successful test, immutable saved route IDs and public-address checks at every connection. File-defined private-network and credentialed routes remain installation-managed. This adds no dependency and does not grant a browser arbitrary HTTP access or credential-file access.

The user-authorized native Lazaret PostgreSQL port replaces `postgres`,
`tokio-postgres`, their protocol/type crates and unused transitive support with
first-party `vendor/lazaret-pg`. The reviewed lockfile loses another 28 registry
package versions (258 to 230), adds no registry package, and preserves all
retained versions/checksums. Unicode data notices remain attached to the native
SASLprep tables. Its optional JSON support uses the existing serde_json crate.
The direct/transitive allowlists are updated for this explicit architecture
change. No PostgreSQL server, schema, secret or stored-data conversion is added.

The user-authorized staged replacements use first-party Base64, CSV and test
directory helpers. Each stage removes only reviewed registry packages, preserves
retained versions/checksums and provides its own complete source ZIP. Base64
uses Pratique with canonical padded/URL-safe policies; acceptance is compared
against the former pinned codec before removal. No installed data conversion
is introduced. See CRATE-REPLACEMENTS.md for stage-specific evidence.

The user-authorized mail-auth cryptography replacement uses Pratique for RSA,
strict Ed25519 and streaming hashes. The upstream mail-auth 0.13.3 protocol code
is an explicitly attributed path dependency; it remains in the external count.
Its complete deployment manifest is pinned in `vendored_third_party`, and the
regression suite checks the allowed path packages as well as registry packages.
The graph loses 35 external package versions (224 to 189, comprising 188 registry
and one vendored third-party package). No remaining registry version/checksum
is changed. Preserve strict verification and weak-key bounds; see
[MAIL-AUTH-PRATIQUE.md](../MAIL-AUTH-PRATIQUE.md).

The user-authorized native replication codec removes bincode 1.3.3 without
changing the existing fixed-integer little-endian operation format or 24 MiB
encoded frame bound. The graph decreases from 189 to 188 external package
versions (187 registry plus mail-auth). No added package, retained version or
checksum change is permitted for this checkpoint. The reviewed direct and
transitive allowlists reflect this removal; see REPLICATION-CODEC.md.

The user-authorized unused mail-auth report/compression cleanup removes flate2
and its five exclusive transitive packages. The report module remains disabled
and its compression re-export now has the same feature gate. Active mail-builder,
similar and other protocol utilities remain. Native archive inspection and
mandatory incomplete-scan quarantine are unchanged. The graph decreases from
188 to 182 external versions (181 registry plus mail-auth), with no additions,
upgrades or retained checksum changes. The vendored manifest and full registry
allowlists reflect this reviewed removal. See MAIL-AUTH-REPORT-TRIM.md.

DEPS-07 is explicitly authorized: disable mail-builder's unused native hostname
feature while retaining its Base64 codec. Four exclusive registry packages are
removed (182 to 178 external versions); no additions, version or checksum
changes. The complete vendored manifest and registry allowlist reflect this
review. See MAIL-AUTH-UTILITIES.md for this and subsequent utility checkpoints.

DEPS-08 is explicitly authorized: use the first-party Pratique Base64 adapter
for mail-auth's active calls and remove mail-builder. The graph loses one
registry package (178 to 177 external versions), with no additions, upgrades or
retained checksum changes. Padding, short-buffer behavior and signature output
are covered by old/new comparisons and delivery tests. The allowlists reflect
this removal. See MAIL-AUTH-UTILITIES.md.

DEPS-09 is explicitly authorized: replace similar with first-party bounded DKIM2
recipe generation and remove its exclusive bstr dependency. The graph decreases
from 177 to 175 external versions (174 registry plus mail-auth), with no added
package or retained version/checksum change. Retain DKIM2 and its JSON formats;
limits must return a losslessly verified literal recipe or the existing explicit
unreconstructable state. Reject overflowing copy indices. Full graph and vendored
manifest allowlists reflect this reviewed change. See MAIL-AUTH-UTILITIES.md and
DEPENDENCY-CATALOG.md; this does not authorize disabling other protocols or
removing remaining packages merely to lower the count.

DEPS-10 is explicitly authorized: replace anyhow with first-party standard-library
error/context wrappers. Preserve typed denial, timeout and delivery errors as
well as user-facing error context. The graph loses anyhow only (175 to 174
external versions), with no additions or retained version/checksum changes.
The direct and transitive allowlists reflect this reviewed removal. No runtime
helper is added. See NATIVE-ERRORS-AND-DATES.md.

DEPS-11 is explicitly authorized: replace Chrono with first-party fixed-format
Gregorian date/time handling using standard SystemTime and arithmetic already
used by Pratique. Preserve UTC seconds/milliseconds, accounting calendar rules,
IMAP/email date formats, certificate dates and retry timing. The graph loses
Chrono only (174 to 173 external versions); num-traits/autocfg remain shared
with the DNS graph. No additions or retained version/checksum changes. The
allowlists reflect this removal. See NATIVE-ERRORS-AND-DATES.md.

DEPS-12 (2026-10-25) is explicitly authorized by the request for internal DNS,
URL and mail authentication functionality. First-party `workglen-dns` replaces
Hickory's active recursive-client path, and `src/url.rs` replaces HTTP(S) URL
and form parsing. IDNA 1.1.0 remains pinned for Unicode normalization and checks;
Pratique's conservative IDNA helper is not an equivalent substitute. Tokio's
existing I/O utility feature is now requested by the native DNS crate. The
reviewed graph removes 77 registry versions, adds none, and retains all remaining
versions and checksums: 96 external versions (95 registry plus mail-auth).
The new path crate is first-party. The attributed mail-auth adapter now selects
`dns-native`; mail-auth remains third-party and is still counted. DNSSEC status
remains indeterminate, as in the former Workglen configuration (`validate=false`).

Native DKIM signing uses Pratique and internal RFC 6376 canonicalization. The
inbound SPF/DKIM/DMARC candidates under `native-auth-candidate` are development
only, are not selected by the SMTP checker, and do not justify removing mail-auth.
Full mail-auth removal remains incomplete: retain inbound protocol behavior,
DKIM2, optional ARC and their attribution until replacement coverage is complete.


DEPS-13 (2026-10-25) is explicitly authorized by the request to fully remove
mail-auth and its associated dependencies. Native SPF, DKIM/ATPS and DMARC now
serve the SMTP authentication path. First-party DKIM2 preserves the deployed
draft wire format and bounded reconstruction, including signed DSN validation;
ARC remains available under the optional `arc` feature. Pratique provides all
cryptography. The third-party mail-auth source and manifest are removed, rather
than relabeled as first-party code. Only previously authored Workglen diff and
Base64 adapter files move from the old vendor directory into src/mailauth.
Synthetic independent cryptographic fixtures, bidirectional wire checks against
the prior attributed engine, closed-DNS protocol/limit checks and the ordinary
mail regressions validate this review. The reviewed graph removes 17 external
package versions (96 to 79), adds none, and preserves every retained registry
version and checksum. IDNA and its Unicode machinery remain in this checkpoint.
See NATIVE-MAILAUTH.md for scope, evidence and reproducibility.

DEPS-14 (2026-10-25) is explicitly authorized by the subsequent IDNA focus.
First-party workglen-idna replaces both direct consumers of idna 1.1.0: native
DNS and URL host conversion. It retains Unicode 18 UTS #46 mapping, NFC, bidi,
ContextJ and A-label validation using attributed official data and Pratique
Punycode. Data licenses and input hashes remain in the source. The graph removes
25 registry versions (79 to 54), adds only a first-party path crate, and keeps
every remaining registry version/checksum unchanged. No conservative/ASCII-only
substitute, hidden vendored engine or external runtime service is introduced.
Official conformance corpora, exhaustive scalar comparisons, regeneration,
application tests and loopback regressions accompany this explicit review.
See NATIVE-IDNA.md and PORTABLE-CHECKS.md.

DEPS-15 (2026-10-25) is explicitly authorized by the request for native email/MIME
parsing. First-party workglen-mime replaces mail-parser at every application
consumer: SMTP authentication, security inspection, IMAP, Webmail and DKIM2 DSNs.
Message structure, headers/addresses, transfer codecs, RFC 2231 filenames and
HTML text projection are first-party protocol code. The existing encoding_rs
0.8.42 remains pinned for legacy charset conversion; official Unicode and WHATWG
data retain their attribution. No upstream parser implementation is copied.
The reviewed graph removes mail-parser 0.11.9, hashify 0.2.9 and their exclusive
syn 2.0.119: 54 to 51 registry versions, with six first-party packages. Retained
versions and checksums do not change. Malformed/ambiguous MIME and decoding
failures remain visible to mandatory incomplete-scan quarantine. Shared input,
header, part, nesting and decoded-byte limits are enforced before/through parsing.
The portable comparison corpus records exact matches and explicitly reviewed
corrections; it does not silently bless parser differences. See NATIVE-MIME.md.

## DEPS-16 — Native TOML, explicit review (October 26, 2026)

User-authorized replacement of TOML parsing uses first-party workglen-toml and
existing Serde schemas. Node, witness and dependency-policy test consumers all
move off the external parser. No TOML crate is retained as a test dependency;
the optional former-engine oracle has its own isolated, frozen lockfile.

Review: 51 to 41 registry versions; seven first-party packages and six direct
external crates remain. The ten removals are toml, toml_datetime, toml_parser,
toml_writer, serde_spanned, indexmap, hashbrown, equivalent and both winnow
versions. Existing registry versions and checksums are unchanged. The direct,
transitive and first-party allowlists are updated for this specific replacement.

Preserved: configuration format, defaults, typed fields/enums, unknown-field
rejection and subsequent application validation. Duplicate/redefined values
fail closed. Bounded input/depth/work/key processing is explicit; no configuration,
key, persisted data or service deployment is modified by this change. Evidence:
712 official TOML 1.1 cases, 5,748 pinned former-parser snapshots, schema/limit
checks, mutation tests and the portable application checks. The MIT fixture
notice remains attributed. See NATIVE-TOML.md and VALIDATION.md.

## DEPS-17 — Pratique networking, explicit review (October 26, 2026)

User authorization: remove Tokio, add the reusable required capabilities to
Pratique, and track additions for a later Pratique GitLab update. Existing
executor, timer and async I/O APIs are reused. Newly authored Pratique code adds
cooperative yielding and bounded nonblocking UDP/TCP, with cancellation closing
owned sockets rather than abandoning background I/O. Workglen keeps DNS wire,
retry/cache, authentication and routing semantics, with one deadline across each
UDP/TCP attempt and the existing overall timeouts. A shared socket budget bounds
concurrency without a queue. No third-party implementation is relabeled.

Review: 41 to 33 registry versions; seven first-party packages and five direct
external crates remain. Exact removals: bytes 1.12.1, mio 1.2.4, pin-project-lite
0.2.17, socket2 0.6.5, tokio 1.54.1, wasi 0.11.1+wasi-snapshot-preview1,
windows-link 0.2.1 and windows-sys 0.61.2. Retained versions and checksums remain
unchanged. Direct and full transitive allowlists reflect this reviewed change.

Evidence includes bounded capacity/cancellation/backpressure tests, IPv4/IPv6,
TCP fallback/trickling, wrong-ID flood fairness, overall authentication deadlines
and portable application checks. The 2 ms readiness polling tradeoff and macOS
validation still required are explicit. No live installation is changed. The
Pratique handoff records exact prior/new patches and source hashes; no GitLab
push is part of this review. See NATIVE-ASYNC-DNS.md and PRATIQUE-UPSTREAM.md.

## DEPS-18 — First-party typed data and JSON, explicit review (October 26, 2026, UTC)

User-authorized removal of Serde and JSON uses explicit application schemas and
Pratique's reusable typed-data/JSON-value modules. The original Pratique signed
JSON parser remains strict; its canonical/signature policy is unchanged. Native
TOML retains its grammar and locations, with a direct first-party data adapter.
The PostgreSQL client's optional JSON adapter now uses Pratique JSON values.

Reviewed graph: 33 to 22 external package versions, with the same seven
first-party packages. Removed serde, serde_core, serde_derive, serde_json,
proc-macro2, quote, syn, unicode-ident, itoa, memchr and zmij. No retained version
or registry checksum changes. Direct and full graph allowlists reflect this
specific authorized architecture change. No third-party implementation is
copied or relabeled, and no external derive or JSON engine remains in the
application/workspace test graph. Frozen former engines belong only to isolated
development oracles outside that graph.

Preserve record field ordering, sorted generic maps, precise numeric tokens,
optional/default/omitted fields, enum tags, typed duplicate/unknown rejection,
configuration kinds, audit hash inputs, encrypted-store and external wire
formats. No installed schema/key/configuration conversion is authorized or
needed. Portable independent comparisons and same-schema reopen checks are
required before completion. See NATIVE-DATA.md and PRATIQUE-UPSTREAM.md.

## DEPS-19 — Dependency-free reusable libraries (October 26, 2026)

User requirement: our reusable libraries must not require external libraries.
All six reusable first-party crates (Pratique, Lazaret PostgreSQL, native DNS,
IDNA, MIME and TOML) may use std and reviewed first-party paths only. Registry,
Git, unreviewed paths, optional, build, development and target-specific external
dependencies are rejected by tools/check-first-party-dependencies.py. The root
application's existing database/password dependencies remain separately counted.

First-party charset decoders replace encoding_rs using official WHATWG mappings
and labels, with original notices, hashes and an offline generator. No third-party
codec implementation was copied or relabeled. MIME alias normalization, BOM
behavior, error flags and mandatory incomplete-scan handling are preserved.
Single-byte, Chinese, Japanese, Korean and stateful decoders remain supported;
malformed sequences retain ASCII delimiters according to their codec rules.

Reviewed graph: 22 to 15 registry versions (33 to 15 for this combined source
update); seven first-party packages and three direct external crates remain.
Exact charset removals: encoding_rs, cfg-if, core_detect, multiversion_no_op,
rustversion, scopeguard and simdutf8. Retained registry versions/checksums are
unchanged. simdutf8 was a cross-platform encoding_rs helper, not Android-only.
Evidence: 2,883,056 deterministic old/new decoder comparisons and portable
SHA-256 fixture fingerprints, MIME snapshots and application checks. This is
synthetic compatibility evidence, not an independent security audit.
See NATIVE-CHARSETS.md and NATIVE-DATA.md.

## Offensive-review test tooling (October 26, 2026)

The main-workspace allowlists and all reusable-library dependency boundaries
remain unchanged. Optional cargo-fuzz tooling lives in the separate `fuzz/`
workspace with its own pinned lockfile and 10 registry versions, documented in
DEPENDENCY-CATALOG.md. These are development tools only, never deployed runtime
requirements. The seed/replay workspace uses only first-party Pratique.

## DEPS-20 — Lazaret archive integration (November 3, 2026)

User authorization: integrate and harden Lazaret archive support in Mail
Security, without moving Workglen ZIP into Lazaret or making Workglen-owned
changes to Lazaret's implementation. `vendor/lazaret-archive` is the exact Rust
source, fixtures and tests from Lazaret commit
`a08bc1684abd29d13e726c014b9dee4d4eacfc20`. Its standalone manifest retains
the upstream version, repository and Apache-2.0 AND Unicode-3.0 license and
points the archive crate's one dependency at `workglen-lazaret-verify`, a narrow
first-party compatibility facade that exposes only the existing Pratique
inflater. Behavioral changes belong in Lazaret and are tracked separately in
`LAZARET-ARCHIVE-BACKLOG.md`.

Review: Cargo.lock grows from 22 to 24 entries, both added entries first-party.
The 15 registry packages, versions, sources and checksums are unchanged. The
application still has three direct external crates. All eight reusable
first-party crates have only approved first-party path dependencies. No
extractor executable, interpreter, scanner daemon, network call, downloaded
decoder or additional deployed service is introduced. Lazaret's Unicode 15.1
path-folding table retains its Unicode-3.0 license and notice.

Workglen's adapter applies the configured per-message decoded/expanded-byte
budget, 256-member and eight-level aggregate bounds, a 200x expansion-ratio
guard after the first MiB, path/name ambiguity quarantine and recursive
inspection of every returned file. Unsupported, encrypted, corrupt, truncated,
conflicting, special-entry and over-budget results remain mandatory
administrator-only quarantine and are rechecked before release. Lazaret's
current synchronous API has no cooperative mid-decoder deadline; Workglen
bounds input, output and concurrent calls and checks its five-second deadline
before and after the call. A native work/cancellation budget is an upstream
backlog item, not a hidden patch to the vendored source.

## DEPS-21 — Restartable native scan role (November 4, 2026)

The user-requested durable-ingress boundary separates SMTP acknowledgment from
sender authentication and content inspection. This is a process role in the same
native `workglen` executable, under the same dedicated account; it is not an
installed third-party scanner daemon, interpreter, extractor, database, cloud API
or separately distributed runtime. The registry/path dependency graph and
allowlists do not change.

`security-serve` remains the sole encrypted-redb owner and commits exact MIME
before SMTP `250`. `security-scan-worker` receives bounded leased work over a
mode-0600 Unix socket inside the mode-0700 data directory. Protocol, API,
analysis-profile and coverage versions are explicit; incompatible workers are
refused before a claim. The local protocol carries a required cancellation
context (currently the documented no-op form), caps inspection/result/evidence
frames and never puts decoded content in audit events. This native role may be
restarted or replaced while ingress continues to spool within configured
capacity. Lazaret remains in-process first-party library code inside that role;
no Lazaret implementation change is made by this boundary.

The native scan role also has durable light and heavy scheduling lanes without
adding a process, runtime or dependency. Only small, clearly single-part mail is
assigned to the latency lane; multipart, attachment, encoded, large, malformed
or legacy work is conservatively heavy. With the default two scan threads one is
reserved for each lane. Light workers never claim heavy work, while an idle heavy
worker may assist the light queue. Both lanes run the identical pinned analysis
profile, rules, coverage checks and mandatory incomplete-scan quarantine.
