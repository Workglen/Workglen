# Checks shipped with this source ZIP

From a fresh extraction, run:

```sh
python3 tools/check-native-replacements.py
```

The runner verifies the source hashes, runs all workspace tests including ARC,
runs warnings-denied release Clippy in a separate target directory, builds the
release executable, and runs synthetic outbound DKIM/SMTP and broader mail/IMAP
integration checks. The cumulative IDNA checkpoint also verifies exact offline
Unicode table regeneration and runs the official IDNA/NFC conformance corpus.
Logs and a machine-readable `results.json` go into `target/portable-validation`.
Use `--output /absolute/path` to put results elsewhere. All Cargo commands are
offline and locked; nothing installs, downloads, deploys or contacts a real mail
provider. Synthetic tests use loopback listeners and temporary database/key files.

Prerequisites: the repository's supported Rust toolchain with Clippy, Python 3.11 or newer,
and the already fetched Cargo.lock dependencies. Prepare dependencies through the
existing source-build workflow before going offline. The OpenSSL CLI is used only
by the independent development TLS/signature peers, never by the application.
Python fixture regeneration additionally needs `cryptography`; running the
checked-in Rust fixtures does not. Pass `--cargo /path/to/cargo` for a custom
toolchain wrapper. `--skip-loopback` gives Rust-only validation. After intentional
source edits, `--skip-source-integrity` bypasses only the release-source hashes.
The runner reports failures instead of silently skipping a missing prerequisite.

## Included evidence and reproducible inputs

| Check | Portable source/input |
|---|---|
| Cryptographic known answers and independent signatures | `tests/mailauth_crypto.rs`, `tests/mailauth_dkim.rs`, `tests/fixtures/mailauth-crypto.json`, generator `tools/mailauth-fixtures.py` |
| ATPS, identity, expiry, key restrictions and body length | `tests/native_auth_limits.rs`, `tests/fixtures/native-auth-extensions.json`, deterministic generator `tools/native-auth-fixtures.py` |
| Closed-DNS SPF/DMARC and bounded failure handling | `tests/native_mailauth.rs`, `tests/native_auth_limits.rs`, `tests/fixtures/spf-reference.json` |
| Independent DKIM2/ARC, recipes, DSNs and signed refusals | `tests/native_protocols.rs`, `tests/mailauth_diff.rs`, `tests/fixtures/mailauth-protocol-reference.json` |
| Native DNS wire/cache/TCP/UDP and routing behavior | `crates/native-dns/src/lib.rs` tests and the loopback scripts |
| Unicode IDNA and NFC (IDNA checkpoint) | `crates/native-idna/tests/conformance.rs`, verbatim official files in `data/`, `data/SHA256.json`, `LICENSE-UNICODE` |
| Generated Unicode tables (IDNA checkpoint) | `python3 crates/native-idna/tools/generate.py --check`; no downloads or Python Unicode database |
| Entire dependency graph and policy | `src/security/tests.rs`, `security/dependency-policy.json`, `Cargo.lock` |
| Complete source integrity | `SOURCE-SHA256.json` and `SOURCE-SHA256` |

Executed logs and graph/license inventories are included under `validation/`.
Historical logs identify earlier checkpoints; consult VALIDATION.md for the
current results. Four PostgreSQL-dependent tests remain explicitly ignored
without their separate local database fixture.

## Independent retired-engine comparisons

The executable test fixtures above are self-contained. Re-running an independent
comparison also needs the independent implementation; it is deliberately outside
the deployed Cargo graph. The source includes the complete comparison programs:

- `tools/mailauth-protocol-oracle.rs`: generate old-engine DKIM2/ARC/SPF fixtures
  and verify native signatures using the previous source archive. The exact
  isolated-checkout commands are in NATIVE-MAILAUTH.md.
- `tools/url-compat.rs`: 106,600 HTTP URL comparisons, 256 form-byte cases and six
  setter cases against the previously pinned `url` crate.
- `tools/idna-compat.rs` (IDNA checkpoint): every Unicode scalar in three domain
  contexts, seeded mixed-script/context/normalization cases, Punycode and limits,
  against `idna` 1.1.0 with ICU 2.4.0. NATIVE-IDNA.md provides the isolated harness.

No archived third-party engine is disguised as internal code or bundled back into
the application to run these checks. Preserve the old source archive and pinned
development Cargo cache if you want to repeat those comparisons offline.

The included wrapper creates a fresh isolated harness and records its lockfile:

```sh
python3 tools/check-reference-oracles.py mailauth --reference-source /path/to/version-29/workglen --output /tmp/auth-oracle
python3 tools/check-reference-oracles.py url --output /tmp/url-oracle
python3 tools/check-reference-oracles.py idna --output /tmp/idna-oracle
```

Each output directory must be empty. All dependencies must already be cached;
these commands never fetch. IDNA/URL harnesses pin IDNA 1.1.0, adapter 1.2.2 and
ICU/data 2.4.0, prepare a separate lockfile offline, then execute with `--locked`.
The mail-auth harness copies the prior source instead of editing it. It requires
Python 3.11 or later for the standard-library TOML reader.

Tests establish the recorded synthetic behavior. They do not establish live
provider validation, independent security review or production deployment.


## MIME and IDNA security-boundary additions

The cumulative MIME ZIP includes `tests/native_mime.rs`, all fixture inputs and
old/new snapshots, generators, Unicode/WHATWG source data, notices and exact
regeneration checks. The ordinary runner now checks the MIME data generator and
MIME tests as well. The IDNA tests explicitly record that strict UTS #46 is not
full IDNA2008 or Unicode impersonation detection; see NATIVE-IDNA.md.

To reproduce the former-parser comparison in a fresh development directory:

```sh
python3 tools/check-mime-reference.py --output /tmp/workglen-mime-reference
```

Use `--cargo /path/to/cargo-wrapper` if needed. The wrapper regenerates synthetic
inputs, builds isolated pinned old/new harnesses offline, and compares every
record against the included expectations. It requires cached mail-parser 0.11.9
with full_encoding/base64_slice, its locked dependencies and serde_json 1.0.154.
The application itself does not need the former parser. An empty output directory
is required so evidence is not overwritten. Both harness locks, logs, JSONL
outputs and summary stay there. No test contacts live providers or handles real
messages; test coverage is not an independent security review.

The runner also includes the disposable Webmail API/MIME/attachment suite
(`tools/webmail-test.py`, without its optional browser mode).

The optional Python comparison behind the IDNA security assessment is portable:
`python3 tools/check-idna-security.py`. It requires development-only Python
`idna==3.19`; the application and normal native checks do not. Its Unicode 17
reference data is not used to claim full parity with our Unicode 18 engine.

To package or independently verify a source ZIP:

```sh
python3 tools/package-source.py --output ../workglen-source.zip
python3 tools/package-source.py --check ../workglen-source.zip
```

The packager rebuilds both source hash manifests and verifies every ZIP entry,
CRC and SHA-256, including exact manifest membership. Output must be outside the
source tree. It excludes build targets and Python caches.

## Native TOML checkpoint

The standard runner includes 712 official TOML 1.1 cases, 5,748 pinned former-parser
snapshots, real node/witness schema tests, limits and 20,000 mutation attempts.
`tools/generate-toml-fixtures.py` reproduces the independent oracle inputs.
The old parser is absent from the application and workspace test dependency graph.
For an independent offline rerun with the retired crates already cached:

```sh
python3 tools/check-toml-reference.py --output /tmp/toml-oracle
```

The wrapper uses shipped isolated lockfiles, checks exact fixture regeneration,
and compares both implementations to the recorded old-engine results. The ZIP
includes the MIT corpus notice, provenance/hashes, both reference driver modules,
all fixture data and executed validation logs. See NATIVE-TOML.md for parser bounds
and compatibility scope. The existing Webmail API/MIME loopback suite also runs
under the standard runner.

The standard runner now also exercises the isolated installer/generated Admin
configuration and split-process checks (10 assertions; no host installation).
To repeat the exact graph/checksum and unchanged-configuration comparison against
the preceding cumulative Tokio/source-v33 ZIP (current typed-data/charset checkpoint):

```sh
python3 tools/check-dependency-reduction.py --baseline-zip /path/to/workglen-0.8.0-native-tokio-source.zip
```

TOML fixture input regeneration and its upstream corpus hash are checked by the
standard runner; they can also run alone with
`python3 tools/generate-toml-fixtures.py --check`.

## Tokio removal and Pratique additions

The standard runner checks the tracked Pratique file hashes and includes ten
standalone socket regressions, twelve DNS tests and the real SPF/DMARC shared
outer-deadline regression. These cover IPv4/IPv6, capacity across clones/threads,
cancellation, partial I/O, peer filtering, backpressure, wrong-ID flooding and
trickled TCP fallback. `tests/pratique_async_socket.rs` includes the exact new
upstream test file; reusable tests stay with the Pratique patch.

```sh
python3 tools/check-pratique-additions.py --output /tmp/pratique-check
python3 upstream/pratique/verify.py --vendor vendor/pratique
python3 upstream/pratique/verify.py --checkout /path/to/pinned-pratique
```

The first command creates an empty disposable standalone harness, preserves all
Pratique library bytes, checks the pure feature boundary and absence of registry
dependencies, executes the ten socket tests, and lints the byte-identical new
socket module and tests with warnings denied. Its disposable manifest omits
upstream example/test entries whose sources are not in the vendor subset.
Clippy explicitly selects this harness with `--no-deps`; it does not claim to
resolve pre-existing lints across unrelated upstream Pratique modules.

The verifier checks both patch hashes and exact before/after source hashes. It
applies patches only in a temporary directory. The supplied checkout is unchanged.
See PRATIQUE-UPSTREAM.md for the tracked GitLab handoff and NATIVE-ASYNC-DNS.md for
polling and platform boundaries. Linux x86-64 was executed; native macOS sign-off
remains outstanding. The old TOML graph comparison is reproducible from its own
checkpoint ZIP and inventory, not against the subsequently reduced lockfile.

Package the separate Pratique handoff with
`python3 tools/package-pratique-upstream.py --output ../pratique-updates.zip`;
verify it again with `--check ../pratique-updates.zip`. Both paths check exact
ZIP membership, CRC and per-file SHA-256. Creation also checks the tracked
vendored tree. The cumulative source ZIP includes this tool and the handoff files.

## First-party data, JSON and charsets

The standard runner now enforces the no-external-dependency boundary for all six
reusable libraries, including manifest entries for disabled optional features.
It runs the 73,260-case frozen JSON corpus, 1,148 contracts across 51 actual
application record types, nine reusable Pratique data tests and the 2,883,056-case
charset output/error fingerprint corpus. Charset source data is regenerated
offline and compared byte-for-byte. All prior application suites remain.

```sh
python3 tools/check-first-party-dependencies.py
python3 tools/check-json-reference.py --output /tmp/json-oracle
python3 tools/check-json-rounding.py
python3 tools/check-record-reference.py --baseline-zip /path/to/native-tokio-source.zip --output /tmp/records-oracle
python3 tools/check-charset-reference.py --baseline-zip /path/to/native-tokio-source.zip --output /tmp/charset-oracle
python3 tools/check-pratique-additions.py --output /tmp/pratique-check
```

Independent former engines require their already cached registry dependencies.
They use separate frozen lockfiles and never enter the application/workspace
test graph. The record and charset wrappers pin the exact v33 baseline ZIP hash
recorded in NATIVE-DATA.md. JSON's 416 reviewed corrections are independently
checked; every unexpected difference fails. The record, TOML and charset
comparisons have zero differences. The MIME oracle preserves its earlier
explicitly reviewed parser corrections. Ordinary tests need no retired engine.

The Pratique standalone check now also runs thirteen existing signed-JSON tests,
nine new data tests, the ten socket tests and warnings-denied linting of the new
modules. The original JSON fixture is bundled with its existing Pratique
provenance. The exact three-patch series and 199 vendor hashes are verified.

To check the separately recorded Serde step against the same baseline, pass
`--inventory validation/0.8-native-data-inventory.json --after-lock validation/0.8-native-data.Cargo.lock`
to `tools/check-dependency-reduction.py`. Its default checks the combined
33-to-15 reduction. The packager verifies source hashes, ZIP CRC, entry names
and exact manifest membership. NATIVE-DATA.md and NATIVE-CHARSETS.md describe
compatibility, bounds and limitations.

## Offensive-review regressions

`python3 tools/check-resilience.py` runs the native suite followed by the local
Microsoft 365 gateway checks. Add `--browser` for the documented preinstalled
browser fixtures. It records results under `target/resilience-validation`.
See OFFENSIVE-REVIEW-REMEDIATION.md for results, remaining items and scope.
Optional `tools/check-security-fuzz.py` remains a sequential, separately prepared
development runner; further fuzzer enhancements were deferred at user request.
