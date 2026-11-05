# Crate reduction order — updated November 3, 2026

Current baseline: **15 external package versions**, three direct external crates,
24 lockfile entries including nine first-party packages. All eight reusable
first-party libraries have zero external dependencies, enforced by a portable
manifest/graph check. F5 adds an opt-in mixed-script risk heuristic; full
IDNA2008 and UTS #39 confusable policy remain deferred under SEC-IDNA-04.

| Completed replacement | Packages removed | Remaining external versions |
| --- | ---: | ---: |
| Native TOML/configuration parsing | 10 | 41 |
| Pratique DNS transport, removing Tokio | 8 | 33 |
| First-party typed data/JSON | 11 | 22 |
| Native MIME charset decoding | 7 | 15 |

The remaining graph belongs to the root application: Argon2/password hashing,
redb storage and subtle constant-time comparisons. Further reduction needs a
separate review of these security/storage boundaries. None is replaced by this
update. See NATIVE-DATA.md and NATIVE-CHARSETS.md for the completed work.
The sections below retain the earlier implementation rationale.

### 1. TOML complete — historical implementation plan

Production use is confined to `Config::load` in src/config.rs and witness
configuration loading in src/witness.rs. Security policy tests now use
`workglen_toml::Value` to parse Cargo.toml and Cargo.lock; leaving TOML as a test dependency
would prevent the promised removal. Keep the pinned reference implementation in
an isolated development oracle outside the application graph.

Replace parsing while retaining the existing configuration schema, validation,
defaults, enum handling, unknown-field rejection and installed file formats.
Keep Serde for existing typed deserialization if useful. Test quoted/multiline
strings, escapes, arrays, tables/arrays of tables, dotted keys, numbers and
malformed input; reject duplicate/redefined keys and tables as required by the
applicable TOML grammar. Compare against the currently pinned parser, including
its actual dialect/features, rather than silently shrinking supported syntax.
Use the current TOML specification at https://toml.io/en/v1.1.0 as a reference;
any version-policy difference must be explicit and compatible with saved files.
Exercise setup/install-generated configurations and both service types.

The ten removable package versions are toml, toml_datetime, toml_parser,
toml_writer, serde_spanned, indexmap, hashbrown, equivalent, and both winnow
versions. Serde and its shared macro packages remain. TOML already disables
default features and enables only std/serde/parse, so there is no unverified
feature-toggle saving counted in this recommendation.

### 2. Tokio complete — implementation boundary

Pratique now supplies native DNS UDP/TCP sockets, I/O, executor and the
outer authentication/lookup timeouts. The new reusable additions are tracked in
PRATIQUE-UPSTREAM.md; NATIVE-ASYNC-DNS.md records validation and platform limits. The rest of the mail service already uses
blocking standard-library/Pratique transports. The implemented replacement reuses
that architecture and preserves absolute deadlines across retries and TCP
fallback, response validation, concurrency limits and timely cancellation.
Merely running blocking calls inside an async wrapper would break outer timeout
semantics and is not an acceptable replacement. Retain slow/trickle-response,
wrong-transaction, cancellation and concurrent-request loopback tests.

Verified removals: tokio, bytes, mio, pin-project-lite, socket2, wasi,
windows-link and windows-sys. libc remains shared with Argon2/redb.

### 3. Charset decoding complete

The implementation replaces encoding_rs and six exclusive support packages, preserving
all currently accepted MIME labels and multibyte/stateful decoding behavior.
The new MIME corpus supplies a starting point, but empty-input label recognition
and 33 single-byte sweeps are not sufficient to prove complete charset parity.
Add independent Japanese, Chinese, Korean and stateful/malformed-input corpora;
retain Unicode/WHATWG data provenance, bounded decoding and incomplete-scan flags.
Do not reduce support to UTF-8 or relabel third-party implementation code.

Verified removals: encoding_rs, cfg-if, core_detect, multiversion_no_op,
rustversion, scopeguard and simdutf8. The current encoding_rs feature set is
alloc/default; no additional feature-only reduction is claimed here.

## Retain for now

- Argon2: 12 packages are exclusive, but this is the password-hashing boundary.
  Pratique currently has no equivalent Argon2 implementation. Any future change
  must preserve existing PHC hashes and algorithm/parameter behavior, with
  independent vectors and security review. Replacing it is not the next task.
- redb: only one exclusive package, with substantial transactional durability,
  recovery, encrypted-storage and backup risk. Poor near-term reduction value.
- subtle: retain the reviewed constant-time comparison boundary unless an
  equivalent first-party implementation receives independent security review.

Serde/JSON was an earlier retention recommendation and has since been replaced;
see NATIVE-DATA.md. It is not part of the current dependency graph.

## Reproduce the counts

```sh
python3 tools/analyze-crate-reduction.py
```

This standard-library script traverses the pinned dependency graph and preserves
shared dependencies. Historical results and baseline Cargo.lock hashes are in
validation/0.8-next-crate-reduction-projections.json (51 packages),
validation/0.8-post-toml-reduction-projections.json (41 packages) and
validation/0.8-post-tokio-reduction-projections.json (33 packages). The current
15-package baseline is defined by Cargo.lock and DEPENDENCY-CATALOG.md. Confirm
counts with Cargo metadata/lockfile checks when another implementation lands.
