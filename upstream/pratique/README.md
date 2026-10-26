# Pratique changes for GitLab

Prepared October 26, 2026. These patches are ready for review/application in the
Pratique GitLab checkout. No remote repository, branch or merge request was changed.

The authoritative source baseline recovered for this comparison is
`9efaab9c010a2ca7f5ffaaf46b3b82eb50e20be4` from
`https://github.com/lazaret-dev/pratique`. GitLab may have additional commits;
check the recorded file preimages before applying. Do not force a patch across
divergent source. The series leaves omitted upstream tests/examples and all
unrelated upstream files alone; Workglen vendors only the library subset.

## Tracked additions

| ID | Patch | Purpose and actual changed files |
| --- | --- | --- |
| PRA-WG-01 | `0001-workglen-crypto.patch` | Earlier integration: strict Ed25519 verification, streaming legacy SHA-1, RSA exponent accessor, RSA-2048 generation, protected private-key PEM export, and fail-closed Linux entropy readiness. Seven files: `src/crypto/ed25519.rs`, `mod.rs`, `rand.rs`, `rsa.rs`, `rsa_generate.rs`, `sha1.rs`, and `src/sign.rs`. |
| PRA-WG-02 | `0002-workglen-async-sockets.patch` | This Tokio-removal stage: cooperative `asyncio::yield_now`, bounded nonblocking UDP/TCP sockets, cancellable TCP connect/read/write, literal-address operation and standalone socket tests. Five files: `src/asyncio/exec.rs`, `mod.rs`, `socket.rs`, `socket/connect.rs`, and `tests/async_socket.rs`. |
| PRA-WG-03 | `0003-workglen-typed-data-json.patch` | Explicit typed record contracts, bounded JSON values/parser/writer, reuse of the existing strict parser grammar and new reusable tests. Six files: `src/data/mod.rs`, `src/data/macros.rs`, `src/json_value.rs`, `src/json.rs`, `src/lib.rs`, `tests/data_json.rs`. |

Existing `block_on`, timer/timeout futures and async I/O traits are reused, not
new additions. Workglen keeps DNS wire parsing, validation, retry/cache policy and
mail authentication. Those application changes are in the cumulative Workglen ZIP,
not in the Pratique patch series. Pratique still has zero external dependencies.

`changes.json` records each stage's before/after SHA-256, patch hash, original
commit/archive provenance and the complete final vendored-file inventory. This
separates crypto, Tokio-removal and typed-data/JSON changes.
The earlier cryptography patch is included for tracking and carries its existing
review limits; this networking work is not a new cryptographic audit.

## Verify and apply

Python 3 and Git are sufficient for the non-mutating verification:

```sh
python3 /path/to/this-folder/verify.py --checkout /path/to/pratique --stage all
```

It checks exact preimages, runs `git apply --check`, applies the patches only in
a temporary directory, and verifies exact postimages. The supplied checkout is
never changed. The three patches have been verified against the pinned baseline.

If GitLab already contains the earlier crypto additions, verify only the new stage:

```sh
python3 /path/to/this-folder/verify.py --checkout /path/to/pratique --stage tokio-removal
```

On a branch in the matching Pratique checkout, apply the applicable verified series:

```sh
git switch -c workglen-pratique-additions
git apply /path/to/this-folder/0001-workglen-crypto.patch
git apply /path/to/this-folder/0002-workglen-async-sockets.patch
git apply /path/to/this-folder/0003-workglen-typed-data-json.patch
cargo test --offline --locked --test async_socket --features net
cargo test --offline --locked --test data_json --no-default-features
```

If patches 0001/0002 are already present, run `verify.py --checkout /path/to/pratique --stage serde-json-removal` and apply only 0003. If only 0001 is present, verify/apply 0002 first, then verify/apply 0003. Omit patches already present. Review and commit the resulting diff
before opening the GitLab merge request. This folder intentionally contains no
guessed GitLab URL or automatic push command. Retain LICENSE and NOTICE.

## Networking contract and limits

- `SocketBudget` bounds live UDP and pending/connected TCP sockets, shared across
  clones. Exhaustion returns `WouldBlock`; no unbounded task queue is introduced.
- Nonblocking operations yield cooperatively and retry readiness after 2 ms using
  the existing shared timer. This trades a small readiness delay and polling work
  for a small implementation; it is not an epoll/kqueue replacement or a throughput
  benchmark claim. No thread or blocking operation is created per socket.
- Dropping the owning future closes pending sockets and releases capacity. There
  is no detached connect/read/write worker or write buffer surviving cancellation.
- Wrap operations with existing `timeout`/`timeout_at` for time limits. As with the
  existing executor, synchronous CPU work is not preempted. Workglen's DNS attempt
  budget spans UDP, TCP fallback, the length prefix and full response payload.
- TCP connection initiation is implemented for Linux and macOS. Other targets
  return `Unsupported`; no silently blocking fallback is used. The OS boundary is
  small and explicitly documented. macOS sets close-on-exec and SO_NOSIGPIPE;
  Linux creates the socket with SOCK_CLOEXEC. macOS close-on-exec is a subsequent
  fcntl operation, as in APIs without atomic socket creation flags.
- Executed socket tests are Linux x86-64 only. The macOS implementation still needs
  native compile/runtime sign-off before upstream release. No Windows connector,
  production load validation or live DNS/provider test is claimed.

The ten standalone tests cover IPv4/IPv6, peer filtering, partial I/O, half-close,
capacity races, refused/dropped connects, cancellation, backpressure and trickling.
The Workglen source also includes DNS-specific wrong-ID flooding, shared attempt
deadline, cancellation/cache tests, and an overall SPF/DMARC deadline test.
`validation/` holds the recorded patch verification and `validation/standalone/`
holds the raw feature/test/lint logs and machine-readable results for this handoff. To reproduce the
independent pure-feature check and new-module Clippy check from Workglen:

```sh
python3 tools/check-pratique-additions.py --output /tmp/pratique-check
```

The disposable harness preserves all library source bytes and removes references
to upstream example/test files omitted from Workglen's library-only vendor copy.

## Typed data and JSON contract

`data` and `json_value` are std-only and compile with unsafe code forbidden when
`net` is disabled. `to_writer` is an I/O feature seam. Existing signed JSON APIs
retain strict duplicate/canonical behavior; the general application API has a
private duplicate-preserving parser entry and explicit typed duplicate policy.
Default JSON limits: 256 MiB input/output, depth 127, two million value nodes.
Caller-created Encode nodes are constructed before output checks.

The Workglen source contains 73,260 JSON comparisons and 1,148 actual-record
contracts. There are 414 independently verified typed-f64 rounding corrections
and two changes treating Serde's private marker as an ordinary JSON object key.
No migrated application schema field is floating-point. See NATIVE-DATA.md in
the Workglen ZIP for the exact scope, reviewed fixtures and portable oracle tools.
The handoff's nine data tests, thirteen existing signed-JSON unit tests, ten
socket tests, pure-feature check and new-module Clippy check all passed.
Pratique still has zero external dependencies.

## Future changes

Give each new Pratique capability a separate ID and patch, record its base and
postimage hashes in `changes.json`, add reusable tests under Pratique, and include
the updated series in the Workglen source ZIP. Update the vendored inventory and
run `verify.py --vendor vendor/pratique` as well as the portable workspace checks.
Do not mark a change upstreamed until its GitLab commit/merge request is known.

## Offensive-review fuzz support

This checkpoint restores 23 byte-identical development files from the pinned
upstream commit: three public certificate fixtures and 20 manifest-referenced
example/test targets. Their source URLs and SHA-256 hashes are in changes.json
under `restored_upstream_fuzz_fixtures` and `restored_upstream_manifest_targets`
(in the upstream/pratique directory). The vendor inventory now has 222 files.
No Pratique runtime/library source or existing upstream patch changes here.
The separate Workglen fuzz workspace calls existing Pratique fuzz hooks.
No additional GitLab implementation patch is required for these restorations.
