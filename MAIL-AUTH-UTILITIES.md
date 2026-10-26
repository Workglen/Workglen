# Mail-auth utility replacement checkpoints

These changes implement DEPS-07, DEPS-08 and DEPS-09 in order, with a complete
cumulative source ZIP for each completed step. The pinned upstream mail-auth
package remains attributed third-party code. Configurations, keys, database
formats, inbound authentication policies and supported protocols are preserved.

## DEPS-07: unused hostname feature

The native-target mail-builder dependency now uses `default-features = false`,
matching the existing WebAssembly declaration. Mail-auth's active production
calls use its Base64 encoder, not hostname discovery or message generation.
This removes gethostname 1.1.0, rustix 1.1.5, errno 0.3.14 and linux-raw-sys
0.12.1: **182 to 178 external package versions** (177 registry plus mail-auth).
The encoder remains for the next checkpoint. No retained registry version or
checksum changes; no new package is added.

Validation results and the reviewed graph are in `validation/0.8-native-hostname-*`.
The upstream patch is regenerated and reapplied against verified original source.
The normal four opt-in database tests require a disposable PostgreSQL fixture
and are not part of the automatic offline test count.

## DEPS-08: Pratique Base64 replaces mail-builder

The two active mail-auth encoder imports now use a first-party adapter backed
by Pratique. It preserves padded Base64, complete four-byte output groups,
short-buffer behavior and untouched bytes beyond the returned length. Encoding
uses 192-byte input chunks, keeping each temporary encoded string at 256 bytes.
Header folding remains in the existing mail-auth code. Disabled upstream report,
key-generation and upstream-test source remains for provenance; it is not built
by the deployment manifest.

This removes mail-builder 1.0.0: **178 to 177 external package versions**
(176 registry plus mail-auth). No new dependency or retained version/checksum
change. A development-only oracle compared the former pinned encoder against
the adapter across **53,261** binary input/output-capacity cases, including
padding, truncation and sentinel preservation. Its source is
`tools/mailbuilder-compat.rs`; the former library is not shipped or required
by Workglen. The log is `validation/0.8-native-mailbuilder-compat.txt`.

## DEPS-09: bounded native DKIM2 recipe generation

First-party `vendor/mail-auth/src/dkim2/native_diff.rs` replaces similar's one
active diff call. It computes copy/insert instructions with a bounded shortest
insert/delete search; deletions require no emitted data. DKIM2 remains enabled.
This removes similar 3.2.0 and its exclusive bstr 1.13.1 dependency:
**177 to 175 external package versions** (174 registry plus mail-auth).
No dependency is added; retained versions and checksums stay unchanged.

Generation bounds are explicit: at most 64 MiB combined original/modified raw
message bytes, at most 200,000 combined headers/body-line slots (conservative
line counting), edit distance at most 512, 2,000,000 search work units and
64 MiB of compared line bytes shared across all header groups and the body.
The retained traceback matrix is bounded to about 4.1 MiB on a 64-bit host;
input, generated literals, header maps and reconstruction buffers are additional
bounded allocations. This is not a total-process memory or 1 GB host benchmark.

When the search limit is reached, generation falls back to a linear literal
recipe. The final recipe is applied and its canonical SHA-256 header/body hashes
must match the original. Unrepresentable lossy UTF-8 literals or oversized inputs
use DKIM2's existing `Unreconstructable` (`"b": null`) representation; generation
never labels a corrupted reconstruction as successful. These are generation
limits, not changes to SMTP acceptance/quarantine or installed storage formats.
Existing valid recipe JSON remains readable. Invalid copy indices outside the
32-bit range now reject instead of wrapping. The existing forward-compatible
handling of unknown/scalar recipe steps is preserved.

Different shortest scripts are possible for repeated lines. The old/new oracle
compared 5,000 synthetic message pairs: **1,396 generated JSON recipes were
byte-identical and 3,604 used different valid scripts**. All **20,000 canonical
reconstruction checks** passed, including new recipes read by the previous
implementation and previous recipes read by the new implementation. Both readers
produced identical reconstructed bytes for each recipe. The JSON wire format is
unchanged; newly generated signed bytes are not promised to match the former
algorithm's output. See `tools/dkim2-diff-compat.rs` and
`validation/0.8-native-diff-compat.txt`.

The root regression suite additionally checks all 14,641 short sequence pairs
against an independent LCS oracle, 2,000 seeded binary/repeated-line cases,
folded/repeated headers, Unicode, empty messages, literal fallback, binary
reconstruction, malformed recipes and generation limits. A synthetic signed
originator/forwarder DKIM2 chain exercises both ordinary and fallback recipes,
with closed DNS fixtures and tampered-body rejection. These fixtures are not
validation against a live third-party DKIM2 service.

See [DEPENDENCY-CATALOG.md](DEPENDENCY-CATALOG.md) for every remaining crate's
purpose and the companion JSON for its resolved parents/features.

## Installation

Extract the desired full source checkpoint and run `bash install.sh build` as
the normal build user. Follow the existing Mac/Lightsail stop, binary replacement
and restart instructions; keep installed configuration, storage/DKIM keys and
databases. Tests are synthetic/local; no live host or Microsoft 365 tenant is
modified by these checkpoints.

**Executed `hostname` checkpoint:** 152 offline locked Rust tests, release
Clippy with warnings denied, release build and 54 direct-delivery/DKIM checks
passed on Linux x86-64 with Rust 1.99.1. Four opt-in database tests skipped.

**Executed `mailbuilder` checkpoint:** 154 offline locked Rust tests, release
Clippy with warnings denied, release build and 54 direct-delivery/DKIM checks
passed on Linux x86-64 with Rust 1.99.1. Four opt-in database tests skipped.

**Executed `native-diff` checkpoint:** 164 offline locked Rust tests, release
Clippy with warnings denied, release build and 54 direct-delivery/DKIM checks
passed on Linux x86-64 with Rust 1.99.1. Four opt-in database tests skipped.
