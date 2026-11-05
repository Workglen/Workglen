# Lazaret archive upstream backlog

Updated: November 3, 2026. Owner: Lazaret project agent.

This file records changes that belong in Lazaret. Do not patch Workglen's
vendored snapshot to implement them. Land and validate them in Lazaret first,
then refresh the pinned Workglen snapshot. ZIP is explicitly out of scope:
Workglen retains its existing ZIP reader and there is no request to add ZIP to
`lazaret-archive`.

## LAZ-ARCHIVE-WORK-01 — Cooperative decoder work budget

**Priority:** Security hardening before claiming a strict processing-time bound.

The current API bounds entries, member bytes, total output, names and metadata,
but a synchronous extraction call cannot be interrupted by Workglen's
five-second scanner deadline. Add an optional deterministic operation/work
budget or a cooperative cancellation callback checked inside container and
decoder loops. Exhaustion must return `Error::Limit`, return no partial archive
and behave identically across native and WebAssembly builds for the same input
and budget. Cover high-cost valid inputs, malformed inputs, exact-boundary
success, chunk/folder loops and every supported decoder.

## LAZ-ARCHIVE-RAR-01 — Prioritized compressed RAR subset

**Priority:** Coverage expansion after attachment-demand measurement.

RAR4/RAR5 stored members are supported; ordinary compressed RAR remains
administrator-only quarantine in Workglen. Select and document compression
methods from observed mail demand, implement them under the member/total/work
budgets, and add independently generated interoperability, corruption,
truncation and decompression-bomb fixtures. Solid, encrypted, split/multi-volume
and special-entry behavior must remain explicit; do not advertise blanket RAR
support when only a subset is inspectable.

## LAZ-ARCHIVE-RUST-01 — Rust 1.99 Clippy style cleanup

**Priority:** Low; no behavioral or security defect is established.

Workglen's Rust 1.99 `-D warnings` gate suggests `is_multiple_of` in BZIP2,
TAR and XZ code, `div_ceil` in a 7-Zip test helper, and expression-based
initialization in LZMA decoding, plus struct-update initialization in one
archive regression test. Apply those mechanical changes in Lazaret,
run its debug/release/WebAssembly archive gates, and then remove Workglen's
four manifest-level lint allowances on the next snapshot refresh.
