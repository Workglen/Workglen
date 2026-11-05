# Workglen Lazaret archive snapshot

This directory is copied from `rust/crates/lazaret-archive` at Lazaret commit
`a08bc1684abd29d13e726c014b9dee4d4eacfc20` (November 3, 2026).

The Rust source, tests, fixtures and README are unchanged. Workglen makes only
these packaging adaptations:

- standalone package metadata replaces Lazaret workspace-inherited metadata;
- the dependency named `lazaret-verify` points to the
  `workglen-lazaret-verify` compatibility facade;
- the standalone manifest allows four Rust 1.99 style-only Clippy suggestions
  so Workglen can keep the upstream source byte-for-byte unchanged; and
- Lazaret's Apache 2.0 license, native-engine NOTICE and Unicode-3.0 license are
  copied into this directory.

The compatibility facade exposes only `pratique::inflate`, the sole API this
archive crate uses from Lazaret's larger verification facade. It avoids copying
unrelated verification code and adds no third-party dependency.

Do not make behavioral fixes directly in this snapshot. Record required Lazaret
changes in `LAZARET-ARCHIVE-BACKLOG.md`, have the Lazaret owner implement and
validate them upstream, then refresh this snapshot and rerun both upstream and
Workglen product gates.
