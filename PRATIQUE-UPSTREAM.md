# Pratique upstream tracking

The reusable additions are tracked in [upstream/pratique/README.md](upstream/pratique/README.md).
It includes a verified three-patch series against the pinned Pratique commit:

- PRA-WG-01: the seven earlier cryptography/entropy files.
- PRA-WG-02: the five files added/changed for Tokio removal.
- PRA-WG-03: six files for typed data, JSON values/writing, a private parser entry and reusable tests.

The manifest records before/after source hashes, complete vendor hashes and
baseline provenance. `verify.py` checks application in a temporary directory,
without modifying the supplied GitLab checkout. The portable Workglen runner
checks that the vendored code still matches the tracked series.

Status: prepared for upstream review; no GitLab push or merge has been performed.
No GitLab URL or commit has been guessed. See the handoff for precise commands,
feature/API boundaries, tests and platform limitations.

## Pending filesystem-capacity addition

Workglen currently carries one additional first-party Pratique system API that is
not yet included in the verified patch upstream series:

```rust
pratique::sys::filesystem_available(path) -> std::io::Result<u64>
```

It uses `statvfs` on Linux and `statfs` on macOS to return blocks available to
the unprivileged service account. The operating-system ABI and its narrowly
documented unsafe calls stay inside Pratique's existing `sys` boundary;
Workglen's Mail Security code remains safe Rust and uses the value for
fail-closed SMTP free-space admission. Other targets return `Unsupported`.
There is no shell command, subprocess, parser or new package dependency.

Before proposing this as PRA-WG-05, the Pratique owner should confirm the Linux
and macOS ABI layouts on supported architectures, add upstream-native tests for
an existing path and an invalid path, and decide whether the stable public API
should expose available bytes or a richer filesystem-capacity record. Until
then, this is a documented local delta and `upstream/pratique/verify.py` should
not claim that the current patch series reproduces it.

## Offensive-review fuzz support

This checkpoint restores 23 byte-identical development files from the pinned
upstream commit: three public certificate fixtures and 20 manifest-referenced
example/test targets. Their source URLs and SHA-256 hashes are in changes.json
under `restored_upstream_fuzz_fixtures` and `restored_upstream_manifest_targets`
(in the upstream/pratique directory). The vendor inventory now has 222 files.
No Pratique runtime/library source or existing upstream patch changes here.
The separate Workglen fuzz workspace calls existing Pratique fuzz hooks.
No additional GitLab implementation patch is required for these restorations.
