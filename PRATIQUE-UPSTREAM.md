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

## Offensive-review fuzz support

This checkpoint restores 23 byte-identical development files from the pinned
upstream commit: three public certificate fixtures and 20 manifest-referenced
example/test targets. Their source URLs and SHA-256 hashes are in changes.json
under `restored_upstream_fuzz_fixtures` and `restored_upstream_manifest_targets`
(in the upstream/pratique directory). The vendor inventory now has 222 files.
No Pratique runtime/library source or existing upstream patch changes here.
The separate Workglen fuzz workspace calls existing Pratique fuzz hooks.
No additional GitLab implementation patch is required for these restorations.
