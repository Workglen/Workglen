# workglen-toml

First-party bounded TOML 1.1 reader with owned Serde deserialization.
See [NATIVE-TOML.md](../../NATIVE-TOML.md) for scope, limits, provenance and checks.
Run `cargo test --offline --locked -p workglen-toml` from the source workspace.
No upstream parser implementation is included. The separate official test data
retains its MIT notice under `tests/fixtures/toml-test/LICENSE`.
