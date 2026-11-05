# Native TOML — DEPS-16, October 26, 2026

The first-party `workglen-toml` crate replaces `toml` in node configuration,
witness configuration and dependency-policy tests. It uses explicit first-party typed
schemas, defaults, enums, optional fields and unknown-field rejection. Installed
configuration files and setup output retain their format; no migration, key
replacement or data rewrite is introduced. Parser implementation is original
Rust; no former TOML implementation is copied or vendored.

## Scope and bounds

The reader implements TOML 1.1 tables, arrays of tables, dotted/quoted keys,
basic/literal/multiline strings, Unicode escapes, numbers, booleans, arrays,
inline tables and date/time values. This includes 1.1 optional seconds, `\e`,
`\xHH`, and multiline/trailing-comma inline tables. It rejects duplicate keys,
conflicting tables, malformed numbers/escapes and invalid calendar values.
An initial BOM, table-definition rules and the former typed schema behavior follow the
pinned former parser, including its rejection of overflowed decimal floats.
Explicit `inf` and `nan` remain supported.

`from_str` takes valid UTF-8 and returns an owned first-party Decode value. `Value` supports
the table/array/string inspection and serialization needed by the dependency
policy. Date/time values are distinct from strings, normalized with nanosecond
precision, truncating additional fractional digits as the former parser does.
This is a configuration reader, not a TOML writer, editing API or borrowed-value
replacement for every upstream public API; those APIs were unused here.

Default bounds: 8 MiB input, depth 64, 100,000 combined key/value operations,
and 64 KiB per decoded key. `from_str_with_limits` allows explicit budgets with
a hard depth ceiling of 128. Oversized configurations now fail with an error.
Errors include line, column and a typed field path where available. Existing
application configuration validation still runs after deserialization.

## Dependency result

External package versions: **51 → 41**, with **48 total lock entries**, including
seven first-party packages. Direct external crates: **7 → 6**. Across the
mail-auth, IDNA, MIME and TOML stages, **55 of the 96 external versions are gone**.
No registry additions, upgrades or retained checksum changes.

Removed: toml 0.9.12+spec-1.1.0, toml_datetime 0.7.5+spec-1.1.0,
toml_parser 1.1.5+spec-1.1.0, toml_writer 1.1.3+spec-1.1.0,
serde_spanned 1.1.2, indexmap 2.14.2, hashbrown 0.17.1, equivalent 1.0.3,
winnow 0.7.15 and winnow 1.0.4. This was the TOML-only checkpoint; subsequent first-party typed-data work removes Serde too. See NATIVE-DATA.md.
The former parser is only referenced by an isolated optional development oracle;
it is absent from application, workspace-test, build and platform dependencies.

## Portable checks and provenance

Run the complete source checks with `python3 tools/check-native-replacements.py`.
The workspace tests include:

- 712 official TOML 1.1 corpus cases: 218 accepted and 494 rejected.
- 5,748 pinned former-parser snapshots: that corpus, 26 pinned former-Serde contracts,
  six shipped configurations, four edge cases and 5,000 seeded mutations.
- Resource limits, duplicate definitions, type/error paths, actual node/witness
  schemas, and an additional 20,000 deterministic mutation attempts.
- The complete dependency allowlist and existing application regression suite.

Fixture bytes and upstream expected values come from
[toml-lang/toml-test](https://github.com/toml-lang/toml-test), commit
`ff49d109861c1ad25af53f687f2aef19ab650600`, manifest `files-toml-1.1.0`.
`tests/fixtures/toml-test/provenance.json` records archive and fixture hashes;
the MIT notice is preserved in that directory. Only test data is incorporated.
Grammar reference: [TOML 1.1](https://toml.io/en/v1.1.0).

The optional independent comparison requires the already cached retired crates:

```sh
python3 tools/check-toml-reference.py --output /tmp/toml-oracle
```

This regenerates inputs and runs former/native harnesses with shipped isolated
lockfiles, `--offline --locked`, and no production network or configuration.
Recorded snapshots run without the retired dependency. Comparison results cover
these fixtures, not every possible TOML document. See VALIDATION.md for executed
results and `validation/0.8-native-toml-*` for logs and the exact graph difference.

F5's opt-in mixed-script heuristic is separate; full IDNA2008 and UTS #39 confusable policy remain deferred under SEC-IDNA-04.
