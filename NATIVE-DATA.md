# First-party typed data and JSON

Serde and serde_json are absent from the application and workspace test graph.
Pratique now provides explicit `data::Encode`/`Decode` contracts and the
`json_value` parser/writer/value APIs needed by Workglen. JSON remains the wire
and persisted-record format. This is a replacement for the application's actual
schemas, not an implementation of every Serde attribute or API.

The Serde step removes 11 registry package versions: 33 to 22. Native charset
replacement then removes seven more, leaving 15 in the current source. The
saved intermediate lock and inventory under `validation/0.8-native-data*`
record the independent Serde reduction. No retained registry version/checksum,
installed configuration, storage key or database schema changes.

## Contracts and boundaries

- Explicit field macros preserve declaration order, defaults, optional values,
  omission predicates and unknown-field policy. Adding a struct field requires
  an explicit encoding decision. The migration ledger records 61 original
  schemas; 51 top-level decodable application types have 1,148 actual-type
  compatibility cases. Local HTTP request types also run through application
  checks. Generic maps remain sorted; typed duplicate fields remain errors.
- Pratique's existing signed JSON parser retains its strict duplicate and
  canonical-number behavior. A crate-private parser entry retains object
  members for application decoding; it does not expose duplicate objects to
  signed-document callers. Generic JSON values retain the last duplicate value,
  matching the former application engine.
- Arbitrary-precision JSON numeric tokens stay exact. Typed integers reject
  overflow. Floating-point writing uses std's shortest digits plus first-party
  formatting and exact decimal tie handling; no external formatter was copied.
- Native TOML keeps its grammar, source offsets, typed kinds and configuration
  defaults, using the new data adapter. Its ordinary tuple and tuple-variant
  behavior remains covered by pinned comparisons. TOML datetimes do not silently
  become strings when a typed string field is expected.
- Lazaret PostgreSQL's optional `with-json` feature now uses Pratique values.
  Its synthetic authentication-refusal peer sends only AuthenticationOk before
  the expected disconnect, avoiding a test-only BrokenPipe race. Authentication
  refusal itself is unchanged.

Default JSON limits are 256 MiB of input/output, 127 nesting levels and two
million value nodes. Explicit input/output limit APIs support smaller budgets.
These bound parsing and emitted output; a caller-supplied `Encode` implementation
constructs its own intermediate nodes before writing. They are not a universal
allocator cap. The pure Pratique feature forbids unsafe code; writing to an I/O
sink is available only with `net`.

## Explicitly reviewed compatibility corrections

The 73,260-case JSON comparison has 72,844 exact matches and 416 documented
corrections in `tests/fixtures/native-json-reviewed.json`:

- 414 typed f64 inputs now use correctly rounded std parsing. Exact rational
  distance to neighboring IEEE-754 values, ties-to-even checks and independent
  CPython parsing verify the results. None of the migrated application schema
  fields is f64/f32; generic JSON number access already used std parsing in the
  former implementation. Floating-point serialization matches the corpus.
- Two raw objects using Serde's private `$serde_json::private::Number` key now
  remain ordinary objects. The former engine interpreted that implementation
  marker as a numeric value, or rejected its nonnumeric payload.

These corrections are checked explicitly; unexpected differences fail the
comparison. They are not silently refreshed. The corpus includes malformed
syntax/UTF-8/Unicode, precise numbers, integers, 40,000 seeded float bit patterns,
exponent boundaries, records, duplicates and mutations. It is synthetic evidence,
not proof for every JSON document or an independent security audit.

## Portable checks and upstream tracking

The standard runner executes the frozen JSON expectations, actual record
contracts, MIME/TOML checks and application regressions. The source includes the
full independent drivers, frozen isolated locks and generation/check scripts:

```sh
python3 tools/check-json-reference.py --output /tmp/json-reference
python3 tools/check-record-reference.py --baseline-zip /path/to/native-tokio-source.zip --output /tmp/record-reference
python3 tools/check-toml-reference.py --output /tmp/toml-reference
python3 tools/check-json-rounding.py
```

Use an empty output directory and cached former dependencies. `--cargo` selects
a Cargo wrapper. The record oracle requires the exact preceding v33 ZIP with
SHA-256 `b4592aa1dc9d95c31ac5e13ec46008347fb99cfd463d1266446d9af25a4e8769`.
Former Serde/JSON engines are isolated development oracles, not dependencies of
Workglen or its reusable libraries. Same-schema binary checks use the shipped
`tools/dependency-compat-test.py` with pre/post executables and disposable data.

PRA-WG-03 and `upstream/pratique/0003-workglen-typed-data-json.patch` track the
six changed/new Pratique files, source hashes, tests and application commands.
See PRATIQUE-UPSTREAM.md. No GitLab push is implied by preparing the handoff.
