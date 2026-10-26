# Native IDNA — DEPS-14

The cumulative checkpoint removes `idna` 1.1.0, idna_adapter and their exclusive
Unicode/ICU dependency graph: **79 to 54 external package versions**. Including
the completed mail-auth stage, that is **42 fewer than the former 96**. There
are 59 lockfile entries: 54 registry packages and five first-party packages.
No registry package is added or upgraded; retained checksums are unchanged.

First-party `workglen-idna` now serves native DNS and HTTP URL parsing, and thus
the authentication domain lookups. It implements UTS #46 mapping, NFC canonical
normalization, combining-mark validation, bidi and ContextJ checks, and A-label
validation. Punycode reuses the existing first-party Pratique implementation.
The older conservative Pratique hostname helper is not substituted for UTS #46.

The former ICU 2.4.0 data and this implementation both use **Unicode 18.0.0**.
Verbatim official Unicode data and test files, their hashes, the deterministic
offline generator and the Unicode License v3 are included in `crates/native-idna`.
This removes Rust crates, not the Unicode data or its attribution obligations.
No ICU/IDNA implementation source is copied or renamed as first-party code.

Default processing preserves nontransitional conversion with joiner and bidi
checks. URL forbidden-host-character checks and DNS wire-length checks remain
at their existing call sites. Added resource limits reject input domains above
64 KiB; legal DNS names are smaller. Punycode retains the former 1000-scalar
encode and 2000-byte decode limits. Normalization uses stable sorting for long
combining sequences. See the crate README for API and buffer limits.

## Portable evidence

- 19,182 official IDNA checks: Unicode, nontransitional ASCII and transitional
  ASCII outputs/validity across the official corpus. Two isolated-surrogate
  source rows are counted as skipped because Rust strings cannot represent them.
- 20,171 official normalization rows, totaling 100,855 NFC assertions.
- 3,456,617 comparisons against pinned IDNA 1.1.0 / adapter 1.2.2 / ICU 2.4.0,
  including every Unicode scalar in three domain contexts, mixed-script cases,
  A-labels, malformed Punycode and limits. Zero mismatches in the exercised inputs.
- The existing 106,600 URL comparisons, all 256 form bytes and six setter cases
  exercise the same URL API after the IDNA switch.
- Exact regeneration checks verify both generated Rust tables and input hashes.

The portable runner additionally covers the whole workspace, optional ARC,
Clippy, release build, and local SMTP/DKIM/IMAP flows. Complete commands and
prerequisites are in [PORTABLE-CHECKS.md](PORTABLE-CHECKS.md). To repeat the two
independent comparisons, use its isolated `check-reference-oracles.py` wrapper.
The old libraries stay outside the application's dependency graph. No build or
test fetches data at runtime; caches must be prepared beforehand.

The tests establish recorded protocol behavior and finite comparison coverage;
they are not a claim of independent security review. The Rust implementation,
official tables, fixtures, generators, comparison tools and recorded results
all travel with the source ZIP. No installed data, key or configuration changes
and no production deployment are performed.

Specifications and data provenance are listed in `crates/native-idna/README.md`.

## Security capability boundary

Python `idna` describes protection from vulnerable domain forms relative to the
older IDNA2003 codec. This means Unicode protocol validation, not a maintained
list of malicious domains. Our current UTS #46 profile enforces normalization,
leading-mark, disallowed-code-point, ContextJ, bidi and A-label rules. It is
compatible with the former Rust IDNA profile, not Python's full IDNA2008 profile.

| Capability | Current native engine |
| --- | --- |
| NFC, UTS #46 mapping and prohibited characters | Implemented |
| Bidi and contextual joiner validation | Implemented by default |
| STD3 syntax, hyphen and DNS length rules | Available through `domain_to_ascii_strict`; DNS/URL callers also enforce their own rules |
| IDNA2008 PVALID and ContextO | Not implemented |
| Unicode confusables / impersonation detection | Not implemented |
| Live malicious-domain reputation feed | Not implemented; configured domain blocking is separate |
| Resource bounds before expensive processing | Implemented; regression inputs included |

For example, both native helpers accept `a·b.test` and emoji labels; Python's
IDNA2008 validator rejects them. Both permit `l·l.test`. A Latin/Cyrillic lookalike
such as `раypal.com` can pass either library: protocol validity is not trust.
`strict` in our current function name denotes stricter UTS #46 options only.
The optional `tools/check-idna-security.py` reproduces selected Python 3.19
examples; its Unicode 17 data is not a whole-version oracle for Unicode 18.
The test `security_boundary.rs` records these distinctions and oversized
contextual-sequence rejection. It does not claim phishing detection efficacy.

Deferred policy backlog (SEC-IDNA-04 in MAIL-SECURITY-BACKLOG.md),
not part of the next crate-reduction work:

1. An explicit IDNA2008 eligibility/ContextO validation profile, using pinned
   Unicode data, for provisioned domain names. Keep browser-compatible URL
   normalization available for inspecting received content.
2. A separate UTS #39 confusable skeleton and script-risk check against configured
   protected domains. Report Unicode and canonical ASCII forms together; do not
   treat all multilingual names as malicious or substitute skeletons for DNS
   lookup, authentication alignment or authorization identity.
3. Keep reputation/blocking as separately audited policy. Any future feed needs
   provenance, freshness and failure behavior; no feed is enabled here.

Sources: [Python project description](https://pypi.org/project/idna/),
[Python validation API](https://github.com/kjd/idna/blob/master/idna/core.py),
[RFC 5892](https://www.rfc-editor.org/rfc/rfc5892.html),
[UTS #39](https://www.unicode.org/reports/tr39/), and
[bounded-input advisory](https://github.com/kjd/idna/security/advisories/GHSA-65pc-fj4g-8rjx).
