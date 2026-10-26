# Native DNS, HTTP URLs and outbound DKIM — 2026-10-25

> Historical DEPS-12 checkpoint. DEPS-13 replaces the retained mail-auth engine;
> see [NATIVE-MAILAUTH.md](NATIVE-MAILAUTH.md) and the latest catalog.

This checkpoint replaces Workglen's active `hickory-resolver` and `url` usage
and outbound DKIM signing with first-party code. **The complete `mail-auth`
replacement is unfinished.** Its attributed protocol engine still performs
inbound authentication; DKIM2 and optional ARC are preserved in that engine.
No copied upstream protocol implementation is described as first-party code.

| Area | Active implementation | Status |
|---|---|---|
| Mail/security DNS | `crates/native-dns` | Native; wired into authentication, routing and destination checks |
| HTTP(S) URL parsing and form encoding | `src/url.rs` | Native; all former application call sites switched |
| Outbound DKIM canonicalization/signing | `src/mailauth/dkim.rs`, existing Pratique RSA | Native; existing key loading/provisioning preserved |
| Inbound SPF/DKIM/DMARC | Attributed `vendor/mail-auth` with native DNS adapter | Retained pending replacement conformance |
| Native inbound candidates | `src/mailauth/{spf,dmarc,verify_dkim}.rs` | Development-only; never selected by the SMTP checker |
| DKIM2 / optional ARC | Attributed `vendor/mail-auth` | Retained; no native replacement yet |

## Dependency result

The lockfile decreases from 176 to 100 package/version entries. External
package versions decrease from 173 to **96**: 95 registry packages and the
attributed mail-auth package. Four packages are first-party: Workglen,
Pratique, lazaret-pg and workglen-dns. There are ten direct external dependencies.
No registry package is added or upgraded, and every retained registry checksum
is unchanged. The exact 77 removals are in
`validation/0.8-native-dns-url-inventory.json`.

IDNA 1.1.0 remains pinned explicitly. Complete Unicode normalization and
context validation are needed for hostnames; Pratique's smaller IDNA helper
does not provide equivalent coverage. Removing `url` does not mean removing
these Unicode tables. Tokio remains the cancellable DNS transport runtime.

## DNS behavior

The resolver implements A, AAAA, MX, TXT, PTR and CNAME lookup against the
configured recursive servers, including IPv6 reverse names and null MX.
It uses connected UDP sockets with OS-random transaction IDs, checks the
response question, and retries a truncated UDP response over TCP. Parsing
bounds names, compression jumps, record counts, packet lengths and alias chains;
unrelated answers are not accepted as the requested record set.

Default settings are three seconds per server attempt, two attempts and a
256-entry cache. Configuration validates upper bounds. Application-level
authentication/routing timeouts continue to cancel pending network work.
Positive entries expire at the shortest data/alias TTL (capped at one day).
Negative caching requires an enclosing SOA and uses its TTL/minimum, capped
at three hours. TTL zero and transient failures are not cached. NXDOMAIN,
NODATA and temporary errors remain distinct at the mail-auth adapter boundary.

Explicit resolver socket configuration is unchanged. Otherwise `/etc/resolv.conf`
provides up to three nameservers. There are no search suffixes, DNS subprocesses
or automatic public resolver fallbacks. This is a client of recursive resolvers,
not a new recursive server. Local DNSSEC validation is not implemented: the
previous application used Hickory with `validate = false`, and mail-auth's
DNSSEC result remains `Indeterminate`. The AD bit is not treated as validation.

## HTTP(S) URL behavior

The implementation covers Workglen's existing HTTP(S) call sites: parsing,
serialization, origins, credential/host/port checks, path/query/fragment setters,
and URL-form encoding. It handles IPv4 numeric forms, IPv6, Unicode hosts,
percent encoding, dot segments, default ports, backslashes and URL whitespace.
Other schemes and general-purpose relative URL resolution are outside its API.
Existing public-address/SSRF and credential restrictions remain at their call
sites; URL parsing itself does not perform network access.

`tools/url-compat.rs` compares against the former cached `url` implementation
without adding it back to Cargo. It recorded 106,600 parser comparisons, all
256 byte values for form encoding, and six setter cases with zero differences
in the exercised inputs. This finite test set is not a proof of complete
WHATWG conformance.

## Outbound DKIM and remaining authentication work

The active signer uses RSA-SHA256, relaxed header/body canonicalization, a
timestamp, no body-length truncation, and streaming body hashing. Every
occurrence of each protected header is signed, followed by one absent occurrence
to protect against insertion. Existing private-key permissions, exclusive
generation, selector files, public-key output and RSA 2048–4096-bit limits remain.
Default-suite tests independently verify new signatures with the retained
engine and reject modified bodies, altered repeated headers and added subjects.
Explicit expected-byte/hash vectors cover RFC 6376 empty bodies, whitespace,
folding and trailing empty lines. SMTP continues to reject bare-LF lines.

The native inbound candidates include bounded SPF mechanisms/macros and
recursive lookup accounting, DMARC tree discovery/alignment, and RSA/Ed25519
DKIM verification. The `native-auth-candidate` feature only makes those APIs
available for development tests; it does not switch `src/auth.rs` away from the
retained engine. The six candidate tests include independently signed fixtures,
tampering, recursive SPF, DMARC alignment and valid text-only SPF comparisons.

Known differences and gaps prevent deleting mail-auth:

- For `v=spf1 ip4:192.0.2.1/33 -all`, the retained engine returns Pass for
  192.0.2.1 while the candidate rejects the invalid prefix with PermError.
  For `v=spf1 unknown -all`, it returns Neutral while the candidate returns
  PermError. These are documented differences, not equivalent results.
- SPF macro/grammar edge cases, explanation processing, lookup accounting,
  DMARC malformed/duplicate-record handling and reporting need broader fixtures.
- The native DKIM verifier explicitly rejects ATPS; the retained engine remains
  available. DKIM2 and optional ARC are not reimplemented in the candidates.
- A broad interoperable corpus and independent review are still needed before
  replacing active inbound decisions. Passing the small candidate suite is not
  authorization to remove these protocol capabilities.

## Validation and installation boundary

Evidence is under `validation/0.8-native-*`. Tests are synthetic and local.
The default workspace suite, candidate suite, warnings-denied release Clippy,
release build, optional ARC compilation and loopback mail/delivery suites are
recorded in [VALIDATION.md](VALIDATION.md). No public mail, real mailbox removal,
live-provider validation, deployment or database/key conversion is performed.

The source ZIP is cumulative. Extract into a fresh source directory, rebuild
using the existing installer instructions, and preserve deployed configuration,
keys and data. No setting is required to enable native DNS/URLs/outbound DKIM.
Keep `native-auth-candidate` disabled for ordinary builds. The mail-auth upstream
hashes and cumulative patch remain verifiable; see
`validation/0.8-native-dns-provenance.json` and `vendor/mail-auth/WORKGLEN-PATCHES.md`.

Protocol references: [DNS RFC 1035](https://www.rfc-editor.org/rfc/rfc1035),
[negative caching RFC 2308](https://www.rfc-editor.org/rfc/rfc2308),
[SPF RFC 7208](https://www.rfc-editor.org/rfc/rfc7208),
[DKIM RFC 6376](https://www.rfc-editor.org/rfc/rfc6376),
[Ed25519 DKIM RFC 8463](https://www.rfc-editor.org/rfc/rfc8463),
[DMARC RFC 9989](https://www.rfc-editor.org/rfc/rfc9989), and the
[WHATWG URL Standard](https://url.spec.whatwg.org/).
