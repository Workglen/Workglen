# 0.8 native Mail Security review boundary

The runtime has moved into the Workglen Rust executable. Local validation covers native rule lifecycle, archive/attachment policy, scopes, digests, replay protection, TLS delivery, central control of two instances and held-content preservation before IMAPS/EWS removal. The test results are implementation checks, not an independent audit. Graph still needs live-provider validation. Native heuristic and policy scanning does not provide comprehensive malware detection. Existing first-party TLS code remains within its prior unaudited boundary. See security/README.md and VALIDATION.md.

## Native storage encryption

Mail Security now uses authenticated encrypted redb storage with supplied or generated 256-bit keys. All database content, journal frames and compaction files are encrypted. Wrong keys and authenticated corruption fail closed; crash recovery and compaction have synthetic tests. Whole-file rollback, host compromise, and a disk image containing both database and key remain outside that guarantee. The first-party storage container requires independent review and broader power-failure/performance validation. Other modules are not automatically encrypted. See [security/ENCRYPTED-STORAGE.md](security/ENCRYPTED-STORAGE.md).

# Direct delivery and Webmail additions — 0.5

Implementation self-check only; not an independent audit. Direct MX routing bounds
DNS/candidate work, blocks special-use destinations by default, detects own-MX
loops, verifies STARTTLS certificates/names and does not downgrade a failed
STARTTLS connection. Command/capability parsing, post-TLS state reset, signed-byte
stability and ambiguous acknowledgments have loopback regression
coverage. DKIM private keys must be protected RSA-2048..4096 PEM files; generation
is exclusive and mode 0600. Public TXT output contains no private key material.

Webmail uses a distinct listener/origin/cookie, mailbox-only sessions, bounded
password work/sessions/HTTP bodies, Host/Origin/CSRF checks and CSP. Account scope
comes from the authenticated session. Password changes invalidate sessions on the
next request. Mailbox references include UIDVALIDITY; mutation transactions recheck
primary ownership, module state and credentials. Sent and delivery entries commit
atomically, with aggregate quota checks and bounded idempotency receipts. Message
HTML becomes text; attachment bytes download rather than execute inline. Existing
untrusted attachment and underlying TLS implementation risks remain.

The local harness covers account scope, stale references, module lifecycle,
password-reset revocation, send replay, MIME/header injection, quota rollback,
pagination, no remote-image requests, and desktop/mobile browser behavior. Shared
module state is exercised through replication, promotion and replacement. This
work does not establish live deliverability, general webmail conformance,
production-scale concurrency, antivirus protection or an independent security
review. See DIRECT-MAIL.md, WEBMAIL.md and VALIDATION.md for exact limits.

# Accounting additions — 0.4

This is an implementation self-check, not an independent audit. Accounting enforces
verified PostgreSQL TLS; bounded connection pools and requests; exact minor-unit
amounts; balanced immutable posted journals; period locks; parameterized SQL;
hashed previews and replay protection. Writes acquire a book row lock under
READ COMMITTED so a waiter observes preceding payments; report reads use a
repeatable snapshot. Bank feeds stage data without automatic posting.

SimpleFIN uses fixed HTTPS provider hosts, no redirects, encrypted access tokens
scoped to workspace/book/connection, shared database polling leases, bounded
responses, and explicit review of source corrections. Disconnect invalidates an
in-flight setup/sync. Web accounting actions inherit authenticated sessions and
CSRF/origin checks. No bank credentials are collected.

Remaining validation: native PostgreSQL concurrency and managed-service failover,
live SimpleFIN/Chase coverage, financial reporting review, scoped financial roles,
and the existing Pratique cryptography/server review. Xero completeness depends
on operator-supplied exports. CSV without stable IDs cannot reliably deduplicate
all partial overlapping exports. Full limitations are in ACCOUNTING.md.

# Mail review response — Workglen Mail 0.3

The supplied `OFFENSIVE-REVIEW-portmail-0.2.0.md` reviewed the earlier mail
implementation. Its two availability findings also applied to the initial
Workglen code. This document records the changes; it does not reinterpret the
review as a security certification or claim that its full external battery was
re-run. The original review is not modified.

| Finding | Resolution | Regression coverage |
|---|---|---|
| F-1: accepted MIME boundary flood breaks later mailbox commands | Moved the raw MIME budget into common message validation before SMTP acceptance or parsing. MX, submission and IMAP APPEND now reject it. Also validate parsed MIME part count and the same nesting ceiling used by BODYSTRUCTURE, covering a related deep-nesting failure. | Real SMTP MX/submission rejection, APPEND refusal, unchanged stored-message count, successful subsequent bulk BODYSTRUCTURE and header SEARCH; unit tests for boundary floods, excessive nesting and valid multipart mail |
| F-2: one client's login attempts exhaust a global web budget | Use actual socket-peer IP buckets, canonicalizing IPv4-mapped IPv6 addresses. Each source has 20 valid-shaped credential attempts per 60-second window; malformed bodies consume no password-attempt allowance. Do not trust forwarding headers. | Separate loopback client IPs: one becomes throttled while another signs in; spoofed forwarding headers do not evade throttling; malformed requests do not block subsequent login; unit tests cover expiry and the bounded table |
| F-3: oversized SMTP command closes silently | A typed bounded-reader error allows SMTP to send `500 5.5.2 Command line too long`, then close. It does not drain an unlimited line or parse the suffix as another command. | Oversized NOOP receives 500, that connection closes, a new SMTP connection still works |

## Scope and operating behavior

- The common cheap boundary-marker guard runs before full MIME parsing; parsed
  messages have a 1,024-part ceiling and the same 32-level nesting ceiling as
  IMAP BODYSTRUCTURE. Existing read-time checks remain as defense in depth.
  This is a resource/representability limit, not a malware scanner or a full
  MIME conformance validator. Conservative limits may reject unusually complex
  legitimate messages.
- The login table holds at most 1,024 active source buckets and expires them
  after the window. At capacity, a previously unseen source is temporarily
  refused; existing buckets retain their allowance. A distributed flood can
  still exhaust shared resources. This is not general DDoS protection.
- Clients behind the same NAT, SSH tunnel or reverse proxy share its visible
  source bucket. Proxy address attribution is deliberately not inferred from
  untrusted `Forwarded` or `X-Forwarded-For` headers. A trusted-proxy scheme
  would require explicit configuration and tests before use.
- Only one expensive password operation runs at a time. A web sign-in returns
  a short 503/Retry-After when that slot is occupied instead of queueing all web
  handlers behind hashing. The local authenticated admin CLI remains separate.
- No accepted mail is rewritten or purged. There are no live legacy systems to
  repair; these changes prevent the reproduced acceptance-path poisoning in
  new Workglen installations. Restoring externally edited/unvalidated databases
  is outside the supported ingestion path.
- The added harness tests run against loopback services that the harness starts
  itself. They do not silently skip when a manually configured server is absent.

See `VALIDATION.md` and `validation/integration-results.json` for the final run.
Pratique's experimental/unaudited TLS status, actual Outlook testing, full IMAP
conformance and broader production assurance remain unchanged limitations.
