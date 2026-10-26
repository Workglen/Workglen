# Direct delivery and DKIM — Workglen 0.5

Workglen can deliver directly to each recipient domain's MX hosts. It remains the
inbound MX gateway, mailbox server and authenticated submission server. Direct
mode does not need SES or another outbound relay. It does require a host whose
provider permits outbound TCP port 25, suitable public IP addresses, working DNS
and operator-managed sender reputation. These changes have only been tested with
local synthetic peers; this release is experimental and has not been independently
audited. Successful local tests do not establish public inbox deliverability.

## Configuration

Start from `config/direct.toml`, or remove the entire `[relay]` section from your
existing node configuration and add:

```toml
[dkim]
selector = "mail2026"
key_file = "/etc/workglen/dkim-mail2026.pem"

[direct]
tls = "required"
own_addresses = ["YOUR_PUBLIC_IPV4", "YOUR_PUBLIC_IPV6"]
# ca_file = "/etc/ssl/certs/ca-certificates.crt"
# port = 25
# retry_seconds = 1800
```

Replace the address placeholders with real IP literals; omit IPv6 if you do not
operate it. Include the public addresses of **both** nodes in a replicated pair.
The same owned addresses should be listed on both nodes. `hostname` is used for
SMTP EHLO and loop detection, and `domain` is the DKIM signing domain. Direct and
relay configuration are mutually exclusive. Direct mode requires a usable DKIM
key; startup fails if it cannot be loaded. Existing relay configurations continue
to work, and adding `[dkim]` also enables local signing with a relay.

The default OS certificate authority store validates outbound TLS certificates.
A custom `ca_file` must validate destination MX names. `tls = "required"` defers
mail to hosts without STARTTLS; this is stricter than common opportunistic SMTP.
Choose `tls = "opportunistic"` explicitly if delivering to plaintext-only MTAs is
acceptable: it permits plaintext only when STARTTLS is absent. Advertised STARTTLS
that fails, has an invalid certificate or leaves injected bytes is never silently
downgraded on that connection. Other eligible MX hosts can still be attempted.
This is not MTA-STS, DANE or DNSSEC-authenticated routing.

Private, loopback, link-local, documentation, multicast and other special-use
addresses are refused by default, including IPv4-mapped IPv6. The
`allow_private_addresses = true` option exists for controlled private networks and
loopback tests, removes that protection, and should remain false for Internet mail.
A nonstandard `port` is useful for test fixtures; Internet MX delivery uses 25.

## Generate and publish a key

After installing your node configuration, create the private key in a protected
directory. The command creates a new mode-0600 RSA-2048 PEM and prints its **public**
DNS TXT record. It refuses to overwrite an existing file.

```sh
sudo workglen dkim-generate /etc/workglen/node.toml
sudo chown workglen:workglen /etc/workglen/dkim-mail2026.pem
sudo chmod 600 /etc/workglen/dkim-mail2026.pem
sudo -u workglen workglen dkim-dns /etc/workglen/node.toml
```

Publish the generated TXT at `mail2026._domainkey.YOUR_DOMAIN`. The CLI uses BIND
syntax with multiple quoted chunks; DNS providers that accept one text value may
need the concatenated value without the zone-file wrapper. Never publish, paste
into DNS or include the private PEM in an ordinary source backup. Keep a separate
encrypted operational backup. External RSA keys between 2048 and 4096 bits are
accepted with the same protected-file requirements.

For two nodes, securely install the same private key and selector on each, or use
separate node selectors with both public records published. Keys are node-local
configuration, not replicated database contents. Signed queue payloads are
replicated and retain their original signatures across retries and failover.

For rotation, generate a different selector and key file, publish its TXT, wait
for DNS availability, update both nodes and restart. Keep the old public TXT until
all messages signed with it have left the queue and relevant DNS/cache windows
have passed. Failed queue records are retained, so inspect them before retiring
old keys. Do not overwrite a key behind an existing selector without a rotation
plan. Signing happens at submission before the message is committed to the queue.
Queued bytes are preserved across retries and configuration changes; there is no
conversion of old queue formats. Drain any unsigned relay queue before changing to
direct delivery, which requires signed queue entries.

## DNS and network checklist

Use your own domain and addresses. This source package makes no DNS changes.

- Publish A records for the mail host. Publish AAAA only if IPv6 routing, port 25,
  firewall policy and reverse DNS all work.
- Publish the domain's MX record pointing at the mail hostname, not a literal IP.
  Both inbound and outbound routing need to reach an active Workglen primary.
- Ask the IP provider to set PTR/reverse DNS to the mail hostname; ensure the
  forward A/AAAA resolves back to the same IP. Use a consistent SMTP hostname.
- Publish SPF authorizing every IP that actually sends, including either node that
  can become primary. Start DMARC monitoring deliberately, for example a `p=none`
  policy, and review results before enforcing rejection. A reporting address must
  exist and be operated by you if included in DMARC.
- Publish DKIM and independently check external DNS resolution before sending.
- Permit inbound TCP 25 and authenticated clients on 465/993; allow outbound TCP
  25 and DNS. A cloud provider's outbound SMTP restriction must be resolved with
  the provider. An HTTP hosting plan alone is not an MX host.
- Keep the public SMTP peer's source IP visible for SPF. Ordinary HTTP reverse
  proxies are not SMTP gateways. A TCP proxy that hides source addresses breaks
  the current SPF peer model; Workglen does not parse PROXY protocol.
- Webmail uses separate HTTPS; admin and replication/witness endpoints should have
  appropriate network restrictions. See WEBMAIL.md and README.md.

## Delivery behavior

MX preferences are respected, equal preferences are randomized, and alternate
addresses/hosts are attempted on eligible temporary errors. An absent MX set uses
the domain's A/AAAA; a sole Null MX or nonexistent domain is a permanent failure.
Mixed Null MX and DNS failures defer delivery. Local MXs and their equal/worse
preferences are excluded to prevent loops. Lookup budgets bound resolution to 32
MX records, 32 addresses per host and 128 total endpoints; exceeding a bound defers
rather than silently dropping candidates. Individual DNS calls have 10-second
timeouts within an overall routing budget.

Authenticated submission and Webmail sign accepted messages once using
RSA-SHA256, relaxed header/body canonicalization, a full-body hash and header
oversigning. Incoming mail is verified but not re-signed. Sender addresses still
must match the authenticated account; signing does not open unauthenticated relay.
The existing message, recipient, mailbox and queue limits apply after signing.

Outgoing SMTP supports EHLO, HELO fallback where appropriate, STARTTLS, SIZE and
8BITMIME. SMTPUTF8 is not supported. Signed messages are not rewritten to satisfy a
peer that lacks required capabilities. Webmail generates ASCII MIME headers with
encoded Unicode subjects and base64 bodies/attachments.

Queue state and bodies persist in redb. The single delivery worker retries after
30 minutes by default, backs off to at most six hours, and expires a message after
five days. `retry_seconds` may be 1..3600 for deployment/testing needs. Permanent
SMTP failures and expiry retain a failed queue record and attempt a local failure
notice. Failed records need operational retention management; the UI currently
inspects the queue rather than editing or resending it.

A lost final SMTP acknowledgment is ambiguous. Workglen retains the delivery and
does not immediately try a different MX in the same attempt. A later retry or
crash can still duplicate delivery: SMTP is not exactly once. A final `250` counts
as success even if QUIT fails. Connection, command, data and final-reply deadlines
bound each attempt to 20 minutes overall; this compact single-worker design is
intended for small workloads, not high-volume marketing or bulk sending.

## Validation and references

`tools/outbound-integration.py` supplies local DNS, independent Python SMTP peers
and OpenSSL DKIM verification for fresh installations and normal queue retries.
See VALIDATION.md for results and remaining production checks.

Protocol references: [SMTP RFC 5321](https://www.rfc-editor.org/rfc/rfc5321),
[DKIM RFC 6376](https://www.rfc-editor.org/rfc/rfc6376),
[DKIM key requirements RFC 8301](https://www.rfc-editor.org/rfc/rfc8301),
[STARTTLS RFC 3207](https://www.rfc-editor.org/rfc/rfc3207), and
[Null MX RFC 7505](https://www.rfc-editor.org/rfc/rfc7505).
