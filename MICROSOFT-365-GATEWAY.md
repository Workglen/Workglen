# Microsoft 365: require inbound delivery through Workglen

The setup wizard now includes **Microsoft 365 protection** immediately before
Go live. It prepares a reviewable tenant configuration and explains how to prove
it works. Workglen does not log into Microsoft, execute PowerShell, change DNS,
send live test messages or mark a tenant verified. The administrator performs
those deployment steps and retains the evidence.

MX records direct ordinary delivery to Workglen; they do not prevent a sender
from addressing Exchange Online's SMTP endpoint directly. Microsoft's documented
control is a **Partner inbound connector** with `SenderDomains '*'` and
`RestrictDomainsToIPAddresses $true`, limited to the gateway's public egress IPs.
This guide also requires TLS. An OnPremises connector alone does not enforce
these restriction flags. See [Microsoft's third-party mail-flow guidance][flow].

## Prepare the tenant

1. In Workglen → Setup → Mail flow, select the tenant's real
   `*.mail.protection.outlook.com` delivery hostname, obtained from the Microsoft
   365 admin center's domain DNS settings. Do not derive it from the custom domain
   or replace it with the public MX after that MX points to Workglen.
2. Configure and review all intended domains, recipient aliases and groups,
   detector settings and tested Active rules. Preserve existing installation
   settings, keys and mail data.
3. Open Setup → Microsoft 365 protection. Select the destination belonging to
   the tenant you will administer. Several domains/destinations can belong to
   one tenant; do not create competing wildcard restrictions for each domain.
4. Inventory the entire tenant in Exchange admin center → Mail flow → Connectors,
   including accepted domains, hybrid routes, other connectors, transport rules,
   scanners, printers and applications. The proposed wildcard restriction is
   tenant-wide, not restricted to the domains shown in this Workglen instance.
   Unreviewed independent mail paths could stop receiving mail.
5. Enter a new connector name and every dedicated static **public outbound/NAT
   IPv4 address** used by Workglen gateways for this tenant, including failover.
   Confirm the addresses actually observed by Microsoft. The inbound MX address
   may differ. Sharing an allowed egress IP with other systems trusts those
   systems too. This guide rejects private/reserved addresses and ranges, and
   accepts at most 16 exact addresses as a conservative local policy.

Microsoft's `SenderIPAddresses` connector parameter supports IPv4, not IPv6.
Ensure the actual gateway delivery uses the listed IPv4 egress. This walkthrough
targets a direct Workglen → Exchange Online path in the global cloud. Additional
relays, hybrid loops and sovereign clouds require separate configuration review.
Microsoft also documents certificate restrictions, but the current Workglen
outbound SMTP client does not present a client certificate. A receiving SMTP or
HTTPS certificate cannot substitute for that outbound identity.

## Stage, then activate

After reviewing the tenant and dedicated addresses, select **Prepare Microsoft
365 commands**. Use an authenticated Exchange Online PowerShell session in the
correct tenant with the necessary connector-management permissions. Microsoft's
administration tools are optional operator tools, not Workglen dependencies.
Run each generated section separately and stop on errors.

The inventory commands list accepted domains, inbound connectors and transport
rules. Save the output with the change record. The create command uses a unique
name and creates a **disabled Partner connector**. It fails on a duplicate name;
do not apply later commands to an existing, unreviewed connector. Sender domains
must remain `*` (all external senders), not your recipient domain. Verify the
restriction flag, exact addresses and required TLS before enabling. See the
[connector parameter reference][new] and [update reference][set].

The next section configures **Enhanced Filtering for Connectors** with the exact
trusted gateway IPs, explicit skip listing and all-recipient scope. Review a
pilot deployment first if required. For this direct topology, it allows Microsoft
to recover the external sender IP from the trace chain while continuing its
filtering. Never add Microsoft 365 IPs or untrusted hops to the skip list. Review
existing SCL -1 bypass rules for this flow; the generated commands do not disable
Microsoft scanning or treat mail as internal. Intermediate public hops require
their own review. See [Enhanced Filtering guidance][filtering].

Continue to **Go live** and finish Workglen's readiness checks. Enable gateway
acceptance, then prove delivery through every active/failover gateway before
enforcing the tenant restriction. Change public MX records, including backup MX,
to Workglen in the planned change window. Account for cached old MX records:
senders still using them may fail once enforcement begins. Review the staged
connector again, run the separately displayed enable command, inspect its state
and perform the tests below. Until enforcement and those tests succeed, bypass
protection is unproven. Monitor both Workglen queues and Exchange message trace.

If this new connector blocks required traffic, the separately labeled emergency
command disables it. **Disabling it reopens direct-delivery bypass.** Record and
monitor the exception, repair the configuration, then re-enable and retest. Do
not delete unrelated connectors or replace existing deployment data.

## Deployment evidence

Use controlled harmless messages and known valid recipients. Retain UTC time,
source public IP, recipient, Message-ID, SMTP result and matching trace evidence.

| Check | Required observation |
| --- | --- |
| Positive, each gateway and failover address | Workglen inspection and successful downstream receipt; repeat through normal public MX after propagation. |
| Negative, independent external SMTP host | Direct delivery to the actual Microsoft endpoint is permanently rejected by the connector policy. Complete submission through DATA if needed. No mailbox delivery. |
| Coverage | Test every accepted domain and deliverable tenant `.onmicrosoft.com` aliases; also test a sender from a separate Microsoft 365 tenant. Review other inbound connectors and application/device routes. |
| Original sender context | Review received trace/authentication results for the real external source IP and continued Microsoft protection after Enhanced Filtering. |

A timeout, 4xx response, nonexistent-recipient rejection or spam rejection is
not proof of connector enforcement. Neither is a successful TCP/TLS/SMTP NOOP
probe. Workglen readiness tests send no message and cannot establish that
Microsoft rejects a bypass attempt. The existing `check-gateway-relay.py` tests
the Workglen listener's relay policy, not Microsoft tenant restrictions.

This control covers external SMTP. Same-tenant mail and authenticated Microsoft
submission, Graph and application permissions are separate paths. Recheck after
connector, gateway-IP, failover, MX or accepted-domain changes. Inbound gateway
filtering alone does not require adding Workglen to your outbound SPF record.
Do not configure trusted ARC sealing unless sealing is actually implemented and
enabled for that route.

## Trusted SMTP trace and portable checks

Forwarded SMTP copies now prepend one Workglen `Received` header using the
observed socket peer, stored arrival time and message ID. Untrusted EHLO text
and sender-supplied headers cannot override that hop. The original stored MIME,
its hash, authentication input and audit evidence remain intact. Retries and
quarantine releases build their copy from the same original, avoiding repeated
headers. IPv6/mapped-IPv4 trace formatting is supported; this does not enable
IPv6 Partner-IP restrictions. Mailbox-remediation content with no observed SMTP
peer retains its original trace rather than inventing one. No schema migration,
Pratique patch, new crate or runtime dependency is introduced.

Run from the extracted source with the pinned Cargo dependencies already cached:

```sh
python3 tools/check-microsoft365-setup.py --browser
```

The runner performs offline locked workspace tests, warnings-denied Clippy, a
release build, the first-party dependency audit, plan validation, browser
workflows and real local gateway/central-admin SMTP integration. Development
fixtures require Node and the OpenSSL CLI; `--browser` additionally requires
Playwright and Chromium. Set `WORKGLEN_CHROMIUM` to an existing compatible
Chromium executable if needed. Nothing is installed or downloaded by the check.
Omit `--browser` for non-browser checks. `--binary /absolute/path/to/workglen`
reuses an already validated executable and explicitly records skipped build
checks. `--cargo` selects a toolchain wrapper; `--output` selects the log directory.

The plan-only check has no browser or network prerequisites:

```sh
node security/tests/microsoft365-plan.cjs
```

All fixtures are synthetic and local. They validate our guide, trace generation
and protocol behavior; **live Microsoft tenant interoperability and enforcement
remain deployment tests**, not results claimed by this source package.

[flow]: https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/manage-mail-flow-using-third-party-cloud
[new]: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-inboundconnector
[set]: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-inboundconnector
[filtering]: https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors
