# Gateway relay protection and Ubuntu test verification

Reviewed 2026-10-25 against the current source. This checkpoint adds documentation
and an operator diagnostic, plus a loopback regression using that diagnostic.
It changes no production Rust code, dependency, configuration or deployed host.
No rebuild is required just to use the diagnostic. Test binary versions and
Ubuntu/Lightsail firewall settings must still be checked before claiming test
deployment verification. There is no current installation.

## Required test deployment behavior

For the Metavero Microsoft 365 test scenario, Workglen Security receives
synthetic test mail addressed to explicitly enabled synthetic test recipients,
scans it, and forwards allowed mail to an administrator-provisioned test
destination. Quarantine releases and summaries use configured test recipients
and routes. This forwarding is
the reason a gateway needs outbound SMTP port 25 even while mailboxes remain in
Microsoft 365. It is not public arbitrary-recipient SMTP submission.

Implemented source controls:

- SMTP RCPT checks an explicit enabled-mailbox allowlist before DATA. Validated
  settings restrict those mailboxes to accepted domains and saved routes.
  Claiming a local MAIL FROM address or using a null sender does not grant relay.
- The Security listener neither advertises nor implements SMTP AUTH. It does
  not expose Mail's separate authenticated submission service. In Mail itself,
  external recipients require the submission listener; submission requires TLS,
  authentication and an envelope sender matching the authenticated account.
- The sender cannot supply a next-hop host. Delivery uses an administrator-saved
  route with TLS certificate/hostname verification. Recipient headers do not
  choose the SMTP delivery recipient. The Security worker retains failed jobs;
  it does not send automatic failure notices to arbitrary inbound envelope senders.
- SMTP commits exact MIME and envelope metadata to encrypted `pending-scan`
  storage before returning `250`. Sender authentication and inspection run in a
  separately restartable role from the same native executable. Scanner outage
  therefore grows a bounded local receive backlog instead of disabling ingress;
  capacity or storage-commit failure returns a transient SMTP response.
- Spam/authentication and attachment inspection can quarantine content. Mandatory
  incomplete/unsupported archive findings cannot be bypassed by ordinary spam
  release. Inspection does not guarantee that every unwanted message is detected.
- Configuration/release operations require authenticated scoped authorization;
  remote management additionally checks signed requests. Accepted messages,
  management actions and delivery jobs have audit records. Web sign-in attempts,
  sessions, SMTP concurrency/recipients/message size, receive-spool reservations
  and queue storage are bounded. Scan results are hash/source/lease/version bound;
  incomplete coverage cannot produce delivery.
  These are not per-sender hourly outbound rate quotas.
- The provided service unit uses a dedicated unprivileged account, restricted
  writable paths, no new privileges and only the bind-service capability.
  Whether this unit is actually installed is a live-host check.

## Checks to complete on the actual host

1. Confirm `workglen-security` runs `workglen security-serve` under its dedicated
   service account, using the intended configuration. Inspect without printing
   secret values:

   ```sh
   sudo systemctl show workglen-security -p ExecStart -p User -p Group -p NoNewPrivileges -p ProtectSystem
   sudo ss -lntp
   ```

2. In authenticated Setup, confirm only authorized domains and enabled mailboxes
   are present, recipients from Microsoft 365 discovery were reviewed, and each
   domain points to the intended tenant delivery destination. Remove unneeded
   routes, connectors and administrator accounts. A configured sender address
   is never sufficient authorization for external relay.
3. For an authorized external test gateway, review the Lightsail IPv4 **and** IPv6
   firewalls. Permit test SMTP on the actual listener (normally TCP 25), HTTP-01
   on TCP 80 only when a simulated ACME test is enabled, and the configured HTTPS
   interface. Restrict SSH to administrative sources. Keep unnecessary
   submission/IMAP/debug listeners closed on this gateway-only host. Do not change
   public MX during the current development phase.
4. Check any OS firewall and other running services. Lightsail's firewall does
   not restrict outbound connections or private-address ingress. Optional host
   egress rules can restrict SMTP to the service account and maintained approved
   destination address sets, covering IPv4 and IPv6. Do not use a static snapshot
   of Microsoft 365 IPs without an update process. Those rules are not installed
   by this checkpoint. Account compromise and an administrator's route changes
   are separate risks from unauthenticated open relay.
5. Run the envelope-only diagnostic against a disposable test gateway from an
   external machine you control (for example the M5 Mac), from the extracted
   source directory:

   ```sh
   python3 tools/check-gateway-relay.py mailgw.metavero.com --domain metavero.com
   ```

   Use the test host/domain in place of this example and enter a synthetic enabled
   test mailbox when prompted. The diagnostic verifies the TLS certificate and
   tests every address returned by local DNS (up to eight). It confirms the known
   test mailbox is accepted, then checks foreign recipients, unknown local
   recipients, claimed local senders, null senders, alternate recipient syntax,
   unavailable AUTH and reset behavior. It **never sends DATA or a message body**,
   and finishes with no submitted mail. Repeat from both IPv4/IPv6-capable
   networks if DNS or network visibility differs. A failed connection, certificate
   failure, paused gateway or rejected positive control is not a pass. Activation
   may first need AWS to permit the configured next-hop connection; keep external
   test verification explicitly pending until it can run.
6. Review test queues and audit records during initial test operation; investigate
   unusual forwarding/digest volume, unexpected destinations, administrator
   changes and repeated failures. No claim of a staffed monitoring process or
   alert delivery is made by this source review. Keep test DNS, patching and
   credential access under operator control. Verify the test static IP, hostname
   and any requested PTR separately; do not infer DNS readiness from a source test.

No finite test guarantees that a host can never be abused. These checks establish
specific relay restrictions and make remaining host/configuration work explicit.

## Executed checks

The current release binary passed **18 native Security loopback integration
checks**, including **12 envelope/TLS assertions** from the new diagnostic. The
positive/negative envelope probes left message storage and the SMTP sink empty.
The fixture also exercised real synthetic forwarding, quarantine, digest delivery,
authorization, scoped remediation and encrypted-store restart. Results are in
`validation/0.8-relay-review-network.json` and `0.8-relay-review-envelope.json`.
No production mailbox, Lightsail instance or Microsoft 365 tenant was contacted.
The production code remains the previously validated 152-test release; that
Rust suite is not claimed as rerun for this documentation/test-only checkpoint.

## AWS references

- https://aws.amazon.com/aup/ — prohibits facilitating unsolicited mass email.
- https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-configuring-reverse-dns.html — outbound port 25 requests and reverse DNS.
- https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-firewall-and-port-mappings-in-amazon-lightsail.html — inbound/public-IP scope; separate IPv4/IPv6 rules and allowed outbound traffic.
