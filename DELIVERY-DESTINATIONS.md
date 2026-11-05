# Guided delivery destination setup

In **Mail Security → Setup → Mail flow**, Workglen now creates delivery destinations inside the app. You do not need to edit the gateway's JSON or restart it to add a normal public SMTP destination. Existing installation-provisioned routes remain available.

The message **“Every domain needs one provisioned route”** in earlier screens meant a domain had no valid destination selected. The old wizard could advance to Recipients before detecting that missing choice. The revised wizard explains an empty destination list immediately, opens the destination setup form, and prevents advancing until a saved destination is selected. It also preserves unsaved recipient text when moving back to Mail flow within the same browser session and gateway.

## Microsoft 365

1. Select the intended security instance, then enter your accepted email domain, such as `metavero.com`.
2. Open **Add a delivery destination**. Choose **Microsoft 365** and enter a friendly destination name.
3. Choose **Find Microsoft 365 hostname**. Workglen reads the first accepted domain's MX records and offers only Microsoft 365 destinations ending in `.mail.protection.outlook.com`. It never guesses a hostname or automatically routes back through the gateway.
4. If public MX already points at Workglen or another filter, use the in-app link to Microsoft 365 Admin. Open **Settings → Domains → your domain → DNS records → MX** and copy **Points to address** into Delivery hostname. This is the downstream Microsoft value, not your new public MX record pointing at Workglen.
5. Choose **Test connection**. Workglen connects from the gateway using port 25 and STARTTLS, verifies the server certificate, and checks SMTP readiness with NOOP. No email is sent. A failed test keeps your inputs and explains how to retry.
6. Choose **Save destination** after a successful test. The new destination appears immediately. For an empty installation it is selected automatically; if an existing destination was already selected, choose the new one explicitly before changing mail flow.
7. Select the destination for your domains. Expand **Use different destinations for some domains** if needed. Continue to Recipients and add or discover the addresses to protect.
8. Complete the remaining setup steps and final connection tests. If acceptance is already enabled, pause it before changing domain assignments. Verify actual delivery through the Microsoft 365 receive connector before switching MX.

When a test fails on Lightsail, check **outbound TCP 25** access. Adding an inbound firewall rule does not remove AWS's outbound SMTP restriction. The in-app help calls out this distinction. DNS suggestions and successful TLS/NOOP tests do not prove that Microsoft 365 will accept a particular recipient or sender; verify the intended connector policy and end-to-end mail flow separately.

Microsoft references: [find the Microsoft MX value](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365#appendix-find-the-mx-record-for-the-chosen-accepted-domain-in-microsoft-365-or-office-365) and [mail flow through a third-party filtering gateway](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/manage-mail-flow-using-third-party-cloud).

## Other mail systems and security boundaries

Choose **Another SMTP mail system** for a public DNS hostname with either STARTTLS on port 25 or TLS from connection start on port 465. Certificate verification is mandatory. The app does not accept arbitrary ports, URLs, credential-file paths, custom CA paths or a “disable TLS verification” setting.

Browser-created destinations must resolve to public unicast addresses at each connection, including subsequent delivery retries. Loopback, private, link-local, reserved and mapped private addresses are rejected before connecting. Workglen connects to the checked socket address while retaining the configured DNS hostname for TLS verification. Private/on-premises networks, custom trust stores and authenticated SMTP routes remain available through installation-provisioned routes. Those advanced cases have not gained a credential editor in this update.

Creating and testing destinations requires `security.configure`, the selected instance scope, all configured mailbox scopes, and the proposed domain scopes. Tests run outside database transactions and independently of mail delivery. Saves require the same administrator's successful test, less than 15 minutes old, and an unchanged settings revision. Restarting an in-progress check marks it failed for explicit retry. The test and save are audited.

Destinations created in the wizard are immutable entries in the encrypted security settings. Adding a new destination does not overwrite a file-defined destination, change active domain assignments, or redirect queued messages. To change a destination, add and test a new entry, then select it for the relevant domains. The existing route IDs remain available for queued messages. Tests and saves are idempotent for stable request IDs.

Back up the encrypted security database and its separate storage key as usual. No schema conversion or reinitialization is required. Route persistence uses the existing store; it introduces no runtime dependency.

## Updating a disposable test installation

Rebuild and replace the embedded application binary on **both the M5 Mac Admin and Ubuntu test gateway**, then refresh the browser. Your source directory's `target/` build cache can be retained. Use the test-installation update commands in [MICROSOFT-365-RECIPIENTS.md](MICROSOFT-365-RECIPIENTS.md#updating-a-disposable-test-installation). This changes the code, not the test keys, database, pairing or existing route configuration. Do not rerun `security-init`. No current installation exists.

After this update, delivery destination creation itself requires no further JSON edits or gateway restart. Microsoft 365 directory discovery is a separate optional integration; its one-time Entra credentials and consent are documented in that guide.
