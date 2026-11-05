# Microsoft 365 recipient discovery

Mail Security can now read recipients directly from Microsoft Graph. In **Setup → Recipients**, choose **Discover recipients**, review the complete result, and **Apply additions**. This is an on-demand refresh, not scheduled synchronization. Existing addresses, disabled flags and digest preferences remain intact; missing addresses are listed for manual review, never automatically deleted. No mailbox content is read, and no Microsoft tenant objects are changed.

The native Rust gateway performs the requests through Pratique. No SDK, additional runtime, PowerShell, external database or paid scanning service is needed. Existing configurations work without this optional profile. No Workglen database conversion, reinitialization or key replacement is involved.

## One-time Microsoft setup

1. In Microsoft Entra admin center, open **App registrations → New registration**. Name it `Workglen recipient discovery`, choose accounts in your organizational directory only, and register it. A redirect URI is not needed for this service-to-service flow.
2. Record **Directory (tenant) ID** and **Application (client) ID**, both GUIDs.
3. Under **API permissions → Add a permission → Microsoft Graph → Application permissions**, add `User.Read.All`, `Group.Read.All` and `OrgContact.Read.All`. A tenant administrator must grant admin consent. Do not add mail-content or write permissions for recipient discovery. Use a separate app from any optional mailbox-remediation integration.
4. Under **Certificates & secrets**, create a client secret. Copy its **Value**, not its ID, into the protected file described below. Record the expiry and rotate the secret before it expires. Workglen does not automatically renew Microsoft client secrets.

This implementation supports the global Microsoft cloud (`login.microsoftonline.com` and `graph.microsoft.com`). Sovereign/national cloud endpoints are not yet configurable. Directory permissions apply across the tenant; Workglen filters the retrieved addresses to the accepted domains before saving or displaying them.

## Gateway configuration

Create `/etc/workglen-security/microsoft365.secret` with a private editor on Lightsail. It should contain only the client-secret value on one line. Avoid putting the value into a shell command, shell history, pairing bundle or screenshot. Give the service read access while keeping the file private:

```sh
sudo chown workglen-security:workglen-security /etc/workglen-security/microsoft365.secret
sudo chmod 600 /etc/workglen-security/microsoft365.secret
```

Add the following **top-level property** to your existing `/etc/workglen-security/config.json`, with the correct JSON comma between properties. Keep all existing settings, routes, keys, TLS/ACME state and data paths:

```json
"recipient_directory": {
  "tenant": "YOUR-TENANT-GUID",
  "client_id": "YOUR-APPLICATION-GUID",
  "secret_file": "/etc/workglen-security/microsoft365.secret"
}
```

Validate the file as the service user, then restart:

```sh
sudo -u workglen-security /usr/local/bin/workglen security-check /etc/workglen-security/config.json
sudo systemctl restart workglen-security
sudo systemctl status workglen-security --no-pager -l
```

`security-check` is offline: it validates configuration and secret-file access, not Microsoft credentials or admin consent. The Discover action tests the actual API integration. Allow outbound HTTPS (443) to the two Microsoft hosts above. No additional inbound port is needed. Discovery redirects are refused and TLS certificates are verified.

## Review and apply

1. In central Admin, open **Mail Security → Setup** and select the intended gateway.
2. In **Mail flow**, choose your accepted domains and Microsoft 365 delivery destination. If none exists, use **Add a delivery destination → Find Microsoft 365 hostname → Test connection → Save destination**, as described in [DELIVERY-DESTINATIONS.md](DELIVERY-DESTINATIONS.md). Continue to **Recipients**; first-time setup can discover recipients before saving a manual mailbox list.
3. If protection is already live, pause new acceptance before starting this review. Senders will retry while acceptance is paused; queued delivery continues.
4. Choose **Discover recipients**. It runs in a separate background worker. You can leave and return to this page under the same administrator identity. A failed, incomplete, throttled or interrupted fetch leaves accepted recipients unchanged.
5. Review the discovered addresses and existing addresses absent from the snapshot. Choose **Apply additions** within 15 minutes. Changes require `security.configure`, the selected instance scope, all configured mailbox scopes and the chosen domain scopes. The actor, source, request ID, result and configuration change are audited. Another administrator must run their own discovery before applying it.
6. Keep manual exceptions and check mailbox-holder access in **Access**. Discovery grants no portal identities or permissions. Digests are addressed to the exact accepted address, including aliases/groups, and use the configured preferences; review these before enabling digests for a large directory.
7. Continue setup, rerun connection tests and explicitly enable acceptance. Verify delivery through your real Microsoft 365 connector before changing MX. Repeat discovery when addresses change; remove departed recipients deliberately after review.

Workglen reads SMTP proxy addresses and `mail` from users (without excluding disabled or unlicensed shared/resource accounts), mail-enabled groups, and organizational contacts. Guest users, non-mail-enabled groups, non-SMTP proxies and addresses outside accepted domains are excluded. A login UPN is not assumed to be a mailbox address. The result is a directory candidate list, not proof of successful Exchange delivery.

**Graph does not list dynamic distribution groups.** Keep those addresses manually and verify other hybrid or unusual recipient types against Exchange. Microsoft directory data can be eventually consistent. These limitations are shown in the app; do not treat an empty or reduced result as permission to delete recipients.

A snapshot is bounded to 200 pages, 100,000 directory objects, 10,000 distinct accepted addresses, 64 MiB decoded JSON overall and roughly five minutes of work plus the final bounded request. Exceeding a limit fails the whole discovery. Individual requests have time/body limits; continuation URLs must remain on the same Microsoft collection. No OAuth token, secret or raw provider error body is stored in the preview or audit log.

## Updating a disposable test installation

Build the new source on both test machines as your normal user with `bash install.sh build`. Extract updated source into your existing source directory to keep `target/` and its reusable build cache. The application binary embeds the UI, so a source update alone does not update test installation screens. No current installation exists.

On the Mac, stop the running Admin process with Ctrl-C, then:

```sh
WG_ADMIN="$HOME/Library/Application Support/Workglen"
install -m 700 target/release/workglen "$WG_ADMIN/bin/workglen.new"
mv "$WG_ADMIN/bin/workglen.new" "$WG_ADMIN/bin/workglen"
bash "$WG_ADMIN/run-admin.sh"
```

On the Ubuntu test server, stage the rebuilt binary, then replace it while the service is stopped:

```sh
sudo install -o root -g root -m 755 target/release/workglen /usr/local/bin/workglen.new
sudo systemctl stop workglen-security
sudo mv /usr/local/bin/workglen.new /usr/local/bin/workglen
sudo systemctl start workglen-security
sudo systemctl status workglen-security --no-pager -l
```

These steps retain the disposable test configuration, keys and databases. Do not run `security-init` or reinstall a fresh pairing bundle over the test deployment. Configure the optional directory profile after updating the binary. Refresh the browser after restarting Admin.

## Navigation

Central Mail Security now has a persistent **Back to Admin** header link, including at narrow widths and on its login screen. Mail and Accounting administration views also have a labeled return link to the module overview. Webmail shows a return link after sign-in when its host has a configured Admin origin; Admin authentication remains separate.

For administrators visiting the gateway directly, optionally add a top-level `admin_origin` to its JSON configuration. For this Mac installation, the example is `"admin_origin": "https://localhost:8444"`; it only works in a browser running on that Mac. Use the actual reachable Admin origin for other deployments. Only administrator sessions see this link; mailbox-holder digest sessions do not. No session or credential is forwarded by navigation. Without a configured origin, a standalone gateway does not invent an Admin destination.

## Microsoft references

- [List users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0)
- [List groups and dynamic-distribution-group limitation](https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0)
- [List organizational contacts](https://learn.microsoft.com/en-us/graph/api/orgcontact-list?view=graph-rest-1.0)
- [Client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
