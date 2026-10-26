# Workglen Webmail — optional module

Webmail is a compact mailbox client in the same Rust binary. It adds no Node.js
server, frontend package runtime, extra mail database or cloud service. Mail and
Webmail use the same redb messages, folders, flags, quotas, replication and signed
outbound queue. Accounting continues to use its separately configured PostgreSQL
database.

The first version provides Inbox/Sent/Drafts/Junk/Trash and existing custom folders,
a paged message list, plain-text reading, compose, reply, To/Cc/Bcc, attachments,
read/unread and star flags, and moving between folders. Trash is reversible; there
is no permanent-delete button. Browser layout adapts to desktop and mobile.

## Configure and enable

Add a separate HTTPS listener and origin to each node's configuration:

```toml
[webmail]
listen = "0.0.0.0:8444"
origin = "https://mail.example.com:8444"
session_minutes = 30
```

Use your own hostname and a matching trusted certificate in the existing
`tls_cert`/`tls_key` configuration. Workglen terminates HTTPS itself. The origin
must match exactly, with no trailing slash, and must differ from `[web].origin`.
The socket must differ from the admin HTTPS socket. Prefer a distinct hostname
for public Webmail and restrict administration to a private network or VPN.
Same-host different-port origins are supported, but cookies are host-scoped, so
that arrangement is not a substitute for separate administration exposure.

Restart the node to open the listener, then use **Administration → Modules →
Enable Webmail**, or run:

```sh
workglen module-enable /etc/workglen/node.toml webmail
```

Mail must be enabled. Webmail starts disabled for new installations.
The enable setting is stored in redb and replicated; listener addresses and TLS
files remain node-local. Configure both nodes before enabling it for a pair.
The standby refuses mailbox API access; direct browsers to the current primary
using a deployment arrangement appropriate to your hostnames and certificates.
Sessions are node-local and users must sign in again after failover or restart.

Sign in with the **full mailbox email address and mailbox password**. Administrator
credentials or cookies do not grant mailbox access. Creating/resetting mailbox
credentials remains an administration task. Changing a mailbox password invalidates
its Webmail sessions on the next API request. SMTP and IMAP session behavior is
unchanged.

## Independent lifecycle

```sh
workglen module-disable /etc/workglen/node.toml webmail
workglen module-enable /etc/workglen/node.toml webmail
```

Disabling Webmail blocks new and existing mailbox API sessions while SMTP, IMAP
and outbound delivery continue. Disabling Mail also pauses Webmail, preserving its
setting and data for re-enable. In-flight reads may finish; writes recheck enable
state and credentials inside the serialized primary-only transaction. The HTTPS
socket stays open to serve a sign-in/unavailable page; disabling is not a firewall
change. The Core administration UI continues independently.

## Reading and sending

Message HTML is converted to text by the MIME parser and inserted as browser text,
never executable markup. Remote images, scripts and tracking pixels are not loaded.
Attachments download as `application/octet-stream` with an attachment disposition;
they are not rendered inline or scanned for malware. Reading shows at most 256 KiB
of decoded body text; larger messages remain available in an IMAP client.

Compose supports up to ten attachments totaling 3 MiB, and up to 256 KiB of UTF-8
text, within the node's overall MIME/message and recipient limits. Use bare email
addresses separated by commas or semicolons; SMTPUTF8 addresses are unsupported.
Subjects and Unicode bodies/filenames are MIME encoded. Bcc addresses remain in
the delivery envelope and are not added to delivered headers. Reply adds an
In-Reply-To/References header from the mailbox message selected by the user.

A send commits local recipients, external delivery entries and the sender's Sent
copy atomically. It fails without storing any of those if an account, recipient,
quota, module state or queue check fails. DKIM uses the configured shared signing
path. **Sent means accepted/queued, not confirmed delivery to an external inbox.**
Later remote delivery failures follow the normal queue/failure-notice behavior.

The browser keeps a send ID and locks the payload after a lost response, allowing
Retry Send to confirm the same request. The server retains the latest 128 send
receipts per mailbox, including across replication and restart. Replaying a receipt
with different content fails. This bounded protection is not a permanent exactly-once
guarantee; clearing the tab, using a new ID, old receipt eviction or loss of an
unreplicated write can remove it. SMTP itself also has ambiguous acknowledgment
cases described in DIRECT-MAIL.md.

Unsent drafts stay only in the current browser tab. Closing/discarding the composer,
signing out, session expiry, reloading or closing the tab can lose them. There is
no draft autosave or localStorage copy. The Drafts folder displays messages saved
by IMAP clients but does not yet provide draft editing. Other limits: no global
search, threading, reply-all/forward action, contact directory, rich-text editor,
folder creation/rename UI, push updates, offline mode or multi-account switcher.
Refresh retrieves new mail. These are deliberate boundaries of this slim release.

## Resource and access boundaries

The Webmail HTTPS listener permits four simultaneous connections and uses Mail's
existing transfer gate for mailbox reads/writes. Message lists contain at most 25
entries, and sessions are bounded to 64 total and four per account. Sessions expire
after a fixed 1..60 minutes (30 default). Password work shares the existing Argon2
lock and has a bounded per-source login rate limit. Host validation, exact Origin,
CSRF tokens, HttpOnly/Secure/SameSite cookies and restrictive CSP are enforced.
Mailbox API calls derive the user from the session; callers cannot select another
account. Message references include UIDVALIDITY to reject stale selections after
mailbox generation changes. All mutation paths require current primary ownership.

This is a development release using the existing unaudited Pratique TLS server.
Local API/browser tests do not replace an independent security audit, accessibility
review or production load test. No real mailbox or external recipient was used
in the bundled tests.

## Run the tests

```sh
python3 tools/webmail-test.py --binary target/release/workglen \
  --work /tmp/workglen-webmail-test --browser
```

Omit `--browser` to run only the API/IMAP checks. Browser checks require externally
installed Playwright and Chromium; those dependencies are not shipped or used by
the server. The harness uses only generated credentials and loopback TLS.
