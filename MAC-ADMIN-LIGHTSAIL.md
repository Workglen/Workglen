# Mac Admin, local PostgreSQL, Lightsail Mail Security

## Where each part runs

| Machine | Component | State |
|---|---|---|
| Your Mac | Native Admin with browser interface at `https://localhost:8443` | Local redb for identities, scopes and administration records |
| Your Mac | Accounting within the Admin process | Your existing PostgreSQL, in a dedicated Workglen database/schema |
| Lightsail | Native Mail Security gateway | Encrypted redb for quarantine, queues, rules and security audit |

The Mac initiates authenticated HTTPS management requests to the gateway. Lightsail does not connect back to your Mac or PostgreSQL. Gateway detection, quarantine, scheduled digests and delivery continue with the last active settings while the Mac is asleep or disconnected. Accounting and its scheduled bank-feed work are available only while your Mac's Admin process and PostgreSQL are running. Recipient digest links point to the gateway, so access for mailbox holders must be included in its HTTPS firewall plan.

This is a local native web console, not a signed/notarized `.app` desktop bundle. Launch it from Terminal and use your normal browser. The installer does not install a Login Item or background LaunchAgent.

## 1. Prepare local Accounting

Use your existing PostgreSQL installation. Prefer a dedicated database and a non-superuser role that owns it. If they do not already exist, an operator with PostgreSQL creation privileges can run:

```sh
createuser --pwprompt workglen
createdb --owner=workglen workglen
```

These are operator-run PostgreSQL client commands, not actions the Workglen installer performs. Adapt the administrative connection arguments to your installation. Do not select an unrelated application's database.

Create a private connection file and edit it locally:

```sh
umask 077
touch "$HOME/workglen-postgres.dsn"
chmod 600 "$HOME/workglen-postgres.dsn"
nano "$HOME/workglen-postgres.dsn"
```

Example content (replace the password inside the file):

```text
host=127.0.0.1 port=5432 dbname=workglen user=workglen password='replace-with-your-database-password'
```

`transport = "local"` explicitly permits unencrypted **host-local** communication over a literal loopback IP or an absolute Unix socket directory, such as `host=/tmp` if that is where your PostgreSQL listens. Network hostnames, remote IP addresses, multiple endpoints and `hostaddr` overrides are refused in this mode. Prefer a socket directory accessible only to the database owner where your PostgreSQL setup supports it. PostgreSQL authentication still applies; Workglen does not modify `pg_hba.conf` or enable trust authentication. If your local server already has TLS, select `--postgres-transport verified-tls` and its CA file instead. Remote PostgreSQL continues to require verified TLS by default.

Passwords containing single quotes or backslashes need libpq connection-string escaping; see [PostgreSQL's connection parameters](https://www.postgresql.org/docs/current/libpq-connect.html). DSN contents stay in mode-0600 files and are excluded from the gateway bundle and logs. Local PostgreSQL disk encryption/backups remain your responsibility; Mail Security's encrypted redb does not encrypt Accounting or the local Admin store.

## 2. Build and configure on your Mac

Unzip the source, then run the build as your normal user. It handles system prerequisites and Rust/Cargo automatically; if Apple's tools are missing, complete the installation dialog it opens. See [INSTALL.md](INSTALL.md) for details.

```sh
cd workglen
bash install.sh build
bash install.sh admin --postgres-dsn-file "$HOME/workglen-postgres.dsn"
```

Use a real gateway hostname, such as `security.yourdomain.com`, and the mail domain it will protect. Choose Let's Encrypt production when DNS and public port 80 are ready. Staging is for issuance tests and will be rejected by the Mac's normal TLS verifier. Enter separate local Admin and gateway recovery passwords.

The wizard creates `workglen-gateway-bundle` in the current directory. It contains a management secret, so keep its directory 0700 and files 0600. It is a deployment artifact for your hosts, not part of the distributable source ZIP. BYOK storage keys should be transferred only if explicitly selected.

Initialize Accounting in the dedicated database when ready:

```sh
"$HOME/Library/Application Support/Workglen/bin/workglen" accounting-init \
  "$HOME/Library/Application Support/Workglen/etc/admin.toml"
```

Alternatively use `--initialize-accounting` during setup. The schema starts disabled; enable Accounting in Modules after the console starts, then create a book. Initialization creates only Workglen's current schema and checks its workspace binding on later runs. It is not a Workglen upgrade/import operation.

## 3. Trust and launch the local console

The Mac console binds only to loopback and uses its generated localhost certificate. Public Let's Encrypt certificates are used on the gateway; a public CA cannot validate your private `localhost` name. In Keychain Access, import the **public** file `~/Library/Application Support/Workglen/etc/local-ca.pem` into your login keychain, open that certificate's Trust settings, and explicitly trust it for SSL. Check that it is your locally generated `Workglen Local Admin CA`. Do not import or share `local-key.pem` or `local-ca-key.pem`. Corporate-managed Macs may require an administrator's approved trust procedure.

Start:

```sh
bash "$HOME/Library/Application Support/Workglen/run-admin.sh"
```

Keep that terminal running and open `https://localhost:8443/mail-security`; sign in as `admin` using your local Admin password. Use the main console for Accounting and Access. Stop with Control+C. The local certificate expires after one year; renew it with the local CA through your certificate process and restart. The generated local CA expires after five years; replacing that CA also requires updating its trust. Local certificate trust/renewal is separate from automatic gateway ACME renewal. The SSH `.pem` used by `ssh metavero` is an SSH login key and is not a Workglen TLS or database key.

## 4. Transfer and install on Lightsail

From the directory containing the source ZIP and pairing bundle on your Mac, use your existing SSH alias:

```sh
scp workglen-0.8.0-source.zip metavero:~/
scp -r workglen-gateway-bundle metavero:~/
ssh metavero
```

On Lightsail, unpack into a fresh directory and build for Linux:

```sh
unzip workglen-0.8.0-source.zip
cd workglen
bash install.sh check
# Handles system tools, Rust/Cargo and dependencies; do not run build with sudo.
bash install.sh build
sudo bash install.sh gateway --bundle "$HOME/workglen-gateway-bundle" --start
sudo journalctl -u workglen-security -n 50 --no-pager
```

The build uses the lighter release profile by default. Compilation can still
need more memory than the running gateway. If the kernel kills `rustc` for
running out of memory, follow the recovery instructions in [INSTALL.md](INSTALL.md);
keep the Cargo cache and use more build memory or swap if the lighter profile
is still insufficient.

Use the source copy that includes this installer. If you already extracted an older source ZIP, extract the new one into a different empty directory rather than merging source trees. The gateway's native configuration is `/etc/workglen-security/config.json`; state is `/var/lib/workglen-security`. Back up `/etc/workglen-security/storage.key` separately from the encrypted database. After securely backing up the management key and any supplied storage key, remove unneeded transferred bundle copies so secrets are not left in Downloads/home folders indefinitely.

## 5. Network and go-live checks

- Assign stable addressing and correct A/AAAA records for the gateway hostname.
- Keep TCP 80 reachable for HTTP-01. TCP 8445 serves the gateway's verified HTTPS management and recipient digest interface; constrain access to intended administrators/recipients where practical. TCP 25 is inbound SMTP. Do not open your Mac's PostgreSQL port to Lightsail or the public internet.
- Keep your SSH firewall rule intact. The installer changes neither host nor Lightsail firewall rules.
- Check [AWS's Lightsail port-25 restrictions](https://repost.aws/knowledge-center/lightsail-port-25-throttle) before relying on outbound SMTP forwarding, and follow [Lightsail firewall guidance](https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-firewall-and-port-mappings-in-amazon-lightsail.html). Removing a provider restriction and changing a firewall rule are separate steps.
- Wait for a valid production gateway certificate. Then open Mail Security in the Mac console and confirm a live status response. The shared workspace ID, instance ID and management key are generated consistently by the wizard; delegated user roles and scopes are still enforced independently by the gateway.
- Provision the verified downstream SMTP route if omitted from the wizard, then complete domains, recipients, rules/tests, digests and optional mailbox connectors. Activate tested rules and explicitly enable gateway acceptance before changing public MX. Run synthetic delivery/quarantine/digest checks for your actual destination.

The gateway is mail security and SMTP forwarding. Your existing downstream mail system still provides mailbox hosting; the gateway does not become an Outlook/Exchange mailbox server merely by being installed.
