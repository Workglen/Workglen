# M5 Mac Admin, local PostgreSQL, Ubuntu test Mail Security

This guide targets the TBD 0.1.1 development/test release. There are no current installations, live or otherwise. The procedures below create disposable test installations only.

## Where each part runs

| Machine | Component | State |
|---|---|---|
| Apple Silicon M5 developer laptop | Native Admin with browser interface at `https://localhost:8443` | Encrypted local redb for identities, scopes and administration records |
| Apple Silicon M5 developer laptop | Accounting within the Admin process | Local PostgreSQL, in a dedicated Workglen test database/schema |
| Ubuntu server test machine | Native Mail Security gateway | Encrypted redb for quarantine, queues, rules and security audit |

The Mac initiates verified-TLS management requests authenticated by the paired installation's shared key. That key is not a per-operator credential, so the generated gateway confines it to status/read, rule drafting and rule testing. The Ubuntu test server does not connect back to the Mac or PostgreSQL. Gateway detection, quarantine, scheduled digests and delivery continue with the last active settings while the Mac is asleep or disconnected. Accounting and its scheduled bank-feed work are available only while the Mac's Admin process and PostgreSQL are running. Recipient digest links point to the gateway, so access for mailbox holders must be included in its HTTPS firewall plan.

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

Passwords containing single quotes or backslashes need libpq connection-string escaping; see [PostgreSQL's connection parameters](https://www.postgresql.org/docs/current/libpq-connect.html). DSN contents stay in mode-0600 files and are excluded from the gateway bundle and logs. Local PostgreSQL disk encryption/backups remain your responsibility. The encrypted local Admin redb protects its own administration state, not Accounting data.

## 2. Build and configure on your Mac

Unzip the source, then run the build as your normal user. It handles system prerequisites and Rust/Cargo automatically; if Apple's tools are missing, complete the installation dialog it opens. See [INSTALL.md](INSTALL.md) for details.

```sh
cd workglen
bash install.sh build
bash install.sh admin --postgres-dsn-file "$HOME/workglen-postgres.dsn"
```

Use a test gateway hostname, such as `security.test.example`, and the test mail domain it will protect. For end-to-end testing, use a manually provisioned private test CA and configure its trust chain as described in [INSTALL.md](INSTALL.md). Public Let's Encrypt issuance, including staging, is not part of the current development test procedure. Enter separate local Admin and gateway recovery passwords.

The wizard creates `workglen-gateway-bundle` in the current directory. It contains a management secret, so keep its directory 0700 and files 0600. It is a deployment artifact for your hosts, not part of the distributable source ZIP. BYOK storage keys should be transferred only if explicitly selected.

The wizard also creates `etc/admin-storage.key` outside the local Admin data directory. It is not included in the gateway bundle. Back it up separately from `data/admin.redb` and encrypted `backup-*.redb` files; all of those database files require the same key, and the key alone contains no recoverable administration data.

Initialize Accounting in the dedicated database when ready:

```sh
"$HOME/Library/Application Support/Workglen/bin/workglen" accounting-init \
  "$HOME/Library/Application Support/Workglen/etc/admin.toml"
```

Alternatively use `--initialize-accounting` during setup. The schema starts disabled; enable Accounting in Modules after the console starts, then create a book. Initialization creates only Workglen's current schema and checks its workspace binding on later runs. It is not a Workglen upgrade/import operation.

## 3. Trust and launch the local console

The Mac console binds only to loopback and uses its generated localhost certificate. The current gateway test procedure uses a manually provisioned private test CA; public ACME/Let's Encrypt issuance is a separately tested capability. A public CA cannot validate your private `localhost` name.

For the guided path, open `~/Library/Application Support/Workglen` in Finder and double-click `install-local-ca.command`. It opens only the public `etc/local-ca.cer` in Keychain Access, shows the exact approval clicks, and opens the Admin URL after you confirm completion. Add the certificate to the Login keychain for the current user or System for all users, double-click `Workglen Local Admin CA`, expand Trust, set **When using this certificate** to **Always Trust**, close the window, and approve the macOS prompt. Quit and reopen Safari and Chrome. See [LOCAL-CA-TRUST.md](LOCAL-CA-TRUST.md) for the fallback import path and troubleshooting.

Check that the CA's critical name constraints permit only exact `localhost`, `127.0.0.1` and `::1`. Do not import or share `local-key.pem`. There is no CA private-key file: its in-memory signing key is discarded immediately after issuance. Corporate-managed Macs may require an administrator's approved trust procedure. The installer may open Keychain Access but never changes trust; macOS always requires explicit operator approval.

Start:

```sh
bash "$HOME/Library/Application Support/Workglen/run-admin.sh"
```

Keep that terminal running and open `https://localhost:8443/mail-security`; sign in as `admin` using your local Admin password. Use the main console for Accounting and Access. Stop with Control+C. The local leaf and constrained CA expire together within one year; they cannot be renewed with the discarded CA key. Before expiry, run `setup-local-tls` into a fresh private directory, update `admin.toml` to its new leaf/key, import and trust the new public CA, restart Admin, confirm the new certificate in Safari and Chrome, then delete the old trusted CA. Never generate into or overwrite the active directory. Local certificate trust/renewal is separate from automatic gateway ACME renewal. The SSH `.pem` used by `ssh metavero` is an SSH login key and is not a Workglen TLS or database key.

## 4. Transfer and install on the Ubuntu test server

From the directory containing the source ZIP and pairing bundle on your Mac, use your test-server SSH alias. Lightsail is one optional Ubuntu test host; the `metavero` alias below is only an example.

```sh
scp workglen-0.1.1-source.zip metavero:~/
scp -r workglen-gateway-bundle metavero:~/
ssh metavero
```

On the Ubuntu test server, unpack into a fresh directory and build for Linux:

```sh
unzip workglen-0.1.1-source.zip
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

## 5. Network and synthetic test checks

- Use test DNS records only where the test scenario requires them. Do not change public MX records during the current development phase.
- TCP 8445 serves the gateway's verified HTTPS management and recipient digest interface; constrain access to intended test administrators/recipients where practical. TCP 25 is the test inbound SMTP interface. TCP 80 is needed only for an explicitly configured simulated ACME HTTP-01 test, not for the manual private-CA setup above. Do not open the Mac's PostgreSQL port to the Ubuntu server or the public internet.
- Keep your SSH firewall rule intact. The installer changes neither host nor Lightsail firewall rules.
- When using Lightsail as the Ubuntu test host, check [AWS's Lightsail port-25 restrictions](https://repost.aws/knowledge-center/lightsail-port-25-throttle) before relying on outbound SMTP forwarding, and follow [Lightsail firewall guidance](https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-firewall-and-port-mappings-in-amazon-lightsail.html). Removing a provider restriction and changing a firewall rule are separate steps.
- Wait for a valid private test gateway certificate trusted by the Mac. Then open Mail Security in the Mac console and confirm a test status response. The shared workspace ID, instance ID and management key are generated consistently by the wizard. Central Admin checks the signed-in user's role and scope before projecting one command capability, and the gateway applies the narrow installation ceiling. Use the separate gateway recovery login for activation, configuration, quarantine disposition and other privileged operations during this containment phase.
- Provision the verified synthetic downstream SMTP route if omitted from the wizard, then complete test domains, synthetic recipients, rules/tests, digests and optional mailbox connectors. Activate tested rules and explicitly enable gateway acceptance only inside the test scenario. Run synthetic delivery/quarantine/digest checks for the test destination.

The gateway is mail security and SMTP forwarding. The test downstream mail system still provides mailbox hosting; the gateway does not become an Outlook/Exchange mailbox server merely by being installed.
