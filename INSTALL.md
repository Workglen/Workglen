# CLI installer

The Bash helper supports local Admin on macOS/Linux and an independently hosted Linux Mail Security gateway. It preserves the single Rust executable runtime: Bash orchestrates setup; the Rust executable generates secrets and certificates through Pratique. No OpenSSL executable, library, headers or pkg-config are required. It does not install PostgreSQL, change an existing database server, change DNS/firewalls, enroll a certificate into the OS trust store, or silently start services.

## One-command build

After extracting the source, run this as your normal login user:

```sh
bash install.sh build
```

The helper handles all supported build prerequisites in four steps:

1. Install missing system tools using the OS package manager or Apple's installer.
2. Install the pinned Rust/Cargo toolchain if needed.
3. Fetch missing dependencies at the exact versions in Cargo.lock.
4. Compile the release executable for this machine with one build job.

On **Ubuntu/Debian**, it detects and installs missing `build-essential`, `curl`,
`ca-certificates` and `unzip`. It runs `apt-get update` only when packages are
missing, then installs those packages and their dependencies. On **Amazon Linux
2023/Fedora and other DNF-based systems**, it installs missing `gcc`, `gcc-c++`,
`make`, `curl`, `ca-certificates` and `unzip`; an existing `curl-minimal` is reused.
It uses the configured system repositories, adds no repositories, and does not
request a full system upgrade or package removal. Existing prerequisites are
reused on later builds.

Run **without sudo**. The helper uses sudo only for Linux package operations,
which may request your login password. Rust installation, dependency fetching and
compilation run as your normal user. `--non-interactive` uses `sudo -n`; it requires
existing passwordless/cached authorization and fails clearly if unavailable.

On **macOS**, the helper checks for a working developer-tools selection and SDK.
If missing, it starts Apple's Command Line Tools installer. Complete Apple's
desktop dialog; an interactive build waits up to 30 minutes and resumes when the
tools are ready. A headless/noninteractive invocation explains the required
desktop step and asks you to rerun after completion. It does not bypass Apple's
agreements or install Homebrew. The system curl and unzip are reused.

`bash install.sh check` reports readiness without installing or downloading
anything. On other Linux package-manager families, already provisioned tools
can be used; missing tools require manual setup and produce a clear error.

## Rust and dependency setup

`bash install.sh build` sets up the pinned Rust **1.99.1** toolchain, including **Cargo**, when missing. It first checks `${CARGO_HOME:-$HOME/.cargo}/bin`, so an existing installation works even if your current shell has not refreshed PATH. If Rustup is absent, the helper downloads the official installer from `https://sh.rustup.rs` over verified HTTPS into a private temporary directory and executes it only after a successful download. It then installs Rust 1.99.1, rustfmt and Clippy from `https://static.rust-lang.org`. Existing Rustup is reused. No Rust mirror, OS Rust package, or extra runtime service is introduced.

Rust is installed for your user; the helper updates only its own PATH and does not edit shell profiles or select a new global default toolchain. Subsequent installer runs find the same tools automatically. Toolchain installation is an explicit installer step; Rustup's implicit downloads remain disabled during checks and compilation. `--offline` refuses missing tools without attempting installation.

For manual setup instead, follow [the official Rust installer](https://rust-lang.org/install.html), then run `rustup toolchain install 1.99.1 --profile minimal --component rustfmt --component clippy`.

`build` automatically runs `cargo fetch --locked` to download any missing dependencies at the versions recorded in `Cargo.lock`. Compilation then uses `--release --offline --locked --jobs 1`. The fetch does not upgrade locked dependencies. An explicit `build --fetch` is also accepted.

For a build with no system-package, toolchain or Cargo dependency downloads, use `bash install.sh build --offline`. It checks the installed prerequisites and dependency cache offline and stops with a clear instruction to run the normal build if either is unavailable; it never invokes sudo, an OS installer, or an online retry. A missing-package error such as `no matching package named anyhow found` means the offline cache is incomplete. Run `bash install.sh build` with network access to populate it.

Build on the target OS and CPU architecture. A macOS executable cannot be copied to Linux.

## Small hosts and out-of-memory builds

The default release profile now uses basic optimisation (`opt-level = 1`),
disabled link-time optimisation (`lto = "off"`), 16 codegen units, no debug symbols
and no incremental compilation. The helper still runs only one Cargo job.
This replaces the previous opt-level 3 / thin-LTO / one-codegen-unit profile,
which was too memory intensive on the reported Lightsail host. The executable
remains `target/release/workglen`; no feature is removed. These choices favour
build memory use over maximum optimisation; production throughput should be
benchmarked for the deployment.

`signal: 9, SIGKILL` means the compiler was killed externally. It can indicate
memory exhaustion, but the signal alone does not prove that. On Ubuntu/Linux,
check the kernel evidence and available memory:

```sh
sudo journalctl -k -b --no-pager | grep -Ei 'out of memory|oom-kill|killed process'
free -h
swapon --show
```

For an existing checkout with the older profile, retry without downloading a new
archive or cleaning the cache:

```sh
CARGO_PROFILE_RELEASE_LTO=off \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
CARGO_PROFILE_RELEASE_OPT_LEVEL=1 \
bash install.sh build --offline
```

The updated source makes those settings the default, so its normal `build`
command is sufficient. Cargo rebuilds affected artifacts and keeps reusable
cache entries. A very small instance may still need administrator-provided swap
or more RAM, or a build on a larger Linux host with a compatible architecture and
system ABI. Compile-time resource requirements are different from service
runtime limits. This change does not promise that a full build fits in 512 MiB.

### Temporary swap on Ubuntu

If the kernel confirms an out-of-memory kill even with the lighter settings,
temporary disk-backed swap can provide build headroom. The following creates a
new private 4 GiB file, refuses an existing path, and requires 6 GiB of free disk
space to leave some space for compilation. It preserves existing swap and does
not add a boot-time entry. Swap-file support depends on the filesystem; the
commands stop on a failure. Swapping may substantially slow compilation.

```sh
sudo bash <<'SWAP'
set -euo pipefail
swap_file=/var/lib/workglen-build.swap
if [ -e "$swap_file" ] || [ -L "$swap_file" ]; then
  echo "Swap file already exists; inspect it before continuing."
  exit 1
fi
available_kib=$(df -Pk /var/lib | awk 'NR==2 {print $4}')
if [ "$available_kib" -lt 6291456 ]; then
  echo "At least 6 GiB of free disk space is needed for this setup."
  exit 1
fi
umask 077
dd if=/dev/zero of="$swap_file" bs=1M count=4096 conv=excl status=progress
mkswap "$swap_file"
swapon "$swap_file"
swapon --show
SWAP
```

Only after that succeeds, retry the build as your normal user. Failed setup may
leave the newly created file for inspection; do not overwrite or reformat it
without checking its state. After the build, remove only the temporary swap
created by these instructions:

```sh
sudo swapoff /var/lib/workglen-build.swap && sudo rm -- /var/lib/workglen-build.swap
```

If swapoff fails, leave the file in place and resolve the memory pressure first.
The build helper itself does not change swap configuration.

### Resuming a build

Retry from the same Workglen source directory and keep its `target` directory.
Cargo reuses successfully compiled artifacts whose inputs and compiler settings
are unchanged. It retries a failed crate from that crate's compilation step;
it cannot resume halfway through an individual rustc process. Changing the
optimisation settings causes affected crates to rebuild once. Later retries
with those same settings reuse completed work. The helper never invokes
`cargo clean` or deletes the cache. A freshly extracted source directory has a
different default target directory and will not automatically reuse the old one.

References: [Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html)
[AWS memory troubleshooting](https://repost.aws/knowledge-center/ec2-linux-high-memory-usage),
and [AWS swap-file instructions](https://repost.aws/knowledge-center/ec2-memory-swap-file).

System-package installation failures retain the OS package manager's diagnostic
output and stop before Rust setup or compilation. Resolve network, repository,
package-lock or sudo errors, then rerun the same build command; installed tools
are reused. The helper does not create swap files or resize the machine.

PostgreSQL and the Linux gateway service are separate deployment choices. The
build does not install a database or start a gateway. The live gateway installer
requires systemd, `useradd`, `getent`, `runuser` and standard Unix utilities,
normally supplied by the supported Lightsail Linux images.

## Local Admin wizard

`bash install.sh admin` runs interactively. Default local installation: `~/Library/Application Support/Workglen`; default pairing bundle: `./workglen-gateway-bundle`. Both must be new paths. The helper creates:

- A native executable and `run-admin.sh`, with local HTTPS on 127.0.0.1:8443 and the token-authenticated CLI on 127.0.0.1:8025.
- A public P-256 local CA certificate in PEM and Keychain-friendly DER `.cer` formats, with critical constraints limited to exact `localhost`, `127.0.0.1` and `::1`, plus a one-year localhost certificate/key, local Admin password hash, CLI token and gateway management key. The CA signing key is held only in zeroizing memory while the leaf is signed and is never written.
- A fresh encrypted `admin.redb` store and separate owner-only `admin-storage.key`, with Mail and Webmail disabled. The `admin_only` profile cannot start SMTP, submission, IMAP, Webmail, relay, replication or witness workers and never creates `mail.redb`.
- Optional protected Accounting DSN and base64-encoded bank-feed encryption key. `--initialize-accounting` explicitly creates the Workglen schema in the selected database; it does not create a PostgreSQL server, database or role.
- A separately protected gateway bundle carrying its own configuration, shared management key and recovery administrator hash. The shared key authenticates the paired Admin installation, not an individual operator, and the generated gateway limits it to read/status, rule drafting and rule testing. Higher-risk changes use the gateway recovery login until the planned non-bearer operator protocol is implemented. The bundle never includes the Mac's PostgreSQL DSN, local private TLS key, local CLI token or local Admin password hash.

Passwords are prompted without echo, confirmed and hashed immediately; raw passwords are not saved. Automation uses `--password-file` and `--gateway-password-file` with owner-only regular files; passwords are never command-line values. The local Admin key is always generated into its own private `etc` directory and is never copied into the gateway bundle. Generated gateway storage keys are created on the gateway, while `--storage-key-file` selects gateway BYOK. The gateway bundle therefore contains a gateway database key only when you explicitly supplied one.

Interactive password errors keep your earlier setup answers. A confirmation
mismatch, invalid length or multiline entry displays an explanation and asks
for that password again. If the Local Admin and gateway recovery passwords
match, the wizard asks for a different gateway password; if the gateway password
came from a file, it asks for a different interactive Local Admin password.
Invalid password files or identical passwords supplied entirely through files
stop with an error so the operator can correct the files. End-of-input or
Control+C cancels setup. No installation or pairing bundle is created until
both passwords have been accepted.

See `bash install.sh --help` for ports, manual certificates, staging, paths and noninteractive options. `--tls manual` requires a matching existing certificate/key; the configured public gateway DNS name must appear on the certificate. Native TLS hostname verification remains enabled when the Admin connects. For private CA deployments, supply a trust chain that contains the appropriate issuer; preserve that trust bundle across certificate renewals.

The wizard issues only its constrained, host-local Admin CA/leaf and performs no public or gateway CA issuance and no mailbox operations. Native `check` parses configuration and credentials offline. Initialization of local redb also stays offline. A requested Accounting initialization contacts only the configured PostgreSQL endpoint. In a separately and explicitly authorized ACME test, the Linux `--start` operation may initiate Let's Encrypt issuance because it starts an ACME-configured service. ACME is not part of the current private-test-CA procedure; use manual private test certificates for that procedure.

After installation, double-click `install-local-ca.command` in the local Admin directory for the macOS trust click path. The helper opens only the public CA in Keychain Access and prints the remaining approval steps; it cannot silently add trust. See [LOCAL-CA-TRUST.md](LOCAL-CA-TRUST.md) for manual import, Safari/Chrome verification, managed-Mac guidance and renewal cautions.

### Local Admin backup and recovery

With Admin running, `workglen backup ADMIN_CONFIG` creates an encrypted logical backup in the Admin data directory. It never places the storage key in the backup. Preserve a protected copy of `admin-storage.key` separately; losing either the key or every valid database/backup is unrecoverable.

`workglen admin-restore ADMIN_CONFIG ENCRYPTED_BACKUP` validates the key, encryption authentication, Admin-store marker and workspace binding, writes a new encrypted database, and atomically installs it. The command is fresh-only: Admin must be stopped and the configured data directory must not already contain `admin.redb`. It refuses to overwrite a live or preserved store. A wrong key, plaintext input, damaged header, different workspace or non-Admin encrypted store fails closed.

## Ubuntu test gateway install

Build the Linux executable and transfer the bundle first. The following creates a disposable test installation on an Ubuntu server test machine; no current installation exists.

```sh
sudo bash install.sh gateway --bundle /absolute/path/workglen-gateway-bundle --start
```

The helper refuses pre-existing `/etc/workglen-security`, `/var/lib/workglen-security` or either systemd unit, and refuses to replace a different installed binary. It creates a dedicated unprivileged service account, private directories and credentials, generates the encryption key if BYOK was not supplied, validates the configuration, initializes the administrator, and installs the ingress/control and scanner units. Both roles use the same native executable; only `security-serve` opens encrypted storage. Without `--start` it initializes the files/database but leaves both services stopped. `--start` enables automatic startup after reboot and checks both processes; certificate readiness still needs the service log/status check.

No firewall rules or SSH configuration are changed. Port 80 is required only when ACME HTTP-01 is explicitly tested. The current development procedure uses private test certificates and synthetic recipients/routes; do not issue public certificates or change public MX. The gateway initially defers new messages until its guided setup and rules are explicitly enabled.

Failures retain partial files for inspection and never delete or overwrite data to retry. Inspect a partial installation before removing only newly created files yourself. Keep a separate protected backup of the database encryption key and the pairing key.

`gateway --destdir /new/path` stages the filesystem layout for inspection/tests. It creates no account, database or service, never generates a gateway storage key and cannot be combined with `--start`. It is not a completed live installation.

## Validation boundary

The bundled tests exercise the actual generated configurations, native initialization, loopback-only Admin startup, authenticated remote gateway control, local PostgreSQL transport, file separation/permissions and refusal paths using synthetic local fixtures. No production host, firewall, public certificate account or customer database is changed. The developer laptop is an Apple Silicon M5 Mac and server test machines run Ubuntu. The executed evidence packaged here is Linux x86-64 unless a record explicitly says otherwise; do not treat it as M5 macOS compilation, Keychain enrollment or startup validation. There are no current installations. See [VALIDATION.md](VALIDATION.md).

## Delivery destinations after installation

`--downstream-host` remains an optional way to supply an initial STARTTLS route. If omitted, use **Mail Security → Setup → Mail flow → Add a delivery destination** in the app; no JSON edit is needed for a public Microsoft 365 or other supported SMTP destination. The wizard finds Microsoft MX candidates, tests verified TLS and saves the route in encrypted settings. See [DELIVERY-DESTINATIONS.md](DELIVERY-DESTINATIONS.md).
