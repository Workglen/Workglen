#!/usr/bin/env bash
# Workglen fresh-install helper. Compatible with macOS Bash 3.2 and Linux Bash.
set +x
set -Eeuo pipefail
umask 077
export LC_ALL=C
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
COMMAND=${1:-help}
if [ "$#" -gt 0 ]; then shift; fi
BINARY="$SOURCE/target/release/workglen"
ADMIN_HOME="${HOME}/Library/Application Support/Workglen"
BUNDLE="$PWD/workglen-gateway-bundle"
GATEWAY_HOST= DOMAIN= EMAIL= PASSWORD_FILE= GATEWAY_PASSWORD_FILE=
PG_DSN= PG_CA= STORAGE_KEY= CERT= KEY= DOWNSTREAM=
TLS=letsencrypt PG_TRANSPORT=local INSTANCE=gateway-a
WEB_PORT=8443 CLI_PORT=8025 GATEWAY_PORT=8445 SMTP_PORT=25 ACME_PORT=80
NONINTERACTIVE=false AGREE=false START=false FETCH=false OFFLINE=false INIT_ACCOUNTING=false DESTDIR=
die() { printf 'workglen installer: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing $1. See INSTALL.md prerequisites."; }
help() {
cat <<'HELP'
Workglen installer — Mac/local Admin + Accounting and Linux Mail Security

  bash install.sh check                       # Check build prerequisites
  bash install.sh build                       # Install prerequisites and build
  bash install.sh build --offline             # Installed tools and cached crates only
  bash install.sh admin [options]             # Interactive local setup + pairing bundle
  sudo bash install.sh gateway --bundle PATH [--binary PATH] [--start]

Admin options:
  --binary PATH               Native executable (default target/release/workglen)
  --home PATH                 New local installation directory
  --bundle PATH               New private gateway bundle directory
  --gateway-host DNS          Public gateway hostname (required)
  --domain DNS                Mail domain managed by this console (required)
  --tls letsencrypt|staging|manual    Gateway certificates; production is typical
  --email ADDRESS --agree-to-terms   Required for Let's Encrypt
  --cert PATH --key PATH      Existing gateway certificate/key for manual TLS
  --password-file PATH        Local Admin password, owner-only file
  --gateway-password-file PATH      Separate gateway recovery password
  --storage-key-file PATH     Optional gateway BYOK; otherwise generated on Linux
  --postgres-dsn-file PATH    Existing PostgreSQL connection file (optional)
  --postgres-transport local|verified-tls    Default local (loopback/socket only)
  --postgres-ca-file PATH     CA for verified-tls, if needed
  --initialize-accounting     Create Workglen schema in the chosen dedicated DB
  --downstream-host DNS       Optional initial verified STARTTLS delivery route
  --instance ID              Default gateway-a
  --web-port N --cli-port N  Local loopback Admin ports (8443 / 8025)
  --gateway-port N --smtp-port N --acme-port N    Default 8445 / 25 / 80
  --non-interactive           Require explicit inputs; never prompt for secrets

Gateway options:
  --destdir PATH              Stage files only; no users, DB initialization or services
  --start                    Enable/start systemd service after successful initialization

No existing configuration, key or database is overwritten. Build installs missing
system prerequisites, Rust/Cargo and locked dependencies. Run it without sudo;
only Linux package installation uses sudo. Compilation runs as your normal user.
Use build --offline to skip downloads. An explicit --fetch is also accepted.
See START-HERE.md, INSTALL.md, MAC-ADMIN-LIGHTSAIL.md and DOCUMENTATION.md.
HELP
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h) help; exit 0;;
        --non-interactive) NONINTERACTIVE=true; shift;;
        --agree-to-terms) AGREE=true; shift;;
        --start) START=true; shift;;
        --fetch) FETCH=true; shift;;
        --offline) OFFLINE=true; shift;;
        --initialize-accounting) INIT_ACCOUNTING=true; shift;;
        --binary|--home|--bundle|--gateway-host|--domain|--email|--password-file|--gateway-password-file|--postgres-dsn-file|--postgres-ca-file|--postgres-transport|--storage-key-file|--tls|--cert|--key|--downstream-host|--instance|--web-port|--cli-port|--gateway-port|--smtp-port|--acme-port|--destdir)
            [ "$#" -ge 2 ] || die "Missing value for $1"
            case "$1" in
                --binary) BINARY=$2;; --home) ADMIN_HOME=$2;; --bundle) BUNDLE=$2;;
                --gateway-host) GATEWAY_HOST=$2;; --domain) DOMAIN=$2;; --email) EMAIL=$2;;
                --password-file) PASSWORD_FILE=$2;; --gateway-password-file) GATEWAY_PASSWORD_FILE=$2;;
                --postgres-dsn-file) PG_DSN=$2;; --postgres-ca-file) PG_CA=$2;; --postgres-transport) PG_TRANSPORT=$2;;
                --storage-key-file) STORAGE_KEY=$2;; --tls) TLS=$2;; --cert) CERT=$2;; --key) KEY=$2;;
                --downstream-host) DOWNSTREAM=$2;; --instance) INSTANCE=$2;;
                --web-port) WEB_PORT=$2;; --cli-port) CLI_PORT=$2;; --gateway-port) GATEWAY_PORT=$2;;
                --smtp-port) SMTP_PORT=$2;; --acme-port) ACME_PORT=$2;; --destdir) DESTDIR=$2;;
            esac
            shift 2;;
        *) die "Unknown option: $1";;
    esac
done
OS=$(uname -s)
absolute() {
    case "$1" in /*) ;; *) die "Use an absolute path: $1";; esac
    case "$1" in *$'\n'*|*$'\r'*|*/../*|*/..|/) die "Unsafe path: $1";; esac
}
private_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || die "Expected a regular, unlinked file: $1"
    local mode links
    if [ "$OS" = Darwin ]; then mode=$(stat -f '%Lp' "$1"); links=$(stat -f '%l' "$1");
    else mode=$(stat -c '%a' "$1"); links=$(stat -c '%h' "$1"); fi
    [ "$links" = 1 ] && [ $((8#$mode & 077)) -eq 0 ] || die "Use owner-only permissions (chmod 600) and no hard links: $1"
}
dns_name() {
    local label value=$1
    [ "${#value}" -le 253 ] && [[ "$value" == *.* ]] || die "Use a full lowercase DNS name: $value"
    local parts
    IFS=. read -r -a parts <<< "$value"
    [[ "$value" != *. ]] || die "DNS name must not end in a dot"
    for label in "${parts[@]}"; do
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] && [ "${#label}" -le 63 ] || die "Invalid DNS name: $value"
    done
}
port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ] || die "Invalid port: $1"; }
q() { local value=$1; value=${value//\\/\\\\}; value=${value//\"/\\\"}; printf '"%s"' "$value"; }
prompt() {
    local name=$1 text=$2 default=${3:-} answer
    if [ -n "${!name}" ]; then return; fi
    if $NONINTERACTIVE; then [ -n "$default" ] || die "$text is required"; printf -v "$name" '%s' "$default"; return; fi
    printf '%s%s: ' "$text" "${default:+ [$default]}" >&2
    IFS= read -r answer || die "Input ended"
    printf -v "$name" '%s' "${answer:-$default}"
    [ -n "${!name}" ] || die "$text is required"
}
password() {
    local file=$1 label=$2 value again error
    while :; do
        error=
        if [ -n "$file" ]; then
            private_file "$file"; [ "$(wc -c < "$file")" -le 1025 ] || die "Password file too large"
            value=$(cat -- "$file")
        else
            $NONINTERACTIVE && die "$label password file is required"
            printf '%s password (12+ characters): ' "$label" >&2
            IFS= read -r -s value || die "Input ended"; printf '\n' >&2
            printf 'Repeat password: ' >&2
            IFS= read -r -s again || die "Input ended"; printf '\n' >&2
            [ "$value" = "$again" ] || error='Passwords do not match'
        fi
        if [ -z "$error" ]; then
            [ "${#value}" -ge 12 ] && [ "${#value}" -le 1024 ] || error='Use a password of 12..1024 characters'
            case "$value" in *$'\n'*|*$'\r'*) error='Password must be a single line';; esac
        fi
        if [ -z "$error" ]; then printf '%s' "$value"; return; fi
        [ -z "$file" ] || die "$label: $error"
        printf 'workglen installer: %s. Please enter the %s password again.\n' "$error" "$label" >&2
        unset value again
    done
}
copy_docs() {
    local dest=$1 file rel
    mkdir -p "$dest/security" "$dest/validation"
    for file in "$SOURCE"/*.md "$SOURCE"/security/*.md "$SOURCE"/validation/*; do
        [ -f "$file" ] || continue
        rel=${file#"$SOURCE"/}; cp -- "$file" "$dest/$rel"
    done
    cp "$SOURCE/LICENSE" "$dest/LICENSE"
    mkdir -p "$dest/vendor/pratique"
    cp "$SOURCE/vendor/pratique/LICENSE" "$dest/vendor/pratique/LICENSE"
    for file in config deploy examples schema; do cp -R "$SOURCE/$file" "$dest/$file"; done
    for file in "$SOURCE"/security/*.json; do cp "$file" "$dest/security/"; done
}
platform_packages() {
    PACKAGE_MANAGER=none
    MISSING_PACKAGES=
    local package status
    if command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then
        PACKAGE_MANAGER=apt
        for package in build-essential curl ca-certificates unzip; do
            if ! status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null) || [ "$status" != 'install ok installed' ]; then
                MISSING_PACKAGES="$MISSING_PACKAGES $package"
            fi
        done
    elif command -v dnf >/dev/null 2>&1 && command -v rpm >/dev/null 2>&1; then
        PACKAGE_MANAGER=dnf
        for package in gcc gcc-c++ make curl ca-certificates unzip; do
            # Amazon Linux's existing curl-minimal supports HTTPS; do not replace it.
            if [ "$package" = curl ] && command -v curl >/dev/null 2>&1; then continue; fi
            if ! rpm -q "$package" >/dev/null 2>&1; then MISSING_PACKAGES="$MISSING_PACKAGES $package"; fi
        done
    fi
}
privileged() {
    command -v sudo >/dev/null 2>&1 || die "Installing system prerequisites needs sudo. Use a login with sudo access, then rerun build."
    if $NONINTERACTIVE; then
        sudo -n -- "$@" || die "System package setup failed. Check the error above and sudo access, then rerun build."
    else
        sudo -- "$@" || die "System package setup failed. Check the error above and sudo access, then rerun build."
    fi
}
mac_tools_ready() {
    command -v xcode-select >/dev/null 2>&1 && xcode-select -p >/dev/null 2>&1 &&
        xcrun --find clang >/dev/null 2>&1 && xcrun --find clang++ >/dev/null 2>&1 &&
        xcrun --show-sdk-path >/dev/null 2>&1
}
ensure_platform() {
    local tool elapsed
    if [ "$OS" = Darwin ]; then
        if ! mac_tools_ready; then
            $OFFLINE && die "Apple Command Line Tools are missing. Run build without --offline to install them."
            say "Opening Apple's Command Line Tools installer. Complete its installation dialog to continue."
            xcode-select --install || die "Cannot start Apple's installer. If it is already open, finish it and rerun build; otherwise see INSTALL.md."
            elapsed=0
            while ! mac_tools_ready; do
                if $NONINTERACTIVE || [ ! -t 0 ]; then
                    die "Apple's installation needs desktop interaction. Complete it, then rerun bash install.sh build."
                fi
                [ "$elapsed" -lt 1800 ] || die "Still waiting for Apple tools. Finish the installation and rerun build."
                if [ $((elapsed % 60)) -eq 0 ]; then say "Waiting for Apple tools; the build will continue automatically. Ctrl-C cancels this wait."; fi
                sleep 5
                elapsed=$((elapsed + 5))
            done
        fi
    else
        platform_packages
        if [ -n "$MISSING_PACKAGES" ]; then
            $OFFLINE && die "Missing system prerequisites:$MISSING_PACKAGES. Run build without --offline to install them."
            say "Installing missing system prerequisites:$MISSING_PACKAGES"
            say "Sudo may ask for your login password. Rust and compilation will run as your normal user."
            # Package names come only from the fixed lists above; splitting is intentional.
            if [ "$PACKAGE_MANAGER" = apt ]; then
                privileged env DEBIAN_FRONTEND=noninteractive apt-get update
                privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-remove --no-upgrade $MISSING_PACKAGES
            else
                privileged dnf install -y $MISSING_PACKAGES
            fi
            hash -r
            platform_packages
            [ -z "$MISSING_PACKAGES" ] || die "Some system prerequisites are still unavailable:$MISSING_PACKAGES. Check the package-manager output above."
        fi
    fi
    for tool in cc c++ make curl unzip; do
        command -v "$tool" >/dev/null 2>&1 || die "Missing $tool after checking prerequisites. Automatic Linux setup supports APT and DNF; see INSTALL.md for other systems or PATH repairs."
    done
}
rust_path() {
    local bin="${CARGO_HOME:-$HOME/.cargo}/bin"
    # Rustup may already be installed in a shell whose PATH has not been refreshed.
    if [ -x "$bin/rustup" ] || [ -x "$bin/cargo" ]; then
        export PATH="$bin:$PATH"
        hash -r
    fi
}
rust_version() {
    local version
    version=$(RUSTUP_AUTO_INSTALL=0 RUSTUP_TOOLCHAIN=1.99.1 rustc --version) || return 1
    case "$version" in
        'rustc 1.99.1 '*) say "$version";;
        *) printf 'Expected Rust 1.99.1; found %s\n' "$version" >&2; return 1;;
    esac
}
install_rust() (
    # A subshell keeps download cleanup and official-source overrides local.
    [ "$(id -u)" != 0 ] || die "Run build as your normal login user, without sudo, to install Rust/Cargo."
    export RUSTUP_DIST_SERVER=https://static.rust-lang.org
    export RUSTUP_UPDATE_ROOT=https://static.rust-lang.org/rustup
    if ! command -v rustup >/dev/null 2>&1; then
        need curl; need mktemp; need sh
        local temp
        temp=$(mktemp -d "${TMPDIR:-/tmp}/workglen-rust.XXXXXXXX") || die "Cannot create a private download directory."
        trap 'rm -rf -- "$temp"' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        say "Installing Rustup for your user from https://sh.rustup.rs."
        curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error \
            --location --connect-timeout 30 --max-time 180 \
            --output "$temp/rustup-init.sh" https://sh.rustup.rs \
            || die "Rustup download failed. No downloaded script was executed. Check network access and CA certificates."
        # Download completely before execution. Do not change shell profiles/defaults.
        sh "$temp/rustup-init.sh" -y --no-modify-path --profile minimal --default-toolchain none \
            || die "Rustup installation failed; resolve the error above, then rerun build."
        rust_path
    fi
    need rustup
    say "Installing pinned Rust 1.99.1, including Cargo, rustfmt and Clippy."
    rustup toolchain install 1.99.1 --profile minimal --component rustfmt --component clippy --no-self-update \
        || die "Rust toolchain installation failed; resolve the error above, then rerun build."
)
ensure_rust() {
    rust_path
    if command -v cargo >/dev/null 2>&1 && rust_version 2>/dev/null; then return; fi
    $OFFLINE && die "Rust/Cargo 1.99.1 is missing or unavailable. Run bash install.sh build with network access to install it. Offline mode downloads nothing."
    say "Rust/Cargo 1.99.1 is not ready; setting it up before the build."
    install_rust
    rust_path
    need cargo
    rust_version || die "Rust setup completed but the pinned compiler is unavailable. See INSTALL.md."
}
check() {
    export RUSTUP_AUTO_INSTALL=0 RUSTUP_TOOLCHAIN=1.99.1
    rust_path
    say "System: $OS / $(uname -m)"
    for tool in bash cc c++ make curl unzip cargo rustc; do
        if command -v "$tool" >/dev/null 2>&1; then say "Available: $tool"; else say "Missing: $tool"; fi
    done
    if [ "$OS" = Linux ]; then
        platform_packages
        [ -z "$MISSING_PACKAGES" ] || say "Build will install system packages:$MISSING_PACKAGES"
    elif [ "$OS" = Darwin ] && ! mac_tools_ready; then
        say "Build will open Apple's Command Line Tools installer."
    fi
    local version
    if version=$(rust_version 2>/dev/null); then say "Toolchain ready: $version";
    else
        say "Pinned Rust/Cargo 1.99.1 is not ready. Build will install it from the official Rust distribution."
    fi
    say "Build (sets up system tools, Rust/Cargo and dependencies): bash install.sh build"
    say "Build using cached dependencies only: bash install.sh build --offline"
    say "This check does not install or download anything. See INSTALL.md."
    say "Build on each target OS/architecture. A macOS binary cannot run on Lightsail Linux."
}
build() {
    [ "$OS" = Linux ] || [ "$OS" = Darwin ] || die "Build helper supports Linux and macOS"
    if $OFFLINE && $FETCH; then die "Choose --offline or --fetch, not both."; fi
    cd "$SOURCE"
    # Only our explicit setup step may install a missing toolchain.
    export RUSTUP_AUTO_INSTALL=0 RUSTUP_TOOLCHAIN=1.99.1
    [ "$(id -u)" != 0 ] || die "Run bash install.sh build as your normal login user, without sudo. The helper elevates only system package installation."
    say "Step 1/4: Checking system build prerequisites."
    ensure_platform
    say "Step 2/4: Checking Rust/Cargo 1.99.1."
    ensure_rust
    say "Step 3/4: Preparing locked Cargo dependencies."
    if $OFFLINE; then
        say "Checking cached Cargo dependencies without downloading."
        cargo fetch --offline --locked || die "Locked dependencies are not ready for an offline build. Run bash install.sh build with network access to fetch them. If that fails, resolve the Cargo error above."
    else
        say "Fetching locked Cargo dependencies before offline compilation."
        cargo fetch --locked || die "Dependency download failed; resolve the Cargo error above, then retry bash install.sh build."
    fi
    say "Step 4/4: Building for this machine using cached dependencies (one job)."
    say "The default release profile uses basic optimisation, no LTO and 16 codegen units to reduce compiler memory use."
    local result
    if cargo build --release --offline --locked --jobs 1; then
        :
    else
        result=$?
        say "Compilation failed; the Cargo diagnostic above is the primary error."
        if [ "$OS" = Linux ]; then
            say "If it reports SIGKILL/signal 9, memory exhaustion is one possible cause. Check:"
            say "  free -h"
            say "  sudo journalctl -k -b --no-pager | grep -Ei 'out of memory|oom-kill|killed process'"
            say "A small host may still need more memory or administrator-provided swap, or a build on a larger compatible Linux host."
        fi
        say "Rerun the same build command after resolving the error; keep the target cache."
        return "$result"
    fi
    say "Built target/release/workglen for $OS / $(uname -m)"
}
admin() {
    [ "$OS" = Darwin ] || [ "$OS" = Linux ] || die "Local Admin supports macOS and Linux"
    absolute "$ADMIN_HOME"; absolute "$BUNDLE"
    [ ! -e "$ADMIN_HOME" ] && [ ! -L "$ADMIN_HOME" ] || die "Admin installation already exists: $ADMIN_HOME"
    [ ! -e "$BUNDLE" ] && [ ! -L "$BUNDLE" ] || die "Gateway bundle already exists: $BUNDLE"
    case "$BUNDLE/" in "$ADMIN_HOME/"*) die "Keep the gateway bundle outside the local installation";; esac
    case "$ADMIN_HOME/" in "$BUNDLE/"*) die "Keep the local installation outside the gateway bundle";; esac
    [ -x "$BINARY" ] || die "Build Workglen first, or provide --binary PATH. See INSTALL.md."
    prompt GATEWAY_HOST 'Public DNS hostname of the Lightsail gateway'
    prompt DOMAIN 'Mail domain managed by this gateway'
    dns_name "$GATEWAY_HOST"; dns_name "$DOMAIN"
    [[ "$INSTANCE" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$ ]] || die "Invalid instance ID"
    for p in "$WEB_PORT" "$CLI_PORT" "$GATEWAY_PORT" "$SMTP_PORT" "$ACME_PORT"; do port "$p"; done
    [ "$WEB_PORT" != "$CLI_PORT" ] || die "Local Admin ports must differ"
    [ "$GATEWAY_PORT" != "$SMTP_PORT" ] && [ "$GATEWAY_PORT" != "$ACME_PORT" ] && [ "$SMTP_PORT" != "$ACME_PORT" ] || die "Gateway listener ports must differ"
    if ! $NONINTERACTIVE; then
        say "Gateway TLS: letsencrypt (production), staging (untrusted test certificates), or manual."
        printf 'Certificate mode [%s]: ' "$TLS" >&2; IFS= read -r answer || die "Input ended"; TLS=${answer:-$TLS}
    fi
    case "$TLS" in
        letsencrypt|staging)
            prompt EMAIL 'Contact email for the certificate account'
            [[ "$EMAIL" =~ ^[a-zA-Z0-9._+%-]+@[a-zA-Z0-9.-]+$ ]] || die "Invalid contact email"
            dns_name "${EMAIL#*@}"
            if ! $AGREE && ! $NONINTERACTIVE; then
                say "Review https://letsencrypt.org/repository/ and ensure public port 80 reaches this gateway."
                printf 'Do you accept the subscriber terms? [no]: ' >&2
                IFS= read -r answer || die "Input ended"; [ "$answer" != yes ] || AGREE=true
            fi
            $AGREE || die "Explicit agreement is required (--agree-to-terms after review)";;
        manual)
            prompt CERT 'Gateway certificate chain file'; prompt KEY 'Gateway private key file'
            private_file "$KEY"; [ -f "$CERT" ] && [ ! -L "$CERT" ] || die "Certificate must be a regular file"
            "$BINARY" setup-check-tls "$CERT" "$KEY" "$GATEWAY_HOST";;
        *) die "Unknown TLS mode";;
    esac
    if [ -n "$DOWNSTREAM" ]; then dns_name "$DOWNSTREAM"; fi
    if [ -n "$STORAGE_KEY" ]; then private_file "$STORAGE_KEY"; fi
    if [ -z "$PG_DSN" ] && ! $NONINTERACTIVE; then
        say "Accounting can use PostgreSQL already on this Mac. No database server will be installed."
        printf 'Path to a protected PostgreSQL connection file (Enter to configure later): ' >&2
        IFS= read -r PG_DSN || die "Input ended"
    fi
    case "$PG_TRANSPORT" in local|verified-tls) ;; *) die "Unknown PostgreSQL transport";; esac
    if [ -n "$PG_DSN" ]; then
        private_file "$PG_DSN"
        if [ -n "$PG_CA" ]; then [ "$PG_TRANSPORT" = verified-tls ] || die "CA file requires verified-tls"; [ -f "$PG_CA" ] || die "CA file missing"; fi
    else
        ! $INIT_ACCOUNTING || die "Accounting initialization requires --postgres-dsn-file"
    fi
    local local_password gateway_password workspace etc data staging
    local_password=$(password "$PASSWORD_FILE" 'Local Admin')
    gateway_password=$(password "$GATEWAY_PASSWORD_FILE" 'Gateway recovery administrator')
    while [ "$local_password" = "$gateway_password" ]; do
        if $NONINTERACTIVE || { [ -n "$PASSWORD_FILE" ] && [ -n "$GATEWAY_PASSWORD_FILE" ]; }; then
            die "Use different local Admin and gateway recovery passwords; update the supplied password files"
        fi
        printf 'workglen installer: Use different local Admin and gateway recovery passwords.\n' >&2
        if [ -z "$GATEWAY_PASSWORD_FILE" ]; then
            gateway_password=$(password '' 'Gateway recovery administrator')
        else
            local_password=$(password '' 'Local Admin')
        fi
    done
    say "Preparing local Admin at $ADMIN_HOME and gateway bundle at $BUNDLE"
    mkdir -p "$ADMIN_HOME" "$BUNDLE"
    chmod 700 "$ADMIN_HOME" "$BUNDLE"
    # Failures retain partial artifacts for inspection; never silently replace keys on retry.
    trap 'say "Setup stopped. Partial files were retained; inspect them before choosing a new installation path." >&2' ERR
    etc="$ADMIN_HOME/etc"; data="$ADMIN_HOME/data"
    mkdir -p "$etc" "$data" "$ADMIN_HOME/bin"
    cp -- "$BINARY" "$ADMIN_HOME/bin/workglen"; chmod 700 "$ADMIN_HOME/bin/workglen"
    workspace=$("$BINARY" setup-random hex 16)
    "$BINARY" setup-random hex 32 > "$etc/admin.token"
    "$BINARY" setup-random hex 32 > "$etc/gateway-control.key"
    "$BINARY" security-generate-key "$etc/admin-storage.key"
    cp -- "$etc/gateway-control.key" "$BUNDLE/control.key"
    printf '%s' "$local_password" | "$BINARY" hash-password > "$etc/admin.hash"
    printf '%s' "$gateway_password" | "$BINARY" hash-password > "$BUNDLE/admin.hash"
    unset local_password gateway_password
    "$BINARY" setup-local-tls "$etc"

    if [ -n "$PG_DSN" ]; then
        cp -- "$PG_DSN" "$etc/postgres.dsn"
        "$BINARY" setup-random base64 32 > "$etc/feed.key"
        if [ -n "$PG_CA" ]; then cp -- "$PG_CA" "$etc/postgres-ca.pem"; fi
    fi
    {
        printf 'admin_only = true\nmode = "single"\nnode_id = "local-admin"\nhostname = "localhost"\nrole = "primary"\ndomain = '; q "$DOMAIN"
        printf '\ndata_dir = '; q "$data"
        printf '\nadmin_storage_key_file = '; q "$etc/admin-storage.key"
        printf '\nadmin_listen = "127.0.0.1:%s"\nadmin_token_file = ' "$CLI_PORT"; q "$etc/admin.token"
        printf '\ntls_cert = '; q "$etc/local-cert.pem"; printf '\ntls_key = '; q "$etc/local-key.pem"
        printf '\n# Placeholders are never bound in the admin_only process profile.\nsmtp_listen = "127.0.0.1:0"\nsubmission_listen = "127.0.0.1:0"\nimap_listen = "127.0.0.1:0"\n'
        printf '\n[replication]\ncluster_id = "%s"\n[web]\nlisten = "127.0.0.1:%s"\norigin = "https://localhost:%s"\nusername = "admin"\npassword_hash_file = ' "$workspace" "$WEB_PORT" "$WEB_PORT"; q "$etc/admin.hash"
        printf '\n[[security_remotes]]\nid = "%s"\nlabel = "Lightsail gateway"\norigin = "https://%s:%s"\nkey_file = ' "$INSTANCE" "$GATEWAY_HOST" "$GATEWAY_PORT"; q "$etc/gateway-control.key"
        if [ "$TLS" = manual ]; then cp -- "$CERT" "$etc/gateway-ca.pem"; printf '\nca_file = '; q "$etc/gateway-ca.pem"; fi
        if [ -n "$PG_DSN" ]; then
            printf '\n[accounting]\ntransport = "%s"\ndsn_file = ' "$PG_TRANSPORT"; q "$etc/postgres.dsn"
            printf '\nfeed_key_file = '; q "$etc/feed.key"; printf '\npool_size = 2'
            if [ -n "$PG_CA" ]; then printf '\nca_file = '; q "$etc/postgres-ca.pem"; fi
        fi
        printf '\n'
    } > "$etc/admin.toml"
    staging=false; [ "$TLS" != staging ] || staging=true
    {
        printf '{"workspace":"%s","instance":"%s","hostname":"%s","origin":"https://%s:%s",' "$workspace" "$INSTANCE" "$GATEWAY_HOST" "$GATEWAY_HOST" "$GATEWAY_PORT"
        printf '"data_dir":"/var/lib/workglen-security","storage_key_file":"/etc/workglen-security/storage.key","control_key_file":"/etc/workglen-security/control.key",'
        printf '"smtp_listen":["0.0.0.0",%s],"https_listen":["0.0.0.0",%s],"connectors":{},"routes":{' "$SMTP_PORT" "$GATEWAY_PORT"
        if [ -n "$DOWNSTREAM" ]; then printf '"downstream":{"host":"%s","port":25,"implicit_tls":false}' "$DOWNSTREAM"; fi
        printf '},"trusted_admin":{"permissions":["read","rules.write","rules.test"],"domains":["*"],"mailboxes":["*"]},'
        if [ "$TLS" = manual ]; then
            printf '"tls_cert":"/etc/workglen-security/fullchain.pem","tls_key":"/etc/workglen-security/privkey.pem"'
        else
            printf '"acme":{"domains":["%s"],"email":"%s","state_dir":"/var/lib/workglen-security/acme","http_listen":"0.0.0.0:%s","staging":%s,"agree_to_terms":true}' "$GATEWAY_HOST" "$EMAIL" "$ACME_PORT" "$staging"
        fi
        printf '}\n'
    } > "$BUNDLE/config.json"
    if [ "$TLS" = manual ]; then cp -- "$CERT" "$BUNDLE/fullchain.pem"; cp -- "$KEY" "$BUNDLE/privkey.pem"; fi
    if [ -n "$STORAGE_KEY" ]; then cp -- "$STORAGE_KEY" "$BUNDLE/storage.key"; fi
    chmod 600 "$etc"/* "$BUNDLE"/*
    "$ADMIN_HOME/bin/workglen" check "$etc/admin.toml"
    "$ADMIN_HOME/bin/workglen" init "$etc/admin.toml" --bootstrap
    if $INIT_ACCOUNTING; then "$ADMIN_HOME/bin/workglen" accounting-init "$etc/admin.toml"; fi
    cat > "$ADMIN_HOME/run-admin.sh" <<'RUN'
#!/usr/bin/env bash
set -eu
HERE=$(cd -- "$(dirname -- "$0")" && pwd -P)
exec "$HERE/bin/workglen" admin-serve "$HERE/etc/admin.toml"
RUN
    chmod 700 "$ADMIN_HOME/run-admin.sh"
    copy_docs "$ADMIN_HOME/docs"
    cp "$SOURCE/MAC-ADMIN-LIGHTSAIL.md" "$BUNDLE/README.md"
    say "Local Admin installed. Start: bash \"$ADMIN_HOME/run-admin.sh\""
    say "Open https://localhost:$WEB_PORT/mail-security after trusting the local certificate as documented."
    say "The one-year CA is constrained to exact loopback names; its signing key was discarded. Renew into a fresh directory and replace the manually trusted CA before expiry."
    say "Pairing bundle: $BUNDLE — contains a management secret; transfer it privately to Lightsail."
    say "Back up $etc/admin-storage.key separately from encrypted Admin database backups; neither can recover the other."
    say "On Lightsail: sudo bash install.sh gateway --bundle /absolute/path/to/bundle --start"
    say "Gateway mail acceptance remains paused until guided setup, route tests and rule activation."
    if [ -n "$PG_DSN" ] && ! $INIT_ACCOUNTING; then say "Accounting connection saved. Initialize its dedicated database with: \"$ADMIN_HOME/bin/workglen\" accounting-init \"$etc/admin.toml\""; fi
    if [ "$TLS" = staging ]; then say "Staging TLS is untrusted. Switch the gateway to production before connecting the local console; do not disable TLS verification."; fi
    trap - ERR
}
gateway() {
    if [ "$OS" != Linux ] && [ -z "$DESTDIR" ]; then
        die "Install the gateway on Linux; run the admin command on your Mac"
    fi
    absolute "$BUNDLE"
    [ -d "$BUNDLE" ] && [ ! -L "$BUNDLE" ] || die "Gateway bundle must be a real directory"
    for file in config.json control.key admin.hash; do private_file "$BUNDLE/$file"; done
    for file in storage.key fullchain.pem privkey.pem; do [ ! -e "$BUNDLE/$file" ] || private_file "$BUNDLE/$file"; done
    [ -x "$BINARY" ] || die "Build a native Linux executable first, or provide --binary"
    local root= etc data bin docs unit scanner_unit file
    if [ -n "$DESTDIR" ]; then
        absolute "$DESTDIR"; [ ! -e "$DESTDIR" ] && [ ! -L "$DESTDIR" ] || die "Staging destination must be new"
        ! $START || die "Cannot start services in --destdir mode"
        root=$DESTDIR
    else
        [ "$(id -u)" = 0 ] || die "Use sudo for the Linux gateway install"
        need systemctl; need runuser; need useradd; need getent
        [ -d /run/systemd/system ] || die "A running systemd host is required"
        if id workglen-security >/dev/null 2>&1; then
            [ "$(id -u workglen-security)" != 0 ] && [ "$(id -gn workglen-security)" = workglen-security ] || die "Existing service account has unexpected uid/group"
        fi
    fi
    etc="$root/etc/workglen-security"; data="$root/var/lib/workglen-security"
    bin="$root/usr/local/bin/workglen"; docs="$root/usr/local/share/doc/workglen"
    unit="$root/etc/systemd/system/workglen-security.service"
    scanner_unit="$root/etc/systemd/system/workglen-security-scanner.service"
    for file in "$etc" "$data" "$unit" "$scanner_unit"; do [ ! -e "$file" ] && [ ! -L "$file" ] || die "Existing installation or partial setup found: $file"; done
    if [ -e "$bin" ]; then [ ! -L "$bin" ] && cmp -s "$BINARY" "$bin" || die "A different Workglen executable is already installed"; fi
    mkdir -p "$etc" "$data" "$(dirname "$bin")" "$(dirname "$unit")"
    chmod 700 "$etc" "$data"
    if [ ! -e "$bin" ]; then cp -- "$BINARY" "$bin"; chmod 755 "$bin"; fi
    for file in config.json control.key admin.hash storage.key fullchain.pem privkey.pem; do
        if [ -f "$BUNDLE/$file" ]; then cp -- "$BUNDLE/$file" "$etc/$file"; chmod 600 "$etc/$file"; fi
    done
    cp "$SOURCE/deploy/workglen-security.service" "$unit"; chmod 644 "$unit"
    cp "$SOURCE/deploy/workglen-security-scanner.service" "$scanner_unit"; chmod 644 "$scanner_unit"
    copy_docs "$docs"
    if [ -n "$DESTDIR" ]; then say "Staged files at $DESTDIR; no accounts, databases or services were created."; return; fi
    if ! id workglen-security >/dev/null 2>&1; then
        useradd --system --user-group --home-dir /var/lib/workglen-security --shell /usr/sbin/nologin workglen-security
    fi
    [ "$(id -u workglen-security)" != 0 ] || die "Service account must not be root"
    chown -R "workglen-security:$(id -gn workglen-security)" "$etc" "$data"
    if [ ! -e "$etc/storage.key" ]; then runuser -u workglen-security -- "$bin" security-generate-key "$etc/storage.key"; fi
    runuser -u workglen-security -- "$bin" security-check "$etc/config.json"
    runuser -u workglen-security -- "$bin" security-init "$etc/config.json" admin "$etc/admin.hash"
    systemctl daemon-reload
    if $START; then
        systemctl enable --now workglen-security.service workglen-security-scanner.service
        systemctl is-active --quiet workglen-security.service || die "Ingress service failed; inspect journalctl -u workglen-security"
        systemctl is-active --quiet workglen-security-scanner.service || die "Scanner service failed; inspect journalctl -u workglen-security-scanner"
        say "Gateway ingress and scanner services started. Certificate issuance may still be pending; check their journals."
    else say "Gateway initialized. Start when DNS/firewall are ready: sudo systemctl enable --now workglen-security workglen-security-scanner"; fi
    say "Back up storage.key separately. Keep port 80 reachable for ACME and configure mail flow in the Mac console."
}
case "$COMMAND" in
    help|--help|-h) help;; check) check;; build) build;; admin) admin;; gateway) gateway;; *) die "Unknown command: $COMMAND";;
esac
