# Automatic TLS certificates

Use the native Let's Encrypt integration for publicly named Workglen services. It runs inside the existing Rust executable: no certificate daemon, renewal cron job or additional Cargo dependency. It supports the Mail/Core, Admin/Accounting HTTPS, Webmail, independent Mail Security and witness process profiles. Each process has its own account/certificate state and renewal worker. HTTPS and mail listeners in that process share the same live certificate store.

## Guided installation

1. Choose the DNS hostnames clients use, including the configured `hostname`, Admin origin and Webmail origin. Create correct public A/AAAA records. If an AAAA record exists, make sure IPv6 reaches the same challenge service. Hostnames become public certificate-transparency information. HTTP-01 does not support wildcard names; this integration accepts DNS names, not IP-address certificates.
2. Make **public TCP port 80** reach the process's `acme.http_listen`. The native HTTP listener serves only ACME challenges; other requests return 404. HTTPS can remain on 443 or its configured alternative port. A reverse proxy may forward `/.well-known/acme-challenge/` on public port 80 to a higher local port; setting a high local port alone is insufficient. Keep this route available for renewals. If several modules share a host, use separate local challenge ports and route by hostname. A single shared hostname needs one owner for its challenge path; do not run competing managers for it.
3. Create a dedicated state directory owned by the service user, mode 0700. It holds the ACME account key and certificate keys (0600) and must persist across restarts. Never place it in a web-served directory or replicate it as a live shared directory. Workglen rejects linked files, unsafe key/directory permissions and concurrent use of one state directory. Back it up securely; it is separate from the Mail Security database encryption key.
4. Remove `tls_cert` and `tls_key` and add `acme` settings below. Start with `staging = true`. Read [Let's Encrypt's subscriber terms](https://letsencrypt.org/repository/) and explicitly set `agree_to_terms = true` when accepted. A false or omitted agreement prevents startup. Contact email is required for account contact; do not rely on CA email for expiry monitoring.
5. Initialize Workglen normally, then start its service. Initialization and `security-check` perform no ACME network requests. Issuance begins during `serve`, `security-serve` or `witness`. Before the first certificate arrives, TLS handshakes fail; Workglen does not invent a trusted certificate or disable client verification. Watch service logs for `TLS ACME`. Staging certificates are intentionally untrusted by ordinary clients.
6. Once staging validation works, set `staging = false` and restart once to select production. Staging and production accounts/certificates are stored separately. Allow production issuance to finish, then verify HTTPS and mail TLS from a normal client before directing user traffic to the service. Normal renewals thereafter do not require a restart.
7. Monitor the **TLS certificates** card in Admin and Mail Security Overview, authenticated status APIs and service logs. Status includes expiry, staging, readiness and the most recent renewal error. Mail Security also records lifecycle events in its append-only audit trail. Seven-day expiry warnings require operator attention; no outbound alert email is implemented for certificate expiry.

## Configuration

Complete starting points: [Mail/Core](config/letsencrypt.toml) and [Mail Security](security/letsencrypt.example.json). They deliberately require hostname/contact changes and explicit agreement to subscriber terms before startup.

For Mail/Core, add this TOML table at the end of the node configuration after removing the top-level manual certificate settings. Include every enabled HTTPS origin hostname; replace all examples.

```toml
[acme]
domains = ["mail.example.com", "admin.example.com", "webmail.example.com"]
email = "operations@example.com"
state_dir = "/var/lib/workglen/acme"
http_listen = "0.0.0.0:80"
staging = true
agree_to_terms = false # Set true after reviewing subscriber terms.
```

For Mail Security, replace the two manual TLS properties with this JSON property, adapting the names to `hostname` and `origin`:

```json
"acme": {
  "domains": ["security.example.com"],
  "email": "operations@example.com",
  "state_dir": "/var/lib/workglen-security/acme",
  "http_listen": "0.0.0.0:80",
  "staging": true,
  "agree_to_terms": false
}
```

The witness accepts the same TOML table; use its DNS name and `/var/lib/workglen-witness/acme`. Each node in a dual-node deployment needs independently reachable challenge routing for its names. Issuance/renewal is independent of the primary lease so standby nodes can maintain certificates.

The supplied systemd services permit binding port 80 using `CAP_NET_BIND_SERVICE`. Keep state inside their writable `/var/lib/workglen*` directory, or explicitly adjust sandbox write permissions. For a proxy-forwarded high port, the capability may be removed if all other listeners also use high ports. Check firewall rules and CAA records when issuance fails.

## Renewal and trust

The native manager follows ACME Renewal Information (ARI) from the CA. When ARI is unavailable it schedules renewal at two-thirds of the actual certificate lifetime (half for certificates shorter than ten days). It does not assume 90-day certificates. Failures retry with exponential backoff and CA Retry-After delta-seconds handling. A valid existing certificate remains available during retries; expired certificates are removed from the managed store. New TLS connections use renewed keys immediately, while established sessions continue. A readable, valid cached certificate is loaded before listeners start, including when the CA is temporarily unavailable.

Certificate renewal replaces the leaf key. Use CA trust and hostname verification for remote modules, replication and witness clients; **do not pin a rotating leaf certificate**. The local Admin CLI uses system roots when ACME is configured. For peer/witness `ca_file` settings, supply the OS CA bundle (for example `/etc/ssl/certs/ca-certificates.crt` on Debian-family hosts) or an appropriate maintained trust bundle. Mail Security routes and central registrations use system trust when their optional CA file is omitted. Never disable verification to accommodate staging in production.

Manual `tls_cert`/`tls_key` configurations remain supported, including private/internal CA installations. They require administrator-managed renewal and a service restart after replacing the files. DNS-01 automation, wildcard issuance, central certificate distribution and certificate-expiry notification emails are not implemented. Let’s Encrypt validation requires outbound HTTPS and public inbound HTTP; mail/attachment inspection remains local and never sends content to the CA.

Sources: [integration guide](https://letsencrypt.org/docs/integration-guide/), [HTTP-01](https://letsencrypt.org/docs/challenge-types/), [certificate lifetime changes](https://letsencrypt.org/2025/12/02/from-90-to-45/).
