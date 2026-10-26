# Documentation included in this source ZIP

All the documents listed below, the implementation, examples, SQL schema, tests and validation records are packaged under `workglen/`. They do not require a repository checkout or earlier conversation. The CLI installer also copies these guides and validation records into the installed local documentation directory.

| Topic | Included document | How to use it |
|---|---|---|
| Offensive review | [OFFENSIVE-REVIEW-REMEDIATION.md](OFFENSIVE-REVIEW-REMEDIATION.md) | Implemented fixes, portable checks, evidence and remaining work |
| Native errors and dates | [NATIVE-ERRORS-AND-DATES.md](NATIVE-ERRORS-AND-DATES.md) | Anyhow/Chrono replacement scope, compatibility and validation |
| Remaining crate catalog | [DEPENDENCY-CATALOG.md](DEPENDENCY-CATALOG.md) | Every remaining external crate, its purpose and resolved parent dependencies |
| Mail-auth native utilities | [MAIL-AUTH-UTILITIES.md](MAIL-AUTH-UTILITIES.md) | Ordered hostname, Base64 and bounded diff checkpoints and validation |
| Gateway relay protection | [GATEWAY-RELAY-SECURITY.md](GATEWAY-RELAY-SECURITY.md) | Verified source controls, safe external diagnostic and pending Lightsail checks |
| Mail-auth utility cleanup | [MAIL-AUTH-REPORT-TRIM.md](MAIL-AUTH-REPORT-TRIM.md) | Removed unused reporting/compression dependencies and retained protocol utilities |
| Replication codec | [REPLICATION-CODEC.md](REPLICATION-CODEC.md) | Native bincode replacement, unchanged wire format and compatibility checks |
| First steps | [START-HERE.md](START-HERE.md) | Entry point after unzipping |
| CLI installer | [INSTALL.md](INSTALL.md) | Prerequisites, options, behavior, failure handling |
| Your deployment | [MAC-ADMIN-LIGHTSAIL.md](MAC-ADMIN-LIGHTSAIL.md) | Mac Admin, existing local PostgreSQL, paired Lightsail gateway |
| Implemented design | [ARCHITECTURE.md](ARCHITECTURE.md) | Current processes, storage, trust and lifecycle |
| Suite overview and Mail | [README.md](README.md) | Mail operations, build, limits and historical release sections |
| Mail Security | [security/README.md](security/README.md) | Native gateway operations and capability limits |
| Delivery destination wizard | [DELIVERY-DESTINATIONS.md](DELIVERY-DESTINATIONS.md) | In-app SMTP destination creation, Microsoft MX discovery, tests and empty-list recovery |
| Microsoft 365 recipients | [MICROSOFT-365-RECIPIENTS.md](MICROSOFT-365-RECIPIENTS.md) | Directory discovery, review, manual exceptions, existing-install update and navigation |
| Encryption/BYOK | [security/ENCRYPTED-STORAGE.md](security/ENCRYPTED-STORAGE.md) | Whole-store encryption, keys, backup/restore and boundaries |
| Pratique integration | [PRATIQUE-INTEGRATION.md](PRATIQUE-INTEGRATION.md) | Cryptography ownership, native PostgreSQL driver, native provisioning and review limits |
| Native PostgreSQL client | [LAZARET-POSTGRESQL.md](LAZARET-POSTGRESQL.md) and [crate README](vendor/lazaret-pg/README.md) | Lazaret Rust port, handoff boundary and supported features |
| Dependency policy | [security/DEPENDENCY-POLICY.md](security/DEPENDENCY-POLICY.md) | Native runtime/no additional scanner-service rule |
| Crate replacement checkpoints | [CRATE-REPLACEMENTS.md](CRATE-REPLACEMENTS.md) | Cumulative source ZIP stages and compatibility evidence |
| Native DNS, URLs and authentication | [NATIVE-DNS-URL-AUTH.md](NATIVE-DNS-URL-AUTH.md) | Active replacements, candidate limits and remaining mail-auth work |
| Dependency reduction | [DEPENDENCIES.md](DEPENDENCIES.md) | Current counts, removed crates, retained capabilities and next priorities |
| TLS/Let's Encrypt | [TLS-CERTIFICATES.md](TLS-CERTIFICATES.md) | Gateway issuance, renewal, challenge routing and certificate status |
| Accounting | [ACCOUNTING.md](ACCOUNTING.md) | PostgreSQL, journals, edits/locks/audit, Xero, bank feeds, imports/exports |
| Outbound Mail | [DIRECT-MAIL.md](DIRECT-MAIL.md) | Direct MX delivery, DKIM and DNS prerequisites |
| Webmail | [WEBMAIL.md](WEBMAIL.md) | Slim mailbox-client module |
| Module design | [MODULES.md](MODULES.md) | Delivered module controls plus explicitly planned foundation features |
| Scaling design | [SCALING.md](SCALING.md) | Capacity model and future scaling targets |
| Remote-module design history | [MODULE-HOSTING-AND-MAIL-SECURITY.md](MODULE-HOSTING-AND-MAIL-SECURITY.md) | Original requirements; historical/target sections are labeled |
| Remaining Security work | [MAIL-SECURITY-BACKLOG.md](MAIL-SECURITY-BACKLOG.md) | Native archive formats and storage/key lifecycle backlog |
| Security review boundary | [SECURITY-REVIEW.md](SECURITY-REVIEW.md) | Delivered review notes and outstanding independent review limits |
| Validation | [VALIDATION.md](VALIDATION.md) and [validation/](validation/) | Current results and explicitly labeled historical evidence |
| Contributor instructions | [AGENTS.md](AGENTS.md) | Rules for implementation and verification |
| Licensing | [LICENSE](LICENSE), [THIRD-PARTY.md](THIRD-PARTY.md), [vendor/pratique/LICENSE](vendor/pratique/LICENSE) | First-party package license and real third-party notices |

Supporting files: `config/` contains node/witness/TLS examples; `security/*.json` contains gateway/connector examples; `deploy/` contains service/proxy examples; `schema/accounting.sql` is the complete current Accounting schema; `examples/accounting/` contains external Xero cutover data; `tools/`, `tests/` and `security/tests/` hold development fixtures. `SOURCE-SHA256` and `SOURCE-SHA256.json` inventory the packaged source files. Checksums detect changed bytes relative to the manifest, not publisher authenticity.

No deployment passwords, management keys, storage keys, private certificates, database files, local installation bundles or browser screenshots belong in this archive. The public Mozilla CA bundle and its notices under the vendored source are intentional source dependencies.

- [MAIL-AUTH-PRATIQUE.md](MAIL-AUTH-PRATIQUE.md): native mail-auth cryptography,
  package counts, compatibility checks and attributed upstream patch.

- [Native mail authentication](NATIVE-MAILAUTH.md): DEPS-13 replacement and validation.
- [Portable validation](PORTABLE-CHECKS.md): run the included offline checks.

- [Native IDNA](NATIVE-IDNA.md): Unicode processing and DEPS-14 evidence.

- [Microsoft 365 gateway enforcement](MICROSOFT-365-GATEWAY.md): setup walkthrough, Partner connector restriction, Enhanced Filtering and bypass verification.
