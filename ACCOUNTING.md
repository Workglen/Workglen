> Local Mac PostgreSQL is supported with explicit `transport = "local"` (literal loopback TCP or absolute Unix socket). The default `verified-tls` still applies to remote databases. See [MAC-ADMIN-LIGHTSAIL.md](MAC-ADMIN-LIGHTSAIL.md) for setup and the local transport boundary.

# Workglen Accounting

Current documentation targets the TBD 0.1.1 development/test release. Posting corrections, named roles and retained audit history are included. There are no current installations or live books.

The optional Accounting module stores its entire ledger, books, contacts, documents,
import previews, bank transactions, feed state and audit history in your PostgreSQL
database. It is separate from Mail's redb database. There is no SQLite dependency.

## Scope

Implemented: multiple books; one base currency and fixed decimal scale per book;
chart of accounts; contacts; balanced journals, audited edits/voids/deletes, and reversals; basic
invoices/bills and payments; trial balance; period locks; a checked Xero cutover;
multiple bank/card accounts; SimpleFIN v2 connections and scheduled polling;
CSV/OFX/QFX/QBO statement imports; transaction matching, posting and exclusion.
Web administration and the CLI call the same backend operations.

This is not a full Xero replacement yet. Tax calculation/filing, payroll,
multicurrency/FX, credit-note workflows, document emailing/printing, recurring
invoices, bank payment initiation and formal statement-close certification are not
implemented. Named `accounting_admin`, `accountant` and `accounting_viewer` roles
are available with book scopes; an external accountant or contractor should receive
a named, scoped identity. Do not share the workspace owner login. Have an accountant review the cutover
and reporting behavior before using it for live books.

Plaid is **not required**. This release implements SimpleFIN and statement files.
A native Plaid Link/OAuth adapter remains unimplemented, and no Plaid credentials
or fees are needed. Provider ingestion is separate from reconciliation so a later
optional adapter can reuse the same review flow. No bank credentials are collected
by Workglen. Live Chase account coverage has not been validated.

## BYO PostgreSQL

Use a dedicated database on a provider-supported PostgreSQL release (target 16+).
Both Workglen nodes must use the SAME database endpoint, database, workspace ID,
and feed encryption key. Cloud database replication, availability, backups and
point-in-time recovery are the provider's responsibility. Workglen does not mirror
PostgreSQL into redb or another cloud database. A Mail backup does not include any
Accounting data. Test restoring the PostgreSQL database and the separate encryption
key together. Keep keys/DSNs out of source control and source archives.

Configure the node:

```toml
[accounting]
dsn_file = "/etc/workglen/postgres.dsn"
ca_file = "/etc/workglen/provider-ca.pem" # optional when the provider uses a trusted system CA
pool_size = 2 # hard maximum 8 per Workglen process
feed_key_file = "/etc/workglen/feed.key" # needed for SimpleFIN, not file imports
```

The 0600 DSN file contains a standard PostgreSQL connection string, for example:

```text
host=db.example.net port=5432 dbname=workglen user=workglen password=REPLACE
```

The default `transport = "verified-tls"` enforces certificate-chain and hostname
verification over TCP; it does not honor insecure TLS overrides from the DSN.
Explicit `transport = "local"` permits only literal loopback TCP or an absolute
Unix socket path on the same machine, without TLS; use that for local Mac PostgreSQL. Network firewall access should be limited to your nodes. Connection,
statement and lock timeouts and bounded pools prevent unlimited application work.

Initialize with a database owner role, then use a restricted runtime role:

```sh
workglen accounting-init /etc/workglen/node.toml
```

Initialization creates the complete current schema from `schema/accounting.sql` in
one transaction, locks setup and binds the database to the configured workspace ID.
It creates no older intermediate schema and performs no version upgrades. Repeating
initialization validates the existing workspace/schema and returns its database ID
without changing records or schema. Run it before starting either node. For separate
setup/runtime roles, grant the runtime role USAGE on schema
`workglen_accounting`, SELECT/INSERT/UPDATE/DELETE on its tables and USAGE/SELECT on
its sequences. Do not grant schema ownership, CREATE, TRUNCATE, superuser or trigger
disabling rights to the runtime role. Correction guards require a versioned change record in the same transaction.
Audit and change-history records reject updates/deletes; database owners can still
bypass those safeguards. Ordinary users must use the application API, never SQL.
Switch the DSN to the runtime role after initialization.

Start the server, open Modules and enable Accounting. Disabling it stops new API/CLI
work and feed polling and preserves all data. Enabled state lives in PostgreSQL.
Mail remains independently available if Accounting's database is offline. The
original under-512-MiB goal applied to a measured Mail workload, not to the cloud
PostgreSQL service or an arbitrary mix of accounting workloads.

## External accounting import/export

External-system data exchange remains in scope. Existing Xero cutover import,
`tools/prepare-xero.py`, and CSV/OFX/QFX/QBO bank-statement imports remain implemented.
QBO statement support does not constitute a full QuickBooks books importer.

Planned work:

- Full QuickBooks cutover import for accounts, contacts, opening balances and open documents.
- Xero and QuickBooks export adapters with explicit supported formats and field mappings.
- Reusable CSV/JSON import/export for other accounting systems, with preview, balance reconciliation, source identifiers, duplicate detection, scoped access and audited commits/exports.

These adapters are backlog requirements, not implemented integrations. They are
separate from Workglen version upgrades. There are no current installations or
live books; all present accounting work is development and testing.

## Xero cutover

This version uses a prepared bundle, not an automatic Xero OAuth connection. Retain
Xero's historical ledger, statutory reports, attachments and source exports separately.

1. Choose a cutover date. Complete reconciliation and freeze changes in Xero.
2. Export/retrieve all accounts and contacts and the unpaid invoices/bills, plus
   credit notes, prepayments and overpayments. Native Xero API JSON arrays retain
   the IDs needed by this importer. No API calls are made by the import tool.
3. Export the reconciled trial balance as of that date. Prepare a CSV with exactly
   `AccountCode,Debit,Credit`, using net closing balances, decimal strings without
   currency symbols or separators, and the destination currency precision.
4. Use `tools/prepare-xero.py` and the documented JSON exports, or prepare a bundle
   following `examples/accounting/xero-cutover.json`. Account codes must be present;
   assign missing codes in Xero first. Set the correct AR and AP control codes.
5. Create an empty destination book of the same base currency. Open Xero migration,
   choose the bundle and preview. Review the totals and warnings.
6. Commit the exact preview. Its hash is checked; a replay cannot post twice. The
   opening journal contains the trial balance once. Unpaid documents are subledger
   detail, not additional AR/AP entries. The cutover date becomes locked.
7. Compare the resulting trial balance and all outstanding documents against Xero.
   Set each bank's import-from date to the next day; do not post old bank activity
   a second time.

Import refuses AR/AP mismatches, unbalanced balances, foreign-currency outstanding
documents, unallocated credits/prepayments/overpayments, invalid precision, duplicate
IDs or document numbers and a destination that is not empty. Fully paid invoices
are not migrated. The operator must supply complete exports as of the cutover;
Workglen cannot independently prove the export is complete. Opening history, tax
metadata, historical payments, payroll, attachments and feed credentials are excluded.
Limits: 4 MiB API command; web bundle 3 MiB; 5,000 accounts; 10,000 contacts/documents.
Larger migrations require a separately designed streaming/batched migration path.

## SimpleFIN and multiple Chase accounts

Generate a random key once and securely copy the SAME key to both nodes:

```sh
umask 077
workglen setup-random base64 32 > /etc/workglen/feed.key
```

1. Subscribe to SimpleFIN Bridge yourself and link the required bank logins there.
   Confirm your particular Chase checking/savings/credit-card accounts appear.
2. In Workglen create bank/card ledger accounts (asset for deposits, liability for
   cards), then add Bank accounts with separate names, IDs and import-from dates.
3. Generate a dedicated Workglen setup token in SimpleFIN. Paste it into Connect
   SimpleFIN. Access tokens are encrypted with AES-256-GCM, with workspace/book/
   connection identity authenticated, before entering PostgreSQL. Tokens are never
   returned in list responses or audit records.
4. Sync to discover accounts, then map each to its bank ledger account. Account
   identity includes the provider login ID, not just its account ID, so two logins
   at the same bank remain separate. Mapping refuses currency mismatches.
5. Scheduled polling runs every six hours, only on the primary. Both nodes share
   the stored schedule and an attempt lease in PostgreSQL. Manual refresh/retry
   cannot run more often than hourly. Requests are bounded to 89-day windows with
   five-day overlap, and old cursors catch up window by window. Provider history
   can be shorter than the requested range: missing history requires file imports
   and comparison with bank statements. This is not a real-time feed.
6. Review the imported transactions. Pending and zero-value entries never post.
   Errors/partial results are displayed and do not advance the cursor. Corrected
   transactions already matched to a journal are flagged as conflicts; the ledger
   is never silently rewritten.

Setup-token claiming is a one-time external operation and cannot be atomic with the
local database. If a claim fails or the process dies before storage, revoke that
setup/access token in SimpleFIN and create a new one with a new connection ID.
Disconnect removes the locally encrypted token and stops polling; revoke the app in
SimpleFIN as well. Retained transactions and accounting records are not deleted.

Only official `bridge.simplefin.org` and `beta-bridge.simplefin.org` HTTPS endpoints
are supported; redirects are refused. API messages are rendered as text. Request
bodies, credentials and returned Access URLs must not be logged by reverse proxies.
The embedded web server does not log them. The current Pratique security limitations
in SECURITY-REVIEW.md still apply to these outbound connections.

## Statement files and reconciliation

CSV accepts Date/Posting Date/Post Date, Description, Amount and optionally
ID/Transaction ID/FITID. Dates are YYYY-MM-DD or MM/DD/YYYY. Common Chase activity
CSV headers are accepted; unrelated columns are ignored. Amounts must be signed:
positive deposits/card payments; negative withdrawals/card charges. Preview the signs
before committing. Decimal strings are converted exactly to minor units, never floats.
OFX/QFX/QBO support one bank/card statement, stable FITID values and UTF-8 content.
The exact ACCTID must match the configured statement_account_id and CURDEF must
match the book. DTD/entity expansion, correction records and multiple-account files
are refused. Convert legacy encodings to UTF-8 before import.

Imports first create a stored, hashed preview. Commit places entries in review only.
Exact same-source transaction IDs and repeated committed imports do not add entries.
ID-less CSV uses date/amount/description plus occurrence count; it cannot distinguish
all overlapping subsets of identical purchases. Cross-provider/file duplicates are
flagged by same account/date/amount, never automatically merged. Always reconcile
against actual statements, particularly after changing provider or importing history.

Actions:

- **Match** attaches a transaction to an existing journal only when that bank's net
  journal amount equals the statement amount. A bank/journal pair can match once.
- **Post** makes a balanced bank/counter-account journal. Control-account posting
  is refused; use a document payment for AR/AP.
- **Payment** settles an invoice/bill, enforcing direction and outstanding balance.
- **Exclude** requires an explanation. It does not post a ledger entry.
- **Unmatch/reopen** requires an explanation and keeps existing ledger entries.
  Correct or reverse them before matching again; don't create duplicate entries.

For an inter-account transfer, post one journal between the two bank accounts and
match each bank's statement row to it. For a mixed/split transaction, create the
balanced multi-line journal with the CLI, then match it. Full automatic matching,
categorization rules, split-payment allocation and a statement-close workflow are
future work.

## CLI

`workglen accounting CONFIG COMMAND.json` (or `-` for stdin) calls the same backend
as HTTPS administration. The body is `{ "action": "...", "book_id": "main", "data": {...} }`.
Use `book_id: null` for books/create-book/status. Monetary amounts are strings.

Read actions: books, chart, contacts, trial-balance (as_of), ledger, documents,
imports, audit, bank-accounts, bank-transactions (bank_id), feed-connections,
feed-accounts. Paginated lists accept `offset` and return at most 200 rows.

Write actions: create-book, add-account, add-contact, post-journal, reverse-journal,
create-document, record-payment, lock-date, xero-preview, xero-commit, bank-create,
bank-preview, bank-commit, bank-match, bank-post, bank-payment, bank-exclude,
bank-unmatch, feed-connect, feed-map, feed-sync, feed-disconnect. See the test and
example files for exact payloads. Bank statements and Xero bundles can be submitted
through the web forms without composing JSON commands.

Examples:

```json
{"action":"bank-post","book_id":"main","data":{"id":"REVIEW_TRANSACTION_ID","account":"5000"}}
```

```json
{"action":"post-journal","book_id":"main","data":{"request_id":"transfer-2026-10-23","date":"2026-10-23","description":"Checking to savings","lines":[{"account":"1010","debit":"500.00","credit":"0"},{"account":"1000","debit":"0","credit":"500.00"}]}}
```

## Provider references

Checked during implementation (October 23, 2026, America/Chicago):
- https://www.simplefin.org/protocol.html — v2 account/login identities and error model.
- https://beta-bridge.simplefin.org/info/developers — setup exchange, rate limits,
  date windows and overlap guidance.
- https://bridge.simplefin.org/ — user-owned subscription.
- https://developer.xero.com/documentation/api/accounting/accounts
- https://developer.xero.com/documentation/api/accounting/invoices

Live provider authorization, real Chase feeds, production cloud PostgreSQL failover
and an independent financial/security review remain deployment validation tasks.


## Optional PlanetScale Postgres deployment

PlanetScale's **Postgres** product is a candidate for this module's BYO PostgreSQL
connection. The Vitess/MySQL product is a different engine and is not compatible
with this adapter. No PlanetScale database was provisioned or used in validation.

Place the database near the Workglen hosts, use the provider's direct primary
PostgreSQL endpoint on port 5432 with TLS certificate/hostname verification, and
start with `pool_size = 2` per Workglen node. Pool totals include both nodes and any
operator tools. Use a role with the privileges required by `accounting-init` for
schema setup; follow the provider's role guidance and grant application access only
to the Workglen schema and operations it needs. Protect the DSN file at mode 0600.
This adapter does not target the Vitess connection URL or an HTTP database API.

The provider also offers a pooled endpoint, but direct PostgreSQL is the initial
integration choice to avoid adding pooling semantics before this adapter has been
validated against the service. Verify schema initialization, ledger/import flows,
connection recovery and a restore from backup on an empty staging database before
using live books. Choose availability/replica capacity deliberately; a low-cost
single-node database does not provide the same availability as a replicated plan.
Consult current pricing for compute, storage, branches and transfer charges.

PlanetScale would hold Accounting data. Mail, Webmail, the outbound spool and mail
replication continue to use redb; messages and attachments do not move into
PostgreSQL as a consequence of choosing this provider.

Provider references: [Postgres compatibility](https://planetscale.com/docs/postgres/postgres-compatibility),
[connections](https://planetscale.com/docs/postgres/connecting),
[pricing](https://planetscale.com/pricing), and
[backups](https://planetscale.com/docs/postgres/backups).

## Corrections and period reopening

Fresh installations include all correction tables, views and audit guards.

Books & ledger now has Postings & history, a manual journal form, and Period lock
settings. An accountant assigned to a book can edit, void, or delete ordinary
open-period postings. Voided postings remain visible; deleted postings are omitted
from normal lists and reports but available with Include deleted postings and audit
history. A voided posting may subsequently be deleted from the normal listing.
Neither action physically erases audit evidence or reuses a document number.

Edits retain the journal ID, increment its revision, and replace its current values
atomically with complete before/after audit snapshots. Trial balance and ledger
reports use current posted values; historical reports reflect authorized backdated
corrections. Audit history records what the values were before correction. Request
IDs prevent duplicate corrections, and expected_revision prevents stale edits.
Balanced lines, exact currency precision, valid account references, and source
transaction consistency remain mandatory.

Both the old and new posting dates must be outside the locked period. `lock-date`
closes a period or advances a lock. `reopen-period` may move or remove it and
requires `expected_lock_date` plus a nonempty reason. Reopening does not change any
postings automatically. Relock after completing corrections. Only owner and
accounting_admin roles have accounting.periods; an ordinary accountant's correction
rights do not imply reopening rights. Assigned-book scopes apply to both.

Correct invoices/bills and payments through their originating operation, not a raw
manual-journal edit. A document cannot be reduced below its allocated payments or
removed while active payments remain. Edit/reallocate, void, or delete those payments
first. Removing a payment restores the outstanding amount. Imported opening journals
represent a migration aggregate and require a cutover adjustment, not an ordinary
invoice edit. Related reversing journals are not silently rewritten; correcting one
requires acknowledging the linked reversal.

A matched posting requires either prior unmatching or explicit `unmatch:true`, which
returns every linked bank transaction to review in the same transaction. Locked
bank transaction dates remain protected. Removed postings cannot be rematched.
Bank-post/payment can create a fresh posting after the previous generated posting
was removed, without reusing its idempotency identity.

New read commands: `journals` (offset, include_deleted), `journal` (journal_id).
New writes: `edit-journal`, `void-journal`, `delete-journal`, `edit-document`,
`void-document`, `delete-document`, `edit-payment`, `void-payment`, `delete-payment`,
and `reopen-period`. Every correction supplies journal_id, request_id, and
expected_revision. Void/delete require a reason; edits accept one. Manual edits
also supply date, description, and lines in the existing decimal-string format.
Document edits supply date, due, number, contact_id, and account/amount lines.
Payment edits supply date, document_id, bank_account, and amount.

Example reopening:

```json
{"action":"reopen-period","book_id":"main","data":{"date":"2026-09-30","expected_lock_date":"2026-10-31","reason":"Correct October accruals"}}
```

Named administration identities are provisioned with `workglen access-set CONFIG`
and a JSON object on stdin: username, password (new/reset only), roles, books,
enabled, and expected_revision (null for new identities). Use explicit book IDs for
outside accountants. `accountant` has ordinary correction rights; `accounting_viewer`
is read-only; `accounting_admin` also controls periods and setup. `owner` controls
all modules and identity management. Mailbox authentication remains separate.
Changes to an identity invalidate its existing administration sessions. Provisioning
via the local token/CLI is a privileged owner recovery path. A dedicated contractor
submission/approval workflow is still future work; do not grant posting rights when
only preparation access is intended.

Design comparison: [QuickBooks journal deletion](https://quickbooks.intuit.com/learn-support/en-us/help-article/journal-entries/reverse-delete-journal-entry-quickbooks-online/L2prlrnkh_US_en_US),
[Xero journal editing](https://central.xero.com/0/article/View-edit-or-copy-a-manual-journal-ROW),
[Xero voiding](https://central.xero.com/0/article/Void-archive-or-delete-multiple-journals-ROW),
and [QuickBooks closed-book changes](https://quickbooks.intuit.com/learn-support/en-us/help-article/customer-company-settings/edit-closed-books/L76xHuaZ5_US_en_US).
Workglen adopts ordinary corrections with retained evidence; it does not claim complete
feature parity, tax filing, or payroll correction support.

## Native database TLS

Accounting now uses the first-party native Rust `lazaret-pg` crate, translated
from Lazaret's Python PostgreSQL driver and kept separate for an eventual Lazaret
handoff. Pratique handles TLS and SCRAM cryptography. Certificate verification,
required channel binding, explicit local endpoint restrictions, parameterized
queries, SQLSTATE recovery and transactional posting/audit behavior are retained.
The existing PostgreSQL server, schema and data remain in place; no importer or
reinitialization is needed. See [LAZARET-POSTGRESQL.md](LAZARET-POSTGRESQL.md) and
[vendor/lazaret-pg/README.md](vendor/lazaret-pg/README.md) for limits and tests.
