-- Current fresh-install schema. accounting-init creates this atomically once.
CREATE SCHEMA workglen_accounting;
CREATE TABLE workglen_accounting.installation (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 version integer NOT NULL CHECK(version=2), workspace_id text NOT NULL,
 database_id text NOT NULL, enabled boolean NOT NULL DEFAULT false,
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0)
);
CREATE TABLE workglen_accounting.books (
 id text PRIMARY KEY, name text NOT NULL, currency text NOT NULL CHECK(currency ~ '^[A-Z]{3}$'),
 scale smallint NOT NULL CHECK(scale BETWEEN 0 AND 3), lock_date date,
 cutover_date date, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE workglen_accounting.accounts (
 book_id text NOT NULL REFERENCES workglen_accounting.books, code text NOT NULL,
 name text NOT NULL, kind text NOT NULL CHECK(kind IN ('asset','liability','equity','income','expense')),
 bank boolean NOT NULL DEFAULT false, control text CHECK(control IN ('receivable','payable')),
 source_id text, PRIMARY KEY(book_id,code), UNIQUE(book_id,source_id), UNIQUE(book_id,control),
 CHECK(NOT bank OR kind IN ('asset','liability')),
 CHECK(control IS NULL OR (control='receivable' AND kind='asset') OR (control='payable' AND kind='liability'))
);
CREATE TABLE workglen_accounting.contacts (
 book_id text NOT NULL REFERENCES workglen_accounting.books, id text NOT NULL,
 name text NOT NULL, email text NOT NULL DEFAULT '', source_id text,
 PRIMARY KEY(book_id,id), UNIQUE(book_id,source_id)
);
CREATE TABLE workglen_accounting.journals (
 book_id text NOT NULL REFERENCES workglen_accounting.books, id text NOT NULL,
 entry_date date NOT NULL, description text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('manual','opening','invoice','bill','payment','reversal')),
 request_id text NOT NULL, payload_hash text NOT NULL, actor text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), created_xid bigint NOT NULL DEFAULT txid_current(),
 status text NOT NULL DEFAULT 'posted' CHECK(status IN ('posted','void','deleted')),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0), updated_xid bigint,
 PRIMARY KEY(book_id,id), UNIQUE(book_id,request_id)
);
CREATE TABLE workglen_accounting.lines (
 book_id text NOT NULL, journal_id text NOT NULL, line_no integer NOT NULL CHECK(line_no>0),
 account_code text NOT NULL, debit bigint NOT NULL CHECK(debit BETWEEN 0 AND 9000000000000000),
 credit bigint NOT NULL CHECK(credit BETWEEN 0 AND 9000000000000000),
 CHECK((debit>0 AND credit=0) OR (credit>0 AND debit=0)),
 PRIMARY KEY(book_id,journal_id,line_no),
 FOREIGN KEY(book_id,journal_id) REFERENCES workglen_accounting.journals(book_id,id),
 FOREIGN KEY(book_id,account_code) REFERENCES workglen_accounting.accounts(book_id,code)
);
CREATE INDEX lines_account ON workglen_accounting.lines(book_id,account_code);
CREATE INDEX journal_dates ON workglen_accounting.journals(book_id,entry_date,id);
CREATE TABLE workglen_accounting.documents (
 book_id text NOT NULL REFERENCES workglen_accounting.books, id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('receivable','payable')), contact_id text NOT NULL,
 number text NOT NULL, issued date NOT NULL, due date NOT NULL, control_account text NOT NULL,
 original_amount bigint NOT NULL CHECK(original_amount>0),
 opening_due bigint NOT NULL CHECK(opening_due>0 AND opening_due<=original_amount),
 journal_id text NOT NULL, source_id text, PRIMARY KEY(book_id,id), UNIQUE(book_id,source_id),
 UNIQUE(book_id,kind,contact_id,number),
 FOREIGN KEY(book_id,contact_id) REFERENCES workglen_accounting.contacts(book_id,id),
 FOREIGN KEY(book_id,control_account) REFERENCES workglen_accounting.accounts(book_id,code),
 FOREIGN KEY(book_id,journal_id) REFERENCES workglen_accounting.journals(book_id,id)
);
CREATE TABLE workglen_accounting.payments (
 book_id text NOT NULL, id text NOT NULL, document_id text NOT NULL, journal_id text NOT NULL,
 amount bigint NOT NULL CHECK(amount>0), payment_date date NOT NULL,
 PRIMARY KEY(book_id,id), UNIQUE(book_id,journal_id),
 FOREIGN KEY(book_id,document_id) REFERENCES workglen_accounting.documents(book_id,id),
 FOREIGN KEY(book_id,journal_id) REFERENCES workglen_accounting.journals(book_id,id)
);
CREATE TABLE workglen_accounting.reversals (
 book_id text NOT NULL, original_id text NOT NULL, reversal_id text NOT NULL,
 PRIMARY KEY(book_id,original_id), UNIQUE(book_id,reversal_id),
 FOREIGN KEY(book_id,original_id) REFERENCES workglen_accounting.journals(book_id,id),
 FOREIGN KEY(book_id,reversal_id) REFERENCES workglen_accounting.journals(book_id,id)
);
CREATE TABLE workglen_accounting.imports (
 book_id text NOT NULL REFERENCES workglen_accounting.books, id text NOT NULL,
 payload_hash text NOT NULL, source_org text NOT NULL, as_of date NOT NULL,
 plan jsonb NOT NULL, summary jsonb NOT NULL, state text NOT NULL CHECK(state IN ('preview','committed')),
 journal_id text, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(book_id,id), UNIQUE(book_id,payload_hash)
);
CREATE TABLE workglen_accounting.audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 book_id text, actor text NOT NULL, action text NOT NULL, record_id text NOT NULL,
 details jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE workglen_accounting.feed_connections (
 book_id text NOT NULL REFERENCES workglen_accounting.books, id text NOT NULL,
 name text NOT NULL, provider text NOT NULL CHECK(provider='simplefin'),
 secret bytea, active boolean NOT NULL DEFAULT true, cursor_at bigint,
 next_sync timestamptz NOT NULL DEFAULT now(), last_sync timestamptz,
 lease text, errors jsonb NOT NULL DEFAULT '[]',
 PRIMARY KEY(book_id,id)
);
CREATE TABLE workglen_accounting.bank_accounts (
 book_id text NOT NULL, id text NOT NULL, name text NOT NULL,
 ledger_account text NOT NULL, import_from date NOT NULL, statement_account_id text,
 PRIMARY KEY(book_id,id), UNIQUE(book_id,ledger_account),
 FOREIGN KEY(book_id,ledger_account) REFERENCES workglen_accounting.accounts(book_id,code)
);
CREATE TABLE workglen_accounting.feed_accounts (
 book_id text NOT NULL, connection_id text NOT NULL, source_key text NOT NULL,
 name text NOT NULL, currency text NOT NULL, balance text NOT NULL, balance_at bigint NOT NULL,
 bank_id text, PRIMARY KEY(book_id,connection_id,source_key), UNIQUE(book_id,bank_id),
 FOREIGN KEY(book_id,connection_id) REFERENCES workglen_accounting.feed_connections(book_id,id),
 FOREIGN KEY(book_id,bank_id) REFERENCES workglen_accounting.bank_accounts(book_id,id)
);
CREATE TABLE workglen_accounting.bank_transactions (
 book_id text NOT NULL, bank_id text NOT NULL, id text NOT NULL,
 source text NOT NULL, source_id text NOT NULL, posted date NOT NULL,
 amount bigint NOT NULL CHECK(amount<>0 AND abs(amount)<=9000000000000000), description text NOT NULL,
 state text NOT NULL DEFAULT 'unmatched' CHECK(state IN ('unmatched','matched','excluded','conflict')),
 journal_id text, note text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(),
 posting_generation bigint NOT NULL DEFAULT 0 CHECK(posting_generation>=0),
 PRIMARY KEY(book_id,id), UNIQUE(book_id,bank_id,source,source_id),
 FOREIGN KEY(book_id,bank_id) REFERENCES workglen_accounting.bank_accounts(book_id,id),
 FOREIGN KEY(book_id,journal_id) REFERENCES workglen_accounting.journals(book_id,id)
);
CREATE UNIQUE INDEX bank_match_once ON workglen_accounting.bank_transactions(book_id,bank_id,journal_id) WHERE journal_id IS NOT NULL;
CREATE INDEX bank_review ON workglen_accounting.bank_transactions(book_id,bank_id,posted,id);
CREATE TABLE workglen_accounting.bank_imports (
 book_id text NOT NULL, id text NOT NULL, bank_id text NOT NULL,
 payload_hash text NOT NULL, plan jsonb NOT NULL, state text NOT NULL DEFAULT 'preview',
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(book_id,id), UNIQUE(book_id,bank_id,payload_hash),
 FOREIGN KEY(book_id,bank_id) REFERENCES workglen_accounting.bank_accounts(book_id,id)
);
CREATE FUNCTION workglen_accounting.immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Posted accounting records are immutable'; END $$;
CREATE FUNCTION workglen_accounting.balance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE n bigint; d numeric; c numeric;
BEGIN
 SELECT count(*),coalesce(sum(debit),0),coalesce(sum(credit),0) INTO n,d,c FROM workglen_accounting.lines WHERE book_id=NEW.book_id AND journal_id=NEW.id;
 IF n<2 OR d<>c OR d<=0 OR d>9000000000000000 THEN RAISE EXCEPTION 'Journal must contain balanced positive debit and credit lines'; END IF;
 RETURN NULL;
END $$;
CREATE TABLE workglen_accounting.journal_changes (
 book_id text NOT NULL, journal_id text NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 request_id text NOT NULL, payload_hash text NOT NULL, action text NOT NULL,
 actor text NOT NULL, reason text NOT NULL, before_value jsonb NOT NULL, request_value jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), created_xid bigint NOT NULL DEFAULT txid_current(),
 PRIMARY KEY(book_id,journal_id,revision), UNIQUE(book_id,request_id),
 FOREIGN KEY(book_id,journal_id) REFERENCES workglen_accounting.journals(book_id,id)
);
CREATE VIEW workglen_accounting.active_journals AS SELECT * FROM workglen_accounting.journals WHERE status='posted';
CREATE VIEW workglen_accounting.active_documents AS SELECT d.* FROM workglen_accounting.documents d JOIN workglen_accounting.active_journals j ON(j.book_id=d.book_id AND j.id=d.journal_id);
CREATE VIEW workglen_accounting.active_payments AS SELECT p.* FROM workglen_accounting.payments p JOIN workglen_accounting.active_journals j ON(j.book_id=p.book_id AND j.id=p.journal_id);
CREATE FUNCTION workglen_accounting.correction_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE b text; j text;
BEGIN
 IF TG_OP='DELETE' AND TG_TABLE_NAME<>'lines' THEN RAISE EXCEPTION 'Use an audited void or delete; history is retained'; END IF;
 b=OLD.book_id;
 IF TG_TABLE_NAME='journals' THEN
  j=OLD.id;
  IF NEW.book_id<>b OR NEW.id<>j OR NEW.revision<>OLD.revision+1 OR NEW.updated_xid<>txid_current()
   OR (to_jsonb(NEW)-ARRAY['entry_date','description','status','revision','updated_xid'])<>(to_jsonb(OLD)-ARRAY['entry_date','description','status','revision','updated_xid']) THEN
   RAISE EXCEPTION 'Invalid journal revision';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM workglen_accounting.journal_changes c WHERE c.book_id=b AND c.journal_id=j AND c.revision=NEW.revision AND c.created_xid=txid_current()) THEN RAISE EXCEPTION 'Audited correction required'; END IF;
 ELSE
  j=OLD.journal_id;
  IF TG_OP='UPDATE' AND (NEW.book_id<>b OR NEW.journal_id<>j) THEN RAISE EXCEPTION 'Cannot move accounting records'; END IF;
  IF NOT EXISTS(SELECT 1 FROM workglen_accounting.journals q JOIN workglen_accounting.journal_changes c ON(c.book_id=q.book_id AND c.journal_id=q.id AND c.revision=q.revision) WHERE q.book_id=b AND q.id=j AND q.updated_xid=txid_current() AND c.created_xid=txid_current()) THEN RAISE EXCEPTION 'Audited correction required'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION workglen_accounting.line_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM workglen_accounting.journals j WHERE j.book_id=NEW.book_id AND j.id=NEW.journal_id AND (j.created_xid=txid_current() OR (j.updated_xid=txid_current() AND EXISTS(SELECT 1 FROM workglen_accounting.journal_changes c WHERE c.book_id=j.book_id AND c.journal_id=j.id AND c.revision=j.revision AND c.created_xid=txid_current())))) THEN RAISE EXCEPTION 'Lines require a posting or audited correction transaction'; END IF;
 RETURN NEW;
END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['reversals','audit','journal_changes'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON workglen_accounting.%I FOR EACH ROW EXECUTE FUNCTION workglen_accounting.immutable()', 'wg_immutable_'||t,t);
 END LOOP;
 FOREACH t IN ARRAY ARRAY['journals','lines','documents','payments'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON workglen_accounting.%I FOR EACH ROW EXECUTE FUNCTION workglen_accounting.correction_guard()', 'wg_correct_'||t,t);
 END LOOP;
END $$;
CREATE TRIGGER wg_line_insert BEFORE INSERT ON workglen_accounting.lines FOR EACH ROW EXECUTE FUNCTION workglen_accounting.line_insert_guard();
CREATE CONSTRAINT TRIGGER wg_journal_balance AFTER INSERT OR UPDATE ON workglen_accounting.journals DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workglen_accounting.balance_guard();
CREATE UNIQUE INDEX unique_sales_invoice_number ON workglen_accounting.documents(book_id,number) WHERE kind='receivable';
