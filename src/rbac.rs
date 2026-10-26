//! Administration identities and explicit, deny-by-default role permissions.
//! Mailbox login is independent; no administration role grants message-body access.
use crate::error::{Result, ensure};
use crate::{
    app::App,
    store::{self, Op},
};
use pratique::json_value::{Value, json};

pub const ROLES: &[&str] = &[
    "owner",
    "security_admin",
    "security_author",
    "security_operator",
    "security_viewer",
    "security_auditor",
    "operator",
    "mail_admin",
    "accounting_admin",
    "accountant",
    "accounting_viewer",
    "observer",
];
pub const PERMISSIONS: &[&str] = &[
    "security.read",
    "security.rules.write",
    "security.rules.test",
    "security.rules.activate",
    "security.content",
    "security.release",
    "security.discard",
    "security.remediation.preview",
    "security.remediation.execute",
    "security.configure",
    "security.retention",
    "security.jobs",
    "security.audit",
    "security.learn",
    "system.read",
    "mail.read",
    "mail.manage",
    "queue.read",
    "queue.manage",
    "modules.mail",
    "modules.accounts",
    "backups.read",
    "backups.create",
    "access.manage",
    "audit.read",
    "accounting.read",
    "accounting.write",
    "accounting.admin",
    "accounting.periods",
];
const IDENTITIES: &str = "core/identity/";
const AUDIT: &str = "core/access-audit/";
#[derive(Debug)]
pub struct Denied;
impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Permission denied")
    }
}
impl std::error::Error for Denied {}
#[derive(Clone, Debug)]
pub struct Identity {
    pub username: String,
    pub password_hash: String,
    pub roles: Vec<String>,
    pub books: Vec<String>,
    pub security_domains: Vec<String>,
    pub security_mailboxes: Vec<String>,
    pub security_instances: Vec<String>,
    pub enabled: bool,
    pub revision: u64,
}
pratique::data_encode!(Identity {
    username,
    password_hash,
    roles,
    books,
    security_domains,
    security_mailboxes,
    security_instances,
    enabled,
    revision
});
pratique::data_decode!(Identity, deny_unknown=true, { username, password_hash, roles, books, security_domains, security_mailboxes, security_instances, enabled, revision });

#[derive(Clone)]
pub struct Principal {
    pub username: String,
    pub revision: u64,
    pub bootstrap: bool,
}
impl Principal {
    pub fn bootstrap(username: &str) -> Self {
        Self {
            username: username.into(),
            revision: 0,
            bootstrap: true,
        }
    }
}
#[derive(Clone)]
pub struct Access {
    pub username: String,
    pub roles: Vec<String>,
    pub books: Vec<String>,
    pub security_domains: Vec<String>,
    pub security_mailboxes: Vec<String>,
    pub security_instances: Vec<String>,
}
impl Access {
    pub fn owner(username: &str) -> Self {
        Self {
            username: username.into(),
            roles: vec!["owner".into()],
            books: vec!["*".into()],
            security_domains: vec!["*".into()],
            security_mailboxes: vec!["*".into()],
            security_instances: vec!["*".into()],
        }
    }
    pub fn allows(&self, p: &str) -> bool {
        if !PERMISSIONS.contains(&p) {
            return false;
        }
        self.roles.iter().any(|r| match r.as_str() {
            "owner" => true,
            "security_admin" => p.starts_with("security."),
            "security_author" => matches!(
                p,
                "security.read" | "security.rules.write" | "security.rules.test"
            ),
            "security_operator" => matches!(
                p,
                "security.read"
                    | "security.content"
                    | "security.release"
                    | "security.discard"
                    | "security.jobs"
                    | "security.remediation.preview"
            ),
            "security_viewer" => p == "security.read",
            "security_auditor" => matches!(p, "security.read" | "security.audit"),
            "operator" => matches!(
                p,
                "system.read" | "backups.read" | "backups.create" | "audit.read"
            ),
            "mail_admin" => matches!(
                p,
                "system.read"
                    | "mail.read"
                    | "mail.manage"
                    | "queue.read"
                    | "queue.manage"
                    | "modules.mail"
            ),
            "accounting_admin" => matches!(
                p,
                "accounting.read" | "accounting.write" | "accounting.admin" | "accounting.periods"
            ),
            "accountant" => matches!(p, "accounting.read" | "accounting.write"),
            "accounting_viewer" => p == "accounting.read",
            "observer" => p == "system.read",
            _ => false,
        })
    }
    pub fn require(&self, p: &str) -> Result<()> {
        if self.allows(p) {
            Ok(())
        } else {
            Err(Denied.into())
        }
    }
    pub fn book(&self, id: &str) -> bool {
        self.roles.iter().any(|r| r == "owner") || self.books.iter().any(|b| b == "*" || b == id)
    }
    pub fn permissions(&self) -> Vec<&'static str> {
        PERMISSIONS
            .iter()
            .copied()
            .filter(|p| self.allows(p))
            .collect()
    }
    pub fn accounting(&self, c: &crate::accounting::model::Command) -> Result<()> {
        let p = accounting_permission(&c.action).ok_or(Denied)?;
        self.require(p)?;
        if matches!(c.action.as_str(), "books" | "status") {
            return Ok(());
        }
        if c.action == "create-book" {
            if !self.book("*") {
                return Err(Denied.into());
            }
            return Ok(());
        }
        let b = c.book_id.as_deref().ok_or(Denied)?;
        if self.book(b) {
            Ok(())
        } else {
            Err(Denied.into())
        }
    }
}
pub fn accounting_permission(action: &str) -> Option<&'static str> {
    Some(match action {
        "status" | "books" | "chart" | "contacts" | "trial-balance" | "ledger" | "journals"
        | "journal" | "documents" | "imports" | "audit" | "bank-accounts" | "bank-transactions"
        | "feed-connections" | "feed-accounts" => "accounting.read",
        "edit-journal" | "void-journal" | "delete-journal" | "edit-document" | "void-document"
        | "delete-document" | "edit-payment" | "void-payment" | "delete-payment"
        | "reverse-journal" | "add-contact" | "post-journal" | "create-document"
        | "record-payment" | "bank-preview" | "bank-commit" | "bank-match" | "bank-post"
        | "bank-payment" | "bank-exclude" | "bank-unmatch" => "accounting.write",
        "lock-date" | "reopen-period" => "accounting.periods",
        "create-book" | "add-account" | "xero-preview" | "xero-commit" | "bank-create"
        | "feed-connect" | "feed-sync" | "feed-map" | "feed-disconnect" => "accounting.admin",
        _ => return None,
    })
}
pub fn username(s: &str) -> Result<String> {
    ensure!(
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "Username must contain 1..64 letters, digits, - _ . or @"
    );
    Ok(s.to_ascii_lowercase())
}
pub fn authenticate(app: &App, name: &str, password: &str) -> Result<Option<Principal>> {
    let name = username(name).unwrap_or_default();
    let u = app
        .read_store()?
        .get::<Identity>(&format!("{IDENTITIES}{name}"))?;
    let hash = u
        .as_ref()
        .map(|u| u.password_hash.as_str())
        .unwrap_or(&app.dummy_hash);
    let good = crate::auth::verify(password, hash);
    Ok(u.filter(|u| good && u.enabled).map(|u| Principal {
        username: u.username,
        revision: u.revision,
        bootstrap: false,
    }))
}
pub fn resolve(app: &App, p: &Principal) -> Result<Option<Access>> {
    if p.bootstrap {
        return Ok(Some(Access::owner(&p.username)));
    }
    // Named users only run on the primary: a lagging replica must not serve stale grants.
    if !app.primary() {
        return Ok(None);
    }
    Ok(app
        .read_store()?
        .get::<Identity>(&format!("{IDENTITIES}{}", p.username))?
        .filter(|u| u.enabled && u.revision == p.revision)
        .map(|u| Access {
            username: u.username,
            roles: u.roles,
            books: u.books,
            security_domains: u.security_domains,
            security_mailboxes: u.security_mailboxes,
            security_instances: u.security_instances,
        }))
}
fn summary(u: Identity) -> Value {
    json!({"username":u.username,"roles":u.roles,"books":u.books,"security_domains":u.security_domains,"security_mailboxes":u.security_mailboxes,"security_instances":u.security_instances,"enabled":u.enabled,"revision":u.revision})
}
pub fn list(app: &App) -> Result<Value> {
    let rows = app.read_store()?.list::<Identity>(IDENTITIES)?;
    Ok(
        json!({"roles":ROLES,"identities":rows.into_iter().map(|(_,u)|summary(u)).collect::<Vec<_>>(),"bootstrap":app.config.web.as_ref().map(|w|&w.username)}),
    )
}
pub struct Change {
    pub username: String,
    pub roles: Vec<String>,
    pub books: Vec<String>,
    pub security_domains: Vec<String>,
    pub security_mailboxes: Vec<String>,
    pub security_instances: Vec<String>,
    pub enabled: bool,
    pub expected_revision: Option<u64>,
    pub password: Option<String>,
}
pratique::data_encode!(Change {
    username,
    roles,
    books,
    security_domains,
    security_mailboxes,
    security_instances,
    enabled,
    expected_revision,
    password
});
pratique::data_decode!(Change, deny_unknown=true, { username, roles, books, security_domains = Default::default(), security_mailboxes = Default::default(), security_instances = Default::default(), enabled, expected_revision, password });

/// Caller holds App.authorization write lock. No secret values enter audit records.
pub fn change(app: &App, actor: &str, c: Change) -> Result<Value> {
    let name = username(&c.username)?;
    ensure!(
        app.config
            .web
            .as_ref()
            .is_none_or(|w| !w.username.eq_ignore_ascii_case(&name)),
        "The configured bootstrap owner cannot be changed here"
    );
    ensure!(
        c.roles.len() <= ROLES.len() && c.roles.iter().all(|r| ROLES.contains(&r.as_str())),
        "Unknown role"
    );
    ensure!(
        !c.enabled || !c.roles.is_empty(),
        "Enabled identities need a role"
    );
    ensure!(c.books.len() <= 200, "At most 200 book scopes");
    for b in &c.books {
        if b != "*" {
            crate::accounting::model::key(b)?;
        }
    }
    ensure!(
        c.security_domains.len() <= 100
            && c.security_mailboxes.len() <= 10000
            && c.security_instances.len() <= 100,
        "Security scope limit"
    );
    for d in &c.security_domains {
        ensure!(
            d == "*" || crate::config::domain(d),
            "Invalid security domain"
        );
    }
    for m in &c.security_mailboxes {
        if m != "*" {
            crate::config::address(m)?;
        }
    }
    for id in &c.security_instances {
        if id != "*" {
            crate::accounting::model::key(id)?;
        }
    }
    let hash = c.password.as_deref().map(crate::auth::hash).transpose()?;
    app.commit(|t|{
        let key=format!("{IDENTITIES}{name}");let old=store::json::<Identity>(t,&key)?;
        ensure!(old.as_ref().map(|u|u.revision)==c.expected_revision,"Identity changed. Refresh before saving.");
        if old.is_none(){ensure!(store::scan::<Identity>(t,IDENTITIES)?.len()<256,"Identity limit reached");}
        let password_hash=hash.clone().or_else(||old.as_ref().map(|u|u.password_hash.clone())).ok_or_else(||crate::error!("A password is required for a new identity"))?;
        let mut roles=c.roles.clone();roles.sort();roles.dedup();let mut books=c.books.clone();books.sort();books.dedup();
        let revision=old.as_ref().map(|u|u.revision).unwrap_or(0).checked_add(1).ok_or_else(||crate::error!("Identity revision overflow"))?;
        let u=Identity{username:name.clone(),password_hash,roles,books,security_domains:c.security_domains.clone(),security_mailboxes:c.security_mailboxes.clone(),security_instances:c.security_instances.clone(),enabled:c.enabled,revision};
        let mut ops=vec![Op::json(key,&u)?];ops.extend(audit_ops(t,actor,"identity-change",&name,json!({"roles":u.roles,"books":u.books,"security_domains":u.security_domains,"security_mailboxes":u.security_mailboxes,"security_instances":u.security_instances,"enabled":u.enabled,"revision":revision,"password_changed":hash.is_some()}))?);
        Ok((ops,summary(u)))
    })
}
pub fn audit_ops(
    t: &redb::Table<&str, &[u8]>,
    actor: &str,
    action: &str,
    target: &str,
    details: Value,
) -> Result<Vec<Op>> {
    let seq: u64 = store::json(t, "core/access-audit-sequence")?.unwrap_or(0);
    let seq = seq
        .checked_add(1)
        .ok_or_else(|| crate::error!("Audit sequence exhausted"))?;
    let mut ops = vec![
        Op::json("core/access-audit-sequence".into(), &seq)?,
        Op::json(
            format!("{AUDIT}{seq:020}"),
            &json!({"id":seq,"at":crate::datetime::Utc::now().timestamp(),"actor":actor,"action":action,"target":target,"details":details}),
        )?,
    ];
    if seq > 10000 {
        ops.push(Op::del(format!("{AUDIT}{:020}", seq - 10000)));
    }
    Ok(ops)
}
pub fn audit(app: &App) -> Result<Value> {
    let mut rows = app.read_store()?.list::<Value>(AUDIT)?;
    rows.reverse();
    rows.truncate(200);
    Ok(json!(rows.into_iter().map(|(_, v)| v).collect::<Vec<_>>()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn access(role: &str) -> Access {
        Access {
            username: "test".into(),
            roles: vec![role.into()],
            books: vec!["one".into()],
            security_domains: vec![],
            security_mailboxes: vec![],
            security_instances: vec![],
        }
    }
    fn command(a: &str, b: Option<&str>) -> crate::accounting::model::Command {
        crate::accounting::model::Command {
            action: a.into(),
            book_id: b.map(str::to_owned),
            data: json!({}),
        }
    }
    #[test]
    fn finance_roles_are_scoped_and_deny_unknown_actions() {
        let a = access("accountant");
        assert!(a.accounting(&command("post-journal", Some("one"))).is_ok());
        assert!(a.accounting(&command("post-journal", Some("two"))).is_err());
        assert!(a.accounting(&command("xero-commit", Some("one"))).is_err());
        assert!(
            a.accounting(&command("new-future-action", Some("one")))
                .is_err()
        );
        assert!(
            access("accounting_viewer")
                .accounting(&command("post-journal", Some("one")))
                .is_err()
        );
        assert!(
            access("accounting_admin")
                .accounting(&command("create-book", None))
                .is_err()
        );
    }
    #[test]
    fn posting_corrections_and_period_control_are_separate() {
        for action in [
            "edit-journal",
            "void-journal",
            "delete-journal",
            "reverse-journal",
            "edit-document",
            "void-document",
            "delete-document",
            "edit-payment",
            "void-payment",
            "delete-payment",
        ] {
            assert!(
                access("accountant")
                    .accounting(&command(action, Some("one")))
                    .is_ok()
            );
            assert!(
                access("accountant")
                    .accounting(&command(action, Some("other")))
                    .is_err()
            );
            assert!(
                access("accounting_viewer")
                    .accounting(&command(action, Some("one")))
                    .is_err()
            );
        }
        for action in ["lock-date", "reopen-period"] {
            assert!(
                access("accountant")
                    .accounting(&command(action, Some("one")))
                    .is_err()
            );
            assert!(
                access("accounting_admin")
                    .accounting(&command(action, Some("one")))
                    .is_ok()
            );
            assert!(
                access("accounting_admin")
                    .accounting(&command(action, Some("other")))
                    .is_err()
            );
        }
    }
    #[test]
    fn role_domains_do_not_imply_each_other() {
        assert!(!access("mail_admin").allows("accounting.read"));
        assert!(!access("operator").allows("access.manage"));
        assert!(!access("accounting_admin").allows("modules.accounts"));
        assert!(!access("observer").allows("backups.create"));
        assert!(access("owner").allows("access.manage"));
        assert!(!access("owner").allows("unknown.permission"));
    }
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    #[test]
    fn record_contract_identity() {
        crate::data_contracts::check::<Identity>(
            "src_rbac_Identity",
            &[
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00","sample-\u00e9\ud83d\ude00",["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],true,18446744073709551615]"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615,"unexpected_field":1}"###,
                r###"{"password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":false,"password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615,"username":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":false,"roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615,"password_hash":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":"wrong","books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615,"roles":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":"wrong","security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615,"books":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":"wrong","security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615,"security_domains":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":"wrong","security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615,"security_mailboxes":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":"wrong","enabled":true,"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615,"security_instances":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":"wrong","revision":18446744073709551615}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615,"enabled":true}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":"wrong"}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","password_hash":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"revision":18446744073709551615,"revision":18446744073709551615}"###,
            ],
        );
    }
    #[test]
    fn record_contract_change() {
        crate::data_contracts::check::<Change>(
            "src_rbac_Change",
            &[
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{}"###,
                r###"["sample-\u00e9\ud83d\ude00",["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],["sample-\u00e9\ud83d\ude00"],true,null,null]"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null,"unexpected_field":1}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"enabled":true}"###,
                r###"{"roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":false,"roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null,"username":"sample-\u00e9\ud83d\ude00"}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":"wrong","books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null,"roles":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":"wrong","security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null,"books":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":"wrong","security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null,"security_domains":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":"wrong","security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null,"security_mailboxes":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":"wrong","enabled":true,"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null,"security_instances":["sample-\u00e9\ud83d\ude00"]}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":"wrong","expected_revision":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null,"enabled":true}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":"wrong","password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null,"expected_revision":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":18446744073709551615,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":"wrong"}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":null,"password":null}"###,
                r###"{"username":"sample-\u00e9\ud83d\ude00","roles":["sample-\u00e9\ud83d\ude00"],"books":["sample-\u00e9\ud83d\ude00"],"security_domains":["sample-\u00e9\ud83d\ude00"],"security_mailboxes":["sample-\u00e9\ud83d\ude00"],"security_instances":["sample-\u00e9\ud83d\ude00"],"enabled":true,"expected_revision":null,"password":"sample-\u00e9\ud83d\ude00"}"###,
            ],
        );
    }
}
