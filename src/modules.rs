//! Cluster-wide module preferences live in the replicated KV store.
//! Mail is enabled by default when the workspace has no saved preference.
use crate::error::{Result, ensure};
use crate::{
    app::App,
    store::{self, Op, Store},
};

pub const STATE_KEY: &str = "core/modules/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub revision: u64,
    pub mail_enabled: bool,
    pub webmail_enabled: bool,
    pub changed_at: Option<i64>,
}
pratique::data_encode!(State {
    revision,
    mail_enabled,
    webmail_enabled,
    changed_at
});
pratique::data_decode!(State, deny_unknown=true, { revision, mail_enabled, webmail_enabled, changed_at });

impl Default for State {
    fn default() -> Self {
        Self {
            revision: 0,
            mail_enabled: true,
            webmail_enabled: false,
            changed_at: None,
        }
    }
}
pub fn state(store: &Store) -> Result<State> {
    Ok(store.get(STATE_KEY)?.unwrap_or_default())
}

pub struct Module {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub implemented: bool,
    pub enabled: bool,
    pub requires: &'static [&'static str],
}
pratique::data_encode!(Module {
    id,
    name,
    description,
    implemented,
    enabled,
    requires
});

pub fn catalog(app: &App) -> Result<pratique::json_value::Value> {
    let state = state(&*app.read_store()?)?;
    let mut modules = vec![Module {
        id: "mail",
        name: "Workglen Mail",
        description: "Mailboxes, delivery, and email protection. Your existing mail data stays in place when disabled.",
        implemented: true,
        enabled: state.mail_enabled,
        requires: &["core"],
    }];
    modules.push(Module {
        id: "webmail", name: "Workglen Webmail",
        description: "A compact browser inbox, reading, composing, replies, attachments and sent mail. Requires Mail and a configured HTTPS listener.",
        implemented: true, enabled: state.webmail_enabled,
        requires: &["core", "mail"],
    });
    for (id, name, description) in [
        (
            "contacts",
            "Contacts",
            "Shared customers, suppliers, organizations, and contact details.",
        ),
        (
            "calendar",
            "Calendar",
            "Personal and team calendars, availability, and bookings.",
        ),
        (
            "sites",
            "Sites",
            "Website content, pages, forms, and publishing.",
        ),
        (
            "sales",
            "Sales",
            "Leads, opportunities, quotes, and the sales pipeline.",
        ),
        (
            "projects",
            "Projects",
            "Projects, tasks, milestones, and time tracking.",
        ),
        (
            "people",
            "People",
            "Employee records, leave, and onboarding with restricted access.",
        ),
        (
            "accounts",
            "Accounts",
            "Accounting, invoices, bills, and financial reporting.",
        ),
        (
            "files",
            "Files",
            "Documents, versions, and shared knowledge.",
        ),
        (
            "support",
            "Support",
            "Cases, service requests, and customer conversations.",
        ),
        (
            "messages",
            "Messages",
            "Light conversations and record threads with permission-aware recent-record suggestions.",
        ),
        (
            "workflows",
            "Workflows",
            "Reusable processes, approvals, reminders, and automation across enabled modules.",
        ),
    ] {
        modules.push(Module {
            id,
            name,
            description,
            implemented: false,
            enabled: false,
            requires: &["core"],
        });
    }
    let accounting = crate::accounting::status(app);
    if let Some(m) = modules.iter_mut().find(|m| m.id == "accounts") {
        m.implemented = true;
        m.name = "Workglen Accounting";
        m.enabled = accounting["enabled"].as_bool().unwrap_or(false);
        m.description =
            "Ledger, invoices, bills, Xero cutover, and bank feeds on your PostgreSQL database.";
    }
    Ok(
        pratique::json_value::json!({ "admin_only": app.config.admin_only, "state": state, "modules": modules, "primary": app.primary(), "accounting":accounting, "webmail_configured":app.config.webmail.is_some() }),
    )
}

pub fn change(
    app: &App,
    id: &str,
    enabled: bool,
    expected: Option<u64>,
) -> Result<pratique::json_value::Value> {
    if id == "accounts" {
        app.require_primary()?;
        return app
            .accounting
            .as_ref()
            .ok_or_else(|| crate::error!("Configure PostgreSQL and run accounting-init first"))?
            .set_enabled(enabled, expected, "admin");
    }
    Ok(pratique::json_value::json!(set(
        app, id, enabled, expected
    )?))
}
pub fn set(app: &App, id: &str, enabled: bool, expected: Option<u64>) -> Result<State> {
    ensure!(
        !app.config.admin_only,
        "Mail and Webmail cannot be changed in the local Admin profile"
    );
    ensure!(id != "core", "Core is foundational and cannot be disabled");
    ensure!(
        matches!(id, "mail" | "webmail"),
        "Unknown or planned modules cannot be enabled"
    );
    if id == "webmail" && enabled {
        ensure!(
            app.config.webmail.is_some(),
            "Configure the webmail HTTPS listener first"
        );
    }
    // Never suspend delivery between the external SMTP result and its durable
    // queue update. A caller can retry after the bounded attempt finishes.
    let _delivery = if id == "mail" {
        Some(
            crate::resilience::try_lock(&app.relay_activity).map_err(|_| {
                crate::error!("An outbound delivery is in progress. Retry after it finishes.")
            })?,
        )
    } else {
        None
    };
    app.commit(|t| {
        let current: State = store::json(t, STATE_KEY)?.unwrap_or_default();
        ensure!(
            expected.is_none_or(|v| v == current.revision),
            "Module settings changed. Refresh and try again."
        );
        if id == "webmail" && enabled {
            ensure!(current.mail_enabled, "Enable Mail first");
        }
        if (if id == "mail" {
            current.mail_enabled
        } else {
            current.webmail_enabled
        }) == enabled
        {
            return Ok((vec![], current));
        }
        let next = State {
            revision: current
                .revision
                .checked_add(1)
                .ok_or_else(|| crate::error!("module revision overflow"))?,
            mail_enabled: if id == "mail" {
                enabled
            } else {
                current.mail_enabled
            },
            webmail_enabled: if id == "webmail" {
                enabled
            } else {
                current.webmail_enabled
            },
            changed_at: Some(crate::datetime::Utc::now().timestamp()),
        };
        Ok((vec![Op::json(STATE_KEY.into(), &next)?], next))
    })
}
// BEGIN GENERATED RECORD CONTRACTS
#[cfg(test)]
mod record_contracts {
    use super::*;
    #[test]
    fn record_contract_state() {
        crate::data_contracts::check::<State>(
            "src_modules_State",
            &[
                r###"{"revision":18446744073709551615,"mail_enabled":true,"webmail_enabled":true,"changed_at":null}"###,
                r###"{}"###,
                r###"[18446744073709551615,true,true,null]"###,
                r###"{"revision":18446744073709551615,"mail_enabled":true,"webmail_enabled":true,"changed_at":null,"unexpected_field":1}"###,
                r###"{"revision":18446744073709551615,"mail_enabled":true,"webmail_enabled":true}"###,
                r###"{"mail_enabled":true,"webmail_enabled":true,"changed_at":null}"###,
                r###"{"revision":"wrong","mail_enabled":true,"webmail_enabled":true,"changed_at":null}"###,
                r###"{"revision":18446744073709551615,"mail_enabled":true,"webmail_enabled":true,"changed_at":null,"revision":18446744073709551615}"###,
                r###"{"revision":18446744073709551615,"webmail_enabled":true,"changed_at":null}"###,
                r###"{"revision":18446744073709551615,"mail_enabled":"wrong","webmail_enabled":true,"changed_at":null}"###,
                r###"{"revision":18446744073709551615,"mail_enabled":true,"webmail_enabled":true,"changed_at":null,"mail_enabled":true}"###,
                r###"{"revision":18446744073709551615,"mail_enabled":true,"changed_at":null}"###,
                r###"{"revision":18446744073709551615,"mail_enabled":true,"webmail_enabled":"wrong","changed_at":null}"###,
                r###"{"revision":18446744073709551615,"mail_enabled":true,"webmail_enabled":true,"changed_at":null,"webmail_enabled":true}"###,
                r###"{"revision":18446744073709551615,"mail_enabled":true,"webmail_enabled":true,"changed_at":"wrong"}"###,
                r###"{"revision":18446744073709551615,"mail_enabled":true,"webmail_enabled":true,"changed_at":null,"changed_at":null}"###,
                r###"{"revision":18446744073709551615,"mail_enabled":true,"webmail_enabled":true,"changed_at":-9223372036854775808}"###,
            ],
        );
    }
}
