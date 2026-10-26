'use strict';
function can(permission){return !Array.isArray(session?.permissions)||session.permissions.includes(permission);}
function pageAllowed(name){const p={overview:'system.read',capacity:'system.read',foundation:'system.read',accounts:'mail.read',queue:'queue.read',security:'mail.read',backups:'backups.read',finance:'accounting.read',banking:'accounting.read',xero:'accounting.admin'};return !p[name]||can(p[name]);}
function applyPermissions(){
 if($("remote-security-link"))$("remote-security-link").hidden=!can("security.read");
 document.querySelectorAll('[data-page]').forEach(b=>{b.hidden = !pageAllowed(b.dataset.page) || (b.hasAttribute('data-mail')&&!overview?.modules.mail_enabled) || (b.hasAttribute('data-accounting')&&!accountingState?.enabled);});
 const forms={'book-form':'accounting.admin','ledger-account-form':'accounting.admin','contact-form':'accounting.write','document-form':'accounting.write','bank-form':'accounting.admin','feed-form':'accounting.admin','statement-form':'accounting.write','xero-form':'accounting.admin','period-form':'accounting.periods','journal-create-form':'accounting.write'};
 for(const [id,permission] of Object.entries(forms)){const f=$(id);if(f)f.closest('details')?.toggleAttribute('hidden',!can(permission));}
}
