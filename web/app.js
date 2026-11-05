'use strict';
const $ = id => document.getElementById(id);
const THEME_KEY='workglen-theme',THEMES=new Set(['forest','ocean','clay']),THEME_NAMES={forest:'Forest',ocean:'Ocean',clay:'Clay'};
function storedTheme(){try{const value=localStorage.getItem(THEME_KEY);return THEMES.has(value)?value:'forest';}catch(_){return 'forest';}}
function applyTheme(value,persist=true){const theme=THEMES.has(value)?value:'forest';document.documentElement.dataset.theme=theme;for(const choice of document.querySelectorAll('[data-theme-choice]'))choice.setAttribute('aria-pressed',String(choice.dataset.themeChoice===theme));const status=$('theme-status');if(status)status.textContent=THEME_NAMES[theme]+' theme selected';if(persist)try{localStorage.setItem(THEME_KEY,theme);}catch(_){}return theme;}
applyTheme(storedTheme(),false);
let session = null, page = 'overview', overview = null, accounts = [], queue = [], editing = false;
let moduleState = null, accountingState = null;
let refreshing = false, revision = 0, toastTimer;
const pages = {
  finance: ['ACCOUNTING', 'Accounting overview', 'See what needs attention and move today’s work forward.'],
  banking: ['ACCOUNTING', 'Banking', 'Review transactions, balances, and bank connections.'],
  xero: ['ACCOUNTING', 'Migration', 'Bring checked opening balances into your new ledger.'],
  overview: ['WORKSPACE HEALTH', 'Overview', 'Your workspace and infrastructure, at a glance.'],
  modules: ['WORKSPACE SETUP', 'Modules', 'Choose the capabilities your business needs.'],
  settings: ['WORKSPACE SETTINGS', 'Settings', 'Personalize how Workglen looks on this browser.'],
  capacity: ['OPERATIONS', 'Capacity', 'Inspect current limits and plan for growth.'],
  foundation: ['SHARED SERVICES', 'Core services', 'The foundation for every Workglen module.'],
  accounts: ['MAILBOX MANAGEMENT', 'Mailboxes', 'Manage accounts within Workglen Mail.'],
  queue: ['OUTBOUND DELIVERY', 'Delivery queue', 'See what’s waiting and what needs attention.'],
  security: ['MAIL PROTECTION', 'Mail protection', 'Inspect the authentication and filtering rules.'],
  backups: ['DATA RECOVERY', 'Backups', 'Preserve a consistent copy of your workspace data.']
};
const text = (id, value) => { $(id).textContent = value; };
const el = (tag, content, cls) => { const n = document.createElement(tag); if (content !== undefined) n.textContent = content; if (cls) n.className = cls; return n; };
const number = n => Number(n || 0).toLocaleString();
function bytes(n) { if (n == null) return 'Unavailable'; if (n < 1024) return n + ' B'; const u = ['KiB','MiB','GiB','TiB']; let i = -1; do { n /= 1024; i++; } while (n >= 1024 && i < 3); return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i]; }
function date(n) { return n ? new Date(n * 1000).toLocaleString(undefined, {dateStyle:'medium',timeStyle:'short'}) : '—'; }
function ago(n) { if (!n) return 'No contact recorded'; const s = Math.max(0, Math.floor(Date.now()/1000-n)); return s < 5 ? 'Just now' : s < 60 ? s+' seconds ago' : Math.floor(s/60)+' minutes ago'; }
function toast(message) { text('toast', message); $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 5000); }
function loggedOut() { if (typeof clearAccounting === 'function') clearAccounting(); session = null; revision++; $('account-dialog').close(); $('module-dialog').close(); $('account-form').reset(); moduleState = null; overview = null; $('app-view').hidden = true; $('login-view').hidden = false; $('password').value = ''; document.title = 'Workglen · Sign in'; }
let apiQueue=Promise.resolve();
function api(path,data){const request=apiQueue.then(()=>requestApi(path,data));apiQueue=request.catch(()=>{});return request;}
async function requestApi(path, data) {
  const headers = {Accept:'application/json'};
  if (data !== undefined) { headers['Content-Type'] = 'application/json'; if (session) headers['X-CSRF-Token'] = session.csrf; }
  let r;
  try { r = await fetch('/api/' + path, {method:data === undefined ? 'GET':'POST', headers, credentials:'same-origin', cache:'no-store', body:data === undefined ? undefined : JSON.stringify(data)}); }
  catch (_) { throw new Error('Unable to reach this node. Check the connection and try again.'); }
  let v; try { v = await r.json(); } catch (_) { throw new Error('The server returned an unexpected response.'); }
  if (!r.ok) { if (r.status === 401 && path !== 'login') { loggedOut(); text('login-error', 'Your session ended. Sign in again.'); } throw new Error(v.error || 'Request failed'); }
  return v;
}
function badge(node, label, kind='') { node.textContent = label; node.className = 'badge ' + kind; }
function renderOverview(s) {
  overview = s;
  const single = s.mode === 'single', primary = s.primary, rep = s.replication || {};
  const mail = s.modules.mail_enabled;
  document.querySelectorAll('[data-mail]').forEach(n => { n.hidden = !mail; });
  text('mail-summary', mail ? 'Enabled · Mailboxes, delivery, and protection' : 'Disabled · Data retained; mail service paused');
  if (!mail && ['accounts','queue','security'].includes(page)) navigate('modules');
  text('top-domain', s.domain); text('sidebar-node', s.node); text('sidebar-mode', single ? 'Single node · Primary' : 'Dual node · ' + (primary ? 'Primary' : 'Standby'));
  if (!can('system.read')) return;
  const limits = s.limits;
  text('capacity-connections',number(limits.connections)); text('capacity-transfers',number(limits.data_transfers));
  text('capacity-message',bytes(limits.message_bytes)); text('capacity-memory',bytes(s.peak_rss_kib == null ? null : s.peak_rss_kib * 1024));
  text('capacity-quota',bytes(limits.quota_bytes)); text('capacity-folder',number(limits.mailbox_messages)); text('capacity-queue',number(limits.queue_messages));
  text('node-name', s.node); text('hostname', s.hostname);
  badge($('role-badge'), primary ? '● PRIMARY' : '● STANDBY', primary ? '' : 'warning');
  text('service-headline', s.admin_only ? 'Your local Admin console is running.' : primary ? (mail ? 'Ready to serve your mail.' : 'Core is running. Mail is disabled.') : s.ready ? 'Standing by for the primary.' : 'Waiting for the initial snapshot.');
  text('service-description', s.admin_only ? 'Manage the remote gateway and local Accounting here. Gateway protection continues when this console is offline.' : single ? 'Single-node mode is active. Data is stored locally; no replica or witness is required.' : primary ? 'This node holds the witness lease and accepts enabled-module writes. Replication runs in the background.' : 'Mail access is paused on this node. It becomes eligible for failover after it has a complete database.');
  $('standby-notice').hidden = primary; $('add-account').disabled = !primary || !mail;
  document.querySelectorAll('[data-reset]').forEach(b => { b.disabled = !primary; });
  text('metric-accounts', number(s.accounts)); text('metric-messages', number(s.messages));
  text('metric-storage', bytes(s.mailbox_bytes) + ' across all folders'); text('metric-queue', number(s.queue_count));
  text('metric-failed', s.queue_failed ? number(s.queue_failed)+' failed · review delivery queue' : 'No failed deliveries');
  text('metric-memory', bytes(s.peak_rss_kib == null ? null : s.peak_rss_kib * 1024));
  badge($('mode-badge'), single ? 'Single node' : 'Dual node', 'neutral');
  text('replica-local', s.node); text('replica-peer', single ? 'No replica configured' : 'Peer database');
  const fresh = rep.last_contact && Date.now()/1000-rep.last_contact < 15;
  text('replica-state', single ? 'Add a second node to replicate' : rep.last_error ? 'Peer unavailable' : fresh ? (rep.direction === 'sending' ? 'Acknowledging writes' : 'Receiving updates') : 'No recent contact');
  text('replica-term', number(s.term)); text('replica-sequence', number(s.sequence));
  text('replica-contact', single ? 'Not applicable' : ago(rep.last_contact));
  text('replica-ack', single ? 'Not applicable' : rep.peer_sequence == null ? 'Not recorded' : number(rep.peer_sequence)+' (term '+number(rep.term)+')');
  let note;
  if (single) note = 'To scale out, keep this database and cluster ID, configure the witness and peer, then restart in dual mode. The new node receives an automatic snapshot.';
  else if (rep.last_error && primary) note = 'Peer contact failed. Local acceptance continues; recent writes may exist on this node only. ' + rep.last_error;
  else if (primary && rep.term === s.term && rep.peer_sequence != null) note = number(Math.max(0,s.sequence-rep.peer_sequence))+' transaction(s) beyond the last peer acknowledgment. Replication is asynchronous; an acknowledgment is not a guarantee about future writes.';
  else note = 'Replication is asynchronous. This view records the last exchange; it does not prove that the peer has every latest write. Both nodes need the witness for safe failover.';
  text('replica-note', note);
  const t=s.tls;
  text('tls-status', !t?'Certificate status requires system read access.':(t.mode==='letsencrypt'?'Let’s Encrypt · automatic renewal':'Manual certificate · administrator manages renewal')+' · '+(t.ready?'Available':'Waiting for certificate')+' · Expires '+date(t.expires_at));
  text('tls-warning', !t?'':t.staging?'Staging certificate: test use only; clients do not trust it.':t.last_error||t.expiring_soon?(t.automatic_renewal?'Certificate needs attention. Check service logs, DNS and public port 80 access.':'Certificate expires soon. Renew it with your issuer, replace the certificate and key, then restart the service.'):t.automatic_renewal?'Renewals follow the CA’s suggested window or certificate lifetime. New TLS connections load the renewed certificate automatically.':'Restart after replacing the certificate and key files.');
}
function renderAccounts() {
  const q = $('account-search').value.trim().toLowerCase(); const rows = accounts.filter(a => a.email.toLowerCase().includes(q));
  $('accounts-body').replaceChildren(); $('accounts-empty').hidden = rows.length !== 0;
  rows.forEach(a => {
    const tr = el('tr'), email = el('td'); email.append(el('strong', a.email));
    const storage = el('td', undefined, 'storage-cell'); storage.append(el('span', bytes(a.used_bytes) + ' / ' + bytes(a.quota)));
    const progress = el('progress'); progress.max = Math.max(1,a.quota); progress.value = a.used_bytes; progress.setAttribute('aria-label', 'Storage used by '+a.email); storage.append(progress);
    const actions = el('td'), reset = el('button', 'Reset password', 'quiet'); reset.dataset.reset = a.email; reset.disabled = !overview?.primary; reset.addEventListener('click', () => openAccount(a.email)); actions.append(reset);
    tr.append(email,storage,el('td',number(a.messages)),el('td',number(a.folders)),actions); $('accounts-body').append(tr);
  });
}
function renderQueue() {
  const delivery = overview?.delivery || {};
  const route = delivery.mode === 'direct' ? 'Direct delivery to recipient MX servers · '+(delivery.tls === 'required' ? 'TLS required' : 'TLS when offered') : delivery.mode === 'relay' ? 'Delivery through configured relay' : 'Outbound delivery disabled';
  text('queue-routing', route + (delivery.dkim_selector ? ' · DKIM: '+delivery.dkim_selector+'._domainkey.'+delivery.dkim_domain : ' · Local DKIM signing disabled')); 
  const q = $('queue-search').value.trim().toLowerCase(), status = $('queue-status').value;
  const rows = queue.filter(([,v]) => (v.sender+' '+v.recipient).toLowerCase().includes(q) && (status === 'all' || v.status === status));
  $('queue-body').replaceChildren(); $('queue-empty').hidden = rows.length !== 0;
  rows.forEach(([,v]) => {
    const tr = el('tr'), recipient = el('td'), state = el('td'); recipient.append(el('strong', v.recipient),el('small','From: '+(v.sender || '<>')));
    const b = el('span'); badge(b, v.status, v.status === 'failed' ? 'bad' : 'warning'); state.append(b); state.append(el('small', v.dkim_signed ? 'DKIM signed' : 'Not locally signed'));
    tr.append(recipient,state,el('td',number(v.attempts)),el('td',v.status === 'failed' ? 'No automatic retry' : date(v.next_try)),el('td',v.last_error || '—','error-cell')); $('queue-body').append(tr);
  });
}
function renderSecurity(v) {
  const rules = [
    ['DMARC policy','Enforces the sender domain’s effective policy using aligned SPF or DKIM.','Always evaluated',true],
    ['DMARC quarantine','Failed mail under p=quarantine is routed to Junk when enabled.',v.quarantine_dmarc ? 'Route to Junk' : 'Reject',true],
    ['Reject SPF failures','Strict rule independent of DMARC. Forwarded mail can fail SPF.',v.reject_spf_fail ? 'Enabled':'Disabled',v.reject_spf_fail],
    ['Reject DKIM failures','Reject signatures that fail verification, independently of DMARC.',v.reject_dkim_fail ? 'Enabled':'Disabled',v.reject_dkim_fail],
    ['Require DKIM','Require a passing DKIM signature even when other authentication passes.',v.require_dkim ? 'Enabled':'Disabled',v.require_dkim]
  ];
  $('security-rules').replaceChildren(); rules.forEach(([title, description, status, on]) => { const row = el('div',undefined,'rule-row'), copy = el('div'), b = el('span'); copy.append(el('strong',title),el('p',description)); badge(b,status,on ? '' : 'neutral'); row.append(copy,b); $('security-rules').append(row); });
  ['senders','domains','ips'].forEach(key => { const list = v['blocked_'+key] || []; $('blocked-'+key).replaceChildren(...(list.length ? list.map(s => el('p',s)) : [el('p','No entries configured')])); });
}
function renderBackups(v) { $('backups-body').replaceChildren(); $('backups-empty').hidden = v.length !== 0; v.forEach(b => { const row = el('tr'), name = el('td'); name.append(el('code',b.name)); row.append(name,el('td',date(b.created)),el('td',bytes(b.bytes))); $('backups-body').append(row); }); }
async function refresh() {
  if (!session || refreshing) return;
  refreshing = true; const view = page, current = revision;
  $('refresh').disabled = true;
  try {
    const s = await api('overview'); if (current !== revision || !session) return; renderOverview(s);
    if (current !== revision) return;
    const catalog = await api('modules'); if (current !== revision) return; accountingState = catalog.accounting;
    document.querySelectorAll('[data-accounting]').forEach(n => {n.hidden = !accountingState?.enabled;});
    if (view === 'modules') renderModules(catalog);
    applyPermissions();
    if (['finance','banking','xero'].includes(view)) {if (!accountingState?.enabled) {navigate('modules'); return;} await refreshAccounting(view,current);}
    if (view === 'accounts') { const v = await api('users'); if (current !== revision) return; accounts = v; renderAccounts(); }
    if (view === 'queue') { const v = await api('queue'); if (current !== revision) return; queue = v; renderQueue(); }
    if (view === 'security') { const v = await api('policy'); if (current !== revision) return; renderSecurity(v); }
    if (view === 'backups') { const v = await api('backups'); if (current !== revision) return; renderBackups(v); }
    text('updated','Updated '+new Date().toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'})); $('global-error').hidden = true;
  } catch (e) { if (session && current === revision) { text('global-error',e.message); $('global-error').hidden = false; } }
  finally { refreshing = false; $('refresh').disabled = false; if (session && current !== revision) void refresh(); }
}
function navigate(next) {
  page = pages[next] && pageAllowed(next) ? next : can('accounting.read') ? 'finance' : 'modules';
  if (overview && !overview.modules.mail_enabled && ['accounts','queue','security'].includes(page)) page = 'modules';
  $('module-back-admin').hidden=!['finance','banking','xero','accounts','queue','security'].includes(page);
  revision++;
  document.querySelectorAll('.page-panel').forEach(p => { p.hidden = p.id !== page; });
  document.querySelectorAll('[data-page]').forEach(b => { if (b.dataset.page === page) b.setAttribute('aria-current','page'); else b.removeAttribute('aria-current'); });
  const [eyebrow,title,description] = pages[page]; text('page-eyebrow',eyebrow); text('page-title',title); text('page-description',description); document.title = title+' · Workglen';
  history.replaceState(null,'','#'+page); void refresh();
}
function loggedIn(v) { session = v; $('login-view').hidden = true; $('app-view').hidden = false; text('signed-in-user', v.username); $('password').value = ''; text('login-error',''); navigate(location.hash.slice(1) || 'overview'); }
$('module-back-admin').addEventListener('click',e=>{e.preventDefault();navigate('modules');});
$('login-form').addEventListener('submit', async e => {
  e.preventDefault(); const button = e.submitter; button.disabled = true; text('login-error','');
  try { loggedIn(await api('login', {username:$('username').value,password:$('password').value})); }
  catch (error) { text('login-error',error.message); }
  finally { button.disabled = false; }
});
$('logout').addEventListener('click', async () => { try { await api('logout',{}); loggedOut(); text('login-error',''); } catch (e) { toast(e.message); } });
document.querySelectorAll('[data-page]').forEach(b => b.addEventListener('click', () => navigate(b.dataset.page)));
document.querySelectorAll('[data-open-page]').forEach(b => b.addEventListener('click', () => navigate(b.dataset.openPage)));
document.querySelectorAll('[data-theme-choice]').forEach(b=>b.addEventListener('click',()=>{const theme=applyTheme(b.dataset.themeChoice);toast(THEME_NAMES[theme]+' theme applied.');}));
window.addEventListener('storage',e=>{if(e.key===THEME_KEY)applyTheme(e.newValue,false);});
$('refresh').addEventListener('click', () => void refresh());
$('account-search').addEventListener('input',renderAccounts); $('queue-search').addEventListener('input',renderQueue); $('queue-status').addEventListener('change',renderQueue);
function openAccount(email) {
  editing = !!email; $('account-form').reset(); text('account-error',''); $('account-email').readOnly = editing; $('account-email').value = email || '';
  $('account-email').placeholder = 'name@'+(overview?.domain || 'example.com');
  text('dialog-title',editing ? 'Reset password' : 'Create account'); text('dialog-description',editing ? 'Existing signed-in mailbox sessions can remain active until they reconnect.' : 'Create an IMAP and SMTP account on the primary.');
  text('save-account',editing ? 'Save password' : 'Create account'); $('account-dialog').showModal(); (editing ? $('account-password') : $('account-email')).focus();
}
$('add-account').addEventListener('click', () => openAccount());
function closeDialog() { $('account-dialog').close(); $('account-form').reset(); }
$('close-dialog').addEventListener('click',closeDialog); $('cancel-dialog').addEventListener('click',closeDialog); $('account-dialog').addEventListener('close', () => $('account-form').reset());
$('account-form').addEventListener('submit', async e => {
  e.preventDefault(); text('account-error','');
  if ($('account-password').value !== $('account-confirm').value) { text('account-error','The passwords do not match.'); $('account-confirm').focus(); return; }
  const button = $('save-account'); button.disabled = true;
  try { await api(editing ? 'users/password' : 'users', {email:$('account-email').value,password:$('account-password').value}); closeDialog(); toast(editing ? 'Password updated.' : 'Account created.'); await refresh(); }
  catch (error) { text('account-error',error.message); }
  finally { button.disabled = false; }
});
$('create-backup').addEventListener('click', async () => {
  const button = $('create-backup'); button.disabled = true; button.textContent = 'Creating backup…';
  try { const result = await api('backups',{}); text('backup-result','Completed backup: '+result.path); toast('Database backup created.'); await refresh(); }
  catch (error) { text('backup-result',error.message); toast('Backup could not be completed.'); }
  finally { button.disabled = false; button.textContent = '+ Create backup'; }
});
setInterval(() => { if (!document.hidden && session && !$('account-dialog').open && !$('module-dialog').open && !$('posting-dialog').open) void refresh(); },10000);
void api('session').then(loggedIn).catch(() => { loggedOut(); text('login-error',''); });

function renderModules(v) {
  moduleState = v.state;
  $('available-modules').replaceChildren(); $('planned-modules').replaceChildren();
  for (const m of v.modules) {
    const card = el('article', undefined, 'module-card' + (m.implemented ? ' installed' : ''));
    const head = el('div',undefined,'module-card-heading'), icon = el('span',m.id === 'mail' ? 'M' : m.name[0],'module-icon'), state = el('span');
    badge(state,m.implemented ? (m.enabled ? 'Enabled' : 'Disabled') : 'Planned',m.enabled ? '' : 'neutral'); head.append(icon,state);
    card.append(head,el('h3',m.name),el('p',m.description));
    const foot = el('div',undefined,'module-card-footer'); foot.append(el('span','Requires Core','small muted'));
    if (v.admin_only && ['mail','webmail'].includes(m.id)) {
      foot.replaceChildren(el('span','Not run by the local Admin profile','small muted'));
    } else if (m.id === 'accounts') {
      foot.replaceChildren(el('span',v.accounting?.message || 'Requires your PostgreSQL database','small muted'));
      const b=el('button',m.enabled?'Disable Accounting':'Enable Accounting',m.enabled?'secondary':'primary');b.id='toggle-accounting';b.disabled=!v.primary || !v.accounting?.ready || !can('modules.accounts');
      b.addEventListener('click',async()=>{b.disabled=true;try{await api('modules',{id:'accounts',enabled:!m.enabled,expected_revision:v.accounting.revision});toast(m.enabled?'Accounting disabled. Data retained.':'Accounting enabled.');await refresh();}catch(e){toast(e.message);b.disabled=false;}});foot.append(b);
    } else if (m.id === 'webmail') {
      foot.replaceChildren(el('span',!v.webmail_configured?'Configure the Webmail HTTPS listener':!v.state.mail_enabled?'Paused while Mail is disabled':'Requires Core and Mail','small muted'));
      const b=el('button',m.enabled?'Disable Webmail':'Enable Webmail',m.enabled?'secondary':'primary');b.id='toggle-webmail';b.disabled=!v.primary||!can('modules.mail')||(!m.enabled&&(!v.webmail_configured||!v.state.mail_enabled));
      b.addEventListener('click',async()=>{b.disabled=true;try{await api('modules',{id:'webmail',enabled:!m.enabled,expected_revision:v.state.revision});toast(m.enabled?'Webmail disabled. Mail delivery continues.':'Webmail enabled.');await refresh();}catch(e){toast(e.message);await refresh();}});foot.append(b);
    } else if (m.implemented) {
      const button = el('button', m.enabled ? 'Disable Mail' : 'Enable Mail', m.enabled ? 'secondary' : 'primary');
      button.id = 'toggle-mail'; button.disabled = !v.primary || !can('modules.mail');
      button.addEventListener('click',() => {
        if (m.enabled) { text('module-error',''); $('module-dialog').showModal(); }
        else void changeMail(true);
      }); foot.append(button);
    } else foot.append(el('span','Not installed','small muted'));
    card.append(foot); $(m.implemented ? 'available-modules' : 'planned-modules').append(card);
  }
}
async function changeMail(enabled) {
  if (!moduleState) return;
  $('confirm-module').disabled = true;
  if ($('toggle-mail')) $('toggle-mail').disabled = true;
  try {
    await api('modules',{id:'mail',enabled,expected_revision:moduleState.revision});
    $('module-dialog').close(); toast(enabled ? 'Workglen Mail enabled.' : 'Workglen Mail disabled. Data retained.');
    await refresh();
  } catch (e) {
    if ($('module-dialog').open) text('module-error',e.message);
    else toast(e.message);
    // Refresh the expected revision after a concurrent administrator change.
    try { renderModules(await api('modules')); } catch (_) { /* next refresh reports connection errors */ }
  } finally {
    $('confirm-module').disabled = false;
    if ($('toggle-mail')) $('toggle-mail').disabled = !overview?.primary;
  }
}
$('cancel-module').addEventListener('click',() => $('module-dialog').close());
$('module-form').addEventListener('submit',e => { e.preventDefault(); void changeMail(false); });
