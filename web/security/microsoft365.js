'use strict';

// A local, dependency-free guide. No tenant credentials, Microsoft API calls or
// persisted claims of enforcement. The administrator applies and tests the plan.
let microsoft365Draft = null;

function microsoft365Routes(settings, routes) {
 const groups = new Map();
 for (const domain of settings.domains || []) {
  const id = settings.routes?.[domain], route = routes[id];
  const host = String(route?.host || '').toLowerCase().replace(/\.$/, '');
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+mail\.protection\.outlook\.com$/.test(host)) continue;
  if (!groups.has(id)) groups.set(id, {id, host, domains: [], label: route.label || id});
  groups.get(id).domains.push(domain);
 }
 return [...groups.values()];
}

function microsoft365Plan(name, input) {
 name = name.trim();
 if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(name)) throw Error('Use a connector name of 1–64 letters, digits, spaces, dots, underscores or hyphens, starting with a letter or digit.');
 if (input.length > 1024) throw Error('Enter at most 16 dedicated public IPv4 addresses.');
 const ips = [...new Set(input.trim().split(/[\s,]+/).filter(Boolean))];
 if (!ips.length || ips.length > 16) throw Error('Enter 1–16 dedicated public IPv4 addresses, including every failover gateway.');
 for (const ip of ips) {
  if (!/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(ip)) throw Error('Use exact IPv4 addresses only; hostnames, IPv6, CIDR ranges and commands are not accepted.');
  const [a,b,c,d] = ip.split('.').map(Number);
  if ([a,b,c,d].some(n => n > 255) || a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && ((b === 168) || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)) throw Error('Use the real public outbound/NAT IPv4 address seen by Microsoft 365. Private, shared-address space, loopback, documentation and reserved addresses are not usable.');
 }
 // The strict alphabets above make every interpolated single-quoted value inert.
 const identity = "'" + name + "'", addresses = '@(' + ips.map(ip => "'" + ip + "'").join(', ') + ')';
 return {
  name, ips,
  inventory: 'Get-AcceptedDomain | Format-Table Name,DomainName,DomainType\nGet-InboundConnector | Format-List Name,Enabled,ConnectorType,SenderDomains,SenderIPAddresses,RestrictDomainsToIPAddresses,RestrictDomainsToCertificate,RequireTls,TreatMessagesAsInternal,EFSkipLastIP,EFSkipIPs,EFUsers\nGet-TransportRule | Format-Table Name,State,Mode,SetSCL',
  stage: 'New-InboundConnector -Name ' + identity + " -ConnectorType Partner -SenderDomains '*' -SenderIPAddresses " + addresses + ' -RestrictDomainsToIPAddresses $true -RestrictDomainsToCertificate $false -RequireTls $true -TreatMessagesAsInternal $false -Enabled $false -ErrorAction Stop',
  filtering: 'Set-InboundConnector -Identity ' + identity + ' -EFSkipLastIP $false -EFSkipIPs ' + addresses + ' -EFUsers $null -ErrorAction Stop',
  inspect: 'Get-InboundConnector -Identity ' + identity + ' | Format-List Name,Enabled,ConnectorType,SenderDomains,SenderIPAddresses,RestrictDomainsToIPAddresses,RestrictDomainsToCertificate,RequireTls,TreatMessagesAsInternal,EFSkipLastIP,EFSkipIPs,EFUsers',
  activate: 'Set-InboundConnector -Identity ' + identity + ' -Enabled $true -ErrorAction Stop',
  rollback: 'Set-InboundConnector -Identity ' + identity + ' -Enabled $false -ErrorAction Stop'
 };
}

function microsoft365Setup(parent, settings, data) {
 const routes = microsoft365Routes(settings, data.routes || {});
 parent.append(node('p','MX records guide normal senders to Workglen. A restricted Microsoft 365 Partner inbound connector also rejects external SMTP delivery that tries to bypass the gateway.'));
 if (!routes.length) {
  parent.append(node('p','No selected Microsoft 365 delivery destination was found. For Microsoft 365, return to Mail flow and select the tenant’s actual *.mail.protection.outlook.com destination. Other mail servers need their own equivalent receive restrictions.'));
  return;
 }
 parent.append(node('p','Microsoft 365 enforcement is not verified by Workglen. This guide prepares commands for your tenant administrator; it does not change Microsoft 365 or send test mail.','warning'));
 const key = JSON.stringify([instance, routes]);
 if (microsoft365Draft?.key !== key) microsoft365Draft = {key, route: routes[0].id, name: 'Workglen gateway only', ips: ''};
 const draft = microsoft365Draft;
 const route = select(parent,'Microsoft 365 destination',routes.map(r => [r.id,r.domains.join(', ')+' → '+r.host]),draft.route,'Use the Microsoft 365 admin center to confirm which tenant owns this destination. Different domains or destinations may share one tenant; prepare one reviewed restriction per tenant.');
 const list = (title, items) => { parent.append(node('h3',title));const ol=node('ol');for(const text of items)ol.append(node('li',text));parent.append(ol); };
 list('1. Review the whole tenant',[
  'Sign in to the correct tenant in Exchange admin center → Mail flow → Connectors. Review all accepted domains, existing connectors, transport rules, hybrid routing, applications and devices before proceeding. This wildcard restriction affects incoming SMTP across the tenant, including domains not listed in Workglen.',
  'Identify the dedicated, static public IPv4 addresses used for outbound SMTP by every Workglen gateway and failover gateway. Use the addresses Microsoft actually sees after NAT, which may differ from your public MX address. A shared NAT or provider relay would also trust other systems using that address.',
  'This guide supports a direct Workglen → Exchange Online route in the global Microsoft cloud. Intermediate relays, hybrid loops, sovereign clouds and IPv6-only egress need a separately reviewed design. Microsoft’s sender-IP restriction accepts IPv4 only. Your gateway must actually deliver over the listed IPv4 addresses.',
  'Use a Partner connector (from Partner organization to Microsoft 365), applying to all sender domains (*). An OnPremises connector alone, an IP allow entry or an MX change is not this restriction. The wildcard means external senders; do not substitute your recipient domain.'
 ]);
 const name=field(parent,'Partner connector name',draft.name,'Use a new, unique name. The create command fails if it already exists; review existing settings instead of overwriting them.');
 const ips=field(parent,'Gateway public outbound IPv4 addresses',draft.ips,'One exact dedicated address per line (maximum 16). Include every gateway in this tenant, not only the selected instance. No CIDR ranges or shared outbound IPs.','textarea');
 const reviewed=check(parent,'I reviewed the entire tenant’s mail paths and confirmed these addresses are dedicated to our gateways.',false);
 const result=node('section');
 const invalidate=()=>{draft.route=route.value;draft.name=name.value;draft.ips=ips.value;reviewed.checked=false;result.replaceChildren();};
 route.addEventListener('change',invalidate);name.addEventListener('input',invalidate);ips.addEventListener('input',invalidate);
 parent.append(button('Prepare Microsoft 365 commands',()=>{
  if(!reviewed.checked)throw Error('Review the tenant’s mail paths and dedicated gateway addresses before preparing commands.');
  const plan=microsoft365Plan(name.value,ips.value);
  result.replaceChildren();
  result.append(node('h3','2. Stage a disabled connector'),node('p','In an Exchange Online PowerShell session authenticated to the correct tenant, run each section separately and stop on any error. Exchange administration tools run on the administrator’s machine; Workglen needs no additional runtime or Microsoft credentials.'));
  const command=(label,value)=>{const box=field(result,label,value,'Review before running. These commands are never executed by Workglen.','textarea');box.readOnly=true;};
  command('Inspect tenant mail flow',plan.inventory);
  result.append(node('p','Save the inventory output with your change record. Create the Partner connector disabled so preparation does not interrupt delivery. If creation fails or the name already exists, stop; do not apply later commands to an unreviewed connector.'));
  command('Create disabled Partner connector',plan.stage);
  result.append(node('h3','3. Preserve Microsoft filtering'),node('p','Configure Enhanced Filtering for Connectors on this new connector. The command below skips only the listed gateway public IPs and applies to all recipients. Review pilot scope first if needed. Keep Microsoft spam/phishing protection enabled; remove existing SCL -1 bypass rules for this flow only after review. Do not skip Microsoft 365 IPs or untrusted senders, and do not mark mail as internal.'));
  command('Configure Enhanced Filtering',plan.filtering);
  command('Review staged connector',plan.inspect);
  result.append(node('p','Confirm Partner, SenderDomains *, the exact gateway IPs, RestrictDomainsToIPAddresses True, RequireTls True, TreatMessagesAsInternal False and Enabled False. In Microsoft Defender → Email & collaboration → Policies & rules → Threat policies → Enhanced filtering, review this connector and its skip list.'));
  result.append(node('h3','4. Activate during your go-live window'),node('p','Continue to Go live, finish Workglen readiness checks and enable gateway acceptance. First send a controlled message through each gateway directly and confirm downstream receipt. Then point public MX records only to Workglen (including backup MX), allow for DNS propagation, review the staged connector again, and run the enable command. Old MX caches can cause delivery failures after enforcement; schedule and monitor the transition. Until this connector is enabled and bypass tests pass, the bypass protection is unproven.'));
  command('Enable reviewed connector after gateway delivery succeeds',plan.activate);
  command('Inspect enabled connector',plan.inspect);
  result.append(node('h3','Emergency recovery'),node('p','If this new connector blocks legitimate mail, an authorized tenant administrator can disable it while investigating. This reopens direct-delivery bypass; record the exception, monitor mail and restore enforcement after repair. Do not delete or rewrite existing connectors or gateway data.'));
  command('Emergency disable — reopens bypass',plan.rollback);
 }),result);
 list('5. Prove both paths with controlled messages',[
  'Positive: send a harmless uniquely identified message through each active/failover Workglen gateway to a known valid mailbox. Confirm Workglen inspection and downstream delivery in both Workglen audit/queues and Exchange message trace. Repeat using normal public MX delivery after DNS propagation.',
  'Negative: from an independent external SMTP sender outside every allowed IP, send a harmless controlled message directly to the tenant’s actual Microsoft mail endpoint, bypassing MX lookup. Use a known valid mailbox and complete SMTP submission if necessary: rejection may occur after DATA. Require a permanent 5xx rejection specifically attributable to the connector restriction and no mailbox delivery. A timeout, 4xx, invalid-recipient error, spam rejection, or successful TLS/NOOP check is not proof.',
  'Cover every accepted domain and any deliverable tenant .onmicrosoft.com aliases. Also test a sender in a separate Microsoft 365 tenant. Review alternative inbound connectors and application/device paths; do not assume a single negative test covers them all.',
  'Record UTC time, source egress IP, recipient, Message-ID, SMTP response and trace evidence in your change record. Verify Enhanced Filtering preserves the original external sender context and that Microsoft protection still runs. Investigate any bypass acceptance before calling the tenant protected.',
  'This restricts external SMTP delivery. Same-tenant mail and authenticated submission through Microsoft 365, Graph or applications are separate paths and need their own access policies. Recheck after connector, IP, failover, MX or tenant-domain changes.'
 ]);
 parent.append(node('p','Certificate-based Partner restrictions are another Microsoft option, but this Workglen SMTP client does not present a client certificate. Its HTTPS or receiving-SMTP certificate is not proof of outbound SMTP identity. This guide therefore uses dedicated outbound IPv4 addresses.'));
 const links=node('p',undefined,'delivery-help');
 for(const [label,url]of [
  ['Microsoft mail-flow guidance','https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/manage-mail-flow-using-third-party-cloud'],
  ['Partner connector parameters','https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-inboundconnector'],
  ['Enhanced Filtering','https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors']
 ]){const a=node('a',label);a.href=url;a.target='_blank';a.rel='noopener noreferrer';links.append(a);}parent.append(links,node('small','MICROSOFT-365-GATEWAY.md in the source package contains the rollout and evidence checklist. Draft inputs last only for this signed-in page session; revisiting the step requires review again.'));
}

if (typeof module !== 'undefined' && module.exports) module.exports = {microsoft365Routes, microsoft365Plan};
