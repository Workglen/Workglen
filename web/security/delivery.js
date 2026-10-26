'use strict';
function deliverySetup(parent,s,data,update){
 parent.append(node('p','Tell Workglen where clean mail should go. For Microsoft 365, use the Microsoft destination behind your gateway. The connection must use verified TLS.'));
 const domains=field(parent,'Accepted domains',(setupDraft?.domains||s.domains).join('\n'),'Your email domains, one per line. Example: example.com','textarea');
 const names=()=>[...new Set(domains.value.split(/\s+/).filter(Boolean).map(x=>x.toLowerCase()))];
 const options=()=>Object.entries(data.routes).map(([id,r])=>[id,(r.label||id)+' — '+r.host+':'+r.port]);
 const initial=Object.values(setupDraft?.routes||s.routes)[0];
 const defaultId=data.routes[initial]?initial:Object.keys(data.routes)[0]||'';
 const destination=select(parent,'Default delivery destination',options().length?options():[['','No delivery destinations configured']],defaultId,'Choose an existing destination or add one below. New destinations are saved on this gateway and survive restarts.');
 destination.disabled=!options().length;
 const empty=node('p','No delivery destination is configured yet. Follow the steps below to add and test one before continuing.','warning');empty.hidden=options().length>0;parent.append(empty);
 const overrides=node('details'),perDomain={};overrides.append(node('summary','Use different destinations for some domains'));
 function refreshOverrides(){const old=Object.fromEntries(Object.entries(perDomain).map(([d,v])=>[d,v.value]));for(const d of Object.keys(perDomain))delete perDomain[d];overrides.replaceChildren(node('summary','Use different destinations for some domains'));for(const domain of names()){const previous=old[domain]??(s.routes[domain]===defaultId?'':s.routes[domain]||'');perDomain[domain]=select(overrides,'Destination for '+domain,[['','Use the default destination'],...options()],data.routes[previous]?previous:'');}overrides.hidden=!names().length;}
 parent.append(overrides);refreshOverrides();domains.addEventListener('input',refreshOverrides);
 const form=node('details');form.open=!options().length;form.append(node('summary','Add a delivery destination'));parent.append(form);
 form.append(node('h3','1. Choose your mail system'));
 const provider=select(form,'Mail system',[['microsoft365','Microsoft 365'],['smtp','Another SMTP mail system']],'microsoft365');
 const label=field(form,'Destination name','Microsoft 365','A friendly name for this selection.');
 const msHelp=node('div',undefined,'delivery-help');msHelp.append(node('h3','2. Find the Microsoft delivery hostname'),node('p','Try finding it from your domain’s MX records. If MX already points at Workglen or another filter, copy the Microsoft value from Microsoft 365 Admin → Settings → Domains → your domain → DNS records → MX → Points to address.'));
 const portal=node('a','Open Microsoft 365 domain settings');portal.href='https://admin.microsoft.com/#/Domains';portal.target='_blank';portal.rel='noopener noreferrer';msHelp.append(portal);form.append(msHelp);
 const host=field(form,'Delivery hostname','','Example: your-domain.mail.protection.outlook.com. Enter the hostname only. Never use this gateway’s own hostname.');
 const tlsMode=select(form,'Connection security',[['starttls','STARTTLS · port 25'],['implicit','TLS from connection start · port 465']],'starttls','Certificates are always verified. Microsoft 365 uses STARTTLS on port 25.');
 const otherHelp=node('p','For another mail system, use its public SMTP receive hostname with a trusted certificate. Private-network routes, custom certificate authorities and SMTP credentials can still be provisioned by the installation administrator.');otherHelp.hidden=true;form.append(otherHelp);
 const progress=node('p',''),result=node('div'),actions=node('div',undefined,'actions');progress.setAttribute('role','status');form.append(node('h3','3. Test and save'),node('p','The test checks the SMTP greeting and TLS connection. It sends no email. Saving adds a destination; assigning it to your domains and enabling mail acceptance are separate steps.'),progress,actions,result);
 let currentTask=null,verified=null,epoch=0;const selectedInstance=instance;
 const attached=()=>form.isConnected&&selectedInstance===instance;
 const candidate=()=>({label:label.value.trim(),provider:provider.value,host:host.value.trim().toLowerCase().replace(/\.$/,''),port:tlsMode.value==='implicit'?465:25,implicit_tls:tlsMode.value==='implicit'});

 // Compare fields without relying on object key order in server JSON.
 function matches(task){const c=candidate();return task.candidate&&Object.keys(c).every(k=>c[k]===task.candidate[k])&&JSON.stringify(task.domains)===JSON.stringify(names());}
 function busy(value){for(const b of [find,test,save]){b.dataset.keepDisabled=String(value);b.disabled=value;}if(!value)save.disabled=!verified;for(const f of [provider,label,host,tlsMode])f.disabled=value;tlsMode.disabled=value||provider.value==='microsoft365';}
 function invalidate(){verified=null;save.disabled=true;result.replaceChildren();if(currentTask?.state==='ready')progress.textContent='Details changed. Test this destination again before saving.';}
 provider.onchange=()=>{const ms=provider.value==='microsoft365';msHelp.hidden=!ms;find.hidden=!ms;otherHelp.hidden=ms;tlsMode.value='starttls';tlsMode.disabled=ms;label.value=ms?'Microsoft 365':'Mail server';invalidate();};
 for(const f of [label,host,tlsMode,domains])f.addEventListener('input',invalidate);
 const find=button('Find Microsoft 365 hostname',async()=>start('delivery-discover'));msHelp.append(find);
 const test=button('Test connection',async()=>start('delivery-test'));
 const save=button('Save destination',async()=>{
  if(!verified||!matches(verified))throw Error('Test the current destination details first.');
  const value=await cmd('delivery-save',{id:verified.id,expected_revision:s.revision,confirm:true});
  if(!attached())return;
  s.revision=value.revision;data.routes[value.id]=value.route;
  const previous=destination.value;
  destination.replaceChildren(...options().map(([v,t])=>new Option(t,v)));destination.disabled=false;
  destination.value=data.routes[previous]?previous:value.id;
  for(const [domain,select]of Object.entries(perDomain)){const before=select.value;select.replaceChildren(new Option('Use the default destination',''),...options().map(([v,t])=>new Option(t,v)));select.value=before;}
  empty.hidden=true;currentTask={...verified,state:'saved'};verified=null;result.replaceChildren();save.dataset.keepDisabled='true';save.disabled=true;
  progress.textContent='Destination saved. '+(destination.value===value.id?'It is selected above.':'Choose it above if you want to change the current destination.')+' Continue to recipients when ready.';
  setupDraft={domains:names(),routes:Object.fromEntries(names().map(d=>[d,perDomain[d]?.value||destination.value]))};
 });save.disabled=true;save.dataset.keepDisabled='true';actions.append(test,save);tlsMode.disabled=true;
 async function start(action){
  const ds=names();if(!ds.length)throw Error('Enter your accepted email domain above first.');
  if(action==='delivery-test'&&!host.value.trim())throw Error('Find or enter the delivery hostname first.');
  invalidate();const version=++epoch;busy(true);progress.textContent=action==='delivery-discover'?'Looking for a Microsoft 365 MX destination…':'Testing SMTP and verified TLS from the gateway…';
  try{const task=await cmd(action,{domains:ds,domain:ds[0],candidate:candidate(),expected_revision:s.revision});await render(task,version);}
  catch(e){if(attached()){busy(false);progress.textContent=e.message;}throw e;}
 }
 async function render(task,version){
  if(!attached()||version!==epoch)return;currentTask=task;result.replaceChildren();
  if(['queued','running'].includes(task.state)){busy(true);progress.textContent=task.kind==='delivery-discover'?'Looking up MX records…':'Checking the delivery connection… Mail processing continues while this runs.';
   setTimeout(async()=>{if(!attached()||version!==epoch)return;try{await render(await cmd('delivery-status'),version);}catch(e){busy(false);progress.textContent=e.message;}},1500);return;}
  busy(false);tlsMode.disabled=provider.value==='microsoft365';
  if(task.state==='failed'){
   progress.textContent='Check did not succeed. '+task.error;
   result.append(node('p','For a connection failure: confirm the hostname and outbound SMTP access. Lightsail may restrict outbound port 25; opening an inbound firewall port does not remove that restriction. Check TLS certificates at the destination. Your entries are kept so you can correct them and retry.','warning'));return;
  }
  if(task.state!=='ready')return;
  if(task.kind==='delivery-discover'){
   const hosts=task.result.hosts||[];
   if(!hosts.length){progress.textContent='No Microsoft 365 MX destination was found. Your MX may already point to a gateway. Copy the Microsoft hostname using step 2 above, then test it.';return;}
   if(hosts.length===1){host.value=hosts[0];progress.textContent='Microsoft 365 hostname found. Review it, then choose Test connection.';}
   else{const pick=select(result,'Discovered Microsoft 365 destinations',hosts.map(h=>[h,h]),hosts[0]);host.value=pick.value;pick.onchange=()=>{host.value=pick.value;invalidate();};progress.textContent='Choose a discovered destination, then test it.';}return;
  }
  if(task.result.ok===true&&task.revision===s.revision&&matches(task)){
   verified=task;save.disabled=false;save.dataset.keepDisabled='false';progress.textContent=task.result.detail;result.append(node('p','Connection verified. Choose Save destination to make it available in the selection above.'));
  }else{progress.textContent='The destination or settings changed after testing. Test again before saving.';}
 }
 // Recover an in-progress test after navigating away, without copying credentials.
 cmd('delivery-status').then(task=>{
  if(!attached()||epoch||!['queued','running'].includes(task.state))return;
  if(task.candidate){provider.value=task.candidate.provider;label.value=task.candidate.label;host.value=task.candidate.host;tlsMode.value=task.candidate.implicit_tls?'implicit':'starttls';msHelp.hidden=provider.value!=='microsoft365';find.hidden=msHelp.hidden;otherHelp.hidden=!msHelp.hidden;}
  void render(task,epoch);
 }).catch(()=>{});
 return async()=>{
  const ds=names();if(!ds.length)throw Error('Enter at least one accepted email domain.');
  const routes=Object.fromEntries(ds.map(d=>[d,perDomain[d]?.value||destination.value]));
  if(!Object.keys(data.routes).length||Object.values(routes).some(id=>!data.routes[id])){form.open=true;empty.hidden=false;destination.focus();throw Error('Add, test and save a delivery destination in Mail flow before continuing to recipients.');}
  const mailboxes=Object.fromEntries(Object.entries(s.mailboxes).filter(([a])=>ds.includes(a.split('@')[1])));
  if(!Object.keys(mailboxes).length){setupDraft={domains:ds,routes};notice('Delivery destination selected. Next, add or discover your recipients.');return;}
  await update({domains:ds,routes,mailboxes});setupDraft=null;
 };
}
