'use strict';
const {chromium}=require('playwright'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../../web'),checks=[],pass=s=>{checks.push(s);console.log('PASS '+s);};
let mutations=0;
const settings={revision:3,enabled:false,domains:['example.test'],routes:{'example.test':'m365'},mailboxes:{'person@example.test':{enabled:true}},connectors:{}};
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://localhost');let value;
 if(url.pathname==='/api/session')value={username:'admin',csrf:'synthetic',permissions:['security.read','security.configure'],security_domains:['*'],security_mailboxes:['*']};
 else if(url.pathname==='/api/security/remotes')value=[{id:'a',label:'Gateway A'},{id:'b',label:'Gateway B'}];
 else if(url.pathname==='/api/logout')value={ok:true};
 else if(url.pathname==='/api/security'){
  let body='';for await(const part of req)body+=part;
  const {instance,command:c}=JSON.parse(body);
  if(c.action==='status')value={messages:{},jobs:{},bytes:0,enabled:false,instance,storage_encryption:{enabled:true}};
  else if(c.action==='setup')value={settings,routes:{m365:{host:'example.mail.protection.outlook.com',port:25,tls:true,label:'Microsoft 365'}},connector_profiles:{},tests:{}};
  else {mutations++;res.writeHead(400);res.end(JSON.stringify({error:'Unexpected mutation '+c.action}));return;}
 }
 if(value!==undefined){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(value));return;}
 const files={'/mail-security':'security/index.html','/delivery.js':'security/delivery.js','/microsoft365.js':'security/microsoft365.js','/security.js':'security/security.js','/security.css':'security/security.css'};
 if(files[url.pathname]){res.writeHead(200,{'content-type':url.pathname.endsWith('.js')?'text/javascript':url.pathname.endsWith('.css')?'text/css':'text/html'});res.end(fs.readFileSync(path.join(root,files[url.pathname])));}else{res.writeHead(404);res.end();}
});
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const b=await chromium.launch({headless:true,executablePath:process.env.WORKGLEN_CHROMIUM,args:['--no-sandbox','--single-process','--no-zygote']});
 try{
  const p=await b.newPage({viewport:{width:1280,height:900}}),errors=[],external=[];p.on('pageerror',e=>errors.push(e.message));
  await p.route('**/*',r=>{const u=new URL(r.request().url());if(u.hostname!=='127.0.0.1'){external.push(u.href);return r.abort();}return r.continue();});
  await p.goto('http://127.0.0.1:'+server.address().port+'/mail-security');await p.getByRole('heading',{name:'Operations',exact:true}).waitFor();
  await p.evaluate(async()=>{wizardStep=6;await show('Setup');});
  await p.getByRole('heading',{name:'Microsoft 365 protection',exact:true}).waitFor();
  assert((await p.getByLabel('Microsoft 365 destination',{exact:true}).textContent()).includes('example.test → example.mail.protection.outlook.com'));
  await p.getByText('Microsoft 365 enforcement is not verified by Workglen.',{exact:false}).waitFor();pass('selected Microsoft route shows tenant scope and truthful unverified status');
  await p.getByRole('button',{name:'Prepare Microsoft 365 commands'}).click();await p.locator('#notice').filter({hasText:'Review the tenant’s mail paths'}).waitFor();assert.equal(await p.getByLabel('Create disabled Partner connector',{exact:true}).count(),0);pass('commands require explicit tenant and dedicated-address review');
  const review=()=>p.getByLabel('I reviewed the entire tenant’s mail paths and confirmed these addresses are dedicated to our gateways.',{exact:true});
  await p.getByLabel('Gateway public outbound IPv4 addresses',{exact:true}).fill('192.168.1.1');await review().check();await p.getByRole('button',{name:'Prepare Microsoft 365 commands'}).click();await p.locator('#notice').filter({hasText:'real public outbound/NAT'}).waitFor();assert.equal(await p.getByLabel('Create disabled Partner connector',{exact:true}).count(),0);pass('private source addresses cannot generate a plan');
  await p.getByLabel('Gateway public outbound IPv4 addresses',{exact:true}).fill('8.8.8.8\n8.8.4.4');assert.equal(await review().isChecked(),false);await review().check();await p.getByRole('button',{name:'Prepare Microsoft 365 commands'}).click();
  const stage=await p.getByLabel('Create disabled Partner connector',{exact:true}).inputValue();assert(stage.includes('-SenderDomains \'*\''));assert(stage.includes('-Enabled $false'));assert(stage.includes('-RestrictDomainsToIPAddresses $true'));assert(await p.getByLabel('Create disabled Partner connector',{exact:true}).evaluate(e=>e.readOnly));
  assert((await p.getByLabel('Configure Enhanced Filtering',{exact:true}).inputValue()).includes('-EFUsers $null'));await p.getByText('Old MX caches can cause delivery failures',{exact:false}).waitFor();await p.getByText('Require a permanent 5xx rejection',{exact:false}).waitFor();pass('staged commands, filtering, rollout and positive/negative evidence are guided separately');
  await p.getByLabel('Partner connector name',{exact:true}).fill('Changed connector');assert.equal(await p.getByLabel('Create disabled Partner connector',{exact:true}).count(),0);assert.equal(await review().isChecked(),false);pass('editing inputs invalidates generated commands and review');
  await p.getByRole('button',{name:'Save and continue',exact:true}).click();await p.getByRole('heading',{name:'Go live',exact:true}).waitFor();await p.getByText('Microsoft 365 bypass protection is not verified by Workglen.',{exact:false}).waitFor();await p.getByRole('button',{name:'Review Microsoft 365 protection'}).click();assert.equal(await p.getByLabel('Partner connector name',{exact:true}).inputValue(),'Changed connector');assert.equal(await review().isChecked(),false);pass('go-live preserves the unverified status without a circular activation gate');
  await p.setViewportSize({width:390,height:844});await review().check();await p.getByRole('button',{name:'Prepare Microsoft 365 commands'}).click();assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  if(process.argv[2])await p.screenshot({path:path.join(path.dirname(process.argv[2]),'microsoft365-mobile.png'),fullPage:true});pass('guide and commands fit a narrow viewport');
  await p.getByLabel('Security instance',{exact:true}).selectOption('b');await p.getByRole('heading',{name:'Operations',exact:true}).waitFor();await p.evaluate(async()=>{wizardStep=6;await show('Setup');});assert.equal(await p.getByLabel('Gateway public outbound IPv4 addresses',{exact:true}).inputValue(),'');assert.equal(await p.getByLabel('Partner connector name',{exact:true}).inputValue(),'Workglen gateway only');pass('switching gateways clears the tenant-specific draft');
  assert.equal(mutations,0);assert.deepEqual(external,[]);assert.deepEqual(errors,[]);pass('guide never mutates a tenant, sends mail, loads external code or raises browser errors');
  if(process.argv[2])fs.writeFileSync(process.argv[2],JSON.stringify({passed:checks.length,checks},null,2));
 }finally{await b.close();server.close();}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
