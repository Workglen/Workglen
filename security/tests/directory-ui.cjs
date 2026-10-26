'use strict';
// Browser-only synthetic Graph snapshot/API fixture. Never contacts Microsoft.
const {chromium}=require('playwright'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../../web'),checks=[],pass=s=>{checks.push(s);console.log('PASS '+s);};
let settings={revision:1,enabled:false,domains:['example.test'],routes:{'example.test':'m365'},mailboxes:{'old@example.test':{enabled:false,digest_hours:48},'manual@example.test':{enabled:true}},connectors:{},protected_people:[],protected_domains:[],digest_sender:'',digest_hours:24,retention_days:30};
let task={state:'none'},fail=false,applied=0,mode='security';
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://localhost');let value;
 if(url.pathname==='/api/session')value=mode==='mail'?{user:'person@example.test',csrf:'test',admin_origin:'https://admin.example.test:8444'}:{username:'admin',csrf:'test',permissions:['security.read','security.configure'],security_domains:['*'],security_mailboxes:['*']};
 else if(url.pathname==='/api/security/remotes')value=[{id:'gateway',label:'Lightsail gateway'}];
 else if(url.pathname==='/api/mail'){let text='';for await(const part of req)text+=part;const c=JSON.parse(text);value=c.action==='folders'?[{name:'INBOX',unread:0}]:{validity:1,next:null,messages:[]};}
 else if(url.pathname==='/api/security'){
  let text='';for await(const part of req)text+=part;const {command:c}=JSON.parse(text),d=c.data;
  if(c.action==='status')value={messages:{},jobs:{},bytes:0,enabled:false,instance:'gateway',storage_encryption:{enabled:true}};
  else if(c.action==='delivery-status')value={state:'none'};
  else if(c.action==='setup')value={settings,routes:{m365:{host:'example.mail.protection.outlook.com',port:25}},connector_profiles:{},recipient_directory:{configured:true},tests:{}};
  else if(c.action==='configure'){assert.equal(d.expected_revision,settings.revision);Object.assign(settings,d.settings);settings.revision++;value={revision:settings.revision,enabled:false};}
  else if(c.action==='recipient-discover'){task={id:c.request_id,state:'queued',domains:d.domains,revision:d.expected_revision,addresses:['new@example.test','old@example.test']};value={...task};task.state=fail?'failed':'ready';task.error='Synthetic Microsoft 365 failure; accepted recipients are unchanged';}
  else if(c.action==='recipient-discovery')value=task;
  else if(c.action==='recipient-apply'){assert.equal(d.confirm,true);assert.equal(d.id,task.id);assert.equal(d.expected_revision,settings.revision);assert.deepEqual(d.domains,['example.test']);assert.deepEqual(d.routes,{'example.test':'m365'});for(const a of task.addresses)settings.mailboxes[a]??={enabled:true};settings.revision++;task.state='applied';applied++;value={revision:settings.revision,enabled:false};}
  else throw Error('Unexpected command '+c.action);
 }
 if(value!==undefined){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(value));return;}
 const files={'/mail-security':'security/index.html','/delivery.js':'security/delivery.js','/microsoft365.js':'security/microsoft365.js','/security.js':'security/security.js','/security.css':'security/security.css','/':'mail.html','/mail.js':'mail.js','/mail.css':'mail.css','/favicon.svg':'favicon.svg'};
 if(files[url.pathname]){res.writeHead(200,{'content-type':url.pathname.endsWith('.js')?'text/javascript':url.pathname.endsWith('.css')?'text/css':'text/html'});res.end(fs.readFileSync(path.join(root,files[url.pathname])));}else{res.writeHead(404);res.end();}
});
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const b=await chromium.launch({headless:true,executablePath:process.env.WORKGLEN_CHROMIUM,args:['--no-sandbox','--single-process','--no-zygote']});
 try{
  const p=await b.newPage({viewport:{width:1280,height:900}}),errors=[];p.on('pageerror',e=>errors.push(e.message));p.on('dialog',d=>d.accept());
  await p.goto('http://127.0.0.1:'+server.address().port+'/mail-security');await p.getByRole('heading',{name:'Protection at a glance'}).waitFor();
  assert(await p.getByRole('link',{name:'Back to Admin',exact:false}).isVisible());
  await p.getByRole('button',{name:'Setup',exact:true}).click();await p.getByRole('button',{name:'Save and continue'}).click();
  await p.getByRole('heading',{name:'Microsoft 365 recipient discovery'}).waitFor();
  await p.getByRole('button',{name:'Discover recipients',exact:true}).click();
  await p.getByRole('button',{name:'Apply additions',exact:true}).waitFor();assert.equal(applied,0);
  await p.getByText('2 discovered addresses · 1 additions · 1 existing addresses absent from this result (retained).',{exact:true}).waitFor();
  assert.equal(await p.getByLabel('Discovered addresses',{exact:true}).inputValue(),'new@example.test\nold@example.test');pass('discovery requires explicit review before applying additions');
  await p.getByRole('button',{name:'Apply additions',exact:true}).click();await p.getByText('Recipient additions saved.',{exact:false}).waitFor();assert.equal(applied,1);assert.deepEqual(settings.mailboxes['old@example.test'],{enabled:false,digest_hours:48});assert(settings.mailboxes['manual@example.test']);
  const accepted=await p.getByLabel('Accepted mailbox addresses',{exact:true}).inputValue();assert(accepted.includes('new@example.test'));assert(accepted.includes('manual@example.test'));pass('applying discovery preserves existing recipients and preferences');
  fail=true;await p.getByRole('button',{name:'Discover recipients',exact:true}).click();await p.getByText('Synthetic Microsoft 365 failure; accepted recipients are unchanged',{exact:true}).waitFor();assert.equal(await p.getByRole('button',{name:'Apply additions',exact:true}).count(),0);assert.equal(applied,1);pass('failed discovery offers no apply action');
  await p.getByText('Connect Microsoft 365 — one-time setup',{exact:true}).click();await p.getByText('Under API permissions,',{exact:false}).waitFor();
  await p.setViewportSize({width:390,height:844});const link=await p.locator('#back-admin').boundingBox();assert(link&&link.x>=0&&link.x+link.width<=390);assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));pass('Admin navigation and Microsoft 365 setup fit narrow screens');
  mode='mail';await p.goto('http://127.0.0.1:'+server.address().port+'/');await p.locator('#back-admin').waitFor();assert.equal(await p.locator('#back-admin').getAttribute('href'),'https://admin.example.test:8444');pass('Webmail uses the configured Admin origin without forwarding credentials');
  assert.deepEqual(errors,[]);pass('no browser script errors');
  if(process.argv[2])fs.writeFileSync(process.argv[2],JSON.stringify({passed:checks.length,checks},null,2));
 }finally{await b.close();server.close();}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
