'use strict';
// Synthetic UI workflow starting with the installer's empty route map.
const {chromium}=require('playwright'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../../web'),checks=[],pass=s=>{checks.push(s);console.log('PASS '+s);};
let settings={revision:0,enabled:false,domains:[],routes:{},mailboxes:{},connectors:{},protected_people:[],protected_domains:[],digest_sender:'',digest_hours:24,retention_days:30},routes={},task={state:'none'},saved=0,tests=0;
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://localhost');let value;
 if(url.pathname==='/api/session')value={username:'admin',csrf:'test',permissions:['security.read','security.configure'],security_domains:['*'],security_mailboxes:['*']};
 else if(url.pathname==='/api/security/remotes')value=[{id:'gateway',label:'Lightsail gateway'}];
 else if(url.pathname==='/api/security'){
  let text='';for await(const part of req)text+=part;const {command:c}=JSON.parse(text),d=c.data;
  if(c.action==='status')value={messages:{},jobs:{},bytes:0,enabled:false,instance:'gateway',storage_encryption:{enabled:true}};
  else if(c.action==='setup')value={settings,routes,connector_profiles:{},recipient_directory:{configured:false},tests:{}};
  else if(c.action==='configure'){assert.equal(d.expected_revision,settings.revision);assert(Object.values(d.settings.routes||settings.routes).every(id=>routes[id]));Object.assign(settings,d.settings);settings.revision++;value={revision:settings.revision,enabled:false};}
  else if(['delivery-test','delivery-discover'].includes(c.action)){
   assert.equal(d.expected_revision,settings.revision);assert.deepEqual(d.domains,['example.test']);
   task={id:c.request_id,kind:c.action,state:'queued',candidate:d.candidate,domain:d.domain,domains:d.domains,revision:d.expected_revision};value={...task};
   if(c.action==='delivery-discover'){task.state='ready';task.result={hosts:['example-com.mail.protection.outlook.com']};}
   else{tests++;task.state=tests===1?'failed':'ready';task.error='Synthetic TLS test failure';task.result={ok:tests>1,detail:'SMTP greeting and verified TLS succeeded; no email was sent.'};}
  }
  else if(c.action==='delivery-status')value=task;
  else if(c.action==='delivery-save'){
   assert.equal(task.state,'ready');assert.equal(d.confirm,true);assert.equal(d.id,task.id);assert.equal(d.expected_revision,settings.revision);saved++;
   routes={m365:{...task.candidate,tls:true,source:'wizard'}};settings.revision++;task.state='saved';value={id:'m365',route:routes.m365,revision:settings.revision};
  }else throw Error('Unexpected '+c.action);
 }
 if(value!==undefined){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(value));return;}
 const files={'/mail-security':'security/index.html','/delivery.js':'security/delivery.js','/microsoft365.js':'security/microsoft365.js','/security.js':'security/security.js','/security.css':'security/security.css'};
 if(files[url.pathname]){res.writeHead(200,{'content-type':url.pathname.endsWith('.js')?'text/javascript':url.pathname.endsWith('.css')?'text/css':'text/html'});res.end(fs.readFileSync(path.join(root,files[url.pathname])));}else{res.writeHead(404);res.end();}
});
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const b=await chromium.launch({headless:true,executablePath:process.env.WORKGLEN_CHROMIUM,args:['--no-sandbox','--single-process','--no-zygote']});
 try{
  const p=await b.newPage({viewport:{width:1280,height:900}}),errors=[];p.on('pageerror',e=>errors.push(e.message));p.on('dialog',d=>d.accept());
  await p.goto('http://127.0.0.1:'+server.address().port+'/mail-security');await p.getByRole('heading',{name:'Operations',exact:true}).waitFor();await p.getByRole('button',{name:'Setup',exact:true}).click();
  await p.getByLabel('Accepted domains',{exact:true}).fill('example.test');assert(await p.getByLabel('Default delivery destination',{exact:true}).isDisabled());
  await p.getByRole('button',{name:'Save and continue',exact:true}).click();await p.locator('#notice').filter({hasText:'Add, test and save a delivery destination'}).waitFor();assert.equal(await p.getByRole('heading',{name:'Recipients',exact:true}).count(),0);pass('empty install explains missing destination and prevents premature advance');
  await p.getByRole('button',{name:'Find Microsoft 365 hostname',exact:true}).click();await p.getByText('Microsoft 365 hostname found.',{exact:false}).waitFor();assert.equal(await p.getByLabel('Delivery hostname',{exact:true}).inputValue(),'example-com.mail.protection.outlook.com');pass('Microsoft MX discovery fills a reviewable hostname');
  await p.getByRole('button',{name:'Test connection',exact:true}).click();await p.getByText('Check did not succeed.',{exact:false}).waitFor();assert(await p.getByRole('button',{name:'Save destination',exact:true}).isDisabled());assert.equal(saved,0);assert.equal(await p.getByLabel('Delivery hostname',{exact:true}).inputValue(),'example-com.mail.protection.outlook.com');pass('failed test retains inputs, explains outbound SMTP and prevents save');
  await p.getByRole('button',{name:'Test connection',exact:true}).click();await p.getByText('Connection verified.',{exact:false}).waitFor();await p.getByRole('button',{name:'Save destination',exact:true}).click();await p.getByText('Destination saved.',{exact:false}).waitFor();assert.equal(saved,1);assert.equal(await p.getByLabel('Default delivery destination',{exact:true}).inputValue(),'m365');pass('successful test saves and selects a destination without JSON editing');
  if(process.argv[2])await p.screenshot({path:path.join(path.dirname(process.argv[2]),'destination-wizard.png'),fullPage:true});
  await p.getByRole('button',{name:'Save and continue',exact:true}).click();await p.getByRole('heading',{name:'Recipients',exact:true}).waitFor();await p.getByLabel('Accepted mailbox addresses',{exact:true}).fill('person@example.test');
  await p.getByRole('button',{name:'Back',exact:true}).click();await p.getByLabel('Accepted domains',{exact:true}).waitFor();await p.getByRole('button',{name:'Save and continue',exact:true}).click();assert.equal(await p.getByLabel('Accepted mailbox addresses',{exact:true}).inputValue(),'person@example.test');pass('recipient draft survives returning to Mail flow');
  await p.getByRole('button',{name:'Save and continue',exact:true}).click();await p.getByRole('heading',{name:'Detection',exact:true}).waitFor();assert.equal(settings.routes['example.test'],'m365');assert(settings.mailboxes['person@example.test']);pass('domain destination and recipient save together and continue to Detection');
  await p.getByRole('button',{name:'Back',exact:true}).click();await p.getByRole('button',{name:'Back',exact:true}).click();await p.setViewportSize({width:390,height:844});await p.getByText('Add a delivery destination',{exact:true}).click();assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));pass('guided destination setup fits a narrow viewport');
  assert.deepEqual(errors,[]);pass('no browser script errors');if(process.argv[2])fs.writeFileSync(process.argv[2],JSON.stringify({passed:checks.length,checks},null,2));
 }finally{await b.close();server.close();}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
