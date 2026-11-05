'use strict';
// Synthetic browser fixture for the cluster operations, receive, quarantine, and delivery views.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../../web'),commands=[],now=Math.floor(Date.now()/1000);
const status=id=>{const other=id==='a'?'b':'a';return {instance:id,at:now,enabled:true,active:1,messages:{quarantined:1},jobs:{queued:1,uncertain:1},bytes:2048,storage_encryption:{enabled:true},storage_host:{available_bytes:8*1024*1024*1024,minimum_free_bytes:256*1024*1024,state:'healthy',admission:'fail-closed'},scanner:{receive_records:1,oldest_pending_seconds:id==='a'?120:240,active:1,configured_workers:2},delivery:{active:1,configured_workers:4},capacity:{bytes:{used:1024,limit:1048576}},cluster:{node_id:id,health:'peer-transport',accepting:true,scanner_eligible:true,delivery_eligible:true,synchronized:true,topology:'authenticated-peer-log',node_mode:{mode:'active',acceptance_eligible:true,scanner_eligible:true,delivery_eligible:true},partitions:[{partition:id,owner:id,term:1,state:'stable'},{partition:other,owner:other,term:1,state:'stable'}],owned_partitions:[{partition:id,owner:id,term:1,state:'stable'}],peers:[{node_id:other,lag_operations:0,state_lag_operations:0}],replication_debt:{operations:0,bytes:0},state_replication_debt:{operations:0,bytes:0}}};};
const message=id=>({id:'message-'+id,recipient:'owner@example.test',arrived:now-60,state:'quarantined',revision:1,subject:'Synthetic review '+id,sender:'sender@example.invalid',releasable:true,expires:now+86400,hold:false,rule_version:1,origin_node:id,scan_owner:id,delivery_owner:id,decision:'quarantine',coverage_complete:true,reasons:['Synthetic spam signal']});
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://localhost');let value;
 if(url.pathname==='/api/session')value={username:'admin',csrf:'test',permissions:['security.read','security.content','security.release','security.discard','security.jobs','security.retention','security.rules.test','security.configure','security.cluster.operate','security.cluster.takeover'],security_domains:['*'],security_mailboxes:['*']};
 else if(url.pathname==='/api/security/remotes')value=[{id:'a',label:'Gateway A'},{id:'b',label:'Gateway B'}];
 else if(url.pathname==='/api/security'){
  let text='';for await(const part of req)text+=part;const request=JSON.parse(text),id=request.instance,command=request.command,data=command.data;commands.push({id,action:command.action,data});
  if(command.action==='status')value=status(id);
  else if(command.action==='ingress')value={instance:id,records:[{id:'ingress-'+id,state:'queued',arrived:now-(id==='a'?120:240),due:now,attempts:0,lease_until:0,error:'',sender:'sender@example.invalid',recipients:['owner@example.test'],rule_version:1,api_version:1,profile_version:1,coverage_version:1,origin_node:id,scan_owner:id,scan_generation:1,delivery_owner:id,delivery_partition:id,replication:'tracked'}],totals:{queued:1},total_recipients:1,limit:100,next_cursor:null};
  else if(command.action==='messages')value={instance:id,messages:[message(id)],totals:{quarantined:1},limit:100,next_cursor:null};
  else if(command.action==='message-detail')value={instance:id,message:message(id),verdict:{action:'quarantine',coverage:{complete:true},matches:[{reason:'Synthetic spam signal'}]},evidence:{engine:'synthetic'},route:'mail',jobs:[],events:[{seq:1,at:now-55,action:'scan-complete'}]};
  else if(command.action==='content')value={id:data.id,text:'Inert synthetic text',rendering:'inert text only'};
  else if(command.action==='jobs')value={instance:id,jobs:[{id:'job-'+id,kind:'delivery',state:'uncertain',due:now-30,attempts:1,error:'Synthetic uncertain acknowledgement',recipient:'owner@example.test',message:'message-'+id,plan:null,released:false,route:'mail',delivery_partition:id,delivery_owner:id,delivery_term:1}],totals:{queued:1,uncertain:1},limit:100,next_cursor:null};
  else if(command.action==='setup')value={settings:{revision:1}};
  else if(command.action==='configure')value={revision:2};
  else if(['cluster-drain','cluster-handoff','cluster-resync','cluster-rejoin','cluster-takeover'].includes(command.action))value={ok:true};
  else if(['release','discard','hold','reevaluate','job-retry','job-cancel'].includes(command.action))value={state:'queued'};
  else throw Error('Unexpected command '+command.action);
 }
 if(value!==undefined){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(value));return;}
 const files={'/mail-security':'security/index.html','/delivery.js':'security/delivery.js','/microsoft365.js':'security/microsoft365.js','/security.js':'security/security.js','/security.css':'security/security.css'};
 if(files[url.pathname]){res.writeHead(200,{'content-type':url.pathname.endsWith('.js')?'text/javascript':url.pathname.endsWith('.css')?'text/css':'text/html'});res.end(fs.readFileSync(path.join(root,files[url.pathname])));}else{res.writeHead(404);res.end();}
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 if(process.env.WORKGLEN_UI_SERVE){console.log('OPERATIONS_UI_URL=http://127.0.0.1:'+server.address().port+'/mail-security');return;}
 const {chromium}=require('playwright');
 const browser=await chromium.launch({headless:true,executablePath:process.env.WORKGLEN_CHROMIUM,args:['--no-sandbox','--single-process','--no-zygote']});
 try{
  const page=await browser.newPage({viewport:{width:1280,height:900}}),errors=[];page.on('pageerror',error=>errors.push(error.message));page.on('dialog',dialog=>dialog.accept());
  await page.goto('http://127.0.0.1:'+server.address().port+'/mail-security');await page.getByRole('heading',{name:'Operations',exact:true}).waitFor();
  assert.equal(await page.locator('.storage-state.good').count(),2);await page.getByRole('button',{name:'Drain selected node',exact:true}).click();await page.getByRole('checkbox',{name:/pauses new acceptance/}).check();await page.getByRole('button',{name:'Begin drain',exact:true}).click();await page.getByRole('heading',{name:'Operations',exact:true}).waitFor();const drain=commands.find(command=>command.action==='cluster-drain');assert.deepEqual(drain,{id:'a',action:'cluster-drain',data:{partition:'a',new_owner:'b',expected_term:1,confirm:true}});
  await page.getByRole('button',{name:'Resynchronize peer',exact:true}).click();await page.getByRole('checkbox',{name:/acceptance pauses/}).check();await page.getByRole('button',{name:'Start resynchronization',exact:true}).click();await page.getByRole('heading',{name:'Operations',exact:true}).waitFor();assert.equal(commands.filter(command=>command.action==='cluster-resync').length,1);
  await page.getByRole('button',{name:'Forced takeover',exact:true}).click();await page.getByRole('checkbox',{name:/former owner is stopped/}).check();await page.getByRole('checkbox',{name:/incomplete replication/}).check();await page.getByRole('textbox',{name:'Type the confirmation phrase'}).fill('TAKE OVER b');await page.getByRole('button',{name:'Force takeover',exact:true}).click();await page.getByRole('heading',{name:'Operations',exact:true}).waitFor();const takeover=commands.find(command=>command.action==='cluster-takeover');assert.deepEqual(takeover,{id:'a',action:'cluster-takeover',data:{partition:'b',expected_owner:'b',expected_term:1,confirm:true,old_owner_fenced:true,acknowledge_incomplete_replication:true}});
  await page.getByRole('button',{name:'Receive',exact:true}).click();await page.getByText('ingress-a',{exact:false}).waitFor();await page.getByText('ingress-b',{exact:false}).waitFor();
  await page.getByRole('button',{name:'Quarantine',exact:true}).click();await page.getByText('Synthetic review a',{exact:false}).waitFor();await page.getByRole('button',{name:'Review journey'}).first().click();await page.locator('#journey').waitFor();await page.getByText('Detection evidence and coverage',{exact:true}).waitFor();await page.locator('#close-journey').click();
  const choices=page.locator('.queue-table tbody input[type=checkbox]');assert.equal(await choices.count(),2);await choices.nth(0).check();await choices.nth(1).check();await page.getByRole('button',{name:'Release selected',exact:true}).click();assert.equal(commands.filter(command=>command.action==='release').length,2);assert.deepEqual(commands.filter(command=>command.action==='release').map(command=>command.id).sort(),['a','b']);
  await page.getByRole('button',{name:'Jobs',exact:true}).click();await page.getByText('Uncertain means the remote system may already have accepted',{exact:false}).waitFor();await page.getByRole('button',{name:'Retry',exact:true}).first().click();assert.equal(commands.filter(command=>command.action==='job-retry').length,1);
  await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));assert.deepEqual(errors,[]);
  console.log('PASS operations UI cluster controls, storage reserve, queues, journey, node-routed actions, and mobile layout');
 }finally{await browser.close();server.close();}
})().catch(error=>{console.error(error);server.close();process.exitCode=1;});
