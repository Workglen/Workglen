'use strict';
// No network or browser dependencies: validate the exact production plan builder.
const assert = require('node:assert/strict');
const {microsoft365Plan: plan, microsoft365Routes: routes} = require('../../web/security/microsoft365.js');
let passed=0;
const test=(name,fn)=>{fn();passed++;console.log('PASS '+name);};
test('selected Microsoft routes are grouped; unused and lookalike hosts are excluded',()=>{
 const settings={domains:['one.test','two.test','other.test','fake.test'],routes:{'one.test':'m','two.test':'m','other.test':'smtp','fake.test':'fake'}};
 const found=routes(settings,{m:{host:'TENANT.mail.protection.outlook.com.',label:'Microsoft'},smtp:{host:'smtp.other.test'},fake:{host:'tenant.mail.protection.outlook.com.evil.test'},unused:{host:'unused.mail.protection.outlook.com'}});
 assert.deepEqual(found,[{id:'m',host:'tenant.mail.protection.outlook.com',label:'Microsoft',domains:['one.test','two.test']}]);
 assert.deepEqual(routes({domains:['one.test'],routes:{}},{}),[]);
});
test('new connector is Partner, wildcard, TLS required and initially disabled',()=>{
 const p=plan('Workglen gateway only','8.8.8.8\n8.8.4.4,8.8.8.8');
 assert.deepEqual(p.ips,['8.8.8.8','8.8.4.4']);
 for(const token of ['-ConnectorType Partner',"-SenderDomains '*'","-SenderIPAddresses @('8.8.8.8', '8.8.4.4')",'-RestrictDomainsToIPAddresses $true','-RequireTls $true','-TreatMessagesAsInternal $false','-Enabled $false','-ErrorAction Stop'])assert(p.stage.includes(token));
 assert(!p.stage.includes('-Enabled $true'));
 assert(p.activate.includes('-Enabled $true'));assert(p.rollback.includes('-Enabled $false'));
});
test('Enhanced Filtering trusts exact gateway IPs and retains Microsoft scanning',()=>{
 const p=plan('Workglen-1','8.8.8.8');
 assert(p.filtering.includes("-EFSkipIPs @('8.8.8.8')"));
 assert(p.filtering.includes('-EFSkipLastIP $false'));assert(p.filtering.includes('-EFUsers $null'));
 assert(!Object.values(p).some(v=>typeof v==='string'&&/SetSCL\s+-1|TreatMessagesAsInternal \$true/.test(v)));
});
test('private, reserved, malformed and range inputs are rejected',()=>{
 for(const value of ['', '0.0.0.0','10.1.2.3','127.0.0.1','169.254.1.2','172.16.0.1','172.31.255.255','192.168.1.1','100.64.0.1','100.127.255.254','192.0.0.1','192.0.2.1','192.88.99.1','198.18.0.1','198.19.0.1','198.51.100.2','203.0.113.2','224.0.0.1','240.0.0.1','255.255.255.255','8.8.8.256','999.1.1.1','8.8.8','01.2.3.4','1.2.3.-1','1.2.3.4.5','8.8.8.8/32','8.8.8.0/24','::1','2001:4860:4860::8888','gateway.example.test','8.8.8.8;Remove-InboundConnector','8.8.8.8\u0000',"8.8.8.8'",'8.8.8.8\n#bad'])assert.throws(()=>plan('Workglen',value),undefined,value);
});
test('no connector name can inject PowerShell or exceed bounds',()=>{
 for(const name of ['', 'a'.repeat(65),"x'; Remove-InboundConnector x; '",'$(whoami)','x`nWrite-Host','x\nDisable-Mailbox','évil','-flag'])assert.throws(()=>plan(name,'8.8.8.8'));
 assert.equal(plan('a'.repeat(64),'8.8.8.8').name.length,64);
 assert.throws(()=>plan('Workglen',Array.from({length:17},(_,i)=>'8.8.4.'+(i+1)).join('\n')));
 assert.throws(()=>plan('Workglen',' '.repeat(1025)));
});
test('valid boundaries outside private ranges remain usable',()=>{
 assert.equal(plan('Gateway_1.2 - standby','172.15.1.1 172.32.1.1 100.63.1.1 100.128.1.1').ips.length,4);
});
console.log(JSON.stringify({passed,scope:'Local generation only; no Microsoft tenant or SMTP calls'}));
