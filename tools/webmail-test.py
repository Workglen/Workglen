#!/usr/bin/env python3
"""Disposable loopback Webmail API, MIME, IMAP, lifecycle and browser checks."""
import argparse,base64,http.client,imaplib,json,os,pathlib,socket,ssl,subprocess,time
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--work',required=True);p.add_argument('--browser',action='store_true');a=p.parse_args()
root=pathlib.Path(a.work).resolve();root.mkdir(parents=True,exist_ok=True);root.chmod(0o700);src=pathlib.Path(__file__).resolve().parents[1];binary=str(pathlib.Path(a.binary).resolve());checks=[]
def run(*args,input=None):return subprocess.run(args,input=input,check=True,capture_output=True).stdout
def check(n,v=True):assert v,n;checks.append(n);print('PASS',n,flush=True)
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
cert=root/'cert.pem';key=root/'key.pem';run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1');key.chmod(0o600)
for name in ['token','relay']:(root/name).write_text('test-only-'+'a'*64);(root/name).chmod(0o600)
password='webmail-fixture-password';imap=port();mail=port();smtp=port();url=f'https://localhost:{mail}';cfg=src.joinpath('config/single.toml').read_text().replace('replace-with-a-unique-cluster-id','webmail-fixture-0001').replace('mail.example.com','localhost').replace('example.com','example.test').replace('/var/lib/workglen',str(root/'data')).replace('/etc/workglen/fullchain.pem',str(cert)).replace('/etc/workglen/privkey.pem',str(key)).replace('/etc/workglen/admin.token',str(root/'token')).replace('/etc/workglen/relay.password',str(root/'relay'))
# Outbound integration is covered separately. Refuse remote connections in this fixture.
start=cfg.index('[relay]');end=cfg.index('\n[',start+1) if '\n[' in cfg[start+1:] else len(cfg);cfg=cfg[:start]+cfg[end:]
for old,new in [('0.0.0.0:25',port()),('0.0.0.0:465',smtp),('0.0.0.0:993',imap),('127.0.0.1:8025',port())]:cfg=cfg.replace(old,'127.0.0.1:'+str(new))
cfg+=f'\n[webmail]\nlisten="127.0.0.1:{mail}"\norigin="{url}"\n\n[dkim]\nselector="webtest"\nkey_file="{root}/dkim.pem"\n';config=root/'node.toml';config.write_text(cfg);run(binary,'dkim-generate',str(config));run(binary,'init',str(config),'--bootstrap')
for user in ['alice','bob']:run(binary,'add-user-offline',str(config),user+'@example.test',input=password.encode())
smallconfig=root/'small.toml';smallconfig.write_text(cfg.replace('quota_bytes = 1073741824','quota_bytes = 2000'));run(binary,'add-user-offline',str(smallconfig),'small@example.test',input=password.encode())
ctx=ssl.create_default_context(cafile=str(cert));server=None
class Client:
 def __init__(self):self.cookie=None;self.csrf=None
 def call(self,path='/api/mail',data=None,csrf=True,origin=None,host=None):
  headers={'Origin':origin or url}
  if self.cookie:headers['Cookie']=self.cookie
  if data is not None:headers['Content-Type']='application/json'
  if csrf and self.csrf:headers['X-CSRF-Token']=self.csrf
  if host:headers['Host']=host
  c=http.client.HTTPSConnection('localhost',mail,context=ctx,timeout=30);c.request('POST' if data is not None else 'GET',path,body=None if data is None else json.dumps(data),headers=headers);r=c.getresponse();raw=r.read();h={k.lower():v for k,v in r.getheaders()};status=r.status;c.close()
  if 'set-cookie' in h:self.cookie=h['set-cookie'].split(';')[0]
  try:value=json.loads(raw)
  except Exception:value=raw
  return status,value,h
 def login(self,user='alice'):
  status,v,h=self.call('/api/login',{'username':user+'@example.test','password':password});assert status==200,(status,v);self.csrf=v['csrf'];return h
 def api(self,action,**kw):
  status,v,_=self.call(data={'action':action,**kw});assert status==200,(action,status,v);return v
try:
 log=open(root/'node.log','w');server=subprocess.Popen([binary,'serve',str(config)],stdout=log,stderr=subprocess.STDOUT)
 for i in range(100):
  try:
   if Client().call('/')[0]==200:break
  except OSError:pass
  time.sleep(.1)
 else:raise RuntimeError('No HTTPS listener')
 c=Client();check('Webmail is disabled by default',c.call('/api/login',{'username':'alice@example.test','password':password})[0]==503)
 run(binary,'module-enable',str(config),'webmail');check('Webmail enables independently',json.loads(run(binary,'modules',str(config)))['state']['webmail_enabled'])
 check('Mailbox API requires its own session',c.call(data={'action':'folders'})[0]==401)
 c.cookie='__Host-workglen_session='+'a'*64;check('Administrator cookie is not a mailbox session',c.call(data={'action':'folders'})[0]==401);c.cookie=None
 h=c.login();check('Mailbox cookie is secure and protected',all(v in h['set-cookie'] for v in ['HttpOnly','Secure','SameSite=Strict','Path=/']))
 check('Webmail enforces Origin',c.call(data={'action':'folders'},origin='https://wrong.test')[0]==403)
 check('Webmail enforces Host',c.call(data={'action':'folders'},host='wrong.test')[0]==421)
 check('Webmail enforces CSRF on mailbox actions',c.call(data={'action':'folders'},csrf=False)[0]==403)
 check('Mailbox session cannot reach administration APIs',c.call('/api/users')[0]==404)
 check('Folders are scoped to authenticated mailbox',len(c.api('folders'))==5)
 draft={'id':'a'*32,'to':['alice@example.test','bob@example.test'],'cc':[],'bcc':[],'subject':'Unicode résumé ☕','text':'Hello Alice and Bob.\nA small test.','attachments':[{'name':'résumé.txt','data':base64.b64encode(b'Attachment\x00content').decode()}],'reply':None}
 sent=c.api('send',draft=draft);check('One send stores local mail and Sent atomically',len(c.api('list',folder='INBOX')['messages'])==1 and len(c.api('list',folder='Sent')['messages'])==1)
 check('Lost-response retry returns the same receipt',c.api('send',draft=draft)==sent and len(c.api('list',folder='Sent')['messages'])==1)
 check('Changed replay is rejected',c.call(data={'action':'send','draft':{**draft,'subject':'changed'}})[0]==400)
 listing=c.api('list',folder='INBOX');ref={'folder':'INBOX','validity':listing['validity'],'uid':listing['messages'][0]['uid']};read=c.api('read',message=ref);check('Unicode text and attachment name survive MIME',read['subject']==draft['subject'] and read['attachments'][0]['name']=='résumé.txt' and 'Hello Alice' in read['text'])
 status,raw,h=c.call(data={'action':'attachment','message':ref,'index':0});check('Attachments download as inert binary',status==200 and raw==b'Attachment\x00content' and h['content-type']=='application/octet-stream' and 'attachment' in h['content-disposition'])
 check('Stale UIDVALIDITY is rejected',c.call(data={'action':'read','message':{**ref,'validity':1}})[0]==400)
 check('Caller cannot choose another mailbox',c.call(data={'action':'list','folder':'INBOX','user':'bob@example.test'})[0]==400)
 check('Folder traversal is rejected',c.call(data={'action':'list','folder':'../bob@example.test/INBOX'})[0]==400)
 c.api('flag',message=ref,seen=True,starred=True);check('Seen and star flags persist',set(c.api('read',message=ref)['flags'])=={'\\Seen','\\Flagged'})
 c.api('move',message=ref,target='Trash');check('Move to Trash preserves body and clears old UID',not c.api('list',folder='INBOX')['messages'] and len(c.api('list',folder='Trash')['messages'])==1)
 trash=c.api('list',folder='Trash');c.api('move',message={'folder':'Trash','validity':trash['validity'],'uid':trash['messages'][0]['uid']},target='INBOX');check('Trash can be restored',len(c.api('list',folder='INBOX')['messages'])==1)
 b=Client();b.login('bob');check('Other recipient receives its own copy',len(b.api('list',folder='INBOX')['messages'])==1 and not b.api('list',folder='Sent')['messages'])
 bad={**draft,'id':'b'*32,'to':['missing@example.test']};check('Invalid recipient rolls back Sent and all delivery',c.call(data={'action':'send','draft':bad})[0]==400 and len(c.api('list',folder='Sent')['messages'])==1)
 check('Unconfigured outbound delivery refuses before acceptance',c.call(data={'action':'send','draft':{**bad,'to':['outside@example.invalid']}})[0]==400)
 check('Header injection refuses before storage',c.call(data={'action':'send','draft':{**bad,'to':['bob@example.test'],'subject':'hello\r\nBcc: injected@example.test'}})[0]==400)
 small=Client();small.login('small');check('Self-delivery counts both Inbox and Sent against quota',small.call(data={'action':'send','draft':{**draft,'id':'c'*32,'to':['small@example.test'],'attachments':[],'text':'x'*500}})[0]==400 and not small.api('list',folder='INBOX')['messages'] and not small.api('list',folder='Sent')['messages'])
 # Read actual stored MIME through independent IMAP client.
 with imaplib.IMAP4_SSL('localhost',imap,ssl_context=ctx) as im:
  im.login('alice@example.test',password);im.select('Sent');raw=im.fetch('1','(RFC822)')[1][0][1];check('Webmail sends DKIM-signed MIME through shared storage',raw.startswith(b'DKIM-Signature:') and b'd=example.test' in raw)
  hostile=b'From: bob@example.test\r\nTo: alice@example.test\r\nSubject: Browser hostile HTML\r\nDate: Fri, 23 Oct 2026 12:00:00 +0000\r\nMessage-ID: <hostile@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Safe visible words</p><img src="https://remote.invalid/pixel"><script>alert(1)</script>\r\n';im.append('INBOX',None,None,hostile)
 with imaplib.IMAP4_SSL('localhost',imap,ssl_context=ctx) as im:
  im.login('bob@example.test',password)
  for i in range(27):im.append('INBOX',None,None,hostile.replace(b'Browser hostile HTML',f'Pagination {i}'.encode()))
 page1=b.api('list',folder='INBOX');page2=b.api('list',folder='INBOX',before=page1['next']);check('Bounded pagination has no overlapping messages',len(page1['messages'])==25 and len(page2['messages'])==3 and not ({m['uid'] for m in page1['messages']}&{m['uid'] for m in page2['messages']}))
 if a.browser:
  manifest=root/'browser.json';manifest.write_text(json.dumps({'url':url,'password':password,'work':str(root)}));subprocess.run([os.environ.get('CODEX_PRIMARY_RUNTIME_NODE','node'),str(src/'tools/webmail-browser.cjs'),str(manifest)],check=True)
 run(binary,'module-disable',str(config),'webmail');check('Disabling Webmail blocks existing sessions',c.call(data={'action':'folders'})[0]==503)
 with imaplib.IMAP4_SSL('localhost',imap,ssl_context=ctx) as im:check('Mail remains available when Webmail is disabled',im.login('alice@example.test',password)[0]=='OK')
 run(binary,'module-enable',str(config),'webmail');run(binary,'module-disable',str(config),'mail');check('Disabling Mail also pauses Webmail',c.call(data={'action':'folders'})[0]==503);run(binary,'module-enable',str(config),'mail')
 check('Module lifecycle retains mailbox data',len(c.api('list',folder='Sent')['messages'])>=1)
 run(binary,'set-password',str(config),'alice@example.test',input=b'new-fixture-password');check('Password reset revokes Webmail session',c.call(data={'action':'folders'})[0]==401)
 check('Logout invalidates Bob session',b.call('/api/logout',{})[0]==200 and b.call('/api/session')[0]==401)
 root.joinpath('webmail-results.json').write_text(json.dumps({'passed':len(checks),'checks':checks},indent=2))
finally:
 if server:server.terminate();server.wait(timeout=15)
