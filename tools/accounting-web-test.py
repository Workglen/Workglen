#!/usr/bin/env python3
"""Loopback HTTPS accounting/API/browser fixture. PostgreSQL must be disposable.
Use an existing empty database or start a local JavaScript fixture; never calls bank providers.
"""
import argparse,subprocess,os,pathlib,json,socket,time,ssl,urllib.request,http.cookiejar,base64
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--pg-server');p.add_argument('--pg-dsn-file');p.add_argument('--pg-ca',required=True);p.add_argument('--work',required=True);a=p.parse_args();root=pathlib.Path(a.work).resolve();root.mkdir(parents=True,exist_ok=True);os.chmod(root,0o700);binary=str(pathlib.Path(a.binary).resolve());src=pathlib.Path(__file__).resolve().parents[1]
if not a.pg_server and not a.pg_dsn_file:p.error('provide --pg-dsn-file for an empty disposable database, or --pg-server for a local fixture')
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def run(*args,input=None):return subprocess.run(args,input=input,check=True,capture_output=True).stdout
cert=root/'cert.pem';key=root/'key.pem';run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1');key.chmod(0o600)
password='accounting-test-password';secret_files={'token':'a'*64,'relay':'b'*64,'feed.key':base64.b64encode(os.urandom(32)).decode(),'dsn':pathlib.Path(a.pg_dsn_file).read_text().strip() if a.pg_dsn_file else 'host=localhost port=55431 user=postgres dbname=postgres','admin.hash':run(binary,'hash-password',input=password.encode()).decode().strip()}
for name,value in secret_files.items():f=root/name;f.write_text(value);f.chmod(0o600)
web=port();url=f'https://localhost:{web}';cfg=src.joinpath('config/single.toml').read_text();cfg=cfg.replace('replace-with-a-unique-cluster-id','test-accounting-0001').replace('mail.example.com','localhost').replace('example.com','example.test').replace('/var/lib/workglen',str(root/'data')).replace('/etc/workglen/fullchain.pem',str(cert)).replace('/etc/workglen/privkey.pem',str(key)).replace('/etc/workglen/admin.token',str(root/'token')).replace('/etc/workglen/relay.password',str(root/'relay'))
for original in ['0.0.0.0:25','0.0.0.0:465','0.0.0.0:993','127.0.0.1:8025']:cfg=cfg.replace(original,'127.0.0.1:'+str(port()))
cfg+=f'\n[web]\nlisten="127.0.0.1:{web}"\norigin="{url}"\nusername="admin"\npassword_hash_file="{root}/admin.hash"\n\n[accounting]\ndsn_file="{root}/dsn"\nca_file="{pathlib.Path(a.pg_ca).resolve()}"\npool_size=1\nfeed_key_file="{root}/feed.key"\n';config=root/'node.toml';config.write_text(cfg)
pg=None;server=None;log=None
try:
 if a.pg_server:
  pg=subprocess.Popen([os.environ.get('CODEX_PRIMARY_RUNTIME_NODE','node'),str(pathlib.Path(a.pg_server).resolve())],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  assert 'ready' in pg.stdout.readline()
 run(binary,'init',str(config),'--bootstrap');run(binary,'accounting-init',str(config));log=open(root/'node.log','w');server=subprocess.Popen([binary,'serve',str(config)],stdout=log,stderr=subprocess.STDOUT)
 context=ssl.create_default_context(cafile=str(cert));opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf=None
 def api(path,data=None,token=True):
  headers={'Origin':url};
  if data is not None:headers['Content-Type']='application/json'
  if token and csrf:headers['X-CSRF-Token']=csrf
  r=opener.open(urllib.request.Request(url+'/api/'+path,data=None if data is None else json.dumps(data).encode(),headers=headers),timeout=30);return json.load(r)
 for i in range(100):
  try:csrf=api('login',{'username':'admin','password':password})['csrf'];break
  except Exception:time.sleep(.1)
 else:raise RuntimeError('server did not start: '+(root/'node.log').read_text())
 checks=[]
 def check(n,v):assert v,n;checks.append(n);print('PASS',n,flush=True)
 try:api('accounting',{'action':'books'},token=False);raise AssertionError('missing CSRF accepted')
 except urllib.error.HTTPError as e:check('Accounting requires CSRF',e.code==403)
 try:api('accounting',{'action':'books'});raise AssertionError('disabled Accounting accepted')
 except urllib.error.HTTPError as e:check('disabled Accounting blocks commands',e.code==400)
 fixture={'url':url,'password':password,'work':str(root),'bundle':str(src/'examples/accounting/xero-cutover.json')};f=root/'browser.json';f.write_text(json.dumps(fixture));env=dict(os.environ);subprocess.run([env.get('CODEX_PRIMARY_RUNTIME_NODE','node'),str(src/'tools/accounting-browser.cjs'),str(f)],check=True,env=env)
 # Host validation happens before an outbound request; fake URL is never contacted.
 try:api('accounting',{'action':'feed-connect','book_id':'browser','data':{'id':'bad-token','name':'Test','setup_token':base64.b64encode(b'http://127.0.0.1/simplefin/claim/x').decode()}});raise AssertionError('unsafe endpoint accepted')
 except urllib.error.HTTPError as e:check('SimpleFIN rejects non-provider insecure destination',e.code==400)
 status=api('accounting',{'action':'status'});check('Accounting ready after browser lifecycle',status['enabled'])
 # Named users enforce correction and period permissions independently of UI controls.
 for name,role in [('accountant','accountant'),('viewer','accounting_viewer'),('controller','accounting_admin')]:
  run(binary,'access-set',str(config),input=json.dumps({'username':name,'roles':[role],'books':['browser'],'enabled':True,'expected_revision':None,'password':password}).encode())
 subprocess.run([env.get('CODEX_PRIMARY_RUNTIME_NODE','node'),str(src/'tools/rbac-browser.cjs'),str(f)],check=True,env=env)
 api('logout',{})
 csrf=api('login',{'username':'accountant','password':password})['csrf']
 check('accountant sees assigned books only', [b['id'] for b in api('accounting',{'action':'books'})]==['browser'])
 for command,label in [({'action':'reopen-period','book_id':'browser','data':{'date':None,'expected_lock_date':'2026-09-30','reason':'not authorized'}},'ordinary accountant cannot reopen periods'),({'action':'journals','book_id':'migration'},'cross-book posting access denied')]:
  try:api('accounting',command);raise AssertionError(label)
  except urllib.error.HTTPError as e:check(label,e.code==403)
 journals=api('accounting',{'action':'journals','book_id':'browser'})['rows'];j=next(j for j in journals if j['description']=='UI adjustment')
 data={'journal_id':j['id'],'request_id':'api-correction','expected_revision':j['revision'],'date':'2026-10-25','description':'Accountant correction','lines':[{'account':'1000','debit':'16','credit':'0'},{'account':'4000','debit':'0','credit':'16'}]}
 check('assigned accountant can edit ordinary postings',api('accounting',{'action':'edit-journal','book_id':'browser','data':data})['revision']==1)
 history=api('accounting',{'action':'journal','book_id':'browser','data':{'journal_id':j['id']}})['history']
 check('audit retains named external actor',any(a['actor']=='web:accountant' and a['action']=='edit-journal' for a in history))
 api('logout',{});csrf=api('login',{'username':'viewer','password':password})['csrf']
 try:api('accounting',{'action':'edit-journal','book_id':'browser','data':data});raise AssertionError('read only edit accepted')
 except urllib.error.HTTPError as e:check('read-only users cannot correct postings',e.code==403)
 api('logout',{});csrf=api('login',{'username':'controller','password':password})['csrf']
 check('assigned accounting administrator can reopen periods',api('accounting',{'action':'reopen-period','book_id':'browser','data':{'date':None,'expected_lock_date':'2026-09-30','reason':'Controller approval'}})['lock_date'] is None)
 out=run(binary,'accounting',str(config),'-',input=json.dumps({'action':'books'}).encode());check('CLI sees browser-created books',len(json.loads(out))==2)
 root.joinpath('accounting-api-results.json').write_text(json.dumps({'passed':len(checks),'checks':checks},indent=2))
finally:
 if server:server.terminate();server.wait(timeout=15)
 if pg:pg.terminate();pg.wait(timeout=15)
 if log:log.close()
