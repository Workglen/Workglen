#!/usr/bin/env python3
"""Loopback-only integration test. Requires Python 3, OpenSSL, and a built Workglen Mail.
Creates temporary certificates, a DNS fixture server, SMTP relay, witness and two nodes.
Never sends mail to a real host. Keeps logs under --work for inspection.
"""
import argparse, base64, concurrent.futures, hashlib, imaplib, json, os, pathlib, signal, smtplib, socket, socketserver, ssl, struct, subprocess, threading, time
p=argparse.ArgumentParser();p.add_argument('--binary',default='target/release/workglen');p.add_argument('--work',default='/tmp/workglen-integration');p.add_argument('--browser-smoke',action='store_true');a=p.parse_args()
BIN=str(pathlib.Path(a.binary).resolve());ROOT=pathlib.Path(a.work);ROOT.mkdir(parents=True,exist_ok=True);os.chmod(ROOT,0o700)
PROCS=[];LOGS=[];PEAK={};PASS=[];EXPECTED_FENCING=False
def check(name,truth=True):
    assert truth,name
    PASS.append(name);print('PASS',name,flush=True)
def run(*args,input=None):return subprocess.run(args,input=input,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
# Random available local ports; no public listeners or destinations.
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
ports=[port() for _ in range(10)];WIT,RELAY,DNS=ports[:3];N1=ports[3:6]+[ports[9]];N2=ports[6:9]+[port()]
WEB={'node1':port(),'node2':port()}
ADMIN_PASSWORD='test-admin-password-long'
admin_hash=ROOT/'admin.hash';admin_hash.write_bytes(run(BIN,'hash-password',input=ADMIN_PASSWORD.encode()));os.chmod(admin_hash,0o600)
cert=ROOT/'cert.pem';key=ROOT/'key.pem'
run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,DNS:mail.example.test,IP:127.0.0.1')
os.chmod(key,0o600)
for name in ['token','relay-password']:(ROOT/name).write_text('a'*64);os.chmod(ROOT/name,0o600)
ctx=ssl.create_default_context(cafile=str(cert));ctx.minimum_version=ssl.TLSVersion.TLSv1_3
serverctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);serverctx.load_cert_chain(str(cert),str(key))
dkimkey=ROOT/'dkim.key';run('openssl','genrsa','-out',str(dkimkey),'2048');dkimkey.chmod(0o600)
pub=base64.b64encode(run('openssl','pkey','-in',str(dkimkey),'-pubout','-outform','DER')).decode()
RECORDS={'good.test':['v=spf1 ip4:127.0.0.1 -all'],'bad.test':['v=spf1 -all'],'dkim.test':['v=spf1 -all'],'soft.test':['v=spf1 ~all'],'_dmarc.good.test':['v=DMARC1; p=reject; aspf=s'],'_dmarc.bad.test':['v=DMARC1; p=reject; aspf=s'],'_dmarc.dkim.test':['v=DMARC1; p=reject; adkim=s'],'test._domainkey.dkim.test':['v=DKIM1; k=rsa; p='+pub]}
def dns_response(data):
    off=12;labels=[]
    while data[off]:n=data[off];off+=1;labels.append(data[off:off+n].decode().lower());off+=n
    off+=1;name='.'.join(labels);typ,cls=struct.unpack('!HH',data[off:off+4]);question=data[12:off+4];answers=[]
    if name.endswith('temp.test'):return data[:2]+struct.pack('!HHHHH',0x8182,1,0,0,0)+question
    if typ==16:
        for value in RECORDS.get(name,[]):
            b=value.encode();value=b''.join(bytes([len(b[i:i+250])])+b[i:i+250] for i in range(0,len(b),250));answers.append(b'\xc0\x0c'+struct.pack('!HHIH',16,1,0,len(value))+value)
    if typ==1:answers.append(b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+socket.inet_aton('127.0.0.1'))
    return data[:2]+struct.pack('!HHHHH',0x8580,1,len(answers),0,0)+question+b''.join(answers)
class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request
        try:sock.sendto(dns_response(data),self.client_address)
        except Exception:pass
class TCPDNS(socketserver.BaseRequestHandler):
    def handle(self):
        n=struct.unpack('!H',self.request.recv(2))[0];data=b''
        while len(data)<n:data+=self.request.recv(n-len(data))
        r=dns_response(data);self.request.sendall(struct.pack('!H',len(r))+r)
class ThreadTCP(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
servers=[]
for server in [socketserver.ThreadingUDPServer(('127.0.0.1',DNS),UDP),ThreadTCP(('127.0.0.1',DNS),TCPDNS)]:servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start()
DELIVERED=[]
HOLD_RELAY=threading.Event();RELAY_IN_FLIGHT=threading.Event();RELEASE_RELAY=threading.Event();RELEASE_RELAY.set()
class Relay(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with serverctx.wrap_socket(self.request,server_side=True) as s:
                f=s.makefile('rb');s.sendall(b'220 localhost relay\r\n')
                while True:
                    line=f.readline();cmd=line.split(b' ')[0].strip().upper()
                    if not line:break
                    if cmd==b'EHLO':s.sendall(b'250-localhost\r\n250 AUTH PLAIN\r\n')
                    elif cmd==b'AUTH':s.sendall(b'235 authenticated\r\n')
                    elif cmd in [b'MAIL',b'RCPT']:s.sendall(b'250 ok\r\n')
                    elif cmd==b'DATA':
                        s.sendall(b'354 send\r\n');data=[]
                        while True:
                            l=f.readline()
                            if l==b'.\r\n':break
                            if not l:return
                            data.append(l[1:] if l.startswith(b'..') else l)
                        if HOLD_RELAY.is_set():RELAY_IN_FLIGHT.set();RELEASE_RELAY.wait(15)
                        DELIVERED.append(b''.join(data));s.sendall(b'250 queued\r\n')
                    elif cmd==b'QUIT':s.sendall(b'221 bye\r\n');break
                    else:s.sendall(b'500 unsupported\r\n')
        except (OSError,ssl.SSLError):pass
relay=ThreadTCP(('127.0.0.1',RELAY),Relay);servers.append(relay);threading.Thread(target=relay.serve_forever,daemon=True).start()
def config(name,ports,peer,role):
    data=ROOT/name;data.mkdir(exist_ok=True)
    path=ROOT/(name+'.toml')
    mailweb=port()
    path.write_text(f'''hostname = "mail.example.test"
domain = "example.test"
dns_server = "127.0.0.1:{DNS}"
data_dir = "{data}"
admin_listen = "127.0.0.1:{port()}"
admin_token_file = "{ROOT/'token'}"
role = "{role}"
tls_cert = "{cert}"
tls_key = "{key}"
smtp_listen = "127.0.0.1:{ports[0]}"
submission_listen = "127.0.0.1:{ports[1]}"
imap_listen = "127.0.0.1:{ports[2]}"
[limits]
io_seconds = 10
[policy]
quarantine_dmarc = true
[replication]
cluster_id = "workglen-test-cluster-0001"
listen = "127.0.0.1:{ports[3]}"
peer_address = "127.0.0.1:{peer[3]}"
peer_name = "localhost"
ca_file = "{cert}"
token_file = "{ROOT/'token'}"
[witness]
address = "127.0.0.1:{WIT}"
server_name = "localhost"
ca_file = "{cert}"
token_file = "{ROOT/'token'}"
node_id = "{name}"
[dkim]
selector = "outbound"
key_file = "{dkimkey}"
[relay]
address = "127.0.0.1:{RELAY}"
server_name = "localhost"
ca_file = "{cert}"
username = "relay-user"
password_file = "{ROOT/'relay-password'}"
[web]
listen = "127.0.0.1:{WEB[name]}"
origin = "https://localhost:{WEB[name]}"
username = "admin"
password_hash_file = "{admin_hash}"
[webmail]
listen = "127.0.0.1:{mailweb}"
origin = "https://localhost:{mailweb}"
''');return path
C1=config('node1',N1,N2,'primary');C2=config('node2',N2,N1,'standby')
WC=ROOT/'witness.toml';WC.write_text(f'''listen = "127.0.0.1:{WIT}"
tls_cert = "{cert}"
tls_key = "{key}"
token_file = "{ROOT/'token'}"
state_file = "{ROOT/'witness-state'}"
cluster_id = "workglen-test-cluster-0001"
lease_seconds = 12
''')
def start(command,cfg):
    f=open(ROOT/(cfg.stem+'-'+command+'.log'),'ab');LOGS.append(f);p=subprocess.Popen([BIN,command,str(cfg)],stdout=f,stderr=f);PROCS.append(p);return p
def status(c):
    try:return json.loads(run(BIN,'status',str(c)))
    except Exception:return {}
def until(fn,seconds=40):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        sample()
        try:
            if fn():return
        except Exception:pass
        time.sleep(.25)
    raise AssertionError('Timed out waiting for '+str(fn))
def sample():
    for cfg in [C1,C2]:
        st=status(cfg)
        if st.get('peak_rss_kib') is not None:PEAK[cfg.stem]=max(PEAK.get(cfg.stem,0),st['peak_rss_kib'])
PASSWORD='test-password-very-long'
def imap(ports=N1,user='alice@example.test'):
    m=imaplib.IMAP4_SSL('localhost',ports[2],ssl_context=ctx,timeout=15);assert m.login(user,PASSWORD)[0]=='OK';return m
def message(domain='good.test',body=b'Hello from a test.\r\n',subject='fixture'):
    return f'From: Sender <sender@{domain}>\r\nTo: alice@example.test\r\nSubject: {subject}\r\nDate: Fri, 23 Oct 2026 12:00:00 +0000\r\nMessage-ID: <{os.urandom(8).hex()}@{domain}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'.encode()+body

def inbound(raw,from_addr='sender@good.test',ports=N1):
    with smtplib.SMTP('127.0.0.1',ports[0],timeout=30) as s:
        s.ehlo('sender.test');s.mail(from_addr);assert s.rcpt('alice@example.test')[0]==250;return s.data(raw)
def signed():
    raw=message('dkim.test');head,body=raw.split(b'\r\n\r\n',1);headers=head.split(b'\r\n');names=[b'from',b'to',b'subject',b'date',b'message-id']
    signed_headers=b''.join(next(h for h in headers if h.split(b':')[0].lower()==n)+b'\r\n' for n in names)
    d=b'DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=dkim.test; s=test; h=from:to:subject:date:message-id; bh='+base64.b64encode(hashlib.sha256(body).digest())+b'; b='
    sig=run('openssl','dgst','-sha256','-sign',str(dkimkey),input=signed_headers+d)
    return d+base64.b64encode(sig)+b'\r\n'+raw
def single_config(text, node):
    import re
    return f'mode = "single"\nnode_id = "{node}"\n'+re.sub(r'\[witness\]\n.*?(?=\[|\Z)', '', text, flags=re.S).replace('role = "standby"','role = "primary"')
class WebClient:
    def __init__(self,node,source=None):self.source=source;self.port=WEB[node];self.origin=f'https://localhost:{self.port}';self.cookie='';self.csrf=''
    def call(self,path,data=None,origin=True,csrf=True,cookie=True,host=None,extra_headers=None):
        import http.client
        headers={'Host':host or f'localhost:{self.port}'}
        if cookie and self.cookie:headers['Cookie']=self.cookie
        if data is not None:
            headers['Content-Type']='application/json'
            if origin:headers['Origin']=self.origin if origin is True else origin
            if csrf:headers['X-CSRF-Token']=self.csrf
        if extra_headers:headers.update(extra_headers)
        c=http.client.HTTPSConnection('localhost',self.port,context=ctx,timeout=60,source_address=(self.source,0) if self.source else None)
        c.request('GET' if data is None else 'POST',path,body=None if data is None else json.dumps(data),headers=headers)
        r=c.getresponse();payload=r.read();headers={k.title():v for k,v in r.getheaders()};code=r.status;c.close()
        if headers.get('Set-Cookie'):self.cookie=headers['Set-Cookie'].split(';')[0]
        try:value=json.loads(payload)
        except Exception:value=payload.decode()
        return code,value,headers
    def login(self):
        code,v,h=self.call('/api/login',{'username':'admin','password':ADMIN_PASSWORD});assert code==200,(code,v);self.csrf=v['csrf'];return h

def security_review_checks():
    before=sum(u['messages'] for u in json.loads(run(BIN,'users',str(C1))))
    poison=message(body=(b'--X\r\nContent-Type: text/plain\r\n\r\npayload\r\n'*1100)+b'--X--\r\n').replace(b'Content-Type: text/plain; charset=utf-8',b'Content-Type: multipart/mixed; boundary=X')
    check('review F-1: MX rejects MIME boundary flood before delivery',inbound(poison)[0]==550)
    depth=40
    nested=b'From: sender@good.test\r\n'+b''.join(f'Content-Type: multipart/mixed; boundary=b{n}\r\n\r\n--b{n}\r\n'.encode() for n in range(depth))+b'Content-Type: text/plain\r\n\r\nx\r\n'+b''.join(f'--b{n}--\r\n'.encode() for n in reversed(range(depth)))
    check('review F-1: MX also rejects excessive BODYSTRUCTURE nesting',inbound(nested)[0]==550)
    with smtplib.SMTP_SSL('localhost',N1[1],context=ctx,timeout=20) as client:
        client.login('alice@example.test',PASSWORD)
        assert client.mail('alice@example.test')[0]==250
        assert client.rcpt('target@external.test')[0]==250
        raw=poison.replace(b'Sender <sender@good.test>',b'Alice <alice@example.test>')
        check('review F-1: authenticated submission rejects MIME boundary flood',client.data(raw)[0]==550)
    mm=imap();mm.select('INBOX')
    check('review F-1: IMAP APPEND uses the same acceptance guard',mm.append('INBOX',None,None,poison)[0]=='NO')
    check('review F-1: mailbox SEARCH remains usable',mm.uid('SEARCH',None,'HEADER','X-Foo','bar')[0]=='OK')
    check('review F-1: bulk BODYSTRUCTURE remains usable',mm.uid('FETCH','1:*','(BODYSTRUCTURE)')[0]=='OK')
    mm.logout()
    check('review F-1: rejected messages never enter mailbox storage',sum(u['messages'] for u in json.loads(run(BIN,'users',str(C1))))==before)
    with socket.create_connection(('127.0.0.1',N1[0]),timeout=10) as tcp:
        assert tcp.recv(512).startswith(b'220')
        tcp.sendall(b'NOOP '+b'x'*5000+b'\r\n')
        check('review F-3: oversized SMTP command gets explicit 500 response',tcp.recv(1024).startswith(b'500 5.5.2'))
        try:closed=tcp.recv(1024)==b''
        except ConnectionResetError:closed=True
        check('review F-3: oversized line is closed without parsing its suffix',closed)
    with smtplib.SMTP('127.0.0.1',N1[0],timeout=10) as client:
        check('review F-3: SMTP remains responsive after oversized command',client.noop()[0]==250)
    attacker=WebClient('node1','127.0.0.2')
    bad={'username':'admin','password':'incorrect'}
    check('review F-2: one source receives its own attempt budget',all(attacker.call('/api/login',bad)[0]==401 for _ in range(20)))
    limited=attacker.call('/api/login',bad)
    check('review F-2: excessive attempts are throttled with Retry-After',limited[0]==429 and limited[2]['Retry-After']=='60')
    check('review F-2: forwarding headers cannot bypass source throttling',attacker.call('/api/login',bad,extra_headers={'X-Forwarded-For':'127.0.0.99','Forwarded':'for=127.0.0.99'})[0]==429)
    admin=WebClient('node1','127.0.0.1');admin.login()
    check('review F-2: another client can sign in during attacker lockout',admin.call('/api/overview')[0]==200)
    admin.call('/api/logout',{})
    malformed=WebClient('node1','127.0.0.3')
    check('review F-2: malformed credentials do not consume password budget',all(malformed.call('/api/login',{})[0]==400 for _ in range(25)))
    malformed.login();check('review F-2: valid login works after malformed requests')
    malformed.call('/api/logout',{})

def module_checks():
    w=WebClient('node1');b=WebClient('node2');w.login();b.login()
    check('module catalog requires administrator login',WebClient('node1').call('/api/modules')[0]==401)
    v=w.call('/api/modules')[1];rev=v['state']['revision']
    check('catalog distinguishes available Mail/Webmail/Accounting from planned modules',v['modules'][0]['id']=='mail' and all(not m['enabled'] and m['implemented']==(m['id'] in ['accounts','webmail']) for m in v['modules'][1:]))
    change={'id':'mail','enabled':False,'expected_revision':rev}
    check('module changes require CSRF token',w.call('/api/modules',change,csrf=False)[0]==403)
    check('standby rejects module mutations',b.call('/api/modules',change)[0]==409)
    for module_id in ['core','sales','unknown']:
        check('reject unavailable or foundational module: '+module_id,w.call('/api/modules',{**change,'id':module_id})[0]==400)
    HOLD_RELAY.set();RELEASE_RELAY.clear()
    try:
        with smtplib.SMTP_SSL('localhost',N1[1],context=ctx,timeout=20) as client:
            client.login('alice@example.test',PASSWORD)
            raw=message('example.test').replace(b'Sender <sender@example.test>',b'Alice <alice@example.test>')
            client.sendmail('alice@example.test',['module-test@external.test'],raw)
        until(lambda:RELAY_IN_FLIGHT.is_set(),seconds=10)
        refused=w.call('/api/modules',change)
        check('disable refuses in-flight external delivery until queue bookkeeping finishes',refused[0]==400 and 'in progress' in refused[1]['error'])
    finally:
        RELEASE_RELAY.set();HOLD_RELAY.clear()
    until(lambda:w.call('/api/queue')[1]==[])
    DELIVERED.clear()
    before=w.call('/api/overview')[1]
    existing=imap()
    submitting=smtplib.SMTP('127.0.0.1',N1[0],timeout=20)
    submitting.ehlo('sender.test');submitting.mail('sender@good.test');assert submitting.rcpt('alice@example.test')[0]==250
    assert submitting.docmd('DATA')[0]==354
    check('web disables Mail',w.call('/api/modules',change)[0]==200)
    submitting.send(message()+b'.\r\n')
    check('DATA started before disable cannot commit after disable',submitting.getreply()[0]==452)
    submitting.close()
    until(lambda:status(C2).get('modules',{}).get('mail_enabled') is False)
    check('disabled module state replicates to standby',b.call('/api/modules')[1]['state']['mail_enabled'] is False)
    with socket.create_connection(('127.0.0.1',N1[0]),timeout=10) as tcp:
        check('disabled SMTP returns temporary unavailable',tcp.recv(512).startswith(b'421'))
    with ctx.wrap_socket(socket.create_connection(('localhost',N1[2]),timeout=10),server_hostname='localhost') as tcp:
        check('disabled IMAP rejects connections',tcp.recv(512).startswith(b'* BYE'))
    try:
        existing.noop();raise AssertionError('disabled mailbox session still active')
    except (imaplib.IMAP4.abort,OSError):
        check('existing IMAP session stops on next command')
    finally:
        try:existing.shutdown()
        except OSError:pass
    check('disabled module blocks mail API and CLI',w.call('/api/users')[0]==400 and subprocess.run([BIN,'users',str(C1)],capture_output=True).returncode!=0)
    check('disabled module blocks mailbox mutations',w.call('/api/users',{'email':'disabled@example.test','password':PASSWORD})[0]==400)
    after=w.call('/api/overview')[1]
    check('disabling preserves messages and accounts',all(before[k]==after[k] for k in ['accounts','messages','mailbox_bytes','queue_count']))
    check('Core backup and admin remain available with all optional modules off',w.call('/api/backups',{})[0]==200 and status(C1)['primary'])
    check('stale module revision is rejected',w.call('/api/modules',{**change,'enabled':True})[0]==400)
    run(BIN,'module-enable',str(C1),'mail')
    check('CLI re-enables Mail and web sees same setting',w.call('/api/modules')[1]['state']['mail_enabled'])
    mm=imap();mm.logout();check('mailbox access resumes after re-enable')
    until(lambda:status(C1).get('sequence')==status(C2).get('sequence'))
    run(BIN,'module-enable',str(C1),'webmail')
    until(lambda:status(C2).get('modules',{}).get('webmail_enabled') is True)
    check('Webmail enable setting replicates independently',status(C1)['modules']['webmail_enabled'])
    w.call('/api/logout',{});b.call('/api/logout',{})

def web_checks():
    w=WebClient('node1');b=WebClient('node2')
    check('web protects account metadata before login',w.call('/api/users')[0]==401)
    check('web denies unexpected Host',w.call('/api/overview',host='evil.test')[0]==421)
    check('web login rejects missing or foreign origin',w.call('/api/login',{},origin=False)[0]==403 and w.call('/api/login',{},origin='https://evil.test')[0]==403)
    check('web login rejects invalid credentials',w.call('/api/login',{'username':'admin','password':'incorrect'})[0]==401)
    h=w.login();check('web login cookie is Secure HttpOnly SameSite Strict','Secure' in h['Set-Cookie'] and 'HttpOnly' in h['Set-Cookie'] and 'SameSite=Strict' in h['Set-Cookie'])
    check('web sends no-store and restrictive CSP',h['Cache-Control']=='no-store' and "frame-ancestors 'none'" in h['Content-Security-Policy'])
    check('web session restores CSRF token',w.call('/api/session')[1]['csrf']==w.csrf)
    check('web CSRF guard blocks writes',w.call('/api/users',{'email':'webtest@example.test','password':PASSWORD},csrf=False)[0]==403)
    check('web rejects wrong mailbox domain',w.call('/api/users',{'email':'webtest@other.test','password':PASSWORD})[0]==400)
    check('web rejects short mailbox passwords',w.call('/api/users',{'email':'webtest@example.test','password':'short'})[0]==400)
    check('web creates mailbox account',w.call('/api/users',{'email':'webtest@example.test','password':PASSWORD})[0]==200)
    check('web creation rejects duplicate accounts',w.call('/api/users',{'email':'webtest@example.test','password':PASSWORD})[0]==400)
    users=w.call('/api/users')[1];check('web account summaries omit credentials',any(x['email']=='webtest@example.test' for x in users) and 'password_hash' not in json.dumps(users))
    mm=imap(N1,'webtest@example.test');mm.logout();check('web-created account can log in over IMAP')
    check('CLI sees account created in web UI',any(x['email']=='webtest@example.test' for x in json.loads(run(BIN,'users',str(C1)))))
    newpass='replacement-mail-password-long';check('web resets mailbox password',w.call('/api/users/password',{'email':'webtest@example.test','password':newpass})[0]==200)
    mm=imaplib.IMAP4_SSL('localhost',N1[2],ssl_context=ctx,timeout=15);check('new web-set password authenticates IMAP',mm.login('webtest@example.test',newpass)[0]=='OK');mm.logout()
    check('web and CLI show same policy',w.call('/api/policy')[1]==json.loads(run(BIN,'policy',str(C1))))
    check('web queue view available',w.call('/api/queue')[0]==200)
    v=w.call('/api/backups',{});check('web creates consistent backup',v[0]==200 and pathlib.Path(v[1]['path']).exists())
    check('web lists completed backups',len(w.call('/api/backups')[1])>=1)
    b.login();check('standby permits web login and inspection',b.call('/api/overview')[1]['primary'] is False)
    check('standby rejects web account mutations',b.call('/api/users',{'email':'standby@example.test','password':PASSWORD})[0]==409)
    check('web logout invalidates server session',w.call('/api/logout',{})[0]==200 and w.call('/api/session')[0]==401)
    b.call('/api/logout',{})
    if a.browser_smoke:
        manifest=ROOT/'browser-fixture.json';manifest.write_text(json.dumps({'primary':w.origin,'standby':b.origin,'password':ADMIN_PASSWORD,'work':str(ROOT)}))
        subprocess.run(['node',str(pathlib.Path(__file__).with_name('browser-smoke.cjs')),str(manifest)],check=True)
        check('desktop and mobile browser interactions pass')

try:
    dual_config=C1.read_text();C1.write_text(single_config(dual_config,'node1'))
    run(BIN,'init' ,str(C1),'--bootstrap');run(BIN,'init',str(C2))
    run(BIN,'add-user-offline',str(C1),'alice@example.test',input=PASSWORD.encode())
    for n in range(1,10):run(BIN,'add-user-offline',str(C1),f'user{n}@example.test',input=PASSWORD.encode())
    one=start('serve',C1)
    until(lambda:status(C1).get('primary'),seconds=15)
    check('single mode serves without any witness or peer',status(C1)['mode']=='single')
    mm=imap(N1,'user1@example.test');assert mm.append('Sent',None,None,message('example.test',subject='before-scale-out'))[0]=='OK';mm.logout()
    run(BIN,'module-disable',str(C1),'mail')
    check('CLI disables Mail in single-node mode',not status(C1)['modules']['mail_enabled'])
    single_sequence=status(C1)['sequence'];one.terminate();one.wait(10)
    one=start('serve',C1);until(lambda:status(C1).get('primary'),seconds=15)
    check('single-mode restart preserves transaction sequence',status(C1)['sequence']==single_sequence)
    check('module disabled state survives restart',not status(C1)['modules']['mail_enabled'])
    run(BIN,'module-enable',str(C1),'mail')
    one.terminate();one.wait(10);C1.write_text(dual_config)
    witness=start('witness',WC);one=start('serve',C1);two=start('serve',C2)
    until(lambda:status(C1).get('primary') and status(C2).get('ready'))
    check('primary lease and initial database snapshot')
    until(lambda:status(C1).get('sequence')==status(C2).get('sequence'))
    check('single-to-dual transition preserves mailbox data',any(u['email']=='user1@example.test' and u['messages']==1 for u in json.loads(run(BIN,'users',str(C2)))))
    module_checks()
    web_checks()
    with smtplib.SMTP('127.0.0.1',N1[0],timeout=15) as s:
        s.ehlo('sender.test');s.mail('sender@good.test');check('open relay refused',s.rcpt('victim@external.test')[0]==550);check('unknown local account refused',s.rcpt('missing@example.test')[0]==550)
        s.rset();s.starttls(context=ctx);s.ehlo('sender.test');check('Pratique SMTP STARTTLS',s.noop()[0]==250)
    check('SPF aligned pass accepted',inbound(message())[0]==250)
    check('DMARC reject enforced',inbound(message('bad.test'),'sender@bad.test')[0]==550)
    check('SPF softfail without DMARC policy accepted',inbound(message('soft.test'),'sender@soft.test')[0]==250)
    check('DNS temporary errors defer',inbound(message('temp.test'),'sender@temp.test')[0]==451)
    dk=signed();check('DKIM pass rescues SPF fail through aligned DMARC',inbound(dk,'sender@dkim.test')[0]==250)
    check('tampered DKIM and failed SPF rejected',inbound(dk.replace(b'Hello from',b'Tampered x'),'sender@dkim.test')[0]==550)
    security_review_checks()
    m=imap();check('IMAP login and folder listing',m.list()[0]=='OK');check('SELECT INBOX',m.select('INBOX')[0]=='OK')
    check('SEARCH returns accepted messages',len(m.uid('SEARCH',None,'ALL')[1][0].split())==3)
    uid=m.uid('SEARCH',None,'ALL')[1][0].split()[0]
    response=m.uid('FETCH',uid,'(FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])')
    check('IMAP metadata, envelope, MIME structure, header preview',response[0]=='OK' and any(isinstance(x,tuple) and b'Subject:' in x[1] for x in response[1]))
    check('IMAP partial body fetch',m.uid('FETCH',uid,'(BODY.PEEK[]<0.20>)')[0]=='OK')
    check('IMAP flags',m.uid('STORE',uid,'+FLAGS','(\\Seen \\Flagged)')[0]=='OK')
    check('SEARCH UNSEEN',len(m.uid('SEARCH',None,'UNSEEN')[1][0].split())==2)
    check('CREATE folder',m.create('Archive')[0]=='OK');check('COPY message',m.uid('COPY',uid,'Archive')[0]=='OK')
    check('APPEND sent mail',m.append('Sent','(\\Seen)',None,message('example.test'))[0]=='OK')
    check('MOVE message',m.uid('MOVE',uid,'Archive')[0]=='OK')
    m.logout()
    with smtplib.SMTP_SSL('localhost',N1[1],context=ctx,timeout=20) as s:
        s.login('alice@example.test',PASSWORD)
        raw=message('example.test').replace(b'Sender <sender@example.test>',b'Alice <alice@example.test>')
        check('authenticated submission queues external mail',not s.sendmail('alice@example.test',['target@external.test'],raw))
    until(lambda:len(DELIVERED)==1);check('TLS authenticated outbound relay delivered',b'From: Alice' in DELIVERED[0]);check('outbound DKIM remains enabled with relay and replicated mail',b'DKIM-Signature:' in DELIVERED[0] and b'd=example.test' in DELIVERED[0])
    # Verify IDLE updates after a new message arrives.
    with ctx.wrap_socket(socket.create_connection(('localhost',N1[2]),timeout=10),server_hostname='localhost') as idle_socket:
        f=idle_socket.makefile('rb');f.readline()
        for tag,cmd in [(b'a1',b'LOGIN alice@example.test '+PASSWORD.encode()),(b'a2',b'SELECT INBOX')]:
            idle_socket.sendall(tag+b' '+cmd+b'\r\n')
            while not f.readline().startswith(tag+b' OK'):pass
        idle_socket.sendall(b'a3 IDLE\r\n');assert f.readline().startswith(b'+')
        assert inbound(message(subject='idle-notification'))[0]==250
        check('IMAP IDLE announces new mail',b'EXISTS' in f.readline())
        idle_socket.sendall(b'DONE\r\n');assert f.readline().startswith(b'a3 OK')
    backup_path=run(BIN,'backup',str(C1)).decode().strip()
    export_dir=ROOT/'backup-export';run(BIN,'export-recovery',str(C1),backup_path,str(export_dir))
    check('consistent backup and read-only message export',len(list(export_dir.glob('*.eml')))>=4)
    until(lambda:status(C1).get('sequence')==status(C2).get('sequence'))
    before=status(C2)['sequence'];check('accounts, folders, flags and queue transactions replicated',before>5)
    two.terminate();two.wait(10)
    check('primary accepts mail while replica is offline',inbound(message(subject='while-peer-offline'))[0]==250)
    two=start('serve',C2);until(lambda:status(C1).get('sequence')==status(C2).get('sequence'))
    check('missed transactions catch up after peer returns')
    run(BIN,'module-disable',str(C1),'mail')
    until(lambda:status(C2).get('modules',{}).get('mail_enabled') is False)
    one.kill();one.wait(10);until(lambda:status(C2).get('primary'))
    check('promoted node retains Webmail enable setting',status(C2)['modules']['webmail_enabled'])
    check('promoted node inherits disabled Mail setting',not status(C2)['modules']['mail_enabled'])
    run(BIN,'module-enable',str(C2),'mail')
    check('standby automatically promotes after lease expiry')
    check('promoted node accepts mail',inbound(message(subject='after-failover'),ports=N2)[0]==250)
    m=imap(N2);check('replicated account works after promotion',m.select('Archive')[0]=='OK' and int(m.response('EXISTS')[1][0])==2);m.logout()
    # Old primary returns, must follow the new lease holder and reseed safely.
    one=start('serve',C1);until(lambda:status(C1).get('term')==status(C2).get('term') and status(C1).get('sequence')==status(C2).get('sequence'))
    check('old primary rejoins as replica without taking leadership',not status(C1)['primary'])
    one.terminate();one.wait(10)
    import shutil
    shutil.move(str(ROOT/'node1'),str(ROOT/'node1-retired'))
    run(BIN,'module-disable',str(C2),'mail')
    run(BIN,'init',str(C1));one=start('serve',C1)
    until(lambda:status(C1).get('ready') and status(C1).get('sequence')==status(C2).get('sequence'))
    check('empty replacement node receives database snapshot')
    check('replacement snapshot includes Webmail setting',status(C1)['modules']['webmail_enabled'])
    check('replacement snapshot includes disabled module setting',not status(C1)['modules']['mail_enabled'])
    run(BIN,'module-enable',str(C2),'mail')
    # Exercise maximum message size with simultaneous connections and repeated fetches.
    big=message(body=(b'x'*998+b'\r\n')*9000,subject='memory-pressure')
    m=imap(N2);check('9 MB APPEND',m.append('INBOX',None,None,big)[0]=='OK');m.select('INBOX')
    last=m.uid('SEARCH',None,'ALL')[1][0].split()[-1];m.logout()
    idle=[imap(N2)]+[imap(N2,f'user{n}@example.test') for n in range(1,10)]
    check('ten replicated accounts authenticate on promoted node',len(idle)==10)
    check('mailbox isolation between accounts',idle[-1].select('INBOX')[1]==[b'0'])
    def fetch_big(_):
        mm=imap(N2);mm.select('INBOX');res=mm.uid('FETCH',last,'(BODY.PEEK[] BODYSTRUCTURE)');mm.logout();return res[0]
    web_load=WebClient('node2');web_load.login()
    def inspect_web():
        for _ in range(5):
            assert web_load.call('/api/overview')[0]==200
            assert web_load.call('/api/users')[0]==200
        return True
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        web_future=pool.submit(inspect_web)
        check('two concurrent large fetches with ten idle sessions',all(r=='OK' for r in pool.map(fetch_big,range(2))))
        check('web inspection remains responsive during concurrent mail load',web_future.result())
    web_load.call('/api/logout',{})
    for mm in idle:mm.logout()
    sample();check('mail processes stay below 512 MB RSS in tested load',max(PEAK.values())<512*1024)
    # Witness loss must stop writers after the lease expires, preventing partition split-brain.
    witness.kill();witness.wait(10);until(lambda:not status(C2).get('primary'),seconds=25)
    EXPECTED_FENCING=True
    with smtplib.SMTP('127.0.0.1',N2[0],timeout=10) as s:pass
    raise AssertionError('writer remained available after witness lease expired')
except smtplib.SMTPConnectError as exc:
    if EXPECTED_FENCING and exc.smtp_code==421:
        check('witness outage fences mail acceptance after lease expiry')
        one.terminate();one.wait(10);two.terminate();two.wait(10)
        # Both peer processes are stopped and this test never starts the retired peer again.
        old=C2.read_text();C2.write_text(single_config(old,'node2'))
        refused=subprocess.run([BIN,'serve',str(C2)],capture_output=True,timeout=15)
        check('config-only dual-to-single downgrade is refused',refused.returncode!=0 and b'unsafe downgrade' in refused.stderr)
        refused=subprocess.run([BIN,'demote-single',str(C2)],capture_output=True,timeout=15)
        check('demotion requires explicit peer-fencing assertion',refused.returncode!=0 and b'--peer-fenced' in refused.stderr)
        before=sorted((ROOT/'node2').glob('backup-*.redb'))
        run(BIN,'demote-single',str(C2),'--peer-fenced')
        check('explicit demotion creates a backup first',len(list((ROOT/'node2').glob('backup-*.redb')))==len(before)+1)
        two=start('serve',C2);until(lambda:status(C2).get('primary'),seconds=15)
        check('dual-to-single conversion runs with witness stopped',status(C2)['mode']=='single')
        mm=imap(N2);mm.select('Archive');check('demotion preserves account, folders and mail',int(mm.response('EXISTS')[1][0])==2);mm.logout()
        b=WebClient('node2');b.login();check('web UI remains available in single mode after demotion',b.call('/api/overview')[1]['mode']=='single');b.call('/api/logout',{})
        refused=subprocess.run([BIN,'demote-single',str(C2),'--peer-fenced'],capture_output=True,timeout=15)
        check('offline demotion refuses a live locked database',refused.returncode!=0)
    else:raise
finally:
    sample()
    for proc in PROCS:
        if proc.poll() is None:proc.terminate()
    for proc in PROCS:
        try:proc.wait(10)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
    for f in LOGS:f.close()
    for s in servers:s.shutdown();s.server_close()
    result={'passed':PASS,'checks':len(PASS),'peak_rss_kib_by_node':PEAK};(ROOT/'results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2),flush=True)
