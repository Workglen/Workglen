#!/usr/bin/env python3
"""Loopback-only direct SMTP/DKIM regression. Never contacts a real mail server.
Uses synthetic DNS and Python/OpenSSL SMTP peers; generates disposable keys.
"""
import argparse
import base64
import hashlib
import imaplib
import json
import os
import pathlib
import re
import smtplib
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', required=True)
p.add_argument('--work', required=True)
a = p.parse_args()
BIN = str(pathlib.Path(a.binary).resolve())
ROOT = pathlib.Path(a.work).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
ROOT.chmod(0o700)
PASS, SERVERS, PROCESSES, LOGS = [], [], [], []
EVENTS, DELIVERED, QUERIES, ATTEMPTS = [], [], [], {}
LOCK = threading.Lock()

def check(name, condition=True):
    assert condition, name
    PASS.append(name)
    print('PASS', name, flush=True)

def run(*args, input=None):
    return subprocess.run(args, input=input, check=True, capture_output=True).stdout

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def until(predicate, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(.15)
    raise AssertionError('timed out waiting for ' + getattr(predicate, '__name__', 'condition'))

DNS, OUT = port(), port()
MXPORT, SUBMIT, IMAP, ADMIN = port(), port(), port(), port()
cert, key = ROOT/'cert.pem', ROOT/'tls.key'
hosts = ['localhost', 'mail.example.test', 'mx.primary.test', 'mx.good.test',
         'mx.backup.test', 'implicit.test', 'mx.multi.test', 'mx.v6.test',
         'mx.plain.test', 'mx.startfail.test', 'mx.inject.test', 'mx.cap.test',
         'mx.small.test', 'mx.uncertain.test', 'mx.reject.test', 'mx.retry.test',
         'mx.helo.test', 'mx.forward.test', 'mx.datareject.test', 'relay.smtp.test']
run('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '2', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=' + ','.join('DNS:'+h for h in hosts) + ',IP:127.0.0.1')
key.chmod(0o600)
for name in ['admin.token', 'relay.password']:
    (ROOT/name).write_text('fixture-secret-' + 'a'*64)
    (ROOT/name).chmod(0o600)
CLIENT = ssl.create_default_context(cafile=str(cert))
TLS = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
TLS.load_cert_chain(str(cert), str(key))
PASSWORD = 'synthetic-mail-password'

MX = {
    'mx.test': [(10, 'mx.primary.test'), (20, 'mx.backup.test')],
    'direct.test': [(10, 'mx.good.test')],
    'multi.test': [(10, 'mx.multi.test')],
    'v6.test': [(10, 'mx.v6.test')],
    'mixedfamily.test': [(10, 'mx.v6.test')],
    'null.test': [(0, '.')],
    'mixednull.test': [(0, '.'), (10, 'mx.good.test')],
    'empty.test': [(10, 'mx.empty.test')],
    'loop.test': [(10, 'mail.example.test'), (20, 'mx.good.test')],
    'better.test': [(5, 'mx.good.test'), (10, 'mail.example.test'), (20, 'mx.backup.test')],
    'private.test': [(10, 'mx.internal.test')],
    'plain.test': [(10, 'mx.plain.test')],
    'badcert.test': [(10, 'mx.badcert.test')],
    'startfail.test': [(10, 'mx.startfail.test')],
    'inject.test': [(10, 'mx.inject.test')],
    'cap.test': [(10, 'mx.cap.test')],
    'small.test': [(10, 'mx.small.test')],
    'uncertain.test': [(10, 'mx.uncertain.test'), (20, 'mx.backup.test')],
    'reject.test': [(10, 'mx.reject.test'), (20, 'mx.backup.test')],
    'retry.test': [(10, 'mx.retry.test')],
    'helo.test': [(10, 'mx.helo.test')],
    'forward.test': [(10, 'mx.forward.test')],
    'datareject.test': [(10, 'mx.datareject.test')],
}
IPS = {'mx.primary.test': ['127.0.0.2'], 'mx.good.test': ['127.0.0.3'],
       'mx.backup.test': ['127.0.0.3'], 'implicit.test': ['127.0.0.3'],
       'mx.multi.test': ['127.0.0.22', '127.0.0.3'], 'mx.v6.test': ['::1'],
       'mx.internal.test': ['10.0.0.1'], 'mx.plain.test': ['127.0.0.4'],
       'mx.badcert.test': ['127.0.0.3'], 'mx.startfail.test': ['127.0.0.6'],
       'mx.inject.test': ['127.0.0.7'], 'mx.cap.test': ['127.0.0.8'],
       'mx.small.test': ['127.0.0.9'], 'mx.uncertain.test': ['127.0.0.10'],
       'mx.reject.test': ['127.0.0.11'], 'mx.retry.test': ['127.0.0.12'],
       'mx.helo.test': ['127.0.0.13'], 'mx.forward.test': ['127.0.0.14'],
       'mx.datareject.test': ['127.0.0.16'], 'relay.smtp.test': ['127.0.0.18']}
TXT = {}

def dns_name(name):
    return b''.join(bytes([len(x)])+x.encode() for x in name.rstrip('.').split('.') if x) + b'\0'

def dns_response(data):
    off, labels = 12, []
    while data[off]:
        size = data[off]
        labels.append(data[off+1:off+1+size].decode().lower())
        off += size+1
    off += 1
    name = '.'.join(labels)
    kind, cls = struct.unpack('!HH', data[off:off+4])
    question = data[12:off+4]
    with LOCK:
        QUERIES.append((name, kind))
    code = 3 if name == 'nx.test' else 2 if name == 'servfail.test' or name == 'mx.v6.test' and kind == 1 else 0
    values = []
    if code == 0:
        if kind == 15:
            values = [struct.pack('!H', n) + dns_name(h) for n, h in MX.get(name, [])]
        elif kind in (1, 28):
            family = socket.AF_INET if kind == 1 else socket.AF_INET6
            values = [socket.inet_pton(family, ip) for ip in IPS.get(name, []) if (':' in ip) == (kind == 28)]
        elif kind == 16:
            for value in TXT.get(name, []):
                value = value.encode()
                values.append(b''.join(bytes([len(value[i:i+200])])+value[i:i+200] for i in range(0, len(value), 200)))
    answers = b''.join(b'\xc0\x0c'+struct.pack('!HHIH', kind, 1, 0, len(v))+v for v in values)
    return data[:2]+struct.pack('!HHHHH', 0x8580 | code, 1, len(values), 0, 0)+question+answers

class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(dns_response(data), self.client_address)

class ThreadTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class V6TCP(ThreadTCP):
    address_family = socket.AF_INET6

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request.makefile('rb')
        size = struct.unpack('!H', stream.read(2))[0]
        answer = dns_response(stream.read(size))
        self.request.sendall(struct.pack('!H', len(answer))+answer)

def start_server(server):
    SERVERS.append(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()

class SMTP(socketserver.BaseRequestHandler):
    def handle(self):
        actor = self.server.actor
        secure = actor == 'relay'
        sock = self.request
        recipient = None
        try:
            sock.settimeout(20)
            if secure:
                sock = TLS.wrap_socket(sock, server_side=True)
            if actor == 'busy':
                sock.sendall(b'421 4.3.0 try another MX\r\n')
                EVENTS.append((actor, 'GREETING', '', secure))
                return
            sock.sendall(b'220 fixture ESMTP\r\n')
            stream = sock.makefile('rb')
            while True:
                line = stream.readline(4096)
                if not line:
                    return
                verb = line.split(b' ', 1)[0].strip().upper()
                EVENTS.append((actor, verb.decode(), recipient or '', secure))
                if verb == b'EHLO':
                    if actor == 'helo':
                        sock.sendall(b'502 EHLO not implemented\r\n')
                        continue
                    caps = [b'fixture']
                    if actor == 'relay':
                        caps.append(b'AUTH PLAIN')
                    if not secure and actor not in ['plain', 'helo']:
                        caps.append(b'STARTTLS')
                    if not (actor == 'cap' and secure):
                        caps.append(b'8BITMIME')
                    caps.append(b'SIZE 64' if actor == 'small' and secure else b'SIZE 20000000')
                    sock.sendall(b''.join(b'250'+(b' ' if i == len(caps)-1 else b'-')+v+b'\r\n' for i, v in enumerate(caps)))
                elif verb == b'HELO':
                    sock.sendall(b'250 fixture\r\n')
                elif verb == b'STARTTLS':
                    if actor == 'startfail':
                        sock.sendall(b'454 4.7.0 unavailable\r\n')
                        continue
                    if actor == 'inject':
                        sock.sendall(b'220 Ready\r\n250 injected\r\n')
                        return
                    sock.sendall(b'220 Ready\r\n')
                    stream.close()
                    sock = TLS.wrap_socket(sock, server_side=True)
                    stream = sock.makefile('rb')
                    secure = True
                elif verb == b'AUTH' and actor == 'relay':
                    sock.sendall(b'235 authenticated\r\n')
                elif verb == b'MAIL':
                    sock.sendall(b'250 2.1.0 OK\r\n')
                elif verb == b'RCPT':
                    recipient = line.split(b'<', 1)[1].split(b'>', 1)[0].decode()
                    ATTEMPTS[recipient] = ATTEMPTS.get(recipient, 0) + 1
                    if actor == 'reject':
                        sock.sendall(b'550 5.1.1 nonexistent\r\n')
                    elif actor == 'retry' and ATTEMPTS[recipient] == 1:
                        sock.sendall(b'451 4.3.0 try later\r\n')
                    elif actor == 'forward':
                        sock.sendall(b'251 2.1.5 will forward\r\n')
                    else:
                        sock.sendall(b'250 2.1.5 OK\r\n')
                elif verb == b'DATA':
                    sock.sendall(b'354 send body\r\n')
                    body = []
                    while True:
                        chunk = stream.readline(2000)
                        if not chunk:
                            return
                        if chunk == b'.\r\n':
                            break
                        body.append(chunk[1:] if chunk.startswith(b'..') else chunk)
                    record = {'actor': actor, 'recipient': recipient, 'body': b''.join(body), 'secure': secure}
                    DELIVERED.append(record)
                    if actor == 'uncertain':
                        return
                    if actor == 'datareject':
                        sock.sendall(b'554 5.7.1 policy rejection\r\n')
                    else:
                        sock.sendall(b'250 2.0.0 accepted\r\n')
                elif verb == b'QUIT':
                    sock.sendall(b'221 bye\r\n')
                    return
                else:
                    sock.sendall(b'500 unsupported\r\n')
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            sock.close()

def configuration(path, data_dir, tls='required', private=True, relay=False, retry=1800):
    text = f'''mode = "single"
hostname = "mail.example.test"
domain = "example.test"
dns_server = "127.0.0.1:{DNS}"
data_dir = "{data_dir}"
admin_listen = "127.0.0.1:{ADMIN}"
admin_token_file = "{ROOT/'admin.token'}"
role = "primary"
tls_cert = "{cert}"
tls_key = "{key}"
smtp_listen = "127.0.0.1:{MXPORT}"
submission_listen = "127.0.0.1:{SUBMIT}"
imap_listen = "127.0.0.1:{IMAP}"
[replication]
cluster_id = "workglen-direct-test-0001"
'''
    text += f'\n[dkim]\nselector="outbound2026"\nkey_file="{ROOT}/dkim.key"\n'
    if relay:
        text += f'\n[relay]\naddress="relay.smtp.test:{OUT}"\nserver_name="relay.smtp.test"\nca_file="{cert}"\nusername="fixture"\npassword_file="{ROOT}/relay.password"\n'
    else:
        text += f'\n[direct]\ntls="{tls}"\nca_file="{cert}"\nport={OUT}\nallow_private_addresses={str(private).lower()}\nretry_seconds={retry}\n'
    path.write_text(text)

def start(config):
    log = open(ROOT/(config.stem + '-serve.log'), 'ab')
    LOGS.append(log)
    process = subprocess.Popen([BIN, 'serve', str(config)], stdout=log, stderr=log)
    PROCESSES.append(process)
    def ready():
        assert process.poll() is None, (ROOT/(config.stem+'-serve.log')).read_text()
        try:
            return json.loads(run(BIN, 'status', str(config)))['primary']
        except subprocess.CalledProcessError:
            return False
    until(ready)
    return process

def stop(process):
    process.terminate()
    process.wait(timeout=10)

def queue(config):
    return dict(json.loads(run(BIN, 'queue', str(config))))

def pending(config, recipient, state='pending'):
    return next((v for v in queue(config).values() if v['recipient'] == recipient and v['status'] == state and v['attempts'] > 0), None)

def received(recipient):
    return next((v for v in DELIVERED if v['recipient'] == recipient), None)

def message(subject='Fixture', body=b'Hello\t  world. \t\r\n.leading dot\r\n..two dots\r\n\r\n'):
    return ('From: Alice <alice@example.test>\r\nTo: recipient@direct.test\r\n'
            'Date: Sat, 24 Oct 2026 10:00:00 -0500\r\nMessage-ID: <fixture@example.test>\r\n'
            'Subject: '+subject+'\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n').encode() + body

def submit(recipient, raw=None, expected=250):
    with smtplib.SMTP_SSL('localhost', SUBMIT, context=CLIENT, timeout=10) as smtp:
        smtp.ehlo('client.test')
        smtp.login('alice@example.test', PASSWORD)
        assert smtp.mail('alice@example.test')[0] == 250
        recipients = [recipient] if isinstance(recipient, str) else recipient
        for rcpt in recipients:
            assert smtp.rcpt(rcpt)[0] == 250
        try:
            result = smtp.data(raw or message())
        except smtplib.SMTPDataError as e:
            result = (e.smtp_code, e.smtp_error)
        assert result[0] == expected, result

def header_parts(raw):
    head, body = raw.split(b'\r\n\r\n', 1)
    headers = []
    for line in head.split(b'\r\n'):
        if line.startswith((b' ', b'\t')):
            headers[-1][1] += b'\r\n' + line
        else:
            name, value = line.split(b':', 1)
            headers.append([name.lower(), value])
    return headers, body

def relaxed_header(name, value):
    value = re.sub(rb'\r\n[ \t]+', b' ', value)
    value = re.sub(rb'[ \t]+', b' ', value).strip(b' \t')
    return name.lower() + b':' + value + b'\r\n'

def verify_dkim(raw):
    # Independent RFC 6376 relaxed/relaxed implementation and OpenSSL verifier.
    # No Python DKIM package and no DNS/network lookup are used here.
    headers, body = header_parts(raw)
    signature = next((v for n, v in headers if n == b'dkim-signature'), None)
    if signature is None:
        return False
    tags = {}
    for part in signature.split(b';'):
        if b'=' in part:
            name, value = part.split(b'=', 1)
            tags[name.strip()] = re.sub(rb'\s+', b'', value)
    lines = [re.sub(rb'[ \t]+', b' ', x.rstrip(b' \t')) for x in body.split(b'\r\n')]
    while lines and not lines[-1]:
        lines.pop()
    canonical_body = b'\r\n'.join(lines) + (b'\r\n' if lines else b'')
    if tags.get(b'bh') != base64.b64encode(hashlib.sha256(canonical_body).digest()):
        return False
    available = list(headers)
    signed = bytearray()
    for name in tags[b'h'].lower().split(b':'):
        for i in range(len(available)-1, -1, -1):
            if available[i][0] == name:
                n, value = available.pop(i)
                signed.extend(relaxed_header(n, value))
                break
    unsigned = re.sub(rb'(\bb[ \t]*=)[^;]*', rb'\1', signature)
    signed.extend(relaxed_header(b'dkim-signature', unsigned)[:-2])
    (ROOT/'signature.bin').write_bytes(base64.b64decode(tags[b'b']))
    result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(ROOT/'dkim.pub'),
                             '-signature', str(ROOT/'signature.bin')], input=signed, capture_output=True)
    return result.returncode == 0

def failed_case(config, recipient, contains):
    submit(recipient)
    item = until(lambda: pending(config, recipient, 'failed'))
    check(recipient + ' permanent failure retained', contains in item['last_error'] and item['dkim_signed'])

def deferred_case(config, recipient, raw=None):
    submit(recipient, raw)
    item = until(lambda: pending(config, recipient))
    check(recipient + ' deferred without message loss', item['dkim_signed'] and item['next_try'] > item['created'])
    return item

try:
    start_server(socketserver.ThreadingUDPServer(('127.0.0.1', DNS), UDP))
    start_server(ThreadTCP(('127.0.0.1', DNS), DNSHandler))
    actors = {2:'busy', 3:'good', 4:'plain', 6:'startfail', 7:'inject', 8:'cap', 9:'small',
              10:'uncertain', 11:'reject', 12:'retry', 13:'helo', 14:'forward', 16:'datareject', 18:'relay'}
    for suffix, actor in actors.items():
        server = ThreadTCP((f'127.0.0.{suffix}', OUT), SMTP)
        server.actor = actor
        start_server(server)
    v6 = V6TCP(('::1', OUT), SMTP)
    v6.actor = 'good-v6'
    start_server(v6)

    config = ROOT/'node.toml'
    configuration(config, ROOT/'data')
    record = run(BIN, 'dkim-generate', str(config)).decode()
    check('DKIM generation returns chunked public DNS record', 'outbound2026._domainkey.example.test' in record and 'PRIVATE' not in record)
    check('DKIM private key permissions', (ROOT/'dkim.key').stat().st_mode & 0o777 == 0o600)
    refusal = subprocess.run([BIN, 'dkim-generate', str(config)], capture_output=True)
    check('DKIM generation refuses to replace an existing key', refusal.returncode != 0)
    check('DKIM DNS command is stable', run(BIN, 'dkim-dns', str(config)).decode() == record)
    (ROOT/'dkim.pub').write_bytes(run('openssl', 'pkey', '-in', str(ROOT/'dkim.key'), '-pubout'))
    public_der = run('openssl', 'pkey', '-in', str(ROOT/'dkim.key'), '-pubout', '-outform', 'DER')
    TXT['outbound2026._domainkey.example.test'] = ['v=DKIM1; k=rsa; p='+base64.b64encode(public_der).decode()]
    TXT['example.test'] = ['v=spf1 -all']
    TXT['_dmarc.example.test'] = ['v=DMARC1; p=reject; adkim=s']
    run(BIN, 'init', str(config), '--bootstrap')
    run(BIN, 'add-user-offline', str(config), 'alice@example.test', input=PASSWORD.encode())
    process = start(config)
    status = json.loads(run(BIN, 'status', str(config)))
    check('status exposes direct delivery and DKIM selector', status['delivery']['mode'] == 'direct' and status['delivery']['dkim_selector'] == 'outbound2026')
    with smtplib.SMTP('localhost', MXPORT, timeout=10) as smtp:
        smtp.ehlo('outside.test')
        smtp.mail('stranger@external.test')
        check('direct mode does not enable an open relay', smtp.rcpt('victim@direct.test')[0] == 550)
    submit('one@direct.test')
    delivered = until(lambda: received('one@direct.test'))
    check('direct delivery negotiates STARTTLS and preserves dot-stuffed body', delivered['secure'] and delivered['body'].endswith(message().split(b'\r\n\r\n', 1)[1]))
    check('independent OpenSSL DKIM verification', verify_dkim(delivered['body']))
    with smtplib.SMTP('localhost', MXPORT, timeout=10) as inbound:
        inbound.ehlo('outside.test')
        inbound.mail('alice@example.test')
        inbound.rcpt('alice@example.test')
        check('published DKIM TXT passes receiving verification and aligned DMARC', inbound.data(delivered['body'])[0] == 250)
    with imaplib.IMAP4_SSL('localhost', IMAP, ssl_context=CLIENT) as mailbox:
        mailbox.login('alice@example.test', PASSWORD)
        mailbox.select('INBOX')
        _, fetched = mailbox.fetch('1', '(RFC822)')
        stored = next(x[1] for x in fetched if isinstance(x, tuple))
        check('inbound mail preserves signature without re-signing', stored.lower().count(b'dkim-signature:') == 1 and verify_dkim(stored))
    check('DKIM rejects body tampering', not verify_dkim(delivered['body'] + b'Injected\r\n'))
    check('DKIM rejects Subject tampering', not verify_dkim(delivered['body'].replace(b'Subject: Fixture', b'Subject: Forged')))
    check('DKIM oversigning rejects added From', not verify_dkim(b'From: attacker@example.test\r\n' + delivered['body']))
    check('relaxed DKIM tolerates body whitespace normalization', verify_dkim(delivered['body'].replace(b'Hello\t  world. \t', b'Hello world.')))
    check('direct transport sends no AUTH command', not any(e[1] == 'AUTH' for e in EVENTS))
    submit('empty@direct.test', message(body=b''))
    check('DKIM empty body verification', verify_dkim(until(lambda: received('empty@direct.test'))['body']))
    submit('eight@direct.test', message(body='Unicode body: café\r\n'.encode()))
    check('8BITMIME body delivered and signed', verify_dkim(until(lambda: received('eight@direct.test'))['body']))
    submit('badheader@direct.test', message(subject='café'), expected=550)
    check('SMTPUTF8 headers refused before acceptance', not received('badheader@direct.test'))
    submit('priority@mx.test')
    until(lambda: received('priority@mx.test'))
    check('lower-priority MX tried after primary greeting failure', any(e[0] == 'busy' for e in EVENTS))
    for domain in ['implicit.test', 'multi.test', 'v6.test', 'better.test', 'forward.test']:
        submit('ok@'+domain)
        check(domain + ' routing succeeds', verify_dkim(until(lambda: received('ok@'+domain))['body']))
    check('AAAA works despite A lookup SERVFAIL', ('mx.v6.test', 1) in QUERIES and ('mx.v6.test', 28) in QUERIES)
    for recipient, error in [('no@null.test', 'Null MX'), ('no@nx.test', 'NXDOMAIN'), ('no@empty.test', 'no usable'), ('no@loop.test', 'routing loop'), ('no@reject.test', '550'), ('no@small.test', 'SIZE'), ('no@datareject.test', '554')]:
        failed_case(config, recipient, error)
    check('Null MX never falls back to A/AAAA', ('null.test', 1) not in QUERIES and ('null.test', 28) not in QUERIES)
    check('recipient 550 is not bypassed using another MX', not received('no@reject.test'))
    for recipient in ['later@servfail.test', 'later@mixednull.test', 'later@plain.test', 'later@badcert.test', 'later@startfail.test', 'later@inject.test']:
        deferred_case(config, recipient)
    deferred_case(config, 'later@cap.test', message(body='café\r\n'.encode()))
    check('post-TLS EHLO replaces pre-TLS capabilities', not received('later@cap.test'))
    deferred_case(config, 'maybe@uncertain.test')
    uncertain = [x for x in DELIVERED if x['recipient'] == 'maybe@uncertain.test']
    check('lost final acknowledgment does not trigger another MX in same attempt', len(uncertain) == 1 and uncertain[0]['actor'] == 'uncertain')
    check('required TLS sends no MAIL to plaintext peer', not any(e[0] == 'plain' and e[1] == 'MAIL' for e in EVENTS))
    check('failed STARTTLS never falls back to plaintext', not any(e[0] == 'startfail' and e[1] == 'MAIL' for e in EVENTS))
    stop(process)

    configuration(config, ROOT/'data', tls='opportunistic', private=False)
    process = start(config)
    failed_case(config, 'blocked@private.test', 'non-public')
    stop(process)
    configuration(config, ROOT/'data', tls='opportunistic', retry=1)
    process = start(config)
    for recipient in ['compat@plain.test', 'compat@helo.test']:
        submit(recipient)
        record = until(lambda: received(recipient))
        check(recipient + ' explicit plaintext compatibility', not record['secure'] and verify_dkim(record['body']))
    submit(['again@retry.test', 'same@direct.test'])
    until(lambda: received('again@retry.test'))
    check('451 is retried and delivery eventually leaves queue', ATTEMPTS['again@retry.test'] >= 2)
    sibling = until(lambda: received('same@direct.test'))
    check('DKIM signed bytes remain identical across recipient retry', sibling['body'] == received('again@retry.test')['body'])
    until(lambda: not any(q['recipient'] == 'again@retry.test' for q in queue(config).values()))
    with imaplib.IMAP4_SSL('localhost', IMAP, ssl_context=CLIENT) as client:
        client.login('alice@example.test', PASSWORD)
        client.select('INBOX')
        _, data = client.search(None, 'SUBJECT', '"Mail delivery failed"')
        check('permanent errors create local failure notices', len(data[0].split()) >= 7)
    stop(process)

    configuration(config, ROOT/'data', relay=True)
    process = start(config)
    submit('via@direct.test')
    record = until(lambda: received('via@direct.test'))
    check('relay hostname resolves through configured DNS', ('relay.smtp.test', 1) in QUERIES)
    check('authenticated implicit-TLS relay remains available with DKIM', record['actor'] == 'relay' and record['secure'] and verify_dkim(record['body']))
    stop(process)

    ROOT.joinpath('outbound-results.json').write_text(json.dumps({'passed': len(PASS), 'checks': PASS}, indent=2)+'\n')
    print(json.dumps({'passed': len(PASS)}), flush=True)
finally:
    for process in PROCESSES:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
    for server in SERVERS:
        server.shutdown()
        server.server_close()
    for log in LOGS:
        log.close()
