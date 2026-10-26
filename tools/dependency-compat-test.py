#!/usr/bin/env python3
"""Same-schema regression across the dependency reduction; synthetic loopback only.

Uses a supplied pre-change executable as an independent compatibility oracle.
Creates a new private fixture; never opens an operator's database or sends mail.
"""
import argparse
import fcntl
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import time
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--before', required=True)
parser.add_argument('--after', required=True)
parser.add_argument('--work', required=True)
args = parser.parse_args()
before, after = str(Path(args.before).resolve()), str(Path(args.after).resolve())
root = Path(args.work).resolve()
root.mkdir(mode=0o700, parents=True, exist_ok=False)
checks = []
password = 'synthetic-dependency-fixture-password'


def run(binary, *args, data=None, success=True):
    result = subprocess.run([binary, *map(str, args)], input=data,
                            capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == success, result.stderr
    return result.stdout


def write(name, data):
    path = root / name
    path.write_text(data)
    path.chmod(0o600)
    return path


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def passed(label):
    checks.append(label)
    print('PASS ' + label, flush=True)


def command(binary, action, data=None):
    return json.loads(run(binary, 'security-command', config, data=json.dumps({
        'action': action, 'data': data or {}, 'request_id': str(uuid.uuid4())})))


def verify(binary):
    return json.loads(run(binary, 'security-audit-verify', config))


def login(binary, user):
    context = ssl.create_default_context(cafile=str(root / 'local-ca.pem'))
    with (root / ('server-' + user + '.log')).open('w') as log:
        process = subprocess.Popen([binary, 'security-serve', str(config)],
                                   stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                assert process.poll() is None, 'fixture service exited'
                try:
                    connection = http.client.HTTPSConnection('localhost', https_port,
                                                            context=context, timeout=2)
                    connection.request('POST', '/api/login',
                                       json.dumps({'username': user, 'password': password}),
                                       {'Content-Type': 'application/json', 'Origin': origin})
                    response = connection.getresponse()
                    response.read()
                    connection.close()
                    assert response.status == 200, response.status
                    return
                except OSError:
                    time.sleep(.1)
            raise AssertionError('fixture listener did not start')
        finally:
            process.terminate()
            process.wait(timeout=10)


run(before, 'setup-local-tls', root)
key = root / 'storage.key'
run(before, 'security-generate-key', key)
control = write('control.key', 'c' * 64)
admin_hash = write('admin.hash', run(before, 'hash-password', data=password).strip())
https_port = port()
origin = f'https://localhost:{https_port}'
config = write('config.json', json.dumps({
    'data_dir': str(root / 'data'), 'storage_key_file': str(key),
    'workspace': 'dependency-fixture', 'instance': 'gateway', 'hostname': 'localhost',
    'origin': origin, 'https_listen': ['127.0.0.1', https_port],
    'smtp_listen': ['127.0.0.1', port()], 'tls_cert': str(root / 'local-cert.pem'),
    'tls_key': str(root / 'local-key.pem'), 'control_key_file': str(control),
    'dns_server': '127.0.0.1:9', 'routes': {}, 'connectors': {},
}))
run(before, 'security-init', config, 'admin', admin_hash)
original_key, original_config = key.read_bytes(), config.read_bytes()
old_audit = verify(before)
assert verify(after) == old_audit
passed('new executable reopens existing encrypted store and validates existing audit chain')
login(after, 'admin')
passed('new executable authenticates the existing Argon2 password hash')
command(after, 'identity-set', {
    'username': 'new-admin', 'enabled': True, 'mailbox': None,
    'permissions': ['read'], 'domains': ['*'], 'mailboxes': ['*'],
    'password': password, 'expected_revision': None,
})
new_audit = verify(after)
assert new_audit != old_audit
assert verify(before) == new_audit
passed('pre-change executable validates newly appended audit and encrypted records')
login(before, 'new-admin')
passed('pre-change executable authenticates newly generated Argon2 password hash')

for lock_name in ['security.lock', 'security.redb.lock']:
    with (root / 'data' / lock_name).open('r+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for binary in [before, after]:
            run(binary, 'security-audit-verify', config, success=False)
    assert verify(after) == new_audit
passed('pre-change and updated executables both exclude independent flock holders')
assert key.read_bytes() == original_key
assert config.read_bytes() == original_config
assert (root / 'data/security.redb').read_bytes().startswith(b'WGCRYPT1')
passed('configuration and original storage key remain unchanged')
(root / 'results.json').write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2) + '\n')
