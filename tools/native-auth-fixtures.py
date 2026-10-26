#!/usr/bin/env python3
"""Independent, deterministic DKIM extension fixtures. Public synthetic key only."""
import base64, hashlib, json, re
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
record='v=DKIM1;k=ed25519;p='+base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
headers=b'From: a@author.test\r\nSubject: Extension fixture\r\n'
body=b'Hello world\r\n'
def canon(field):
    name,value=field.split(b':',1)
    return name.lower()+b':'+re.sub(rb'[ \t]+',b' ',value.strip(b' \t\r\n'))
cases=[]
def case(label,tags,expected='Pass',now=150,policy=None,dns=None,length=None):
    hashed=body if length is None else body[:length]
    field=f'DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=dkim.test; s=test; h=from:subject; {tags} bh={base64.b64encode(hashlib.sha256(hashed).digest()).decode()}; b='.encode()
    signed=b''.join(canon(h)+b'\r\n' for h in headers.split(b'\r\n')if h)+canon(field)
    raw=field+base64.b64encode(key.sign(hashlib.sha256(signed).digest()))+b'\r\n'+headers+b'\r\n'+body
    cases.append(dict(label=label,raw=raw.decode(),record=record+(policy or ''),dns=dns or {},expected=expected,now=now))
case('quoted identity','i=user@d=6Bim.test;')
case('subdomain identity','i=user@sub.dkim.test;')
case('strict identity rejects subdomain','i=user@sub.dkim.test;',expected='Fail',policy=';t=s')
case('key hash restriction','',expected='Fail',policy=';h=sha1')
case('key service restriction','',expected='Fail',policy=';s=other')
case('expiry before deadline','t=100; x=200;')
case('expired','t=100; x=200;',expected='Fail',now=250)
case('invalid interval','t=200; x=100;',expected='Fail',now=50)
case('partial body','l=3;',length=3)
case('body shorter than l','l=100;',expected='Fail')
for algorithm in ['none','sha1','sha256']:
    label='dkim.test' if algorithm=='none' else base64.b32encode(hashlib.new(algorithm,b'dkim.test').digest()).decode().rstrip('=')
    case('ATPS '+algorithm,f'atps=author.test; atpsh={algorithm};',dns={label.lower()+'._atps.author.test':'v=ATPS1'})
case('missing ATPS authorization','atps=author.test; atpsh=none;',expected='Fail')
case('temporary ATPS','atps=author.test; atpsh=none;',expected='Temporary',dns={'dkim.test._atps.author.test':'TIMEOUT'})
case('unknown ATPS hash ignored','atps=author.test; atpsh=unknown;')
case('unrelated ATPS author ignored','atps=other.test; atpsh=none;')
path=Path(__file__).resolve().parents[1]/'tests/fixtures/native-auth-extensions.json'
path.write_text(json.dumps({'provenance':'Independent Python cryptography signatures; deterministic public seed 00..1f; closed DNS','cases':cases},indent=2)+'\n')
print(f'{len(cases)} independent extension fixtures')
