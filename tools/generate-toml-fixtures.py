#!/usr/bin/env python3
"""Deterministic, synthetic TOML oracle inputs; no downloads or live configuration."""
import argparse,json,pathlib,random,hashlib
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check',action='store_true',help='Verify recorded input regeneration without printing inputs')
args=parser.parse_args()
generated=[]
def emit(row):generated.append(row)
ROOT=pathlib.Path(__file__).resolve().parents[1]
source=ROOT/'tests/fixtures/toml-test/cases.json'
provenance=json.loads(source.with_name('provenance.json').read_text())
assert hashlib.sha256(source.read_bytes()).hexdigest()==provenance['cases_sha256']
rows=json.loads(source.read_text())
for row in rows: emit({k:row[k] for k in ('label','hex')})
base="name='example.test'\nrole='primary'\n"
cases=['','count=0','count=65_535','count=-1','count=65536','count=1.0',"count='1'",'enabled=true','enabled=1',"optional='yes'",'optional=1979-05-27',"unknown='no'",'values=[1,-2,3]',"values=[1,'2']",'pair=[1,2]','pair=[1]','pair=[1,2,3]',"listen='127.0.0.1:80'","listen='bad'","variant='Unit'","variant={Unit={}}",'variant={New=1}','variant={Tuple=[1,2]}','variant={Tuple=[1,2,3]}','variant={Struct={enabled=true}}','variant={Struct={enabled=1}}']
for i,case in enumerate(cases):emit({'label':f'schema/{i:02}','kind':'schema','hex':(base+case).encode().hex()})
for path in sorted((ROOT/'config').glob('*.toml')):emit({'label':'config/'+path.name,'hex':path.read_bytes().hex()})
for label,text in [('bom','\ufeffa=1'),('fractional-minute','a=07:32.5'),('implicit-parent','[a.b.c]\n[a]\nb.d=1'),('explicit-child','[a.b]\nx=1\n[a]\nb.y=2')]:emit({'label':label,'hex':text.encode().hex()})
rng=random.Random(0x544f4d4c)
seeds=[bytes.fromhex(r['hex']) for r in rows if r['valid']]
for i in range(5000):
    data=bytearray(seeds[i%len(seeds)]);pos=rng.randrange(len(data)+1);value=rng.randrange(256)
    if i%3==0:data[pos:pos]=bytes([value])
    elif i%3==1 and pos<len(data):del data[pos]
    elif pos<len(data):data[pos]=value
    emit({'label':f'mutation/{i:04}','hex':data.hex()})
if args.check:
    recorded=json.loads((ROOT/'tests/fixtures/native-toml-reference.json').read_text())
    assert generated==[{k:v for k,v in r.items()if k!='expected'}for r in recorded], 'Input regeneration differs'
    print('PASS exact TOML fixture regeneration:',len(generated),'cases; corpus hash verified')
else:
    for row in generated:print(json.dumps(row))
