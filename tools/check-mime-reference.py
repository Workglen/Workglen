#!/usr/bin/env python3
"""Reproduce MIME snapshots with the former parser in an isolated offline harness."""
import argparse,json,os,pathlib,subprocess,sys,re,shutil
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cargo',default='cargo');p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();out=a.output.resolve()
if out.exists() and any(out.iterdir()):raise SystemExit('--output must be empty')
out.mkdir(parents=True,exist_ok=True)
rows=json.loads((ROOT/'tests/fixtures/native-mime.json').read_text())
inputs=subprocess.check_output([sys.executable,str(ROOT/'tools/generate-mime-fixtures.py')])
assert [json.loads(s) for s in inputs.decode().split('\n') if s]==[{k:v for k,v in row.items() if k in ('label','profile','hex')}for row in rows], 'Fixture input regeneration differs'
(out/'inputs.jsonl').write_bytes(inputs)
pratique=out/'pratique-source'
shutil.copytree(ROOT/'vendor/pratique',pratique,ignore=shutil.ignore_patterns('target','target-*','__pycache__'))
p=pratique/'Cargo.toml';p.write_text(re.sub(r'(?ms)^\[\[(?:example|test)\]\]\n.*?(?=^\[|\Z)','',p.read_text()))

for kind,dependency in [('former','mail-parser = { version = "=0.11.9", features = ["full_encoding", "base64_slice"] }'),('native','mail-parser = { package = "workglen-mime", path = '+json.dumps(str(ROOT/'crates/native-mime'))+' }')]:
    harness=out/kind;(harness/'src').mkdir(parents=True)
    (harness/'Cargo.toml').write_text('[package]\nname="mime-reference"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'+dependency+'\n'+('serde_json="=1.0.154"\n'if kind=='former'else 'pratique={path='+json.dumps(str(pratique))+',default-features=false}\n'))
    (harness/'src/main.rs').write_text((ROOT/'tools'/('mime-reference.rs'if kind=='former'else'mime-reference-native.rs')).read_text())
    env=os.environ.copy();env['CARGO_TARGET_DIR']=str(out/'target')
    with (out/(kind+'-build.txt')).open('w')as log:
        (harness/'Cargo.lock').write_bytes((ROOT/'tests/fixtures'/f'mime-{kind}-oracle.lock').read_bytes())
        result=subprocess.run([a.cargo,'run','--offline','--locked','--release'],cwd=harness,env=env,input=inputs,stdout=subprocess.PIPE,stderr=log,check=True)
    (out/(kind+'.jsonl')).write_bytes(result.stdout)
    actual=[json.loads(s)for s in result.stdout.decode().split('\n')if s]
    assert len(actual)==len(rows)
    for row,got in zip(rows,actual):
        want=row.get('native',row['expected'])if kind=='native'else row['expected']
        assert got['label']==row['label'] and got['expected']==want, f'{kind}: {row["label"]}'
    print('PASS',kind,len(rows),'snapshots',flush=True)
summary={'cases':len(rows),'exact_matches':sum('native'not in r for r in rows),'reviewed_differences':sum('native'in r for r in rows),'former':'mail-parser 0.11.9','native':'workglen-mime 0.1.0','scope':'Synthetic local corpus, not universal MIME conformance'}
(out/'results.json').write_text(json.dumps(summary,indent=2)+'\n');print('PASS independent MIME comparison',out)
