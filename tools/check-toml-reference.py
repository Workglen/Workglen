#!/usr/bin/env python3
"""Repeat TOML comparisons using isolated, pinned, offline former/native harnesses."""
import argparse, json, os, pathlib, subprocess, sys, re, shutil
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cargo',default='cargo')
p.add_argument('--output',type=pathlib.Path,required=True)
a=p.parse_args();out=a.output.resolve()
if out.exists() and any(out.iterdir()):raise SystemExit('--output must be empty')
out.mkdir(parents=True,exist_ok=True)
rows=json.loads((ROOT/'tests/fixtures/native-toml-reference.json').read_text())
inputs=subprocess.check_output([sys.executable,str(ROOT/'tools/generate-toml-fixtures.py')])
assert [json.loads(s)for s in inputs.decode().splitlines()]==[{k:v for k,v in r.items()if k!='expected'}for r in rows], 'Input regeneration differs'
(out/'inputs.jsonl').write_bytes(inputs)
pratique=out/'pratique-source'
shutil.copytree(ROOT/'vendor/pratique',pratique,ignore=shutil.ignore_patterns('target','target-*','__pycache__'))
p=pratique/'Cargo.toml';p.write_text(re.sub(r'(?ms)^\[\[(?:example|test)\]\]\n.*?(?=^\[|\Z)','',p.read_text()))

toml_source=out/'toml-source'
shutil.copytree(ROOT/'crates/native-toml',toml_source,ignore=shutil.ignore_patterns('target','__pycache__'))
p=toml_source/'Cargo.toml';p.write_text(p.read_text().replace('../../vendor/pratique','../pratique-source'))
dependencies=[('former','toml = { version = "=0.9.12", default-features = false, features = ["std", "serde", "parse"] }'),('native','toml = { package = "workglen-toml", path = '+json.dumps(str(toml_source))+' }')]
for kind,dependency in dependencies:
    harness=out/kind;(harness/'src').mkdir(parents=True)
    (harness/'Cargo.toml').write_text('[package]\nname="toml-reference"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'+dependency+'\n'+('serde_json="=1.0.154"\nserde={version="=1.0.229",features=["derive"]}\n'if kind=='former'else'pratique={path='+json.dumps(str(pratique))+',default-features=false}\n'))
    for src,dest in ([('toml-reference.rs','main.rs'),('toml-schema-reference.rs','toml-schema-reference.rs')]if kind=='former'else[('toml-reference-native.rs','main.rs'),('toml-schema-native.rs','toml-schema-native.rs')]):
        (harness/'src'/dest).write_text((ROOT/'tools'/src).read_text())
    # Frozen isolated locks are shipped so upstream cache additions cannot change the oracle.
    (harness/'Cargo.lock').write_bytes((ROOT/'tests/fixtures/toml-test'/f'{kind}-oracle.lock').read_bytes())
    env=os.environ.copy();env['CARGO_TARGET_DIR']=str(out/'target')
    with (out/(kind+'-build.txt')).open('w')as log:
        result=subprocess.run([a.cargo,'run','--offline','--locked','--release'],cwd=harness,env=env,input=inputs,stdout=subprocess.PIPE,stderr=log,check=True)
    (out/(kind+'.jsonl')).write_bytes(result.stdout)
    actual=[json.loads(s)for s in result.stdout.decode().splitlines()]
    assert len(actual)==len(rows)
    for row,got in zip(rows,actual):
        assert got['label']==row['label'] and got['result']==row['expected'],f'{kind}: {row["label"]}'
    print('PASS',kind,len(rows),'snapshots',flush=True)
summary={'cases':len(rows),'official_corpus':712,'schema_contracts':26,'shipped_configs':6,'edge_cases':4,'seeded_mutations':5000,'mismatches':0,'former':'toml 0.9.12+spec-1.1.0','native':'workglen-toml 0.1.0','scope':'Pinned corpus and synthetic compatibility checks, not proof for every possible document'}
(out/'results.json').write_text(json.dumps(summary,indent=2)+'\n')
print('PASS independent TOML comparison',out)
