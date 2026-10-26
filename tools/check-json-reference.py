#!/usr/bin/env python3
"""Compare first-party JSON against the pinned former engine, offline and isolated."""
import argparse,json,os,pathlib,subprocess,sys,re,shutil
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cargo',default='cargo');p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();out=a.output.resolve()
if out.exists()and any(out.iterdir()):raise SystemExit('--output must be empty')
out.mkdir(parents=True)
inputs=subprocess.check_output([sys.executable,str(ROOT/'tools/generate-json-fixtures.py')]);(out/'inputs.jsonl').write_bytes(inputs)
base=(ROOT/'tools/json-reference.rs').read_text()
pratique=out/'pratique-source'
shutil.copytree(ROOT/'vendor/pratique',pratique,ignore=shutil.ignore_patterns('target','target-*','__pycache__'))
p=pratique/'Cargo.toml';p.write_text(re.sub(r'(?ms)^\[\[(?:example|test)\]\]\n.*?(?=^\[|\Z)','',p.read_text()))
for kind in ['former','native']:
 h=out/kind;(h/'src').mkdir(parents=True)
 if kind=='former':
  deps='serde={version="=1.0.229",features=["derive"]}\nserde_json={version="=1.0.154",features=["arbitrary_precision"]}\n'
  imports='use serde::{Serialize as Encode,de::DeserializeOwned as Decode};\nuse serde_json as json;'
  record='''#[derive(serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {z:u64,a:String,optional:Option<String>,#[serde(default)]items:Vec<i16>,#[serde(default,skip_serializing_if="std::ops::Not::not")]disabled:bool}'''
 else:
  deps='pratique={path='+json.dumps(str(pratique))+',default-features=false}\n'
  imports='use pratique::{data::{Encode,Decode},json_value as json};'
  record='''struct Record {z:u64,a:String,optional:Option<String>,items:Vec<i16>,disabled:bool}
pratique::data_encode!(Record{z,a,optional,items,disabled=>std::ops::Not::not});
pratique::data_decode!(Record,deny_unknown=true,{z,a,optional,items=Vec::new(),disabled=false});'''
 (h/'Cargo.toml').write_text('[package]\nname="json-reference-'+kind+'"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'+deps)
 (h/'src/main.rs').write_text(base.replace('// CODEC_IMPORT',imports).replace('// RECORD_CONTRACT',record))
 env=os.environ.copy();env['CARGO_TARGET_DIR']=str(out/(kind+'-target'))
 with (out/(kind+'-build.txt')).open('w')as log:
  (h/'Cargo.lock').write_bytes((ROOT/'tests/fixtures'/f'json-{kind}-oracle.lock').read_bytes())
  with (out/(kind+'.jsonl')).open('wb')as results:subprocess.run([a.cargo,'run','--offline','--locked','--release'],cwd=h,env=env,input=inputs,stdout=results,stderr=log,check=True)
 print('BUILT',kind,flush=True)
former=[json.loads(l)for l in (out/'former.jsonl').read_text().splitlines()];native=[json.loads(l)for l in (out/'native.jsonl').read_text().splitlines()];assert len(former)==len(native)==len(inputs.splitlines())
differences=[{'input':json.loads(row),'former':f['result'],'native':n['result']}for row,f,n in zip(inputs.splitlines(),former,native)if f!=n]
(out/'differences.json').write_text(json.dumps(differences,indent=2)+'\n')
summary={'cases':len(former),'differences':len(differences),'former':'serde 1.0.229 / serde_json 1.0.154, arbitrary_precision','native':'Pratique typed data/JSON values','scope':'Synthetic pinned-engine comparison; not universal conformance'};(out/'results.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
reviewed=json.loads((ROOT/'tests/fixtures/native-json-reviewed.json').read_text())
assert differences==reviewed,'Unexpected JSON compatibility difference; review, do not refresh automatically'
subprocess.run([sys.executable,str(ROOT/'tools/check-json-rounding.py'),'--differences',str(out/'differences.json')],check=True)
summary['reviewed_differences']=len(reviewed);summary['unexpected_differences']=0;summary['exact_matches']=len(former)-len(reviewed)
(out/'results.json').write_text(json.dumps(summary,indent=2)+'\n')
print('PASS exact matches and independently verified reviewed differences')
