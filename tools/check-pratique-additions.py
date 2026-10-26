#!/usr/bin/env python3
"""Check reusable Pratique additions with a dependency-free standalone harness."""
import argparse,json,os,pathlib,re,shutil,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cargo',default='cargo');p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();out=a.output.resolve()
if out.exists()and any(out.iterdir()):raise SystemExit('--output must be empty')
(out/'src').mkdir(parents=True);(out/'tests').mkdir()
# Workglen vendors the library subset; upstream's manifest also names omitted
# examples/tests. Keep every library source byte, pruning only those absent targets
# in this disposable validation copy so Cargo can inspect it independently.
pratique=out/'pratique-source'
shutil.copytree(ROOT/'vendor/pratique',pratique,ignore=shutil.ignore_patterns('target','target-*'))
manifest=(pratique/'Cargo.toml').read_text()
manifest=re.sub(r'(?ms)^\[\[(?:example|test)\]\]\n.*?(?=^\[|\Z)','',manifest)
(pratique/'Cargo.toml').write_text(manifest)

(out/'Cargo.toml').write_text('[package]\nname="pratique-additions-check"\nversion="0.0.0"\nedition="2021"\n[workspace]\n[features]\nnet=["pratique/net"]\n[dependencies]\npratique={path='+json.dumps(str(pratique))+',default-features=false}\n[[test]]\nname="async_socket"\nrequired-features=["net"]\n')
(out/'src/lib.rs').write_text('''pub fn hash(bytes: &[u8]) -> Vec<u8> { use pratique::crypto::sha2::{Hash,Sha256}; Sha256::digest(bytes) }
#[cfg(feature="net")]
pub use pratique::asyncio::{AsyncRead,AsyncWrite,Sleep,sleep,yield_now};
// Compile and lint the new socket module itself, not just its public callers.
#[cfg(feature="net")]
pub mod socket;
pub mod data;
pub mod json_value;
#[allow(clippy::all)] // Existing signed-JSON module; new policy seam is covered by data_json tests.
pub mod json;
''')
(out/'src/socket').mkdir()
(out/'src/socket.rs').write_bytes((pratique/'src/asyncio/socket.rs').read_bytes())
(out/'src/socket/connect.rs').write_bytes((pratique/'src/asyncio/socket/connect.rs').read_bytes())
(out/'tests/async_socket.rs').write_bytes((ROOT/'vendor/pratique/tests/async_socket.rs').read_bytes())
for name in ['data/mod.rs','data/macros.rs','json.rs','json_value.rs']:
    dest=out/'src'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((pratique/'src'/name).read_bytes())
(out/'tests/data_json.rs').write_bytes((ROOT/'vendor/pratique/tests/data_json.rs').read_bytes())
(out/'tests/data').mkdir();(out/'tests/data/json_vectors.txt').write_bytes((ROOT/'tests/fixtures/pratique-json-vectors.txt').read_bytes())
env=os.environ.copy();env['CARGO_TARGET_DIR']=str(out/'target');results=[]
for name,command in [('lock',['generate-lockfile','--offline']),('pure',['check','--offline','--locked','--no-default-features']),('signed-json-tests',['test','--offline','--locked','--no-default-features','--lib']),('data-tests',['test','--offline','--locked','--no-default-features','--test','data_json']),('net-tests',['test','--offline','--locked','--features','net','--test','async_socket']),('net-clippy',['clippy','--offline','--locked','--no-deps','--package','pratique-additions-check','--features','net','--all-targets','--','-D','warnings'])]:
    with (out/(name+'.txt')).open('w')as log:r=subprocess.run([a.cargo,*command],cwd=out,env=env,stdout=log,stderr=subprocess.STDOUT)
    results.append({'check':name,'exit_code':r.returncode,'log':name+'.txt'})
    (out/'results.json').write_text(json.dumps({'scope':'Pratique only; zero external dependencies; synthetic loopback tests','results':results},indent=2)+'\n')
    if r.returncode:print((out/(name+'.txt')).read_text());raise SystemExit(r.returncode)
    print('PASS Pratique',name,flush=True)
assert 'source = 'not in (out/'Cargo.lock').read_text(), 'Unexpected external dependency'
