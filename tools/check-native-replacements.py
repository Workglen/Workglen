#!/usr/bin/env python3
"""Portable offline authentication/IDNA/MIME/TOML/DNS transport validation. No live service or real mail."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys, time

ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cargo',default='cargo',help='Cargo executable, including a toolchain wrapper if needed')
p.add_argument('--output',type=pathlib.Path,default=ROOT/'target/portable-validation')
p.add_argument('--skip-loopback',action='store_true',help='Skip only synthetic SMTP/IMAP integration peers')
p.add_argument('--skip-source-integrity',action='store_true',help='Use after intentional local source edits')
a=p.parse_args();output=a.output.resolve();output.mkdir(parents=True,exist_ok=True)
results=[]
def run(name,args,env=None):
    log=output/(name+'.txt');print('CHECK',name,flush=True);start=time.monotonic()
    with log.open('w')as f:r=subprocess.run([str(s)for s in args],cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT)
    results.append({'check':name,'exit_code':r.returncode,'seconds':round(time.monotonic()-start,2),'log':log.name})
    (output/'results.json').write_text(json.dumps({'scope':'Synthetic local offline checks; no production deployment','results':results},indent=2)+'\n')
    if r.returncode:
        print(log.read_text()[-8000:]);raise SystemExit(f'FAILED {name}; see {log}')

if not a.skip_source_integrity:
    manifest=json.loads((ROOT/'SOURCE-SHA256.json').read_text())
    for name,want in manifest.items():
        path=ROOT/name
        if not path.is_file()or hashlib.sha256(path.read_bytes()).hexdigest()!=want:
            raise SystemExit(f'Source integrity mismatch: {name}; use --skip-source-integrity only for intentional edits')
    print(f'PASS source integrity: {len(manifest)} files',flush=True)
if not a.skip_loopback and not shutil.which('openssl'):
    raise SystemExit('Loopback fixtures need the OpenSSL CLI as an independent development peer. No runtime OpenSSL dependency is added. Use --skip-loopback for Rust-only checks.')
with (output/'toolchain.txt').open('w')as f:
    subprocess.run([a.cargo,'--version'],stdout=f,stderr=subprocess.STDOUT,check=True)
generator=ROOT/'crates/native-idna/tools/generate.py'
if generator.exists():run('unicode-data-regeneration',[sys.executable,generator,'--check'])
mime_generator=ROOT/'crates/native-mime/tools/generate.py'
if mime_generator.exists():run('mime-data-regeneration',[sys.executable,mime_generator,'--check'])
run('toml-fixture-regeneration',[sys.executable,ROOT/'tools/generate-toml-fixtures.py','--check'])
run('pratique-source-tracking',[sys.executable,ROOT/'upstream/pratique/verify.py','--vendor',ROOT/'vendor/pratique'])
run('first-party-dependency-boundary',[sys.executable,ROOT/'tools/check-first-party-dependencies.py','--cargo',a.cargo])
run('rust-tests',[a.cargo,'test','--offline','--locked','--workspace','--all-features','--','--nocapture'])
clippy=os.environ.copy();clippy['CARGO_TARGET_DIR']=str(output/'clippy-target')
run('clippy',[a.cargo,'clippy','--offline','--locked','--workspace','--all-targets','--all-features','--release','--','-D','warnings'],clippy)
run('release-build',[a.cargo,'build','--offline','--locked','--release'])
if not a.skip_loopback:
    target=pathlib.Path(os.environ.get('CARGO_TARGET_DIR',str(ROOT/'target')))
    if not target.is_absolute():target=ROOT/target
    binary=target/'release/workglen'
    for name,script in [('outbound','outbound-integration.py'),('mail','integration.py'),('webmail','webmail-test.py'),('installer','install-test.py')]:
        # Each run gets a fresh isolated database/key directory; never reuse a deployment.
        import tempfile
        work=tempfile.mkdtemp(prefix=name+'-',dir=output)
        try:
            fixture=pathlib.Path(work)/'install' if name=='installer' else work
            run(name,[sys.executable,ROOT/'tools'/script,'--binary',binary,'--work',fixture])
        except BaseException:
            print('Failed synthetic fixture retained for diagnosis:',work,flush=True)
            raise
        else:
            shutil.rmtree(work)
print('PASS portable checks; logs and results.json:',output)

