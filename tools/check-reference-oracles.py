#!/usr/bin/env python3
"""Reproduce independent comparisons in isolated, offline development harnesses."""
import argparse,json,os,pathlib,shutil,subprocess,sys,tomllib
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('kind',choices=['mailauth','idna','url'])
p.add_argument('--output',type=pathlib.Path,required=True,help='New empty directory for harness, cache and logs')
p.add_argument('--reference-source',type=pathlib.Path,help='Extracted source version 29, needed for mailauth')
p.add_argument('--cargo',default='cargo');a=p.parse_args();out=a.output.resolve()
if out.exists() and any(out.iterdir()):raise SystemExit('--output must be an empty directory')
out.mkdir(parents=True,exist_ok=True);env=os.environ.copy();env['CARGO_TARGET_DIR']=str(out/'target')
def run(label,args,cwd,stdout=None,extra=None):
    e=env.copy();e.update(extra or {});print('CHECK',label,flush=True)
    with (out/(label+'.txt')).open('w')as log:
        if stdout is None:r=subprocess.run(args,cwd=cwd,env=e,stdout=log,stderr=subprocess.STDOUT)
        else:
            with stdout.open('w')as f:r=subprocess.run(args,cwd=cwd,env=e,stdout=f,stderr=log)
    if r.returncode:raise SystemExit(f'{label} failed; see {out/(label+".txt")}')
if a.kind=='mailauth':
    if not a.reference_source:raise SystemExit('--reference-source must identify extracted source version 29')
    reference=a.reference_source.resolve()
    if not (reference/'vendor/mail-auth/Cargo.toml').is_file()or not(reference/'crates/native-dns/Cargo.toml').is_file():raise SystemExit('Expected the native-DNS source checkpoint retaining mail-auth')
    copy=out/'reference';shutil.copytree(reference,copy,ignore=shutil.ignore_patterns('target','.git','__pycache__'))
    shutil.copy(ROOT/'tools/mailauth-protocol-oracle.rs',copy/'tools/portable-protocol-oracle.rs')
    with (copy/'Cargo.toml').open('a')as f:f.write('\n[[bin]]\nname = "portable-protocol-oracle"\npath = "tools/portable-protocol-oracle.rs"\n')
    base=[a.cargo,'run','--offline','--locked','--features','mail-auth/arc','--bin','portable-protocol-oracle']
    run('reference-protocol-fixtures',base,copy,out/'reference-protocols.json')
    run('reference-spf',base+['--','--spf'],copy,out/'reference-spf.json')
    assert json.loads((out/'reference-spf.json').read_text())==json.loads((ROOT/'tests/fixtures/spf-reference.json').read_text())
    run('native-protocol-fixtures',[a.cargo,'test','--offline','--locked','--features','arc','--test','native_protocols','native_dkim2_signing_reconstruction_flags_and_envelope','--','--exact'],ROOT,extra={'WORKGLEN_EXPORT_PROTOCOL_FIXTURES':str(out/'native-protocols.json')})
    run('reference-verifies-native',base+['--',str(out/'native-protocols.json')],copy)
else:
    harness=out/'harness';(harness/'src').mkdir(parents=True)
    module=ROOT/'crates/native-idna'
    dependencies='idna = "=1.1.0"\nidna_adapter = "=1.2.2"\nicu_normalizer = { version = "=2.4.0", default-features = false }\nicu_properties = { version = "=2.4.0", default-features = false }\nicu_normalizer_data = "=2.4.0"\nicu_properties_data = "=2.4.0"\n'
    if module.exists():dependencies+='workglen-idna = { path = '+json.dumps(str(module))+' }\n'
    elif a.kind=='idna':raise SystemExit('Native IDNA is available in the cumulative IDNA checkpoint')
    if a.kind=='url':
        dependencies+='url = "=2.5.8"\n'
        code=(ROOT/'tools/url-compat.rs').read_text().replace('"../src/url.rs"',json.dumps(str(ROOT/'src/url.rs')))
    else:code=(ROOT/'tools/idna-compat.rs').read_text()
    (harness/'Cargo.toml').write_text('[package]\nname = "workglen-reference-oracle"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\n[dependencies]\n'+dependencies)
    (harness/'src/main.rs').write_text(code)
    # This isolated harness is new; prepare its lock offline, then only execute locked.
    run('prepare-oracle-lock',[a.cargo,'generate-lockfile','--offline'],harness)
    lock=tomllib.loads((harness/'Cargo.lock').read_text())
    expected={'idna':'1.1.0','idna_adapter':'1.2.2','icu_normalizer':'2.4.0','icu_properties':'2.4.0','icu_normalizer_data':'2.4.0','icu_properties_data':'2.4.0'}
    for pkg in lock['package']:
        if pkg['name']in expected:assert pkg['version']==expected[pkg['name']]
    run(a.kind+'-comparison',[a.cargo,'run','--offline','--locked','--release'],harness)
print('PASS independent comparison; complete harness and logs:',out)
