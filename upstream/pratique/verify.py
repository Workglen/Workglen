#!/usr/bin/env python3
"""Verify Pratique patch preimages/application without modifying the checkout."""
import argparse,hashlib,json,pathlib,subprocess,tempfile
HERE=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--checkout',type=pathlib.Path,help='Pratique checkout to check; never modified')
p.add_argument('--stage',choices=['all','earlier-crypto','tokio-removal','serde-json-removal'],default='all')
p.add_argument('--vendor',type=pathlib.Path,help='Also verify the complete Workglen vendored tree')
a=p.parse_args();manifest=json.loads((HERE/'changes.json').read_text())
digest=lambda b:hashlib.sha256(b).hexdigest()
for stage in manifest['stages']:
    assert digest((HERE/stage['patch']).read_bytes())==stage['patch_sha256'],stage['patch']
if a.vendor:
    actual_files={str(p.relative_to(a.vendor)) for p in a.vendor.rglob('*') if p.is_file() and not any(part=='target' or part.startswith('target-') or part=='__pycache__' for part in p.relative_to(a.vendor).parts)}
    assert actual_files==set(manifest['vendored_files']),f'Vendored inventory differs; untracked={sorted(actual_files-set(manifest["vendored_files"]))}; missing={sorted(set(manifest["vendored_files"])-actual_files)}'
    for name,want in manifest['vendored_files'].items():
        assert digest((a.vendor/name).read_bytes())==want,f'Vendored file changed: {name}'
    print('PASS vendored Pratique source hashes:',len(manifest['vendored_files']))
if a.checkout:
    selected=[s for s in manifest['stages']if a.stage=='all'or s['stage']==a.stage]
    with tempfile.TemporaryDirectory(prefix='pratique-patch-check-')as work:
        work=pathlib.Path(work)
        for name in {f['path']for stage in selected for f in stage['files']}:
            source=a.checkout/name
            if source.is_file():
                dest=work/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(source.read_bytes())
        for stage in selected:
            for f in stage['files']:
                file=work/f['path'];actual=digest(file.read_bytes())if file.exists()else None
                assert actual==f['before_sha256'],f"Preimage mismatch: {stage['stage']} / {f['path']} (review/rebase; do not force)"
            patch=(HERE/stage['patch']).resolve()
            subprocess.run(['git','apply','--check','--whitespace=error',str(patch)],cwd=work,check=True)
            subprocess.run(['git','apply','--whitespace=error',str(patch)],cwd=work,check=True)
            for f in stage['files']:
                file=work/f['path'];actual=digest(file.read_bytes())if file.exists()else None
                assert actual==f['after_sha256'],f"Postimage mismatch: {f['path']}"
            print('PASS patch application and exact resulting bytes:',stage['patch'])
if not a.checkout and not a.vendor:raise SystemExit('Provide --checkout and/or --vendor')
