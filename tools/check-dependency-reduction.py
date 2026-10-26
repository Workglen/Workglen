#!/usr/bin/env python3
"""Verify a recorded dependency reduction against the preceding source ZIP."""
import argparse, hashlib, json, pathlib, tomllib, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--baseline-zip',type=pathlib.Path,required=True,help='Unmodified archive immediately before this reduction (native Tokio/source v33 for this combined update)')
p.add_argument('--inventory',type=pathlib.Path,default=ROOT/'validation/0.8-native-library-inventory.json',help='Recorded inventory for this source checkpoint')
p.add_argument('--after-lock',type=pathlib.Path,default=ROOT/'Cargo.lock',help='Override only when checking a saved intermediate lock')
a=p.parse_args()
inventory=json.loads(a.inventory.read_text())
key=lambda p:(p['name'],p['version'])
with zipfile.ZipFile(a.baseline_zip)as z:
    before={key(p):p for p in tomllib.loads(z.read('workglen/Cargo.lock').decode())['package']if 'source'in p}
    for path in [ROOT/'install.sh',*sorted((ROOT/'config').glob('*.toml'))]:
        assert path.read_bytes()==z.read('workglen/'+str(path.relative_to(ROOT))),f'Configuration/installer changed: {path.name}'
after={key(p):p for p in tomllib.loads(a.after_lock.read_text())['package']if 'source'in p}
assert len(before)==inventory['before_external_versions']
assert len(after)==inventory['after_external_versions']
assert not after.keys()-before.keys(),'Registry additions or version upgrades'
assert all(before[k]['checksum']==p['checksum'] and before[k]['source']==p['source'] for k,p in after.items()),'Retained package changed'
assert [{'name':n,'version':v}for n,v in sorted(before.keys()-after.keys())]==inventory['removed']
assert hashlib.sha256(a.after_lock.read_bytes()).hexdigest()==inventory['cargo_lock_sha256']
print(f'PASS {len(before)} -> {len(after)} external versions; exact {len(before)-len(after)} removals; no additions/upgrades/checksum changes; installer and shipped configurations unchanged')
