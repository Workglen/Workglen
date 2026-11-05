#!/usr/bin/env python3
"""Reject registry, Git or unreviewed path dependencies beneath reusable libraries."""
import argparse, json, pathlib, subprocess, tomllib
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__); p.add_argument('--cargo', default='cargo'); a = p.parse_args()
meta = json.loads(subprocess.check_output([a.cargo, 'metadata', '--offline', '--locked', '--all-features', '--format-version', '1'], cwd=ROOT))
packages = {v['id']: v for v in meta['packages']}
nodes = {v['id']: v for v in meta['resolve']['nodes']}
approved = {'pratique': 'vendor/pratique', 'lazaret-archive': 'vendor/lazaret-archive', 'workglen-lazaret-verify': 'crates/lazaret-verify', 'lazaret-pg': 'vendor/lazaret-pg', 'workglen-mime': 'crates/native-mime', 'workglen-dns': 'crates/native-dns', 'workglen-idna': 'crates/native-idna', 'workglen-toml': 'crates/native-toml'}
roots = [v['id'] for v in packages.values() if v['name'] in approved]
assert len(roots) == len(approved), 'Missing or duplicate first-party library'
assert {v['name'] for v in packages.values() if v['source'] is None and v['id'] != meta['resolve']['root']} == set(approved), 'Unreviewed first-party library'
for name, directory in approved.items():
    manifest_path = ROOT / directory / 'Cargo.toml'
    manifest = tomllib.loads(manifest_path.read_text())
    # Also cover disabled optional dependencies that Cargo metadata does not resolve.
    for table in [manifest, *manifest.get('target', {}).values()]:
        for kind in ['dependencies', 'dev-dependencies', 'build-dependencies']:
            for alias, spec in table.get(kind, {}).items():
                assert isinstance(spec, dict) and 'path' in spec and 'git' not in spec and 'registry' not in spec, f'External manifest dependency: {name} -> {alias}'
                target = spec.get('package', alias)
                assert target in approved and (manifest_path.parent / spec['path']).resolve() == ROOT / approved[target], f'Unreviewed path: {name} -> {alias}'
for start in roots:
    seen = set(); pending = [(start, [packages[start]['name']])]
    while pending:
        item, path = pending.pop()
        if item in seen: continue
        seen.add(item); package = packages[item]
        assert package['source'] is None and package['name'] in approved, 'External dependency: ' + ' -> '.join(path)
        assert pathlib.Path(package['manifest_path']).resolve() == ROOT / approved[package['name']] / 'Cargo.toml', 'Unreviewed path dependency: ' + ' -> '.join(path)
        for dependency in nodes[item]['deps']:
            pending.append((dependency['pkg'], path + [packages[dependency['pkg']]['name']]))
    print('PASS', packages[start]['name'], 'has only first-party dependencies, including build/dev/platform edges')
print('Application-level database/password dependencies are counted separately; this check covers eight reusable libraries.')
