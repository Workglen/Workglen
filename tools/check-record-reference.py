#!/usr/bin/env python3
"""Compare actual application records against the pinned preceding source ZIP."""
import argparse, hashlib, json, os, pathlib, subprocess, sys, zipfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--baseline-zip', type=pathlib.Path, required=True)
p.add_argument('--cargo', default='cargo')
p.add_argument('--output', type=pathlib.Path, required=True)
a = p.parse_args(); out = a.output.resolve()
if out.exists() and any(out.iterdir()): raise SystemExit('--output must be empty')
expected_sha = 'b4592aa1dc9d95c31ac5e13ec46008347fb99cfd463d1266446d9af25a4e8769'
assert hashlib.sha256(a.baseline_zip.read_bytes()).hexdigest() == expected_sha, 'Wrong preceding source ZIP'
out.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(a.baseline_zip) as archive:
    for item in archive.infolist():
        path = pathlib.PurePosixPath(item.filename)
        assert not path.is_absolute() and '..' not in path.parts
    archive.extractall(out / 'source')
source = out / 'source/workglen'
subprocess.run([sys.executable, str(ROOT / 'tools/generate-record-contracts.py'), '--baseline-zip', str(a.baseline_zip.resolve()), '--root', str(source), '--former'], check=True)
env = os.environ.copy(); env['WORKGLEN_RECORD_EXPORT'] = str(out / 'records'); env['CARGO_TARGET_DIR'] = str(out / 'target')
with (out / 'former-build.txt').open('w') as log:
    subprocess.run([a.cargo, 'test', '--offline', '--locked', '--release', '--lib', '--all-features', 'record_contract_'], cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
actual = {f.stem: json.loads(f.read_text()) for f in sorted((out / 'records').glob('*.json'))}
expected = json.loads((ROOT / 'tests/fixtures/native-records.json').read_text())
assert actual == expected, 'Actual record contracts differ; do not refresh expectations automatically'
result = {'baseline_sha256': expected_sha, 'types': len(actual), 'cases': sum(map(len, actual.values())), 'mismatches': 0, 'scope': 'Actual application record decoding and compact/pretty encoding; synthetic inputs'}
(out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS', json.dumps(result))
