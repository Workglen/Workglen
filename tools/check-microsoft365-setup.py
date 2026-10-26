#!/usr/bin/env python3
"""Portable local Microsoft 365 setup/SMTP trace regression checks. No real mail or tenant calls."""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cargo', default='cargo')
p.add_argument('--output', type=pathlib.Path, default=ROOT / 'target/microsoft365-validation')
p.add_argument('--binary', type=pathlib.Path, help='Use an already validated executable; skip Rust tests, Clippy and build')
p.add_argument('--browser', action='store_true', help='Also run browser workflows using development-only Playwright/Chromium')
a = p.parse_args()
output = a.output.resolve()
output.mkdir(parents=True, exist_ok=True)
for tool in ['node', 'openssl']:
    if not shutil.which(tool):
        raise SystemExit(f'Missing development fixture tool: {tool}; no installation is performed by this check')
results = []


def run(name, args):
    print('CHECK', name, flush=True)
    start = time.monotonic()
    log = output / (name + '.txt')
    with log.open('w') as f:
        result = subprocess.run([str(arg) for arg in args], cwd=ROOT, stdout=f, stderr=subprocess.STDOUT)
    results.append({'check': name, 'exit_code': result.returncode,
                    'seconds': round(time.monotonic() - start, 2), 'log': log.name})
    (output / 'results.json').write_text(json.dumps({
        'scope': 'Synthetic local tests only; no live Microsoft tenant, DNS changes or real mail',
        'build_checks_skipped': bool(a.binary), 'browser_requested': a.browser,
        'results': results}, indent=2) + '\n')
    if result.returncode:
        print(log.read_text()[-8000:])
        raise SystemExit(f'FAILED {name}; see {log}')


run('first-party-dependencies', [sys.executable, ROOT / 'tools/check-first-party-dependencies.py', '--cargo', a.cargo])
if a.binary:
    binary = a.binary.resolve()
else:
    run('rust-tests', [a.cargo, 'test', '--offline', '--locked', '--workspace', '--all-features'])
    run('clippy', [a.cargo, 'clippy', '--offline', '--locked', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'])
    run('release-build', [a.cargo, 'build', '--offline', '--locked', '--release'])
    target = pathlib.Path(os.environ.get('CARGO_TARGET_DIR', str(ROOT / 'target')))
    binary = (ROOT / target if not target.is_absolute() else target) / 'release/workglen'
if not binary.is_file():
    raise SystemExit(f'Executable not found: {binary}')
run('microsoft365-plan', ['node', ROOT / 'security/tests/microsoft365-plan.cjs'])
if a.browser:
    for name in ['microsoft365', 'destinations', 'directory']:
        run(name + '-ui', ['node', ROOT / f'security/tests/{name}-ui.cjs', output / (name + '-ui.json')])
fixture = pathlib.Path(tempfile.mkdtemp(prefix='smtp-fixture-', dir=output))
try:
    run('native-network', ['node', ROOT / 'security/tests/native-network.cjs', binary, fixture] + (['--browser'] if a.browser else []))
except BaseException:
    print('Failed synthetic fixture retained for diagnosis:', fixture)
    raise
else:
    for name in ['network-results.json', 'browser-results.json', 'relay-check-results.json']:
        if (fixture / name).exists():
            shutil.copy2(fixture / name, output / name)
    shutil.rmtree(fixture)
print('PASS local Microsoft 365 setup checks:', output)
