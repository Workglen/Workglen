#!/usr/bin/env python3
"""Portable offensive-review regressions; synthetic offline/loopback only."""
import argparse
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cargo', default='cargo')
p.add_argument('--output', type=pathlib.Path, default=ROOT / 'target/resilience-validation')
p.add_argument('--skip-source-integrity', action='store_true', help='Only for intentional local edits')
p.add_argument('--browser', action='store_true', help='Use preinstalled Playwright/Chromium for browser regressions')
p.add_argument('--fuzz-seconds', type=int, default=0, help='Also run ASan fuzzing for this many seconds per target (0 skips)')
a = p.parse_args()
output = a.output.resolve()
output.mkdir(parents=True, exist_ok=True)
checks = []


def run(name, command):
    print('CHECK', name, flush=True)
    code = subprocess.run([str(s) for s in command], cwd=ROOT).returncode
    checks.append({'check': name, 'exit_code': code})
    (output / 'results.json').write_text(json.dumps({
        'scope': 'Synthetic offline and loopback checks; no live mail, DNS provider or tenant tests',
        'checks': checks, 'browser_requested': a.browser,
        'fuzz_seconds_per_target': a.fuzz_seconds}, indent=2) + '\n')
    if code:
        raise SystemExit(code)


native = [sys.executable, ROOT / 'tools/check-native-replacements.py', '--cargo', a.cargo, '--output', output / 'native']
if a.skip_source_integrity:
    native.append('--skip-source-integrity')
run('native-regressions', native)
target = pathlib.Path(os.environ.get('CARGO_TARGET_DIR', str(ROOT / 'target')))
if not target.is_absolute():
    target = ROOT / target
gateway = [sys.executable, ROOT / 'tools/check-microsoft365-setup.py', '--cargo', a.cargo,
           '--binary', target / 'release/workglen', '--output', output / 'gateway']
if a.browser:
    gateway.append('--browser')
run('security-gateway-regressions', gateway)
if a.fuzz_seconds:
    run('coverage-guided-fuzzing', [sys.executable, ROOT / 'tools/check-security-fuzz.py', '--cargo', a.cargo,
                                   '--seconds', a.fuzz_seconds, '--output', output / 'fuzz'])
print('PASS resilience regressions:', output)
