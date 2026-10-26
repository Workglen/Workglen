#!/usr/bin/env python3
"""Offline, memory-only cargo-fuzz campaign with persisted seeds and results.

Prepare nightly Rust, cargo-fuzz and fuzz/Cargo.lock dependencies separately.
This script never installs tools, fetches dependencies, contacts a provider or
opens a network socket. No fuzzing dependency enters the application workspace.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = ['tls_client', 'tls_server', 'h2', 'x509']
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cargo', default='cargo')
p.add_argument('--nightly', default='nightly')
p.add_argument('--seconds', type=int, default=60)
p.add_argument('--target', choices=TARGETS)
p.add_argument('--output', type=pathlib.Path, default=ROOT / 'target/security-fuzz')
p.add_argument('--no-leak-check', action='store_true', help='Only for environments where LeakSanitizer process inspection is unsupported; ASan remains enabled')
a = p.parse_args()
if not 1 <= a.seconds <= 3600:
    p.error('--seconds must be 1..3600 per target')
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env['CARGO_NET_OFFLINE'] = 'true'
env['RUSTFLAGS'] = env.get('RUSTFLAGS', '') + ' --cfg pratique_fuzzing'
if a.no_leak_check:
    env['ASAN_OPTIONS'] = env.get('ASAN_OPTIONS', '') + ':detect_leaks=0'
results = []


def run(name, command, timeout=None):
    print('CHECK', name, flush=True)
    log = out / (name + '.txt')
    start = time.monotonic()
    with log.open('w') as f:
        try:
            code = subprocess.run([str(x) for x in command], cwd=ROOT, env=env,
                                  stdout=f, stderr=subprocess.STDOUT, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            code = 124
    text = log.read_text(errors='replace')
    executions = re.search(r'stat::number_of_executed_units:\s*(\d+)', text)
    results.append({'check': name, 'exit_code': code, 'seconds': round(time.monotonic()-start, 2),
                    'executed_inputs': int(executions[1]) if executions else None, 'log': log.name})
    (out / 'results.json').write_text(json.dumps({
        'scope': 'Memory-only local ASan and coverage-guided fuzzing; bounded campaign, not a security certification',
        'nightly': a.nightly, 'seconds_per_target': a.seconds,
        'leak_detection': not a.no_leak_check,
        'fuzz_lock_sha256': hashlib.sha256((ROOT / 'fuzz/Cargo.lock').read_bytes()).hexdigest(),
        'results': results}, indent=2) + '\n')
    if code:
        print(text[-6000:])
        raise SystemExit(f'FAILED {name}; retain the corpus, artifacts and log in {out}')


run('fuzzer-version', [a.cargo, '+' + a.nightly, 'fuzz', '--version'])
run('seed-replay', [a.cargo, 'run', '--offline', '--locked', '--release',
                   '--manifest-path', ROOT / 'fuzz/replay/Cargo.toml', '--', 'seeds', out / 'corpus'])
run('fuzz-build', [a.cargo, '+' + a.nightly, 'fuzz', 'build', '--codegen-units', '16',
                  '--target-dir', out / 'build'])
for target in [a.target] if a.target else TARGETS:
    # cargo-fuzz supplies the target triple/build path and uses the same build
    # flags. Its child fuzzer has its own deadline, RSS cap and per-input timeout.
    artifacts = out / 'artifacts' / target
    artifacts.mkdir(parents=True, exist_ok=True)
    run(target, [a.cargo, '+' + a.nightly, 'fuzz', 'run', target, out / 'corpus' / target,
                 '--codegen-units', '16', '--target-dir', out / 'build', '--',
                 f'-max_total_time={a.seconds}', '-timeout=10', '-rss_limit_mb=512',
                 '-max_len=65536', '-seed=20261026', '-print_final_stats=1',
                 '-detect_leaks=' + ('0' if a.no_leak_check else '1'),
                 '-artifact_prefix=' + str(artifacts) + '/'], timeout=a.seconds + 120)
print('PASS bounded security fuzz campaign:', out / 'results.json')
