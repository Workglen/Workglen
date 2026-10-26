#!/usr/bin/env python3
"""Compare native MIME charset decoding to the pinned former adapter, offline."""
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess, zipfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--baseline-zip', type=pathlib.Path, required=True)
p.add_argument('--cargo', default='cargo')
p.add_argument('--output', type=pathlib.Path, required=True)
a = p.parse_args(); out = a.output.resolve()
if out.exists() and any(out.iterdir()): raise SystemExit('--output must be empty')
assert hashlib.sha256(a.baseline_zip.read_bytes()).hexdigest() == 'b4592aa1dc9d95c31ac5e13ec46008347fb99cfd463d1266446d9af25a4e8769', 'Wrong pinned baseline ZIP'
(out / 'src').mkdir(parents=True)
with zipfile.ZipFile(a.baseline_zip) as archive:
    for source, dest in [('charset.rs','former.rs'), ('charset_tables.rs','charset_tables.rs')]:
        (out / 'src' / dest).write_bytes(archive.read('workglen/crates/native-mime/src/' + source))
pratique = out / 'pratique-source'
shutil.copytree(ROOT / 'vendor/pratique', pratique, ignore=shutil.ignore_patterns('target','target-*','__pycache__'))
manifest = pratique / 'Cargo.toml'
manifest.write_text(re.sub(r'(?ms)^\[\[(?:example|test)\]\]\n.*?(?=^\[|\Z)', '', manifest.read_text()))
(out / 'Cargo.toml').write_text('[package]\nname="charset-reference"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\nencoding_rs="=0.8.42"\npratique={path=' + json.dumps(str(pratique)) + ',default-features=false}\n')
(out / 'Cargo.lock').write_bytes((ROOT / 'tests/fixtures/charset-former-oracle.lock').read_bytes())
(out / 'src/main.rs').write_text((ROOT / 'tools/charset-reference.rs').read_text().replace('NATIVE_SOURCE', str(ROOT / 'crates/native-mime')))
env = os.environ.copy(); env['CARGO_TARGET_DIR'] = str(out / 'target')
with (out / 'build.txt').open('w') as log, (out / 'actual.txt').open('w') as actual:
    subprocess.run([a.cargo,'run','--offline','--locked','--release'], cwd=out, env=env, stdout=actual, stderr=log, check=True)
golden = ROOT / 'crates/native-mime/tests/charset-golden.txt'
assert (out / 'actual.txt').read_bytes() == golden.read_bytes(), 'Charset fingerprint changed; review rather than refresh'
counts = [int(line.split()[1]) for line in golden.read_text().splitlines()]
result = {'cases': sum(counts), 'label_groups': len(counts), 'mismatches': 0, 'former': 'encoding_rs 0.8.42 through pinned Workglen MIME adapter', 'native': 'first-party WHATWG decoder with existing MIME label/UTF behavior', 'golden_sha256': hashlib.sha256(golden.read_bytes()).hexdigest(), 'scope': 'Deterministic byte sweeps and synthetic states, not universal conformance or a security audit'}
(out / 'results.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS',json.dumps(result))
