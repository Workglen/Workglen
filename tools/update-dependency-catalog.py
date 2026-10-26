#!/usr/bin/env python3
from pathlib import Path
import json,collections,hashlib
import argparse,subprocess
p=argparse.ArgumentParser(description="Refresh catalog after an explicitly reviewed graph change; does not approve dependency policy.")
p.add_argument('--cargo',default='cargo');a=p.parse_args()
r=Path(__file__).resolve().parents[1];meta=json.loads(subprocess.check_output([a.cargo,'metadata','--offline','--locked','--all-features','--format-version','1'],cwd=r));old=json.loads((r/'validation/0.8-dependency-catalog.json').read_text());purposes={(p['name'],p['version']):p['purpose']for p in old['packages']}
packages={p['id']:p for p in meta['packages']};nodes={p['id']:p for p in meta['resolve']['nodes']};app=meta['resolve']['root'];direct={d['pkg']for d in nodes[app]['deps']};paths=collections.defaultdict(set);parents=collections.defaultdict(list)
for pid,node in nodes.items():
 for dep in node['deps']:
  for kind in dep['dep_kinds']:parents[dep['pkg']].append({'name':packages[pid]['name'],'version':packages[pid]['version'],'edge_kind':kind['kind']or'normal','target_condition':kind['target']})
for d in nodes[app]['deps']:
 seen=set();pending=[d['pkg']];name=packages[d['pkg']]['name']
 while pending:
  pid=pending.pop()
  if pid in seen:continue
  seen.add(pid);paths[pid].add(name);pending.extend(d['pkg']for d in nodes[pid]['deps'])
first=[];external=[]
for pid,p in packages.items():
 if p['source']is None:first.append({'name':p['name'],'version':p['version'],'purpose':p.get('description')or'Bounded first-party recursive DNS client'});continue
 external.append({'name':p['name'],'version':p['version'],'relationship':'direct'if pid in direct else'transitive','purpose':purposes.get((p['name'],p['version']),p.get('description')or''),'used_through_direct_dependencies':sorted(paths[pid]),'source':'crates.io registry','immediate_parents':sorted(parents[pid],key=lambda x:(x['name'],x['version'],x['edge_kind'],x['target_condition']or'')),'enabled_features':nodes[pid]['features'],'procedural_macro':any('proc-macro'in t['kind']for t in p['targets'])})
external.sort(key=lambda p:(p['name'],p['version']));first.sort(key=lambda p:p['name']);sha=hashlib.sha256((r/'Cargo.lock').read_bytes()).hexdigest();assert len(external)==15 and len(first)==7
result={'date':'2026-10-26','cargo_lock_sha256':sha,'external_package_versions':15,'registry_package_versions':15,'direct_external_crates':sum(p['relationship']=='direct'for p in external),'scope':old['scope'],'first_party_packages':first,'packages':external}
(r/'validation/0.8-dependency-catalog.json').write_text(json.dumps(result,indent=2)+'\n')
s='''# Full crate catalog — October 26, 2026

This checkpoint has **15 external package versions**, **3 direct external crates**
and **22 total Cargo.lock entries**, including seven first-party packages.
All six reusable first-party libraries have zero external dependencies, including
optional, development, build and platform edges. The root application retains
its separately reviewed database/password dependencies.

| Completed checkpoint | Removed | Remaining external versions |
| --- | ---: | ---: |
| mail-auth | 17 | 79 |
| IDNA / ICU | 25 | 54 |
| Email / MIME | 3 | 51 |
| TOML | 10 | 41 |
| Tokio | 8 | 33 |
| Serde / serde_json | 11 | 22 |
| Native MIME charsets | 7 | 15 |

This removes 81 package versions from the 96-package baseline. No registry
package was added or upgraded; retained checksums are unchanged. JSON remains
the interchange/storage format; its implementation and explicit typed schemas
are now first-party. Legacy charset support remains through native decoders.
Additional IDNA security capabilities remain deferred under SEC-IDNA-04.
See NATIVE-DATA.md, NATIVE-CHARSETS.md, PRATIQUE-UPSTREAM.md and PORTABLE-CHECKS.md.

The former simdutf8 entry incorrectly described an Android-only purpose. It was
encoding_rs's CPU SIMD UTF-8 helper on x86/ARM64, including Linux and macOS.
Both crates are now removed from the application and workspace test graph.

Counts cover all target/build/test dependencies; they are not runtime size
measurements or a vulnerability audit.

## First-party crates

| Crate | Version | Purpose |
| --- | --- | --- |
'''
for p in first:s+=f"| `{p['name']}` | {p['version']} | {p['purpose']} |\n"
s+='\n## Direct external crates\n\n| Crate | Pinned version | Purpose |\n| --- | --- | --- |\n'
for p in external:
 if p['relationship']=='direct':s+=f"| `{p['name']}` | {p['version']} | {p['purpose']} |\n"
s+='\n## All transitive crates\n\nShared packages remain until every consumer releases them. Exact parents,\nfeatures and target conditions are in `validation/0.8-dependency-catalog.json`.\n\n| Crate | Pinned version | Purpose | Included through |\n| --- | --- | --- | --- |\n'
for p in external:
 if p['relationship']=='transitive':s+=f"| `{p['name']}` | {p['version']} | {p['purpose']} | {', '.join('`'+n+'`'for n in p['used_through_direct_dependencies'])} |\n"
(r/'DEPENDENCY-CATALOG.md').write_text(s)
licenses={'review_date':'2026-10-26','scope':'All lockfile package declarations; existing notices retained, not a full source provenance audit. TOML test corpus is MIT; retain tests/fixtures/toml-test/LICENSE.','cargo_lock_sha256':sha,'package_count':22,'registry_count':15,'packages':[{'name':p['name'],'version':p['version'],'source':p['source']or'first-party path','license':p['license']}for p in sorted(packages.values(),key=lambda p:(p['name'],p['version']))]}
(r/'validation/0.8-license-inventory.json').write_text(json.dumps(licenses,indent=2)+'\n');print('15 external, 22 total, 3 direct; inventory refreshed')
