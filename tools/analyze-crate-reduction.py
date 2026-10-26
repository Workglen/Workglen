#!/usr/bin/env python3
"""Project package removals from the pinned graph; does not edit Cargo files."""
import argparse,hashlib,json,pathlib,tomllib
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];lock=root/'Cargo.lock';packages=tomllib.loads(lock.read_text())['package'];by_name={}
for package in packages:by_name.setdefault(package['name'],[]).append((package['name'],package['version']))
graph={};first=set()
for package in packages:
    key=(package['name'],package['version']);edges=set()
    if 'source'not in package:first.add(key)
    for dependency in package.get('dependencies',[]):
        fields=dependency.split()
        if len(fields)>1:target=(fields[0],fields[1])
        else:
            assert len(by_name[fields[0]])==1,'ambiguous unversioned dependency'
            target=by_name[fields[0]][0]
        edges.add(target)
    graph[key]=edges
assert all(target in graph for edges in graph.values()for target in edges)
external=set(graph)-first

def project(cut):
    seen=set();pending=list(first)
    while pending:
        node=pending.pop()
        if node in seen:continue
        seen.add(node);pending.extend(target for target in graph[node]if target[0]not in cut)
    removed=external-seen
    return {'replace':sorted(cut),'removed_count':len(removed),'remaining_external_versions':len(external)-len(removed),'removed':[{'name':name,'version':version}for name,version in sorted(removed)]}
assert not project(set())['removed'],'baseline contains unreachable entries; review before projecting'
scenarios=[{'toml'},{'tokio'},{'encoding_rs'},{'argon2'},{'redb'},{'serde_derive'},{'toml','tokio'},{'toml','tokio','encoding_rs'}]
result={'date':'2026-10-26','cargo_lock_sha256':hashlib.sha256(lock.read_bytes()).hexdigest(),'baseline_external_versions':len(external),'method':'Remove every edge to the replaced package(s), retain all first-party workspace/path packages, then count unreachable external package versions. Shared dependencies remain. No Cargo resolution or behavior validation is claimed.','assumptions':['Replacement code adds no new external packages.','All production, test, feature and platform uses of each removed package are replaced.','Final savings must be confirmed by the regenerated Cargo graph and portable checks.'],'scenarios':[project(s)for s in scenarios]}
text=json.dumps(result,indent=2)+'\n'
if a.output:a.output.write_text(text)
print(text,end='')
