#!/usr/bin/env python3
"""Package source with SHA-256 manifests, or verify an existing source ZIP."""
import argparse,hashlib,json,pathlib,zipfile
p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True);g.add_argument('--output',type=pathlib.Path);g.add_argument('--check',type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
if a.output:
    archive=a.output.resolve()
    if archive.is_relative_to(root):raise SystemExit('Use an output path outside the source directory')
    archive.parent.mkdir(parents=True,exist_ok=True)
    paths=sorted(x for x in root.rglob('*')if x.is_file()and not any(v in {'target','__pycache__','.git'}or v.startswith('target-')for v in x.relative_to(root).parts)and x.name not in {'SOURCE-SHA256','SOURCE-SHA256.json'}and not x.name.endswith('.pyc'))
    manifest={str(x.relative_to(root)):hashlib.sha256(x.read_bytes()).hexdigest()for x in paths}
    (root/'SOURCE-SHA256.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (root/'SOURCE-SHA256').write_text(''.join(f'{sha}  {name}\n'for name,sha in manifest.items()))
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9)as z:
        for path in paths+[root/'SOURCE-SHA256',root/'SOURCE-SHA256.json']:z.write(path,'workglen/'+str(path.relative_to(root)))
else:archive=a.check.resolve()
with zipfile.ZipFile(archive)as z:
    assert z.testzip()is None,'ZIP CRC mismatch'
    names=z.namelist();assert len(names)==len(set(names)),'duplicate ZIP paths'
    manifest=json.loads(z.read('workglen/SOURCE-SHA256.json'))
    expected={'workglen/'+name for name in manifest}|{'workglen/SOURCE-SHA256','workglen/SOURCE-SHA256.json'}
    assert set(names)==expected,'ZIP membership differs from manifest'
    for name,sha in manifest.items():
        assert not pathlib.PurePosixPath(name).is_absolute() and '..'not in pathlib.PurePosixPath(name).parts,'unsafe path'
        assert hashlib.sha256(z.read('workglen/'+name)).hexdigest()==sha,'source hash: '+name
    assert z.read('workglen/SOURCE-SHA256').decode()==''.join(f'{sha}  {name}\n'for name,sha in manifest.items())
print(json.dumps({'archive':str(archive),'files':len(names),'bytes':archive.stat().st_size,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'integrity':'passed'},indent=2))
