#!/usr/bin/env python3
"""Package/verify the tracked Pratique handoff, including patches and test evidence."""
import argparse,hashlib,json,pathlib,subprocess,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/'upstream/pratique'
p=argparse.ArgumentParser(description=__doc__)
g=p.add_mutually_exclusive_group(required=True)
g.add_argument('--output',type=pathlib.Path)
g.add_argument('--check',type=pathlib.Path)
a=p.parse_args();prefix='pratique-workglen-upstream-updates/'
if a.output:
    archive=a.output.resolve()
    if archive.is_relative_to(ROOT):raise SystemExit('Output must be outside the source tree')
    subprocess.run([sys.executable,str(SOURCE/'verify.py'),'--vendor',str(ROOT/'vendor/pratique')],check=True)
    files={str(f.relative_to(SOURCE)):f.read_bytes()for f in sorted(SOURCE.rglob('*'))if f.is_file()and '__pycache__'not in f.parts and not f.name.endswith('.pyc')}
    hashes={name:hashlib.sha256(data).hexdigest()for name,data in files.items()}
    files['SOURCE-SHA256.json']=(json.dumps(hashes,indent=2)+'\n').encode()
    archive.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9)as z:
        for name,data in files.items():z.writestr(prefix+name,data)
else:archive=a.check.resolve()
with zipfile.ZipFile(archive)as z:
    assert z.testzip()is None,'ZIP CRC mismatch'
    names=z.namelist();assert len(names)==len(set(names)),'Duplicate path'
    hashes=json.loads(z.read(prefix+'SOURCE-SHA256.json'))
    assert set(names)=={prefix+n for n in hashes}|{prefix+'SOURCE-SHA256.json'},'ZIP membership mismatch'
    for name,want in hashes.items():
        assert not pathlib.PurePosixPath(name).is_absolute()and '..'not in pathlib.PurePosixPath(name).parts,'Unsafe path'
        assert hashlib.sha256(z.read(prefix+name)).hexdigest()==want,name
print(json.dumps({'archive':str(archive),'files':len(names),'bytes':archive.stat().st_size,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'integrity':'passed'},indent=2))
