#!/usr/bin/env python3
"""Regenerate attributed MIME data from bundled official inputs, without network."""
import argparse, hashlib, json
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('--check',action='store_true'); a=p.parse_args()
r=Path(__file__).resolve().parents[1]
outputs={}
s='// Generated from Unicode mapping data. See data/LICENSE-UNICODE.\n'
for name,file in [('CP850','cp850.txt'),('ISO8859_16','iso8859-16.txt')]:
    t=list(range(256))
    for line in (r/'data'/file).read_text().splitlines():
        v=line.split('#')[0].split()
        if len(v)>=2 and v[0].startswith('0x') and v[1].startswith('0x'): t[int(v[0],16)]=int(v[1],16)
    s+=f'pub const {name}: &[u32; 256] = &[\n'+''.join('    '+','.join(hex(v) for v in t[i:i+16])+',\n' for i in range(0,256,16))+'];\n'
outputs['src/charset_tables.rs']=s
entities=json.loads((r/'data/entities.json').read_text())
def rust(s): return '"'+''.join('\\u{'+format(ord(c),'x')+'}' for c in s)+'"'
outputs['src/html_entities.rs']='// Generated from WHATWG HTML entities. See data/LICENSE-HTML (BSD-3-Clause for code).\npub const ENTITIES: &[(&str, &str)] = &[\n'+''.join(f'    ({json.dumps(k[1:])}, {rust(v["characters"])}),\n' for k,v in sorted(entities.items()))+'];\n'
# WHATWG scalar mappings and labels are data, not an imported codec implementation.
indexes=json.loads((r/'data/indexes.json').read_text())
labels=sorted((label,encoding['name']) for group in json.loads((r/'data/encodings.json').read_text()) for encoding in group['encodings'] for label in encoding['labels'])
t='// Generated from official WHATWG Encoding data. See data/LICENSE-WHATWG.\n'
t+='pub const LABELS: &[(&str,&str)] = &[\n'+''.join('    ('+json.dumps(k)+','+json.dumps(v)+'),\n'for k,v in labels)+'];\n'
for name,values in indexes.items():
    if name=='iso-2022-jp-katakana':continue # Encoder-only table; this library decodes MIME text.
    symbol=name.upper().replace('-','_')
    if name=='gb18030-ranges':
        t+='pub const GB18030_RANGES: &[(u32,u32)] = &[\n'+''.join(f'    ({a},{b}),\n'for a,b in values)+'];\n'
    else:
        t+='pub const '+symbol+': &[u32] = &[\n'+''.join('    '+','.join('0xffffffff'if n is None else hex(n)for n in values[i:i+16])+',\n'for i in range(0,len(values),16))+'];\n'
t+='pub fn single_byte(name:&str)->Option<&\'static [u32]>{Some(match name{\n'
for name,values in indexes.items():
    if len(values)==128:t+=json.dumps(name.upper()if name.startswith(('iso-','koi8','ibm'))else name)+'=>'+name.upper().replace('-','_')+',\n'
t+='"ISO-8859-8-I"=>ISO_8859_8,_=>return None})}\n'
outputs['src/charset_whatwg_tables.rs']=t
outputs['data/SHA256.json']=json.dumps({x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in sorted((r/'data').iterdir()) if x.name!='SHA256.json'},indent=2)+'\n'
for file,text in outputs.items():
    path=r/file
    if a.check:
        if not path.exists() or path.read_text()!=text: raise SystemExit('stale generated data: '+file)
    else: path.write_text(text)
print('MIME data generation verified' if a.check else 'MIME data generated')
