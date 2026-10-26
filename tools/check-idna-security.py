#!/usr/bin/env python3
"""Optional Python IDNA2008 policy reference; not an application dependency."""
import argparse,json,pathlib
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path);a=p.parse_args()
try:import idna
except ImportError:raise SystemExit('This optional reference check requires Python idna 3.19 in an isolated development environment; native checks need no Python idna.')
if idna.__version__!='3.19':raise SystemExit('Reference version is pinned to Python idna 3.19; review differences before updating it.')
cases=[('a·b.test',None),('l·l.test','xn--ll-0ea.test'),('😀.test',None),('раypal.com','xn--ypal-43d9g.com'),('faß.de','xn--fa-hia.de'),('a\u200db.test',None)]
rows=[]
for domain,want in cases:
    try:got=idna.encode(domain,uts46=True).decode();error=None
    except idna.IDNAError as e:got=None;error=type(e).__name__
    assert got==want,(domain,got,want)
    rows.append({'input':domain,'ascii':got,'error':error})
result={'reference':'Python idna '+idna.__version__,'unicode_data':idna.idnadata.__version__,'scope':'Selected stable policy examples only; native UTS #46 uses Unicode 18, so this is not a complete Unicode-version comparison','cases':rows}
text=json.dumps(result,indent=2,ensure_ascii=True)+'\n'
if a.output:a.output.write_text(text)
print(text,end='')
