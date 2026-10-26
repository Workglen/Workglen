#!/usr/bin/env python3
"""Independently verify reviewed numeric/object differences with exact rationals."""
import argparse,fractions,json,math,pathlib,struct
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--differences',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'tests/fixtures/native-json-reviewed.json');a=p.parse_args();rows=json.loads(a.differences.read_text());counts={'nearest_even_f64':0,'ordinary_object_keys':0}
for row in rows:
 inp,old,new=row['input'],row['former'],row['native']
 if inp['kind']=='f64':
  assert old['valid']is True and new['valid']is True
  exact=fractions.Fraction(inp['raw']);candidate=float(new['compact']);assert math.isfinite(candidate)
  assert struct.pack('>d',candidate)==struct.pack('>d',float(inp['raw'])),'CPython parser disagrees'
  distance=abs(fractions.Fraction.from_float(candidate)-exact)
  for adjacent in [math.nextafter(candidate,-math.inf),math.nextafter(candidate,math.inf)]:
   if not math.isfinite(adjacent):continue
   other=abs(fractions.Fraction.from_float(adjacent)-exact);assert distance<=other
   if distance==other:assert struct.unpack('>Q',struct.pack('>d',candidate))[0]%2==0,'not ties-to-even'
  counts['nearest_even_f64']+=1
 else:
  assert inp['kind']=='value'and set(json.loads(inp['raw']))=={'$serde_json::private::Number'}
  assert json.loads(inp['raw'])==json.loads(new['compact']);assert new['i64']is None and new['u64']is None
  counts['ordinary_object_keys']+=1
print(json.dumps({'reviewed_differences':len(rows),'checks':counts,'independent_checks':'Exact rational distance to adjacent IEEE-754 values and CPython parsing/object preservation','passed':True},indent=2))
