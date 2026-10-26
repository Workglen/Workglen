#!/usr/bin/env python3
"""Deterministic JSON/schema/float inputs. Standard library only, no network."""
import json,random,struct,math
r=random.Random(0x1da72511);n=0
def emit(kind,**payload):
 global n
 print(json.dumps({'label':f'{kind}-{n}','kind':kind,**payload},ensure_ascii=True));n+=1
edge=['null','true','false','0','-0','-0.0','1.0','1e0','1E+0002','1e-0002','18446744073709551615','18446744073709551616','-9223372036854775808','340282366920938463463374607431768211455','340282366920938463463374607431768211456','1e9999','1e-9999','1e+','+1','01','-01','1.','NaN','Infinity','"é😀"','"\\uD83D\\uDE00"','"\\uD800"','"\\uDC00"','"\\uD800x"','"\\u0000"','"\\x41"','\ufeff{}','{"x":1,"x":2}','{"x":1,"\\u0078":2}','[1,]','{"a":1,}','{"a":1} true','', '  {}\n','"line\nraw"']
for s in edge:
 for kind in ['value','i64','u64','i128','u128','f64','f32']:emit(kind,raw=s)
for depth in [1,31,32,63,126,127,128,129,256]:emit('value',raw='['*depth+'0'+']'*depth)
for i in range(12000):
 sign=r.choice(['','-']);digits=str(r.randrange(10**r.randrange(1,45)));fraction=r.choice(['','.'+str(r.randrange(10**r.randrange(1,20)))]);exponent=r.choice(['',r.choice('eE')+r.choice(['','+','-'])+str(r.randrange(0,400))]);s=sign+digits+fraction+exponent
 emit('value',raw=s)
 if i<2000:
  for kind in ['i64','u64','i128','u128','f64','f32']:emit(kind,raw=s)
for i in range(30000):emit('float64',bits=r.getrandbits(64))
for i in range(10000):emit('float32',bits=r.getrandbits(32))
for v in [0,1,0x8000000000000000,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000001,0x0010000000000000,0x000fffffffffffff,0x7fefffffffffffff]:emit('float64',bits=v)
for s in ['{"z":18446744073709551615,"a":"é😀"}','{"a":"x","z":0,"optional":null,"items":[-32768,32767]}','{"z":1,"a":"x","disabled":true}','{"z":1,"a":"x","extra":false}','{"z":1,"a":"x","z":2}','{"z":1,"a":"x","\\u0061":"y"}','{"z":1,"a":"x","items":null}','{"z":1,"a":"x","items":[32768]}','{"z":1,"a":"x","optional":1}','{"a":"x"}','[1,"x",null,[],false]']:emit('record',raw=s)
seed=['null','true','false','{"x":[1,2,"abc"]}','{"z":7,"a":"x","items":[-3,9]}','"\\uD83D\\uDE00"','1.05e-2']
for i in range(8000):
 s=bytearray(r.choice(seed).encode());at=r.randrange(len(s));mode=i%3
 if mode==0:s[at]=r.randrange(128)
 elif mode==1:del s[at]
 else:s[at:at]=bytes([r.randrange(128)])
 emit('record'if i%4==0 else'value',raw=s.decode('utf8'))

for kind,pack,unpack in [('float64','>d','>Q'),('float32','>f','>I')]:
 for exponent in range(-40,39):
  v=10.0**exponent
  for sign in [1,-1]:
   try:bits=struct.unpack(unpack,struct.pack(pack,sign*v))[0]
   except OverflowError:continue
   for delta in [-1,0,1]:emit(kind,bits=bits+delta)
for s in ['{"$serde_json::private::Number":"1.0"}','{"$serde_json::private::Number":"bad"}','{"$serde_json::private::RawValue":"[]"}']:emit('value',raw=s)
