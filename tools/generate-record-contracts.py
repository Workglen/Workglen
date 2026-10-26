#!/usr/bin/env python3
"""Generate actual-record compatibility tests from the reviewed schema ledger.
Requires the preceding source ZIP to recover original top-level type boundaries.
--former writes only into an isolated extracted reference tree supplied by caller.
"""
import argparse,json,pathlib,re,zipfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--baseline-zip',type=pathlib.Path,required=True);p.add_argument('--root',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]);p.add_argument('--former',action='store_true');a=p.parse_args();ROOT=pathlib.Path(__file__).resolve().parents[1];dest=a.root.resolve()
ledger=json.loads((ROOT/'validation/0.8-native-data-schema-ledger.json').read_text());original={}
with zipfile.ZipFile(a.baseline_zip)as z:
 for e in ledger:
  if e['file'].startswith('src/'):original[e['file']]=z.read('workglen/'+e['file']).decode()
entries=[e for e in ledger if e['decode']and e['file'].startswith('src/')and re.search(r'^(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum) '+e['type']+r'\b',original[e['file']],re.M)]
def resolve(t,owner):
 name=t.split('::')[-1]
 if t.startswith('crate::'):
  module='/'.join(t.split('::')[1:-1]);module='accounting/db'if module=='accounting'and name=='Config'else module
  exact=[e for e in entries if e['type']==name and e['file']in ['src/'+module+'.rs','src/'+module+'/mod.rs']]
  if exact:return exact[0]
 if t.startswith('super::'):
  file=str(pathlib.PurePosixPath(owner['file']).parent/('/'.join(t.split('::')[1:-1])+'.rs'))
  exact=[e for e in entries if e['type']==name and e['file']==file]
  if exact:return exact[0]
 same=[e for e in entries if e['type']==name and e['file']==owner['file']]
 if same:return same[0]
 choices=[e for e in entries if e['type']==name]
 if len(choices)==1:return choices[0]
 raise ValueError(('ambiguous type',t,owner))
def seed(t,owner,depth=0):
 if depth>10:raise ValueError('recursive schema')
 if t.startswith('Option<'):return None
 if t.startswith('Vec<'):
  inner=t[4:-1];return [seed(inner,owner,depth+1)]if inner in ['String','u8','i64','Value']or inner.endswith('IpAddr')else[]
 if t.startswith('BTreeMap<'):return {}
 if t in ['String',"&'static str"]:return 'sample-é😀'
 if t in ['Value','serde_json::Value']:return {'z':[1,True,None],'a':'sample'}
 if t=='bool':return True
 if t.startswith('u')and t[1:].isdigit():return (1<<int(t[1:]))-1
 if t=='usize':return 65535
 if t=='i64':return -(1<<63)
 if t.endswith('SocketAddr'):return '127.0.0.1:12345'
 if t.endswith('IpAddr'):return '127.0.0.1'
 if t=='(IpAddr, u16)':return ['127.0.0.1',12345]
 e=resolve(t,owner)
 if e['kind']=='enum':
  v=e['variants'][0];return re.sub(r'(?<!^)([A-Z])',r'-\1',v).lower()if 'kebab-case'in e['attributes']else v.lower()if 'lowercase'in e['attributes']else v
 return {f['name'].removeprefix('r#'):seed(f['type'],e,depth+1)for f in e['fields']}
def dumps(v):return json.dumps(v,ensure_ascii=True,separators=(',',':'))
byfile={};count=0
for e in entries:
 name=e['type'];identifier=e['file'].replace('/','_').replace('.rs','')+'_'+name
 if e.get('manual'):
  reference={'folder':'Inbox','validity':1,'uid':2};cases=[{'action':'folders'},{'action':'list','folder':'Inbox'},{'action':'read','message':reference},{'action':'attachment','message':reference,'index':0},{'action':'flag','message':reference},{'action':'move','message':reference,'target':'Trash'},{'action':'send','draft':{'id':'x','to':[],'subject':'x','text':'y'}},{'action':'folders','extra':1},{'action':'unknown'},['folders'],['folders',1],['list','Inbox',None],['list','Inbox'],['list',{'folder':'Inbox'}],['read',reference],['flag',reference,None,None],{'action':'list','folder':'Inbox','extra':1}];raws=[dumps(v)for v in cases];raws.append('{"action":"folders","action":"list"}')
 elif e['kind']=='enum':
  v=seed(name,e);raws=[dumps(v),'"invalid"','null',dumps({v:None}),dumps({v:{}})]
 else:
  base={f['name'].removeprefix('r#'):seed(f['type'],e)for f in e['fields']};raws=[dumps(base),'{}',dumps(list(base.values())),dumps({**base,'unexpected_field':1})]
  minimal={k:v for k,v in base.items()if not next('default'in ' '.join(f['attributes'])or f['type'].startswith('Option<')or 'default'in e['attributes']for f in e['fields']if f['name'].removeprefix('r#')==k)};raws.append(dumps(minimal))
  for f in e['fields']:
   key=f['name'].removeprefix('r#');missing={k:v for k,v in base.items()if k!=key};raws.append(dumps(missing));raws.append(dumps({**base,key:'wrong'if f['type']!='String'else False}));raws.append(dumps(base)[:-1]+','+dumps(key)+':'+dumps(base[key])+'}')
   if f['type'].startswith('Option<'):raws.append(dumps({**base,key:seed(f['type'][7:-1],e)}))
  raws=list(dict.fromkeys(raws))
 code=''
 if not a.former and not e['encode']:
  if e.get('manual'):
   code+='''impl pratique::data::Encode for Command {fn encode(&self)->Result<pratique::data::Node,pratique::data::Error>{use pratique::data::{Node,Kind};let(a,mut fields)=match self {
Self::Folders=>("folders",vec![]),Self::List{folder,before}=>("list",vec![("folder".into(),folder.encode()?),("before".into(),before.encode()?)]),Self::Read{message}=>("read",vec![("message".into(),message.encode()?)]),Self::Attachment{message,index}=>("attachment",vec![("message".into(),message.encode()?),("index".into(),index.encode()?)]),Self::Flag{message,seen,starred}=>("flag",vec![("message".into(),message.encode()?),("seen".into(),seen.encode()?),("starred".into(),starred.encode()?)]),Self::Move{message,target}=>("move",vec![("message".into(),message.encode()?),("target".into(),target.encode()?)]),Self::Send{draft}=>("send",vec![("draft".into(),draft.encode()?)])};fields.insert(0,("action".into(),a.encode()?));Ok(Node::new(Kind::Object(fields)))}}
'''
  elif e['kind']=='struct':code+='pratique::data_encode!('+name+'{'+','.join(f['name']for f in e['fields'])+'});\n'
  else:
   mapping=[]
   for variant in e['variants']:
    wire=re.sub(r'(?<!^)([A-Z])',r'-\1',variant).lower()if 'kebab-case'in e['attributes']else variant.lower()if 'lowercase'in e['attributes']else variant;mapping.append('Self::'+variant+'=>"'+wire+'"')
   code+='impl pratique::data::Encode for '+name+'{fn encode(&self)->Result<pratique::data::Node,pratique::data::Error>{pratique::data::Encode::encode(match self{'+','.join(mapping)+'})}}\n'
 code+='#[test]\nfn record_contract_'+name.lower()+'(){crate::data_contracts::check::<'+name+'>('+dumps(identifier)+', &['+','.join('r###"'+s+'"###'for s in raws)+']);}\n'
 byfile.setdefault(e['file'],[]).append(code);count+=len(raws)
for file,codes in byfile.items():
 p=dest/file;s=p.read_text().split('// BEGIN GENERATED RECORD CONTRACTS')[0].rstrip()
 if a.former:
  # Only the isolated former tree gains test-only Encode visibility for types
  # that originally derived Deserialize alone; normal runtime source is untouched.
  s=re.sub(r'#\[derive\(([^)]*)\)\]',lambda m:m[0]if'Serialize'in m[1]or'Deserialize'not in m[1]else'#[derive('+m[1]+', serde::Serialize)]',s)
 s+='\n// BEGIN GENERATED RECORD CONTRACTS\n#[cfg(test)]\nmod record_contracts {\nuse super::*;\n'+''.join(codes)+'}\n';p.write_text(s)
helper='''//! Actual application record contracts from the pinned previous source.
use JSON::{self as json,Value,json};
pub(crate) fn check<T:DECODE+ENCODE>(name:&str,inputs:&[&str]){
 let cases:Vec<Value>=inputs.iter().map(|raw|{let result=match json::from_str::<T>(raw){Ok(v)=>json!({"valid":true,"compact":json::to_string(&v).unwrap(),"pretty":json::to_string_pretty(&v).unwrap()}),Err(_)=>json!({"valid":false})};json!({"raw":raw,"result":result})}).collect();
 if let Ok(path)=std::env::var("WORKGLEN_RECORD_EXPORT"){std::fs::create_dir_all(&path).unwrap();std::fs::write(std::path::Path::new(&path).join(format!("{name}.json")),json::to_vec_pretty(&cases).unwrap()).unwrap();}
 else{let expected:Value=json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/fixtures/native-records.json"))).unwrap();let actual=json::to_value(cases).unwrap();assert_eq!(actual.as_array().unwrap().len(),expected[name].as_array().unwrap().len());for(got,want)in actual.as_array().unwrap().iter().zip(expected[name].as_array().unwrap()){assert_eq!(got,want,"record schema {name}; input {}",got["raw"]);}}
}
'''
helper=helper.replace('JSON','serde_json'if a.former else'pratique::json_value').replace('DECODE','serde::de::DeserializeOwned'if a.former else'pratique::data::Decode').replace('ENCODE','serde::Serialize'if a.former else'pratique::data::Encode');(dest/'src/data_contracts.rs').write_text(helper)
p=dest/'src/lib.rs';s=p.read_text();s=s.replace('\n#[cfg(test)]\nmod data_contracts;','');p.write_text(s+'\n#[cfg(test)]\nmod data_contracts;\n')
fixture=dest/'tests/fixtures/native-records.json'
if not fixture.exists():fixture.write_text('{}\n')
print(json.dumps({'types':len(entries),'cases':count,'files':len(byfile)}))
