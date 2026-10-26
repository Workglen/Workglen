// SPDX-License-Identifier: Apache-2.0
// Workglen development harness; run only in an isolated prior source checkout.
// See NATIVE-MAILAUTH.md; not part of the deployed dependency graph.
use std::{collections::HashMap,borrow::Borrow,hash::Hash,time::Instant};
use mail_auth::{AuthenticatedMessage,MessageAuthenticator,Parameters,ResolverCache,Txt,AuthenticationResults,ArcOutput,common::{crypto::Ed25519Key,parse::TxtRecordParser,verify::DomainKey,headers::HeaderWriter},dkim2::{Dkim2Signer,Hop,Envelope},arc::ArcSealer};
struct Closed(HashMap<Box<str>,Txt>);
impl ResolverCache<Box<str>,Txt> for Closed {
 fn get<Q>(&self,n:&Q)->Option<Txt> where Box<str>:Borrow<Q>,Q:Hash+Eq+?Sized {Some(self.0.get(n).expect("unprovisioned reference lookup").clone())}
 fn remove<Q>(&self,_:&Q)->Option<Txt>where Box<str>:Borrow<Q>,Q:Hash+Eq+?Sized{panic!("no network")}
 fn insert(&self,_:Box<str>,_:Txt,_:Instant){panic!("no network")}
}
fn key(seed:u8)->Ed25519Key {let raw=pratique::crypto::ed25519_sign::Ed25519SigningKey::from_seed(&[seed;32]);Ed25519Key::from_seed_and_public_key(&[seed;32],raw.public_key()).unwrap()}
fn main(){
 let rt=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
 rt.block_on(async {
 let auth=MessageAuthenticator::new(workglen_dns::Config::new(vec![])).unwrap();let mut cache=Closed(HashMap::new());let mut records=serde_json::Map::new();
 for (domain,seed) in [("origin.example.test",7),("gateway.example.test",9)] {let raw=pratique::crypto::ed25519_sign::Ed25519SigningKey::from_seed(&[seed;32]);let record=format!("v=DKIM1;k=ed25519;p={}",pratique::pem::base64_encode(raw.public_key()));let name=format!("s._domainkey.{domain}"); records.insert(name.clone(),record.clone().into());let parsed:Txt=DomainKey::parse(record.as_bytes()).unwrap().into();cache.0.insert(name.clone().into(),parsed.clone());cache.0.insert(format!("{name}.").into(),parsed);}
 if std::env::args().nth(1).as_deref()==Some("--spf") {
  use mail_auth::spf::{Spf,verify::SpfParameters};
  let mut output=Vec::new();
  for text in ["v=spf1 +all","v=spf1 -all","v=spf1 ~all","v=spf1 ?all","v=spf1 ip4:192.0.2.0/24 -all","v=spf1 ip6:2001:db8::/32 -all","v=spf1 include:other.test -all","v=spf1 redirect=other.test","v=spf1 ip4:0.0.0.0/0","v=spf1 ip6:::/0","v=spf1","v=spf1 -all redirect=other.test"] {
   let mut cache=Closed(HashMap::new());for(name,value)in [("example.test",text),("other.test","v=spf1 ip4:192.0.2.1 ip6:2001:db8::1 ~all")]{let txt=Txt::Spf(std::sync::Arc::new(Spf::parse(value.as_bytes()).unwrap()));cache.0.insert(name.into(),txt.clone());cache.0.insert(format!("{name}.").into(),txt);}
   for ip in ["192.0.2.1","198.51.100.1","2001:db8::1","2001:db9::1"]{let r=auth.verify_spf(Parameters::new(SpfParameters::verify_mail_from(ip.parse().unwrap(),"example.test","receiver.test","a@example.test")).with_txt_cache(&cache)).await;output.push(serde_json::json!({"record":text,"ip":ip,"expected":format!("{:?}",r.result())}));}
  }println!("{}",serde_json::to_string_pretty(&output).unwrap());return;
 }
 if let Some(path)=std::env::args().nth(1){let v:serde_json::Value=serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
  for f in v["fixtures"].as_array().unwrap(){let raw=f["raw"].as_str().unwrap();let msg=AuthenticatedMessage::parse(raw.as_bytes()).unwrap();
   if f["kind"]=="arc"{let r=auth.verify_arc(Parameters::new(&msg).with_txt_cache(&cache)).await;assert_eq!(r.result(),&mail_auth::DkimResult::Pass,"{r:?}");}
   else {let recipients:Vec<_>=f["rcpt_to"].as_array().unwrap().iter().map(|v|v.as_str().unwrap()).collect();let r=auth.verify_dkim2(Parameters::new(&msg).with_txt_cache(&cache),Envelope::new(f["mail_from"].as_str().unwrap(),recipients)).await;assert_eq!(r.result(),&mail_auth::Dkim2Result::Pass,"{r:?}");}
  }println!("Prior independent engine verified {} native protocol messages",v["fixtures"].as_array().unwrap().len());return;
 }
 let mut fixtures=Vec::new();
 let original="From: Sender <a@origin.example.test>\r\nTo: r@example.test\r\nSubject: Original\r\nSubject: Repeated\r\n\r\nFirst café\r\nSecond line\r\n\r\n";
 let a=Dkim2Signer::from_key(key(7)).domain("origin.example.test").selector("s");let b=Dkim2Signer::from_key(key(9)).domain("gateway.example.test").selector("s");
 let sig=a.sign(original.as_bytes(),Hop::imaginary("gateway.example.test")).unwrap();let first=format!("{}{original}",sig.to_header());
 for change in [false,true] {let modified=if change {first.replace("Original","Revised").replace("First café","Changed café")}else{first.clone()};let sig=if change{b.sign_revised(first.as_bytes(),modified.as_bytes(),Hop::real("<bounce@gateway.example.test>",["<r@example.test>"])).unwrap()}else{b.sign(modified.as_bytes(),Hop::real("<bounce@gateway.example.test>",["<r@example.test>"])).unwrap()};let signed=format!("{}{modified}",sig.to_header());let msg=AuthenticatedMessage::parse(signed.as_bytes()).unwrap();let result=auth.verify_dkim2(Parameters::new(&msg).with_txt_cache(&cache),Envelope::new("<bounce@gateway.example.test>",["<r@example.test>"])).await;assert_eq!(result.result(),&mail_auth::Dkim2Result::Pass);fixtures.push(serde_json::json!({"kind":"dkim2","changed":change,"raw":signed,"mail_from":"<bounce@gateway.example.test>","rcpt_to":["<r@example.test>"]}));}
 let sealer=ArcSealer::from_key(key(7)).domain("origin.example.test").selector("s").headers(["From","To","Subject"]);let parsed=AuthenticatedMessage::parse(original.as_bytes()).unwrap();let results=AuthenticationResults::new("origin.example.test");let set=sealer.seal(&parsed,&results,&ArcOutput::default()).unwrap();let first=format!("{}{original}",set.to_header());let parsed=AuthenticatedMessage::parse(first.as_bytes()).unwrap();let arc=auth.verify_arc(Parameters::new(&parsed).with_txt_cache(&cache)).await;assert_eq!(arc.result(),&mail_auth::DkimResult::Pass);fixtures.push(serde_json::json!({"kind":"arc","raw":first}));
 let sealer=ArcSealer::from_key(key(9)).domain("gateway.example.test").selector("s").headers(["From","To","Subject"]);let results=AuthenticationResults::new("gateway.example.test");let set=sealer.seal(&parsed,&results,&arc).unwrap();let signed=format!("{}{}",set.to_header(),std::str::from_utf8(parsed.raw_message).unwrap());let parsed=AuthenticatedMessage::parse(signed.as_bytes()).unwrap();assert_eq!(auth.verify_arc(Parameters::new(&parsed).with_txt_cache(&cache)).await.result(),&mail_auth::DkimResult::Pass);fixtures.push(serde_json::json!({"kind":"arc","raw":signed}));
 println!("{}",serde_json::to_string_pretty(&serde_json::json!({"provenance":"Generated by attributed mail-auth 0.13.3 with the prior Workglen Pratique adapter; public synthetic seeds 7 and 9; closed DNS","time":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),"records":records,"fixtures":fixtures})).unwrap());
 });
}
