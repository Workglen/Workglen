#![allow(dead_code)]
#[path="NATIVE_SOURCE/src/charset.rs"] mod native;
#[path="NATIVE_SOURCE/src/transfer.rs"] mod transfer;
#[path="NATIVE_SOURCE/tests/charset_corpus.rs"] mod corpus;
mod former;
use pratique::crypto::sha2::{Hash,Sha256};
fn main(){let mut count=0u64;let mut mismatches=0u64;let mut hashes=std::collections::BTreeMap::<String,(u64,Sha256)>::new();
corpus::cases(|label,bytes|{let old=former::decode(bytes,Some(label));let new=native::decode(bytes,Some(label));count+=1;if old!=new{mismatches+=1;if mismatches<=20{println!("DIFF {label} {bytes:02x?} former={old:?} native={new:?}");}}let(n,h)=hashes.entry(label.into()).or_insert_with(||(0,Sha256::new()));*n+=1;h.update(&(bytes.len()as u64).to_le_bytes());h.update(bytes);h.update(&(old.0.len()as u64).to_le_bytes());h.update(old.0.as_bytes());h.update(&[u8::from(old.1)]);});
let summary=format!("cases={count} mismatches={mismatches}");eprintln!("{summary}");assert_eq!(mismatches,0);
for(label,(n,h))in hashes{let hash:String=h.finalize().iter().map(|b|format!("{b:02x}")).collect();println!("{label} {n} {hash}");}
}
