//! Shared first-party compatibility driver. The former engine is isolated/offline.
use json::{Value,json};
use std::io::{self,BufRead};
use pratique::{data::{Encode,Decode},json_value as json};
struct Record {z:u64,a:String,optional:Option<String>,items:Vec<i16>,disabled:bool}
pratique::data_encode!(Record{z,a,optional,items,disabled=>std::ops::Not::not});
pratique::data_decode!(Record,deny_unknown=true,{z,a,optional,items=Vec::new(),disabled=false});
fn typed<T:Decode+Encode>(raw:&str)->Value {
 match json::from_str::<T>(raw){Ok(v)=>json!({"valid":true,"compact":json::to_string(&v).unwrap(),"pretty":json::to_string_pretty(&v).unwrap()}),Err(_)=>json!({"valid":false})}
}
pub fn evaluate(row:&Value)->Value{
 let raw=row["raw"].as_str().unwrap_or("");
 match row["kind"].as_str().unwrap(){
  "value"=>match json::from_str::<Value>(raw){Ok(v)=>json!({"valid":true,"compact":json::to_string(&v).unwrap(),"pretty":json::to_string_pretty(&v).unwrap(),"i64":v.as_i64(),"u64":v.as_u64(),"f64bits":v.as_f64().map(f64::to_bits)}),Err(_)=>json!({"valid":false})},
  "i64"=>typed::<i64>(raw),"u64"=>typed::<u64>(raw),"i128"=>typed::<i128>(raw),"u128"=>typed::<u128>(raw),"f64"=>typed::<f64>(raw),"f32"=>typed::<f32>(raw),"record"=>typed::<Record>(raw),
  "float64"=>{let n=f64::from_bits(row["bits"].as_u64().unwrap());json!({"compact":json::to_string(&n).unwrap(),"value":json::to_string(&json::to_value(n).unwrap()).unwrap()})},
  "float32"=>{let n=f32::from_bits(row["bits"].as_u64().unwrap()as u32);json!({"compact":json::to_string(&n).unwrap(),"value":json::to_string(&json::to_value(n).unwrap()).unwrap()})},
  _=>panic!("unknown fixture kind")
 }
}
fn main(){for line in io::stdin().lock().lines(){let row:Value=json::from_str(&line.unwrap()).unwrap();println!("{}",json!({"label":row["label"],"result":evaluate(&row)}));}}
