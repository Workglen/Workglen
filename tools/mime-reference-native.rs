//! Development-only serializer for the public message behavior Workglen uses.
//! Compile in an isolated harness with mail-parser 0.11.9 and serde_json.
use mail_parser::{Address, ContentType, Message, MessageParser, MimeHeaders, PartType};
use pratique::json_value::{Value, json};
use std::io::{self, BufRead};
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn addresses(a: Option<&Address<'_>>) -> Value {
    a.map(|a| {
        a.iter()
            .map(|a| json!({"name":a.name,"address":a.address}))
            .collect::<Vec<_>>()
    })
    .map_or(Value::Null, |v| json!(v))
}
fn ct(v: Option<&ContentType<'_>>) -> Value {
    v.map_or(Value::Null,|v|json!({"type":v.ctype(),"subtype":v.subtype(),"attributes":v.attributes.as_ref().map(|a|a.iter().map(|a|json!([a.name,a.value])).collect::<Vec<_>>())}))
}
pub fn message(m: &Message<'_>, depth: usize) -> Value {
    assert!(depth < 32);
    json!({
     "from":addresses(m.from()),"to":addresses(m.to()),"cc":addresses(m.cc()),"reply_to":addresses(m.reply_to()),"subject":m.subject(),"message_id":m.message_id(),"date":m.date().map(|d|json!([d.year,d.month,d.day,d.hour,d.minute,d.second,d.tz_before_gmt,d.tz_hour,d.tz_minute])),
     "headers":m.headers_raw().map(|(n,v)|json!([n,v])).collect::<Vec<_>>(),"body_text":m.body_text(0),"attachments":m.attachments().map(|p|json!({"name":p.attachment_name(),"contents":hex(p.contents())})).collect::<Vec<_>>(),
     "parts":m.parts.iter().map(|p|{let(kind,content)=match &p.body{PartType::Text(t)=>("text",json!(t)),PartType::Html(t)=>("html",json!(t)),PartType::Binary(b)=>("binary",json!(hex(b))),PartType::InlineBinary(b)=>("inline",json!(hex(b))),PartType::Multipart(children)=>("multipart",json!(children)),PartType::Message(n)=>("message",message(n,depth+1))};json!({"kind":kind,"content":content,"type":ct(p.content_type()),"disposition":ct(p.content_disposition()),"id":p.content_id(),"description":p.content_description(),"encoding":p.content_transfer_encoding(),"name":p.attachment_name(),"offsets":[p.offset_header,p.offset_body,p.offset_end],"problem":p.is_encoding_problem})}).collect::<Vec<_>>()
    })
}
fn main() {
    for line in io::stdin().lock().lines() {
        let mut v: Value = pratique::json_value::from_str(&line.unwrap()).unwrap();
        let b = v["hex"].as_str().unwrap().as_bytes();
        let raw: Vec<u8> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|h| u8::from_str_radix(std::str::from_utf8(h).unwrap(), 16).unwrap())
            .collect();
        v["expected"] = MessageParser::default()
            .parse(&raw)
            .map_or(Value::Null, |m| message(&m, 0));
        println!("{}", pratique::json_value::to_string(&v).unwrap());
    }
}
