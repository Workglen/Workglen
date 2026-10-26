// SPDX-License-Identifier: Apache-2.0
// Development-only oracle. Link the former pinned anyhow rlib as old_anyhow.
#[allow(dead_code, unused_imports)]
#[path = "../src/error.rs"]
mod error;
use std::{error::Error as StdError, fmt, io};
#[derive(Debug)]
struct Nested(io::Error);
impl fmt::Display for Nested { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.write_str("outer library error") } }
impl StdError for Nested { fn source(&self)->Option<&(dyn StdError+'static)> { Some(&self.0) } }
fn compare(new:error::Error,old:old_anyhow::Error) {
    assert_eq!(format!("{new}"),format!("{old}"));
    assert_eq!(format!("{new:#}"),format!("{old:#}"));
    assert_eq!(format!("{new:?}"),format!("{old:?}"));
    assert_eq!(new.is::<io::Error>(),old.is::<io::Error>());
    assert_eq!(new.is::<Nested>(),old.is::<Nested>());
    assert_eq!(new.chain().map(ToString::to_string).collect::<Vec<_>>(),old.chain().map(ToString::to_string).collect::<Vec<_>>());
}
fn main() {
    let mut cases=0;
    for message in ["plain", "line one\nline two", "Unicode café 日本語", "", "last\n"] {
        for count in 0..10 {
            for kind in 0..3 {
                let (mut new,mut old)=match kind {
                    0=>(error::Error::msg(message),old_anyhow::Error::msg(message.to_string())),
                    1=>(io::Error::new(io::ErrorKind::TimedOut,message).into(),io::Error::new(io::ErrorKind::TimedOut,message).into()),
                    _=>(Nested(io::Error::new(io::ErrorKind::NotFound,message)).into(),Nested(io::Error::new(io::ErrorKind::NotFound,message)).into()),
                };
                for n in 0..count { let context=format!("context {n}");new=new.context(&context);old=old.context(context); }
                compare(new,old);cases+=1;
            }
        }
    }
    println!("{cases} former/native error cases passed: Display, alternate Display, ordinary Debug, source chains and typed classification");
}
