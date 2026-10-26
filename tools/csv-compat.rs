//! Development-only oracle using the former csv 1.4.0 crate from the offline cache.
//! rustc --test --extern csv=OLD_RLIB -L dependency=DEPS_DIRECTORY tools/csv-compat.rs
#[path="../src/csv_reader.rs"]mod csv_reader;
fn check(input:&str){
    let mut old=csv::ReaderBuilder::new().trim(csv::Trim::All).from_reader(input.as_bytes());
    let new=csv_reader::Reader::new(input,1024*1024,10000).unwrap();
    let headers:Vec<_>=old.headers().unwrap().iter().map(str::to_string).collect();assert_eq!(headers,new.headers(),"{input:?}");
    let a:Result<Vec<Vec<String>>,_>=old.records().map(|r|r.map(|r|r.iter().map(str::to_string).collect())).collect();
    let b:Result<Vec<Vec<String>>,_>=new.collect();assert_eq!(a.ok(),b.ok(),"{input:?}");
}
#[test]fn former_csv_reader_agrees_on_generated_and_edge_inputs(){
    for s in ["","\n","\u{feff}a,b\r\nx,y", "a\n\"\"", "a\n\"open", "a,b\n\"x\"tail,z", "a,b\n x\"y,z", "a,b\n,", "a,b\n\n\r\nx,y\n", "a\n\u{a0}é\u{2003}"]{check(s);}
    let mut state=123456789u64;let alphabet=b"a,b\"\r\n \t";
    for size in 0..80{for _ in 0..1000{let mut s=String::new();for _ in 0..size{state^=state<<13;state^=state>>7;state^=state<<17;s.push(alphabet[state as usize%alphabet.len()] as char);}check(&s);}}
}
