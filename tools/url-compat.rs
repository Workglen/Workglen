//! Development-only differential oracle; the former url crate is not a deployed dependency.
#[path = "../src/url.rs"] mod native;
fn check(input:&str) -> bool {
    let a=url::Url::parse(input).map(|u|u.to_string());let b=native::Url::parse(input).map(|u|u.to_string());
    if a.as_ref().ok()!=b.as_ref().ok(){eprintln!("{input:?}: old={a:?}, native={b:?}");false}else{true}
}
fn main(){
    let mut count=0;let mut failures=0;
    for host in ["example.com","bücher.de","faß.de","a\u{200d}b.com","ｅｘａｍｐｌｅ.com","xn--bcher-kva.de","a..b","a_foo.com","-foo.com","127.1","0177.0.0.1","0x7f000001","1.2.3.08","4294967295","4294967296","[::1]","[::ffff:127.0.0.1]","%65xample.com","host.","a%25b"] {
      for path in ["","/","//","/a//b/../c","/a/%2e/..","/é?x='a b'#é","/a\\b","/a/%2e%2e/","?","#","/x;%00"] {
       for cred in ["","user:pass@","u@v@",":p@","u:@"] {
        for port in ["",":443",":0",":99999",":00080",":"] {
         count+=1;if !check(&format!("https://{cred}{host}{port}{path}")){failures+=1;if failures>30{std::process::exit(1);}}
    }}}}
    let mut seed=42u64;let alphabet=b"abcdefghijklmnopqrstuvwxyz0123456789:/?#@%\\[] ._-\t\n";
    for _ in 0..100000{let mut s=String::from("http:");for _ in 0..(seed%55){seed=seed.wrapping_mul(6364136223846793005).wrapping_add(1);s.push(alphabet[(seed>>32)as usize%alphabet.len()]as char);}count+=1;if !check(&s){failures+=1;if failures>30{std::process::exit(1);}}seed=seed.wrapping_add(1);}
    for b in 0..=255u8 {let bytes=[b];assert_eq!(url::form_urlencoded::byte_serialize(&bytes).collect::<String>(),native::form_urlencoded::byte_serialize(&bytes).collect::<String>());}
    for path in ["/a//b/../", "/a?b#c", "é/あ", "/%2e%2e/x", "a\\b", ""] {
        let mut old=url::Url::parse("https://u:p@host:8443/original?q=old#f").unwrap();let mut new=native::Url::parse(old.as_str()).unwrap();
        old.set_username("new@user").unwrap();new.set_username("new@user").unwrap();old.set_password(Some("new:password")).unwrap();new.set_password(Some("new:password")).unwrap();old.set_path(path);new.set_path(path);old.query_pairs_mut().append_pair("q", "a b&é");new.append_query_pair("q", "a b&é");assert_eq!(old.as_str(),new.as_str(),"setter {path}");
    }
    println!("{count} URL comparisons, {failures} mismatches");assert_eq!(failures,0);
}
