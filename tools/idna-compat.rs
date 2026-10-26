//! Development-only oracle against pinned idna 1.1.0 / ICU 2.4.0 (Unicode 18).
//! Build in an isolated harness; never add idna back to the application.
fn check(input:&str,count:&mut usize,errors:&mut usize){
 let old=idna::domain_to_ascii(input).ok();let new=workglen_idna::domain_to_ascii(input).ok();*count+=1;
 if old!=new{*errors+=1;if *errors<=20{eprintln!("{input:?}: old {old:?}; new {new:?}");}}
}
fn main(){let mut count=0;let mut errors=0;
 for cp in 0..=0x10ffff{if let Some(c)=char::from_u32(cp){for input in [format!("a{c}b.test"),format!("א{c}א.test"),format!("{c}.test")]{check(&input,&mut count,&mut errors);}}}
 let alpha=['a','Z','0','-','.','_','ß','ẞ','\u{0300}','\u{0315}','\u{200c}','\u{200d}','\u{094d}','क','ب','א','٠','ᄀ','ᅡ','ς','Σ','\u{00ad}','\u{034f}','。','Ａ','😀','\u{fffd}','\0'];
 let mut seed=0xfacefeedu64;for _ in 0..100000{let mut s=String::new();for _ in 0..(seed%25){seed=seed.wrapping_mul(6364136223846793005).wrapping_add(1);s.push(alpha[(seed>>32)as usize%alpha.len()]);}check(&s,&mut count,&mut errors);if let Ok(encoded)=idna::domain_to_ascii(&s){check(&encoded,&mut count,&mut errors);}seed=seed.wrapping_add(1);}
 for a in b"abcdefghijklmnopqrstuvwxyz0123456789-"{for b in b"abcdefghijklmnopqrstuvwxyz0123456789-"{check(&format!("xn--{}{}.test",*a as char,*b as char),&mut count,&mut errors);}}
 for n in [0,1,63,64,253,254,999,1000,1001,1999,2000,2001]{for c in ["a","ü","א","\u{0300}"]{check(&c.repeat(n),&mut count,&mut errors);}}
 println!("{count} pinned-IDNA comparisons; {errors} mismatches");assert_eq!(errors,0);
}
