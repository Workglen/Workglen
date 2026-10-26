//! Development-only comparison with the former pinned base64 0.22.1 crate.
//! Compile with rustc --test, --extern base64=OLD_RLIB, --extern pratique=RLIB
//! and -L dependency=DEPS_DIRECTORY. The old crate is not a build dependency.
#[path = "../src/encoding.rs"] mod encoding;
use base64::{Engine,engine::general_purpose::{STANDARD,URL_SAFE_NO_PAD}};
#[test] fn independent_previous_codec_agrees_on_binary_and_hostile_inputs(){
    let mut state=0x123456789abcdef0u64;
    let mut random=||{state^=state<<13;state^=state>>7;state^=state<<17;state as u8};
    for size in 0..4096 {
        let data=(0..size).map(|_|random()).collect::<Vec<_>>();
        for (old,new) in [(&STANDARD,encoding::STANDARD),(&URL_SAFE_NO_PAD,encoding::URL_SAFE_NO_PAD)] {
            let text=old.encode(&data);assert_eq!(new.encode(&data),text);assert_eq!(new.decode(&text).unwrap(),data);
        }
    }
    let alphabet=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_- \r\n\t\0\xff";
    for size in 0..20 {for _ in 0..10000 {
        let input=(0..size).map(|_|alphabet[random() as usize%alphabet.len()]).collect::<Vec<_>>();
        for (old,new) in [(&STANDARD,encoding::STANDARD),(&URL_SAFE_NO_PAD,encoding::URL_SAFE_NO_PAD)] {assert_eq!(old.decode(&input).ok(),new.decode(&input).ok(),"{input:?}");}
    }}
    for a in 0..256u16 {for b in 0..256u16 {let input=[a as u8,b as u8];assert_eq!(URL_SAFE_NO_PAD.decode(input).ok(),encoding::URL_SAFE_NO_PAD.decode(input).ok());let padded=[a as u8,b as u8,b'=',b'='];assert_eq!(STANDARD.decode(padded).ok(),encoding::STANDARD.decode(padded).ok());}}
}
