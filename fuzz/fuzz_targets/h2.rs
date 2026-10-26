#![no_main]
#[path = "../harness.rs"]
#[allow(dead_code)]
mod harness;
libfuzzer_sys::fuzz_target!(|data: &[u8]| { harness::exercise("h2", data); });
