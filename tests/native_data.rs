//! Frozen former-engine comparisons, including explicitly reviewed numeric corrections.
#[allow(dead_code)]
#[path = "../tools/json-reference-native.rs"]
mod reference;
#[test]
fn json_compatibility_corpus() {
    use pratique::json_value::{self as json, Value};
    let mut count = 0;
    for line in include_str!("fixtures/native-json-reference.jsonl").lines() {
        let row: Value = json::from_str(line).unwrap();
        assert_eq!(
            reference::evaluate(&row["input"]),
            row["expected"],
            "{}",
            row["input"]
        );
        count += 1;
    }
    assert_eq!(count, 73260);
}

#[test]
fn json_writer_failure(){
use pratique::json_value as json;
let value=json::json!({"x":1});
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic write failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(json::to_writer(Broken, &value).is_err());
}
