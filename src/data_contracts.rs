//! Actual application record contracts from the pinned previous source.
use pratique::json_value::{self as json, Value, json};
pub(crate) fn check<T: pratique::data::Decode + pratique::data::Encode>(
    name: &str,
    inputs: &[&str],
) {
    let cases:Vec<Value>=inputs.iter().map(|raw|{let result=match json::from_str::<T>(raw){Ok(v)=>json!({"valid":true,"compact":json::to_string(&v).unwrap(),"pretty":json::to_string_pretty(&v).unwrap()}),Err(_)=>json!({"valid":false})};json!({"raw":raw,"result":result})}).collect();
    if let Ok(path) = std::env::var("WORKGLEN_RECORD_EXPORT") {
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(
            std::path::Path::new(&path).join(format!("{name}.json")),
            json::to_vec_pretty(&cases).unwrap(),
        )
        .unwrap();
    } else {
        let expected: Value = json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/native-records.json"
        )))
        .unwrap();
        let actual = json::to_value(cases).unwrap();
        assert_eq!(
            actual.as_array().unwrap().len(),
            expected[name].as_array().unwrap().len()
        );
        for (got, want) in actual
            .as_array()
            .unwrap()
            .iter()
            .zip(expected[name].as_array().unwrap())
        {
            assert_eq!(got, want, "record schema {name}; input {}", got["raw"]);
        }
    }
}
