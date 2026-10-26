extern crate workglen_toml as toml;
use pratique::json_value::Value;
#[allow(dead_code)]
#[path = "../../../tools/toml-reference-native.rs"]
mod reference;

fn canonical_datetime(s: &str) -> String {
    let mut s = s.replace('t', "T").replace('z', "Z").replace(' ', "T");
    if let Some(dot) = s.find('.') {
        let end = dot + 1 + s[dot + 1..].bytes().take_while(u8::is_ascii_digit).count();
        let fraction = s[dot + 1..end].chars().take(9).collect::<String>();
        let fraction = fraction.trim_end_matches('0');
        let replacement = if fraction.is_empty() {
            String::new()
        } else {
            format!(".{fraction}")
        };
        s.replace_range(dot..end, &replacement);
    }
    if s.ends_with("+00:00") || s.ends_with("-00:00") {
        s.truncate(s.len() - 6);
        s.push('Z');
    }
    s
}

fn equivalent(a: &Value, b: &Value) -> bool {
    if matches!(
        a.get("type").and_then(Value::as_str),
        Some("datetime" | "datetime-local" | "time-local")
    ) {
        return a["type"] == b["type"]
            && canonical_datetime(a["value"].as_str().unwrap())
                == canonical_datetime(b["value"].as_str().unwrap());
    }
    if a.get("type") == Some(&Value::String("float".into())) {
        if a["type"] != b["type"] {
            return false;
        }
        let x = a["value"].as_str().unwrap().parse::<f64>().unwrap();
        let y = b["value"].as_str().unwrap().parse::<f64>().unwrap();
        return (x.is_nan() && y.is_nan())
            || (x == y && (x != 0.0 || x.is_sign_negative() == y.is_sign_negative()));
    }
    if let (Some(a), Some(b)) = (a.as_array(), b.as_array()) {
        return a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equivalent(a, b));
    }
    if let (Some(a), Some(b)) = (a.as_object(), b.as_object()) {
        return a.len() == b.len()
            && a.iter()
                .all(|(k, a)| b.get(k).is_some_and(|b| equivalent(a, b)));
    }
    a == b
}

#[test]
fn official_toml_11_corpus() {
    let rows: Vec<Value> = pratique::json_value::from_str(include_str!(
        "../../../tests/fixtures/toml-test/cases.json"
    ))
    .unwrap();
    assert_eq!(rows.len(), 712);
    for row in rows {
        let bytes: Vec<u8> = row["hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        let got = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| toml::from_str::<toml::Value>(s).ok());
        assert_eq!(
            got.is_some(),
            row["valid"].as_bool().unwrap(),
            "{}",
            row["label"]
        );
        if let Some(value) = got {
            let actual = reference::project(value);
            assert!(
                equivalent(&row["expected"], &actual),
                "{}: expected {}, got {}",
                row["label"],
                row["expected"],
                actual
            );
        }
    }
}

#[test]
fn pinned_former_parser_snapshots() {
    let rows: Vec<Value> = pratique::json_value::from_str(include_str!(
        "../../../tests/fixtures/native-toml-reference.json"
    ))
    .unwrap();
    assert_eq!(rows.len(), 5748);
    for row in rows {
        assert_eq!(
            reference::evaluate(&row),
            row["expected"],
            "{}",
            row["label"]
        );
    }
}
