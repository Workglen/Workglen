//! Shared standalone oracle driver. The selected TOML dependency is isolated.
use pratique::json_value::{Value, json};
use std::io::{self, BufRead};
#[path = "toml-schema-native.rs"]
mod schema;
pub fn project(value: toml::Value) -> Value {
    match value {
        toml::Value::String(v) => json!({"type":"string","value":v}),
        toml::Value::Integer(v) => json!({"type":"integer","value":v.to_string()}),
        toml::Value::Float(v) => {
            json!({"type":"float","value":if v.is_nan(){"nan".into()}else{v.to_string()}})
        }
        toml::Value::Boolean(v) => json!({"type":"bool","value":v.to_string()}),
        toml::Value::Datetime(v) => {
            let s = v.to_string();
            let kind = if !s.contains('T') {
                if s.contains(':') {
                    "time-local"
                } else {
                    "date-local"
                }
            } else if s.ends_with('Z') || s[10..].contains(['+', '-']) {
                "datetime"
            } else {
                "datetime-local"
            };
            json!({"type":kind,"value":s})
        }
        toml::Value::Array(v) => Value::Array(v.into_iter().map(project).collect()),
        toml::Value::Table(v) => {
            Value::Object(v.into_iter().map(|(k, v)| (k, project(v))).collect())
        }
    }
}
pub fn evaluate(row: &Value) -> Value {
    let hex = row["hex"].as_str().unwrap();
    let bytes: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    let result = std::str::from_utf8(&bytes).ok().and_then(|s| {
        if row["kind"] == "schema" {
            toml::from_str::<schema::Schema>(s)
                .ok()
                .map(|v| pratique::json_value::to_value(v).unwrap())
        } else {
            toml::from_str::<toml::Value>(s).ok().map(project)
        }
    });
    match result {
        Some(v) => json!({"valid":true,"value":v}),
        None => json!({"valid":false}),
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let row: Value = pratique::json_value::from_str(&line.unwrap()).unwrap();
        let value = evaluate(&row);
        println!("{}", json!({"label":row["label"],"result":value}));
    }
}
