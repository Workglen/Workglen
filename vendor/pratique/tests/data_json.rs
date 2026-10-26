use pratique::{
    data::{Decode, Encode, Format, Kind, Node},
    json_value::{self as json, Limits, Value},
};

#[derive(Debug, PartialEq)]
struct Record {
    z: u64,
    a: String,
    optional: Option<String>,
    items: Vec<i16>,
    disabled: bool,
}
pratique::data_encode!(Record { z, a, optional, items, disabled => std::ops::Not::not });
pratique::data_decode!(Record, deny_unknown=true, { z, a, optional, items=Vec::new(), disabled=false });

#[test]
fn record_order_defaults_and_sequence() {
    let v: Record = json::from_str(r#"{"a":"x","z":42}"#).unwrap();
    assert_eq!(
        json::to_string(&v).unwrap(),
        r#"{"z":42,"a":"x","optional":null,"items":[]}"#
    );
    assert_eq!(json::from_str::<Record>(r#"[42,"x",null]"#).unwrap(), v);
    assert!(json::from_str::<Record>(r#"[42,"x"]"#).is_err());
    for raw in [
        r#"{"z":42,"a":"x","extra":0}"#,
        r#"{"z":42,"a":"x","z":42}"#,
        r#"{"z":-1,"a":"x"}"#,
        r#"{"z":42,"a":null}"#,
    ] {
        assert!(json::from_str::<Record>(raw).is_err(), "{raw}");
    }
}

#[test]
fn generic_duplicates_and_signed_json_policy() {
    let raw = br#"{"z":1,"a":2,"z":3}"#;
    let value: Value = json::from_slice(raw).unwrap();
    assert_eq!(json::to_string(&value).unwrap(), r#"{"a":2,"z":3}"#);
    assert!(pratique::json::parse(raw).is_err());
    assert!(pratique::json::parse(br#"{"a":2,"z":3}"#).is_ok());
}

#[test]
fn input_limits_invalid_utf8_and_surrogates() {
    let base = Limits::default();
    assert!(json::from_slice_with_limits::<Value>(
        b"null",
        Limits {
            input_bytes: 3,
            ..base
        }
    )
    .is_err());
    assert!(json::from_slice_with_limits::<Value>(b"[0,1]", Limits { nodes: 2, ..base }).is_err());
    assert!(json::from_slice_with_limits::<Value>(b"[[0]]", Limits { depth: 1, ..base }).is_err());
    assert!(json::from_slice_with_limits::<Value>(b"[0,1]", Limits { nodes: 3, ..base }).is_ok());
    for raw in [
        b"\"\xff\"".as_slice(),
        br#""\ud800""#,
        br#""\udc00""#,
        br#""\ud800\u0041""#,
    ] {
        assert!(json::from_slice::<Value>(raw).is_err());
    }
    assert_eq!(json::from_str::<String>(r#""\ud83d\ude00""#).unwrap(), "😀");
}

#[test]
fn output_limits_include_escaping_and_nodes() {
    let base = Limits::default();
    assert!(json::to_vec_with_limits(
        &"\0",
        Limits {
            output_bytes: 7,
            ..base
        }
    )
    .is_err());
    assert_eq!(
        json::to_vec_with_limits(
            &"\0",
            Limits {
                output_bytes: 8,
                ..base
            }
        )
        .unwrap(),
        br#""\u0000""#
    );
    assert!(json::to_vec_with_limits(&vec![0, 1], Limits { nodes: 2, ..base }).is_err());
    assert!(json::to_vec_with_limits(&vec![vec![0]], Limits { depth: 1, ..base }).is_err());
}

#[test]
fn precise_numbers_and_private_names() {
    let value: Value = json::from_str("1234567890123456789012345678901234567890").unwrap();
    assert_eq!(
        json::to_string(&value).unwrap(),
        "1234567890123456789012345678901234567890"
    );
    assert_eq!(
        json::from_str::<u128>(&u128::MAX.to_string()).unwrap(),
        u128::MAX
    );
    assert!(json::from_str::<u64>("18446744073709551616").is_err());
    let marker = r#"{"$serde_json::private::Number":"bad"}"#;
    assert_eq!(
        json::to_string(&json::from_str::<Value>(marker).unwrap()).unwrap(),
        marker
    );
}

#[test]
fn float_boundaries_rounding_and_nonfinite() {
    for (number, expected) in [
        (0.0, "0.0"),
        (-0.0, "-0.0"),
        (1e-6, "1e-6"),
        (1e-5, "0.00001"),
        (1e16, "1e+16"),
        (f64::MAX, "1.7976931348623157e+308"),
        (f64::from_bits(1), "5e-324"),
    ] {
        assert_eq!(json::to_string(&number).unwrap(), expected);
        assert_eq!(
            json::from_str::<f64>(expected).unwrap().to_bits(),
            number.to_bits()
        );
    }
    assert_eq!(json::to_string(&f64::INFINITY).unwrap(), "null");
    assert_eq!(json::to_string(&f32::NAN).unwrap(), "null");
    assert!(json::from_str::<f64>("1e999").is_err());
}

#[test]
fn format_distinctions_and_error_locations() {
    let node = Node {
        kind: Kind::Datetime("2026-10-25".into()),
        offset: 17,
        format: Format::Toml,
    };
    assert_eq!(String::decode(node).unwrap_err().offset, 17);
    let mut node = Node::new(Kind::Object(vec![(
        "Variant".into(),
        Node::new(Kind::Object(vec![])),
    )]));
    assert!(pratique::data::unit_variant(node.clone()).is_err());
    node.format = Format::Toml;
    assert_eq!(pratique::data::unit_variant(node).unwrap(), "Variant");
    let node = Node::new(Kind::Object(vec![("Variant".into(), ().encode().unwrap())]));
    assert_eq!(pratique::data::unit_variant(node).unwrap(), "Variant");
}

#[test]
fn values_macros_and_mutation() {
    let mut value = json::json!({"x": [true, null, {"s": "a\n\"\\"}]});
    value["new"]["nested"] = Value::from(3);
    assert_eq!(value["new"]["nested"].take(), 3);
    assert!(value["missing"].is_null());
    let bytes = json::to_vec_pretty(&value).unwrap();
    assert_eq!(json::from_slice::<Value>(&bytes).unwrap(), value);
}

#[test]
fn toml_tuple_compatibility_keeps_format_boundary() {
    let mut node = vec![1u8, 2, 3].encode().unwrap();
    assert!(<(u8, u8)>::decode(node.clone()).is_err());
    node.format = Format::Toml;
    assert_eq!(<(u8, u8)>::decode(node).unwrap(), (1, 2));
}
