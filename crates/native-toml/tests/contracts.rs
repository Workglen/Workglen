use workglen_toml::{Limits, Value, from_str, from_str_with_limits};

#[derive(Debug, PartialEq)]
struct Config {
    hostname: String,
    role: Role,
    listen: std::net::SocketAddr,
    count: u16,
    optional: Option<String>,
    remotes: Vec<Remote>,
}
pratique::data_decode!(Config, deny_unknown=true, { hostname, role, listen, count = default_count(), optional, remotes = Default::default() });

fn default_count() -> u16 {
    30
}
#[derive(Debug, PartialEq)]
enum Role {
    Primary,
    Standby,
}
impl pratique::data::Decode for Role {
    fn decode(n: pratique::data::Node) -> Result<Self, pratique::data::Error> {
        let at = n.offset;
        match pratique::data::unit_variant(n)?.as_str() {
            "primary" => Ok(Self::Primary),
            "standby" => Ok(Self::Standby),
            _ => Err(pratique::data::Error::new("unknown Role variant").at(at)),
        }
    }
}

#[derive(Debug, PartialEq)]
struct Remote {
    name: String,
    enabled: bool,
}
pratique::data_decode!(Remote, deny_unknown=true, { name, enabled });

const BASE: &str = "hostname='example.test'\nrole='primary'\nlisten='127.0.0.1:8080'\n";

#[test]
fn schemas_preserve_defaults_options_arrays_and_enums() {
    let config: Config = from_str(BASE).unwrap();
    assert_eq!(config.count, 30);
    assert_eq!(config.optional, None);
    assert_eq!(config.role, Role::Primary);
    let config: Config = from_str(&format!("{BASE}count=65_535\noptional='yes'\n[[remotes]]\nname='one'\nenabled=true\n[[remotes]]\nname='two'\nenabled=false")).unwrap();
    assert_eq!(config.count, 65535);
    assert_eq!(config.remotes.len(), 2);
    assert_eq!(config.remotes[1].name, "two");
    assert_eq!(config.optional, Some("yes".into()));
}

#[test]
fn schema_failures_are_not_coerced_or_ignored() {
    for suffix in [
        "count=-1",
        "count=65536",
        "count=1.0",
        "count='1'",
        "count=true",
        "optional=1979-05-27",
        "extra='no'",
        "remotes=[{name='x',enabled=1}]",
        "remotes=[{name='x',enabled=true,extra=1}]",
    ] {
        assert!(
            from_str::<Config>(&format!("{BASE}{suffix}")).is_err(),
            "{suffix}"
        );
    }
    assert!(from_str::<Config>(&BASE.replace("primary", "invalid")).is_err());
    assert!(from_str::<Config>(&BASE.replace("127.0.0.1:8080", "invalid")).is_err());
    assert!(from_str::<Config>("hostname='x'").is_err());
    let error = from_str::<Config>(&format!("{BASE}[[remotes]]\nname='x'\nenabled=1")).unwrap_err();
    assert_eq!(error.path, ["remotes", "0", "enabled"]);
    assert_eq!(error.line, 6);
    assert_eq!(error.column, 9);
}

#[test]
fn resource_limits_fail_closed() {
    let limits = Limits::default();
    for (input, limit) in [
        (
            "a=1",
            Limits {
                input_bytes: 2,
                ..limits
            },
        ),
        (
            "abc=1",
            Limits {
                key_bytes: 2,
                ..limits
            },
        ),
        ("a.b.c=1", Limits { depth: 2, ..limits }),
        ("a=[[[1]]]", Limits { depth: 3, ..limits }),
        ("a={b={c=1}}", Limits { depth: 2, ..limits }),
        ("a=1\nb=2", Limits { nodes: 3, ..limits }),
        (
            "",
            Limits {
                depth: 129,
                ..limits
            },
        ),
    ] {
        assert!(
            from_str_with_limits::<Value>(input, limit).is_err(),
            "{input}"
        );
    }
    let deep = format!("a={}0{}", "[".repeat(1000), "]".repeat(1000));
    assert!(from_str::<Value>(&deep).is_err());
    assert!(from_str::<Value>(&format!("[{}]\na=1", vec!["a"; 1000].join("."))).is_err());
}

#[test]
fn definitions_and_toml_11_extensions() {
    for bad in [
        "a=1\na=2",
        "a.b=1\n[a]",
        "a={}\na.b=1",
        "a=[]\n[[a]]",
        "[a.b]\nx=1\n[a]\nb.y=2",
        "a=07:32.5",
        "[a.b.c]\n[a]\nb.d=1",
        "a=1e999",
    ] {
        assert!(from_str::<Value>(bad).is_err(), "{bad}");
    }
    let v:Value=from_str("text=\"\\e\\x41\\u00E9\\U0001F600\"\ninline={\nb=1,\n}\ntime=07:32\n[parent.child]\n[parent]\nx=1").unwrap();
    assert_eq!(v["text"].as_str(), Some("\u{1b}Aé😀"));
    assert_eq!(v["time"], Value::Datetime("07:32:00".into()));
}

#[test]
fn deterministic_mutations_never_panic() {
    let seeds = [
        BASE,
        "[[a]]\nx={y=[1,2,3]}\n[[a]]\nx='é😀'",
        "x=\"\"\"hello\nworld\"\"\"",
        "a=1979-05-27T07:32:00.999-07:00",
    ];
    let mut state = 0x84a9d17f_u64;
    for i in 0..20_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut bytes = seeds[i % seeds.len()].as_bytes().to_vec();
        let pos = state as usize % bytes.len();
        match i % 3 {
            0 => bytes[pos] = (state >> 32) as u8,
            1 => {
                bytes.remove(pos);
            }
            _ => bytes.insert(pos, (state >> 40) as u8),
        };
        if let Ok(input) = std::str::from_utf8(&bytes) {
            let _ = from_str::<Value>(input);
        }
    }
}
