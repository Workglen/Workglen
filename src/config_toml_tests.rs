//! Exercise the real application schemas without opening installed files or sockets.
use super::*;

#[test]
fn shipped_node_and_witness_configs_deserialize() {
    for (name, source) in [
        ("single", include_str!("../config/single.toml")),
        ("node-a", include_str!("../config/node-a.toml")),
        ("node-b", include_str!("../config/node-b.toml")),
        ("direct", include_str!("../config/direct.toml")),
        ("letsencrypt", include_str!("../config/letsencrypt.toml")),
    ] {
        let c: Config = workglen_toml::from_str(source).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!c.hostname.is_empty());
        assert!(c.limits.connections > 0);
    }
    let c: crate::witness::WitnessConfig =
        workglen_toml::from_str(include_str!("../config/witness.toml")).unwrap();
    assert!(c.lease_seconds > 0);
    assert!(!c.cluster_id.is_empty());
}

#[test]
fn real_config_schema_keeps_defaults_and_rejects_invalid_fields() {
    let source = include_str!("../config/single.toml");
    let c: Config = workglen_toml::from_str(source).unwrap();
    assert_eq!(c.mode, Mode::Single);
    assert!(c.web.is_none());
    assert!(c.security_remotes.is_empty());
    for bad in [
        format!("unknown=true\n{source}"),
        source.replace("role = \"primary\"", "role = \"invalid\""),
        source.replace("connections = 16", "connections = -1"),
        source.replace("connections = 16", "connections = 1.5"),
        source.replace("connections = 16", "connections = 16\nconnections = 1"),
        source.replace("[limits]", "[limits]\nunknown = true"),
        source.replace("domain = \"example.com\"", "domain = 1979-05-27"),
    ] {
        assert!(workglen_toml::from_str::<Config>(&bad).is_err());
    }
    let witness = include_str!("../config/witness.toml");
    assert!(
        workglen_toml::from_str::<crate::witness::WitnessConfig>(&format!(
            "unknown=true\n{witness}"
        ))
        .is_err()
    );
}
