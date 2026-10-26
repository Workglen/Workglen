//! Typed Serde contracts exercised by both the former and native parsers.
use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Schema {
    name: String,
    #[serde(default)]
    enabled: bool,
    optional: Option<String>,
    #[serde(default)]
    count: u16,
    #[serde(default)]
    values: Vec<i64>,
    role: Role,
    pair: Option<(u8, u8)>,
    listen: Option<std::net::SocketAddr>,
    variant: Option<Variant>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    Primary,
    Standby,
}
#[derive(Deserialize, Serialize)]
enum Variant {
    Unit,
    New(u32),
    Tuple(u8, u8),
    Struct { enabled: bool },
}
