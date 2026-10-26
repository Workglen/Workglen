//! Preserve native TOML kinds/locations when decoding an explicit Pratique schema.
use crate::{Kind, Node};
use pratique::data::{Kind as DataKind, Node as DataNode};
pub(crate) fn into_data(n: Node) -> DataNode {
    DataNode {
        offset: n.at,
        format: pratique::data::Format::Toml,
        kind: match n.kind {
            Kind::String(v) => DataKind::String(v),
            Kind::Integer(v) => DataKind::Number(v.to_string()),
            Kind::Float(v) => DataKind::Float(v),
            Kind::Boolean(v) => DataKind::Bool(v),
            Kind::Datetime(v) => DataKind::Datetime(v),
            Kind::Array(v, _) => DataKind::Array(v.into_iter().map(into_data).collect()),
            Kind::Table(v, _) => {
                DataKind::Object(v.into_iter().map(|(k, n)| (k, into_data(n))).collect())
            }
        },
    }
}
