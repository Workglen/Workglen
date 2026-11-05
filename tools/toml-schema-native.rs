//! Explicit contracts matching the pinned former TOML schema oracle.
pub struct Schema {
    name: String,
    enabled: bool,
    optional: Option<String>,
    count: u16,
    values: Vec<i64>,
    role: Role,
    pair: Option<(u8, u8)>,
    listen: Option<std::net::SocketAddr>,
    variant: Option<Variant>,
}
pratique::data_encode!(Schema {
    name,
    enabled,
    optional,
    count,
    values,
    role,
    pair,
    listen,
    variant
});
pratique::data_decode!(Schema,deny_unknown=true,{name,enabled=false,optional,count=0,values=Vec::new(),role,pair,listen,variant});
enum Role {
    Primary,
    Standby,
}
impl pratique::data::Encode for Role {
    fn encode(&self) -> Result<pratique::data::Node, pratique::data::Error> {
        pratique::data::Encode::encode(match self {
            Self::Primary => "primary",
            Self::Standby => "standby",
        })
    }
}
impl pratique::data::Decode for Role {
    fn decode(n: pratique::data::Node) -> Result<Self, pratique::data::Error> {
        match pratique::data::unit_variant(n)?.as_str() {
            "primary" => Ok(Self::Primary),
            "standby" => Ok(Self::Standby),
            _ => Err(pratique::data::Error::new("invalid role")),
        }
    }
}
enum Variant {
    Unit,
    New(u32),
    Tuple(u8, u8),
    Struct { enabled: bool },
}
impl pratique::data::Encode for Variant {
    fn encode(&self) -> Result<pratique::data::Node, pratique::data::Error> {
        use pratique::data::{Kind, Node};
        Ok(match self {
            Self::Unit => "Unit".encode()?,
            Self::New(v) => Node::new(Kind::Object(vec![("New".into(), v.encode()?)])),
            Self::Tuple(a, b) => Node::new(Kind::Object(vec![("Tuple".into(), (a, b).encode()?)])),
            Self::Struct { enabled } => Node::new(Kind::Object(vec![(
                "Struct".into(),
                Node::new(Kind::Object(vec![("enabled".into(), enabled.encode()?)])),
            )])),
        })
    }
}
impl pratique::data::Decode for Variant {
    fn decode(n: pratique::data::Node) -> Result<Self, pratique::data::Error> {
        use pratique::data::{Error, Fields, Kind};
        match n.kind {
            Kind::String(s) if s == "Unit" => Ok(Self::Unit),
            Kind::Object(mut a) if a.len() == 1 => {
                let (k, n) = a.pop().unwrap();
                match k.as_str() {
                    "Unit" => {
                        let f = Fields::new(n, true)?;
                        f.finish()?;
                        Ok(Self::Unit)
                    }
                    "New" => Ok(Self::New(u32::decode(n)?)),
                    "Tuple" => {
                        let mut n = n;
                        n.format = pratique::data::Format::Data;
                        let (a, b) = <(u8, u8)>::decode(n)?;
                        Ok(Self::Tuple(a, b))
                    }
                    "Struct" => {
                        let mut f = Fields::new(n, false)?;
                        let enabled = f.field("enabled")?;
                        f.finish()?;
                        Ok(Self::Struct { enabled })
                    }
                    _ => Err(Error::new("invalid variant")),
                }
            }
            _ => Err(Error::new("invalid enum value")),
        }
    }
}
