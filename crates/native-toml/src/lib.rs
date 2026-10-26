//! First-party TOML parsing. Grammar code is independent of the former parser.
//! Typed schemas use Pratique data contracts, without a third-party derive engine.
use pratique::data::{Decode, Encode};
use std::{collections::BTreeMap, fmt, ops::Index};
mod de;
mod parse;
pub use parse::Limits;
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Datetime(String),
    Array(Vec<Value>),
    Table(BTreeMap<String, Value>),
}
impl Value {
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        if let Self::Array(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_table(&self) -> Option<&BTreeMap<String, Value>> {
        if let Self::Table(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_table()?.get(key)
    }
}
impl Index<&str> for Value {
    type Output = Value;
    fn index(&self, index: &str) -> &Value {
        self.get(index).expect("missing TOML table key")
    }
}
impl Encode for Value {
    fn encode(&self) -> Result<pratique::data::Node, pratique::data::Error> {
        use pratique::data::{Kind as K, Node as N};
        match self {
            Self::String(v) => v.encode(),
            Self::Integer(v) => v.encode(),
            Self::Float(v) => v.encode(),
            Self::Boolean(v) => v.encode(),
            Self::Datetime(v) => Ok(N::new(K::Datetime(v.clone()))),
            Self::Array(v) => v.encode(),
            Self::Table(v) => v.encode(),
        }
    }
}
impl Decode for Value {
    fn decode(n: pratique::data::Node) -> Result<Self, pratique::data::Error> {
        use pratique::data::{Error as E, Kind as K};
        Ok(match n.kind {
            K::String(v) => Self::String(v),
            K::Number(v) => Self::Integer(
                v.parse()
                    .map_err(|_| E::new("expected TOML integer").at(n.offset))?,
            ),
            K::Float(v) => Self::Float(v),
            K::Bool(v) => Self::Boolean(v),
            K::Datetime(v) => Self::Datetime(v),
            K::Array(v) => Self::Array(v.into_iter().map(Self::decode).collect::<Result<_, _>>()?),
            K::Object(v) => Self::Table(
                v.into_iter()
                    .map(|(k, v)| Ok((k, Self::decode(v)?)))
                    .collect::<Result<_, E>>()?,
            ),
            K::Null => return Err(E::new("TOML has no null").at(n.offset)),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub message: String,
    pub offset: usize,
    pub line: usize,
    pub column: usize,
    pub path: Vec<String>,
}
impl Error {
    pub(crate) fn at(message: impl Into<String>, offset: usize) -> Self {
        Self {
            message: message.into(),
            offset,
            line: 0,
            column: 0,
            path: Vec::new(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TOML error at line {}, column {}: {}",
            self.line, self.column, self.message
        )?;
        if !self.path.is_empty() {
            write!(f, " (at {})", self.path.join("."))?;
        }
        Ok(())
    }
}
impl std::error::Error for Error {}
pub fn from_str<T: Decode>(input: &str) -> Result<T, Error> {
    from_str_with_limits(input, Limits::default())
}
pub fn from_str_with_limits<T: Decode>(input: &str, limits: Limits) -> Result<T, Error> {
    let result = parse::document(input, limits).and_then(|n| {
        T::decode(de::into_data(n)).map_err(|e| Error {
            message: e.message,
            offset: e.offset,
            line: 0,
            column: 0,
            path: e.path,
        })
    });
    result.map_err(|mut e| {
        let offset = e.offset.min(input.len());
        let before = &input.as_bytes()[..offset];
        e.line = before.iter().filter(|b| **b == b'\n').count() + 1;
        let start = before
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |i| i + 1);
        e.column = String::from_utf8_lossy(&before[start..]).chars().count() + 1;
        e
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Implicit,
    Explicit,
    Dotted,
    Inline,
}
#[derive(Debug)]
pub(crate) enum Kind {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Datetime(String),
    Array(Vec<Node>, bool),
    Table(BTreeMap<String, Node>, State),
}
#[derive(Debug)]
pub(crate) struct Node {
    kind: Kind,
    at: usize,
}
impl Node {
    fn table(state: State, at: usize) -> Self {
        Self {
            kind: Kind::Table(BTreeMap::new(), state),
            at,
        }
    }
}
