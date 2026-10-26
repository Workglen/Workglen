//! General JSON values and typed encoding for application records.
//! Uses Pratique's JSON grammar and string escaping. The existing signed-data
//! parser/canonical writer retain their separate, stricter duplicate/number policy.
use crate::data::{self, Decode, Encode, Kind, Node};
pub use crate::data_json as json;
pub use data::Error;
use std::{
    collections::BTreeMap,
    fmt,
    ops::{Index, IndexMut},
    str::FromStr,
};
pub type Map<K, V> = BTreeMap<K, V>;
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub depth: usize,
    pub nodes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 256 * 1024 * 1024,
            output_bytes: 256 * 1024 * 1024,
            depth: 127,
            nodes: 2_000_000,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Number(String);
impl Number {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.0.parse().ok()
    }
    pub fn as_u64(&self) -> Option<u64> {
        self.0.parse().ok()
    }
    pub fn as_f64(&self) -> Option<f64> {
        self.0.parse::<f64>().ok().filter(|v| v.is_finite())
    }
    pub fn is_i64(&self) -> bool {
        self.as_i64().is_some()
    }
    pub fn is_u64(&self) -> bool {
        self.as_u64().is_some()
    }
    pub fn is_f64(&self) -> bool {
        self.0.contains(['.', 'e', 'E']) && self.as_f64().is_some()
    }
    pub fn from_f64(v: f64) -> Option<Self> {
        v.is_finite().then(|| Self(data::format_float64(v)))
    }
}
impl FromStr for Number {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match crate::json::parse(s.as_bytes()) {
            Ok(crate::json::Value::Number(n)) => Ok(Self(normalize_number(n.into_text()))),
            _ => Err(Error::new("invalid JSON number")),
        }
    }
}
fn normalize_number(s: String) -> String {
    if let Some((m, e)) = s.split_once(['e', 'E']) {
        format!(
            "{m}e{}{e}",
            if e.starts_with(['+', '-']) { "" } else { "+" }
        )
    } else {
        s
    }
}
impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Map<String, Value>),
}
impl Value {
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(v) = self {
            Some(*v)
        } else {
            None
        }
    }
    pub fn as_number(&self) -> Option<&Number> {
        if let Self::Number(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number()?.as_i64()
    }
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number()?.as_u64()
    }
    pub fn as_f64(&self) -> Option<f64> {
        self.as_number()?.as_f64()
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        if let Self::Array(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        if let Self::Array(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_object(&self) -> Option<&Map<String, Value>> {
        if let Self::Object(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_object_mut(&mut self) -> Option<&mut Map<String, Value>> {
        if let Self::Object(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }
    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }
    pub fn is_number(&self) -> bool {
        matches!(self, Self::Number(_))
    }
    pub fn is_u64(&self) -> bool {
        self.as_u64().is_some()
    }
    pub fn is_i64(&self) -> bool {
        self.as_i64().is_some()
    }
    pub fn is_f64(&self) -> bool {
        self.as_number().is_some_and(Number::is_f64)
    }
    pub fn is_boolean(&self) -> bool {
        matches!(self, Self::Bool(_))
    }
    pub fn get<I: ValueIndex>(&self, key: I) -> Option<&Value> {
        key.get(self)
    }
    pub fn get_mut<I: ValueIndex>(&mut self, key: I) -> Option<&mut Value> {
        key.get_mut(self)
    }
    pub fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}
pub trait ValueIndex {
    fn get(self, v: &Value) -> Option<&Value>;
    fn get_mut(self, v: &mut Value) -> Option<&mut Value>;
    fn insert(self, v: &mut Value) -> &mut Value;
}
impl ValueIndex for &str {
    fn get(self, v: &Value) -> Option<&Value> {
        v.as_object()?.get(self)
    }
    fn get_mut(self, v: &mut Value) -> Option<&mut Value> {
        v.as_object_mut()?.get_mut(self)
    }
    fn insert(self, v: &mut Value) -> &mut Value {
        if v.is_null() {
            *v = Value::Object(Map::new());
        }
        v.as_object_mut()
            .expect("JSON string index on non-object")
            .entry(self.into())
            .or_default()
    }
}
impl ValueIndex for &String {
    fn get(self, v: &Value) -> Option<&Value> {
        ValueIndex::get(self.as_str(), v)
    }
    fn get_mut(self, v: &mut Value) -> Option<&mut Value> {
        ValueIndex::get_mut(self.as_str(), v)
    }
    fn insert(self, v: &mut Value) -> &mut Value {
        ValueIndex::insert(self.as_str(), v)
    }
}
impl ValueIndex for String {
    fn get(self, v: &Value) -> Option<&Value> {
        v.as_object()?.get(&self)
    }
    fn get_mut(self, v: &mut Value) -> Option<&mut Value> {
        v.as_object_mut()?.get_mut(&self)
    }
    fn insert(self, v: &mut Value) -> &mut Value {
        if v.is_null() {
            *v = Value::Object(Map::new());
        }
        v.as_object_mut()
            .expect("JSON string index on non-object")
            .entry(self)
            .or_default()
    }
}
impl ValueIndex for usize {
    fn get(self, v: &Value) -> Option<&Value> {
        v.as_array()?.get(self)
    }
    fn get_mut(self, v: &mut Value) -> Option<&mut Value> {
        v.as_array_mut()?.get_mut(self)
    }
    fn insert(self, v: &mut Value) -> &mut Value {
        &mut v.as_array_mut().expect("JSON numeric index on non-array")[self]
    }
}
impl<I: ValueIndex> Index<I> for Value {
    type Output = Value;
    fn index(&self, key: I) -> &Value {
        key.get(self).unwrap_or(&Value::Null)
    }
}
impl<I: ValueIndex> IndexMut<I> for Value {
    fn index_mut(&mut self, key: I) -> &mut Value {
        key.insert(self)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Self::String(v.into())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<Number> for Value {
    fn from(v: Number) -> Self {
        Self::Number(v)
    }
}
impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Number::from_f64(v).map(Self::Number).unwrap_or(Self::Null)
    }
}
macro_rules! ints {($($t:ty),*)=>{$(impl From<$t> for Number{fn from(v:$t)->Self{Self(v.to_string())}}impl From<$t> for Value{fn from(v:$t)->Self{Self::Number(v.into())}}impl PartialEq<$t> for Value{fn eq(&self,v:&$t)->bool{self==&Self::from(*v)}})*}}
ints!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);
impl PartialEq<str> for Value {
    fn eq(&self, v: &str) -> bool {
        self.as_str() == Some(v)
    }
}
impl PartialEq<&str> for Value {
    fn eq(&self, v: &&str) -> bool {
        self.as_str() == Some(*v)
    }
}
impl PartialEq<String> for Value {
    fn eq(&self, v: &String) -> bool {
        self.as_str() == Some(v)
    }
}
impl PartialEq<bool> for Value {
    fn eq(&self, v: &bool) -> bool {
        self.as_bool() == Some(*v)
    }
}
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = if f.alternate() {
            to_string_pretty(self)
        } else {
            to_string(self)
        };
        f.write_str(&s.map_err(|_| fmt::Error)?)
    }
}
impl Encode for Number {
    fn encode(&self) -> Result<Node, Error> {
        Ok(Node::new(Kind::Number(self.0.clone())))
    }
}
impl Encode for Value {
    fn encode(&self) -> Result<Node, Error> {
        match self {
            Self::Null => ().encode(),
            Self::Bool(v) => v.encode(),
            Self::Number(v) => v.encode(),
            Self::String(v) => v.encode(),
            Self::Array(v) => v.encode(),
            Self::Object(v) => v.encode(),
        }
    }
}
impl Decode for Value {
    fn decode(n: Node) -> Result<Self, Error> {
        Ok(match n.kind {
            Kind::Null => Self::Null,
            Kind::Bool(v) => Self::Bool(v),
            Kind::Number(v) => Self::Number(v.parse()?),
            Kind::Float(v) => v.into(),
            Kind::String(v) | Kind::Datetime(v) => Self::String(v),
            Kind::Array(v) => {
                Self::Array(v.into_iter().map(Self::decode).collect::<Result<_, _>>()?)
            }
            Kind::Object(v) => Self::Object(
                v.into_iter()
                    .map(|(k, v)| Ok((k, Self::decode(v)?)))
                    .collect::<Result<_, Error>>()?,
            ),
        })
    }
}
fn from_parsed(v: crate::json::Value) -> Node {
    use crate::json::Value as V;
    let mut node = Node::new(match v {
        V::Null => Kind::Null,
        V::Bool(v) => Kind::Bool(v),
        V::Number(n) => Kind::Number(n.into_text()),
        V::String(v) => Kind::String(v),
        V::Array(v) => Kind::Array(v.into_iter().map(from_parsed).collect()),
        V::Object(v) => Kind::Object(
            v.into_members()
                .into_iter()
                .map(|(k, v)| (k, from_parsed(v)))
                .collect(),
        ),
    });
    node.format = data::Format::Json;
    node
}
pub fn from_slice_with_limits<T: Decode>(bytes: &[u8], limits: Limits) -> Result<T, Error> {
    if bytes.len() > limits.input_bytes
        || limits.depth == 0
        || limits.depth > 128
        || limits.nodes == 0
    {
        return Err(Error::new("JSON resource limit"));
    }
    let v = crate::json::parse_for_data(bytes, limits.depth, limits.nodes)
        .map_err(|e| Error::new(e.to_string()).at(e.offset))?;
    T::decode(from_parsed(v))
}
pub fn from_slice<T: Decode>(bytes: &[u8]) -> Result<T, Error> {
    from_slice_with_limits(bytes, Limits::default())
}
pub fn from_str<T: Decode>(s: &str) -> Result<T, Error> {
    from_slice(s.as_bytes())
}
pub fn from_value<T: Decode>(v: Value) -> Result<T, Error> {
    T::decode(v.encode()?)
}
pub fn to_value<T: Encode>(v: T) -> Result<Value, Error> {
    Value::decode(v.encode()?)
}
pub fn to_vec<T: Encode + ?Sized>(v: &T) -> Result<Vec<u8>, Error> {
    write(v, false, Limits::default())
}
/// Bound the emitted JSON; the caller's Encode implementation owns its node construction.
pub fn to_vec_with_limits<T: Encode + ?Sized>(v: &T, limits: Limits) -> Result<Vec<u8>, Error> {
    write(v, false, limits)
}
pub fn to_vec_pretty<T: Encode + ?Sized>(v: &T) -> Result<Vec<u8>, Error> {
    write(v, true, Limits::default())
}
pub fn to_string<T: Encode + ?Sized>(v: &T) -> Result<String, Error> {
    String::from_utf8(to_vec(v)?).map_err(|_| Error::new("invalid UTF-8 output"))
}
pub fn to_string_pretty<T: Encode + ?Sized>(v: &T) -> Result<String, Error> {
    String::from_utf8(to_vec_pretty(v)?).map_err(|_| Error::new("invalid UTF-8 output"))
}
fn write<T: Encode + ?Sized>(v: &T, pretty: bool, limits: Limits) -> Result<Vec<u8>, Error> {
    let node = v.encode()?;
    let mut w = Writer {
        out: Vec::new(),
        limits,
        pretty,
        nodes: 0,
    };
    w.node(&node, 0)?;
    Ok(w.out)
}
struct Writer {
    out: Vec<u8>,
    limits: Limits,
    pretty: bool,
    nodes: usize,
}
impl Writer {
    fn bytes(&mut self, b: &[u8]) -> Result<(), Error> {
        if b.len() > self.limits.output_bytes.saturating_sub(self.out.len()) {
            return Err(Error::new("JSON output limit"));
        }
        self.out.extend_from_slice(b);
        Ok(())
    }
    fn string(&mut self, s: &str) -> Result<(), Error> {
        let mut n = 2usize;
        for b in s.bytes() {
            n = n
                .checked_add(match b {
                    b'"' | b'\\' | 8 | 9 | 10 | 12 | 13 => 2,
                    0..=31 => 6,
                    _ => 1,
                })
                .ok_or_else(|| Error::new("JSON output limit"))?;
        }
        if n > self.limits.output_bytes.saturating_sub(self.out.len()) {
            return Err(Error::new("JSON output limit"));
        }
        crate::json::write_string(s, &mut self.out);
        Ok(())
    }
    fn newline(&mut self, depth: usize) -> Result<(), Error> {
        if self.pretty {
            self.bytes(b"\n")?;
            for _ in 0..depth {
                self.bytes(b"  ")?;
            }
        }
        Ok(())
    }
    fn node(&mut self, n: &Node, depth: usize) -> Result<(), Error> {
        self.nodes += 1;
        if depth > self.limits.depth || self.nodes > self.limits.nodes {
            return Err(Error::new("JSON output resource limit"));
        }
        match &n.kind {
            Kind::Null => self.bytes(b"null"),
            Kind::Bool(b) => self.bytes(if *b { b"true" } else { b"false" }),
            Kind::Number(s) => {
                let _: Number = s.parse()?;
                self.bytes(s.as_bytes())
            }
            Kind::Float(v) => {
                if v.is_finite() {
                    self.bytes(data::format_float64(*v).as_bytes())
                } else {
                    self.bytes(b"null")
                }
            }
            Kind::String(v) | Kind::Datetime(v) => self.string(v),
            Kind::Array(a) => {
                self.bytes(b"[")?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        self.bytes(b",")?;
                    }
                    self.newline(depth + 1)?;
                    self.node(v, depth + 1)?;
                }
                if !a.is_empty() {
                    self.newline(depth)?;
                }
                self.bytes(b"]")
            }
            Kind::Object(a) => {
                self.bytes(b"{")?;
                for (i, (k, v)) in a.iter().enumerate() {
                    if i > 0 {
                        self.bytes(b",")?;
                    }
                    self.newline(depth + 1)?;
                    self.string(k)?;
                    self.bytes(if self.pretty { b": " } else { b":" })?;
                    self.node(v, depth + 1)?;
                }
                if !a.is_empty() {
                    self.newline(depth)?;
                }
                self.bytes(b"}")
            }
        }
    }
}
#[macro_export]
macro_rules! data_json {
 (null)=>{$crate::json_value::Value::Null};
 ([$($items:tt)*])=>{{let mut items=Vec::new();$crate::data_json!(@array items; $($items)*);$crate::json_value::Value::Array(items)}};
 ({$($items:tt)*})=>{{let mut items=$crate::json_value::Map::new();$crate::data_json!(@object items; $($items)*);$crate::json_value::Value::Object(items)}};
 ($v:expr)=>{$crate::json_value::to_value(&$v).expect("JSON value encoding failed")};
 (@array $out:ident;)=>{};
 (@array $out:ident;null $(,$($tail:tt)*)?)=>{{$out.push($crate::data_json!(null));$crate::data_json!(@array $out; $($($tail)*)?);}};
 (@array $out:ident;[$($v:tt)*] $(,$($tail:tt)*)?)=>{{$out.push($crate::data_json!([$($v)*]));$crate::data_json!(@array $out; $($($tail)*)?);}};
 (@array $out:ident;{$($v:tt)*} $(,$($tail:tt)*)?)=>{{$out.push($crate::data_json!({$($v)*}));$crate::data_json!(@array $out; $($($tail)*)?);}};
 (@array $out:ident;$v:expr $(,$($tail:tt)*)?)=>{{$out.push($crate::data_json!($v));$crate::data_json!(@array $out; $($($tail)*)?);}};
 (@object $out:ident;)=>{};
 (@object $out:ident;$key:tt:null $(,$($tail:tt)*)?)=>{{$out.insert(($key).into(),$crate::data_json!(null));$crate::data_json!(@object $out; $($($tail)*)?);}};
 (@object $out:ident;$key:tt:[$($v:tt)*] $(,$($tail:tt)*)?)=>{{$out.insert(($key).into(),$crate::data_json!([$($v)*]));$crate::data_json!(@object $out; $($($tail)*)?);}};
 (@object $out:ident;$key:tt:{$($v:tt)*} $(,$($tail:tt)*)?)=>{{$out.insert(($key).into(),$crate::data_json!({$($v)*}));$crate::data_json!(@object $out; $($($tail)*)?);}};
 (@object $out:ident;$key:tt:$v:expr $(,$($tail:tt)*)?)=>{{$out.insert(($key).into(),$crate::data_json!($v));$crate::data_json!(@object $out; $($($tail)*)?);}};
}

#[cfg(feature = "net")] // net seam: writing to caller-supplied I/O belongs to the I/O feature.
pub fn to_writer<W: std::io::Write, T: Encode + ?Sized>(
    mut out: W,
    value: &T,
) -> Result<(), Error> {
    out.write_all(&to_vec(value)?)
        .map_err(|e| Error::new(e.to_string()))
}
