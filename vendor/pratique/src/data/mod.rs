//! First-party typed data contracts. No derive engine or third-party serialization code.
//! Nodes preserve record order, duplicate input fields and TOML source offsets.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
mod macros;
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub kind: Kind,
    pub offset: usize,
    pub format: Format,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Data,
    Json,
    Toml,
}
#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Null,
    Bool(bool),
    Number(String),
    Float(f64),
    String(String),
    Datetime(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}
impl Node {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            offset: 0,
            format: Format::Data,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub message: String,
    pub offset: usize,
    pub path: Vec<String>,
}
impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            offset: 0,
            path: Vec::new(),
        }
    }
    pub fn at(mut self, offset: usize) -> Self {
        if self.offset == 0 {
            self.offset = offset;
        }
        self
    }
    pub fn field(mut self, key: impl Into<String>) -> Self {
        self.path.insert(0, key.into());
        self
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)?;
        if !self.path.is_empty() {
            write!(f, " ({})", self.path.join("."))?;
        }
        Ok(())
    }
}
impl std::error::Error for Error {}
pub trait Encode {
    fn encode(&self) -> Result<Node, Error>;
}
pub trait Decode: Sized {
    fn decode(node: Node) -> Result<Self, Error>;
    fn missing() -> Result<Self, Error> {
        Err(Error::new("missing required field"))
    }
}
pub struct Fields {
    members: Vec<(String, Node)>,
    sequence: Option<std::collections::VecDeque<Node>>,
    offset: usize,
    deny: bool,
}
impl Fields {
    pub fn new(node: Node, deny: bool) -> Result<Self, Error> {
        match node.kind {
            Kind::Object(members) => Ok(Self {
                members,
                sequence: None,
                offset: node.offset,
                deny,
            }),
            Kind::Array(a) => Ok(Self {
                members: Vec::new(),
                sequence: Some(a.into()),
                offset: node.offset,
                deny,
            }),
            _ => Err(Error::new("expected object").at(node.offset)),
        }
    }
    fn take(&mut self, key: &str) -> Result<Option<Node>, Error> {
        if let Some(a) = &mut self.sequence {
            return Ok(a.pop_front());
        }
        let mut value = None;
        let mut i = 0;
        while i < self.members.len() {
            if self.members[i].0 == key {
                let (_, node) = self.members.remove(i);
                if value.is_some() {
                    return Err(Error::new("duplicate field").at(node.offset).field(key));
                }
                value = Some(node);
            } else {
                i += 1;
            }
        }
        Ok(value)
    }
    pub fn field<T: Decode>(&mut self, key: &str) -> Result<T, Error> {
        let result = match self.take(key)? {
            Some(n) => {
                let at = n.offset;
                T::decode(n).map_err(|e| e.at(at))
            }
            None => {
                if self.sequence.is_some() {
                    Err(Error::new("missing sequence field"))
                } else {
                    T::missing()
                }
            }
        };
        result.map_err(|e| e.at(self.offset).field(key))
    }
    pub fn field_or<T: Decode>(
        &mut self,
        key: &str,
        default: impl FnOnce() -> T,
    ) -> Result<T, Error> {
        match self.take(key)? {
            Some(n) => {
                let at = n.offset;
                T::decode(n).map_err(|e| e.at(at).field(key))
            }
            None => Ok(default()),
        }
    }
    pub fn finish(self) -> Result<(), Error> {
        if self.sequence.as_ref().is_some_and(|a| !a.is_empty()) {
            return Err(Error::new("too many sequence fields").at(self.offset));
        }
        if self.deny {
            if let Some((k, v)) = self.members.first() {
                return Err(Error::new("unknown field").at(v.offset).field(k));
            }
        }
        Ok(())
    }
}
impl<T: Encode + ?Sized> Encode for &T {
    fn encode(&self) -> Result<Node, Error> {
        (*self).encode()
    }
}
impl Encode for Node {
    fn encode(&self) -> Result<Node, Error> {
        Ok(self.clone())
    }
}
impl Decode for Node {
    fn decode(node: Node) -> Result<Self, Error> {
        Ok(node)
    }
}
impl Encode for str {
    fn encode(&self) -> Result<Node, Error> {
        Ok(Node::new(Kind::String(self.into())))
    }
}
impl Encode for String {
    fn encode(&self) -> Result<Node, Error> {
        self.as_str().encode()
    }
}
impl Decode for String {
    fn decode(n: Node) -> Result<Self, Error> {
        match n.kind {
            Kind::String(s) => Ok(s),
            _ => Err(Error::new("expected string").at(n.offset)),
        }
    }
}
impl Encode for bool {
    fn encode(&self) -> Result<Node, Error> {
        Ok(Node::new(Kind::Bool(*self)))
    }
}
impl Decode for bool {
    fn decode(n: Node) -> Result<Self, Error> {
        match n.kind {
            Kind::Bool(v) => Ok(v),
            _ => Err(Error::new("expected boolean").at(n.offset)),
        }
    }
}
impl Encode for () {
    fn encode(&self) -> Result<Node, Error> {
        Ok(Node::new(Kind::Null))
    }
}
impl Decode for () {
    fn decode(n: Node) -> Result<Self, Error> {
        if matches!(n.kind, Kind::Null) {
            Ok(())
        } else {
            Err(Error::new("expected null").at(n.offset))
        }
    }
}
macro_rules! integers {($($ty:ty),*)=>{$(impl Encode for $ty {fn encode(&self)->Result<Node,Error>{Ok(Node::new(Kind::Number(self.to_string())))}}impl Decode for $ty {fn decode(n:Node)->Result<Self,Error>{if let Kind::Number(s)=n.kind {if !s.contains(['.','e','E']) && (s!="-0"||std::mem::size_of::<$ty>()==16) {return s.parse().map_err(|_|Error::new("integer out of range").at(n.offset));}}Err(Error::new("expected integer").at(n.offset))}})*}}
integers!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);
impl Encode for f64 {
    fn encode(&self) -> Result<Node, Error> {
        Ok(Node::new(Kind::Float(*self)))
    }
}
impl Decode for f64 {
    fn decode(n: Node) -> Result<Self, Error> {
        match n.kind {
            Kind::Float(v) => Ok(v),
            Kind::Number(s) => s
                .parse::<f64>()
                .ok()
                .filter(|v| v.is_finite())
                .ok_or_else(|| Error::new("float out of range").at(n.offset)),
            _ => Err(Error::new("expected number").at(n.offset)),
        }
    }
}
impl Encode for f32 {
    fn encode(&self) -> Result<Node, Error> {
        if self.is_finite() {
            Ok(Node::new(Kind::Number(format_float32(*self))))
        } else {
            ().encode()
        }
    }
}
impl Decode for f32 {
    fn decode(n: Node) -> Result<Self, Error> {
        Ok(f64::decode(n)? as f32)
    }
}
pub(crate) fn format_float64(v: f64) -> String {
    format_float(format!("{v:?}"), v, -5, 16)
}
fn format_float32(v: f32) -> String {
    format_float(format!("{v:?}"), f64::from(v), -6, 13)
}
// std supplies a shortest round-tripping decimal. Resolve exact halfway choices
// to an even final decimal digit, then apply the application's established JSON
// fixed/scientific thresholds. No external formatter tables or code are used.
fn format_float(s: String, v: f64, lower: i32, upper: i32) -> String {
    let negative = s.starts_with('-');
    let s = s.trim_start_matches('-');
    let (mantissa, exponent) = s.split_once('e').map_or((s, 0), |(m, e)| {
        (m, e.parse::<i32>().expect("Rust float exponent"))
    });
    let fractional = mantissa.split_once('.').map_or(0, |(_, f)| f.len() as i32);
    let digits = mantissa.replace('.', "");
    let mut coefficient = digits.parse::<u64>().expect("shortest float coefficient");
    if coefficient == 0 {
        return if negative { "-0.0" } else { "0.0" }.into();
    }
    let mut power = exponent - fractional;
    while coefficient % 10 == 0 {
        coefficient /= 10;
        power += 1;
    }
    if coefficient % 2 == 1 {
        if midpoint(v, coefficient * 2 - 1, power) {
            coefficient -= 1;
        } else if midpoint(v, coefficient * 2 + 1, power) {
            coefficient += 1;
        }
    }
    while coefficient % 10 == 0 {
        coefficient /= 10;
        power += 1;
    }
    let digits = coefficient.to_string();
    let scientific = power + digits.len() as i32 - 1;
    let mut out = if negative {
        "-".to_owned()
    } else {
        String::new()
    };
    if scientific < lower || scientific >= upper {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        if scientific >= 0 {
            out.push('+');
        }
        out.push_str(&scientific.to_string());
    } else {
        let point = digits.len() as i32 + power;
        if point <= 0 {
            out.push_str("0.");
            out.extend(std::iter::repeat_n('0', (-point) as usize));
            out.push_str(&digits);
        } else if point >= digits.len() as i32 {
            out.push_str(&digits);
            out.extend(std::iter::repeat_n(
                '0',
                (point - digits.len() as i32) as usize,
            ));
            out.push_str(".0");
        } else {
            out.push_str(&digits[..point as usize]);
            out.push('.');
            out.push_str(&digits[point as usize..]);
        }
    }
    out
}
fn midpoint(v: f64, odd: u64, power: i32) -> bool {
    let bits = v.to_bits() & 0x7fff_ffff_ffff_ffff;
    let biased = (bits >> 52) as i32;
    let mut mantissa = (bits & ((1u64 << 52) - 1)) | if biased == 0 { 0 } else { 1u64 << 52 };
    let mut exponent = if biased == 0 {
        -1074
    } else {
        biased - 1023 - 52
    };
    let shift = mantissa.trailing_zeros();
    mantissa >>= shift;
    exponent += shift as i32;
    if power >= 0 {
        if power > 22 {
            return false;
        }
        let Some(n) = odd.checked_mul(5u64.pow(power as u32)) else {
            return false;
        };
        mantissa == n && exponent == power - 1
    } else {
        let count = -power;
        if count > 24 {
            return false;
        }
        let Some(divisor) = 5u64.checked_pow(count as u32) else {
            return false;
        };
        odd.is_multiple_of(divisor) && mantissa == odd / divisor && exponent == power - 1
    }
}
impl<T: Encode> Encode for Option<T> {
    fn encode(&self) -> Result<Node, Error> {
        match self {
            Some(v) => v.encode(),
            None => ().encode(),
        }
    }
}
impl<T: Decode> Decode for Option<T> {
    fn decode(n: Node) -> Result<Self, Error> {
        if matches!(n.kind, Kind::Null) {
            Ok(None)
        } else {
            T::decode(n).map(Some)
        }
    }
    fn missing() -> Result<Self, Error> {
        Ok(None)
    }
}
impl<T: Encode> Encode for [T] {
    fn encode(&self) -> Result<Node, Error> {
        Ok(Node::new(Kind::Array(
            self.iter().map(Encode::encode).collect::<Result<_, _>>()?,
        )))
    }
}
impl<T: Encode> Encode for Vec<T> {
    fn encode(&self) -> Result<Node, Error> {
        self.as_slice().encode()
    }
}
impl<T: Encode, const N: usize> Encode for [T; N] {
    fn encode(&self) -> Result<Node, Error> {
        self.as_slice().encode()
    }
}
impl<T: Decode> Decode for Vec<T> {
    fn decode(n: Node) -> Result<Self, Error> {
        if let Kind::Array(a) = n.kind {
            a.into_iter()
                .enumerate()
                .map(|(i, n)| {
                    let at = n.offset;
                    T::decode(n).map_err(|e| e.at(at).field(i.to_string()))
                })
                .collect()
        } else {
            Err(Error::new("expected array").at(n.offset))
        }
    }
}
impl<T: Decode, const N: usize> Decode for [T; N] {
    fn decode(n: Node) -> Result<Self, Error> {
        Vec::<T>::decode(n)?
            .try_into()
            .map_err(|_| Error::new("array length mismatch"))
    }
}
impl<T: Encode> Encode for BTreeSet<T> {
    fn encode(&self) -> Result<Node, Error> {
        Ok(Node::new(Kind::Array(
            self.iter().map(Encode::encode).collect::<Result<_, _>>()?,
        )))
    }
}
impl<T: Decode + Ord> Decode for BTreeSet<T> {
    fn decode(n: Node) -> Result<Self, Error> {
        Ok(Vec::<T>::decode(n)?.into_iter().collect())
    }
}
impl<K: Encode + Ord, V: Encode> Encode for BTreeMap<K, V> {
    fn encode(&self) -> Result<Node, Error> {
        let mut out = Vec::with_capacity(self.len());
        for (k, v) in self {
            let key = map_key(k.encode()?)?;
            out.push((key, v.encode()?));
        }
        Ok(Node::new(Kind::Object(out)))
    }
}
fn map_key(n: Node) -> Result<String, Error> {
    match n.kind {
        Kind::String(s) | Kind::Number(s) => Ok(s),
        Kind::Bool(v) => Ok(v.to_string()),
        _ => Err(Error::new("invalid object key")),
    }
}
impl<T: Decode> Decode for BTreeMap<String, T> {
    fn decode(n: Node) -> Result<Self, Error> {
        if let Kind::Object(a) = n.kind {
            let mut out = Self::new();
            for (k, n) in a {
                let at = n.offset;
                let v = T::decode(n).map_err(|e| e.at(at).field(k.clone()))?;
                out.insert(k, v);
            }
            Ok(out)
        } else {
            Err(Error::new("expected object").at(n.offset))
        }
    }
}
impl<K: Encode + Eq + Hash, V: Encode> Encode for HashMap<K, V> {
    fn encode(&self) -> Result<Node, Error> {
        let mut out = Vec::with_capacity(self.len());
        for (k, v) in self {
            out.push((map_key(k.encode()?)?, v.encode()?));
        }
        Ok(Node::new(Kind::Object(out)))
    }
}
macro_rules! text_type {($($t:ty),*)=>{$(impl Encode for $t{fn encode(&self)->Result<Node,Error>{self.to_string().encode()}}impl Decode for $t{fn decode(n:Node)->Result<Self,Error>{let at=n.offset;String::decode(n)?.parse().map_err(|_|Error::new("invalid address").at(at))}})*}}
text_type!(SocketAddr, IpAddr);
impl Encode for PathBuf {
    fn encode(&self) -> Result<Node, Error> {
        self.to_str()
            .ok_or_else(|| Error::new("path is not UTF-8"))?
            .encode()
    }
}
impl Decode for PathBuf {
    fn decode(n: Node) -> Result<Self, Error> {
        Ok(String::decode(n)?.into())
    }
}
macro_rules! tuple {($($T:ident:$i:tt),+)=>{impl<$($T:Encode),+> Encode for ($($T,)+){fn encode(&self)->Result<Node,Error>{Ok(Node::new(Kind::Array(vec![$(self.$i.encode()?),+])))}}impl<$($T:Decode),+> Decode for ($($T,)+){fn decode(n:Node)->Result<Self,Error>{let toml=n.format==Format::Toml;let mut a=Vec::<Node>::decode(n)?.into_iter();let v=($($T::decode(a.next().ok_or_else(||Error::new("missing tuple element"))?)?,)+);if !toml&&a.next().is_some(){return Err(Error::new("too many tuple elements"));}Ok(v)}}}}
tuple!(A:0,B:1);
tuple!(A:0,B:1,C:2);
tuple!(A:0,B:1,C:2,D:3);
impl<T: ToOwned + Encode + ?Sized> Encode for std::borrow::Cow<'_, T> {
    fn encode(&self) -> Result<Node, Error> {
        self.as_ref().encode()
    }
}

/// Decode a unit enum's human-readable name without erasing format distinctions.
pub fn unit_variant(n: Node) -> Result<String, Error> {
    match n.kind {
        Kind::String(s) => Ok(s),
        Kind::Object(mut a) if a.len() == 1 => {
            let (k, v) = a.pop().unwrap();
            let valid = if n.format == Format::Toml {
                matches!(v.kind,Kind::Object(ref a)if a.is_empty())
            } else {
                matches!(v.kind, Kind::Null)
            };
            if valid {
                Ok(k)
            } else {
                Err(Error::new("invalid unit variant payload").at(n.offset))
            }
        }
        _ => Err(Error::new("expected enum name or single-entry object").at(n.offset)),
    }
}
