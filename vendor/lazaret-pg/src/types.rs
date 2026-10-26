use crate::{
    Error, Result,
    wire::{Cursor, MAX_COLUMNS},
};
use std::sync::Arc;

pub struct Parameter {
    pub oid: u32,
    pub format: i16,
    pub value: Option<Vec<u8>>,
}
pub trait ToSql: Sync {
    fn to_sql(&self) -> Result<Parameter>;
}
impl<T: ToSql + ?Sized> ToSql for &T {
    fn to_sql(&self) -> Result<Parameter> {
        (**self).to_sql()
    }
}
impl<T: ToSql> ToSql for Option<T> {
    fn to_sql(&self) -> Result<Parameter> {
        self.as_ref().map_or(
            Ok(Parameter {
                oid: 0,
                format: 0,
                value: None,
            }),
            ToSql::to_sql,
        )
    }
}
fn text(oid: u32, value: String) -> Result<Parameter> {
    if value.contains('\0') {
        return Err(Error::data("NUL in text parameter"));
    }
    Ok(Parameter {
        oid,
        format: 0,
        value: Some(value.into_bytes()),
    })
}
impl ToSql for str {
    fn to_sql(&self) -> Result<Parameter> {
        text(0, self.into())
    }
}
impl ToSql for String {
    fn to_sql(&self) -> Result<Parameter> {
        self.as_str().to_sql()
    }
}
macro_rules! number {
    ($ty:ty,$oid:expr) => {
        impl ToSql for $ty {
            fn to_sql(&self) -> Result<Parameter> {
                text($oid, self.to_string())
            }
        }
    };
}
number!(i16, 21);
number!(i32, 23);
number!(i64, 20);
number!(f32, 700);
number!(f64, 701);
impl ToSql for bool {
    fn to_sql(&self) -> Result<Parameter> {
        text(16, if *self { "t" } else { "f" }.into())
    }
}
impl ToSql for [u8] {
    fn to_sql(&self) -> Result<Parameter> {
        Ok(Parameter {
            oid: 17,
            format: 1,
            value: Some(self.to_vec()),
        })
    }
}
impl ToSql for Vec<u8> {
    fn to_sql(&self) -> Result<Parameter> {
        self.as_slice().to_sql()
    }
}
fn text_array<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Result<Parameter> {
    let mut result = String::from("{");
    for (i, value) in values.into_iter().enumerate() {
        if i > 0 {
            result.push(',');
        }
        if let Some(value) = value {
            result.push('"');
            for c in value.chars() {
                if c == '"' || c == '\\' {
                    result.push('\\');
                }
                result.push(c);
            }
            result.push('"');
        } else {
            result.push_str("NULL");
        }
        if result.len() > crate::wire::MAX_MESSAGE - 16 {
            return Err(Error::data("array parameter exceeds limit"));
        }
    }
    result.push('}');
    text(1009, result)
}
impl ToSql for Vec<String> {
    fn to_sql(&self) -> Result<Parameter> {
        text_array(self.iter().map(|s| Some(s.as_str())))
    }
}
impl ToSql for Vec<&str> {
    fn to_sql(&self) -> Result<Parameter> {
        text_array(self.iter().map(|s| Some(*s)))
    }
}
impl ToSql for Vec<Option<String>> {
    fn to_sql(&self) -> Result<Parameter> {
        text_array(self.iter().map(Option::as_deref))
    }
}
#[cfg(feature = "with-json")]
impl ToSql for pratique::json_value::Value {
    fn to_sql(&self) -> Result<Parameter> {
        text(3802, self.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct Column {
    name: String,
    oid: u32,
}
impl Column {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn oid(&self) -> u32 {
        self.oid
    }
}
#[derive(Clone, Debug)]
pub struct Row {
    pub(crate) columns: Arc<Vec<Column>>,
    pub(crate) values: Vec<Option<Vec<u8>>>,
}
pub trait RowIndex {
    fn index(&self, columns: &[Column]) -> Option<usize>;
}
impl RowIndex for usize {
    fn index(&self, columns: &[Column]) -> Option<usize> {
        (*self < columns.len()).then_some(*self)
    }
}
impl RowIndex for &str {
    fn index(&self, columns: &[Column]) -> Option<usize> {
        columns.iter().position(|c| c.name == *self)
    }
}
impl Row {
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }
    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    pub fn try_get<I: RowIndex, T: FromSql>(&self, index: I) -> Result<T> {
        let i = index
            .index(&self.columns)
            .ok_or_else(|| Error::data("column does not exist"))?;
        T::from_sql(self.columns[i].oid, self.values[i].as_deref())
    }
    /// Panics only for an incorrect application-requested type/index; use try_get for dynamic SQL.
    pub fn get<I: RowIndex, T: FromSql>(&self, index: I) -> T {
        self.try_get(index)
            .expect("PostgreSQL column type/index mismatch")
    }
}
pub trait FromSql: Sized {
    fn from_sql(oid: u32, raw: Option<&[u8]>) -> Result<Self>;
}
fn string(raw: Option<&[u8]>) -> Result<&str> {
    std::str::from_utf8(raw.ok_or_else(|| Error::data("unexpected SQL NULL"))?)
        .map_err(|_| Error::protocol("invalid UTF8 result"))
}
impl<T: FromSql> FromSql for Option<T> {
    fn from_sql(oid: u32, raw: Option<&[u8]>) -> Result<Self> {
        raw.map(|v| T::from_sql(oid, Some(v))).transpose()
    }
}
impl FromSql for String {
    fn from_sql(_: u32, raw: Option<&[u8]>) -> Result<Self> {
        Ok(string(raw)?.into())
    }
}
macro_rules! scalar {
    ($ty:ty,$oid:expr) => {
        impl FromSql for $ty {
            fn from_sql(oid: u32, raw: Option<&[u8]>) -> Result<Self> {
                if oid != $oid {
                    return Err(Error::data("unexpected column type"));
                }
                string(raw)?
                    .parse()
                    .map_err(|_| Error::protocol("invalid scalar value"))
            }
        }
    };
}
scalar!(i16, 21);
scalar!(i32, 23);
scalar!(i64, 20);
scalar!(f32, 700);
scalar!(f64, 701);
impl FromSql for bool {
    fn from_sql(oid: u32, raw: Option<&[u8]>) -> Result<Self> {
        if oid != 16 {
            return Err(Error::data("expected boolean"));
        }
        match string(raw)? {
            "t" => Ok(true),
            "f" => Ok(false),
            _ => Err(Error::protocol("invalid boolean value")),
        }
    }
}
impl FromSql for Vec<u8> {
    fn from_sql(oid: u32, raw: Option<&[u8]>) -> Result<Self> {
        if oid != 17 {
            return Err(Error::data("expected bytea"));
        }
        let s = string(raw)?;
        let mut out = Vec::new();
        if let Some(hex) = s.strip_prefix("\\x") {
            if hex.len() % 2 != 0 {
                return Err(Error::protocol("invalid bytea hex"));
            }
            for p in hex.as_bytes().as_chunks::<2>().0 {
                let a = (p[0] as char)
                    .to_digit(16)
                    .ok_or_else(|| Error::protocol("invalid bytea hex"))?;
                let b = (p[1] as char)
                    .to_digit(16)
                    .ok_or_else(|| Error::protocol("invalid bytea hex"))?;
                out.push((a * 16 + b) as u8);
            }
        } else {
            let b = s.as_bytes();
            let mut i = 0;
            while i < b.len() {
                if b[i] != b'\\' {
                    out.push(b[i]);
                    i += 1;
                } else if b.get(i + 1) == Some(&b'\\') {
                    out.push(b'\\');
                    i += 2;
                } else {
                    let p = b
                        .get(i + 1..i + 4)
                        .ok_or_else(|| Error::protocol("invalid bytea escape"))?;
                    if !(b'0'..=b'3').contains(&p[0])
                        || !p[1..].iter().all(|v| (b'0'..=b'7').contains(v))
                    {
                        return Err(Error::protocol("invalid bytea escape"));
                    }
                    out.push((p[0] - b'0') * 64 + (p[1] - b'0') * 8 + p[2] - b'0');
                    i += 4;
                }
            }
        }
        Ok(out)
    }
}
#[cfg(feature = "with-json")]
impl FromSql for pratique::json_value::Value {
    fn from_sql(oid: u32, raw: Option<&[u8]>) -> Result<Self> {
        if ![114, 3802].contains(&oid) {
            return Err(Error::data("expected JSON"));
        }
        pratique::json_value::from_slice(raw.ok_or_else(|| Error::data("unexpected SQL NULL"))?)
            .map_err(|_| Error::protocol("invalid JSON result"))
    }
}

/// Exact PostgreSQL text representation for numeric, date/time, UUID, arrays and custom types.
/// Parameters use server inference; no floating-point conversion is performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Text(pub String);
impl ToSql for Text {
    fn to_sql(&self) -> Result<Parameter> {
        self.0.to_sql()
    }
}
impl FromSql for Text {
    fn from_sql(_: u32, raw: Option<&[u8]>) -> Result<Self> {
        Ok(Self(string(raw)?.into()))
    }
}

pub(crate) fn columns(body: &[u8]) -> Result<Arc<Vec<Column>>> {
    let mut r = Cursor::new(body);
    let n = r.u16()? as usize;
    if n > MAX_COLUMNS {
        return Err(Error::protocol("column limit exceeded"));
    }
    let mut columns = Vec::with_capacity(n);
    for _ in 0..n {
        let name = r.string()?.into();
        r.u32()?;
        r.u16()?;
        let oid = r.u32()?;
        r.u16()?;
        r.i32()?;
        if r.u16()? != 0 {
            return Err(Error::protocol("unexpected binary result format"));
        }
        columns.push(Column { name, oid });
    }
    r.done()?;
    Ok(Arc::new(columns))
}
pub(crate) fn row(body: &[u8], columns: Arc<Vec<Column>>) -> Result<Row> {
    let mut r = Cursor::new(body);
    if r.u16()? as usize != columns.len() {
        return Err(Error::protocol("row column count mismatch"));
    }
    let mut values = Vec::with_capacity(columns.len());
    for column in columns.iter() {
        let size = r.i32()?;
        let value = if size == -1 {
            None
        } else if size < 0 {
            return Err(Error::protocol("invalid field length"));
        } else {
            let v = r.take(size as usize)?;
            validate(column.oid, v)?;
            Some(v.to_vec())
        };
        values.push(value);
    }
    r.done()?;
    Ok(Row { columns, values })
}
fn validate(oid: u32, v: &[u8]) -> Result<()> {
    string(Some(v))?;
    match oid {
        16 => {
            bool::from_sql(oid, Some(v))?;
        }
        20 => {
            i64::from_sql(oid, Some(v))?;
        }
        21 => {
            i16::from_sql(oid, Some(v))?;
        }
        23 => {
            i32::from_sql(oid, Some(v))?;
        }
        17 => {
            Vec::<u8>::from_sql(oid, Some(v))?;
        }
        700 => {
            f32::from_sql(oid, Some(v))?;
        }
        701 => {
            f64::from_sql(oid, Some(v))?;
        }
        #[cfg(feature = "with-json")]
        114 | 3802 => {
            pratique::json_value::Value::from_sql(oid, Some(v))?;
        }
        _ => {}
    }
    Ok(())
}
