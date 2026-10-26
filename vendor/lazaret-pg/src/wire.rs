use crate::{Error, Result};
use std::collections::BTreeMap;

pub(crate) const MAX_MESSAGE: usize = 16 * 1024 * 1024;
pub(crate) const MAX_RESULT: usize = 64 * 1024 * 1024;
pub(crate) const MAX_ROWS: usize = 100_000;
pub(crate) const MAX_COLUMNS: usize = 4096;

pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| Error::protocol("length overflow"))?;
        let v = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| Error::protocol("truncated message"))?;
        self.at = end;
        Ok(v)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn string(&mut self) -> Result<&'a str> {
        let n = self.bytes[self.at..]
            .iter()
            .position(|x| *x == 0)
            .ok_or_else(|| Error::protocol("unterminated protocol string"))?;
        let v = self.take(n)?;
        self.take(1)?;
        std::str::from_utf8(v).map_err(|_| Error::protocol("non-UTF8 protocol string"))
    }
    pub fn done(&self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::protocol("trailing message bytes"))
        }
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let v = &self.bytes[self.at..];
        self.at = self.bytes.len();
        v
    }
}
pub(crate) fn cstr(out: &mut Vec<u8>, value: &str) -> Result<()> {
    if value.as_bytes().contains(&0) {
        return Err(Error::data("NUL in protocol string"));
    }
    out.extend_from_slice(value.as_bytes());
    out.push(0);
    Ok(())
}
pub(crate) fn message(kind: u8, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() > MAX_MESSAGE - 4 {
        return Err(Error::data("message exceeds configured bound"));
    }
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(kind);
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}
pub(crate) fn fields(body: &[u8]) -> Result<BTreeMap<u8, String>> {
    let mut r = Cursor::new(body);
    let mut out = BTreeMap::new();
    loop {
        let kind = r.byte()?;
        if kind == 0 {
            r.done()?;
            return Ok(out);
        }
        if out.insert(kind, r.string()?.into()).is_some() {
            return Err(Error::protocol("duplicate error field"));
        }
    }
}
