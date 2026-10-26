//! DKIM2 reconstruction recipes. Wire keys and one-based inclusive copy ranges
//! follow the existing protocol; bounded edit search is Workglen's own code.
use super::{
    Message, excluded, hashes,
    native_diff::{self, Budget, Edit, MAX_ITEMS},
};
use crate::error::{Result, ensure};
use pratique::json_value::{Value, json};
use std::collections::BTreeMap;
const MAX_BYTES: usize = 64 * 1024 * 1024;
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recipe {
    pub headers: Vec<HeaderRecipe>,
    pub body: BodyRecipe,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRecipe {
    pub name: String,
    pub steps: Vec<Step>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum BodyRecipe {
    #[default]
    None,
    Steps(Vec<Step>),
    Unreconstructable,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Copy { start: u32, end: u32 },
    Data(Vec<String>),
}
fn lines(body: &[u8]) -> Vec<&[u8]> {
    let mut v: Vec<_> = body
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect();
    if v.last() == Some(&&[][..]) {
        v.pop();
    }
    v
}
fn groups<'a>(headers: &[(&'a [u8], &'a [u8])]) -> BTreeMap<String, Vec<&'a [u8]>> {
    let mut out = BTreeMap::new();
    for &(n, v) in headers {
        if !excluded(n) {
            out.entry(String::from_utf8_lossy(n).to_ascii_lowercase())
                .or_insert_with(Vec::new)
                .push(v.trim_ascii());
        }
    }
    out
}
fn literal(input: &[u8]) -> Result<String> {
    let mut out = Vec::new();
    let mut folded = false;
    for &b in input {
        if matches!(b, b'\r' | b'\n') {
            folded = true;
            continue;
        }
        if folded && !b.is_ascii_whitespace() && !out.is_empty() {
            out.push(b' ');
        }
        folded = false;
        out.push(b);
    }
    Ok(String::from_utf8(out)?)
}
fn steps(before: &[&[u8]], after: &[&[u8]], budget: &mut Budget) -> Result<Vec<Step>> {
    if let Some(edits) = native_diff::diff(after, before, budget) {
        edits
            .into_iter()
            .map(|e| {
                Ok(match e {
                    Edit::Copy { start, len } => Step::Copy {
                        start: u32::try_from(start + 1)?,
                        end: u32::try_from(start + len)?,
                    },
                    Edit::Insert { start, len } => Step::Data(
                        before[start..start + len]
                            .iter()
                            .map(|b| literal(b))
                            .collect::<Result<_>>()?,
                    ),
                })
            })
            .collect()
    } else if before.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(vec![Step::Data(
            before.iter().map(|b| literal(b)).collect::<Result<_>>()?,
        )])
    }
}
fn emit<'a>(steps: &'a [Step], values: &[&'a [u8]]) -> Result<Vec<&'a [u8]>> {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for step in steps {
        match step {
            Step::Copy { start, end } => {
                let start = (*start).max(1) as usize;
                let end = (*end as usize).min(values.len());
                if start <= end {
                    for v in &values[start - 1..end] {
                        bytes = bytes.saturating_add(v.len() + 2);
                        ensure!(
                            bytes <= MAX_BYTES && out.len() < MAX_ITEMS,
                            "recipe output limit"
                        );
                        out.push(*v);
                    }
                }
            }
            Step::Data(data) => {
                for v in data {
                    bytes = bytes.saturating_add(v.len() + 2);
                    ensure!(
                        bytes <= MAX_BYTES && out.len() < MAX_ITEMS,
                        "recipe output limit"
                    );
                    out.push(v.as_bytes());
                }
            }
        }
    }
    Ok(out)
}
impl Recipe {
    fn unavailable() -> Self {
        Self {
            headers: Vec::new(),
            body: BodyRecipe::Unreconstructable,
        }
    }
    pub fn diff(before: &Message<'_>, after: &Message<'_>) -> Self {
        let build = || -> Result<Self> {
            ensure!(
                before
                    .raw_message
                    .len()
                    .saturating_add(after.raw_message.len())
                    <= MAX_BYTES,
                "recipe input limit"
            );
            let count = before.raw_body().iter().filter(|b| **b == b'\n').count()
                + after.raw_body().iter().filter(|b| **b == b'\n').count()
                + before.headers.len()
                + after.headers.len()
                + 2;
            ensure!(count <= MAX_ITEMS, "recipe item limit");
            let mut old = groups(&before.headers);
            let mut new = groups(&after.headers);
            let keys: std::collections::BTreeSet<_> =
                old.keys().chain(new.keys()).cloned().collect();
            let mut headers = Vec::new();
            let mut budget = Budget::default();
            for name in keys {
                let mut a = old.remove(&name).unwrap_or_default();
                let mut b = new.remove(&name).unwrap_or_default();
                if a != b {
                    a.reverse();
                    b.reverse();
                    headers.push(HeaderRecipe {
                        name,
                        steps: steps(&a, &b, &mut budget)?,
                    });
                }
            }
            let body = if before.raw_body() == after.raw_body() {
                BodyRecipe::None
            } else {
                BodyRecipe::Steps(steps(
                    &lines(before.raw_body()),
                    &lines(after.raw_body()),
                    &mut budget,
                )?)
            };
            let result = Self { headers, body };
            let rebuilt = result.apply(&after.headers, after.raw_body())?;
            let parsed = Message::parse(&rebuilt)?;
            ensure!(
                hashes(before) == hashes(&parsed),
                "recipe cannot reconstruct bytes"
            );
            Ok(result)
        };
        build().unwrap_or_else(|_| Self::unavailable())
    }
    pub fn apply(&self, headers: &[(&[u8], &[u8])], body: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            body.len() <= MAX_BYTES && self.headers.len() <= 256,
            "recipe input limit"
        );
        let mut grouped = groups(headers);
        for r in &self.headers {
            grouped.entry(r.name.to_ascii_lowercase()).or_default();
        }
        let mut out = Vec::new();
        for (name, mut values) in grouped {
            ensure!(
                !name.is_empty() && name.bytes().all(|b| (33..=126).contains(&b) && b != b':'),
                "invalid recipe header name"
            );
            if let Some(r) = self
                .headers
                .iter()
                .rev()
                .find(|r| r.name.eq_ignore_ascii_case(&name))
            {
                values.reverse();
                values = emit(&r.steps, &values)?;
                values.reverse();
            }
            for value in values {
                ensure!(
                    out.len().saturating_add(value.len() + name.len() + 4) <= MAX_BYTES,
                    "recipe output limit"
                );
                out.extend(name.as_bytes());
                out.extend(b": ");
                out.extend(value);
                out.extend(b"\r\n");
            }
        }
        out.extend(b"\r\n");
        match &self.body {
            BodyRecipe::None => {
                ensure!(out.len() + body.len() <= MAX_BYTES, "recipe output limit");
                out.extend(body)
            }
            BodyRecipe::Unreconstructable => crate::bail!("unreconstructable message"),
            BodyRecipe::Steps(s) => {
                let source = lines(body);
                ensure!(source.len() <= MAX_ITEMS, "recipe line limit");
                let values = emit(s, &source)?;
                if values.is_empty() {
                    out.extend(b"\r\n");
                }
                for value in values {
                    ensure!(
                        out.len() + value.len() + 2 <= MAX_BYTES,
                        "recipe output limit"
                    );
                    out.extend(value);
                    out.extend(b"\r\n");
                }
            }
        }
        Ok(out)
    }
    pub fn to_json(&self, out: &mut Vec<u8>) -> Result<()> {
        fn values(s: &[Step]) -> Value {
            Value::Array(
                s.iter()
                    .map(|s| match s {
                        Step::Copy { start, end } => json!({"c":[start,end]}),
                        Step::Data(v) => json!({"d":v}),
                    })
                    .collect(),
            )
        }
        let mut map: pratique::json_value::Map<String, pratique::json_value::Value> =
            pratique::json_value::Map::new();
        if !self.headers.is_empty() {
            map.insert(
                "h".into(),
                Value::Object(
                    self.headers
                        .iter()
                        .map(|h| (h.name.clone(), values(&h.steps)))
                        .collect(),
                ),
            );
        }
        match &self.body {
            BodyRecipe::None => {}
            BodyRecipe::Unreconstructable => {
                map.insert("b".into(), Value::Null);
            }
            BodyRecipe::Steps(s) => {
                map.insert("b".into(), values(s));
            }
        }
        pratique::json_value::to_writer(out, &map)?;
        Ok(())
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_BYTES, "recipe JSON limit");
        let value: Value = pratique::json_value::from_slice(bytes)?;
        let map = value
            .as_object()
            .ok_or_else(|| crate::error!("recipe object required"))?;
        fn read(v: &Value) -> Result<Vec<Step>> {
            let list = v
                .as_array()
                .ok_or_else(|| crate::error!("recipe steps required"))?;
            ensure!(list.len() <= MAX_ITEMS, "recipe step limit");
            let mut out = Vec::new();
            for v in list {
                let Some(m) = v.as_object() else { continue };
                if let Some(c) = m.get("c").and_then(Value::as_array) {
                    ensure!(c.len() == 2, "copy range requires two indices");
                    let n = |v: &Value| -> Result<u32> {
                        Ok(u32::try_from(
                            v.as_u64()
                                .ok_or_else(|| crate::error!("invalid copy index"))?,
                        )?)
                    };
                    out.push(Step::Copy {
                        start: n(&c[0])?,
                        end: n(&c[1])?,
                    });
                } else if let Some(d) = m.get("d").and_then(Value::as_array) {
                    let data = d
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .map(str::to_owned)
                                .ok_or_else(|| crate::error!("literal text required"))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    out.push(Step::Data(data));
                }
            }
            Ok(out)
        }
        let mut headers = Vec::new();
        if let Some(h) = map.get("h") {
            let h = h
                .as_object()
                .ok_or_else(|| crate::error!("header map required"))?;
            ensure!(h.len() <= 256, "recipe header limit");
            for (n, v) in h {
                headers.push(HeaderRecipe {
                    name: n.clone(),
                    steps: read(v)?,
                });
            }
        }
        let body = match map.get("b") {
            None => BodyRecipe::None,
            Some(Value::Null) => BodyRecipe::Unreconstructable,
            Some(v) => BodyRecipe::Steps(read(v)?),
        };
        Ok(Self { headers, body })
    }
}
