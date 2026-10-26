//! Bounded TOML 1.1 grammar and table-definition state. No upstream parser code.
use crate::{Error, Kind, Node, State};
use std::collections::btree_map::Entry;
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub input_bytes: usize,
    pub depth: usize,
    pub nodes: usize,
    pub key_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 8 * 1024 * 1024,
            depth: 64,
            nodes: 100_000,
            key_bytes: 64 * 1024,
        }
    }
}
struct Parser<'a> {
    s: &'a str,
    pos: usize,
    limits: Limits,
    work: usize,
}
impl<'a> Parser<'a> {
    fn err<T>(&self, message: &str) -> Result<T> {
        Err(Error::at(message, self.pos))
    }
    fn peek(&self) -> Option<u8> {
        self.s.as_bytes().get(self.pos).copied()
    }
    fn hws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }
    fn newline(&mut self) -> Result<bool> {
        match self.peek() {
            Some(b'\n') => {
                self.pos += 1;
                Ok(true)
            }
            Some(b'\r') => {
                if self.s.as_bytes().get(self.pos + 1) != Some(&b'\n') {
                    return self.err("bare carriage return");
                }
                self.pos += 2;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    fn comment(&mut self) -> Result<()> {
        if self.peek() != Some(b'#') {
            return Ok(());
        }
        self.pos += 1;
        while let Some(c) = self.peek() {
            if matches!(c, b'\r' | b'\n') {
                break;
            }
            if c < 32 && c != b'\t' || c == 127 {
                return self.err("control character in comment");
            }
            self.pos += 1;
        }
        Ok(())
    }
    fn ws(&mut self) -> Result<()> {
        loop {
            self.hws();
            self.comment()?;
            if !self.newline()? {
                return Ok(());
            }
        }
    }
    fn expect(&mut self, b: u8) -> Result<()> {
        if self.peek() != Some(b) {
            return self.err("unexpected token");
        }
        self.pos += 1;
        Ok(())
    }
    fn charge(&mut self, n: usize) -> Result<()> {
        self.work = self
            .work
            .checked_add(n)
            .ok_or_else(|| Error::at("node limit", self.pos))?;
        if self.work > self.limits.nodes {
            return self.err("node limit");
        }
        Ok(())
    }
    fn path(&mut self) -> Result<Vec<String>> {
        let mut path = Vec::new();
        loop {
            self.hws();
            let key = match self.peek() {
                Some(b'\'' | b'"') => self.string(false)?,
                _ => {
                    let start = self.pos;
                    while self
                        .peek()
                        .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                    {
                        self.pos += 1;
                    }
                    if self.pos == start {
                        return self.err("expected a key");
                    }
                    self.s[start..self.pos].to_owned()
                }
            };
            if key.len() > self.limits.key_bytes {
                return self.err("key size limit");
            }
            path.push(key);
            if path.len() > self.limits.depth {
                return self.err("key depth limit");
            }
            self.hws();
            if self.peek() != Some(b'.') {
                break;
            }
            self.pos += 1;
        }
        self.charge(path.len())?;
        Ok(path)
    }
    fn string(&mut self, allow_multiline: bool) -> Result<String> {
        let quote = self.peek().unwrap();
        self.pos += 1;
        let multi = self.s.as_bytes().get(self.pos..self.pos + 2) == Some(&[quote, quote]);
        if multi {
            if !allow_multiline {
                return self.err("multiline keys are not allowed");
            }
            self.pos += 2;
            self.newline()?;
        }
        let mut out = String::new();
        loop {
            let Some(b) = self.peek() else {
                return self.err("unterminated string");
            };
            if b == quote {
                if !multi {
                    self.pos += 1;
                    return Ok(out);
                }
                let run = self.s.as_bytes()[self.pos..]
                    .iter()
                    .take_while(|b| **b == quote)
                    .count();
                if run >= 3 {
                    if run > 5 {
                        return self.err("too many string delimiters");
                    }
                    for _ in 3..run {
                        out.push(quote as char);
                    }
                    self.pos += run;
                    return Ok(out);
                }
                for _ in 0..run {
                    out.push(quote as char);
                }
                self.pos += run;
                continue;
            }
            if b == b'\\' && quote == b'"' {
                self.pos += 1;
                if multi && matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                    self.hws();
                    if !self.newline()? {
                        return self.err("line continuation requires newline");
                    }
                    loop {
                        self.hws();
                        if !self.newline()? {
                            break;
                        }
                    }
                    continue;
                }
                let Some(escape) = self.peek() else {
                    return self.err("unfinished string escape");
                };
                self.pos += 1;
                match escape {
                    b'b' => out.push('\u{8}'),
                    b't' => out.push('\t'),
                    b'n' => out.push('\n'),
                    b'f' => out.push('\u{c}'),
                    b'r' => out.push('\r'),
                    b'e' => out.push('\u{1b}'),
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'x' | b'u' | b'U' => {
                        let n = match escape {
                            b'x' => 2,
                            b'u' => 4,
                            _ => 8,
                        };
                        let Some(bytes) = self.s.as_bytes().get(self.pos..self.pos + n) else {
                            return self.err("unfinished Unicode escape");
                        };
                        if !bytes.iter().all(u8::is_ascii_hexdigit) {
                            return self.err("invalid Unicode escape");
                        }
                        let cp =
                            u32::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap();
                        let Some(c) = char::from_u32(cp) else {
                            return self.err("invalid Unicode scalar");
                        };
                        out.push(c);
                        self.pos += n;
                    }
                    _ => return self.err("unknown string escape"),
                };
                continue;
            }
            if matches!(b, b'\r' | b'\n') {
                if !multi {
                    return self.err("newline in single-line string");
                }
                self.newline()?;
                out.push('\n');
                continue;
            }
            if b < 32 && b != b'\t' || b == 127 {
                return self.err("control character in string");
            }
            let c = self.s[self.pos..].chars().next().unwrap();
            out.push(c);
            self.pos += c.len_utf8();
        }
    }
    fn value(&mut self, depth: usize) -> Result<Node> {
        if depth > self.limits.depth {
            return self.err("value depth limit");
        }
        self.charge(1)?;
        let at = self.pos;
        let kind = match self.peek() {
            Some(b'\'' | b'"') => Kind::String(self.string(true)?),
            Some(b'[') => {
                self.pos += 1;
                self.ws()?;
                let mut values = Vec::new();
                if self.peek() != Some(b']') {
                    loop {
                        values.push(self.value(depth + 1)?);
                        self.ws()?;
                        if self.peek() != Some(b',') {
                            break;
                        }
                        self.pos += 1;
                        self.ws()?;
                        if self.peek() == Some(b']') {
                            break;
                        }
                    }
                }
                self.expect(b']')?;
                Kind::Array(values, false)
            }
            Some(b'{') => {
                self.pos += 1;
                self.ws()?;
                let mut table = Node::table(State::Dotted, at);
                if self.peek() != Some(b'}') {
                    loop {
                        let path = self.path()?;
                        if depth + path.len() > self.limits.depth {
                            return self.err("inline table depth limit");
                        }
                        self.expect(b'=')?;
                        self.hws();
                        let value = self.value(depth + path.len())?;
                        assign(&mut table, &path, value)?;
                        self.ws()?;
                        if self.peek() != Some(b',') {
                            break;
                        }
                        self.pos += 1;
                        self.ws()?;
                        if self.peek() == Some(b'}') {
                            break;
                        }
                    }
                }
                self.expect(b'}')?;
                if let Kind::Table(_, state) = &mut table.kind {
                    *state = State::Inline;
                }
                table.kind
            }
            Some(_) => {
                let start = self.pos;
                while self.peek().is_some_and(|b| {
                    !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}' | b'#')
                }) {
                    self.pos += 1;
                }
                // TOML permits exactly one space between date and time.
                if self.pos - start == 10
                    && self.s.as_bytes().get(start + 4) == Some(&b'-')
                    && self.peek() == Some(b' ')
                    && self.s.as_bytes().get(self.pos + 3) == Some(&b':')
                {
                    self.pos += 1;
                    while self.peek().is_some_and(|b| {
                        !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}' | b'#')
                    }) {
                        self.pos += 1;
                    }
                }
                scalar(&self.s[start..self.pos]).map_err(|s| Error::at(s, start))?
            }
            None => return self.err("missing value"),
        };
        Ok(Node { kind, at })
    }
}
fn table_mut(node: &mut Node) -> Result<&mut std::collections::BTreeMap<String, Node>> {
    match &mut node.kind {
        Kind::Table(map, state) if *state != State::Inline => Ok(map),
        _ => Err(Error::at(
            "cannot extend a scalar, array or inline table",
            node.at,
        )),
    }
}
fn descend<'a>(
    node: &'a mut Node,
    path: &[String],
    for_header: bool,
    at: usize,
) -> Result<&'a mut Node> {
    if path.is_empty() {
        return Ok(node);
    }
    let table = table_mut(node)?;
    let child = table.entry(path[0].clone()).or_insert_with(|| {
        Node::table(
            if for_header {
                State::Implicit
            } else {
                State::Dotted
            },
            at,
        )
    });
    if for_header && matches!(&child.kind, Kind::Array(_, true)) {
        let Kind::Array(values, _) = &mut child.kind else {
            unreachable!()
        };
        let current = values
            .last_mut()
            .ok_or_else(|| Error::at("empty array of tables", at))?;
        return descend(current, &path[1..], true, at);
    }
    if !for_header {
        match &mut child.kind {
            Kind::Table(_, state) if *state == State::Dotted => {}
            _ => {
                return Err(Error::at(
                    "dotted key redefines an existing value or table",
                    at,
                ));
            }
        }
    }
    descend(child, &path[1..], for_header, at)
}
fn assign(root: &mut Node, path: &[String], value: Node) -> Result<()> {
    let at = value.at;
    let (last, parent) = path.split_last().unwrap();
    let table = table_mut(descend(root, parent, false, at)?)?;
    match table.entry(last.clone()) {
        Entry::Vacant(e) => {
            e.insert(value);
            Ok(())
        }
        Entry::Occupied(_) => Err(Error::at("duplicate key", at)),
    }
}
fn header(root: &mut Node, path: &[String], array: bool, at: usize) -> Result<()> {
    let (last, parent) = path.split_last().unwrap();
    let table = table_mut(descend(root, parent, true, at)?)?;
    match table.entry(last.clone()) {
        Entry::Vacant(e) => {
            e.insert(if array {
                Node {
                    kind: Kind::Array(vec![Node::table(State::Explicit, at)], true),
                    at,
                }
            } else {
                Node::table(State::Explicit, at)
            });
            Ok(())
        }
        Entry::Occupied(mut e) => {
            let n = e.get_mut();
            match &mut n.kind {
                Kind::Array(values, true) if array => {
                    values.push(Node::table(State::Explicit, at));
                    Ok(())
                }
                Kind::Table(_, state) if !array && *state == State::Implicit => {
                    *state = State::Explicit;
                    Ok(())
                }
                _ => Err(Error::at("duplicate or conflicting table", at)),
            }
        }
    }
}
pub(crate) fn document(input: &str, limits: Limits) -> Result<Node> {
    if input.len() > limits.input_bytes {
        return Err(Error::at("input size limit", 0));
    }
    if limits.depth > 128 {
        return Err(Error::at("depth limit exceeds hard ceiling", 0));
    }
    let mut p = Parser {
        s: input,
        pos: 0,
        limits,
        work: 0,
    };
    let mut root = Node::table(State::Explicit, 0);
    let mut active = Vec::new();
    // A single initial BOM is accepted by the pinned former parser.
    if input.starts_with('\u{feff}') {
        p.pos = 3;
    }
    loop {
        p.ws()?;
        if p.peek().is_none() {
            return Ok(root);
        }
        let at = p.pos;
        if p.peek() == Some(b'[') {
            p.pos += 1;
            let array = p.peek() == Some(b'[');
            if array {
                p.pos += 1;
            }
            let path = p.path()?;
            p.expect(b']')?;
            if array {
                p.expect(b']')?;
            }
            header(&mut root, &path, array, at)?;
            active = path;
        } else {
            let path = p.path()?;
            if active.len() + path.len() > limits.depth {
                return p.err("table depth limit");
            }
            p.expect(b'=')?;
            p.hws();
            let value = p.value(active.len() + path.len())?;
            let table = descend(&mut root, &active, true, at)?;
            assign(table, &path, value)?;
        }
        p.hws();
        p.comment()?;
        if p.peek().is_some() && !p.newline()? {
            return p.err("expected end of statement");
        }
    }
}
fn digit_group(s: &str, radix: u32) -> bool {
    !s.is_empty()
        && s.as_bytes().iter().enumerate().all(|(i, b)| {
            let digit = |b: u8| (b as char).is_digit(radix) && b.is_ascii();
            if *b == b'_' {
                i > 0 && i + 1 < s.len() && digit(s.as_bytes()[i - 1]) && digit(s.as_bytes()[i + 1])
            } else {
                digit(*b)
            }
        })
}
fn decimal(s: &str) -> bool {
    digit_group(s, 10) && !(s.len() > 1 && s.starts_with('0'))
}
fn scalar(s: &str) -> std::result::Result<Kind, &'static str> {
    match s {
        "true" => return Ok(Kind::Boolean(true)),
        "false" => return Ok(Kind::Boolean(false)),
        "inf" | "+inf" => return Ok(Kind::Float(f64::INFINITY)),
        "-inf" => return Ok(Kind::Float(f64::NEG_INFINITY)),
        "nan" | "+nan" => return Ok(Kind::Float(f64::NAN)),
        "-nan" => return Ok(Kind::Float(-f64::NAN)),
        _ => {}
    }
    if s.as_bytes().get(4) == Some(&b'-') || s.as_bytes().get(2) == Some(&b':') {
        return datetime(s).map(Kind::Datetime).ok_or("invalid date/time");
    }
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(digits) = s.strip_prefix(prefix) {
            if !digit_group(digits, radix) {
                return Err("invalid base-prefixed integer");
            }
            return i64::from_str_radix(&digits.replace('_', ""), radix)
                .map(Kind::Integer)
                .map_err(|_| "integer overflow");
        }
    }
    let unsigned = s.strip_prefix(['+', '-']).unwrap_or(s);
    let mut exp = unsigned.split(['e', 'E']);
    let mantissa = exp.next().unwrap();
    let exponent = exp.next();
    if exp.next().is_some() {
        return Err("invalid float exponent");
    }
    let mut point = mantissa.split('.');
    let integer = point.next().unwrap();
    let fraction = point.next();
    if point.next().is_some() || !decimal(integer) {
        return Err("invalid numeric value");
    }
    if let Some(f) = fraction
        && !digit_group(f, 10)
    {
        return Err("invalid float fraction");
    }
    if let Some(e) = exponent
        && !digit_group(e.strip_prefix(['+', '-']).unwrap_or(e), 10)
    {
        return Err("invalid float exponent");
    }
    let clean = s.replace('_', "");
    if fraction.is_some() || exponent.is_some() {
        clean
            .parse::<f64>()
            .map_err(|_| "invalid float")
            .and_then(|v| {
                if v.is_finite() {
                    Ok(Kind::Float(v))
                } else {
                    Err("float overflow")
                }
            })
    } else {
        clean
            .parse::<i64>()
            .map(Kind::Integer)
            .map_err(|_| "integer overflow")
    }
}
fn datetime(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let number = |start: usize, len: usize| -> Option<u32> {
        let b = b.get(start..start + len)?;
        if !b.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(b).ok()?.parse().ok()
    };
    let mut i = 0;
    let mut output = String::new();
    if b.get(4) == Some(&b'-') {
        let y = number(0, 4)?;
        let m = number(5, 2)?;
        let d = number(8, 2)?;
        if b.get(7) != Some(&b'-') || !(1..=12).contains(&m) {
            return None;
        }
        let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
        let max = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ][m as usize - 1];
        if d == 0 || d > max {
            return None;
        }
        output.push_str(&s[..10]);
        i = 10;
        if i == s.len() {
            return Some(output);
        }
        if !matches!(b.get(i), Some(b'T' | b't' | b' ')) {
            return None;
        }
        output.push('T');
        i += 1;
    }
    let has_date = i > 0;
    let h = number(i, 2)?;
    if b.get(i + 2) != Some(&b':') {
        return None;
    }
    let m = number(i + 3, 2)?;
    i += 5;
    let has_seconds = b.get(i) == Some(&b':');
    let sec = if has_seconds {
        i += 1;
        let n = number(i, 2)?;
        i += 2;
        n
    } else {
        0
    };
    if h > 23 || m > 59 || sec > 60 {
        return None;
    }
    output.push_str(&format!("{h:02}:{m:02}:{sec:02}"));
    if b.get(i) == Some(&b'.') {
        if !has_seconds {
            return None;
        }
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
        let fraction = &s[start..i.min(start + 9)];
        let fraction = fraction.trim_end_matches('0');
        if !fraction.is_empty() {
            output.push('.');
            output.push_str(fraction);
        }
    }
    if i == s.len() {
        return Some(output);
    }
    if !has_date {
        return None;
    }
    if matches!(b.get(i), Some(b'Z' | b'z')) {
        output.push('Z');
        i += 1;
    } else if matches!(b.get(i), Some(b'+' | b'-')) {
        let neg = b[i] == b'-';
        let h = number(i + 1, 2)?;
        let m = number(i + 4, 2)?;
        if b.get(i + 3) != Some(&b':') || h > 23 || m > 59 {
            return None;
        }
        output.push(if neg && (h > 0 || m > 0) { '-' } else { '+' });
        output.push_str(&format!("{h:02}:{m:02}"));
        i += 6;
    }
    if i == s.len() { Some(output) } else { None }
}
