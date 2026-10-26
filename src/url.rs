//! Workglen's HTTP(S) URL and form encoding implementation.
//!
//! This is intentionally not a general URL crate. IDNA normalization continues
//! to use the already pinned IDNA implementation until equivalent Unicode tables
//! and contextual validation are available in Pratique.
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError;
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid HTTP(S) URL")
    }
}
impl std::error::Error for ParseError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    scheme: String,
    host: String,
    port: Option<u16>,
    username: String,
    password: Option<String>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
    serialized: String,
}

fn encode(s: &str, component: u8) -> String {
    let mut out = String::with_capacity(s.len());
    const HEX: &[u8] = b"0123456789ABCDEF";
    for b in s.bytes() {
        let escape = b <= 0x20
            || b >= 0x7f
            || match component {
                // WHATWG fragment, special query, path and userinfo encode sets.
                0 => matches!(b, b'"' | b'<' | b'>' | b'`'),
                1 => matches!(b, b'"' | b'#' | b'<' | b'>' | b'\''),
                2 => matches!(b, b'"' | b'#' | b'<' | b'>' | b'?' | b'`' | b'{' | b'}'),
                _ => matches!(
                    b,
                    b'"' | b'#'
                        | b'<'
                        | b'>'
                        | b'?'
                        | b'`'
                        | b'{'
                        | b'}'
                        | b'/'
                        | b':'
                        | b';'
                        | b'='
                        | b'@'
                        | b'['
                        | b'\\'
                        | b']'
                        | b'^'
                        | b'|'
                ),
            };
        if escape {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        } else {
            out.push(b as char);
        }
    }
    out
}
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
fn decode(s: &str) -> Result<String, ParseError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(a), Some(c)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(a * 16 + c);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ParseError)
}
fn ipv4_number(s: &str) -> Result<u64, ParseError> {
    if s.is_empty() {
        return Err(ParseError);
    }
    let (s, radix) = if let Some(s) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (s, 16)
    } else if s.len() > 1 && s.starts_with('0') {
        (&s[1..], 8)
    } else {
        (s, 10)
    };
    if s.is_empty() {
        return Ok(0);
    }
    if !s.bytes().all(|b| match radix {
        16 => b.is_ascii_hexdigit(),
        8 => matches!(b, b'0'..=b'7'),
        _ => b.is_ascii_digit(),
    }) {
        return Err(ParseError);
    }
    u64::from_str_radix(s, radix).map_err(|_| ParseError)
}
fn host(raw: &str) -> Result<String, ParseError> {
    if raw.starts_with('[') {
        let inner = raw
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or(ParseError)?;
        let ip: Ipv6Addr = inner.parse().map_err(|_| ParseError)?;
        // Rust displays mapped IPv6 addresses with a dotted IPv4 suffix; URLs use hex.
        let segments = ip.segments();
        let mut best = (0, 0);
        let mut i = 0;
        while i < 8 {
            if segments[i] == 0 {
                let start = i;
                while i < 8 && segments[i] == 0 {
                    i += 1;
                }
                if i - start > best.1 && i - start > 1 {
                    best = (start, i - start);
                }
            } else {
                i += 1;
            }
        }
        let mut out = String::from("[");
        let mut i = 0;
        while i < 8 {
            if best.1 > 0 && i == best.0 {
                out.push_str("::");
                i += best.1;
            } else {
                if i > 0 && !out.ends_with(':') {
                    out.push(':');
                }
                out.push_str(&format!("{:x}", segments[i]));
                i += 1;
            }
        }
        out.push(']');
        return Ok(out);
    }
    let decoded = decode(raw)?;
    if decoded.is_empty()
        || decoded.chars().any(|c| {
            c <= '\u{20}'
                || matches!(
                    c,
                    '\u{7f}'
                        | '#'
                        | '/'
                        | ':'
                        | '<'
                        | '>'
                        | '?'
                        | '@'
                        | '['
                        | '\\'
                        | ']'
                        | '^'
                        | '|'
                        | '%'
                )
        })
    {
        return Err(ParseError);
    }
    let value = workglen_idna::domain_to_ascii(&decoded)
        .map_err(|_| ParseError)?
        .to_ascii_lowercase();
    if value.is_empty()
        || value.chars().any(|c| {
            c <= '\u{20}'
                || matches!(
                    c,
                    '\u{7f}'
                        | '#'
                        | '/'
                        | ':'
                        | '<'
                        | '>'
                        | '?'
                        | '@'
                        | '['
                        | '\\'
                        | ']'
                        | '^'
                        | '|'
                        | '%'
                )
        })
    {
        return Err(ParseError);
    }
    let trimmed = value.strip_suffix('.').unwrap_or(&value);
    let parts: Vec<_> = trimmed.split('.').collect();
    let last = parts.last().copied().unwrap_or("");
    if !last.is_empty() && (last.bytes().all(|b| b.is_ascii_digit()) || ipv4_number(last).is_ok()) {
        if parts.len() > 4 {
            return Err(ParseError);
        }
        let nums: Vec<_> = parts
            .iter()
            .map(|s| ipv4_number(s))
            .collect::<Result<_, _>>()?;
        if nums[..nums.len() - 1].iter().any(|n| *n > 255)
            || nums[nums.len() - 1] >= (1u64 << (8 * (5 - nums.len())))
        {
            return Err(ParseError);
        }
        let mut n = nums[nums.len() - 1];
        for (i, v) in nums[..nums.len() - 1].iter().enumerate() {
            n += v << (8 * (3 - i));
        }
        return Ok(Ipv4Addr::from(n as u32).to_string());
    }
    Ok(value)
}
fn path(raw: &str) -> String {
    let raw = raw.replace('\\', "/");
    let mut parts = Vec::new();
    for (i, part) in raw.split('/').enumerate() {
        if i == 0 && part.is_empty() {
            continue;
        }
        let lower = part.to_ascii_lowercase();
        if matches!(lower.as_str(), "." | "%2e") {
        } else if matches!(lower.as_str(), ".." | ".%2e" | "%2e." | "%2e%2e") {
            parts.pop();
        } else {
            parts.push(encode(part, 2));
        }
    }
    if let Some(last) = raw.rsplit('/').next()
        && matches!(
            last.to_ascii_lowercase().as_str(),
            "." | "%2e" | ".." | ".%2e" | "%2e." | "%2e%2e"
        )
    {
        parts.push(String::new());
    }
    format!("/{}", parts.join("/"))
}
impl Url {
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        // Same special-URL preprocessing used by browsers and the former parser.
        let input = input
            .trim_matches(|c: char| c <= '\u{20}')
            .replace(['\t', '\r', '\n'], "");
        let (scheme, rest) = input.split_once(':').ok_or(ParseError)?;
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https") {
            return Err(ParseError);
        }
        let rest = rest.trim_start_matches(['/', '\\']);
        let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let (userinfo, hostport) = authority
            .rsplit_once('@')
            .map_or((None, authority), |(u, h)| (Some(u), h));
        let (username, password) = userinfo.map_or((String::new(), None), |u| {
            let (a, b) = u.split_once(':').map_or((u, None), |(a, b)| (a, Some(b)));
            (
                encode(a, 3),
                b.filter(|s| !s.is_empty()).map(|s| encode(s, 3)),
            )
        });
        let (hostname, port) = if hostport.starts_with('[') {
            let i = hostport.find(']').ok_or(ParseError)?;
            let suffix = &hostport[i + 1..];
            (
                &hostport[..i + 1],
                if suffix.is_empty() {
                    None
                } else {
                    Some(suffix.strip_prefix(':').ok_or(ParseError)?)
                },
            )
        } else {
            hostport
                .rsplit_once(':')
                .map_or((hostport, None), |(h, p)| (h, Some(p)))
        };
        let host = host(hostname)?;
        let default = if scheme == "https" { 443 } else { 80 };
        let port = match port {
            None | Some("") => None,
            Some(p) => {
                if !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ParseError);
                }
                let n = p.parse().map_err(|_| ParseError)?;
                if n == default { None } else { Some(n) }
            }
        };
        let (tail, fragment) = tail
            .split_once('#')
            .map_or((tail, None), |(a, b)| (a, Some(encode(b, 0))));
        let (tail, query) = tail
            .split_once('?')
            .map_or((tail, None), |(a, b)| (a, Some(encode(b, 1))));
        let mut value = Self {
            scheme,
            host,
            port,
            username,
            password,
            path: path(tail),
            query,
            fragment,
            serialized: String::new(),
        };
        value.rebuild();
        Ok(value)
    }
    fn rebuild(&mut self) {
        let mut s = format!("{}://", self.scheme);
        if !self.username.is_empty() || self.password.is_some() {
            s.push_str(&self.username);
            if let Some(p) = &self.password {
                s.push(':');
                s.push_str(p);
            }
            s.push('@');
        }
        s.push_str(&self.host);
        if let Some(p) = self.port {
            s.push(':');
            s.push_str(&p.to_string());
        }
        s.push_str(&self.path);
        if let Some(q) = &self.query {
            s.push('?');
            s.push_str(q);
        }
        if let Some(f) = &self.fragment {
            s.push('#');
            s.push_str(f);
        }
        self.serialized = s;
    }
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
    pub fn host_str(&self) -> Option<&str> {
        Some(&self.host)
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
    pub fn port(&self) -> Option<u16> {
        self.port
    }
    pub fn port_or_known_default(&self) -> Option<u16> {
        Some(
            self.port
                .unwrap_or(if self.scheme == "https" { 443 } else { 80 }),
        )
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }
    pub fn as_str(&self) -> &str {
        &self.serialized
    }
    pub fn origin(&self) -> Origin {
        Origin(format!(
            "{}://{}{}",
            self.scheme,
            self.host,
            self.port.map(|p| format!(":{p}")).unwrap_or_default()
        ))
    }
    pub fn set_username(&mut self, value: &str) -> Result<(), ParseError> {
        self.username = encode(value, 3);
        self.rebuild();
        Ok(())
    }
    pub fn set_password(&mut self, value: Option<&str>) -> Result<(), ParseError> {
        self.password = value.filter(|s| !s.is_empty()).map(|s| encode(s, 3));
        self.rebuild();
        Ok(())
    }
    pub fn set_path(&mut self, value: &str) {
        self.path = path(value);
        self.rebuild();
    }
    pub fn append_query_pair(&mut self, key: &str, value: &str) -> &mut Self {
        let query = self.query.get_or_insert_with(String::new);
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str(&form_urlencoded::encode(key));
        query.push('=');
        query.push_str(&form_urlencoded::encode(value));
        self.rebuild();
        self
    }
}
impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.serialized)
    }
}
pub struct Origin(String);
impl Origin {
    pub fn ascii_serialization(&self) -> String {
        self.0.clone()
    }
}

pub mod form_urlencoded {
    pub fn encode(value: &str) -> String {
        const HEX: &[u8] = b"0123456789ABCDEF";
        let mut out = String::new();
        for b in value.bytes() {
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                    out.push(b as char)
                }
                b' ' => out.push('+'),
                _ => {
                    out.push('%');
                    out.push(HEX[(b >> 4) as usize] as char);
                    out.push(HEX[(b & 15) as usize] as char);
                }
            }
        }
        out
    }
    pub fn byte_serialize(bytes: &[u8]) -> std::vec::IntoIter<String> {
        const HEX: &[u8] = b"0123456789ABCDEF";
        bytes
            .iter()
            .map(|&b| match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                    (b as char).to_string()
                }
                b' ' => "+".into(),
                _ => format!(
                    "%{}{}",
                    HEX[(b >> 4) as usize] as char,
                    HEX[(b & 15) as usize] as char
                ),
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
    pub struct Serializer(String);
    impl Serializer {
        pub fn new(value: String) -> Self {
            Self(value)
        }
        pub fn append_pair(&mut self, key: &str, value: &str) -> &mut Self {
            if !self.0.is_empty() {
                self.0.push('&');
            }
            self.0.push_str(&encode(key));
            self.0.push('=');
            self.0.push_str(&encode(value));
            self
        }
        pub fn finish(&mut self) -> String {
            std::mem::take(&mut self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origins_and_authorities() {
        for (input, want) in [
            ("HTTPS://Example.COM:443", "https://example.com/"),
            ("http://0x7f.1/a", "http://127.0.0.1/a"),
            (
                "https://[::ffff:127.0.0.1]:8443",
                "https://[::ffff:7f00:1]:8443/",
            ),
            (
                "https://bücher.example/a",
                "https://xn--bcher-kva.example/a",
            ),
            ("https://ｅｘａｍｐｌｅ.com/", "https://example.com/"),
        ] {
            assert_eq!(Url::parse(input).unwrap().as_str(), want);
        }
        for input in [
            "https://",
            "https://[::1]evil/",
            "https://example.com:65536/",
            "https://%00evil/",
            "https://127.0.0.999/",
            "https://example.com%2fevil/",
            "ftp://example.com/",
        ] {
            assert!(Url::parse(input).is_err(), "{input}");
        }
    }
    #[test]
    fn traversal_and_empty_segments() {
        let u = Url::parse("https://host/a//b/%2e%2E/c?x='é'#frag ment").unwrap();
        assert_eq!(u.path(), "/a//c");
        assert_eq!(u.query(), Some("x=%27%C3%A9%27"));
        assert_eq!(u.fragment(), Some("frag%20ment"));
        assert_eq!(Url::parse("https://host/a/.").unwrap().path(), "/a/");
    }
    #[test]
    fn credentials_removed_before_requests() {
        let mut u = Url::parse("https://alice:p%40ss@bridge.simplefin.org/simplefin").unwrap();
        assert_eq!(u.password(), Some("p%40ss"));
        u.set_username("").unwrap();
        u.set_password(None).unwrap();
        u.set_path("/simplefin/accounts");
        u.append_query_pair("version", "2")
            .append_query_pair("q", "a b&é");
        assert_eq!(
            u.as_str(),
            "https://bridge.simplefin.org/simplefin/accounts?version=2&q=a+b%26%C3%A9"
        );
    }
}
